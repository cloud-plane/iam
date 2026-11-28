// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! Create token (authenticate).

use std::net::{IpAddr, SocketAddr};

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use validator::Validate;

use cadf::Initiator;
use openstack_keystone_api_types::v3::auth::token::TokenBuilder;
use openstack_keystone_core::auth::ValidatedSecurityContext;
use openstack_keystone_core_types::auth::*;

use openstack_keystone_core::api::common::get_authz_info;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scope::{Project as ScopeProject, Scope as ProviderScope};

use crate::api::common::PeerAddr;
use crate::api::error::KeystoneApiError;
use crate::api::v3::auth::token::common::{authenticate_request, enforce_mfa_rules};
use crate::api::v3::auth::token::types::{AuthRequest, CreateTokenParameters, TokenResponse};
use crate::audit::{
    CorrelationId, build_initiator_from_principal, build_initiator_from_vsc,
    build_initiator_unknown, emit_perimeter_authenticate_event, perimeter_outcome,
    resolve_audit_ip,
};
use crate::common::TracedJson;
use crate::keystone::ServiceState;

/// Authenticate user issuing a new token.
#[utoipa::path(
    post,
    path = "/",
    description = "Issue token",
    params(CreateTokenParameters),
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag="auth"
)]
#[tracing::instrument(name = "api::v3::token::post", level = "debug", skip(state, req))]
#[axum::debug_handler]
pub(super) async fn create(
    CorrelationId(cid): CorrelationId,
    Query(query): Query<CreateTokenParameters>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    TracedJson(req): TracedJson<AuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let audit_ip = resolve_audit_ip(&state, &headers, peer_addr).await;
    // Set by `create_inner` once the caller has authenticated, so a request
    // that then fails scope selection or a rescope restriction is recorded
    // against the known principal, not as an unknown caller (ADR 0023
    // Phase 2: partial context is an authorization failure).
    let mut known_initiator = None;
    let result = create_inner(
        &state,
        query,
        req,
        &headers,
        peer_addr,
        audit_ip,
        &cid,
        &mut known_initiator,
    )
    .await;
    let initiator = match result.as_ref() {
        Ok((vsc, _)) => build_initiator_from_vsc(vsc),
        Err(_) => known_initiator.unwrap_or_else(build_initiator_unknown),
    };
    let initiator = initiator.with_address(audit_ip.map(|ip| ip.to_string()));
    let (outcome, reason) = perimeter_outcome(&result);
    emit_perimeter_authenticate_event(&state.audit_dispatcher, &cid, initiator, outcome, reason);
    result.map(|(_, response)| response)
}

/// Inner auth flow that returns the `ValidatedSecurityContext` alongside the
/// HTTP response so the outer handler can build the audit `Initiator`.
#[allow(clippy::too_many_arguments)]
async fn create_inner(
    state: &ServiceState,
    query: CreateTokenParameters,
    req: AuthRequest,
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    audit_ip: Option<IpAddr>,
    correlation_id: &str,
    known_initiator: &mut Option<Initiator>,
) -> Result<(ValidatedSecurityContext, Response), KeystoneApiError> {
    req.validate()?;

    // Global per-IP rate-limit check (ADR-0022, Invariant 4).
    // Fires BEFORE authenticate_request to avoid consuming CPU on password
    // hashing for rejected requests.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(headers, peer_addr.map(|addr| addr.ip()))
    {
        return Err(KeystoneApiError::TooManyRequests {
            retry_after: retry_after.as_secs(),
        });
    }

    let auth_res = authenticate_request(
        state,
        &req,
        headers,
        peer_addr.map(|addr| addr.ip()),
        Some(correlation_id),
    )
    .await?;
    let ctx = SecurityContext::try_from(auth_res)?;
    *known_initiator = Some(build_initiator_from_principal(ctx.principal()));
    enforce_mfa_rules(state, &ctx).await?;
    // Application credentials are bound to a single project, which is derived
    // from the credential. Same as in python keystone, requesting a scope is
    // prohibited, also when exchanging an application credential token. The
    // bound project is passed as the scope; `SecurityContext` rejects every
    // other one.
    let provider_scope: Option<ProviderScope> =
        if let AuthenticationContext::ApplicationCredential {
            application_credential,
            ..
        } = ctx.authentication_context()
        {
            if req.auth.scope.is_some() {
                return Err(AuthenticationError::ScopeNotAllowed.into());
            }
            Some(ProviderScope::Project(ScopeProject {
                id: Some(application_credential.project_id.clone()),
                name: None,
                domain: None,
            }))
        } else {
            req.auth.scope.clone().map(Into::into)
        };
    let authz_info = get_authz_info(state, provider_scope.as_ref()).await?;

    // This is a new authentication/reauthentication. Check if that is allowed
    // at all
    if let Some(token_restriction) = ctx.token_restriction()
        && !token_restriction.allow_rescope
        && req.auth.scope.is_some()
    {
        return Err(KeystoneApiError::AuthenticationRescopeForbidden);
    }

    // The catalog does not depend on the token scope, so it is fetched while
    // the token context (roles, revocation) is being resolved.
    let exec = ExecutionContext::internal(state);
    let catalog_fut = async {
        if query.nocatalog.is_some_and(|x| x) {
            return Ok::<_, KeystoneApiError>(None);
        }
        Ok(Some(crate::catalog::response_catalog(state, &exec).await?))
    };
    let vsc_fut = async {
        Ok::<_, KeystoneApiError>(
            state
                .provider
                .get_token_provider()
                .issue_token_context(state, &ctx, &authz_info)
                .await?,
        )
    };
    // The catalog result is wrapped so that only an issuance failure ends the
    // join: a catalog failure must not cancel the token issuance in flight
    // (audit, last-active and revocation bookkeeping). Cancelling the
    // read-only catalog fetch on an issuance failure is harmless.
    let (mut vsc, catalog) = tokio::try_join!(vsc_fut, async {
        Ok::<_, KeystoneApiError>(catalog_fut.await)
    })?;
    let catalog = catalog?;
    if let Some(ip) = audit_ip {
        vsc.set_peer_addr(ip.to_string());
    }

    let mut api_token = TokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };
    api_token.token.catalog = catalog;
    let response = (
        StatusCode::CREATED,
        [(
            "X-Subject-Token",
            state
                .provider
                .get_token_provider()
                .encode_token(vsc.token()?)?,
        )],
        Json(api_token),
    )
        .into_response();
    Ok((vsc, response))
}

#[cfg(test)]
#[path = "create/tests.rs"]
mod tests;

/// End-to-end HTTP-level integration tests for `mapping`/`route` dynamic
/// auth plugins - drives the real `create()` axum handler via
/// `openapi_router()`/`oneshot()` (like this file's own `test_post`) with a
/// real compiled reference plugin loaded (like `common.rs`'s
/// `route_dispatch_tests`), proving the full round trip: HTTP request in ->
/// `authenticate_request` -> auth-plugin dispatch -> `get_authz_info` ->
/// `issue_token_context` -> `X-Subject-Token` HTTP response out. Every
/// existing auth-plugin test stops one layer short of this (calls
/// `authenticate_via_wasm_*`/`authenticate_request` directly) - this module
/// fills that gap for `mapping` mode and for `route` mode redirecting to a
/// real `full_auth` target.
#[cfg(test)]
#[cfg(feature = "wasm_plugins")]
#[path = "create/auth_plugin_http_tests.rs"]
mod auth_plugin_http_tests;
