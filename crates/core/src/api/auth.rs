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
//! # API authentication handling
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use secrecy::SecretString;
use tracing::{debug, error};

use openstack_keystone_config::Interface;
use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use crate::api::KeystoneApiError;
use crate::auth::{ExecutionContext, ValidatedSecurityContext};
use crate::common::SpiffeId;
use crate::keystone::ServiceState;

#[derive(Debug, Clone)]
pub struct Auth(pub ValidatedSecurityContext);

impl Deref for Auth {
    type Target = ValidatedSecurityContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for Auth
where
    ServiceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = KeystoneApiError;

    #[tracing::instrument(
        name = "auth.from_request_parts",
        level = "debug",
        skip(state, parts),
        err
    )]
    /// Try to authenticate the request
    ///
    /// Authenticate the request creating the `ValidatedSecurityContext` using
    /// the following information:
    ///
    /// * `mTLS` - SPIFFE issued x509 certificate that is passed as an extension
    ///   by the mtls connection handler. The SVID is flattened into claims and
    ///   routed through the mapping engine for authentication. When matched,
    ///   the `ValidatedSecurityContext` is instantiated as
    ///   `ScopeInfo::Unscoped` scope. System principals (`is_system`) are
    ///   overridden to `ScopeInfo::System`.
    /// * `X-Auth-Token` - HTTP header is used as encoded `FernetToken` which is
    ///   decoded and used
    /// to instantiate the `ValidatedSecurityContext`. The `FernetToken` always
    /// contains the scope information (whether it is scoped or explicitly
    /// Unscoped).
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Only available in tests - get mock ValidatedSecurityContext injected
        // as extension instead of populating mocks for all individual
        // calls.
        #[cfg(any(test, feature = "mock"))]
        {
            if let Some(vsc) = parts.extensions.get::<ValidatedSecurityContext>() {
                vsc.fully_resolved()?;
                enforce_access_rules(vsc, parts)?;
                return Ok(Auth(vsc.clone()));
            }
        }

        // Extract the interface on which the connection is being served
        // TODO: Insert interface info into the Context
        let interface = parts
            .extensions
            .get::<Interface>()
            .cloned()
            .unwrap_or(Interface::Public);

        // Resolved once and stamped on every `vsc` this extractor builds, so
        // audit events for every authenticated request carry the client IP
        // without each handler needing its own `PeerAddr` extractor.
        //
        // `public_ingress_peer_addr` is the raw, pre-resolution TCP peer
        // (behind a trusted reverse proxy, that's the proxy's address, not
        // the real client's) -- it must be re-resolved through the
        // operator's configured trusted-proxy/forwarding-header settings,
        // exactly like `rate_limit::check_ip` and `api_key_auth` do, or
        // every audited event behind a proxy would record the proxy's IP.
        let raw_peer_addr = crate::net::public_ingress_peer_addr(&parts.extensions);

        let state = Arc::from_ref(state);

        let peer_addr = {
            let config = state.config_manager.config.read().await;
            crate::net::resolve_client_ip_from_headers(
                &parts.headers,
                raw_peer_addr.map(|addr| addr.ip()),
                &config.oslo_middleware.trusted_proxies,
                config.oslo_middleware.trusted_header,
            )
        };

        // ADR 0036 §8.1: a delegatable service keeps its mTLS connection after
        // it received a service grant or on-behalf-of token, so the request
        // carries an SVID and a bearer JWT. The JWT is accepted only bound to
        // the SVID; a failed binding is a 401, never a fallback to the plain
        // SVID identity.
        if interface == Interface::Internal
            && let Some(svid) = parts.extensions.get::<SpiffeId>()
            && let Some(header) = parts.headers.get(axum::http::header::AUTHORIZATION)
        {
            // Any `Authorization` header next to an SVID is a delegation
            // attempt: one that is not a well-formed bearer is a 401, never
            // a silent fallback to the plain SVID identity.
            let token = bearer_token(header).ok_or_else(|| {
                tracing::warn!("delegated bearer rejected: malformed Authorization header");
                KeystoneApiError::from(AuthenticationError::Unauthorized)
            })?;
            tracing::debug!("authenticating the svid {} bound delegated bearer", svid);
            let mut vsc =
                crate::oauth2_client::bound_bearer::authenticate_bound_bearer(&state, svid, token)
                    .await
                    .map_err(|e| {
                        tracing::warn!("delegated bearer rejected: {e}");
                        KeystoneApiError::from(AuthenticationError::Unauthorized)
                    })?;
            if let Some(addr) = peer_addr {
                vsc.set_peer_addr(addr.to_string());
            }
            enforce_access_rules(&vsc, parts)?;
            crate::audit_context::record_initiator(crate::cadf_hook::build_initiator_from_vsc(
                &vsc,
            ));
            return Ok(Auth(vsc));
        }

        // Check the SPIFFE svid first as the primary identity source
        if let Some(svid) = parts.extensions.get::<SpiffeId>() {
            tracing::debug!("authenticating the spiffe svid {}", svid);

            if let Some(config_admin_svid) = &state
                .config_manager
                .config
                .read()
                .await
                .interface_admin
                .as_ref()
                .and_then(|admin_if| admin_if.admin_svid.as_ref())
                && **config_admin_svid == svid.to_string()
                && interface == Interface::Admin
            {
                // The admin_svid was configured and it is it over the admin
                // interface - short circuit the admin
                let auth_result: AuthenticationResult = AuthenticationResultBuilder::default()
                    .context(AuthenticationContext::Admin)
                    .principal(
                        PrincipalInfoBuilder::default()
                            .identity(IdentityInfo::Principal(
                                PrincipalIdentityInfoBuilder::default()
                                    .id(svid.to_string())
                                    .issuer(svid.trust_domain_name())
                                    .build()?,
                            ))
                            .build()?,
                    )
                    .build()?;

                let mut ctx = SecurityContext::try_from(auth_result)?;
                ctx.set_is_admin();
                let mut vsc = ValidatedSecurityContext::new_for_scope(
                    ctx,
                    ScopeInfo::System("all".into()),
                    &state,
                )
                .await?;
                if let Some(addr) = peer_addr {
                    vsc.set_peer_addr(addr.to_string());
                }
                enforce_access_rules(&vsc, parts)?;
                crate::audit_context::record_initiator(crate::cadf_hook::build_initiator_from_vsc(
                    &vsc,
                ));
                return Ok(Auth(vsc));
            }

            // Authenticate via mapping engine (SPIFFE bindings are deprecated —
            // ADR-0020 Phase 3)
            let result = state
                .provider
                .get_mapping_provider()
                .authenticate_by_mapping(
                    &ExecutionContext::internal(&state),
                    &flat_spiffe_claims(svid)?,
                )
                .await?;
            let ctx = SecurityContext::try_from(result)?;
            let mut vsc =
                ValidatedSecurityContext::new_for_scope(ctx, ScopeInfo::Unscoped, &state).await?;
            if let Some(addr) = peer_addr {
                vsc.set_peer_addr(addr.to_string());
            }
            enforce_access_rules(&vsc, parts)?;
            crate::audit_context::record_initiator(crate::cadf_hook::build_initiator_from_vsc(
                &vsc,
            ));
            return Ok(Auth(vsc));
        }

        // Now headers can be checked
        if let Some(auth_header) = parts
            .headers
            .get("X-Auth-Token")
            .and_then(|h| h.to_str().ok())
        {
            tracing::debug!("authenticating request with the x-auth-token");
            let auth_token = SecretString::from(auth_header.to_owned());
            // ADR 0031 "Authentication": every `X-Auth-Token` re-authentication
            // is `method = "token"`. Timed/recorded around the provider call
            // (not the whole extractor) so the outcome/reason reflect exactly
            // this authentication step.
            let auth_start = std::time::Instant::now();
            let token_result = state
                .provider
                .get_token_provider()
                .authorize_request_token(&ExecutionContext::internal(&state), &auth_token)
                .await;
            let reason = token_result
                .as_ref()
                .err()
                .map(crate::token::metrics::token_failure_reason);
            crate::auth_metrics::AUTH_METRICS.record_attempt(
                "token",
                auth_start.elapsed().as_secs_f64(),
                reason,
            );
            let mut vsc = token_result
                .inspect_err(|e| error!("{:#?}", e))
                .map_err(|_| KeystoneApiError::UnauthorizedNoContext)?;

            vsc.fully_resolved()?;
            reject_if_ec2(&vsc)?;
            if let Some(addr) = peer_addr {
                vsc.set_peer_addr(addr.to_string());
            }
            enforce_access_rules(&vsc, parts)?;
            crate::audit_context::record_initiator(crate::cadf_hook::build_initiator_from_vsc(
                &vsc,
            ));
            return Ok(Auth(vsc));
        }

        debug!("No supported information has been provided.");
        Err(KeystoneApiError::UnauthorizedNoContext)
    }
}

/// Flattens SPIFFE SVID claims into a
/// [`MappingAuthRequest`](crate::mapping::auth::MappingAuthRequest).
///
/// Always produces `spiffe.id` and `spiffe.trust_domain`. When the SVID's
/// path matches one of the known keystone-rs identity patterns (SPIRE
/// integration plan, Phase 3, see [`SpiffeId::path_claims`]), also emits
/// `spiffe.host`, or `spiffe.project_id`/`spiffe.instance_id`.
///
/// # Errors
///
/// Returns `Err(KeystoneApiError::UnauthorizedNoContext)` if the SVID's
/// path looks like it is attempting a known pattern
/// (`service/nova-compute/host/...` or `project/.../instance/...`) but is
/// malformed. An SVID whose path does not resemble any known pattern is
/// *not* an error -- it authenticates with just `spiffe.id`/
/// `spiffe.trust_domain`, same as before this claim derivation existed.
fn flat_spiffe_claims(svid: &SpiffeId) -> Result<MappingAuthRequest, KeystoneApiError> {
    let mut claims = HashMap::new();
    claims.insert("spiffe.id".to_string(), vec![svid.to_string()]);
    claims.insert(
        "spiffe.trust_domain".to_string(),
        vec![svid.trust_domain_name().to_string()],
    );

    match svid.path_claims() {
        crate::common::SpiffePathMatch::Matched(path_claims) => {
            if let Some(host) = path_claims.host {
                claims.insert("spiffe.host".to_string(), vec![host]);
            }
            if let Some(project_id) = path_claims.project_id {
                claims.insert("spiffe.project_id".to_string(), vec![project_id]);
            }
            if let Some(instance_id) = path_claims.instance_id {
                claims.insert("spiffe.instance_id".to_string(), vec![instance_id]);
            }
        }
        crate::common::SpiffePathMatch::Unrecognized => {}
        crate::common::SpiffePathMatch::Malformed => {
            debug!("rejecting malformed spiffe svid path: {}", svid);
            return Err(KeystoneApiError::UnauthorizedNoContext);
        }
    }

    Ok(MappingAuthRequest {
        domain_id: None,
        source: IdentitySource::Spiffe {
            trust_domain: svid.trust_domain_name().to_string(),
        },
        unique_workload_id: svid.to_string(),
        claims,
        rule_name: None,
    })
}

/// Reject requests authenticated via an EC2 token.
///
/// A token minted at `POST /v3/ec2tokens` must not be usable for any
/// operation except being simply a valid token accepted by the GET
/// `/v3/auth/tokens`.
///
/// # Returns
///
/// `Ok(())` when the auth type is not EC2, `Err(400 Bad Request)` otherwise
/// (`KeystoneApiError::SelectedAuthenticationForbidden` — the same variant
/// used for `AuthenticationError::TokenRenewalForbidden` — always maps to
/// 400, never 403, per `error_conv.rs`).
fn reject_if_ec2(user_auth: &ValidatedSecurityContext) -> Result<(), KeystoneApiError> {
    // SECURITY: this must stay here unchanged to prevent security
    // vulnerabilities from the EC2 auth reuse.
    //
    // A bare EC2 credential (not minted under a trust/app-cred) surfaces as
    // `AuthenticationContext::Ec2Credential` directly. One minted under a
    // trust/app-cred reconstructs `AuthenticationContext::Trust` /
    // `ApplicationCredential` on redemption instead (security-model.md §5),
    // so it must also be caught via the immutable `ec2credential` marker in
    // the auth-method chain, which survives that reconstruction.
    if matches!(
        user_auth.inner().authentication_context(),
        AuthenticationContext::Ec2Credential
    ) || user_auth.inner().auth_methods().contains("ec2credential")
    {
        return Err(KeystoneApiError::SelectedAuthenticationForbidden);
    }
    Ok(())
}

/// Security review V5 (`doc/src/contributor/security-model.md` §5 "Open
/// gap"): an application credential created with a non-empty, restricting
/// `access_rules` list must not be usable outside those rules. This is the
/// request-matching enforcement point the gap called for -- run once, here,
/// for every request this extractor resolves (every return path in
/// [`Auth::from_request_parts`] calls it), rather than duplicated per
/// handler, so a new handler cannot forget it and an app-cred's rules
/// cannot be bypassed by calling a route that doesn't happen to check.
///
/// Only rules naming Keystone's own service
/// ([`openstack_keystone_core_types::application_credential::OWN_SERVICE_TYPE`])
/// are ever checked here: a rule naming a different service (compute,
/// image, ...) restricts calls to *that* service, which its own
/// keystonemiddleware enforces via token introspection -- Keystone has no
/// way to enforce a restriction on a request it never receives, and must
/// not treat "this rule doesn't apply to me" as "this rule doesn't apply
/// anywhere" by ignoring the credential's rules entirely.
///
/// A no-op for every `AuthenticationContext` other than
/// `ApplicationCredential`, and for an `ApplicationCredential` with no
/// `access_rules` (`None` or empty) -- the unrestricted, default case.
fn enforce_access_rules(
    vsc: &ValidatedSecurityContext,
    parts: &Parts,
) -> Result<(), KeystoneApiError> {
    if let AuthenticationContext::ApplicationCredential {
        application_credential,
        ..
    } = vsc.inner().authentication_context()
        && let Some(rules) = application_credential.access_rules.as_ref()
        && !rules.is_empty()
    {
        let method = parts.method.as_str();
        let path = parts.uri.path();
        if !openstack_keystone_core_types::application_credential::access_rules_permit(
            rules, method, path,
        ) {
            return Err(
                openstack_keystone_core_types::application_credential::ApplicationCredentialProviderError::AccessRuleDenied {
                    method: method.to_string(),
                    path: path.to_string(),
                }
                .into(),
            );
        }
    }
    Ok(())
}

/// The token of an `Authorization: Bearer <token>` header; the scheme is
/// case-insensitive (RFC 7235 §2.1). `None` for any other scheme, a missing
/// token or a header that is not valid UTF-8.
pub fn bearer_token(header: &axum::http::HeaderValue) -> Option<&str> {
    let (scheme, token) = header.to_str().ok()?.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

#[cfg(test)]
#[path = "auth/tests.rs"]
mod tests;
