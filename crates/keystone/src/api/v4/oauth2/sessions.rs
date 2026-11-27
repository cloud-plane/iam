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
//! Operator listing of the OAuth2 sessions (refresh token families) of a
//! user, for incident triage (`keystone-manage oauth2 sessions list`).

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::{StreamExt, TryStreamExt, stream};

use openstack_keystone_api_types::v4::oauth2_revocation::{
    Oauth2Session, Oauth2SessionList, Oauth2SessionListParameters,
};
use openstack_keystone_core::policy::PolicyError;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Concurrent per-item policy checks of one listing.
const ITEM_CHECK_CONCURRENCY: usize = 16;

/// List the OAuth2 sessions of a user.
#[utoipa::path(
    get,
    path = "/{domain_id}/sessions",
    operation_id = "/oauth2/session:list",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        Oauth2SessionListParameters,
    ),
    responses(
        (status = OK, description = "Sessions of the user", body = Oauth2SessionList),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_revocation"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::sessions::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    Query(query): Query<Oauth2SessionListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/session/list",
            &user_auth,
            serde_json::json!({"domain_id": domain_id, "user_id": query.user_id}),
            None,
        )
        .await?;

    let listing = state
        .provider
        .get_oauth2_session_provider()
        .list_refresh_token_families_by_user(&state, &domain_id, &query.user_id)
        .await?;

    // Per-item re-check (CLAUDE.md): a family is returned only when the
    // caller may read that family. Denied families are dropped, any other
    // policy failure fails the request.
    let auth = &user_auth;
    let enforcer = &state.policy_enforcer;
    let oauth2_sessions = stream::iter(listing.families)
        .map(|f| async move {
            let existing = serde_json::json!({"oauth2_session": {
                "client_id": f.client_id,
                "domain_id": f.domain_id,
                "family_id": f.family_id,
                "user_id": f.user_id,
            }});
            match enforcer
                .enforce(
                    "identity/oauth2/session/show",
                    auth,
                    serde_json::json!({"domain_id": f.domain_id, "user_id": f.user_id}),
                    Some(existing),
                )
                .await
            {
                Ok(_) => Ok(Some(Oauth2Session {
                    family_id: f.family_id,
                    client_id: f.client_id,
                    user_id: f.user_id,
                    issued_at: f.issued_at,
                    last_rotated: f.last_rotated,
                    revoked_at: f.revoked_at,
                    revocation_reason: f.revocation_reason,
                })),
                Err(PolicyError::Forbidden(_)) => Ok(None),
                Err(err) => Err(err),
            }
        })
        .buffered(ITEM_CHECK_CONCURRENCY)
        .try_filter_map(|item| async move { Ok(item) })
        .try_collect()
        .await?;

    Ok((
        StatusCode::OK,
        Json(Oauth2SessionList {
            oauth2_sessions,
            truncated: listing.truncated,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use std::sync::Arc;

    use openstack_keystone_api_types::v4::oauth2_revocation::Oauth2SessionList;
    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core::policy::{PolicyEnforcer, PolicyError, PolicyEvaluationResult};
    use openstack_keystone_core_types::oauth2_session::{
        RefreshTokenFamilyListing, RefreshTokenFamilySummary,
    };

    use crate::api::tests::{get_mocked_state, get_state_with_policy, test_fixture_scoped};
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    const URI: &str = "/domain_id/sessions?user_id=u1";

    fn family(id: &str) -> RefreshTokenFamilySummary {
        RefreshTokenFamilySummary {
            family_id: id.into(),
            domain_id: "domain_id".into(),
            client_id: "c1".into(),
            user_id: "u1".into(),
            issued_at: 10,
            last_rotated: 20,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    /// Denies the per-item check of `forbidden` families and fails the
    /// per-item check of `erroring` ones; allows everything else.
    struct ItemPolicy {
        forbidden: &'static str,
        erroring: Option<&'static str>,
    }

    #[async_trait::async_trait]
    impl PolicyEnforcer for ItemPolicy {
        async fn enforce(
            &self,
            policy_name: &'static str,
            _credentials: &ValidatedSecurityContext,
            _target: serde_json::Value,
            existing: Option<serde_json::Value>,
        ) -> Result<PolicyEvaluationResult, PolicyError> {
            if policy_name == "identity/oauth2/session/show" {
                let id = existing
                    .as_ref()
                    .and_then(|e| e["oauth2_session"]["family_id"].as_str())
                    .unwrap_or_default();
                if id == self.forbidden {
                    return Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()));
                }
                if Some(id) == self.erroring {
                    return Err(PolicyError::IO(std::io::Error::other("opa unreachable")));
                }
            }
            Ok(PolicyEvaluationResult::allowed_admin())
        }

        async fn health_check(&self) -> Result<(), PolicyError> {
            Ok(())
        }
    }

    async fn list_response(state: crate::keystone::ServiceState) -> axum::response::Response {
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        api.as_service().oneshot(request(true)).await.unwrap()
    }

    fn sessions_provider(listing: RefreshTokenFamilyListing) -> MockOauth2SessionProvider {
        let mut mock = MockOauth2SessionProvider::default();
        mock.expect_list_refresh_token_families_by_user()
            .returning(move |_, _, _| Ok(listing.clone()));
        mock
    }

    fn request(authenticated: bool) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri(URI);
        if authenticated {
            builder = builder.extension(test_fixture_scoped());
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let provider = Provider::mocked_builder().mock_oauth2_session(sessions_provider(
            RefreshTokenFamilyListing {
                families: vec![family("f1")],
                truncated: false,
            },
        ));
        let state = get_mocked_state(provider, true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2SessionList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.oauth2_sessions.len(), 1);
        assert_eq!(res.oauth2_sessions[0].last_rotated, 20);
    }

    #[tokio::test]
    async fn test_list_reports_truncation() {
        let provider = Provider::mocked_builder().mock_oauth2_session(sessions_provider(
            RefreshTokenFamilyListing {
                families: vec![family("f1")],
                truncated: true,
            },
        ));
        let state = get_mocked_state(provider, true, None).await;
        let response = list_response(state).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2SessionList = serde_json::from_slice(&body).unwrap();
        assert!(res.truncated);
        assert_eq!(res.oauth2_sessions.len(), 1);
    }

    /// The per-item re-check drops the families the caller may not read.
    #[tokio::test]
    async fn test_list_filters_families_by_show_policy() {
        let provider = Provider::mocked_builder().mock_oauth2_session(sessions_provider(
            RefreshTokenFamilyListing {
                families: vec![family("f1"), family("f2"), family("f3")],
                truncated: false,
            },
        ));
        let state = get_state_with_policy(
            provider,
            Arc::new(ItemPolicy {
                forbidden: "f2",
                erroring: None,
            }),
        )
        .await;
        let response = list_response(state).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2SessionList = serde_json::from_slice(&body).unwrap();
        let ids: Vec<_> = res
            .oauth2_sessions
            .iter()
            .map(|s| s.family_id.as_str())
            .collect();
        assert_eq!(ids, vec!["f1", "f3"]);
    }

    /// A policy failure other than a denial fails the whole listing.
    #[tokio::test]
    async fn test_list_propagates_item_policy_errors() {
        let provider = Provider::mocked_builder().mock_oauth2_session(sessions_provider(
            RefreshTokenFamilyListing {
                families: vec![family("f1"), family("f2")],
                truncated: false,
            },
        ));
        let state = get_state_with_policy(
            provider,
            Arc::new(ItemPolicy {
                forbidden: "none",
                erroring: Some("f2"),
            }),
        )
        .await;
        let response = list_response(state).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_policy_denied() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api.as_service().oneshot(request(false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
