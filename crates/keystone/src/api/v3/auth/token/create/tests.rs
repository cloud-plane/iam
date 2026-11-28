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

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use cadf::Outcome;
use http_body_util::BodyExt; // for `collect`
use sea_orm::DatabaseConnection;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
use tower_http::trace::TraceLayer;
use tracing_test::traced_test;

use cadf::AuditDispatcher;
use openstack_keystone_config::{Config, ConfigManager, Interface, ProxyHeader, RateLimitSection};
use openstack_keystone_core_types::application_credential::{
    ApplicationCredentialAuthData, ApplicationCredentialAuthRequest,
};
use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::identity::{IdentityProviderError, UserPasswordAuthRequest};
use openstack_keystone_core_types::resource::{Domain, DomainBuilder, Project};
use openstack_keystone_core_types::token::{ProjectScopePayload, TokenProviderError};
use secrecy::ExposeSecret;

use crate::api::v3::auth::token::types::*;
use crate::application_credential::MockApplicationCredentialProvider;
use crate::assignment::MockAssignmentProvider;
use crate::catalog::MockCatalogProvider;
use crate::identity::MockIdentityProvider;
use crate::keystone::Service;
use crate::policy::MockPolicy;
use crate::provider::Provider;
use crate::resource::MockResourceProvider;
use crate::token::MockTokenProvider;

use super::super::openapi_router;

fn user_with_options(
    options: openstack_keystone_core_types::identity::UserOptions,
) -> openstack_keystone_core_types::identity::UserResponse {
    openstack_keystone_core_types::identity::UserResponse {
        id: "uid".into(),
        name: "uname".into(),
        domain_id: "user_domain_id".into(),
        enabled: true,
        default_project_id: None,
        extra: std::collections::HashMap::new(),
        federated: None,
        options,
        password_expires_at: None,
    }
}

#[tokio::test]
#[traced_test]
async fn test_post_password_only_rejected_by_mfa_rules() {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
        })
        .build()
        .unwrap();
    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .returning(move |_, _| Ok(auth.clone()));
    identity_mock.expect_get_user().returning(|_, _| {
        Ok(Some(user_with_options(
            openstack_keystone_core_types::identity::UserOptions {
                multi_factor_auth_rules: Some(vec![vec!["password".into(), "totp".into()]]),
                ..Default::default()
            },
        )))
    });
    // No token provider expectation: the token must never be issued.
    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .build()
        .unwrap();
    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(Config::default()),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );
    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "auth": {
                            "identity": {
                                "methods": ["password"],
                                "password": {"user": {"id": "uid", "password": "pass"}}
                            }
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[traced_test]
async fn test_post() {
    let config = Config::default();
    let project = Project {
        id: "pid".into(),
        domain_id: "pdid".into(),
        enabled: true,
        ..Default::default()
    };
    let user_domain = Domain {
        id: "user_domain_id".into(),
        enabled: true,
        ..Default::default()
    };
    let project_domain = Domain {
        id: "pdid".into(),
        enabled: true,
        ..Default::default()
    };
    let mut assignment_mock = MockAssignmentProvider::default();
    let mut catalog_mock = MockCatalogProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(|_, _| Ok(Vec::new()));

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
        })
        .build()
        .unwrap();

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .withf(|_, req: &UserPasswordAuthRequest| {
            req.id == Some("uid".to_string())
                && req.password.expose_secret() == "pass"
                && req.name == Some("uname".to_string())
        })
        .returning(move |_, _| Ok(auth.clone()));
    identity_mock.expect_get_user().returning(|_, _| {
        use openstack_keystone_core_types::identity::UserResponse;
        Ok(Some(UserResponse {
            id: "uid".into(),
            name: "uname".into(),
            domain_id: "user_domain_id".into(),
            enabled: true,
            default_project_id: None,
            extra: std::collections::HashMap::new(),
            federated: None,
            options: openstack_keystone_core_types::identity::UserOptions::default(),
            password_expires_at: None,
        }))
    });

    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_get_project()
        .withf(|_, id: &'_ str| id == "pid")
        .returning(move |_, _| Ok(Some(project.clone())));
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "user_domain_id")
        .returning(move |_, _| Ok(Some(user_domain.clone())));
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "pdid")
        .returning(move |_, _| Ok(Some(project_domain.clone())));
    let mut token_mock = MockTokenProvider::default();
    let vsc_for_mock = {
        use openstack_keystone_core_types::auth::AuthzInfoBuilder;
        use openstack_keystone_core_types::resource::ProjectRefBuilder;
        use openstack_keystone_core_types::role::RoleRefBuilder;
        use openstack_keystone_core_types::token::FernetToken;
        let user_resp = openstack_keystone_core_types::identity::UserResponseBuilder::default()
            .id("uid")
            .name("uname".to_string())
            .domain_id("user_domain_id".to_string())
            .enabled(true)
            .build()
            .unwrap();
        let fernet_payload = ProjectScopePayload {
            user_id: "uid".into(),
            methods: Vec::from(["password".to_string()]),
            project_id: "pid".into(),
            ..Default::default()
        };
        let authz = AuthzInfoBuilder::default()
            .roles(vec![
                RoleRefBuilder::default()
                    .id("admin")
                    .name("admin")
                    .build()
                    .unwrap(),
            ])
            .scope(ScopeInfo::Project {
                project: ProjectRefBuilder::default()
                    .id("pid")
                    .domain_id("pdid")
                    .enabled(true)
                    .name("pname")
                    .build()
                    .unwrap(),
                project_domain: openstack_keystone_core_types::resource::DomainRefBuilder::default(
                )
                .id("pdid")
                .name("pdname")
                .enabled(true)
                .build()
                .unwrap(),
            })
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user_resp)
                        .user_domain(
                            DomainBuilder::default()
                                .id("user_domain_id")
                                .name("user_domain_name")
                                .enabled(true)
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                ),
            })
            .token(FernetToken::ProjectScope(fernet_payload))
            .authorization(authz)
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    };
    let vsc_clone = vsc_for_mock.clone();
    token_mock
        .expect_issue_token_context()
        .returning(move |_, _, _| Ok(vsc_clone.clone()));
    token_mock
        .expect_encode_token()
        .returning(|_| Ok("token".to_string()));
    catalog_mock
        .expect_get_catalog()
        .returning(|_, _| Ok(std::sync::Arc::new(Vec::new())));

    let provider = Provider::mocked_builder()
        .mock_assignment(assignment_mock)
        .mock_catalog(catalog_mock)
        .mock_identity(identity_mock)
        .mock_resource(resource_mock)
        .mock_token(token_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "auth": {
                            "identity": {
                                "methods": ["password"],
                                "password": {
                                    "user": {
                                        "id": "uid",
                                        "name": "uname",
                                        "domain": {
                                            "id": "udid",
                                            "name": "udname"
                                        },
                                        "password": "pass",
                                    },
                                },
                            },
                            "scope": {
                                "project": {
                                    "id": "pid",
                                    "name": "pname",
                                    "domain": {
                                        "id": "pdid",
                                        "name": "pdname"
                                    }
                                }
                            }
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let res: TokenResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(vec!["password"], res.token.methods);
}

#[tokio::test]
#[traced_test]
async fn test_post_explicit_empty_roles_unauthorized() {
    let config = Config::default();
    let project = Project {
        id: "pid".into(),
        domain_id: "pdid".into(),
        enabled: true,
        ..Default::default()
    };
    let user_domain = Domain {
        id: "user_domain_id".into(),
        enabled: true,
        ..Default::default()
    };
    let project_domain = Domain {
        id: "pdid".into(),
        enabled: true,
        ..Default::default()
    };
    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(|_, _| Ok(Vec::new()));

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
        })
        .build()
        .unwrap();

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .withf(|_, req: &UserPasswordAuthRequest| {
            req.id == Some("uid".to_string())
                && req.password.expose_secret() == "pass"
                && req.name == Some("uname".to_string())
        })
        .returning(move |_, _| Ok(auth.clone()));
    identity_mock.expect_get_user().returning(|_, _| {
        use openstack_keystone_core_types::identity::UserResponse;
        Ok(Some(UserResponse {
            id: "uid".into(),
            name: "uname".into(),
            domain_id: "user_domain_id".into(),
            enabled: true,
            default_project_id: None,
            extra: std::collections::HashMap::new(),
            federated: None,
            options: openstack_keystone_core_types::identity::UserOptions::default(),
            password_expires_at: None,
        }))
    });

    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_get_project()
        .withf(|_, id: &'_ str| id == "pid")
        .returning(move |_, _| Ok(Some(project.clone())));
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "user_domain_id")
        .returning(move |_, _| Ok(Some(user_domain.clone())));
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "pdid")
        .returning(move |_, _| Ok(Some(project_domain.clone())));

    let mut token_mock = MockTokenProvider::default();
    token_mock
        .expect_issue_token_context()
        .returning(|_, _, _| {
            Err(TokenProviderError::Authentication(
                AuthenticationError::ActorHasNoRolesOnTarget,
            ))
        });

    let provider = Provider::mocked_builder()
        .mock_assignment(assignment_mock)
        .mock_identity(identity_mock)
        .mock_resource(resource_mock)
        .mock_token(token_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "auth": {
                            "identity": {
                                "methods": ["password"],
                                "password": {
                                    "user": {
                                        "id": "uid",
                                        "name": "uname",
                                        "domain": {
                                            "id": "udid",
                                            "name": "udname"
                                        },
                                        "password": "pass",
                                    },
                                },
                            },
                            "scope": {
                                "project": {
                                    "id": "pid",
                                    "name": "pname",
                                    "domain": {
                                        "id": "pdid",
                                        "name": "pdname"
                                    }
                                }
                            }
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[traced_test]
async fn test_post_project_disabled() {
    let config = Config::default();
    let mut identity_mock = MockIdentityProvider::default();
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
        })
        .build()
        .unwrap();
    let auth_clone = auth.clone();
    identity_mock
        .expect_authenticate_by_password()
        .returning(move |_, _| Ok(auth_clone.clone()));
    identity_mock.expect_get_user().returning(|_, _| {
        Ok(Some(user_with_options(
            openstack_keystone_core_types::identity::UserOptions::default(),
        )))
    });

    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_get_project()
        .withf(|_, id: &'_ str| id == "pid")
        .returning(move |_, _| {
            Ok(Some(Project {
                id: "pid".into(),
                domain_id: "pdid".into(),
                enabled: false,
                ..Default::default()
            }))
        });
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "pdid")
        .returning(move |_, _| {
            Ok(Some(Domain {
                id: "pdid".into(),
                name: "pdname".into(),
                enabled: true,
                ..Default::default()
            }))
        });

    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .mock_resource(resource_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "auth": {
                            "identity": {
                                "methods": ["password"],
                                "password": {
                                    "user": {
                                        "id": "uid",
                                        "name": "uname",
                                        "domain": {
                                            "id": "udid",
                                            "name": "udname"
                                        },
                                        "password": "pass",
                                    },
                                },
                            },
                            "scope": {
                                "project": {
                                    "id": "pid",
                                    "name": "pname",
                                    "domain": {
                                        "id": "pdid",
                                        "name": "pdname"
                                    }
                                }
                            }
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// Build a minimal JSON body that passes `req.validate()`.
fn auth_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "id": "uid",
                        "name": "uname",
                        "domain": { "id": "udid", "name": "udname" },
                        "password": "pass"
                    }
                }
            }
        }
    }))
    .unwrap()
}

#[tokio::test]
#[traced_test]
async fn test_rate_limit_returns_429_after_burst_exhausted() {
    // burst_size=1: the first request consumes the single burst token and
    // passes through to auth; the second must be rejected with 429 before
    // authenticate_request is ever called.
    let config = Config {
        rate_limit_global_ip: RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        },
        ..Config::default()
    };

    // The first request reaches identity — we return an error so we don't
    // need the full auth fixture.  The second must never reach identity at
    // all (rate limited before authenticate_request).
    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .once()
        .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));

    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let client_addr: SocketAddr = "203.0.113.1:1234".parse().unwrap();

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // First request — passes the rate limit, fails at auth → not 429.
    let mut req1 = Request::builder()
        .uri("/")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(auth_body()))
        .unwrap();
    req1.extensions_mut().insert(ConnectInfo(client_addr));
    let resp1 = api.as_service().oneshot(req1).await.unwrap();
    assert_ne!(
        resp1.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "first request must not be rate-limited"
    );

    // Second request from the same IP — burst exhausted → 429 +
    // Retry-After.
    let mut req2 = Request::builder()
        .uri("/")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(auth_body()))
        .unwrap();
    req2.extensions_mut().insert(ConnectInfo(client_addr));
    let resp2 = api.as_service().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        resp2.headers().contains_key(header::RETRY_AFTER),
        "429 response must carry Retry-After header"
    );
}

#[tokio::test]
#[traced_test]
async fn test_audit_initiator_address_uses_resolved_ip_behind_trusted_proxy() {
    // The raw TCP peer (`ConnectInfo`) is a trusted reverse proxy; the
    // audited `initiator.host.address` must be the XFF-resolved real
    // client, never the proxy's own address. Regression test for a bug
    // where `public_ingress_peer_addr`'s raw peer was recorded directly,
    // which would silently record every proxy's IP in production.
    let mut config = Config::default();
    config
        .oslo_middleware
        .trusted_proxies
        .push("10.0.0.0/8".parse().unwrap());

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));
    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .build()
        .unwrap();

    let (audit_dispatcher, mut receivers) = AuditDispatcher::new(
        "test-node",
        uuid::Uuid::new_v4().to_string(),
        Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
        0,
    );

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            audit_dispatcher,
            None,
        )
        .await
        .unwrap(),
    );

    let peer: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let mut request = Request::builder()
        .uri("/")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "203.0.113.55")
        .body(Body::from(auth_body()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let _ = api.as_service().oneshot(request).await.unwrap();

    let event = receivers
        .perimeter
        .try_recv()
        .expect("perimeter audit event should have been emitted");
    assert_eq!(
        event.payload().initiator().address(),
        Some("203.0.113.55"),
        "audit initiator must carry the XFF-resolved client IP, not the trusted proxy's own address"
    );
}

#[tokio::test]
#[traced_test]
async fn test_rate_limit_uses_xff_only_for_trusted_peer() {
    let mut config = Config {
        rate_limit_global_ip: RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        },
        ..Config::default()
    };
    config
        .rate_limit_trusted_proxies
        .trusted_proxies
        .push("10.0.0.0/8".parse().unwrap());

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .times(2)
        .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));
    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .build()
        .unwrap();
    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );
    let peer: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    for client_ip in ["203.0.113.1", "203.0.113.2"] {
        let mut request = Request::builder()
            .uri("/")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", client_ip)
            .body(Body::from(auth_body()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        let response = api.as_service().oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    let mut request = Request::builder()
        .uri("/")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "203.0.113.1")
        .body(Body::from(auth_body()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = api.as_service().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// ADR-0022 phase 2: the per-user limiter trips deep in the identity
/// driver (post-lookup, pre-hash); this proves the rejection surfaces
/// through the handler as the same uniform 429 + `Retry-After` response
/// the global-IP limiter produces (Invariant 3).
#[tokio::test]
#[traced_test]
async fn test_user_rate_limit_from_driver_surfaces_as_429() {
    let config = Config::default();

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .once()
        .returning(|_, _| {
            Err(IdentityProviderError::TooManyRequests {
                retry_after_secs: 3,
            })
        });

    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(auth_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("429 must carry Retry-After")
            .to_str()
            .unwrap(),
        "3"
    );
}

#[tokio::test]
#[traced_test]
async fn test_rate_limit_honours_rfc7239_forwarded_header() {
    // End-to-end through the real handler: explicitly selecting RFC 7239
    // `Forwarded` buckets by that client, ignores a co-present XFF value,
    // and throttles the third hit on the same Forwarded client.
    let mut config = Config {
        rate_limit_global_ip: RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        },
        ..Config::default()
    };
    config
        .rate_limit_trusted_proxies
        .trusted_proxies
        .push("10.0.0.0/8".parse().unwrap());
    config.rate_limit_trusted_proxies.trusted_header = ProxyHeader::Forwarded;

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .times(2)
        .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));
    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .build()
        .unwrap();
    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );
    let peer: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Two distinct Forwarded clients each get their own bucket. The
    // co-present XFF is ignored because this boundary selected Forwarded.
    for client_ip in ["203.0.113.1", "203.0.113.2"] {
        let mut request = Request::builder()
            .uri("/")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .header("forwarded", format!("for={client_ip};proto=https"))
            .header("x-forwarded-for", "198.51.100.7")
            .body(Body::from(auth_body()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        let response = api.as_service().oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // Same Forwarded client again is throttled, even with a fresh ignored
    // XFF.
    let mut request = Request::builder()
        .uri("/")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header("forwarded", "for=203.0.113.1;proto=https")
        .header("x-forwarded-for", "198.51.100.8")
        .body(Body::from(auth_body()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = api.as_service().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
#[traced_test]
async fn test_rate_limit_does_not_apply_to_internal_connect_info() {
    // The SPIFFE listener now records ConnectInfo for audit logging. The
    // explicit Internal interface must still bypass the public limiter.
    let config = Config {
        rate_limit_global_ip: RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        },
        ..Config::default()
    };

    let mut identity_mock = MockIdentityProvider::default();
    // Two calls expected — both reach identity, neither is rate-limited.
    identity_mock
        .expect_authenticate_by_password()
        .times(2)
        .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));

    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let peer: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    // Both requests carry the shared mesh peer but must still reach
    // identity.
    for _ in 0..2 {
        let mut request = Request::builder()
            .uri("/")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(auth_body()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request.extensions_mut().insert(Interface::Internal);
        let resp = api.as_service().oneshot(request).await.unwrap();
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

/// End-to-end path: drive the real `create` route through the exact
/// make-service the public listener uses
/// (`into_make_service_with_connect_info::<SocketAddr>`) with a fixed peer
/// address, so the `ConnectInfo<SocketAddr>` extension is populated by axum
/// itself — not injected by the test. This proves the whole chain wires up:
/// TCP peer → `ConnectInfo` extension → `PeerAddr` extractor → `check_ip`
/// → 429 + `Retry-After`. Confirms the `401 → 429`
/// flip the manual `curl` loop in the PR test plan would show, without a
/// live database or socket (`Connected<SocketAddr> for SocketAddr` drives
/// the make-service with a synthetic peer).
#[tokio::test]
#[traced_test]
async fn test_rate_limit_429_over_connect_info_make_service() {
    use axum::ServiceExt as AxumServiceExt;

    let config = Config {
        rate_limit_global_ip: RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        },
        ..Config::default()
    };

    // Identity returns an auth failure so the first (non-limited) request
    // resolves without the full token fixture; it must be called exactly
    // once — the second request is rejected before reaching identity.
    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .once()
        .returning(|_, _| Err(IdentityProviderError::UserNotFound("uid".into())));

    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    // Same make-service path as `spawn_public_listener`; explicit request
    // type satisfies inference (E0284), as in the binary.
    let (router, _) = openapi_router().split_for_parts();
    let app = router.with_state(state.clone());
    let make =
        AxumServiceExt::<Request<Body>>::into_make_service_with_connect_info::<SocketAddr>(app);
    let peer: SocketAddr = "203.0.113.7:4444".parse().unwrap();

    let post = || {
        Request::builder()
            .uri("/")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(auth_body()))
            .unwrap()
    };

    // First request from the peer: passes rate limit, fails at auth → not
    // 429.
    let svc1 = make.clone().oneshot(peer).await.unwrap();
    let resp1 = svc1.oneshot(post()).await.unwrap();
    assert_ne!(
        resp1.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "first request from a fresh IP must not be rate-limited"
    );

    // Second request from the same peer: burst spent → 429 + Retry-After.
    let svc2 = make.clone().oneshot(peer).await.unwrap();
    let resp2 = svc2.oneshot(post()).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        resp2.headers().contains_key(header::RETRY_AFTER),
        "429 response must carry a Retry-After header"
    );
}

fn app_cred_auth_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {
                    "id": "app_cred_id",
                    "secret": "app_cred_secret"
                }
            }
        }
    }))
    .unwrap()
}

fn app_cred_auth_body_by_name() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {
                    "name": "my_app_cred",
                    "secret": "app_cred_secret",
                    "user": {
                        "id": "uid"
                    }
                }
            }
        }
    }))
    .unwrap()
}

#[tokio::test]
#[traced_test]
async fn test_post_application_credential() {
    let config = Config::default();
    let project = Project {
        id: "pid".into(),
        domain_id: "pdid".into(),
        enabled: true,
        ..Default::default()
    };
    let user_domain = Domain {
        id: "user_domain_id".into(),
        enabled: true,
        ..Default::default()
    };
    let project_domain = Domain {
        id: "pdid".into(),
        enabled: true,
        ..Default::default()
    };

    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(|_, _| Ok(Vec::new()));

    let mut catalog_mock = MockCatalogProvider::default();
    catalog_mock
        .expect_get_catalog()
        .returning(|_, _| Ok(std::sync::Arc::new(Vec::new())));

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::ApplicationCredential {
            application_credential: openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder::default()
                .id("app_cred_id")
                .name("my_app_cred")
                .project_id("pid")
                .user_id("uid")
                .unrestricted(false)
                .roles(vec![])
                .build()
                .unwrap(),
            token: None,
        })
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
        })
        .build()
        .unwrap();

    let mut app_cred_mock = MockApplicationCredentialProvider::default();
    app_cred_mock
        .expect_authenticate_by_application_credential()
        .returning(move |_, _| Ok(auth.clone()));

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock.expect_get_user().returning(|_, _| {
        use openstack_keystone_core_types::identity::UserResponse;
        Ok(Some(UserResponse {
            id: "uid".into(),
            name: "uname".into(),
            domain_id: "user_domain_id".into(),
            enabled: true,
            default_project_id: None,
            extra: std::collections::HashMap::new(),
            federated: None,
            options: openstack_keystone_core_types::identity::UserOptions::default(),
            password_expires_at: None,
        }))
    });

    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_get_project()
        .withf(|_, id: &'_ str| id == "pid")
        .returning(move |_, _| Ok(Some(project.clone())));
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "user_domain_id")
        .returning(move |_, _| Ok(Some(user_domain.clone())));
    resource_mock
        .expect_get_domain()
        .withf(|_, id: &'_ str| id == "pdid")
        .returning(move |_, _| Ok(Some(project_domain.clone())));

    let mut token_mock = MockTokenProvider::default();
    let vsc_for_mock = {
        use openstack_keystone_core_types::auth::AuthzInfoBuilder;
        use openstack_keystone_core_types::resource::ProjectRefBuilder;
        use openstack_keystone_core_types::token::FernetToken;
        let user_resp = openstack_keystone_core_types::identity::UserResponseBuilder::default()
            .id("uid")
            .name("uname".to_string())
            .domain_id("user_domain_id".to_string())
            .enabled(true)
            .build()
            .unwrap();
        let fernet_payload = openstack_keystone_core_types::token::ProjectScopePayload {
            user_id: "uid".into(),
            methods: Vec::from(["application_credential".to_string()]),
            project_id: "pid".into(),
            ..Default::default()
        };
        let authz = AuthzInfoBuilder::default()
            .roles(vec![])
            .scope(ScopeInfo::Project {
                project: ProjectRefBuilder::default()
                    .id("pid")
                    .domain_id("pdid")
                    .enabled(true)
                    .name("pname")
                    .build()
                    .unwrap(),
                project_domain: openstack_keystone_core_types::resource::DomainRefBuilder::default(
                )
                .id("pdid")
                .name("pdname")
                .enabled(true)
                .build()
                .unwrap(),
            })
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential: openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder::default()
                    .id("app_cred_id")
                    .name("my_app_cred")
                    .project_id("pid")
                    .user_id("uid")
                    .unrestricted(false)
                    .roles(vec![])
                    .build()
                    .unwrap(),
                token: None,
            })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user_resp)
                        .user_domain(
                            DomainBuilder::default()
                                .id("user_domain_id")
                                .name("user_domain_name")
                                .enabled(true)
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                ),
            })
            .token(FernetToken::ProjectScope(fernet_payload))
            .authorization(authz)
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    };
    let vsc_clone = vsc_for_mock.clone();
    token_mock
        .expect_issue_token_context()
        .returning(move |_, _, _| Ok(vsc_clone.clone()));
    token_mock
        .expect_encode_token()
        .returning(|_| Ok("token".to_string()));

    let provider = Provider::mocked_builder()
        .mock_application_credential(app_cred_mock)
        .mock_assignment(assignment_mock)
        .mock_catalog(catalog_mock)
        .mock_identity(identity_mock)
        .mock_resource(resource_mock)
        .mock_token(token_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(app_cred_auth_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let res: TokenResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(vec!["application_credential"], res.token.methods);
}

#[tokio::test]
#[traced_test]
async fn test_post_application_credential_explicit_scope_forbidden() {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::ApplicationCredential {
            application_credential: openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder::default()
                .id("app_cred_id")
                .name("my_app_cred")
                .project_id("pid")
                .user_id("uid")
                .unrestricted(false)
                .roles(vec![])
                .build()
                .unwrap(),
            token: None,
        })
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
        })
        .build()
        .unwrap();
    let mut app_cred_mock = MockApplicationCredentialProvider::default();
    app_cred_mock
        .expect_authenticate_by_application_credential()
        .returning(move |_, _| Ok(auth.clone()));
    // No other provider is mocked: the request must be rejected before
    // scope resolution and token issuance.
    let provider = Provider::mocked_builder()
        .mock_application_credential(app_cred_mock)
        .build()
        .unwrap();
    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(Config::default()),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );
    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // Even the credential's own project must not be requested.
    let body = serde_json::to_vec(&json!({
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {"id": "app_cred_id", "secret": "app_cred_secret"}
            },
            "scope": {"project": {"id": "pid"}}
        }
    }))
    .unwrap();
    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[traced_test]
async fn test_post_application_credential_auth_failed() {
    let config = Config::default();

    let mut app_cred_mock = MockApplicationCredentialProvider::default();
    app_cred_mock
        .expect_authenticate_by_application_credential()
        .returning(|_, _| {
            Err(
                openstack_keystone_core_types::application_credential::ApplicationCredentialProviderError::AuthenticationFailed,
            )
        });

    let provider = Provider::mocked_builder()
        .mock_application_credential(app_cred_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(app_cred_auth_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[traced_test]
async fn test_post_application_credential_by_name() {
    let config = Config::default();

    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::ApplicationCredential {
            application_credential: openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder::default()
                .id("app_cred_id")
                .name("my_app_cred")
                .project_id("pid")
                .user_id("uid")
                .unrestricted(false)
                .roles(vec![])
                .build()
                .unwrap(),
            token: None,
        })
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
        })
        .build()
        .unwrap();

    let mut app_cred_mock = MockApplicationCredentialProvider::default();
    app_cred_mock
        .expect_authenticate_by_application_credential()
        .withf(|_, auth: &ApplicationCredentialAuthRequest| {
matches!(&auth.credential, ApplicationCredentialAuthData::Name(by_name) if by_name.name == "my_app_cred")
})
.returning(move |_, _| Ok(auth.clone()));

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock.expect_get_user().returning(|_, _| {
        use openstack_keystone_core_types::identity::UserResponse;
        Ok(Some(UserResponse {
            id: "uid".into(),
            name: "uname".into(),
            domain_id: "user_domain_id".into(),
            enabled: true,
            default_project_id: None,
            extra: std::collections::HashMap::new(),
            federated: None,
            options: openstack_keystone_core_types::identity::UserOptions::default(),
            password_expires_at: None,
        }))
    });

    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock
        .expect_list_role_assignments()
        .returning(|_, _| Ok(Vec::new()));

    let mut catalog_mock = MockCatalogProvider::default();
    catalog_mock
        .expect_get_catalog()
        .returning(|_, _| Ok(std::sync::Arc::new(Vec::new())));

    let mut resource_mock = MockResourceProvider::default();
    resource_mock.expect_get_project().returning(move |_, _| {
        Ok(Some(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        }))
    });
    resource_mock.expect_get_domain().returning(move |_, _| {
        Ok(Some(Domain {
            id: "pdid".into(),
            enabled: true,
            ..Default::default()
        }))
    });

    let mut token_mock = MockTokenProvider::default();
    let vsc_for_mock = {
        use openstack_keystone_core_types::auth::AuthzInfoBuilder;
        use openstack_keystone_core_types::resource::ProjectRefBuilder;
        use openstack_keystone_core_types::token::FernetToken;
        let user_resp = openstack_keystone_core_types::identity::UserResponseBuilder::default()
            .id("uid")
            .name("uname".to_string())
            .domain_id("user_domain_id".to_string())
            .enabled(true)
            .build()
            .unwrap();
        let fernet_payload = openstack_keystone_core_types::token::ProjectScopePayload {
            user_id: "uid".into(),
            methods: Vec::from(["application_credential".to_string()]),
            project_id: "pid".into(),
            ..Default::default()
        };
        let authz = AuthzInfoBuilder::default()
            .roles(vec![])
            .scope(ScopeInfo::Project {
                project: ProjectRefBuilder::default()
                    .id("pid")
                    .domain_id("pdid")
                    .enabled(true)
                    .name("pname")
                    .build()
                    .unwrap(),
                project_domain: openstack_keystone_core_types::resource::DomainRefBuilder::default(
                )
                .id("pdid")
                .name("pdname")
                .enabled(true)
                .build()
                .unwrap(),
            })
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential: openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder::default()
                    .id("app_cred_id")
                    .name("my_app_cred")
                    .project_id("pid")
                    .user_id("uid")
                    .unrestricted(false)
                    .roles(vec![])
                    .build()
                    .unwrap(),
                token: None,
            })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user_resp)
                        .user_domain(
                            DomainBuilder::default()
                                .id("user_domain_id")
                                .name("user_domain_name")
                                .enabled(true)
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                ),
            })
            .token(FernetToken::ProjectScope(fernet_payload))
            .authorization(authz)
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    };
    let vsc_clone = vsc_for_mock.clone();
    token_mock
        .expect_issue_token_context()
        .returning(move |_, _, _| Ok(vsc_clone.clone()));
    token_mock
        .expect_encode_token()
        .returning(|_| Ok("token".to_string()));

    let provider = Provider::mocked_builder()
        .mock_application_credential(app_cred_mock)
        .mock_assignment(assignment_mock)
        .mock_catalog(catalog_mock)
        .mock_identity(identity_mock)
        .mock_resource(resource_mock)
        .mock_token(token_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(app_cred_auth_body_by_name()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
#[traced_test]
async fn test_post_application_credential_expired() {
    let config = Config::default();

    let mut app_cred_mock = MockApplicationCredentialProvider::default();
    app_cred_mock
        .expect_authenticate_by_application_credential()
.returning(|_, _| {
                Err(
                openstack_keystone_core_types::application_credential::ApplicationCredentialProviderError::ApplicationCredentialExpired,
            )
        });

    let provider = Provider::mocked_builder()
        .mock_application_credential(app_cred_mock)
        .build()
        .unwrap();

    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(config),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let response = api
        .as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(app_cred_auth_body()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_failure_after_authentication_is_attributed_to_the_principal() {
    use axum::extract::ConnectInfo;
    // The password is correct but the requested project does not exist:
    // an authorization failure by a known user, which the audit record
    // must say (ADR 0023 Phase 2), not an `unknown` caller.
    const USER_ID: &str = "0123456789abcdef0123456789abcdef";
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(USER_ID)
                    .build()
                    .unwrap(),
            ),
        })
        .build()
        .unwrap();
    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_authenticate_by_password()
        .returning(move |_, _| Ok(auth.clone()));
    identity_mock.expect_get_user().returning(|_, _| {
        Ok(Some(user_with_options(
            openstack_keystone_core_types::identity::UserOptions::default(),
        )))
    });
    let mut resource_mock = MockResourceProvider::default();
    resource_mock
        .expect_get_project()
        .returning(|_, _| Ok(None));
    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .mock_resource(resource_mock)
        .build()
        .unwrap();

    let (audit_dispatcher, mut receivers) = AuditDispatcher::new(
        "test-node",
        uuid::Uuid::new_v4().to_string(),
        Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
        0,
    );
    let state = Arc::new(
        Service::new(
            ConfigManager::not_watched(Config::default()),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            audit_dispatcher,
            None,
        )
        .await
        .unwrap(),
    );

    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    let body = serde_json::to_vec(&json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {"user": {"id": USER_ID, "password": "pass"}}
            },
            "scope": {"project": {"id": "missing"}}
        }
    }))
    .unwrap();
    let mut request = Request::builder()
        .uri("/")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "198.51.100.4:5555".parse::<SocketAddr>().unwrap(),
    ));
    let response = api.as_service().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let event = receivers.perimeter.try_recv().expect("event");
    let initiator = event.payload().initiator();
    assert_eq!(initiator.id(), USER_ID);
    assert_eq!(initiator.address(), Some("198.51.100.4"));
    assert_eq!(event.payload().outcome(), Outcome::Failure);
}
