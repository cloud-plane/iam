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

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use sea_orm::DatabaseConnection;
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use tower_http::trace::TraceLayer;

use cadf::AuditDispatcher;
use openstack_keystone_config::{
    Config, ConfigManager, DynamicPluginsSection, PluginMode, TokenProviderDriver,
};
use openstack_keystone_core::auth_plugin_http::DynamicPluginHttpFetcher;
use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::identity::UserResponseBuilder;
use openstack_keystone_core_types::resource::DomainBuilder;

use crate::api::KeystoneApiError;
use crate::api::v3::auth::token::create::dpop_binding;
use crate::api::v3::auth::token::types::*;
use crate::auth_plugin_identity::MockDynamicPluginIdentityProvider;
use crate::auth_plugin_startup::load_auth_plugins;
use crate::catalog::MockCatalogProvider;
use crate::identity::MockIdentityProvider;
use crate::keystone::{Service, ServiceState};
use crate::mapping::MockMappingProvider;
use crate::policy::MockPolicy;
use crate::provider::Provider;
use crate::token::MockTokenProvider;

use super::super::openapi_router;

struct UnreachableHttpFetcher;

#[async_trait::async_trait]
impl DynamicPluginHttpFetcher for UnreachableHttpFetcher {
    async fn fetch(
        &self,
        _method: &str,
        _url: &str,
        _resolved_addr: std::net::SocketAddr,
        _headers: &std::collections::HashMap<String, String>,
        _body: Option<&str>,
        _timeout_ms: u64,
        _auth_header: Option<(&str, &str)>,
        _max_body_bytes: usize,
    ) -> Result<openstack_keystone_core::auth_plugin_http::FetchResponse, String> {
        panic!("this test's plugins don't grant http_fetch")
    }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../auth-plugin-runtime/tests/fixtures/reference-plugin")
}

fn build_reference_plugin() -> (PathBuf, String) {
    let dir = fixture_dir();
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
        .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
        .current_dir(&dir)
        .status()
        .expect("failed to spawn cargo to build the reference plugin fixture");
    assert!(
        status.success(),
        "building the reference plugin fixture failed"
    );

    let wasm_path = dir.join("target/wasm32-unknown-unknown/release/reference_plugin.wasm");
    assert!(
        wasm_path.is_file(),
        "expected build artifact at {}",
        wasm_path.display()
    );
    let bytes = std::fs::read(&wasm_path).unwrap();
    let sha256 = {
        use std::fmt::Write;
        Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    };
    (wasm_path, sha256)
}

/// Base `DynamicPluginConfig` with every non-essential field at its
/// documented default (`crates/config/src/auth_plugins.rs`) - no
/// `Default` impl exists on the struct itself.
fn base_plugin_config(
    path: PathBuf,
    sha256: String,
    mode: PluginMode,
) -> openstack_keystone_config::DynamicPluginConfig {
    openstack_keystone_config::DynamicPluginConfig {
        path,
        sha256,
        mode,
        capabilities: Vec::new(),
        exposed_headers: Vec::new(),
        allowed_hosts: Vec::new(),
        http_fetch_follow_redirects: false,
        http_fetch_auth_header: None,
        http_fetch_auth_secret_env: None,
        provision_domain_id: None,
        allowed_provision_domains: Vec::new(),
        assign_role_allowed: Vec::new(),
        inspect_methods: Vec::new(),
        route_targets: Vec::new(),
        timeout_ms: 1_000,
        fuel_limit: 10_000_000,
        memory_limit_mb: 16,
        invocation_rate_limit_per_source_per_minute: 20,
        invocation_rate_limit_per_minute: 300,
        max_concurrent_invocations: 16,
        valid_since: None,
    }
}

async fn build_state(cfg: Config, provider: Provider, plugin_names: &[&str]) -> ServiceState {
    let (audit_dispatcher, receivers) = AuditDispatcher::new(
        "test-node",
        uuid::Uuid::new_v4().to_string(),
        Arc::from(b"test-hmac-key-32-bytes-long!!!!".as_slice()),
        0,
    );
    std::mem::forget(receivers);

    let state: ServiceState = Arc::new(
        Service::new(
            ConfigManager::not_watched(cfg),
            DatabaseConnection::default(),
            provider,
            Arc::new(MockPolicy::default()),
            audit_dispatcher,
            None,
        )
        .await
        .unwrap(),
    );

    load_auth_plugins(&state, Arc::new(UnreachableHttpFetcher)).await;
    for name in plugin_names {
        assert!(
            state.auth_plugin_registry.read().await.contains(name),
            "reference plugin {name} should have loaded"
        );
    }
    state
}

fn user_response(
    id: &str,
    domain_id: &str,
) -> openstack_keystone_core_types::identity::UserResponse {
    UserResponseBuilder::default()
        .id(id.to_string())
        .domain_id(domain_id.to_string())
        .name("dave".to_string())
        .enabled(true)
        .build()
        .unwrap()
}

fn canned_vsc(
    ctx: AuthenticationContext,
) -> openstack_keystone_core::auth::ValidatedSecurityContext {
    let user = UserResponseBuilder::default()
        .id("uid")
        .name("uname".to_string())
        .domain_id("user_domain_id".to_string())
        .enabled(true)
        .build()
        .unwrap();
    let sc = SecurityContext::test_build()
        .authentication_context(ctx)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .user(user)
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
        .token(openstack_keystone_core_types::token::FernetToken::Unscoped(
            openstack_keystone_core_types::token::UnscopedPayload::default(),
        ))
        .build();
    openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
}

fn mock_token_and_catalog() -> (MockTokenProvider, MockCatalogProvider) {
    let mut token_mock = MockTokenProvider::default();
    token_mock
        .expect_encode_bound_token()
        .returning(|_, _, _, _| Ok("token".to_string()));
    let mut catalog_mock = MockCatalogProvider::default();
    catalog_mock
        .expect_get_catalog()
        .returning(|_, _| Ok(std::sync::Arc::new(Vec::new())));
    (token_mock, catalog_mock)
}

async fn post(state: &ServiceState, body: serde_json::Value) -> axum::response::Response {
    let mut api = openapi_router()
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());
    api.as_service()
        .oneshot(
            Request::builder()
                .uri("/")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// (1) A `mapping`-mode plugin's claims correctly drive the Mapping
/// Engine and the resulting `AuthenticationContext::Mapping` correctly
/// produces an `X-Subject-Token` over real HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_mapping_plugin_issues_token() {
    let (path, sha256) = build_reference_plugin();
    let mut plugin_cfg = base_plugin_config(path, sha256, PluginMode::Mapping);
    plugin_cfg.inspect_methods = Vec::new();
    let cfg = Config {
        auth_plugins: DynamicPluginsSection {
            plugins: vec!["mapper".to_string()],
            ..Default::default()
        },
        auth_plugin: [("mapper".to_string(), plugin_cfg)].into_iter().collect(),
        ..Default::default()
    };

    let mut mapping_mock = MockMappingProvider::default();
    let vsc = canned_vsc(AuthenticationContext::Mapping(
        openstack_keystone_core_types::mapping::auth::MappingContext {
            mapping_id: "m1".to_string(),
            matched_rule_name: "r1".to_string(),
            virtual_user_id: "vu1".to_string(),
            is_system: false,
        },
    ));
    mapping_mock.expect_authenticate_by_mapping().returning({
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Mapping(
                openstack_keystone_core_types::mapping::auth::MappingContext {
                    mapping_id: "m1".to_string(),
                    matched_rule_name: "r1".to_string(),
                    virtual_user_id: "vu1".to_string(),
                    is_system: false,
                },
            ))
            .principal(PrincipalInfo {
                // The mapping engine yields a workload principal, like
                // production: it has no user options to look up.
                identity: IdentityInfo::Principal(
                    PrincipalIdentityInfoBuilder::default()
                        .id("vu1")
                        .resolved_user_name("alice")
                        .issuer("test")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        move |_, _| Ok(auth.clone())
    });

    let (mut token_mock, catalog_mock) = mock_token_and_catalog();
    token_mock
        .expect_issue_token_context()
        .returning(move |_, _, _| Ok(vsc.clone()));

    let provider = Provider::mocked_builder()
        .mock_mapping(mapping_mock)
        .mock_token(token_mock)
        .mock_catalog(catalog_mock)
        .build()
        .unwrap();

    let state = build_state(cfg, provider, &["mapper"]).await;

    let response = post(
        &state,
        json!({
            "auth": {
                "identity": {
                    "methods": ["mapper"],
                    "mapper": {"external_id": "alice", "deny": false}
                }
            }
        }),
    )
    .await;

    let status = response.status();
    let has_token = response.headers().contains_key("X-Subject-Token");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(has_token);
    let _res: TokenResponse = serde_json::from_slice(&body).unwrap();
}

/// (2) A `route`-mode plugin redirects an `application_credential`
/// shaped request to an allowlisted real `full_auth` target, which
/// independently provisions the user and issues its own token - proves
/// the full chain: HTTP -> route pre-dispatch -> rewrite -> full_auth
/// dispatch -> `provision_user` -> token issuance -> HTTP response.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_route_to_target_issues_token() {
    let (path, sha256) = build_reference_plugin();
    let mut router_cfg = base_plugin_config(path.clone(), sha256.clone(), PluginMode::Route);
    router_cfg.inspect_methods = vec!["application_credential".to_string()];
    router_cfg.route_targets = vec!["hacked_appcred_handler".to_string()];
    let mut target_cfg = base_plugin_config(path, sha256, PluginMode::FullAuth);
    target_cfg.capabilities = vec!["provision_user".to_string()];
    target_cfg.provision_domain_id = Some("d".to_string());

    let cfg = Config {
        auth_plugins: DynamicPluginsSection {
            plugins: vec!["router".to_string(), "hacked_appcred_handler".to_string()],
            ..Default::default()
        },
        auth_plugin: [
            ("router".to_string(), router_cfg),
            ("hacked_appcred_handler".to_string(), target_cfg),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock
        .expect_create_user()
        .returning(|_, _| Ok(user_response("u1", "d")));
    identity_mock
        .expect_get_user()
        .returning(|_, _| Ok(Some(user_response("u1", "d"))));
    identity_mock
        .expect_get_user_domain_id()
        .returning(|_, _| Ok("d".to_string()));

    let mut dpi_mock = MockDynamicPluginIdentityProvider::default();
    dpi_mock.expect_find().returning(|_, _, _| Ok(None));
    dpi_mock
        .expect_create_or_resolve()
        .returning(|_, _, _, user_id| Ok(user_id.to_string()));

    let (mut token_mock, catalog_mock) = mock_token_and_catalog();
    let vsc = canned_vsc(AuthenticationContext::WasmPlugin {
        plugin_name: "hacked_appcred_handler".to_string(),
        claims: std::collections::HashMap::new(),
        token: None,
    });
    token_mock
        .expect_issue_token_context()
        .returning(move |_, _, _| Ok(vsc.clone()));

    let provider = Provider::mocked_builder()
        .mock_identity(identity_mock)
        .mock_auth_plugin_identity(dpi_mock)
        .mock_token(token_mock)
        .mock_catalog(catalog_mock)
        .build()
        .unwrap();

    let state = build_state(cfg, provider, &["router", "hacked_appcred_handler"]).await;

    let response = post(
        &state,
        json!({
            "auth": {
                "identity": {
                    "methods": ["application_credential"],
                    "application_credential": {"id": "tf-alice", "secret": "tf-alice-secret"}
                }
            }
        }),
    )
    .await;

    let status = response.status();
    let has_token = response.headers().contains_key("X-Subject-Token");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(has_token);
}

/// (3) A `mapping`-mode plugin's `Deny` fails closed all the way to the
/// HTTP layer, without ever invoking the Mapping Engine.
#[tokio::test(flavor = "multi_thread")]
async fn test_post_mapping_plugin_deny_is_unauthorized() {
    let (path, sha256) = build_reference_plugin();
    let plugin_cfg = base_plugin_config(path, sha256, PluginMode::Mapping);
    let cfg = Config {
        auth_plugins: DynamicPluginsSection {
            plugins: vec!["mapper".to_string()],
            ..Default::default()
        },
        auth_plugin: [("mapper".to_string(), plugin_cfg)].into_iter().collect(),
        ..Default::default()
    };

    let mut mapping_mock = MockMappingProvider::default();
    mapping_mock.expect_authenticate_by_mapping().times(0);

    let provider = Provider::mocked_builder()
        .mock_mapping(mapping_mock)
        .build()
        .unwrap();

    let state = build_state(cfg, provider, &["mapper"]).await;

    let response = post(
        &state,
        json!({
            "auth": {
                "identity": {
                    "methods": ["mapper"],
                    "mapper": {"external_id": "mallory", "deny": true}
                }
            }
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A deployment that cannot bind tokens refuses a proof instead of
/// handing back an unbound token the client takes for a bound one.
#[tokio::test]
async fn test_dpop_proof_is_refused_when_tokens_cannot_be_bound() {
    use crate::api::tests::get_mocked_state_with_config;

    let mut config = openstack_keystone_config::Config::default();
    config.default.public_endpoint = Some("https://ks.example".parse().unwrap());
    config.token.provider = TokenProviderDriver::Fernet;
    let state = get_mocked_state_with_config(Provider::mocked_builder(), true, None, config).await;
    let mut headers = HeaderMap::new();
    headers.insert("dpop", "a.b.c".parse().unwrap());
    assert!(matches!(
        dpop_binding(&state, &headers).await,
        Err(KeystoneApiError::BadRequest(_))
    ));
    // No proof, nothing to refuse.
    assert!(matches!(
        dpop_binding(&state, &HeaderMap::new()).await,
        Ok(None)
    ));
}
