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

use super::*;
use crate::db_state::DbState;
use crate::keystone::Service;
use crate::mapping::MockMappingProvider;
use crate::policy::MockPolicy;
use crate::provider::Provider;
use axum::http::request::Parts;
use openstack_keystone_config::{AdminInterface, Config, ConfigManager};

use openstack_keystone_core_types::mapping::MappingProviderError;
use std::sync::Arc;

async fn create_test_state(mapping_provider: MockMappingProvider) -> ServiceState {
    create_test_state_with_config(mapping_provider, Config::default(), None).await
}

async fn create_test_state_with_config(
    mapping_provider: MockMappingProvider,
    config: Config,
    token_provider: Option<crate::token::MockTokenProvider>,
) -> ServiceState {
    let config_manager = ConfigManager::not_watched(config);
    let policy_enforcer = Arc::new(MockPolicy::default());
    let db = sea_orm::DatabaseConnection::default();
    let mut provider_builder = Provider::mocked_builder().mock_mapping(mapping_provider);
    if let Some(token_provider) = token_provider {
        provider_builder = provider_builder.mock_token(token_provider);
    }
    let provider = provider_builder.build().unwrap();
    let service = Service {
        config_manager,
        db: DbState::new(db),
        policy_enforcer,
        provider,
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    };
    Arc::new(service)
}

fn make_parts() -> Parts {
    let (parts, _) = axum::http::Request::new(()).into_parts();
    parts
}

#[tokio::test]
async fn test_spiffe_auth_success() {
    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_authenticate_by_mapping()
        .once()
        .returning(|_, _| {
            Ok(AuthenticationResultBuilder::default()
                .context(AuthenticationContext::Password)
                .principal(
                    PrincipalInfoBuilder::default()
                        .identity(IdentityInfo::Principal(
                            PrincipalIdentityInfoBuilder::default()
                                .id("test-user")
                                .issuer("test.domain")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap())
        });

    let state = create_test_state(mapping_mock).await;
    let mut parts = make_parts();
    parts
        .extensions
        .insert(SpiffeId::new("spiffe://test.domain/test-workload").unwrap());

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_ok());
}

#[test]
fn test_bearer_token() {
    use axum::http::HeaderValue;
    for (header, expected) in [
        ("Bearer abc", Some("abc")),
        ("bearer abc", Some("abc")),
        ("BEARER  abc ", Some("abc")),
        ("Bearer ", None),
        ("Bearer", None),
        ("Basic abc", None),
        ("abc", None),
    ] {
        assert_eq!(
            bearer_token(&HeaderValue::from_static(header)),
            expected,
            "{header}"
        );
    }
    assert_eq!(
        bearer_token(&HeaderValue::from_bytes(b"Bearer \xff").unwrap()),
        None
    );
}

/// An SVID next to a malformed or unbindable `Authorization` header on
/// the internal interface is a 401: no fallback to the mapping engine
/// (which is therefore never called) and no acceptance on the public
/// interface path.
#[tokio::test]
async fn test_svid_with_authorization_never_falls_back() {
    for header in ["bearer", "Basic abc", "Bearer not-a-jwt"] {
        let state = create_test_state(MockMappingProvider::new()).await;
        let mut parts = make_parts();
        parts.extensions.insert(Interface::Internal);
        parts
            .extensions
            .insert(SpiffeId::new("spiffe://test.domain/test-workload").unwrap());
        parts.headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static(header),
        );
        let err = Auth::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();
        assert!(
            matches!(err, KeystoneApiError::Unauthorized { .. }),
            "{header}: {err:?}"
        );
    }
}

/// Off the internal interface the header is not a delegation attempt.
#[tokio::test]
async fn test_svid_with_authorization_on_public_interface_uses_mapping() {
    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_authenticate_by_mapping()
        .once()
        .returning(|_, _| Err(MappingProviderError::NoMatchingRule));
    let state = create_test_state(mapping_mock).await;
    let mut parts = make_parts();
    parts
        .extensions
        .insert(SpiffeId::new("spiffe://test.domain/test-workload").unwrap());
    parts.headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer x"),
    );
    assert!(Auth::from_request_parts(&mut parts, &state).await.is_err());
}

#[tokio::test]
async fn test_spiffe_auth_failure_no_fallback() {
    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_authenticate_by_mapping()
        .once()
        .returning(|_, _| Err(MappingProviderError::NoMatchingRule));

    let state = create_test_state(mapping_mock).await;
    let mut parts = make_parts();
    parts
        .extensions
        .insert(SpiffeId::new("spiffe://test.domain/test-workload").unwrap());

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_spiffe_auth_malformed_svid_path_rejected_before_mapping() {
    let mut mapping_mock = MockMappingProvider::new();
    // A malformed nova-compute host path must be rejected inside
    // `flat_spiffe_claims` itself, before the mapping engine is ever
    // consulted -- this prevents a mapping rule from silently matching
    // on an absent/empty derived claim.
    mapping_mock.expect_authenticate_by_mapping().never();

    let state = create_test_state(mapping_mock).await;
    let mut parts = make_parts();
    parts
        .extensions
        .insert(SpiffeId::new("spiffe://test.domain/service/nova-compute/host/").unwrap());

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(matches!(
        result,
        Err(KeystoneApiError::UnauthorizedNoContext)
    ));
}

#[tokio::test]
async fn test_spiffe_admin_shortcut() {
    use crate::role::MockRoleProvider;

    let mapping_mock = MockMappingProvider::new();
    let config = Config {
        interface_admin: Some(AdminInterface {
            admin_svid: Some("spiffe://admin".to_string()),
            listener: openstack_keystone_config::UnixSocketListener::default(),
        }),
        ..Default::default()
    };
    let config_manager = ConfigManager::not_watched(config);

    let mut role_mock = MockRoleProvider::new();
    role_mock.expect_list_roles().returning(|_e, params| {
        let name = params
            .name
            .clone()
            .unwrap_or_else(|| "unknown-role".to_string());
        Ok(vec![openstack_keystone_core_types::role::Role {
            id: format!("{}-id", name),
            name,
            description: None,
            domain_id: None,
            extra: Default::default(),
            options: Default::default(),
        }])
    });

    let state = Arc::new(Service {
        config_manager,
        db: DbState::new(sea_orm::DatabaseConnection::default()),
        policy_enforcer: Arc::new(MockPolicy::default()),
        provider: Provider::mocked_builder()
            .mock_mapping(mapping_mock)
            .mock_role(role_mock)
            .build()
            .unwrap(),
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    });

    let mut parts = make_parts();
    parts
        .extensions
        .insert(SpiffeId::new("spiffe://admin").unwrap());
    parts.extensions.insert(Interface::Admin);

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_ok());
}

#[test]
fn test_flat_spiffe_claims_structure() {
    let svid = SpiffeId::new("spiffe://example.org/workload/test").unwrap();
    let request = flat_spiffe_claims(&svid).unwrap();

    assert_eq!(
        request.claims.get("spiffe.id").unwrap()[0],
        "spiffe://example.org/workload/test"
    );
    assert_eq!(
        request.claims.get("spiffe.trust_domain").unwrap()[0],
        "example.org"
    );
    assert_eq!(
        request.unique_workload_id,
        "spiffe://example.org/workload/test"
    );
    assert!(matches!(
        request.source,
        IdentitySource::Spiffe { trust_domain } if trust_domain == "example.org"
    ));
    assert!(request.domain_id.is_none());
}

#[test]
fn test_flat_spiffe_claims_long_path() {
    let svid = SpiffeId::new("spiffe://ns1.example.org/system/service/deployment/pod").unwrap();
    let request = flat_spiffe_claims(&svid).unwrap();

    assert_eq!(
        request.claims.get("spiffe.id").unwrap()[0],
        "spiffe://ns1.example.org/system/service/deployment/pod"
    );
    assert_eq!(
        request.claims.get("spiffe.trust_domain").unwrap()[0],
        "ns1.example.org"
    );
}

#[test]
fn test_flat_spiffe_claims_derives_nova_compute_host() {
    let svid =
        SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/compute-1").unwrap();
    let request = flat_spiffe_claims(&svid).unwrap();

    assert_eq!(request.claims.get("spiffe.host").unwrap()[0], "compute-1");
    assert!(!request.claims.contains_key("spiffe.project_id"));
    assert!(!request.claims.contains_key("spiffe.instance_id"));
}

#[test]
fn test_flat_spiffe_claims_derives_project_instance() {
    let svid = SpiffeId::new("spiffe://cloud.trust.domain/project/p1/instance/i1").unwrap();
    let request = flat_spiffe_claims(&svid).unwrap();

    assert_eq!(request.claims.get("spiffe.project_id").unwrap()[0], "p1");
    assert_eq!(request.claims.get("spiffe.instance_id").unwrap()[0], "i1");
    assert!(!request.claims.contains_key("spiffe.host"));
}

#[test]
fn test_flat_spiffe_claims_unrecognized_pattern_ok() {
    let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-api").unwrap();
    let request = flat_spiffe_claims(&svid).unwrap();

    assert!(!request.claims.contains_key("spiffe.host"));
    assert!(!request.claims.contains_key("spiffe.project_id"));
    assert!(!request.claims.contains_key("spiffe.instance_id"));
}

#[test]
fn test_flat_spiffe_claims_rejects_malformed_host_trailing_slash() {
    let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/").unwrap();
    assert!(matches!(
        flat_spiffe_claims(&svid),
        Err(KeystoneApiError::UnauthorizedNoContext)
    ));
}

#[test]
fn test_flat_spiffe_claims_rejects_malformed_host_extra_segment() {
    let svid =
        SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/compute-1/extra")
            .unwrap();
    assert!(matches!(
        flat_spiffe_claims(&svid),
        Err(KeystoneApiError::UnauthorizedNoContext)
    ));
}

#[test]
fn test_flat_spiffe_claims_rejects_malformed_project_missing_instance() {
    let svid = SpiffeId::new("spiffe://cloud.trust.domain/project/p1").unwrap();
    assert!(matches!(
        flat_spiffe_claims(&svid),
        Err(KeystoneApiError::UnauthorizedNoContext)
    ));
}

#[test]
fn test_flat_spiffe_claims_rejects_malformed_project_empty_instance_id() {
    let svid = SpiffeId::new("spiffe://cloud.trust.domain/project/p1/instance/").unwrap();
    assert!(matches!(
        flat_spiffe_claims(&svid),
        Err(KeystoneApiError::UnauthorizedNoContext)
    ));
}

#[tokio::test]
async fn test_admin_svid_on_public_interface_falls_to_mapping() {
    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_authenticate_by_mapping()
        .once()
        .returning(|_, _| {
            Ok(AuthenticationResultBuilder::default()
                .context(AuthenticationContext::Password)
                .principal(
                    PrincipalInfoBuilder::default()
                        .identity(IdentityInfo::Principal(
                            PrincipalIdentityInfoBuilder::default()
                                .id("test-user")
                                .issuer("test.domain")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap())
        });

    let config = Config {
        interface_admin: Some(AdminInterface {
            admin_svid: Some("spiffe://admin".to_string()),
            listener: openstack_keystone_config::UnixSocketListener::default(),
        }),
        ..Default::default()
    };
    let config_manager = ConfigManager::not_watched(config);
    let db = sea_orm::DatabaseConnection::default();
    let provider = Provider::mocked_builder()
        .mock_mapping(mapping_mock)
        .build()
        .unwrap();
    let state = Arc::new(Service {
        config_manager,
        db: DbState::new(db),
        policy_enforcer: Arc::new(MockPolicy::default()),
        provider,
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    });

    let mut parts = make_parts();
    parts
        .extensions
        .insert(SpiffeId::new("spiffe://admin").unwrap());
    parts.extensions.insert(Interface::Public);

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_admin_svid_mismatch_falls_to_mapping() {
    use crate::role::MockRoleProvider;

    // When admin_svid is configured and interface is Admin, but the
    // client's SVID does not match the configured admin_svid, the
    // shortcut is bypassed and the request falls through to the
    // mapping engine. If no mapping rule matches, authentication
    // fails.
    let mut mapping_mock = MockMappingProvider::new();
    mapping_mock
        .expect_authenticate_by_mapping()
        .once()
        .returning(|_, _| Err(MappingProviderError::NoMatchingRule));
    let config = Config {
        interface_admin: Some(AdminInterface {
            admin_svid: Some("spiffe://admin".to_string()),
            listener: openstack_keystone_config::UnixSocketListener::default(),
        }),
        ..Default::default()
    };
    let config_manager = ConfigManager::not_watched(config);

    let mut role_mock = MockRoleProvider::new();
    role_mock.expect_list_roles().returning(|_e, params| {
        let name = params
            .name
            .clone()
            .unwrap_or_else(|| "unknown-role".to_string());
        Ok(vec![openstack_keystone_core_types::role::Role {
            id: format!("{}-id", name),
            name,
            description: None,
            domain_id: None,
            extra: Default::default(),
            options: Default::default(),
        }])
    });

    let state = Arc::new(Service {
        config_manager,
        db: DbState::new(sea_orm::DatabaseConnection::default()),
        policy_enforcer: Arc::new(MockPolicy::default()),
        provider: Provider::mocked_builder()
            .mock_mapping(mapping_mock)
            .mock_role(role_mock)
            .build()
            .unwrap(),
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    });

    // Different SVID than configured admin_svid, on admin interface
    let mut parts = make_parts();
    parts
        .extensions
        .insert(SpiffeId::new("spiffe://other-domain/workload").unwrap());
    parts.extensions.insert(Interface::Admin);

    // No mapping rule matches, no X-Auth-Token fallback — authentication
    // fails
    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_x_auth_token_without_svid_authorizes_via_token() {
    use crate::token::MockTokenProvider;

    let config = Config::default();
    let config_manager = ConfigManager::not_watched(config);
    let policy_enforcer = Arc::new(MockPolicy::default());
    let db = sea_orm::DatabaseConnection::default();

    let mut token_mock = MockTokenProvider::new();
    token_mock
        .expect_authorize_request_token()
        .once()
        .returning(move |_exec, _token| {
            let mut security_context = SecurityContextTestingBuilder::default()
                .authentication_context(AuthenticationContext::Password)
                .principal(
                    PrincipalInfoBuilder::default()
                        .identity(IdentityInfo::Principal(
                            PrincipalIdentityInfoBuilder::default()
                                .id("token-user")
                                .issuer("test.domain")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build();
            // Fully resolve the context by setting authorization
            security_context.set_authorization_scope(ScopeInfo::Unscoped)?;
            Ok(ValidatedSecurityContext::test_new(security_context))
        });

    let provider = Provider::mocked_builder()
        .mock_mapping(MockMappingProvider::new())
        .mock_token(token_mock)
        .build()
        .unwrap();
    let state = Arc::new(Service {
        config_manager,
        db: DbState::new(db),
        policy_enforcer,
        provider,
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    });

    let mut parts = make_parts();
    parts
        .headers
        .insert("X-Auth-Token", "valid-token-string".parse().unwrap());

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_ok());
}

async fn binding_state() -> ServiceState {
    let mut config = Config::default();
    config.default.public_endpoint = Some("https://ks.example".parse().unwrap());
    crate::tests::get_mocked_state(Some(config), None).await
}

fn bound() -> Confirmation {
    Confirmation {
        jkt: "thumb".into(),
    }
}

/// A bound token without a proof is refused, whatever the scheme.
#[tokio::test]
async fn test_bound_token_without_proof_is_rejected() {
    let state = binding_state().await;
    let parts = make_parts();
    for as_dpop in [false, true] {
        assert!(
            enforce_dpop_binding(&state, &parts, "token", Some(&bound()), as_dpop)
                .await
                .is_err()
        );
    }
}

/// An unbound token is fine as a bearer but cannot be presented as DPoP.
#[tokio::test]
async fn test_unbound_token_cannot_be_presented_as_dpop() {
    let state = binding_state().await;
    let parts = make_parts();
    assert!(
        enforce_dpop_binding(&state, &parts, "token", None, false)
            .await
            .is_ok()
    );
    assert!(
        enforce_dpop_binding(&state, &parts, "token", None, true)
            .await
            .is_err()
    );
}

fn parts_for(uri: &str, proof: &str) -> Parts {
    let (parts, _) = axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("dpop", proof)
        .body(())
        .unwrap()
        .into_parts();
    parts
}

fn proof_key() -> openstack_keystone_key_repository::asymmetric::KeyMaterial {
    use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, generate_keypair};
    generate_keypair(SigningAlgorithm::Es256).unwrap()
}

/// A proof of the bound key for this very request and token passes, as a
/// bearer-style header and as the `DPoP` scheme; the replay does not.
#[tokio::test]
async fn test_bound_token_with_valid_proof_is_accepted() {
    use crate::oauth2_client::dpop_resource::test_proof;

    let state = binding_state().await;
    let key = proof_key();
    let url = "https://ks.example/v3/projects";
    for (n, as_dpop) in [false, true].into_iter().enumerate() {
        let (proof, jkt) = test_proof(&key, "GET", url, &format!("j{n}"), Some("tok"));
        let parts = parts_for("/v3/projects", &proof);
        let cnf = Confirmation { jkt };
        assert!(
            enforce_dpop_binding(&state, &parts, "tok", Some(&cnf), as_dpop)
                .await
                .is_ok()
        );
        assert!(
            enforce_dpop_binding(&state, &parts, "tok", Some(&cnf), as_dpop)
                .await
                .is_err(),
            "replayed proof"
        );
    }
}

#[tokio::test]
async fn test_bound_token_with_foreign_or_misdirected_proof_is_rejected() {
    use crate::oauth2_client::dpop_resource::test_proof;

    let state = binding_state().await;
    let (_, owner) = test_proof(&proof_key(), "GET", "https://x", "o", None);
    let cnf = Confirmation { jkt: owner };
    let url = "https://ks.example/v3/projects";
    // A valid proof of a key that is not the bound one.
    let (foreign, _) = test_proof(&proof_key(), "GET", url, "f1", Some("tok"));
    assert!(
        enforce_dpop_binding(
            &state,
            &parts_for("/v3/projects", &foreign),
            "tok",
            Some(&cnf),
            false
        )
        .await
        .is_err()
    );
    // The bound key, for another path than the one requested.
    let key = proof_key();
    let (other, jkt) = test_proof(
        &key,
        "GET",
        "https://ks.example/v3/users",
        "f2",
        Some("tok"),
    );
    assert!(
        enforce_dpop_binding(
            &state,
            &parts_for("/v3/projects", &other),
            "tok",
            Some(&Confirmation { jkt }),
            false
        )
        .await
        .is_err()
    );
}

/// A proof is checked against the URL the client called, which a nested
/// router no longer shows in `parts.uri`.
#[tokio::test]
async fn test_proof_is_checked_against_the_original_uri() {
    use crate::oauth2_client::dpop_resource::test_proof;

    let state = binding_state().await;
    let key = proof_key();
    let (proof, jkt) = test_proof(
        &key,
        "GET",
        "https://ks.example/v3/projects",
        "n1",
        Some("tok"),
    );
    let mut parts = parts_for("/projects", &proof);
    parts
        .extensions
        .insert(axum::extract::OriginalUri("/v3/projects".parse().unwrap()));
    assert!(
        enforce_dpop_binding(&state, &parts, "tok", Some(&Confirmation { jkt }), false)
            .await
            .is_ok()
    );
}

fn authorization(value: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::AUTHORIZATION, value.parse().unwrap());
    headers
}

/// Only an OAuth2 JWT is read from `Authorization`; `X-Auth-Token` wins.
#[test]
fn test_presented_token_bearer_is_oauth2_only() {
    let jwt = oauth2_shaped_token();
    for scheme in ["Bearer", "bearer", "DPoP"] {
        assert_eq!(
            presented_token(&authorization(&format!("{scheme} {jwt}"))),
            Some(jwt.clone()),
            "{scheme}"
        );
    }
    // A Fernet token (no dots) and a legacy JWS (no `at+jwt` typ).
    let jws = {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(r#"{"iss":"x"}"#)
        )
    };
    for foreign in ["gAAAAABfernet-token", jws.as_str(), "garbage.with.dots"] {
        assert_eq!(
            presented_token(&authorization(&format!("Bearer {foreign}"))),
            None,
            "{foreign}"
        );
    }
    // Other schemes and an empty token are not tokens.
    assert_eq!(presented_token(&authorization("Basic dXNlcjpwdw==")), None);
    assert_eq!(presented_token(&authorization("Bearer ")), None);
    assert_eq!(presented_token(&axum::http::HeaderMap::new()), None);
    // `X-Auth-Token` is taken as is, whatever the format, and wins.
    let mut headers = authorization(&format!("Bearer {jwt}"));
    headers.insert("X-Auth-Token", "gAAAAABfernet-token".parse().unwrap());
    assert_eq!(
        presented_token(&headers),
        Some("gAAAAABfernet-token".to_string())
    );
}

/// A credential shaped like an OAuth2 access token (ADR 0049 section 1).
fn oauth2_shaped_token() -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    format!(
        "{}.{}.sig",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"at+jwt"}"#),
        URL_SAFE_NO_PAD.encode(r#"{"iss":"https://ks.example/v4/oauth2/d1"}"#)
    )
}

#[tokio::test]
async fn test_bearer_without_x_auth_token_authorizes_via_token() {
    use crate::token::MockTokenProvider;

    let config = Config::default();
    let config_manager = ConfigManager::not_watched(config);
    let policy_enforcer = Arc::new(MockPolicy::default());
    let db = sea_orm::DatabaseConnection::default();

    let mut token_mock = MockTokenProvider::new();
    token_mock
        .expect_authorize_request_token()
        .once()
        .returning(move |_exec, _token| {
            let mut security_context = SecurityContextTestingBuilder::default()
                .authentication_context(AuthenticationContext::Password)
                .principal(
                    PrincipalInfoBuilder::default()
                        .identity(IdentityInfo::Principal(
                            PrincipalIdentityInfoBuilder::default()
                                .id("token-user")
                                .issuer("test.domain")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build();
            // Fully resolve the context by setting authorization
            security_context.set_authorization_scope(ScopeInfo::Unscoped)?;
            Ok(ValidatedSecurityContext::test_new(security_context))
        });

    let provider = Provider::mocked_builder()
        .mock_mapping(MockMappingProvider::new())
        .mock_token(token_mock)
        .build()
        .unwrap();
    let state = Arc::new(Service {
        config_manager,
        db: DbState::new(db),
        policy_enforcer,
        provider,
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    });

    let mut parts = make_parts();
    parts.headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {}", oauth2_shaped_token()).parse().unwrap(),
    );

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_non_bearer_authorization_is_not_a_token() {
    use crate::token::MockTokenProvider;

    let config = Config::default();
    let config_manager = ConfigManager::not_watched(config);
    let policy_enforcer = Arc::new(MockPolicy::default());
    let db = sea_orm::DatabaseConnection::default();

    let mut token_mock = MockTokenProvider::new();
    token_mock
        .expect_authorize_request_token()
        .never()
        .returning(move |_exec, _token| {
            let mut security_context = SecurityContextTestingBuilder::default()
                .authentication_context(AuthenticationContext::Password)
                .principal(
                    PrincipalInfoBuilder::default()
                        .identity(IdentityInfo::Principal(
                            PrincipalIdentityInfoBuilder::default()
                                .id("token-user")
                                .issuer("test.domain")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build();
            // Fully resolve the context by setting authorization
            security_context.set_authorization_scope(ScopeInfo::Unscoped)?;
            Ok(ValidatedSecurityContext::test_new(security_context))
        });

    let provider = Provider::mocked_builder()
        .mock_mapping(MockMappingProvider::new())
        .mock_token(token_mock)
        .build()
        .unwrap();
    let state = Arc::new(Service {
        config_manager,
        db: DbState::new(db),
        policy_enforcer,
        provider,
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    });

    let mut parts = make_parts();
    parts.headers.insert(
        axum::http::header::AUTHORIZATION,
        "Basic dXNlcjpwdw==".parse().unwrap(),
    );

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_err());
}

/// The raw TCP peer (`OriginalPeerAddr`) is a trusted reverse proxy;
/// `peer_addr` on the `Auth`-built `ValidatedSecurityContext` must carry
/// the XFF-resolved real client, never the proxy's own address.
/// Regression test: this extractor previously stamped the raw peer
/// directly, which would silently record every proxy's IP in audit
/// events for every authenticated request behind a reverse proxy.
#[tokio::test]
async fn test_x_auth_token_peer_addr_uses_resolved_ip_behind_trusted_proxy() {
    use crate::net::OriginalPeerAddr;
    use crate::token::MockTokenProvider;

    let mut config = Config::default();
    config
        .oslo_middleware
        .trusted_proxies
        .push("10.0.0.0/8".parse().unwrap());

    let mut token_mock = MockTokenProvider::new();
    token_mock
        .expect_authorize_request_token()
        .once()
        .returning(move |_exec, _token| {
            let mut security_context = SecurityContextTestingBuilder::default()
                .authentication_context(AuthenticationContext::Password)
                .principal(
                    PrincipalInfoBuilder::default()
                        .identity(IdentityInfo::Principal(
                            PrincipalIdentityInfoBuilder::default()
                                .id("token-user")
                                .issuer("test.domain")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build();
            security_context.set_authorization_scope(ScopeInfo::Unscoped)?;
            Ok(ValidatedSecurityContext::test_new(security_context))
        });

    let state =
        create_test_state_with_config(MockMappingProvider::new(), config, Some(token_mock)).await;

    let mut parts = make_parts();
    parts
        .headers
        .insert("X-Auth-Token", "valid-token-string".parse().unwrap());
    parts
        .headers
        .insert("x-forwarded-for", "203.0.113.77".parse().unwrap());
    let peer: std::net::SocketAddr = "10.0.0.1:1234".parse().unwrap();
    parts.extensions.insert(OriginalPeerAddr(peer));

    let result = Auth::from_request_parts(&mut parts, &state).await;
    let auth = result.expect("token auth should succeed");
    assert_eq!(
        auth.0.inner().peer_addr(),
        Some("203.0.113.77"),
        "peer_addr must be the XFF-resolved client, not the trusted proxy's own address"
    );
}

#[tokio::test]
async fn test_x_auth_token_ec2credential_rejected() {
    use crate::token::MockTokenProvider;

    let config = Config::default();
    let config_manager = ConfigManager::not_watched(config);
    let policy_enforcer = Arc::new(MockPolicy::default());
    let db = sea_orm::DatabaseConnection::default();

    let mut token_mock = MockTokenProvider::new();
    token_mock
        .expect_authorize_request_token()
        .once()
        .returning(move |_exec, _token| {
            let mut security_context = SecurityContextTestingBuilder::default()
                .authentication_context(AuthenticationContext::Ec2Credential)
                .principal(
                    PrincipalInfoBuilder::default()
                        .identity(IdentityInfo::Principal(
                            PrincipalIdentityInfoBuilder::default()
                                .id("token-user")
                                .issuer("test.domain")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build();
            // Fully resolve the context by setting authorization
            security_context.set_authorization_scope(ScopeInfo::Unscoped)?;
            Ok(ValidatedSecurityContext::test_new(security_context))
        });

    let provider = Provider::mocked_builder()
        .mock_mapping(MockMappingProvider::new())
        .mock_token(token_mock)
        .build()
        .unwrap();
    let state = Arc::new(Service {
        config_manager,
        db: DbState::new(db),
        policy_enforcer,
        provider,
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    });

    let mut parts = make_parts();
    parts
        .headers
        .insert("X-Auth-Token", "valid-token-string".parse().unwrap());

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        KeystoneApiError::SelectedAuthenticationForbidden
    ));
}

#[tokio::test]
async fn test_x_auth_token_ec2credential_method_rejected() {
    use crate::token::MockTokenProvider;

    let config = Config::default();
    let config_manager = ConfigManager::not_watched(config);
    let policy_enforcer = Arc::new(MockPolicy::default());
    let db = sea_orm::DatabaseConnection::default();

    let mut token_mock = MockTokenProvider::new();
    token_mock
        .expect_authorize_request_token()
        .once()
        .returning(move |_exec, _token| {
            let mut security_context = SecurityContextTestingBuilder::default()
                .authentication_context(AuthenticationContext::Token(Arc::new(
                    openstack_keystone_core_types::token::FernetToken::ProjectScope(
                        openstack_keystone_core_types::token::ProjectScopePayload {
                            user_id: "token-user".into(),
                            methods: vec!["ec2credential".into()],
                            audit_ids: vec![],
                            expires_at: chrono::Utc::now(),
                            project_id: "token-project".into(),
                            ..Default::default()
                        },
                    ),
                )))
                .principal(
                    PrincipalInfoBuilder::default()
                        .identity(IdentityInfo::Principal(
                            PrincipalIdentityInfoBuilder::default()
                                .id("token-user")
                                .issuer("test.domain")
                                .build()
                                .unwrap(),
                        ))
                        .build()
                        .unwrap(),
                )
                .build();
            // Fully resolve the context by setting authorization
            security_context.set_authorization_scope(ScopeInfo::Unscoped)?;
            Ok(ValidatedSecurityContext::test_new(security_context))
        });

    let provider = Provider::mocked_builder()
        .mock_mapping(MockMappingProvider::new())
        .mock_token(token_mock)
        .build()
        .unwrap();
    let state = Arc::new(Service {
        config_manager,
        db: DbState::new(db),
        policy_enforcer,
        provider,
        event_dispatcher: crate::events::EventDispatcher::production(),

        audit_dispatcher: cadf::AuditDispatcher::noop(),

        storage: None,
        local_emergency_store: tokio::sync::RwLock::new(None),
        dpop: Default::default(),
        spiffe_health_check: tokio::sync::RwLock::new(None),
        local_emergency_leaderless_tracker:
            openstack_keystone_local_emergency_store::LeaderlessTracker::new(),
        api_key_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        oauth2_token_rate_limiter: std::sync::Arc::new(governor::RateLimiter::keyed(
            governor::Quota::per_minute(std::num::NonZeroU32::new(60).unwrap()),
        )),
        auth_plugin_registry: tokio::sync::RwLock::new(Arc::new(
            openstack_keystone_auth_plugin_core::EmptyAuthPluginRuntime,
        )),
        core_host_functions: tokio::sync::RwLock::new(None),
        rate_limiters: crate::rate_limit::RateLimitState::default(),
        auth_plugin_limiters: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        shutdown: false,
    });

    let mut parts = make_parts();
    parts
        .headers
        .insert("X-Auth-Token", "valid-token-string".parse().unwrap());

    let result = Auth::from_request_parts(&mut parts, &state).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        KeystoneApiError::SelectedAuthenticationForbidden
    ));
}

/// Gate: security review V5 / ADR 0037. Exercises `enforce_access_rules`
/// through the actual `Auth::from_request_parts` mock-injection path
/// (the same chokepoint production requests go through via the
/// X-Auth-Token branch), rather than calling the private function
/// directly, so a regression here reflects what a real request sees.
mod access_rules {
    use openstack_keystone_core_types::application_credential::{
        AccessRule, AccessRuleBuilder, ApplicationCredential,
    };
    use openstack_keystone_core_types::identity::UserResponseBuilder;

    use super::*;

    fn access_rule(method: &str, path: &str, service: &str) -> AccessRule {
        AccessRuleBuilder::default()
            .id("r1")
            .method(method.to_string())
            .path(path.to_string())
            .service(service.to_string())
            .user_id("u1")
            .build()
            .unwrap()
    }

    fn app_cred_vsc(access_rules: Option<Vec<AccessRule>>) -> ValidatedSecurityContext {
        let ac = ApplicationCredential {
            id: "ac1".to_string(),
            user_id: "u1".to_string(),
            project_id: "p1".to_string(),
            name: "cred".to_string(),
            description: None,
            roles: vec![],
            unrestricted: false,
            expires_at: None,
            access_rules,
        };
        let mut security_context = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential: ac,
                token: None,
            })
            .principal(PrincipalInfo {
                // `AuthenticationResult.principal.identity` for an
                // application credential is always `IdentityInfo::User`
                // (CLAUDE.md's noted gotcha) -- `Principal` is for
                // SPIFFE/workload identities only.
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("u1")
                        .user(
                            UserResponseBuilder::default()
                                .id("u1")
                                .domain_id("d1")
                                .enabled(true)
                                .name("u1")
                                .build()
                                .unwrap(),
                        )
                        .user_domain(openstack_keystone_core_types::resource::Domain {
                            id: "d1".to_string(),
                            enabled: true,
                            name: "d1".to_string(),
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .build();
        // I5: an application credential is permanently bound to its own
        // project -- `Unscoped` is not a legal scope for it, only its
        // own `project_id` (`validate_scope_boundaries`'s
        // `ApplicationCredential` arm).
        security_context
            .set_authorization_scope(ScopeInfo::Project {
                project: openstack_keystone_core_types::resource::ProjectRef {
                    id: "p1".to_string(),
                    domain_id: "d1".to_string(),
                    enabled: true,
                    name: "p1".to_string(),
                    ..Default::default()
                },
                project_domain: openstack_keystone_core_types::resource::DomainRef {
                    id: "d1".to_string(),
                    enabled: true,
                    name: "d1".to_string(),
                    ..Default::default()
                },
            })
            .unwrap();
        ValidatedSecurityContext::test_new(security_context)
    }

    fn parts_for(method: &str, uri: &str) -> Parts {
        let (parts, _) = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .body(())
            .unwrap()
            .into_parts();
        parts
    }

    #[tokio::test]
    async fn no_access_rules_is_unrestricted() {
        let state = create_test_state(MockMappingProvider::new()).await;
        let mut parts = parts_for("DELETE", "/v3/users/1");
        parts.extensions.insert(app_cred_vsc(None));

        let result = Auth::from_request_parts(&mut parts, &state).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn empty_access_rules_list_is_unrestricted() {
        let state = create_test_state(MockMappingProvider::new()).await;
        let mut parts = parts_for("DELETE", "/v3/users/1");
        parts.extensions.insert(app_cred_vsc(Some(vec![])));

        let result = Auth::from_request_parts(&mut parts, &state).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn matching_rule_permits_the_call() {
        let state = create_test_state(MockMappingProvider::new()).await;
        let mut parts = parts_for("GET", "/v3/users");
        parts.extensions.insert(app_cred_vsc(Some(vec![access_rule(
            "GET",
            "/v3/users",
            "identity",
        )])));

        let result = Auth::from_request_parts(&mut parts, &state).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn call_outside_the_rules_is_denied() {
        let state = create_test_state(MockMappingProvider::new()).await;
        let mut parts = parts_for("DELETE", "/v3/users/1");
        parts.extensions.insert(app_cred_vsc(Some(vec![access_rule(
            "GET",
            "/v3/users",
            "identity",
        )])));

        let result = Auth::from_request_parts(&mut parts, &state).await;
        let err = result.expect_err("call outside access_rules must be denied");
        assert!(matches!(err, KeystoneApiError::Forbidden { .. }));
    }

    /// A rule scoped to a different service must never authorize a call
    /// against Keystone's own API (ADR 0037 "Why Keystone can only
    /// enforce its own service's rules").
    #[tokio::test]
    async fn rule_for_a_different_service_does_not_permit_own_api_call() {
        let state = create_test_state(MockMappingProvider::new()).await;
        let mut parts = parts_for("GET", "/v3/users");
        parts.extensions.insert(app_cred_vsc(Some(vec![access_rule(
            "GET",
            "/v3/users",
            "compute",
        )])));

        let result = Auth::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
    }

    /// Non-application-credential auth (e.g. a plain admin/system
    /// principal) is never subject to this check at all.
    #[tokio::test]
    async fn non_app_cred_auth_is_unaffected() {
        let mut mapping_mock = MockMappingProvider::new();
        mapping_mock
            .expect_authenticate_by_mapping()
            .once()
            .returning(|_, _| {
                Ok(AuthenticationResultBuilder::default()
                    .context(AuthenticationContext::Password)
                    .principal(
                        PrincipalInfoBuilder::default()
                            .identity(IdentityInfo::Principal(
                                PrincipalIdentityInfoBuilder::default()
                                    .id("test-user")
                                    .issuer("test.domain")
                                    .build()
                                    .unwrap(),
                            ))
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap())
            });
        let state = create_test_state(mapping_mock).await;
        let mut parts = parts_for("DELETE", "/v3/users/1");
        parts
            .extensions
            .insert(SpiffeId::new("spiffe://test.domain/test-workload").unwrap());

        let result = Auth::from_request_parts(&mut parts, &state).await;
        assert!(result.is_ok());
    }
}

/// A `DPoP` proof sent to an endpoint that cannot bind a token is refused.
#[test]
fn test_reject_dpop_header() {
    let mut headers = axum::http::HeaderMap::new();
    assert!(reject_dpop_header(&headers).is_ok());
    headers.insert("dpop", "proof".parse().unwrap());
    assert!(matches!(
        reject_dpop_header(&headers),
        Err(KeystoneApiError::BadRequest(_))
    ));
}
