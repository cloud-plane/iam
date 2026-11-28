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
// Crypto inventory: TOK-3; see doc/src/contributor/crypto-inventory.md
//! # OAuth2 JWT format of Keystone's own tokens (ADR 0049)
//!
//! The token carries the anchors of a Fernet/JWS token (user, scope, audit
//! chain, methods) as the compact [`KeystoneTokenClaims`] plus the standard
//! registered claims. It carries no roles:
//! Keystone resolves them, and the revocation, on every request.
//!
//! Signed with the key of the user's domain; `iss` is
//! `{public_endpoint}/v4/oauth2/{domain_id}` and selects the verification key.
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

use openstack_keystone_config::TokenProviderDriver;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_client::verify::KEYSTONE_TOKEN_AUDIENCE;
use openstack_keystone_core::oauth2_client::{
    SubjectTokenValidationProfile, TokenVerificationError, verify_subject_token_jwt,
};
use openstack_keystone_core::oauth2_key::{Oauth2KeyProviderError, signing_algorithm};
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::token::TokenProviderError;
use openstack_keystone_core::token::backend::TokenFormatBackend;
use openstack_keystone_core::token::format::OAUTH2_ACCESS_TOKEN_TYP;
use openstack_keystone_core_types::oauth2_client::Confirmation;
use openstack_keystone_core_types::token::{KeystoneTokenClaims, TokenPayload};
use openstack_keystone_key_repository::asymmetric::{derive_kid, jwt_algorithm, to_encoding_key};

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    // Registered only when the format is issued or accepted: a deployment
    // that does not use it must not depend on the OAuth2 key provider.
    BackendRegistration::<dyn TokenFormatBackend> {
        name: "oauth2",
        selected: |cfg| cfg.token.accepts(&TokenProviderDriver::Oauth2),
        build: |_| Box::pin(async {
            Ok(Arc::new(Oauth2TokenFormat) as Arc<dyn TokenFormatBackend>)
        }),
    }
}

/// The OAuth2 JWT format of Keystone tokens. Stateless: the keys, the issuer
/// and the revocations come from the service state of each call.
#[derive(Clone, Copy, Default)]
pub struct Oauth2TokenFormat;

impl fmt::Debug for Oauth2TokenFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Oauth2TokenFormat").finish()
    }
}

#[async_trait]
impl TokenFormatBackend for Oauth2TokenFormat {
    async fn decode<'a>(
        &self,
        state: &ServiceState,
        credential: &'a str,
    ) -> Result<(TokenPayload, Option<Confirmation>), TokenProviderError> {
        decode(state, credential).await
    }

    async fn encode(
        &self,
        state: &ServiceState,
        token: &TokenPayload,
        domain_id: Option<String>,
        cnf: Option<Confirmation>,
    ) -> Result<String, TokenProviderError> {
        encode(state, token, domain_id, cnf).await
    }
}

/// The domain id out of an issuer that is `{prefix}/{domain_id}`.
fn domain_of_issuer(iss: &str, prefix: &str) -> Option<String> {
    iss.strip_prefix(prefix)
        .filter(|d| !d.is_empty() && !d.contains('/'))
        .map(str::to_string)
}

fn invalid(msg: impl Into<String>) -> TokenProviderError {
    TokenProviderError::InvalidToken {
        source: msg.into().into(),
    }
}

/// A token that does not verify: bad signature, claims, algorithm or `typ`.
fn rejected(msg: impl std::fmt::Display) -> TokenProviderError {
    invalid(msg.to_string())
}

/// A failure of Keystone itself (signing, a key store outage), which is not
/// the client's token being invalid and must not read as such.
fn internal(source: impl std::error::Error + Send + Sync + 'static) -> TokenProviderError {
    TokenProviderError::Driver {
        source: Box::new(source),
    }
}

/// An error of the key provider. No keys for an issuer is a forged or foreign
/// `iss` and so an invalid token; everything else is an outage.
fn key_error(error: Oauth2KeyProviderError) -> TokenProviderError {
    match error {
        Oauth2KeyProviderError::NotFound(_) => invalid("no signing keys for the issuer"),
        other => internal(other),
    }
}

async fn issuer_prefix(state: &ServiceState) -> Result<String, TokenProviderError> {
    let config = state.config_manager.config.read().await;
    config
        .default
        .public_endpoint
        .as_ref()
        .map(|e| format!("{}/v4/oauth2/", e.to_string().trim_end_matches('/')))
        .ok_or_else(|| internal(std::io::Error::other("no public endpoint is configured")))
}

/// Encode the token as an OAuth2 JWT signed with the user's domain key.
///
/// `cnf` binds the token to the DPoP proof key of the requester (ADR 0043).
pub async fn encode(
    state: &ServiceState,
    token: &TokenPayload,
    domain_id: Option<String>,
    cnf: Option<Confirmation>,
) -> Result<String, TokenProviderError> {
    let prefix = issuer_prefix(state).await?;
    let domain_id = match domain_id {
        Some(domain_id) => domain_id,
        None => {
            state
                .provider
                .get_identity_provider()
                .get_user_core(&ExecutionContext::internal(state), token.user_id())
                .await?
                .ok_or_else(|| TokenProviderError::UserNotFound(token.user_id().clone()))?
                .domain_id
        }
    };
    let max_groups = state
        .config_manager
        .config
        .read()
        .await
        .token
        .max_federation_groups;
    let groups = match token {
        TokenPayload::FederationUnscoped(p) => p.group_ids.len(),
        TokenPayload::FederationProjectScope(p) => p.group_ids.len(),
        TokenPayload::FederationDomainScope(p) => p.group_ids.len(),
        _ => 0,
    };
    // Never truncate: dropping a group silently drops its roles.
    if groups > max_groups {
        tracing::warn!(
            groups,
            max_groups,
            "federated login refused: more groups than a token may carry"
        );
        return Err(TokenProviderError::TooManyGroups {
            count: groups,
            max: max_groups,
        });
    }
    let mut claims = KeystoneTokenClaims::new(
        token,
        format!("{prefix}{domain_id}"),
        KEYSTONE_TOKEN_AUDIENCE.to_string(),
        Uuid::new_v4().to_string(),
    )
    .map_err(internal)?;
    claims.cnf = cnf;
    let keys = state.provider.get_oauth2_key_provider();
    // Keys are provisioned on the creation event of a domain, which the
    // `default` domain (seeded at bootstrap) and a domain whose provisioning
    // is still pending never had: provision them on the first issuance. The
    // call is idempotent.
    let key = match keys.active_signing_key(state, &domain_id).await {
        Err(Oauth2KeyProviderError::NotFound(_)) => {
            keys.ensure_domain_keys(state, &domain_id).await
        }
        other => other,
    }
    .map_err(key_error)?;
    let encoding_key = to_encoding_key(&key).map_err(internal)?;
    let mut header = jsonwebtoken::Header::new(jwt_algorithm(key.algorithm));
    header.kid = Some(derive_kid(&key.public_key_der));
    header.typ = Some(OAUTH2_ACCESS_TOKEN_TYP.to_string());
    jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(internal)
}

/// Verify and decode an OAuth2 JWT token.
///
/// Returns the token and, when the token carries it, the sender constraint
/// (`cnf`) of the verified claims.
pub async fn decode(
    state: &ServiceState,
    credential: &str,
) -> Result<(TokenPayload, Option<Confirmation>), TokenProviderError> {
    let prefix = issuer_prefix(state).await?;
    // The format is told by the `typ` header; the verifier does not check it.
    let header = jsonwebtoken::decode_header(credential).map_err(rejected)?;
    if !header
        .typ
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case(OAUTH2_ACCESS_TOKEN_TYP))
    {
        return Err(invalid("not an OAuth2 access token"));
    }
    let iss = credential
        .split('.')
        .nth(1)
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("iss")?.as_str().map(str::to_string))
        .ok_or_else(|| invalid("no issuer"))?;
    let domain_id = domain_of_issuer(&iss, &prefix).ok_or_else(|| invalid("unknown issuer"))?;
    let signing_algorithm = {
        let config = state.config_manager.config.read().await;
        signing_algorithm(config.oauth2.signing_algorithm)
    };
    let keys = state.provider.get_oauth2_key_provider();
    let jwks = keys.jwks(state, &domain_id).await.map_err(key_error)?;
    let profile = SubjectTokenValidationProfile::keystone_token(&[iss], signing_algorithm);
    let claims: KeystoneTokenClaims = verify_subject_token_jwt(credential, &jwks, &profile)
        .map_err(|e| match e {
            TokenVerificationError::Malformed(ref jwt)
                if matches!(
                    jwt.kind(),
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature
                ) =>
            {
                TokenProviderError::Expired
            }
            other => rejected(other),
        })?;
    if keys
        .is_jti_revoked(state, &domain_id, &claims.jti)
        .await
        .map_err(key_error)?
    {
        return Err(TokenProviderError::TokenRevoked);
    }
    // The constraint travels with the verified claims: no re-read of the
    // credential is needed to recover it.
    let cnf = claims.cnf.clone();
    let payload = claims
        .into_token_payload()
        .map_err(|e| invalid(e.to_string()))?;
    Ok((payload, cnf))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chrono::{SubsecRound, TimeDelta, Utc};
    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::identity::UserCore;
    use openstack_keystone_core_types::token::{ProjectScopePayload, UnscopedPayload};
    use openstack_keystone_key_repository::asymmetric::{
        ActiveKeys, SigningAlgorithm, generate_keypair,
    };

    use super::*;
    use openstack_keystone_core::identity::MockIdentityProvider;
    use openstack_keystone_core::oauth2_key::{
        MockOauth2KeyProvider, jwks::active_keys_to_jwk_set,
    };
    use openstack_keystone_core::provider::Provider;
    use openstack_keystone_core::tests::get_mocked_state;

    fn config() -> Config {
        let mut config = Config::default();
        config.default.public_endpoint = Some("https://ks.example".parse().unwrap());
        config.oauth2.signing_algorithm = Default::default();
        config
    }

    fn payload() -> TokenPayload {
        TokenPayload::ProjectScope(ProjectScopePayload {
            user_id: "u1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["a1".into()],
            expires_at: Utc::now().trunc_subsecs(0) + TimeDelta::hours(1),
            project_id: "p1".into(),
            issued_at: Utc::now().trunc_subsecs(0),
        })
    }

    async fn state(revoked: HashSet<String>) -> ServiceState {
        revoking_state(std::sync::Arc::new(std::sync::Mutex::new(revoked))).await
    }

    /// A state whose revoked `jti` set can change after the token is issued.
    async fn revoking_state(
        revoked: std::sync::Arc<std::sync::Mutex<HashSet<String>>>,
    ) -> ServiceState {
        keyed_state(revoked).await.0
    }

    /// Like [`revoking_state`], also returning the signing key.
    async fn keyed_state(
        revoked: std::sync::Arc<std::sync::Mutex<HashSet<String>>>,
    ) -> (
        ServiceState,
        openstack_keystone_key_repository::asymmetric::KeyMaterial,
    ) {
        let keys = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let key_out = keys.clone();
        let signing = keys.clone();
        let active = ActiveKeys {
            primary: keys,
            previous: None,
        };
        let jwks = active_keys_to_jwk_set(&active).unwrap();
        let mut key_mock = MockOauth2KeyProvider::default();
        key_mock
            .expect_active_signing_key()
            .returning(move |_, _| Ok(signing.clone()));
        key_mock
            .expect_jwks()
            .returning(move |_, _| Ok(jwks.clone()));
        key_mock
            .expect_revoked_jtis()
            .returning(move |_, _| Ok(revoked.lock().unwrap().clone()));
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user_core().returning(|_, id| {
            Ok(Some(UserCore {
                id: id.to_string(),
                domain_id: "d1".into(),
                enabled: true,
            }))
        });
        let provider = Provider::mocked_builder()
            .mock_oauth2_key(key_mock)
            .mock_identity(identity_mock);
        (
            get_mocked_state(Some(config()), Some(provider)).await,
            key_out,
        )
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let state = state(HashSet::new()).await;
        let token = payload();
        let credential = encode(&state, &token, None, None).await.unwrap();
        assert_eq!(
            openstack_keystone_core::token::format::detect_format(&credential),
            openstack_keystone_core::token::format::TokenFormat::OAuth2
        );
        assert_eq!(decode(&state, &credential).await.unwrap().0, token);
    }

    #[tokio::test]
    async fn test_principal_domain_selects_the_issuer() {
        // A mapped identity has no stored user: its domain comes from the
        // principal, not from a user lookup (which would say `d1`).
        let state = state(HashSet::new()).await;
        let credential = encode(&state, &payload(), Some("d9".into()), None)
            .await
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(credential.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(claims["iss"].as_str().unwrap().ends_with("/v4/oauth2/d9"));
        assert_eq!(decode(&state, &credential).await.unwrap().0, payload());
    }

    #[tokio::test]
    async fn test_confirmation_is_carried() {
        let state = state(HashSet::new()).await;
        let cnf = Confirmation {
            jkt: "thumb".into(),
        };
        let credential = encode(&state, &payload(), None, Some(cnf.clone()))
            .await
            .unwrap();
        let (decoded, cnf_out) = decode(&state, &credential).await.unwrap();
        assert_eq!(decoded, payload());
        assert_eq!(cnf_out, Some(cnf));
        let plain = encode(&state, &payload(), None, None).await.unwrap();
        assert_eq!(decode(&state, &plain).await.unwrap().1, None);
    }

    /// A correctly signed token whose `cnf` is malformed is refused, not
    /// decoded as an unbound token.
    #[tokio::test]
    async fn test_malformed_confirmation_is_rejected() {
        let (state, key) = keyed_state(Default::default()).await;
        let credential = encode(&state, &payload(), None, None).await.unwrap();
        let mut claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(credential.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        // Control: re-signed with untouched claims, it decodes.
        let header = jsonwebtoken::decode_header(&credential).unwrap();
        let resigned =
            jsonwebtoken::encode(&header, &claims, &to_encoding_key(&key).unwrap()).unwrap();
        assert!(decode(&state, &resigned).await.is_ok());
        claims["cnf"] = serde_json::json!({"jkt": 5});
        let mut header = jsonwebtoken::decode_header(&credential).unwrap();
        header.typ = Some(OAUTH2_ACCESS_TOKEN_TYP.to_string());
        let forged =
            jsonwebtoken::encode(&header, &claims, &to_encoding_key(&key).unwrap()).unwrap();
        assert!(decode(&state, &forged).await.is_err());
    }

    #[tokio::test]
    async fn test_tampered_token_is_rejected() {
        let state = state(HashSet::new()).await;
        let credential = encode(&state, &payload(), None, None).await.unwrap();
        let mut parts: Vec<_> = credential.split('.').map(str::to_string).collect();
        parts[1] = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": "https://ks.example/v4/oauth2/d1", "sub": "admin"
            }))
            .unwrap(),
        );
        assert!(decode(&state, &parts.join(".")).await.is_err());
    }

    #[tokio::test]
    async fn test_foreign_issuer_is_rejected() {
        let state = state(HashSet::new()).await;
        let credential = encode(&state, &payload(), None, None).await.unwrap();
        let mut config = config();
        config.default.public_endpoint = Some("https://other.example".parse().unwrap());
        let other = get_mocked_state(Some(config), None).await;
        assert!(decode(&other, &credential).await.is_err());
    }

    #[tokio::test]
    async fn test_unscoped_roundtrip() {
        let state = state(HashSet::new()).await;
        let token = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "u1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["a1".into()],
            expires_at: Utc::now().trunc_subsecs(0) + TimeDelta::hours(1),
            issued_at: Utc::now().trunc_subsecs(0),
            ..Default::default()
        });
        let credential = encode(&state, &token, None, None).await.unwrap();
        assert_eq!(decode(&state, &credential).await.unwrap().0, token);
    }

    fn federated(groups: usize) -> TokenPayload {
        TokenPayload::FederationUnscoped(
            openstack_keystone_core_types::token::FederationUnscopedPayload {
                user_id: "u1".into(),
                methods: vec!["openid".into()],
                audit_ids: vec!["a1".into()],
                expires_at: Utc::now().trunc_subsecs(0) + TimeDelta::hours(1),
                issued_at: Utc::now().trunc_subsecs(0),
                idp_id: "idp".into(),
                protocol_id: "oidc".into(),
                group_ids: (0..groups).map(|i| format!("g{i}")).collect(),
            },
        )
    }

    #[tokio::test]
    async fn test_federated_roundtrip_with_confirmation() {
        let state = state(HashSet::new()).await;
        let token = federated(3);
        let cnf = Confirmation {
            jkt: "thumb".into(),
        };
        let credential = encode(&state, &token, None, Some(cnf.clone()))
            .await
            .unwrap();
        let (decoded, cnf_out) = decode(&state, &credential).await.unwrap();
        assert_eq!(decoded, token);
        assert_eq!(cnf_out, Some(cnf));
    }

    /// Too many groups fail the login: a truncated list would drop roles.
    #[tokio::test]
    async fn test_group_cap_fails_instead_of_truncating() {
        let state = state(HashSet::new()).await;
        let max = state
            .config_manager
            .config
            .read()
            .await
            .token
            .max_federation_groups;
        assert!(encode(&state, &federated(max), None, None).await.is_ok());
        assert!(matches!(
            encode(&state, &federated(max + 1), None, None).await,
            Err(TokenProviderError::TooManyGroups { .. })
        ));
    }

    #[tokio::test]
    async fn test_revoked_jti_is_rejected() {
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(HashSet::new()));
        let state = revoking_state(revoked.clone()).await;
        let credential = encode(&state, &payload(), None, None).await.unwrap();
        assert!(decode(&state, &credential).await.is_ok());
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(credential.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        revoked
            .lock()
            .unwrap()
            .insert(claims["jti"].as_str().unwrap().to_string());
        assert!(matches!(
            decode(&state, &credential).await,
            Err(TokenProviderError::TokenRevoked)
        ));
    }

    #[test]
    fn test_domain_of_issuer() {
        let prefix = "https://ks.example/v4/oauth2/";
        assert_eq!(
            domain_of_issuer("https://ks.example/v4/oauth2/d1", prefix),
            Some("d1".into())
        );
        assert_eq!(
            domain_of_issuer("https://ks.example/v4/oauth2/", prefix),
            None
        );
        assert_eq!(
            domain_of_issuer("https://ks.example/v4/oauth2/a/b", prefix),
            None
        );
        assert_eq!(domain_of_issuer("https://evil/v4/oauth2/d1", prefix), None);
    }
}
