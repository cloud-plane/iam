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
// Crypto inventory: TOK-2; see doc/src/contributor/crypto-inventory.md
//! # JWS token driver for the `openstack_keystone` crate (ADR 0026 §10, Phase 0)
//!
//! Wire-compatible with Python Keystone's `[token] provider = jws`:
//! ES256-signed reference tokens carrying only identity/scope anchors (no
//! roles, no catalog) — a token *format*, not the OP-issued
//! `OpenStackAccessTokenClaims` later ADR 0026 phases introduce.
use std::fmt;
use std::sync::Arc;

use std::collections::HashMap;

use jsonwebtoken::{DecodingKey, Header, Validation, decode, encode};
use openstack_keystone_config::{Config, TokenProviderDriver};
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::token::TokenProviderError;
use openstack_keystone_core::token::backend::TokenBackend;
use openstack_keystone_core_types::token::TokenPayload;
use openstack_keystone_key_repository::asymmetric::{
    ActiveKeys, AsymmetricKeyRepository, FilesystemAsymmetricKeySource, PublicKey,
    SigningAlgorithm, to_decoding_key, to_encoding_key,
};

mod claims;
mod config;
pub mod error;

pub use claims::JwsClaims;
pub use config::{JwsTokensConfig, TrustedAuthority};
pub use error::JwsDriverError;
pub use openstack_keystone_key_repository::asymmetric::jwt_algorithm;

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    // Only registered when actually selected (ADR-0026 §10, Phase 0): unlike
    // fernet, a `[jws_tokens]` key repository need not exist for a
    // fernet-only deployment, so this driver must not be eagerly built.
    BackendRegistration::<dyn TokenBackend> {
        name: "jws",
        selected: |cfg| cfg.token.provider == TokenProviderDriver::Jws,
        build: |cfg| {
            let section = cfg.require::<JwsTokensConfig>().cloned();
            Box::pin(async move {
                let mut provider = JwsTokenProvider::new(section?);
                provider.load_keys().await?;
                Ok(Arc::new(provider) as Arc<dyn TokenBackend>)
            })
        },
    }
}

/// The `iss` claim of a token, read without verifying the signature.
///
/// Only ever used to choose which keys to verify with.
fn unverified_issuer(credential: &str) -> Option<String> {
    use base64::Engine;
    let payload = credential.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("iss")?
        .as_str()
        .map(str::to_owned)
}

/// JWS token provider.
pub struct JwsTokenProvider {
    repo: AsymmetricKeyRepository<FilesystemAsymmetricKeySource>,
    /// Populated by [`Self::load_keys`]: `encode`/`decode` are synchronous
    /// (called on every request) and require it to have already run,
    /// mirroring `FernetTokenProvider`'s `cached` field.
    active: Option<ActiveKeys>,
    /// This authority's name, the `iss` of its tokens.
    issuer: Option<String>,
    /// Keys of the trusted authorities as configured; read by
    /// [`Self::load_keys`].
    trusted_config: HashMap<String, TrustedAuthority>,
    /// Verification keys of the trusted authorities, by issuer.
    trusted: HashMap<String, Vec<PublicKey>>,
}

impl fmt::Debug for JwsTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("JwsTokenProvider").finish()
    }
}

impl JwsTokenProvider {
    /// Construct a new provider. Call [`Self::load_keys`] before use.
    pub fn new(config: JwsTokensConfig) -> Self {
        let repo = AsymmetricKeyRepository::new(FilesystemAsymmetricKeySource::new(
            config.key_repository.clone(),
        ));
        Self {
            repo,
            active: None,
            issuer: config.issuer,
            trusted_config: config.trusted_authorities,
            trusted: HashMap::new(),
        }
    }

    /// Load (or reload) the active signing keys from the configured key
    /// repository.
    ///
    /// # Errors
    /// [`JwsDriverError::KeyRepository`] if the repository has no usable
    /// `Primary` key — a `[token] provider = jws` deployment must fail
    /// loudly at startup rather than silently falling back to Fernet.
    pub async fn load_keys(&mut self) -> Result<(), JwsDriverError> {
        self.active = Some(self.repo.load_active().await?);
        self.load_trusted().await
    }

    /// Read the public keys of the trusted authorities.
    ///
    /// An authority without a key could never verify a token, so it is a
    /// configuration error rather than a silently empty entry.
    async fn load_trusted(&mut self) -> Result<(), JwsDriverError> {
        let mut trusted = HashMap::new();
        for (issuer, authority) in &self.trusted_config {
            let algorithm = match authority.algorithm.as_str() {
                "ES256" => SigningAlgorithm::Es256,
                "RS256" => SigningAlgorithm::Rs256,
                other => {
                    return Err(JwsDriverError::KeyConversion(format!(
                        "trusted authority {issuer}: unsupported algorithm {other}"
                    )));
                }
            };
            if authority.public_key_files.is_empty() {
                return Err(JwsDriverError::KeyConversion(format!(
                    "trusted authority {issuer} has no public_key_files"
                )));
            }
            let mut keys = Vec::new();
            for file in &authority.public_key_files {
                let text = tokio::fs::read_to_string(file).await.map_err(|e| {
                    JwsDriverError::KeyConversion(format!(
                        "reading {} of authority {issuer}: {e}",
                        file.display()
                    ))
                })?;
                keys.push(PublicKey::from_pem(algorithm, &text)?);
            }
            trusted.insert(issuer.clone(), keys);
        }
        self.trusted = trusted;
        Ok(())
    }

    /// Verify `credential` against `keys`, requiring the issuer when given.
    fn verify(
        credential: &str,
        keys: impl Iterator<Item = (jsonwebtoken::Algorithm, Result<DecodingKey, JwsDriverError>)>,
        issuer: Option<&str>,
    ) -> Result<JwsClaims, JwsDriverError> {
        let mut last_error: Option<JwsDriverError> = None;
        for (algorithm, key) in keys {
            let key = match key {
                Ok(key) => key,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let mut validation = Validation::new(algorithm);
            validation.validate_exp = true;
            if let Some(issuer) = issuer {
                validation.set_issuer(&[issuer]);
                validation.set_required_spec_claims(&["exp", "iss"]);
            }
            match decode::<JwsClaims>(credential, &key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(error) => last_error = Some(JwsDriverError::from(error)),
            }
        }
        Err(last_error.unwrap_or(JwsDriverError::KeysNotLoaded))
    }

    fn active(&self) -> Result<&ActiveKeys, JwsDriverError> {
        self.active.as_ref().ok_or(JwsDriverError::KeysNotLoaded)
    }
}

impl TokenBackend for JwsTokenProvider {
    /// The signing keys are loaded once from the `[jws_tokens]` key
    /// repository; nothing in the core configuration affects them.
    fn set_config(&mut self, _config: Config) {}

    fn decode(&self, credential: &str) -> Result<TokenPayload, TokenProviderError> {
        self.decode_with_issuer(credential).map(|(token, _)| token)
    }

    /// A token signed by one of this authority's keys is local, whatever its
    /// `iss` claim says. Otherwise it must verify against the keys of the
    /// authority it names, and then carries that authority as its issuer; a
    /// token that names an authority but verifies against none of its keys
    /// is invalid.
    fn decode_with_issuer(
        &self,
        credential: &str,
    ) -> Result<(TokenPayload, Option<String>), TokenProviderError> {
        let active = self.active().map_err(TokenProviderError::from)?;
        let invalid = |source: JwsDriverError| TokenProviderError::InvalidToken {
            source: Box::new(source),
        };

        // Try Primary first, then Previous (multi-generational tolerance
        // during a rotation's grace window — same principle as ADR 0026
        // §3's JWKS publishing, scoped here to whatever this provider's
        // own key source currently holds).
        let local = std::iter::once(&active.primary)
            .chain(active.previous.iter())
            .map(|material| {
                (
                    jwt_algorithm(material.algorithm),
                    to_decoding_key(material).map_err(JwsDriverError::from),
                )
            });
        let local_error = match Self::verify(credential, local, None) {
            Ok(claims) => {
                return claims
                    .into_token_payload()
                    .map(|token| (token, None))
                    .map_err(invalid);
            }
            Err(error) => error,
        };

        // Not ours. Which authority claims it is read from the unverified
        // payload only to pick the keys to verify against; the issuer is
        // enforced by the verification itself.
        let Some(issuer) = unverified_issuer(credential) else {
            return Err(invalid(local_error));
        };
        let Some(keys) = self.trusted.get(&issuer) else {
            return Err(invalid(local_error));
        };
        let foreign = keys.iter().map(|key| {
            (
                jwt_algorithm(key.algorithm),
                key.decoding_key().map_err(JwsDriverError::from),
            )
        });
        let claims = Self::verify(credential, foreign, Some(&issuer)).map_err(invalid)?;
        claims
            .into_token_payload()
            .map(|token| (token, Some(issuer)))
            .map_err(invalid)
    }

    fn encode(&self, token: &TokenPayload) -> Result<String, TokenProviderError> {
        let active = self.active().map_err(TokenProviderError::from)?;
        let mut claims = JwsClaims::try_from(token).map_err(TokenProviderError::from)?;
        claims.iss.clone_from(&self.issuer);
        let encoding_key = to_encoding_key(&active.primary)
            .map_err(JwsDriverError::from)
            .map_err(TokenProviderError::from)?;
        let header = Header::new(jwt_algorithm(active.primary.algorithm));
        encode(&header, &claims, &encoding_key)
            .map_err(|e| TokenProviderError::from(JwsDriverError::from(e)))
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::token::{ProjectScopePayload, UnscopedPayload};

    use super::*;

    fn setup_config(dir: &std::path::Path) -> JwsTokensConfig {
        JwsTokensConfig {
            key_repository: dir.to_path_buf(),
            ..Default::default()
        }
    }

    async fn provider_with_keys(dir: &std::path::Path) -> JwsTokenProvider {
        openstack_keystone_jwt_crypto::install().unwrap();
        let mut provider = JwsTokenProvider::new(setup_config(dir));
        provider
            .repo
            .setup(openstack_keystone_key_repository::asymmetric::SigningAlgorithm::Es256)
            .await
            .unwrap();
        provider.load_keys().await.unwrap();
        provider
    }

    #[tokio::test]
    async fn test_encode_decode_roundtrip_unscoped() {
        let dir = tempfile::tempdir().unwrap();
        let provider = provider_with_keys(dir.path()).await;

        let token = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            ..Default::default()
        });

        let encoded = provider.encode(&token).unwrap();
        let decoded = provider.decode(&encoded).unwrap();
        match decoded {
            TokenPayload::Unscoped(p) => assert_eq!(p.user_id, "user-1"),
            other => panic!("expected Unscoped, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_encode_decode_roundtrip_project_scope() {
        let dir = tempfile::tempdir().unwrap();
        let provider = provider_with_keys(dir.path()).await;

        let token = TokenPayload::ProjectScope(ProjectScopePayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            project_id: "project-1".into(),
        });

        let encoded = provider.encode(&token).unwrap();
        let decoded = provider.decode(&encoded).unwrap();
        match decoded {
            TokenPayload::ProjectScope(p) => assert_eq!(p.project_id, "project-1"),
            other => panic!("expected ProjectScope, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_decode_before_load_keys_fails() {
        let dir = tempfile::tempdir().unwrap();
        let provider = JwsTokenProvider::new(setup_config(dir.path()));
        assert!(provider.decode("whatever").is_err());
    }

    #[tokio::test]
    async fn test_load_keys_fails_when_repository_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = JwsTokenProvider::new(setup_config(dir.path()));
        assert!(provider.load_keys().await.is_err());
    }

    #[tokio::test]
    async fn test_decode_rejects_tampered_token() {
        let dir = tempfile::tempdir().unwrap();
        let provider = provider_with_keys(dir.path()).await;

        let token = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            ..Default::default()
        });
        let mut encoded = provider.encode(&token).unwrap();
        encoded.push('x');
        assert!(matches!(
            provider.decode(&encoded),
            Err(TokenProviderError::InvalidToken { .. })
        ));
    }

    #[tokio::test]
    async fn test_decode_falls_back_to_previous_when_primary_is_corrupt()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let mut provider = provider_with_keys(dir.path()).await;
        let token = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "previous-key-user".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["previous-key-audit".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            ..Default::default()
        });
        let encoded = provider.encode(&token)?;
        let previous = provider.active()?.primary.clone();
        let mut corrupt_primary = previous.clone();
        corrupt_primary.public_key_der = vec![0];
        provider.active = Some(ActiveKeys {
            primary: corrupt_primary,
            previous: Some(previous),
        });

        let decoded = provider.decode(&encoded)?;
        assert!(matches!(
            decoded,
            TokenPayload::Unscoped(payload) if payload.user_id == "previous-key-user"
        ));
        Ok(())
    }

    fn sample_token() -> TokenPayload {
        TokenPayload::Unscoped(UnscopedPayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            issued_at: chrono::Utc::now(),
            ..Default::default()
        })
    }

    /// A provider named `issuer` that trusts `peer` through `peer_key`.
    async fn mesh_provider(
        dir: &std::path::Path,
        issuer: &str,
        peer: Option<(&str, std::path::PathBuf)>,
    ) -> JwsTokenProvider {
        openstack_keystone_jwt_crypto::install().unwrap();
        let mut config = setup_config(dir);
        config.issuer = Some(issuer.to_owned());
        if let Some((name, key)) = peer {
            config.trusted_authorities.insert(
                name.to_owned(),
                TrustedAuthority {
                    algorithm: "ES256".into(),
                    public_key_files: vec![key],
                },
            );
        }
        let mut provider = JwsTokenProvider::new(config);
        provider.repo.setup(SigningAlgorithm::Es256).await.unwrap();
        provider.load_keys().await.unwrap();
        provider
    }

    #[tokio::test]
    async fn test_own_token_is_local_even_with_issuer_claim() {
        let dir = tempfile::tempdir().unwrap();
        let a = mesh_provider(dir.path(), "authority-a", None).await;
        let credential = a.encode(&sample_token()).unwrap();
        let (_, issuer) = a.decode_with_issuer(&credential).unwrap();
        assert_eq!(issuer, None);
    }

    #[tokio::test]
    async fn test_trusted_authority_token_carries_its_issuer() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = mesh_provider(dir_a.path(), "authority-a", None).await;
        let b = mesh_provider(
            dir_b.path(),
            "authority-b",
            Some(("authority-a", dir_a.path().join("public.pem"))),
        )
        .await;
        let credential = a.encode(&sample_token()).unwrap();
        let (token, issuer) = b.decode_with_issuer(&credential).unwrap();
        assert_eq!(issuer.as_deref(), Some("authority-a"));
        assert_eq!(token.user_id(), "user-1");
    }

    #[tokio::test]
    async fn test_forged_issuer_is_rejected() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let dir_evil = tempfile::tempdir().unwrap();
        let _a = mesh_provider(dir_a.path(), "authority-a", None).await;
        let b = mesh_provider(
            dir_b.path(),
            "authority-b",
            Some(("authority-a", dir_a.path().join("public.pem"))),
        )
        .await;
        // Signed with a key nobody trusts, claiming to be authority-a.
        let evil = mesh_provider(dir_evil.path(), "authority-a", None).await;
        let credential = evil.encode(&sample_token()).unwrap();
        assert!(b.decode_with_issuer(&credential).is_err());
        assert!(b.decode(&credential).is_err());
    }

    #[tokio::test]
    async fn test_trusted_authority_cannot_claim_another_issuer() {
        // authority-a is trusted, but its key must not vouch for a token that
        // names authority-c.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a_as_c = mesh_provider(dir_a.path(), "authority-c", None).await;
        let b = mesh_provider(
            dir_b.path(),
            "authority-b",
            Some(("authority-a", dir_a.path().join("public.pem"))),
        )
        .await;
        let credential = a_as_c.encode(&sample_token()).unwrap();
        assert!(b.decode_with_issuer(&credential).is_err());
    }

    #[tokio::test]
    async fn test_trusted_authority_without_keys_fails_to_load() {
        openstack_keystone_jwt_crypto::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut config = setup_config(dir.path());
        config.trusted_authorities.insert(
            "authority-a".into(),
            TrustedAuthority {
                algorithm: "ES256".into(),
                public_key_files: vec![],
            },
        );
        let mut provider = JwsTokenProvider::new(config);
        provider.repo.setup(SigningAlgorithm::Es256).await.unwrap();
        assert!(provider.load_keys().await.is_err());
    }
}
