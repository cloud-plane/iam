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
//! # Token provider.
//!
//! A Keystone token is an alpha-numeric text string that enables access to
//! OpenStack APIs and resources. A token may be revoked at any time and is
//! valid for a finite duration. OpenStack Identity is an integration service
//! that does not aspire to be a full-fledged identity store and management
//! solution.

pub use openstack_keystone_core_types::token::*;

pub mod backend;
pub mod error;
pub mod format;
pub mod hook;
pub mod metrics;
mod provider_api;
pub mod service;

pub use error::TokenProviderError;
pub use hook::TokenHook;

/// Refuse a context built from a sender-constrained token (`cnf`, ADR 0043,
/// ADR 0049).
///
/// For every path that takes a Keystone token as a *credential value* (the
/// body of `POST /v3/auth/tokens`, the `subject_token` of a token exchange or
/// an on-behalf-of exchange): no proof of the token's key exists there, and
/// exchanging it would hand an unbound token or credential to whoever holds
/// the bytes. The `Auth` extractor is the one place that checks the proof.
///
/// # Errors
/// [`TokenProviderError::InvalidToken`] when the token is bound.
pub fn ensure_unbound(
    vsc: &crate::auth::ValidatedSecurityContext,
) -> Result<(), TokenProviderError> {
    if vsc.confirmation().is_some() {
        return Err(TokenProviderError::InvalidToken {
            source: "a sender-constrained token cannot be exchanged".into(),
        });
    }
    Ok(())
}
pub use metrics::TOKEN_METRICS;
pub use provider_api::TokenApi;
pub use service::TokenService;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockTokenProvider;

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    use openstack_keystone_config::Config;

    pub(super) fn setup_config() -> Config {
        let keys_dir = tempdir().unwrap();
        let file_path = keys_dir.path().join("0");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();

        let builder = config::Config::builder()
            .set_override(
                "auth.methods",
                "password,token,openid,application_credential",
            )
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let mut config: Config = Config::try_from(builder).expect("can build a valid config");
        config.fernet_tokens.key_repository = keys_dir.keep();
        config
    }
}

#[cfg(test)]
mod ensure_unbound_tests {
    use super::*;
    use crate::auth::ValidatedSecurityContext;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, IdentityInfo, PrincipalInfo, SecurityContextTestingBuilder,
        UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::oauth2_client::Confirmation;

    fn vsc(cnf: Option<Confirmation>) -> ValidatedSecurityContext {
        let mut sc = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("u1")
                        .build()
                        .unwrap(),
                ),
            })
            .build();
        sc.set_confirmation(cnf);
        ValidatedSecurityContext::test_new(sc)
    }

    #[test]
    fn test_unbound_context_passes() {
        assert!(ensure_unbound(&vsc(None)).is_ok());
    }

    #[test]
    fn test_bound_context_is_refused_as_an_invalid_token() {
        let bound = vsc(Some(Confirmation {
            jkt: "thumb".into(),
        }));
        assert!(matches!(
            ensure_unbound(&bound),
            Err(TokenProviderError::InvalidToken { .. })
        ));
    }
}
