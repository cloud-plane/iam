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
//! # Python-Keystone-compatible v3 JWS claim layout (ADR 0026 §10, Phase 0)
//!
//! Maps [`TokenPayload`] to/from the claim set Python Keystone's
//! `[token] provider = jws` writes: `sub`, `exp`, `iat`,
//! `openstack_methods`, `openstack_audit_ids`, exactly one of
//! `openstack_project_id`/`openstack_domain_id`/`openstack_system`, and
//! optionally `openstack_trust_id`/`openstack_app_cred_id`.
//!
//! This is a *reference*-token format (§10, Phase 0): the payload carries
//! only identity/scope anchors, not roles/catalog. The OAuth2 token format of
//! ADR 0049 has its own compact claim set ([`super::oauth2_claims`]) built on
//! the same anchors.
use super::{
    ApplicationCredentialPayload, DomainScopePayload, ProjectScopePayload, SystemScopePayload,
    TokenPayload, TrustPayload, UnscopedPayload,
};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use thiserror::Error;

/// Error converting between [`TokenPayload`] and [`JwsClaims`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TokenClaimsError {
    /// The claims carry more than one scope claim.
    #[error("token claims must carry exactly one scope claim, found {0}")]
    AmbiguousOrMissingScopeClaim(usize),

    /// A timestamp claim is out of range.
    #[error("invalid timestamp claim: {0}")]
    InvalidTimestamp(String),

    /// The claims carry both a trust and an application credential.
    #[error("token claims must carry at most one delegation")]
    AmbiguousDelegation,

    /// A delegation (trust, application credential) without a project scope.
    #[error("a delegated token must be project scoped")]
    DelegationWithoutProject,

    /// A restricted token that is not project scoped.
    #[error("a restricted token must be project scoped")]
    InvalidRestrictedToken,

    /// A federated token with a system scope.
    #[error("a federated token cannot be system scoped")]
    InvalidFederatedToken,

    /// A [`TokenPayload`] variant has no representation in the claim layout.
    #[error("token variant {0} has no claim representation")]
    UnsupportedTokenVariant(&'static str),
}

/// The Python-Keystone-compatible v3 JWS claim set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsClaims {
    /// Subject: the token's `user_id`.
    pub sub: String,
    /// Expiration, Unix seconds.
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Authentication methods used to obtain the token.
    pub openstack_methods: Vec<String>,
    /// Token audit IDs.
    pub openstack_audit_ids: Vec<String>,
    /// Project-scope anchor, if project-scoped.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub openstack_project_id: Option<String>,
    /// Domain-scope anchor, if domain-scoped.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub openstack_domain_id: Option<String>,
    /// System-scope anchor, if system-scoped.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub openstack_system: Option<String>,
    /// Trust ID, if this token was issued via a trust.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub openstack_trust_id: Option<String>,
    /// Application credential ID, if this token was issued via an
    /// application credential.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub openstack_app_cred_id: Option<String>,
}

fn to_unix(dt: DateTime<Utc>) -> i64 {
    dt.timestamp()
}

pub(super) fn from_unix(secs: i64) -> Result<DateTime<Utc>, TokenClaimsError> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .ok_or_else(|| TokenClaimsError::InvalidTimestamp(secs.to_string()))
}

impl TryFrom<&TokenPayload> for JwsClaims {
    type Error = TokenClaimsError;

    fn try_from(token: &TokenPayload) -> Result<Self, Self::Error> {
        let base = |user_id: &str,
                    methods: &[String],
                    audit_ids: &[String],
                    expires_at: DateTime<Utc>,
                    iat: DateTime<Utc>| JwsClaims {
            sub: user_id.to_string(),
            exp: to_unix(expires_at),
            iat: to_unix(iat),
            openstack_methods: methods.to_vec(),
            openstack_audit_ids: audit_ids.to_vec(),
            openstack_project_id: None,
            openstack_domain_id: None,
            openstack_system: None,
            openstack_trust_id: None,
            openstack_app_cred_id: None,
        };

        match token {
            TokenPayload::Unscoped(p) => Ok(base(
                &p.user_id,
                &p.methods,
                &p.audit_ids,
                p.expires_at,
                p.issued_at,
            )),
            TokenPayload::ProjectScope(p) => {
                let mut claims = base(
                    &p.user_id,
                    &p.methods,
                    &p.audit_ids,
                    p.expires_at,
                    p.issued_at,
                );
                claims.openstack_project_id = Some(p.project_id.clone());
                Ok(claims)
            }
            TokenPayload::DomainScope(p) => {
                let mut claims = base(
                    &p.user_id,
                    &p.methods,
                    &p.audit_ids,
                    p.expires_at,
                    p.issued_at,
                );
                claims.openstack_domain_id = Some(p.domain_id.clone());
                Ok(claims)
            }
            TokenPayload::SystemScope(p) => {
                let mut claims = base(
                    &p.user_id,
                    &p.methods,
                    &p.audit_ids,
                    p.expires_at,
                    p.issued_at,
                );
                claims.openstack_system = Some(p.system_id.clone());
                Ok(claims)
            }
            TokenPayload::Trust(p) => {
                let mut claims = base(
                    &p.user_id,
                    &p.methods,
                    &p.audit_ids,
                    p.expires_at,
                    p.issued_at,
                );
                claims.openstack_project_id = Some(p.project_id.clone());
                claims.openstack_trust_id = Some(p.trust_id.clone());
                Ok(claims)
            }
            TokenPayload::ApplicationCredential(p) => {
                let mut claims = base(
                    &p.user_id,
                    &p.methods,
                    &p.audit_ids,
                    p.expires_at,
                    p.issued_at,
                );
                claims.openstack_project_id = Some(p.project_id.clone());
                claims.openstack_app_cred_id = Some(p.application_credential_id.clone());
                Ok(claims)
            }
            TokenPayload::Restricted(_) => {
                Err(TokenClaimsError::UnsupportedTokenVariant("Restricted"))
            }
            TokenPayload::FederationUnscoped(_) => Err(TokenClaimsError::UnsupportedTokenVariant(
                "FederationUnscoped",
            )),
            TokenPayload::FederationProjectScope(_) => Err(
                TokenClaimsError::UnsupportedTokenVariant("FederationProjectScope"),
            ),
            TokenPayload::FederationDomainScope(_) => Err(
                TokenClaimsError::UnsupportedTokenVariant("FederationDomainScope"),
            ),
        }
    }
}

impl JwsClaims {
    /// Reconstruct the [`TokenPayload`] variant matching whichever
    /// `openstack_*` scope claim is present. Exactly one of
    /// `openstack_project_id`/`openstack_domain_id`/`openstack_system` must
    /// be present, or none for an unscoped token.
    pub fn into_token_payload(self) -> Result<TokenPayload, TokenClaimsError> {
        let expires_at = from_unix(self.exp)?;
        let issued_at = from_unix(self.iat)?;
        let scope_claims_present = [
            self.openstack_project_id.is_some(),
            self.openstack_domain_id.is_some(),
            self.openstack_system.is_some(),
        ]
        .iter()
        .filter(|present| **present)
        .count();
        if scope_claims_present > 1 {
            return Err(TokenClaimsError::AmbiguousOrMissingScopeClaim(
                scope_claims_present,
            ));
        }

        if let Some(trust_id) = self.openstack_trust_id {
            let project_id = self
                .openstack_project_id
                .ok_or(TokenClaimsError::AmbiguousOrMissingScopeClaim(0))?;
            return Ok(TokenPayload::Trust(TrustPayload {
                user_id: self.sub,
                methods: self.openstack_methods,
                audit_ids: self.openstack_audit_ids,
                expires_at,
                issued_at,
                trust_id,
                project_id,
            }));
        }

        if let Some(application_credential_id) = self.openstack_app_cred_id {
            let project_id = self
                .openstack_project_id
                .ok_or(TokenClaimsError::AmbiguousOrMissingScopeClaim(0))?;
            return Ok(TokenPayload::ApplicationCredential(
                ApplicationCredentialPayload {
                    user_id: self.sub,
                    methods: self.openstack_methods,
                    audit_ids: self.openstack_audit_ids,
                    expires_at,
                    issued_at,
                    project_id,
                    application_credential_id,
                },
            ));
        }

        if let Some(project_id) = self.openstack_project_id {
            return Ok(TokenPayload::ProjectScope(ProjectScopePayload {
                user_id: self.sub,
                methods: self.openstack_methods,
                audit_ids: self.openstack_audit_ids,
                expires_at,
                issued_at,
                project_id,
            }));
        }
        if let Some(domain_id) = self.openstack_domain_id {
            return Ok(TokenPayload::DomainScope(DomainScopePayload {
                user_id: self.sub,
                methods: self.openstack_methods,
                audit_ids: self.openstack_audit_ids,
                expires_at,
                issued_at,
                domain_id,
            }));
        }
        if let Some(system_id) = self.openstack_system {
            return Ok(TokenPayload::SystemScope(SystemScopePayload {
                user_id: self.sub,
                methods: self.openstack_methods,
                audit_ids: self.openstack_audit_ids,
                expires_at,
                issued_at,
                system_id,
            }));
        }

        Ok(TokenPayload::Unscoped(UnscopedPayload {
            user_id: self.sub,
            methods: self.openstack_methods,
            audit_ids: self.openstack_audit_ids,
            expires_at,
            issued_at,
            ..Default::default()
        }))
    }
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now().trunc_subsecs(0)
    }

    #[test]
    fn test_unscoped_roundtrip() {
        let payload = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: now(),
            issued_at: now(),
            ..Default::default()
        });
        let claims = JwsClaims::try_from(&payload).unwrap();
        let roundtripped = claims.into_token_payload().unwrap();
        match roundtripped {
            TokenPayload::Unscoped(p) => assert_eq!(p.user_id, "user-1"),
            other => panic!("expected Unscoped, got {other:?}"),
        }
    }

    #[test]
    fn test_project_scope_roundtrip() {
        let payload = TokenPayload::ProjectScope(ProjectScopePayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: now(),
            issued_at: now(),
            project_id: "project-1".into(),
        });
        let claims = JwsClaims::try_from(&payload).unwrap();
        assert_eq!(claims.openstack_project_id.as_deref(), Some("project-1"));
        let roundtripped = claims.into_token_payload().unwrap();
        match roundtripped {
            TokenPayload::ProjectScope(p) => assert_eq!(p.project_id, "project-1"),
            other => panic!("expected ProjectScope, got {other:?}"),
        }
    }

    #[test]
    fn test_trust_roundtrip() {
        let payload = TokenPayload::Trust(TrustPayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: now(),
            issued_at: now(),
            trust_id: "trust-1".into(),
            project_id: "project-1".into(),
        });
        let claims = JwsClaims::try_from(&payload).unwrap();
        let roundtripped = claims.into_token_payload().unwrap();
        match roundtripped {
            TokenPayload::Trust(p) => {
                assert_eq!(p.trust_id, "trust-1");
                assert_eq!(p.project_id, "project-1");
            }
            other => panic!("expected Trust, got {other:?}"),
        }
    }

    #[test]
    fn test_restricted_is_unsupported() {
        use crate::token::RestrictedPayload;
        let payload = TokenPayload::Restricted(RestrictedPayload {
            user_id: "user-1".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["abc123".into()],
            expires_at: now(),
            issued_at: now(),
            token_restriction_id: "restriction-1".into(),
            project_id: "project-1".into(),
            allow_renew: false,
            allow_rescope: false,
        });
        assert!(matches!(
            JwsClaims::try_from(&payload),
            Err(TokenClaimsError::UnsupportedTokenVariant("Restricted"))
        ));
    }
}
