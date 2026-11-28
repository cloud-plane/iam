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
//! # Compact claim set of the OAuth2 format of Keystone's own tokens
//!
//! Unlike the Python-compatible [`JwsClaims`] layout, this wire format is
//! owned by Keystone and sized for a header: short claim names, no `nbf`
//! (equal to `iat`) and no `token_use` (the exact `aud` and the `typ` header
//! tell the token from every other token of the OAuth2 provider).
//!
//! Two claims carry what the token resolves to, each an enum with exactly one
//! variant on the wire: `ks_scope` (where) and `chain` (how the user got the
//! token: a delegation, a restriction or a federation). A token cannot name
//! two scopes or two chain kinds, and a chain fact can never be read as a
//! scope. Security decisions key on the chain, never on the scope.
//!
//! The scope is an *anchor* kept for the gradual migration of v3 clients. It
//! is optional by design: the scope-less token of the vision document is this
//! same format without `ks_scope`.
//!
//! Only identifiers travel in the token. IdP attributes never do.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::claims::{JwsClaims, TokenClaimsError, from_unix};
use super::{
    FederationDomainScopePayload, FederationProjectScopePayload, FederationUnscopedPayload,
    RestrictedPayload, TokenPayload,
};
use crate::oauth2_client::Confirmation;

/// The scope anchor of the token. Exactly one variant is on the wire, as
/// `{"project": "<id>"}`, `{"domain": "<id>"}` or `{"system": "<id>"}`.
///
/// Security decisions are never keyed on this value: it only tells which
/// scope the client asked for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    /// Project scope: the project id.
    Project(String),
    /// Domain scope: the domain id.
    Domain(String),
    /// System scope: the system id.
    System(String),
}

/// The token restriction of a restricted token. Its roles are resolved live
/// from `id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenRestrictionClaim {
    /// Token restriction id.
    pub id: String,
    /// Whether the token can be renewed. Omitted when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub renew: bool,
    /// Whether the token can be rescoped. Omitted when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rescope: bool,
}

/// The federation of a federated login: identifiers only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenFederationClaim {
    /// Identity provider id.
    pub idp: String,
    /// Federation protocol id.
    pub proto: String,
    /// Group ids the mapping resolved at login. They are frozen for the
    /// life of the token; their role assignments are resolved live.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grp: Vec<String>,
}

/// How the token was obtained: the authentication chain. Exactly one variant
/// is on the wire; absent means a plain authentication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenChain {
    /// Issued through a trust: the trust id. Needs a project scope.
    Trust(String),
    /// Issued through an application credential: the credential id. Needs a
    /// project scope.
    AppCred(String),
    /// Restricted token. Needs a project scope.
    Restricted(TokenRestrictionClaim),
    /// Federated login. Takes no scope, a project scope or a domain scope.
    Federated(TokenFederationClaim),
}

/// Claims of the OAuth2 format of Keystone's own token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoneTokenClaims {
    /// Issuer: `{public_endpoint}/v4/oauth2/{domain_id}`.
    pub iss: String,
    /// Audience, always the Keystone token audience.
    pub aud: String,
    /// Subject: the user id.
    pub sub: String,
    /// Expiration, Unix seconds.
    pub exp: i64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Unique token identifier.
    pub jti: String,
    /// Authentication methods used to obtain the token.
    pub amr: Vec<String>,
    /// Audit ids of the authentication chain.
    pub aid: Vec<String>,
    /// Scope anchor; absent for an unscoped (scope-less) token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ks_scope: Option<TokenScope>,
    /// Authentication chain; absent for a plain authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<TokenChain>,
    /// Sender constraint (ADR 0043).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

/// The common part of a payload, while its scope and chain are mapped.
struct Common {
    sub: String,
    exp: i64,
    iat: i64,
    amr: Vec<String>,
    aid: Vec<String>,
}

impl KeystoneTokenClaims {
    /// Build the claims of a [`TokenPayload`]. `iss`, `aud` and `jti` are the
    /// caller's: they belong to the issuance, not to the payload.
    pub fn new(
        token: &TokenPayload,
        iss: String,
        aud: String,
        jti: String,
    ) -> Result<Self, TokenClaimsError> {
        let (common, ks_scope, chain) = Self::parts(token)?;
        Ok(Self {
            iss,
            aud,
            sub: common.sub,
            exp: common.exp,
            iat: common.iat,
            jti,
            amr: common.amr,
            aid: common.aid,
            ks_scope,
            chain,
            cnf: None,
        })
    }

    fn parts(
        token: &TokenPayload,
    ) -> Result<(Common, Option<TokenScope>, Option<TokenChain>), TokenClaimsError> {
        fn common(
            sub: &str,
            expires_at: DateTime<Utc>,
            issued_at: DateTime<Utc>,
            amr: &[String],
            aid: &[String],
        ) -> Common {
            Common {
                sub: sub.to_string(),
                exp: expires_at.timestamp(),
                iat: issued_at.timestamp(),
                amr: amr.to_vec(),
                aid: aid.to_vec(),
            }
        }
        fn federation(idp: &str, proto: &str, grp: &[String]) -> Option<TokenChain> {
            Some(TokenChain::Federated(TokenFederationClaim {
                idp: idp.to_string(),
                proto: proto.to_string(),
                grp: grp.to_vec(),
            }))
        }
        match token {
            TokenPayload::Restricted(p) => Ok((
                common(
                    &p.user_id,
                    p.expires_at,
                    p.issued_at,
                    &p.methods,
                    &p.audit_ids,
                ),
                Some(TokenScope::Project(p.project_id.clone())),
                Some(TokenChain::Restricted(TokenRestrictionClaim {
                    id: p.token_restriction_id.clone(),
                    renew: p.allow_renew,
                    rescope: p.allow_rescope,
                })),
            )),
            TokenPayload::FederationUnscoped(p) => Ok((
                common(
                    &p.user_id,
                    p.expires_at,
                    p.issued_at,
                    &p.methods,
                    &p.audit_ids,
                ),
                None,
                federation(&p.idp_id, &p.protocol_id, &p.group_ids),
            )),
            TokenPayload::FederationProjectScope(p) => Ok((
                common(
                    &p.user_id,
                    p.expires_at,
                    p.issued_at,
                    &p.methods,
                    &p.audit_ids,
                ),
                Some(TokenScope::Project(p.project_id.clone())),
                federation(&p.idp_id, &p.protocol_id, &p.group_ids),
            )),
            TokenPayload::FederationDomainScope(p) => Ok((
                common(
                    &p.user_id,
                    p.expires_at,
                    p.issued_at,
                    &p.methods,
                    &p.audit_ids,
                ),
                Some(TokenScope::Domain(p.domain_id.clone())),
                federation(&p.idp_id, &p.protocol_id, &p.group_ids),
            )),
            _ => {
                let anchors = JwsClaims::try_from(token)?;
                let ks_scope = match (
                    anchors.openstack_project_id,
                    anchors.openstack_domain_id,
                    anchors.openstack_system,
                ) {
                    (Some(project), None, None) => Some(TokenScope::Project(project)),
                    (None, Some(domain), None) => Some(TokenScope::Domain(domain)),
                    (None, None, Some(system)) => Some(TokenScope::System(system)),
                    (None, None, None) => None,
                    (project, domain, system) => {
                        return Err(TokenClaimsError::AmbiguousOrMissingScopeClaim(
                            [project.is_some(), domain.is_some(), system.is_some()]
                                .iter()
                                .filter(|present| **present)
                                .count(),
                        ));
                    }
                };
                let chain = match (anchors.openstack_trust_id, anchors.openstack_app_cred_id) {
                    (Some(trust), None) => Some(TokenChain::Trust(trust)),
                    (None, Some(app_cred)) => Some(TokenChain::AppCred(app_cred)),
                    (None, None) => None,
                    (Some(_), Some(_)) => return Err(TokenClaimsError::AmbiguousDelegation),
                };
                Ok((
                    Common {
                        sub: anchors.sub,
                        exp: anchors.exp,
                        iat: anchors.iat,
                        amr: anchors.openstack_methods,
                        aid: anchors.openstack_audit_ids,
                    },
                    ks_scope,
                    chain,
                ))
            }
        }
    }

    /// Reconstruct the [`TokenPayload`]. A chain that does not fit the scope
    /// is rejected.
    pub fn into_token_payload(self) -> Result<TokenPayload, TokenClaimsError> {
        let (user_id, methods, audit_ids) = (self.sub, self.amr, self.aid);
        let expires_at = from_unix(self.exp)?;
        let issued_at = from_unix(self.iat)?;
        match (self.chain, self.ks_scope) {
            (Some(TokenChain::Restricted(rst)), Some(TokenScope::Project(project_id))) => {
                Ok(TokenPayload::Restricted(RestrictedPayload {
                    user_id,
                    methods,
                    audit_ids,
                    expires_at,
                    issued_at,
                    token_restriction_id: rst.id,
                    project_id,
                    allow_renew: rst.renew,
                    allow_rescope: rst.rescope,
                }))
            }
            (Some(TokenChain::Restricted(_)), _) => Err(TokenClaimsError::InvalidRestrictedToken),
            (Some(TokenChain::Federated(f)), scope) => {
                let (idp_id, protocol_id, group_ids) = (f.idp, f.proto, f.grp);
                match scope {
                    None => Ok(TokenPayload::FederationUnscoped(
                        FederationUnscopedPayload {
                            user_id,
                            methods,
                            audit_ids,
                            expires_at,
                            issued_at,
                            idp_id,
                            protocol_id,
                            group_ids,
                        },
                    )),
                    Some(TokenScope::Project(project_id)) => Ok(
                        TokenPayload::FederationProjectScope(FederationProjectScopePayload {
                            user_id,
                            methods,
                            audit_ids,
                            expires_at,
                            issued_at,
                            project_id,
                            idp_id,
                            protocol_id,
                            group_ids,
                        }),
                    ),
                    Some(TokenScope::Domain(domain_id)) => Ok(TokenPayload::FederationDomainScope(
                        FederationDomainScopePayload {
                            user_id,
                            methods,
                            audit_ids,
                            expires_at,
                            issued_at,
                            domain_id,
                            idp_id,
                            protocol_id,
                            group_ids,
                        },
                    )),
                    Some(TokenScope::System(_)) => Err(TokenClaimsError::InvalidFederatedToken),
                }
            }
            (chain, scope) => {
                let mut anchors = JwsClaims {
                    sub: user_id,
                    exp: self.exp,
                    iat: self.iat,
                    openstack_methods: methods,
                    openstack_audit_ids: audit_ids,
                    openstack_project_id: None,
                    openstack_domain_id: None,
                    openstack_system: None,
                    openstack_trust_id: None,
                    openstack_app_cred_id: None,
                };
                match scope {
                    Some(TokenScope::Project(id)) => anchors.openstack_project_id = Some(id),
                    Some(TokenScope::Domain(id)) => anchors.openstack_domain_id = Some(id),
                    Some(TokenScope::System(id)) => anchors.openstack_system = Some(id),
                    None => {}
                }
                match chain {
                    Some(TokenChain::Trust(id)) => anchors.openstack_trust_id = Some(id),
                    Some(TokenChain::AppCred(id)) => anchors.openstack_app_cred_id = Some(id),
                    _ => {}
                }
                if (anchors.openstack_trust_id.is_some() || anchors.openstack_app_cred_id.is_some())
                    && anchors.openstack_project_id.is_none()
                {
                    return Err(TokenClaimsError::DelegationWithoutProject);
                }
                anchors.into_token_payload()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{SubsecRound, Utc};
    use serde_json::json;

    use super::*;
    use crate::token::{ProjectScopePayload, TrustPayload, UnscopedPayload};

    fn now() -> DateTime<Utc> {
        Utc::now().trunc_subsecs(0)
    }

    fn claims_of(token: &TokenPayload) -> KeystoneTokenClaims {
        KeystoneTokenClaims::new(token, "iss".into(), "keystone".into(), "jti".into()).unwrap()
    }

    fn project_token() -> TokenPayload {
        TokenPayload::ProjectScope(ProjectScopePayload {
            user_id: "u".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["a".into()],
            expires_at: now(),
            issued_at: now(),
            project_id: "p".into(),
        })
    }

    fn restricted_token() -> TokenPayload {
        TokenPayload::Restricted(RestrictedPayload {
            user_id: "u".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["a".into()],
            expires_at: now(),
            issued_at: now(),
            token_restriction_id: "r".into(),
            project_id: "p".into(),
            allow_renew: true,
            allow_rescope: false,
        })
    }

    fn federated_tokens() -> Vec<TokenPayload> {
        let group_ids = vec!["g1".to_string(), "g2".to_string()];
        vec![
            TokenPayload::FederationUnscoped(FederationUnscopedPayload {
                user_id: "u".into(),
                methods: vec!["openid".into()],
                audit_ids: vec!["a".into()],
                expires_at: now(),
                issued_at: now(),
                idp_id: "idp".into(),
                protocol_id: "oidc".into(),
                group_ids: group_ids.clone(),
            }),
            TokenPayload::FederationProjectScope(FederationProjectScopePayload {
                user_id: "u".into(),
                methods: vec!["openid".into()],
                audit_ids: vec!["a".into()],
                expires_at: now(),
                issued_at: now(),
                project_id: "p".into(),
                idp_id: "idp".into(),
                protocol_id: "oidc".into(),
                group_ids: group_ids.clone(),
            }),
            TokenPayload::FederationDomainScope(FederationDomainScopePayload {
                user_id: "u".into(),
                methods: vec!["openid".into()],
                audit_ids: vec!["a".into()],
                expires_at: now(),
                issued_at: now(),
                domain_id: "d".into(),
                idp_id: "idp".into(),
                protocol_id: "oidc".into(),
                group_ids,
            }),
        ]
    }

    fn base_json() -> serde_json::Value {
        json!({
            "iss": "i", "aud": "keystone", "sub": "u", "exp": 2, "iat": 1,
            "jti": "j", "amr": ["password"], "aid": ["a"]
        })
    }

    #[test]
    fn test_wire_is_compact_and_roleless() {
        let json = serde_json::to_value(claims_of(&project_token())).unwrap();
        assert_eq!(json["ks_scope"], json!({"project": "p"}));
        assert_eq!(json["amr"], json!(["password"]));
        assert_eq!(json["aid"], json!(["a"]));
        for absent in ["roles", "nbf", "token_use", "chain", "cnf"] {
            assert!(
                json.get(absent).is_none(),
                "{absent} must not be on the wire"
            );
        }
        assert!(!json.to_string().contains("openstack_"));
    }

    #[test]
    fn test_unscoped_has_no_scope_claim() {
        let token = TokenPayload::Unscoped(UnscopedPayload {
            user_id: "u".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["a".into()],
            ..Default::default()
        });
        let claims = claims_of(&token);
        assert!(claims.ks_scope.is_none());
        let json = serde_json::to_value(&claims).unwrap();
        assert!(json.get("ks_scope").is_none());
        assert!(matches!(
            claims.into_token_payload().unwrap(),
            TokenPayload::Unscoped(_)
        ));
    }

    #[test]
    fn test_project_roundtrip() {
        let back = claims_of(&project_token()).into_token_payload().unwrap();
        assert!(matches!(back, TokenPayload::ProjectScope(p) if p.project_id == "p"));
    }

    #[test]
    fn test_trust_roundtrip_keeps_chain_and_scope_apart() {
        let token = TokenPayload::Trust(TrustPayload {
            user_id: "u".into(),
            methods: vec!["password".into()],
            audit_ids: vec!["a".into()],
            expires_at: now(),
            issued_at: now(),
            trust_id: "t".into(),
            project_id: "p".into(),
        });
        let claims = claims_of(&token);
        assert_eq!(claims.ks_scope, Some(TokenScope::Project("p".into())));
        assert_eq!(claims.chain, Some(TokenChain::Trust("t".into())));
        assert!(matches!(
            claims.into_token_payload().unwrap(),
            TokenPayload::Trust(p) if p.trust_id == "t" && p.project_id == "p"
        ));
    }

    #[test]
    fn test_restricted_roundtrip() {
        let token = restricted_token();
        let claims = claims_of(&token);
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(
            json["chain"],
            json!({"restricted": {"id": "r", "renew": true}})
        );
        assert_eq!(json["ks_scope"], json!({"project": "p"}));
        assert_eq!(claims.into_token_payload().unwrap(), token);
    }

    #[test]
    fn test_federated_roundtrip() {
        for token in federated_tokens() {
            let claims = claims_of(&token);
            let json = serde_json::to_value(&claims).unwrap();
            assert_eq!(
                json["chain"],
                json!({"federated": {"idp": "idp", "proto": "oidc", "grp": ["g1", "g2"]}})
            );
            assert_eq!(claims.into_token_payload().unwrap(), token);
        }
    }

    #[test]
    fn test_federated_without_groups_omits_them() {
        let mut claims = claims_of(&federated_tokens()[0]);
        if let Some(TokenChain::Federated(f)) = claims.chain.as_mut() {
            f.grp.clear();
        }
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(
            json["chain"],
            json!({"federated": {"idp": "idp", "proto": "oidc"}})
        );
    }

    #[test]
    fn test_federated_system_scope_is_rejected() {
        let mut claims = claims_of(&federated_tokens()[0]);
        claims.ks_scope = Some(TokenScope::System("all".into()));
        assert!(matches!(
            claims.into_token_payload(),
            Err(TokenClaimsError::InvalidFederatedToken)
        ));
    }

    #[test]
    fn test_chain_needs_its_scope() {
        for (scope, chain) in [
            (None, TokenChain::Trust("t".into())),
            (
                Some(TokenScope::Domain("d".into())),
                TokenChain::Trust("t".into()),
            ),
            (None, TokenChain::AppCred("c".into())),
            (
                Some(TokenScope::System("all".into())),
                TokenChain::AppCred("c".into()),
            ),
        ] {
            let mut claims = claims_of(&project_token());
            claims.ks_scope = scope;
            claims.chain = Some(chain);
            assert!(matches!(
                claims.into_token_payload(),
                Err(TokenClaimsError::DelegationWithoutProject)
            ));
        }
        for scope in [None, Some(TokenScope::Domain("d".into()))] {
            let mut claims = claims_of(&restricted_token());
            claims.ks_scope = scope;
            assert!(matches!(
                claims.into_token_payload(),
                Err(TokenClaimsError::InvalidRestrictedToken)
            ));
        }
    }

    #[test]
    fn test_two_chains_do_not_deserialize() {
        let mut json = base_json();
        json["chain"] = json!({"trust": "t", "app_cred": "c"});
        assert!(serde_json::from_value::<KeystoneTokenClaims>(json).is_err());
    }

    #[test]
    fn test_two_scopes_do_not_deserialize() {
        let mut json = base_json();
        json["ks_scope"] = json!({"project": "p", "domain": "d"});
        assert!(serde_json::from_value::<KeystoneTokenClaims>(json).is_err());
    }

    #[test]
    fn test_unknown_scope_or_chain_does_not_deserialize() {
        let mut json = base_json();
        json["ks_scope"] = json!({"region": "r"});
        assert!(serde_json::from_value::<KeystoneTokenClaims>(json).is_err());
        let mut json = base_json();
        json["chain"] = json!({"saml": "x"});
        assert!(serde_json::from_value::<KeystoneTokenClaims>(json).is_err());
    }
}
