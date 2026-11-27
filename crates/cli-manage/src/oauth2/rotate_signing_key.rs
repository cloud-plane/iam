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

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::WrapErr, eyre::eyre};
use reqwest::Client;

use openstack_keystone_api_types::v4::oauth2_key::{
    RotateSigningKeyRequest, RotateSigningKeyResponse,
};
use openstack_keystone_config::LoadedConfig;

use super::{domain_url, ensure_success};
use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client};

/// Rotate an OAuth2/OIDC domain's signing key (ADR 0026 §3).
///
/// Normal rotation (default) generates a new key, promotes it to `Primary`
/// and demotes the current `Primary` to `Previous` immediately -- both keys
/// remain published in JWKS so in-flight tokens still verify.
///
/// Use `--emergency` when the current signing key is suspected or confirmed
/// compromised. Emergency rotation only stages the new key: a second
/// operator must run `confirm-rotate-signing-key` with the returned
/// rotation-id within 15 minutes, or the rotation is automatically aborted.
///
/// Use `--local-quorum-bypass` (with `--justification`) instead of
/// `--emergency` when the cluster has lost Raft quorum and the ordinary
/// emergency path -- itself a Raft proposal -- would block forever
/// (ADR 0028 §2). The candidate is written only to the responding node's
/// local emergency store; it must be explicitly reconciled once quorum
/// returns (not yet implemented). Refused unless that node's
/// `[local_emergency]` guardrail currently permits it.
#[derive(Parser)]
pub(super) struct RotateSigningKeyCommand {
    /// Domain whose signing key should be rotated.
    #[arg(long)]
    pub domain: String,

    /// Initiate an emergency rotation (dual-control required).
    #[arg(long, default_value_t = false)]
    pub emergency: bool,

    /// Stage a node-local, quorum-bypass emergency rotation instead
    /// (ADR 0028 §2). Mutually exclusive in effect with `--emergency`: when
    /// set, `--emergency` is ignored. Requires `--justification`.
    #[arg(long, default_value_t = false)]
    pub local_quorum_bypass: bool,

    /// Required with `--local-quorum-bypass`: the operator's reason for
    /// invoking the bypass, recorded with the candidate for audit.
    #[arg(long)]
    pub justification: Option<String>,
}

impl RotateSigningKeyCommand {
    /// Request the rotation through a pre-built admin client.
    pub(super) async fn rotate_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<RotateSigningKeyResponse, Report> {
        let res = client
            .post(domain_url(base_url, &self.domain, &["rotate-signing-key"]))
            .json(&RotateSigningKeyRequest {
                emergency: self.emergency,
                local_quorum_bypass: self.local_quorum_bypass,
                justification: self.justification.clone(),
            })
            .send()
            .await
            .wrap_err("rotate-signing-key request failed")?;
        let res = ensure_success(res, "rotate-signing-key").await?;
        Ok(res.json().await?)
    }
}

#[async_trait]
impl PerformAction for RotateSigningKeyCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        if self.local_quorum_bypass && self.justification.is_none() {
            return Err(eyre!(
                "--justification is required when --local-quorum-bypass is set"
            ));
        }

        let client = build_admin_client(config).await?;
        let body = self.rotate_with_client(&client, ADMIN_BASE_URL).await?;

        if self.local_quorum_bypass {
            match body.local_rotation_id {
                Some(rotation_id) => {
                    println!(
                        "Local quorum-bypass signing-key rotation staged for domain {} on the \
                         responding node.\nrotation_id={rotation_id}\n\n\
                         This candidate is NOT yet replicated. Once quorum returns, an operator \
                         must explicitly reconcile it.",
                        self.domain,
                    );
                }
                None => {
                    println!("Local quorum-bypass rotation staged but no rotation_id returned.");
                }
            }
        } else if self.emergency {
            match (body.pending_rotation_id, body.expires_at) {
                (Some(rotation_id), Some(expires_at)) => {
                    println!(
                        "Emergency signing-key rotation staged for domain {}.\n\
                         rotation_id={rotation_id}\n\
                         expires_at={expires_at}\n\n\
                         A second operator must confirm within 15 minutes:\n\
                         \n  keystone-manage oauth2 confirm-rotate-signing-key \\\n\
                           \t--domain {} --rotation-id {rotation_id}",
                        self.domain, self.domain,
                    );
                }
                _ => {
                    println!("Emergency signing-key rotation staged but no rotation_id returned.");
                }
            }
        } else {
            println!(
                "Signing-key rotation committed for domain {}. New kid: {}",
                self.domain,
                body.kid.unwrap_or_default()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use httpmock::{Method, MockServer};

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        inner: RotateSigningKeyCommand,
    }

    #[test]
    fn test_parses_domain_and_emergency_flags() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1", "--emergency"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert!(wrapper.inner.emergency);
    }

    #[test]
    fn test_emergency_defaults_to_false() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert!(!wrapper.inner.emergency);
    }

    #[tokio::test]
    async fn test_rotate_commits_normal_rotation() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/rotate-signing-key")
                .json_body(serde_json::json!({
                    "emergency": false,
                    "local_quorum_bypass": false,
                    "justification": null
                }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({"kid": "kid-2"}));
        });

        let cmd = RotateSigningKeyCommand {
            domain: "domain-1".to_string(),
            emergency: false,
            local_quorum_bypass: false,
            justification: None,
        };
        let body = cmd
            .rotate_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body.kid.as_deref(), Some("kid-2"));
    }

    #[tokio::test]
    async fn test_rotate_reports_server_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/rotate-signing-key");
            then.status(403).body("forbidden");
        });

        let cmd = RotateSigningKeyCommand {
            domain: "domain-1".to_string(),
            emergency: true,
            local_quorum_bypass: false,
            justification: None,
        };
        let err = cmd
            .rotate_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rotate-signing-key failed"));
        assert!(err.to_string().contains("forbidden"));
    }

    #[test]
    fn test_parses_local_quorum_bypass_and_justification() {
        let wrapper = Wrapper::parse_from([
            "oauth2",
            "--domain",
            "domain-1",
            "--local-quorum-bypass",
            "--justification",
            "suspected key compromise",
        ]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert!(wrapper.inner.local_quorum_bypass);
        assert_eq!(
            wrapper.inner.justification.as_deref(),
            Some("suspected key compromise")
        );
    }

    #[test]
    fn test_local_quorum_bypass_defaults_to_false() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1"]);
        assert!(!wrapper.inner.local_quorum_bypass);
        assert!(wrapper.inner.justification.is_none());
    }

    #[tokio::test]
    async fn test_take_action_rejects_local_quorum_bypass_without_justification() {
        let cfg = LoadedConfig::new(Default::default());
        let command = RotateSigningKeyCommand {
            domain: "domain-1".to_string(),
            emergency: false,
            local_quorum_bypass: true,
            justification: None,
        };

        let err = command.take_action(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("--justification is required"),
            "unexpected error: {err}"
        );
    }
}
