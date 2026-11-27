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
use color_eyre::{Report, eyre::WrapErr};
use reqwest::Client;

use openstack_keystone_api_types::v4::oauth2_key::{
    ConfirmRotateSigningKeyRequest, ConfirmRotateSigningKeyResponse,
};
use openstack_keystone_config::LoadedConfig;

use super::{domain_url, ensure_success};
use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client};

/// Confirm a pending emergency signing-key rotation (dual-control second
/// factor).
///
/// Must be invoked by a different operator than the one who ran
/// `rotate-signing-key --emergency`, within 15 minutes of that command --
/// enforced by the provider layer. If the window has already expired, the
/// pending rotation has been automatically aborted and this command will
/// return an error.
#[derive(Parser)]
pub(super) struct ConfirmRotateSigningKeyCommand {
    /// Domain whose signing-key rotation is being confirmed.
    #[arg(long)]
    pub domain: String,

    /// The rotation_id printed by `rotate-signing-key --emergency`.
    #[arg(long)]
    pub rotation_id: String,

    /// JTIs known to have been issued by the compromised key during the
    /// incident window, to add to the JTI revocation list. Repeat the flag
    /// for multiple JTIs.
    #[arg(long = "revoke-jti")]
    pub revoke_jtis: Vec<String>,
}

impl ConfirmRotateSigningKeyCommand {
    /// Confirm the rotation through a pre-built admin client.
    pub(super) async fn confirm_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<ConfirmRotateSigningKeyResponse, Report> {
        let res = client
            .post(domain_url(
                base_url,
                &self.domain,
                &["confirm-rotate-signing-key"],
            ))
            .json(&ConfirmRotateSigningKeyRequest {
                rotation_id: self.rotation_id.clone(),
                revoke_jtis: self.revoke_jtis.clone(),
            })
            .send()
            .await
            .wrap_err("confirm-rotate-signing-key request failed")?;
        let res = ensure_success(res, "confirm-rotate-signing-key").await?;
        Ok(res.json().await?)
    }
}

#[async_trait]
impl PerformAction for ConfirmRotateSigningKeyCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.confirm_with_client(&client, ADMIN_BASE_URL).await?;
        println!(
            "Emergency signing-key rotation {} confirmed for domain {}. New kid: {}",
            self.rotation_id, self.domain, body.kid
        );
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
        inner: ConfirmRotateSigningKeyCommand,
    }

    #[test]
    fn test_parses_repeated_revoke_jti_flags() {
        let wrapper = Wrapper::parse_from([
            "oauth2",
            "--domain",
            "domain-1",
            "--rotation-id",
            "rot-1",
            "--revoke-jti",
            "jti-a",
            "--revoke-jti",
            "jti-b",
        ]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert_eq!(wrapper.inner.rotation_id, "rot-1");
        assert_eq!(wrapper.inner.revoke_jtis, vec!["jti-a", "jti-b"]);
    }

    #[test]
    fn test_revoke_jti_defaults_to_empty() {
        let wrapper =
            Wrapper::parse_from(["oauth2", "--domain", "domain-1", "--rotation-id", "rot-1"]);
        assert!(wrapper.inner.revoke_jtis.is_empty());
    }

    #[tokio::test]
    async fn test_confirm_posts_rotation_and_jtis() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/confirm-rotate-signing-key")
                .json_body(serde_json::json!({
                    "rotation_id": "rot-1",
                    "revoke_jtis": ["jti-a"]
                }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({"kid": "kid-3"}));
        });

        let cmd = ConfirmRotateSigningKeyCommand {
            domain: "domain-1".to_string(),
            rotation_id: "rot-1".to_string(),
            revoke_jtis: vec!["jti-a".to_string()],
        };
        let body = cmd
            .confirm_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body.kid, "kid-3");
    }

    #[tokio::test]
    async fn test_confirm_reports_expired_rotation() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/confirm-rotate-signing-key");
            then.status(404).body("rotation expired");
        });

        let cmd = ConfirmRotateSigningKeyCommand {
            domain: "domain-1".to_string(),
            rotation_id: "rot-1".to_string(),
            revoke_jtis: vec![],
        };
        let err = cmd
            .confirm_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("confirm-rotate-signing-key failed")
        );
        assert!(err.to_string().contains("rotation expired"));
    }
}
