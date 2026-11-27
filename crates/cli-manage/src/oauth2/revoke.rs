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
//! # Bulk revocation of OAuth2 sessions (ADR 0026 §9).

use async_trait::async_trait;
use clap::{ArgGroup, Parser};
use color_eyre::{Report, eyre::WrapErr};
use reqwest::Client;

use openstack_keystone_api_types::v4::oauth2_revocation::{
    Oauth2RevocationRequest, Oauth2RevocationResponse,
};
use openstack_keystone_config::LoadedConfig;

use super::{domain_url, ensure_success};
use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, OutputFormat, build_admin_client, print_json};

/// Revoke the refresh token families of a user, a client or a whole domain,
/// for example during an incident.
#[derive(Parser)]
#[command(group(ArgGroup::new("target").required(true).args(["user", "client", "all"])))]
pub(super) struct RevokeCommand {
    /// Domain the revocation applies to.
    #[arg(long)]
    domain: String,
    /// Revoke every session of this user.
    #[arg(long)]
    user: Option<String>,
    /// Revoke every session issued to this `client_id`.
    #[arg(long)]
    client: Option<String>,
    /// Revoke every session in the domain.
    #[arg(long)]
    all: bool,
    /// Reason recorded in the server log.
    #[arg(long)]
    reason: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

impl RevokeCommand {
    /// Send the revocation through a pre-built admin client.
    pub(super) async fn revoke_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<Oauth2RevocationResponse, Report> {
        let req = Oauth2RevocationRequest {
            user_id: self.user.clone(),
            client_id: self.client.clone(),
            all: self.all,
            reason: self.reason.clone(),
        };
        let res = client
            .post(domain_url(base_url, &self.domain, &["revocations"]))
            .json(&req)
            .send()
            .await
            .wrap_err("revocation request failed")?;
        let res = ensure_success(res, "revocation").await?;
        Ok(res.json().await?)
    }
}

#[async_trait]
impl PerformAction for RevokeCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.revoke_with_client(&client, ADMIN_BASE_URL).await?;
        match self.format {
            OutputFormat::Json => print_json(&body)?,
            OutputFormat::Text => println!("revoked {} session families", body.revoked_families),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use httpmock::{Method, MockServer};

    use super::*;

    #[test]
    fn test_requires_one_target() {
        assert!(RevokeCommand::try_parse_from(["revoke", "--domain", "d"]).is_err());
        assert!(RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--user", "u"]).is_ok());
        assert!(
            RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--client", "c"]).is_ok()
        );
        assert!(RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--all"]).is_ok());
        assert!(
            RevokeCommand::try_parse_from(["revoke", "--domain", "d", "--all", "--user", "u"])
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_revoke_posts_user_target() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/revocations")
                .json_body(serde_json::json!({
                    "user_id": "user-1",
                    "all": false,
                    "reason": "incident-42"
                }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({"revoked_families": 3}));
        });

        let cmd = RevokeCommand::try_parse_from([
            "revoke",
            "--domain",
            "domain-1",
            "--user",
            "user-1",
            "--reason",
            "incident-42",
        ])
        .unwrap();
        let body = cmd
            .revoke_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body.revoked_families, 3);
    }

    #[tokio::test]
    async fn test_revoke_reports_server_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/revocations");
            then.status(400).body("bad target");
        });

        let cmd =
            RevokeCommand::try_parse_from(["revoke", "--domain", "domain-1", "--all"]).unwrap();
        let err = cmd
            .revoke_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("revocation failed"));
        assert!(err.to_string().contains("bad target"));
    }
}
