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

use openstack_keystone_api_types::v4::oauth2_key::EnsureSigningKeyResponse;
use openstack_keystone_config::LoadedConfig;

use super::{domain_url, ensure_success};
use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client};

/// Idempotently ensure a domain has an OAuth2/OIDC signing key (ADR 0026 §3).
///
/// A domain created through Keystone's own `POST /v3/domains` gets its
/// signing key automatically, provisioned by `Oauth2KeyHook` when the
/// domain-create event fires. A domain provisioned any other way -- most
/// notably the legacy Python `keystone-manage bootstrap`, which writes the
/// `default` domain straight into the database and never calls the Rust
/// API -- never fires that hook and is left without a signing key
/// indefinitely, so `/token` and `/jwks` fail for it. Run this once after
/// such a bootstrap (safe to re-run: a no-op if the domain already has a
/// key).
#[derive(Parser)]
pub(super) struct EnsureSigningKeyCommand {
    /// Domain to provision a signing key for.
    #[arg(long)]
    pub domain: String,
}

impl EnsureSigningKeyCommand {
    /// Ensure the signing key through a pre-built admin client.
    pub(super) async fn ensure_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<EnsureSigningKeyResponse, Report> {
        let res = client
            .post(domain_url(base_url, &self.domain, &["ensure-signing-key"]))
            .send()
            .await
            .wrap_err("ensure-signing-key request failed")?;
        let res = ensure_success(res, "ensure-signing-key").await?;
        Ok(res.json().await?)
    }
}

#[async_trait]
impl PerformAction for EnsureSigningKeyCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.ensure_with_client(&client, ADMIN_BASE_URL).await?;
        println!(
            "OAuth2 signing key present for domain {}. kid: {}",
            self.domain, body.kid
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
        inner: EnsureSigningKeyCommand,
    }

    #[test]
    fn test_parses_domain_flag() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
    }

    #[tokio::test]
    async fn test_ensure_returns_kid() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/ensure-signing-key");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({"kid": "kid-1"}));
        });

        let cmd = EnsureSigningKeyCommand {
            domain: "domain-1".to_string(),
        };
        let body = cmd
            .ensure_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body.kid, "kid-1");
    }

    #[tokio::test]
    async fn test_ensure_reports_server_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/ensure-signing-key");
            then.status(500).body("boom");
        });

        let cmd = EnsureSigningKeyCommand {
            domain: "domain-1".to_string(),
        };
        let err = cmd
            .ensure_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ensure-signing-key failed"));
        assert!(err.to_string().contains("boom"));
    }
}
