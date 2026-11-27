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

use std::collections::HashMap;

use async_trait::async_trait;
use clap::Parser;
use color_eyre::Report;
use reqwest::{Client, Method};
use serde_json::Value;

use openstack_keystone_api_types::v4::oauth2_client::{
    GrantType, OAuth2ClientCreate, OAuth2ClientCreateRequest, OAuth2ClientCreateResponse,
};
use openstack_keystone_config::LoadedConfig;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, OutputFormat, build_admin_client, print_json};
use crate::oauth2::client::{Common, call, parse_claim, parse_grant_type, print_client};

/// Register a client.
#[derive(Parser)]
pub(crate) struct CreateCommand {
    #[command(flatten)]
    common: Common,
    /// Stable identifier of the registration.
    #[arg(long)]
    provider_id: String,
    /// Display name.
    #[arg(long)]
    name: String,
    /// Register a public client (no secret). Confidential is the default.
    #[arg(long)]
    public: bool,
    /// Redirect URI (repeatable).
    #[arg(long = "redirect-uri")]
    redirect_uris: Vec<String>,
    /// Grant type, for example `authorization_code` (repeatable).
    #[arg(long = "grant-type", value_parser = parse_grant_type)]
    grant_types: Vec<GrantType>,
    /// Allowed scope (repeatable).
    #[arg(long = "scope")]
    scopes: Vec<String>,
    /// Skip the consent page for this client.
    #[arg(long)]
    pre_authorized: bool,
    /// Claims template entry `key=value` (repeatable).
    #[arg(long = "claims-template", value_parser = parse_claim)]
    claims_template: Vec<(String, String)>,
    /// Token endpoint authentication method. Defaults to `none` for public
    /// clients and `client_secret_basic` otherwise.
    #[arg(long)]
    token_endpoint_auth_method: Option<String>,
    /// Do not require PKCE. PKCE is required by default; the server rejects
    /// this for public clients.
    #[arg(long)]
    no_pkce: bool,
    /// Description shown on the consent page.
    #[arg(long)]
    description: Option<String>,
}

impl CreateCommand {
    fn request(&self) -> OAuth2ClientCreateRequest {
        let confidential = !self.public;
        let method = self.token_endpoint_auth_method.clone().unwrap_or_else(|| {
            if confidential {
                "client_secret_basic".to_string()
            } else {
                "none".to_string()
            }
        });
        OAuth2ClientCreateRequest {
            oauth2_client: OAuth2ClientCreate {
                allowed_scopes: self.scopes.clone(),
                claims_template: self
                    .claims_template
                    .iter()
                    .cloned()
                    .collect::<HashMap<_, _>>(),
                confidential,
                grant_types: self.grant_types.clone(),
                pre_authorized: self.pre_authorized,
                provider_id: self.provider_id.clone(),
                redirect_uris: self.redirect_uris.clone(),
                require_pkce: !self.no_pkce,
                token_endpoint_auth_method: method,
                name: self.name.clone(),
                description: self.description.clone(),
                logo_uri: None,
                policy_uri: None,
                tos_uri: None,
                contacts: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                spiffe_ids: Vec::new(),
                delegation: None,
                dpop_bound_access_tokens: false,
            },
        }
    }

    /// Register the client through a pre-built admin client. Returns the raw
    /// response body.
    pub(crate) async fn create_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<Value, Report> {
        call(
            client,
            base_url,
            Method::POST,
            &self.common.domain,
            &[],
            &[],
            Some(&self.request()),
        )
        .await
    }
}

#[async_trait]
impl PerformAction for CreateCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.create_with_client(&client, ADMIN_BASE_URL).await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let res: OAuth2ClientCreateResponse = serde_json::from_value(body)?;
                print_client(&res.oauth2_client);
                if let Some(secret) = res.client_secret {
                    println!("client_secret: {secret}");
                    println!("(shown once, store it now)");
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use httpmock::{Method as MockMethod, MockServer};

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        inner: CreateCommand,
    }

    #[test]
    fn test_parses_create() {
        let w = Wrapper::parse_from([
            "create",
            "--domain",
            "d1",
            "--provider-id",
            "p1",
            "--name",
            "Grafana",
            "--public",
            "--redirect-uri",
            "https://a/cb",
            "--redirect-uri",
            "https://b/cb",
            "--grant-type",
            "authorization_code",
            "--scope",
            "openid",
            "--claims-template",
            "team=ops",
            "--format",
            "json",
        ]);
        let c = w.inner;
        assert!(c.public);
        assert_eq!(c.redirect_uris.len(), 2);
        assert_eq!(c.grant_types, vec![GrantType::AuthorizationCode]);
        assert_eq!(c.claims_template, vec![("team".into(), "ops".into())]);
        assert!(matches!(c.common.format, OutputFormat::Json));
    }

    #[test]
    fn test_create_request_defaults() {
        let w = Wrapper::parse_from([
            "create",
            "--domain",
            "d",
            "--provider-id",
            "p",
            "--name",
            "n",
        ]);
        let req = w.inner.request();
        assert!(req.oauth2_client.confidential);
        assert!(req.oauth2_client.require_pkce);
        assert_eq!(
            req.oauth2_client.token_endpoint_auth_method,
            "client_secret_basic"
        );
    }

    #[test]
    fn test_rejects_bad_claim_and_grant() {
        assert!(
            Wrapper::try_parse_from([
                "create",
                "--domain",
                "d",
                "--provider-id",
                "p",
                "--name",
                "n",
                "--claims-template",
                "nokv",
            ])
            .is_err()
        );
        assert!(
            Wrapper::try_parse_from([
                "create",
                "--domain",
                "d",
                "--provider-id",
                "p",
                "--name",
                "n",
                "--grant-type",
                "bogus",
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn test_create_posts_client() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(MockMethod::POST)
                .path("/v4/oauth2/d1/clients")
                .json_body_includes(r#"{"oauth2_client":{"provider_id":"p1"}}"#);
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "oauth2_client": {"provider_id": "p1"},
                    "client_secret": "s3cret"
                }));
        });

        let w = Wrapper::parse_from([
            "create",
            "--domain",
            "d1",
            "--provider-id",
            "p1",
            "--name",
            "n",
        ]);
        let body = w
            .inner
            .create_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body["client_secret"], "s3cret");
    }
}
