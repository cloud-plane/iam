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
use color_eyre::Report;
use reqwest::{Client, Method};
use serde_json::Value;

use openstack_keystone_api_types::v4::oauth2_client::{
    GrantType, OAuth2ClientResponse, OAuth2ClientUpdate, OAuth2ClientUpdateRequest,
};
use openstack_keystone_config::LoadedConfig;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, OutputFormat, build_admin_client, print_json};
use crate::oauth2::client::{Common, call, parse_claim, parse_grant_type, print_client};

/// Update mutable client settings.
#[derive(Parser)]
pub(crate) struct UpdateCommand {
    #[command(flatten)]
    common: Common,
    /// Registration identifier.
    #[arg(long)]
    provider_id: String,
    /// New display name.
    #[arg(long)]
    name: Option<String>,
    /// Enable or disable the client.
    #[arg(long)]
    enabled: Option<bool>,
    /// Replace the redirect URIs (repeatable). Lists cannot be emptied from
    /// the CLI.
    #[arg(long = "redirect-uri")]
    redirect_uris: Option<Vec<String>>,
    /// Replace the grant types (repeatable).
    #[arg(long = "grant-type", value_parser = parse_grant_type)]
    grant_types: Option<Vec<GrantType>>,
    /// Replace the allowed scopes (repeatable).
    #[arg(long = "scope")]
    scopes: Option<Vec<String>>,
    /// Set whether consent is skipped.
    #[arg(long)]
    pre_authorized: Option<bool>,
    /// Set whether PKCE is required.
    #[arg(long)]
    require_pkce: Option<bool>,
    /// New description; an empty string clears it.
    #[arg(long)]
    description: Option<String>,
    /// Replace the claims template with `key=value` entries (repeatable).
    #[arg(long = "claims-template", value_parser = parse_claim)]
    claims_template: Option<Vec<(String, String)>>,
}

impl UpdateCommand {
    fn request(&self) -> OAuth2ClientUpdateRequest {
        OAuth2ClientUpdateRequest {
            oauth2_client: OAuth2ClientUpdate {
                name: self.name.clone(),
                enabled: self.enabled,
                redirect_uris: self.redirect_uris.clone(),
                grant_types: self.grant_types.clone(),
                allowed_scopes: self.scopes.clone(),
                pre_authorized: self.pre_authorized,
                require_pkce: self.require_pkce,
                description: self.description.clone(),
                claims_template: self
                    .claims_template
                    .as_ref()
                    .map(|c| c.iter().cloned().collect()),
                ..Default::default()
            },
        }
    }

    /// Update the client through a pre-built admin client. Returns the raw
    /// response body.
    pub(crate) async fn update_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<Value, Report> {
        call(
            client,
            base_url,
            Method::PUT,
            &self.common.domain,
            &[&self.provider_id],
            &[],
            Some(&self.request()),
        )
        .await
    }
}

#[async_trait]
impl PerformAction for UpdateCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.update_with_client(&client, ADMIN_BASE_URL).await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let res: OAuth2ClientResponse = serde_json::from_value(body)?;
                print_client(&res.oauth2_client);
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
        inner: UpdateCommand,
    }

    #[test]
    fn test_parses_update_extras() {
        let w = Wrapper::parse_from([
            "update",
            "--domain",
            "d",
            "--provider-id",
            "p",
            "--require-pkce",
            "true",
            "--description",
            "",
            "--claims-template",
            "a=b",
        ]);
        let c = w.inner;
        assert_eq!(c.require_pkce, Some(true));
        assert_eq!(c.description.as_deref(), Some(""));
        assert_eq!(c.claims_template, Some(vec![("a".into(), "b".into())]));
    }

    #[test]
    fn test_rejects_bad_claim() {
        assert!(
            Wrapper::try_parse_from([
                "update",
                "--domain",
                "d",
                "--provider-id",
                "p",
                "--claims-template",
                "nokv",
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn test_update_puts_only_given_fields() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(MockMethod::PUT)
                .path("/v4/oauth2/d1/clients/p1")
                .json_body(serde_json::json!({
                    "oauth2_client": {"enabled": false}
                }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "oauth2_client": {"provider_id": "p1", "enabled": false}
                }));
        });

        let w = Wrapper::parse_from([
            "update",
            "--domain",
            "d1",
            "--provider-id",
            "p1",
            "--enabled",
            "false",
        ]);
        let body = w
            .inner
            .update_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body["oauth2_client"]["enabled"], false);
    }
}
