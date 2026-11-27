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

use openstack_keystone_api_types::v4::oauth2_client::OAuth2ClientRotateSecretResponse;
use openstack_keystone_config::LoadedConfig;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, OutputFormat, build_admin_client, print_json};
use crate::oauth2::client::{Common, call};

/// Rotate the secret of a confidential client.
#[derive(Parser)]
pub(crate) struct RotateSecretCommand {
    #[command(flatten)]
    common: Common,
    /// Registration identifier.
    #[arg(long)]
    provider_id: String,
}

impl RotateSecretCommand {
    /// Rotate the client secret through a pre-built admin client. Returns the
    /// raw response body.
    pub(crate) async fn rotate_secret_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<Value, Report> {
        call(
            client,
            base_url,
            Method::POST,
            &self.common.domain,
            &[&self.provider_id, "rotate-secret"],
            &[],
            None::<&()>,
        )
        .await
    }
}

#[async_trait]
impl PerformAction for RotateSecretCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self
            .rotate_secret_with_client(&client, ADMIN_BASE_URL)
            .await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let res: OAuth2ClientRotateSecretResponse = serde_json::from_value(body)?;
                println!("client_secret: {}", res.client_secret);
                println!("(shown once, store it now)");
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
        inner: RotateSecretCommand,
    }

    #[tokio::test]
    async fn test_rotate_secret_hits_rotate_endpoint() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(MockMethod::POST)
                .path("/v4/oauth2/d1/clients/p1/rotate-secret");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({"client_secret": "new"}));
        });

        let w = Wrapper::parse_from(["rotate-secret", "--domain", "d1", "--provider-id", "p1"]);
        let body = w
            .inner
            .rotate_secret_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body["client_secret"], "new");
    }
}
