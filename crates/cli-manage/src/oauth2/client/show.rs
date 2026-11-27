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

use openstack_keystone_api_types::v4::oauth2_client::OAuth2ClientResponse;
use openstack_keystone_config::LoadedConfig;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, OutputFormat, build_admin_client, print_json};
use crate::oauth2::client::{Common, call, print_client};

/// Show one client.
#[derive(Parser)]
pub(crate) struct ShowCommand {
    #[command(flatten)]
    common: Common,
    /// Registration identifier.
    #[arg(long)]
    provider_id: String,
}

impl ShowCommand {
    /// Fetch the client through a pre-built admin client. Returns the raw
    /// response body.
    pub(crate) async fn show_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<Value, Report> {
        call(
            client,
            base_url,
            Method::GET,
            &self.common.domain,
            &[&self.provider_id],
            &[],
            None::<&()>,
        )
        .await
    }
}

#[async_trait]
impl PerformAction for ShowCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.show_with_client(&client, ADMIN_BASE_URL).await?;
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
        inner: ShowCommand,
    }

    #[tokio::test]
    async fn test_show_reports_server_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(MockMethod::GET)
                .path("/v4/oauth2/d1/clients/p1");
            then.status(404).body("not found");
        });

        let w = Wrapper::parse_from(["show", "--domain", "d1", "--provider-id", "p1"]);
        let err = w
            .inner
            .show_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("oauth2 client request failed"));
        assert!(err.to_string().contains("not found"));
    }
}
