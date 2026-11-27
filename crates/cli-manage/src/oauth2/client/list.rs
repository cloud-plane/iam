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

use openstack_keystone_api_types::v4::oauth2_client::OAuth2ClientList;
use openstack_keystone_config::LoadedConfig;

use crate::PerformAction;
use crate::common::{
    ADMIN_BASE_URL, OutputFormat, build_admin_client, print_json, print_list_table,
};
use crate::oauth2::client::{Common, call};

/// List the clients of a domain.
#[derive(Parser)]
pub(crate) struct ListCommand {
    #[command(flatten)]
    common: Common,
    /// Only enabled (`true`) or disabled (`false`) clients.
    #[arg(long)]
    enabled: Option<bool>,
    /// Only clients whose name contains this text.
    #[arg(long)]
    name: Option<String>,
}

impl ListCommand {
    fn query(&self) -> Vec<(&'static str, String)> {
        let mut query = Vec::new();
        if let Some(enabled) = self.enabled {
            query.push(("enabled", enabled.to_string()));
        }
        if let Some(name) = &self.name {
            query.push(("name", name.clone()));
        }
        query
    }

    /// List the clients through a pre-built admin client. Returns the raw
    /// response body.
    pub(crate) async fn list_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<Value, Report> {
        call(
            client,
            base_url,
            Method::GET,
            &self.common.domain,
            &[],
            &self.query(),
            None::<&()>,
        )
        .await
    }
}

#[async_trait]
impl PerformAction for ListCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.list_with_client(&client, ADMIN_BASE_URL).await?;
        match self.common.format {
            OutputFormat::Json => print_json(&body),
            OutputFormat::Text => {
                let list: OAuth2ClientList = serde_json::from_value(body)?;
                let rows = list
                    .oauth2_clients
                    .into_iter()
                    .map(|c| vec![c.provider_id, c.client_id, c.name, c.enabled.to_string()])
                    .collect();
                print_list_table(vec!["Provider ID", "Client ID", "Name", "Enabled"], rows);
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
        inner: ListCommand,
    }

    #[tokio::test]
    async fn test_list_sends_filters() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(MockMethod::GET)
                .path("/v4/oauth2/d1/clients")
                .query_param("enabled", "true")
                .query_param("name", "graf");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({"oauth2_clients": []}));
        });

        let w = Wrapper::parse_from([
            "list",
            "--domain",
            "d1",
            "--enabled",
            "true",
            "--name",
            "graf",
        ]);
        let body = w
            .inner
            .list_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body["oauth2_clients"], serde_json::json!([]));
    }
}
