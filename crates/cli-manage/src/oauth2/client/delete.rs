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

use openstack_keystone_config::LoadedConfig;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, OutputFormat, build_admin_client, print_json};
use crate::oauth2::client::{Common, call};

/// Delete a client.
#[derive(Parser)]
pub(crate) struct DeleteCommand {
    #[command(flatten)]
    common: Common,
    /// Registration identifier.
    #[arg(long)]
    provider_id: String,
}

impl DeleteCommand {
    /// Delete the client through a pre-built admin client.
    pub(crate) async fn delete_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<Value, Report> {
        call(
            client,
            base_url,
            Method::DELETE,
            &self.common.domain,
            &[&self.provider_id],
            &[],
            None::<&()>,
        )
        .await
    }
}

#[async_trait]
impl PerformAction for DeleteCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        // The API answers with an empty body, so there is nothing to print
        // from the response itself.
        self.delete_with_client(&client, ADMIN_BASE_URL).await?;
        match self.common.format {
            OutputFormat::Json => print_json(&serde_json::json!({"deleted": self.provider_id})),
            OutputFormat::Text => {
                println!("deleted client {}", self.provider_id);
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
        inner: DeleteCommand,
    }

    #[tokio::test]
    async fn test_delete_accepts_empty_body() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(MockMethod::DELETE)
                .path("/v4/oauth2/d1/clients/p1");
            then.status(204);
        });

        let w = Wrapper::parse_from(["delete", "--domain", "d1", "--provider-id", "p1"]);
        let body = w
            .inner
            .delete_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body, Value::Null);
    }
}
