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

use openstack_keystone_api_types::v4::oauth2_key::ListLocalEmergencyCandidatesResponse;
use openstack_keystone_config::LoadedConfig;

use super::{domain_url, ensure_success};
use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_list_table};

/// List node-local, quorum-bypass emergency signing-key rotation candidates
/// on the responding node (ADR 0028 §6).
///
/// Run this against every node that may have been reachable during the
/// outage before choosing a `rotation_id` to pass to
/// `reconcile-local-emergency-key` -- a `conflicted: true` entry means
/// gossip observed a different active candidate for this domain elsewhere,
/// and the operator must make an explicit choice.
#[derive(Parser)]
pub(super) struct ListLocalEmergencyCandidatesCommand {
    /// Domain to list local emergency candidates for.
    #[arg(long)]
    pub domain: String,
}

impl ListLocalEmergencyCandidatesCommand {
    /// Fetch the candidates through a pre-built admin client.
    pub(super) async fn list_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<ListLocalEmergencyCandidatesResponse, Report> {
        let res = client
            .get(domain_url(
                base_url,
                &self.domain,
                &["local-emergency-candidates"],
            ))
            .send()
            .await
            .wrap_err("list-local-emergency-candidates request failed")?;
        let res = ensure_success(res, "list-local-emergency-candidates").await?;
        Ok(res.json().await?)
    }
}

#[async_trait]
impl PerformAction for ListLocalEmergencyCandidatesCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.list_with_client(&client, ADMIN_BASE_URL).await?;
        if body.candidates.is_empty() {
            println!(
                "No local emergency candidates on this node for domain {}.",
                self.domain
            );
            return Ok(());
        }

        let rows = body
            .candidates
            .into_iter()
            .map(|c| {
                vec![
                    c.rotation_id,
                    c.initiator,
                    c.justification,
                    c.created_at_unix.to_string(),
                    c.origin_node_id
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "local".to_string()),
                    c.conflicted.to_string(),
                    c.revoked.to_string(),
                ]
            })
            .collect();
        print_list_table(
            vec![
                "Rotation ID",
                "Initiator",
                "Justification",
                "Created At (unix)",
                "Origin Node",
                "Conflicted",
                "Revoked",
            ],
            rows,
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
        inner: ListLocalEmergencyCandidatesCommand,
    }

    #[test]
    fn test_parses_domain() {
        let wrapper = Wrapper::parse_from(["oauth2", "--domain", "domain-1"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
    }

    #[tokio::test]
    async fn test_list_returns_candidates() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v4/oauth2/domain-1/local-emergency-candidates");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "candidates": [{
                        "rotation_id": "rot-1",
                        "initiator": "ops",
                        "justification": "outage",
                        "created_at_unix": 1700000000,
                        "origin_node_id": null,
                        "conflicted": true,
                        "revoked": false
                    }]
                }));
        });

        let cmd = ListLocalEmergencyCandidatesCommand {
            domain: "domain-1".to_string(),
        };
        let body = cmd
            .list_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body.candidates.len(), 1);
        assert_eq!(body.candidates[0].rotation_id, "rot-1");
        assert!(body.candidates[0].conflicted);
    }

    #[tokio::test]
    async fn test_list_reports_server_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v4/oauth2/domain-1/local-emergency-candidates");
            then.status(403).body("forbidden");
        });

        let cmd = ListLocalEmergencyCandidatesCommand {
            domain: "domain-1".to_string(),
        };
        let err = cmd
            .list_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("list-local-emergency-candidates failed")
        );
    }
}
