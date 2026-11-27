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
    ReconcileLocalEmergencyKeyRequest, ReconcileLocalEmergencyKeyResponse,
};
use openstack_keystone_config::LoadedConfig;

use super::{domain_url, ensure_success};
use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client};

/// Reconcile a node-local, quorum-bypass emergency signing-key rotation
/// candidate into Raft-replicated state (ADR 0028 §6).
///
/// Must be run against the specific node that holds `rotation_id` (see
/// `list-local-emergency-candidates`) -- reconciliation does not fan out
/// across the cluster. Promotes the candidate's key to `Primary`, demoting
/// the current `Primary` to `Previous`, via the normal Raft transaction
/// path; this requires quorum to be available again. The confirming
/// operator must differ from the one who staged the candidate
/// (dual-control, same as `confirm-rotate-signing-key`). On success, the
/// candidate is cleared from this node and any other active candidate for
/// the same domain on this node is revoked.
#[derive(Parser)]
pub(super) struct ReconcileLocalEmergencyKeyCommand {
    /// Domain whose local emergency candidate is being reconciled.
    #[arg(long)]
    pub domain: String,

    /// The rotation_id to promote, from `list-local-emergency-candidates`.
    #[arg(long)]
    pub rotation_id: String,
}

impl ReconcileLocalEmergencyKeyCommand {
    /// Reconcile the candidate through a pre-built admin client.
    pub(super) async fn reconcile_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<ReconcileLocalEmergencyKeyResponse, Report> {
        let res = client
            .post(domain_url(
                base_url,
                &self.domain,
                &["reconcile-local-emergency-key"],
            ))
            .json(&ReconcileLocalEmergencyKeyRequest {
                rotation_id: self.rotation_id.clone(),
            })
            .send()
            .await
            .wrap_err("reconcile-local-emergency-key request failed")?;
        let res = ensure_success(res, "reconcile-local-emergency-key").await?;
        Ok(res.json().await?)
    }
}

#[async_trait]
impl PerformAction for ReconcileLocalEmergencyKeyCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let body = self.reconcile_with_client(&client, ADMIN_BASE_URL).await?;
        println!(
            "Local emergency rotation {} reconciled for domain {}. New kid: {}",
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
        inner: ReconcileLocalEmergencyKeyCommand,
    }

    #[test]
    fn test_parses_domain_and_rotation_id() {
        let wrapper =
            Wrapper::parse_from(["oauth2", "--domain", "domain-1", "--rotation-id", "rot-1"]);
        assert_eq!(wrapper.inner.domain, "domain-1");
        assert_eq!(wrapper.inner.rotation_id, "rot-1");
    }

    #[tokio::test]
    async fn test_reconcile_posts_rotation_id() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/reconcile-local-emergency-key")
                .json_body(serde_json::json!({"rotation_id": "rot-1"}));
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({"kid": "kid-4"}));
        });

        let cmd = ReconcileLocalEmergencyKeyCommand {
            domain: "domain-1".to_string(),
            rotation_id: "rot-1".to_string(),
        };
        let body = cmd
            .reconcile_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap();
        assert_eq!(body.kid, "kid-4");
    }

    #[tokio::test]
    async fn test_reconcile_reports_server_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/oauth2/domain-1/reconcile-local-emergency-key");
            then.status(409).body("quorum unavailable");
        });

        let cmd = ReconcileLocalEmergencyKeyCommand {
            domain: "domain-1".to_string(),
            rotation_id: "rot-1".to_string(),
        };
        let err = cmd
            .reconcile_with_client(&crate::common::test_client(), &server.base_url())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("reconcile-local-emergency-key failed")
        );
        assert!(err.to_string().contains("quorum unavailable"));
    }
}
