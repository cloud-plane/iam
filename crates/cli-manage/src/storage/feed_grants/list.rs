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
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;

use super::{domain_label, list_grants, spiffe_id};
use crate::PerformAction;
use crate::common::print_list_table;

/// List the grants of one subscriber, or of every subscriber.
#[derive(Parser)]
pub(super) struct ListCommand {
    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    cluster_addr: Option<Uri>,

    /// Full SPIFFE ID of the subscriber; omit to list every subscriber.
    #[arg(long, value_parser = spiffe_id)]
    svid: Option<String>,
}

#[async_trait]
impl PerformAction for ListCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let grants = list_grants(config, self.cluster_addr, &self.svid.unwrap_or_default()).await?;
        print_list_table(
            vec!["SVID", "Kind", "Domain"],
            grants
                .into_iter()
                .map(|g| {
                    let domain = domain_label(&g);
                    vec![g.svid, g.kind, domain]
                })
                .collect(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_svid_is_validated() {
        assert!(ListCommand::try_parse_from(["list"]).is_ok());
        assert!(ListCommand::try_parse_from(["list", "--svid", "spiffe://x/y"]).is_ok());
        assert!(ListCommand::try_parse_from(["list", "--svid", ""]).is_err());
        assert!(ListCommand::try_parse_from(["list", "--svid", "foo"]).is_err());
    }
}
