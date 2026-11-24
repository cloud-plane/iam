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

use openstack_keystone_config::LoadedConfig;

use super::{GrantArgs, domain_label};
use crate::PerformAction;
use crate::common::print_attribute_table;

/// Grant a subscriber the events of one kind.
///
/// Give `--domain` for one domain or `--all-domains` for every domain. An
/// event that names no domain reaches a subscriber only through a grant for
/// every domain.
#[derive(Parser)]
pub(super) struct SetCommand {
    #[command(flatten)]
    pub(super) args: GrantArgs,
}

#[async_trait]
impl PerformAction for SetCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        // `feed_kinds` is node-local, so it says nothing of another cluster.
        if self.args.cluster_addr.is_none()
            && let Some(ds) = crate::storage::ds_config(config)
            && !ds.feed_kinds.contains(&self.args.kind)
        {
            eprintln!(
                "warning: kind `{}` is not in this host's `feed_kinds` ({:?}); a \
                 mistyped kind matches no event",
                self.args.kind, ds.feed_kinds
            );
        }
        let grant = self.args.set(config).await?;
        print_attribute_table(vec![
            ("svid", grant.svid.clone()),
            ("kind", grant.kind.clone()),
            ("domain", domain_label(&grant)),
        ]);
        Ok(())
    }
}
