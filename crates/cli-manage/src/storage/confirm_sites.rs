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

use std::io::{IsTerminal, Write};

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::call_leader;
use crate::PerformAction;

/// Confirm a staged site-registry change (dual-control second factor).
///
/// Must be invoked by a *different* `storage-operator` than the one who ran
/// `sites --add`, within 5 minutes of that command. Both identities are
/// recorded in the audit log. The change is held in the leader's memory, so
/// it is lost on a leader change; stage it again then.
///
/// The command fetches the staged list from the leader and prints every
/// site with the SHA-256 fingerprint of its key. Pass the digest the
/// initiator gave you over a separate channel as `--expect-digest`; without
/// it the command asks you to type `yes` after you compared the fingerprints
/// with the ones the initiator holds. The leader applies the list only if
/// its digest matches.
#[derive(Parser)]
pub(super) struct ConfirmSitesCommand {
    /// The change_id printed by `sites --add`.
    #[arg(long)]
    pub change_id: String,

    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Digest of the staged list, received from the initiator out-of-band.
    /// Skips the interactive question.
    #[arg(long)]
    pub expect_digest: Option<String>,
}

/// Checks the pending change against what the operator expects.
fn check_pending(
    pending: &pb::raft::PendingSiteChange,
    change_id: &str,
    expect_digest: Option<&str>,
) -> Result<(), Report> {
    if pending.change_id != change_id {
        return Err(eyre!(
            "the pending change is {}, not {change_id}",
            pending.change_id
        ));
    }
    match expect_digest {
        Some(d) if d != pending.digest => Err(eyre!(
            "digest mismatch: expected {d}, the leader holds {}",
            pending.digest
        )),
        _ => Ok(()),
    }
}

fn print_pending(p: &pb::raft::PendingSiteChange) {
    println!("Staged by {}, change_id={}", p.initiator, p.change_id);
    for s in &p.sites {
        let mark = if p.changed.contains(&s.name) {
            "ADD/REPLACE"
        } else {
            "unchanged"
        };
        println!(
            "  {:<11} {}\tkey_version={}\tsha256={}",
            mark, s.name, s.key_version, s.fingerprint
        );
    }
    for name in &p.removed {
        println!("  REMOVE      {name}");
    }
    println!("digest={}", p.digest);
}

#[async_trait]
impl PerformAction for ConfirmSitesCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let pending = call_leader(
            config,
            self.cluster_addr.clone(),
            false,
            |mut client| async move {
                client
                    .get_pending_site_change(())
                    .await
                    .map(tonic::Response::into_inner)
            },
        )
        .await?;
        print_pending(&pending);
        check_pending(&pending, &self.change_id, self.expect_digest.as_deref())?;

        if self.expect_digest.is_none() {
            if !std::io::stdin().is_terminal() {
                return Err(eyre!(
                    "no terminal to ask on; pass --expect-digest with the digest the initiator gave you"
                ));
            }
            print!("Fingerprints checked against the initiator's? Type 'yes' to confirm: ");
            std::io::stdout().flush()?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if answer.trim() != "yes" {
                return Err(eyre!("not confirmed"));
            }
        }

        let digest = pending.digest;
        call_leader(config, self.cluster_addr, false, |mut client| {
            let request = pb::raft::ConfirmSetSitesRequest {
                change_id: self.change_id.clone(),
                digest: digest.clone(),
            };
            async move { client.confirm_set_sites(request).await }
        })
        .await?;
        println!("Site change {} confirmed and applied.", self.change_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending() -> pb::raft::PendingSiteChange {
        pb::raft::PendingSiteChange {
            change_id: "c1".into(),
            digest: "abc".into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_check_pending() {
        assert!(check_pending(&pending(), "c1", None).is_ok());
        assert!(check_pending(&pending(), "c1", Some("abc")).is_ok());
        assert!(check_pending(&pending(), "c1", Some("xyz")).is_err());
        assert!(check_pending(&pending(), "c2", Some("abc")).is_err());
    }
}
