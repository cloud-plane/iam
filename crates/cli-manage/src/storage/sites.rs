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
use color_eyre::{Report, eyre::eyre};
use rustls::pki_types::{SubjectPublicKeyInfoDer, pem::PemObject};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::config::SiteSpec;
use openstack_keystone_distributed_storage::protobuf as pb;

use super::call_leader;
use crate::PerformAction;

/// List or change the sites the DEK is wrapped for (`per_site` KEK provider).
///
/// Without options the command lists the sites. `--add` registers a site (or
/// replaces the public key of one with the same name) and `--remove` drops
/// one; the new complete list is proposed on the Raft leader. Every node then
/// re-wraps the DEK envelopes it stores, so register a site *before* starting
/// and joining its node. The site of the node answering cannot be removed.
///
/// Adding a site or replacing a site's key needs dual control: the command
/// stages the change and prints a `change_id`. A *different*
/// `storage-operator` must run `confirm-sites` within 5 minutes. Removals
/// apply at once but need `--allow-removal`.
///
/// After removing a site that must lose access, rotate the DEK with
/// `rotate-dek`: the removed site still holds copies of older envelopes.
#[derive(Parser)]
pub(super) struct SitesCommand {
    /// Site to add or update, as `<name>=<public_key_pem_file>[@<version>]`
    /// (SubjectPublicKeyInfo PEM, RSA of at least 2048 bits). Repeatable.
    #[arg(long = "add")]
    pub add: Vec<String>,

    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    pub cluster_addr: Option<Uri>,

    /// Confirm that the new list may drop registered sites. Required with
    /// `--remove`.
    #[arg(long)]
    pub allow_removal: bool,

    /// Site to remove, by name. Repeatable.
    #[arg(long = "remove")]
    pub remove: Vec<String>,
}

/// Applies `add` and `remove` to `current`, keeping the order of existing
/// sites and appending new ones.
fn apply_changes(
    mut current: Vec<pb::raft::Site>,
    add: Vec<pb::raft::Site>,
    remove: &[String],
) -> Result<Vec<pb::raft::Site>, Report> {
    for name in remove {
        let before = current.len();
        current.retain(|s| &s.name != name);
        if current.len() == before {
            return Err(eyre!("site '{name}' is not registered"));
        }
    }
    for site in add {
        match current.iter_mut().find(|s| s.name == site.name) {
            Some(existing) => *existing = site,
            None => current.push(site),
        }
    }
    Ok(current)
}

fn read_site(spec: &str) -> Result<pb::raft::Site, Report> {
    let parsed = SiteSpec::parse(spec)?;
    let pem = std::fs::read(parsed.file).map_err(|e| eyre!("reading {}: {e}", parsed.file))?;
    let der = SubjectPublicKeyInfoDer::from_pem_slice(&pem)
        .map_err(|e| eyre!("{} is not a PEM public key: {e}", parsed.file))?;
    Ok(pb::raft::Site {
        name: parsed.name.to_owned(),
        public_key_der: der.as_ref().to_vec(),
        key_version: parsed.key_version,
    })
}

#[async_trait]
impl PerformAction for SitesCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let cluster_addr = self.cluster_addr.clone();
        let current = call_leader(
            config,
            self.cluster_addr.clone(),
            false,
            |mut client| async move { client.list_sites(()).await.map(|r| r.into_inner().sites) },
        )
        .await?;

        if self.add.is_empty() && self.remove.is_empty() {
            for s in &current {
                println!("{}\tkey_version={}", s.name, s.key_version);
            }
            return Ok(());
        }

        if !self.remove.is_empty() && !self.allow_removal {
            return Err(eyre!("--remove needs --allow-removal"));
        }

        let add = self
            .add
            .iter()
            .map(|s| read_site(s))
            .collect::<Result<Vec<_>, _>>()?;
        let sites = apply_changes(current, add, &self.remove)?;
        let names: Vec<_> = sites.iter().map(|s| s.name.clone()).collect();
        let allow_site_removal = self.allow_removal;
        let resp = call_leader(config, self.cluster_addr.clone(), false, |mut client| {
            let request = pb::raft::SetSitesRequest {
                sites: sites.clone(),
                allow_site_removal,
            };
            async move {
                client
                    .set_sites(request)
                    .await
                    .map(tonic::Response::into_inner)
            }
        })
        .await?;
        if resp.pending_site_change_id.is_empty() {
            println!("Sites are now: {}", names.join(", "));
        } else {
            let pending = call_leader(config, cluster_addr, false, |mut client| async move {
                client
                    .get_pending_site_change(())
                    .await
                    .map(tonic::Response::into_inner)
            })
            .await?;
            println!(
                "Site change staged for: {}\nchange_id={}\ndigest={}",
                names.join(", "),
                resp.pending_site_change_id,
                resp.pending_site_change_digest,
            );
            for s in &pending.sites {
                println!(
                    "  {}\tkey_version={}\tsha256={}",
                    s.name, s.key_version, s.fingerprint
                );
            }
            println!(
                "\nGive the change_id and the digest to a second storage-operator over a \
                 separate channel. They must confirm within 5 minutes:\n\
                 \n  keystone-manage storage confirm-sites \\\n\
                   \t--change-id {} --expect-digest {}",
                resp.pending_site_change_id, resp.pending_site_change_digest,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(name: &str, v: u32) -> pb::raft::Site {
        pb::raft::Site {
            name: name.into(),
            public_key_der: vec![v as u8],
            key_version: v,
        }
    }

    #[test]
    fn test_apply_changes() {
        let out = apply_changes(
            vec![site("a", 1), site("b", 1)],
            vec![site("b", 2), site("c", 1)],
            &["a".to_string()],
        )
        .unwrap();
        let got: Vec<_> = out
            .iter()
            .map(|s| (s.name.as_str(), s.key_version))
            .collect();
        assert_eq!(got, vec![("b", 2), ("c", 1)]);
    }

    #[test]
    fn test_remove_unknown_site_fails() {
        assert!(apply_changes(vec![site("a", 1)], vec![], &["x".to_string()]).is_err());
    }

    #[test]
    fn test_read_site_rejects_bad_input() {
        assert!(read_site("a").is_err());
        assert!(read_site("a=/nonexistent.pem").is_err());
    }
}
