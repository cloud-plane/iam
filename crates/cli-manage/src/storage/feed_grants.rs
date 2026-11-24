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
//! Change-feed grants of the `storage` subcommand.

use async_trait::async_trait;
use clap::{Args, Parser, Subcommand};
use color_eyre::{Report, eyre::eyre};
use tonic::transport::Uri;

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::{config::FEED_GRANT_MAX_FIELD, protobuf as pb};

use super::call_leader;
use crate::PerformAction;

mod list;
mod revoke;
mod set;

use list::ListCommand;
use revoke::RevokeCommand;
use set::SetCommand;

/// Manage the change-feed events a subscriber may receive.
///
/// A grant is replicated through Raft and takes effect on open streams within
/// one poll. The subscriber also needs the `feed-consumer` role (a `peers`
/// entry).
#[derive(Parser)]
pub(super) struct FeedGrantsCommand {
    #[command(subcommand)]
    command: FeedGrantsCommands,
}

#[derive(Subcommand)]
enum FeedGrantsCommands {
    /// List the grants of one subscriber, or of every subscriber.
    List(ListCommand),
    /// Revoke exactly one grant.
    Revoke(RevokeCommand),
    /// Grant the events of a kind for one domain or for every domain.
    Set(SetCommand),
}

#[async_trait]
impl PerformAction for FeedGrantsCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        match self.command {
            FeedGrantsCommands::List(e) => e.take_action(config).await,
            FeedGrantsCommands::Revoke(e) => e.take_action(config).await,
            FeedGrantsCommands::Set(e) => e.take_action(config).await,
        }
    }
}

/// A value the server accepts as an SVID, kind or domain id: 1 to
/// `FEED_GRANT_MAX_FIELD` bytes, without NUL.
fn field(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > FEED_GRANT_MAX_FIELD || value.contains('\0') {
        Err(format!(
            "must be 1 to {FEED_GRANT_MAX_FIELD} bytes with no NUL"
        ))
    } else {
        Ok(value.to_owned())
    }
}

/// A full SPIFFE ID.
fn spiffe_id(value: &str) -> Result<String, String> {
    if value.starts_with("spiffe://") && value.len() > "spiffe://".len() {
        field(value)
    } else {
        Err("must be a full SPIFFE ID (spiffe://...)".to_owned())
    }
}

/// The domain a grant covers.
#[derive(Args)]
#[group(required = true, multiple = false)]
struct DomainScope {
    /// Grant every domain of the kind.
    #[arg(long)]
    all_domains: bool,

    /// Domain id the grant is limited to.
    #[arg(long, value_parser = field)]
    domain: Option<String>,
}

/// What identifies one grant.
#[derive(Args)]
struct GrantArgs {
    /// Cluster member to contact first (e.g. `https://127.0.0.1:50051`).
    /// Defaults to this host's `node_cluster_addr`.
    #[arg(long)]
    cluster_addr: Option<Uri>,

    /// Feed kind (one of `feed_kinds`).
    #[arg(long, value_parser = field)]
    kind: String,

    #[command(flatten)]
    scope: DomainScope,

    /// Full SPIFFE ID of the subscriber.
    #[arg(long, value_parser = spiffe_id)]
    svid: String,
}

impl GrantArgs {
    fn grant(&self) -> pb::raft::FeedGrant {
        pb::raft::FeedGrant {
            svid: self.svid.clone(),
            kind: self.kind.clone(),
            has_domain: self.scope.domain.is_some(),
            domain_id: self.scope.domain.clone().unwrap_or_default(),
        }
    }

    /// Grants it, returning the grant.
    async fn set(&self, config: &LoadedConfig) -> Result<pb::raft::FeedGrant, Report> {
        let grant = self.grant();
        self.write(config, &grant, false).await?;
        Ok(grant)
    }

    /// Revokes it, returning the grant.
    ///
    /// The server treats a revoke of a missing grant as a no-op, so this
    /// first checks that the exact grant exists: a mistyped kind or domain
    /// must not look like a success while the real grant stays in force.
    async fn revoke(&self, config: &LoadedConfig) -> Result<pb::raft::FeedGrant, Report> {
        let grant = self.grant();
        let existing = list_grants(config, self.cluster_addr.clone(), &grant.svid).await?;
        if !existing.contains(&grant) {
            return Err(eyre!(
                "no such grant (svid {}, kind {}, domain {}); \
                 `feed-grants list --svid {}` shows the existing ones",
                grant.svid,
                grant.kind,
                domain_label(&grant),
                grant.svid
            ));
        }
        self.write(config, &grant, true).await?;
        Ok(grant)
    }

    async fn write(
        &self,
        config: &LoadedConfig,
        grant: &pb::raft::FeedGrant,
        revoke: bool,
    ) -> Result<(), Report> {
        call_leader(config, self.cluster_addr.clone(), false, |mut client| {
            let request = pb::raft::FeedGrantRequest {
                grant: Some(grant.clone()),
            };
            async move {
                if revoke {
                    client.revoke_feed_grant(request).await
                } else {
                    client.set_feed_grant(request).await
                }
                .map(tonic::Response::into_inner)
            }
        })
        .await?;
        Ok(())
    }
}

/// The grants of `svid`, or of every subscriber when it is empty.
async fn list_grants(
    config: &LoadedConfig,
    addr: Option<Uri>,
    svid: &str,
) -> Result<Vec<pb::raft::FeedGrant>, Report> {
    call_leader(config, addr, false, |mut client| {
        let request = pb::raft::ListFeedGrantsRequest {
            svid: svid.to_owned(),
        };
        async move {
            client
                .list_feed_grants(request)
                .await
                .map(|r| r.into_inner().grants)
        }
    })
    .await
}

/// The domain of a grant, `<all domains>` for every domain.
fn domain_label(g: &pb::raft::FeedGrant) -> String {
    if g.has_domain {
        g.domain_id.clone()
    } else {
        "<all domains>".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVID: &str = "spiffe://example.org/ns/a";

    fn parse(args: &[&str]) -> Result<FeedGrantsCommand, clap::Error> {
        FeedGrantsCommand::try_parse_from(
            std::iter::once("feed-grants").chain(args.iter().copied()),
        )
    }

    #[test]
    fn test_domain_and_all_domains() {
        for sub in ["set", "revoke"] {
            let cmd = parse(&[sub, "--svid", SVID, "--kind", "k", "--domain", "d1"]).unwrap();
            let (FeedGrantsCommands::Set(SetCommand { args })
            | FeedGrantsCommands::Revoke(RevokeCommand { args })) = cmd.command
            else {
                panic!("not a grant command");
            };
            let g = args.grant();
            assert!(g.has_domain);
            assert_eq!("d1", g.domain_id);

            let cmd = parse(&[sub, "--svid", SVID, "--kind", "k", "--all-domains"]).unwrap();
            let (FeedGrantsCommands::Set(SetCommand { args })
            | FeedGrantsCommands::Revoke(RevokeCommand { args })) = cmd.command
            else {
                panic!("not a grant command");
            };
            assert!(!args.grant().has_domain);
        }
    }

    #[test]
    fn test_invalid_requests_fail() {
        for args in [
            // no scope, both scopes
            vec!["set", "--svid", SVID, "--kind", "k"],
            vec![
                "set",
                "--svid",
                SVID,
                "--kind",
                "k",
                "--all-domains",
                "--domain",
                "d",
            ],
            // missing svid or kind
            vec!["set", "--kind", "k", "--all-domains"],
            vec!["revoke", "--svid", SVID, "--all-domains"],
            // empty or malformed values
            vec!["set", "--svid", "foo", "--kind", "k", "--all-domains"],
            vec!["set", "--svid", SVID, "--kind", "", "--all-domains"],
            vec!["revoke", "--svid", SVID, "--kind", "k", "--domain", ""],
            // longer than the server accepts, or with a NUL
            vec![
                "set",
                "--svid",
                SVID,
                "--kind",
                &"k".repeat(FEED_GRANT_MAX_FIELD + 1),
                "--all-domains",
            ],
            vec!["set", "--svid", SVID, "--kind", "k\0", "--all-domains"],
            // grant flags do not apply to list
            vec!["list", "--kind", "k"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }
}
