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

//! Revocation feed consumers of the other authorities (ADR 0045 section 9).
//!
//! One consumer per `[revoke.peer_authorities]` entry subscribes to the
//! priority stream of that authority and applies its revocation events to the
//! local mirror, which marks the stream as heard from. Without a consumer a
//! token of that authority is stale and the sensitive actions deny it.

use std::sync::Arc;

use color_eyre::eyre::{Report, Result, eyre};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::Startup;
use openstack_keystone_distributed_storage::StorageApi;
use openstack_keystone_revoke_driver_raft::{RevocationFeedSink, feed_consumer_config};

/// Start a feed consumer for every configured peer authority.
pub fn start(startup: &Startup, handles: &mut JoinSet<()>) -> Result<(), Report> {
    let peers = &startup.cfg.revoke.peer_authorities;
    if peers.is_empty() {
        return Ok(());
    }
    if startup.cfg.revoke.driver != "raft" {
        warn!(
            "[revoke.peer_authorities] is set but [revoke] driver is not raft: \
             no revocation feed is consumed"
        );
        return Ok(());
    }
    let storage = startup.concrete_storage.as_ref().ok_or_else(|| {
        eyre!("[revoke.peer_authorities] needs [distributed_storage] to be configured")
    })?;
    for (authority, addr) in peers {
        if authority.is_empty() || addr.is_empty() {
            return Err(eyre!(
                "[revoke.peer_authorities]: the authority and its address must not be empty"
            ));
        }
        let sink = Arc::new(RevocationFeedSink::new(
            authority.clone(),
            storage.clone() as Arc<dyn StorageApi>,
        ));
        let consumer = storage.feed_consumer(feed_consumer_config(authority, addr), sink);
        let stop = startup.token.clone().cancelled_owned();
        let name = authority.clone();
        debug!(authority = %name, "starting the revocation feed consumer");
        handles.spawn(async move {
            consumer.run(stop).await;
            debug!(authority = %name, "revocation feed consumer stopped");
        });
    }
    info!(
        authorities = peers.len(),
        "Revocation feed consumers started"
    );
    Ok(())
}
