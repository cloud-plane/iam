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

//! Feed outbox retention (ADR 0045 section 3).
//!
//! The leader proposes a `PruneOutbox` for the events older than
//! `feed_retention_days` or beyond `feed_max_events`, so every voter deletes
//! the same events.

use super::*;
use crate::store::state_machine::OutboxClass;

/// Interval between two retention checks.
const FEED_RETENTION_CHECK_INTERVAL: Duration = Duration::from_secs(600);

impl Storage {
    /// Propose a prune if retention asks for one. Returns the index pruned up
    /// to; `None` if this node is not the leader or nothing is due.
    pub async fn prune_feed_outbox(&self) -> Result<Option<u64>, StoreError> {
        self.prune_outbox(OutboxClass::Normal).await
    }

    /// [`Self::prune_feed_outbox`] for the priority outbox.
    pub async fn prune_priority_outbox(&self) -> Result<Option<u64>, StoreError> {
        self.prune_outbox(OutboxClass::Priority).await
    }

    async fn prune_outbox(&self, class: OutboxClass) -> Result<Option<u64>, StoreError> {
        if self.current_leader() != Some(self.node_id) {
            return Ok(None);
        }
        // A scan over the whole outbox is a blocking disk read.
        let sm = self.state_machine_store.clone();
        let retention_secs = u64::from(self.feed_retention_days) * 24 * 60 * 60;
        let max_events = self.feed_max_events;
        let point = tokio::task::spawn_blocking(move || {
            sm.outbox_prune_point_in(
                class,
                crate::store::state_machine::unix_now(),
                retention_secs,
                max_events,
            )
        })
        .await
        .map_err(|e| StoreError::Other(eyre!(e)))??;
        let Some(upto_index) = point else {
            return Ok(None);
        };
        let cmd = StoreCommand::Transaction(vec![MutationInner::PruneOutbox {
            upto_index,
            priority: class == OutboxClass::Priority,
        }]);
        let payload = crate::pb::api::CommandRequest::try_from(cmd)
            .map_err(|e| StoreError::Other(eyre!(e)))?;
        match self.raft.client_write(payload).await {
            Ok(_) => Ok(Some(upto_index)),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_))) => Ok(None),
            Err(other) => Err(other)?,
        }
    }
}

/// Spawn the retention task; it holds a weak reference so it never keeps
/// `Storage` alive.
pub(super) fn spawn_feed_retention_task(storage: &Arc<Storage>) {
    let storage_weak = Arc::downgrade(storage);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(FEED_RETENTION_CHECK_INTERVAL);
        loop {
            interval.tick().await;
            let Some(storage) = storage_weak.upgrade() else {
                break;
            };
            if let Err(e) = storage.prune_feed_outbox().await {
                tracing::warn!(error = %e, "feed outbox pruning failed; retrying on the next check");
            }
            if let Err(e) = storage.prune_priority_outbox().await {
                tracing::warn!(
                    error = %e,
                    "priority outbox pruning failed; retrying on the next check"
                );
            }
        }
    });
}
