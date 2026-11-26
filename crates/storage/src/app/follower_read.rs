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
//! Follower-served linearizable reads (ADR 0048).
//!
//! A follower asks the leader for the per-keyspace watermarks at a fresh
//! read index. The leader confirms its leadership with a quorum before it
//! answers, so the answer is never older than a write that was acknowledged.
//! When the follower has applied up to the watermark of every keyspace the
//! read touches, it reads its own copy; otherwise the caller takes the
//! forwarding path as before.

use std::time::Duration;

use super::admin::forwarded_status_error;
use super::*;
use crate::store::state_machine::watermark::replica_is_current;

use crate::store::state_machine::watermark::{ENGINE_KEYSPACE, record_meta_keyspace};

impl Storage {
    /// Leader id and address when another node is leader.
    fn remote_leader(&self) -> Option<(NodeId, String)> {
        let metrics = self.raft.metrics().borrow_watched().clone();
        let id = metrics.current_leader?;
        if id == self.node_id {
            return None;
        }
        let node = metrics.membership_config.membership().get_node(&id)?;
        Some((id, node.rpc_addr.clone()))
    }

    /// Asks the leader for the watermarks of `keyspaces`.
    async fn fetch_watermarks(
        &self,
        leader_id: NodeId,
        leader_addr: String,
        keyspaces: &[String],
    ) -> Result<pb::api::ReadWatermarkResponse, ApiStoreError> {
        let channel = self.get_or_create_channel(leader_id, leader_addr).await?;
        let mut client = StorageServiceClient::new(channel);
        let resp = client
            .read_watermark(pb::api::ReadWatermarkRequest {
                keyspaces: keyspaces.to_vec(),
            })
            .await
            .map_err(|status| forwarded_status_error("read watermark failed", status))?;
        Ok(resp.into_inner())
    }

    /// Serves a read from this follower's own copy when it is current for
    /// `keyspaces`.
    ///
    /// Returns `None` whenever the caller must take the forwarding path:
    /// the mode is off, this node is the leader or knows none, the leader
    /// did not answer, the copy never caught up within the retry budget, or
    /// the read raced an apply. A `None` is never an error; the forwarding
    /// path decides. `read` reads this node's state machine, any tier.
    pub(crate) async fn try_follower_read<T>(
        &self,
        keyspaces: &[&str],
        read: impl Fn() -> Result<Option<T>, ApiStoreError>,
    ) -> Option<T> {
        if !self.follower_linearizable_reads {
            return None;
        }
        let (leader_id, leader_addr) = self.remote_leader()?;
        let mut names: Vec<String> = keyspaces.iter().map(|k| (*k).to_string()).collect();
        // A read also depends on the per-record metadata of each keyspace and
        // on engine state (DEKs, quarantine), both kept in `meta`.
        for ks in keyspaces {
            let meta = record_meta_keyspace(ks);
            if !names.contains(&meta) {
                names.push(meta);
            }
        }
        if !names.iter().any(|n| n == ENGINE_KEYSPACE) {
            names.push(ENGINE_KEYSPACE.to_string());
        }
        let metrics = self.state_machine_store.raft_prometheus_metrics();
        let served = self.try_follower_read_inner(leader_id, leader_addr, &names, &read);
        match served.await {
            Some(v) => {
                metrics.follower_reads_served_total.inc();
                Some(v)
            }
            None => {
                metrics.follower_reads_fallback_total.inc();
                None
            }
        }
    }

    async fn try_follower_read_inner<T>(
        &self,
        leader_id: NodeId,
        leader_addr: String,
        names: &[String],
        read: &impl Fn() -> Result<Option<T>, ApiStoreError>,
    ) -> Option<T> {
        let resp = match self.fetch_watermarks(leader_id, leader_addr, names).await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("follower read: watermark request failed ({e}); forwarding");
                return None;
            }
        };
        let rows: Vec<(String, u64)> = resp
            .watermarks
            .into_iter()
            .map(|w| (w.keyspace, w.index))
            .collect();
        let applied = self.state_machine_store.applied_watermarks();
        let attempts = self.ensure_linearizable_retries.max(1);
        for attempt in 0..attempts {
            if replica_is_current(applied, &rows, resp.default_watermark, names) {
                // `A[S]` must not move while the read runs, or `meta` and the
                // data may come from different entries.
                let before: Vec<u64> = names.iter().map(|k| applied.get(k)).collect();
                let res = read();
                let after: Vec<u64> = names.iter().map(|k| applied.get(k)).collect();
                if before == after {
                    // A miss or a read error is for the forwarding path.
                    return match res {
                        Ok(Some(v)) => Some(v),
                        _ => None,
                    };
                }
                // An apply raced the read: try again.
            } else {
                debug!(
                    attempt = attempt + 1,
                    read_index = resp.read_index,
                    "follower read: replica not caught up yet"
                );
            }
            if attempt + 1 < attempts {
                TypeConfig::sleep(Duration::from_millis(
                    self.ensure_linearizable_retry_delay_ms,
                ))
                .await;
            }
        }
        None
    }
}
