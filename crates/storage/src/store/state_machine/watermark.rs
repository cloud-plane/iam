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
//! Applied keyspace watermarks `A[K]` (ADR 0048).
//!
//! `A[K]` is the log index of the last applied entry that touched keyspace
//! `K`. It is derived from the log, so every node that applied the same index
//! holds the same table. It is persisted in the `meta` keyspace under
//! [`WATERMARK_PREFIX`] and written in the same batch as the entry's data, so
//! it can never be ahead of the data after a crash.
//!
//! The table only records progress; nothing reads it for a decision yet.

use dashmap::DashMap;
use fjall::{Keyspace, UserKey};

use crate::store_command::{MutationInner, StoreCommand};

/// Key prefix in `meta` for one watermark row: `_wm:<keyspace>`.
///
/// It has no NUL byte, so it can never collide with a record's
/// `<keyspace>\0<key>` metadata key (see `meta_key`).
pub(super) const WATERMARK_PREFIX: &str = "_wm:";

/// Pseudo keyspaces for state that is not named by a user keyspace.
const KS_META: &str = "meta";
const KS_INDEX: &str = "index";

/// Builds the `meta` key of the watermark row of `keyspace`.
pub(super) fn watermark_key(keyspace: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(WATERMARK_PREFIX.len() + keyspace.len());
    out.extend_from_slice(WATERMARK_PREFIX.as_bytes());
    out.extend_from_slice(keyspace.as_bytes());
    out
}

/// The applied watermarks of one node.
#[derive(Debug, Default)]
pub(super) struct AppliedWatermarks {
    /// Last applied index per keyspace.
    rows: DashMap<String, u64>,
    /// Index of the last restore or snapshot install, which replaces every
    /// keyspace. Kept in memory only: after a restart it is lost, which makes
    /// `get` lower, never higher, so the table stays safe.
    floor: std::sync::atomic::AtomicU64,
}

impl AppliedWatermarks {
    /// Loads the persisted rows. A missing row is `0` (rolling upgrade).
    pub(super) fn from_meta(meta: &Keyspace) -> Result<Self, fjall::Error> {
        let rows = DashMap::new();
        for item in meta.prefix(WATERMARK_PREFIX.as_bytes()) {
            let (key, value) = item.into_inner()?;
            let Some(name) = key
                .strip_prefix(WATERMARK_PREFIX.as_bytes())
                .and_then(|n| std::str::from_utf8(n).ok())
            else {
                continue;
            };
            if let Some(index) = decode(&value) {
                rows.insert(name.to_string(), index);
            }
        }
        Ok(Self {
            rows,
            floor: std::sync::atomic::AtomicU64::new(0),
        })
    }

    // Read by the local linearizable read path (ADR 0048), not added yet.
    #[allow(dead_code)]
    /// `A[keyspace]`, `0` when the keyspace was never touched.
    pub(super) fn get(&self, keyspace: &str) -> u64 {
        let row = self.rows.get(keyspace).map_or(0, |v| *v);
        row.max(self.floor.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Every keyspace was replaced at `index` (restore, snapshot install).
    pub(super) fn raise_floor(&self, index: u64) {
        self.floor
            .fetch_max(index, std::sync::atomic::Ordering::AcqRel);
    }

    /// Records that entry `index` touched `keyspaces`. Call after the batch
    /// that holds the matching rows committed.
    pub(super) fn record(&self, keyspaces: &[String], index: u64) {
        for ks in keyspaces {
            self.rows
                .entry(ks.clone())
                .and_modify(|v| *v = (*v).max(index))
                .or_insert(index);
        }
    }
}

fn decode(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

/// Encodes a watermark value.
pub(super) fn encode(index: u64) -> UserKey {
    UserKey::from(index.to_be_bytes().as_slice())
}

/// Keyspaces an applied `command` may mutate.
///
/// The match over [`MutationInner`] is exhaustive on purpose: a new variant
/// must decide what it touches, or the build fails. A variant that is not
/// tied to a user keyspace maps to `meta` (engine state) or `index`. Missing
/// a keyspace here would let a replica serve a stale linearizable read, so
/// when unsure, add it.
pub(super) fn touched_keyspaces(command: &StoreCommand) -> Vec<String> {
    let StoreCommand::Transaction(mutations) = command else {
        // Restore chunks stage in `meta`; `RestoreApply` replaces everything
        // and is handled by the caller (every watermark is set to the index).
        return vec![KS_META.to_string()];
    };
    let mut out: Vec<String> = Vec::new();
    let mut push = |ks: &str| {
        if !out.iter().any(|k| k == ks) {
            out.push(ks.to_string());
        }
    };
    for m in mutations {
        match m {
            MutationInner::Remove { keyspace, .. }
            | MutationInner::Set { keyspace, .. }
            | MutationInner::CreateIfAbsent { keyspace, .. } => {
                // Per-record metadata lives in `meta`, so a tier lookup
                // reads both.
                push(keyspace);
                push(KS_META);
            }
            MutationInner::DropKeyspace { keyspace } => push(keyspace),
            MutationInner::RemoveIndex { .. } | MutationInner::SetIndex { .. } => push(KS_INDEX),
            MutationInner::ClearQuarantine { .. }
            | MutationInner::Quarantine { .. }
            | MutationInner::InstallDek { .. }
            | MutationInner::CreatePendingRotation { .. }
            | MutationInner::ConfirmPendingRotation { .. }
            | MutationInner::AbortPendingRotation { .. }
            | MutationInner::SetSites { .. }
            | MutationInner::PruneOutbox { .. }
            | MutationInner::SetFeedEpoch { .. }
            | MutationInner::SetFeedGrant { .. }
            | MutationInner::RevokeFeedGrant { .. }
            | MutationInner::Emit { .. } => push(KS_META),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_has_no_nul() {
        assert!(!watermark_key("data").contains(&0u8));
    }

    #[test]
    fn record_is_monotone() {
        let w = AppliedWatermarks::default();
        w.record(&["a".to_string()], 5);
        w.record(&["a".to_string()], 3);
        assert_eq!(w.get("a"), 5);
        assert_eq!(w.get("b"), 0);
    }

    #[test]
    fn floor_lifts_every_keyspace() {
        let w = AppliedWatermarks::default();
        w.record(&["a".to_string()], 5);
        w.raise_floor(9);
        assert_eq!(w.get("a"), 9);
        assert_eq!(w.get("zzz"), 9);
    }

    #[test]
    fn set_touches_keyspace_and_meta_once() {
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::Remove {
                key: vec![1],
                keyspace: "k".into(),
                expected_revision: None,
            },
            MutationInner::Remove {
                key: vec![2],
                keyspace: "k".into(),
                expected_revision: None,
            },
        ]);
        assert_eq!(touched_keyspaces(&cmd), vec!["k", "meta"]);
    }

    #[test]
    fn index_and_drop() {
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::SetIndex { key: vec![1] },
            MutationInner::DropKeyspace {
                keyspace: "x".into(),
            },
        ]);
        assert_eq!(touched_keyspaces(&cmd), vec!["index", "x"]);
    }
}
