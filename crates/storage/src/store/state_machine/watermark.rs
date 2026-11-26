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
//! `meta` also holds a persisted floor ([`FLOOR_KEY`]): the index of the last
//! restore or snapshot install, which replaced every keyspace. Per-record
//! metadata is tracked per keyspace as `meta:<keyspace>` ([`record_meta_keyspace`]);
//! engine state (DEKs, quarantine, sites, outbox) is tracked as `meta`.

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

/// Wildcard recorded for a log entry that cannot be decoded: it may touch
/// any keyspace, so it raises the watermark of every keyspace.
pub(crate) const KS_ALL: &str = "*";

/// `meta` key of the persisted restore/install floor.
///
/// It does not start with [`WATERMARK_PREFIX`], so the row scan never sees it.
pub(super) const FLOOR_KEY: &[u8] = b"_wmfloor";

/// Name of the pseudo keyspace for the per-record metadata of `keyspace`.
///
/// Per-record metadata lives in the `meta` keyspace. Tracking it per user
/// keyspace keeps a write to one keyspace from making every other
/// keyspace's reads wait.
pub(crate) fn record_meta_keyspace(keyspace: &str) -> String {
    format!("{KS_META}:{keyspace}")
}

/// Pseudo keyspace of engine state in `meta` (DEKs, quarantine, sites, ...).
pub(crate) const ENGINE_KEYSPACE: &str = KS_META;

/// The latest log index that touches each keyspace, as seen by this node's
/// log store (`W[K]` input, ADR 0048).
///
/// Updated in `append`, so it covers entries that are not applied yet, and it
/// is rebuilt from the log tail on start. A truncated entry is never removed:
/// the value can then be too high, which only makes a reader wait longer.
#[derive(Debug, Default)]
pub struct LoggedWatermarks {
    rows: DashMap<String, u64>,
    /// Highest index of an entry that may touch any keyspace ([`KS_ALL`]).
    all: std::sync::atomic::AtomicU64,
}

impl LoggedWatermarks {
    /// Records that the entry at `index` touches `keyspaces`.
    pub fn record(&self, keyspaces: &[String], index: u64) {
        for ks in keyspaces {
            if ks == KS_ALL {
                self.all
                    .fetch_max(index, std::sync::atomic::Ordering::AcqRel);
                continue;
            }
            self.rows
                .entry(ks.clone())
                .and_modify(|v| *v = (*v).max(index))
                .or_insert(index);
        }
    }

    /// Names of the keyspaces with a row.
    pub fn keyspaces(&self) -> Vec<String> {
        self.rows.iter().map(|r| r.key().clone()).collect()
    }

    /// Latest logged index for `keyspace`, `0` if none was seen. Entries
    /// that could not be decoded count for every keyspace.
    pub fn get(&self, keyspace: &str) -> u64 {
        let row = self.rows.get(keyspace).map_or(0, |v| *v);
        row.max(self.all.load(std::sync::atomic::Ordering::Acquire))
    }
}

/// Keyspaces a log entry touches; empty for entries without a command
/// (blank and membership entries). An entry whose command cannot be decoded
/// is assumed to touch every keyspace ([`KS_ALL`]): the state machine treats
/// the same failure as fatal, so being conservative here only delays reads.
pub fn entry_keyspaces(entry: &crate::pb::raft::Entry) -> Vec<String> {
    match entry.app_data.as_deref() {
        None => Vec::new(),
        Some(raw) => match StoreCommand::unpack(raw) {
            Ok(cmd) => touched_keyspaces(&cmd),
            Err(_) => vec![KS_ALL.to_string()],
        },
    }
}

/// `W[K](R)`: how far a replica must have applied to be current for a
/// keyspace at read index `read_index`.
///
/// `applied` is the leader's own `A[K]`, which stands for every entry the
/// leader applied (including ones from before the log tail it scanned);
/// `logged` covers the entries not applied yet. The bound is capped at `R`:
/// entries past `R` do not matter to this read, and `R` is always a safe
/// answer.
pub fn committed_watermark(applied: u64, logged: u64, read_index: u64) -> u64 {
    applied.max(logged).min(read_index)
}

/// Computes the `ReadWatermark` answer at `read_index`.
///
/// Returns one `(keyspace, W)` pair per requested keyspace (every known one
/// when `keyspaces` is empty) and the watermark that holds for all others.
pub fn read_watermarks(
    applied: &AppliedWatermarks,
    logged: &LoggedWatermarks,
    read_index: u64,
    keyspaces: &[String],
) -> (Vec<(String, u64)>, u64) {
    let names: Vec<String> = if keyspaces.is_empty() {
        let mut all = applied.keyspaces();
        for ks in logged.keyspaces() {
            if !all.contains(&ks) {
                all.push(ks);
            }
        }
        all.sort();
        all
    } else {
        keyspaces.to_vec()
    };
    let rows = names
        .into_iter()
        .map(|ks| {
            let w = committed_watermark(applied.get(&ks), logged.get(&ks), read_index);
            (ks, w)
        })
        .collect();
    // A name with no row resolves to the floor alone.
    let default = committed_watermark(
        applied.get("\0unlisted"),
        logged.get("\0unlisted"),
        read_index,
    );
    (rows, default)
}

/// Whether this replica has applied everything the leader's answer says it
/// needs for `keyspaces`: for each one, `A[K] >= W[K]`.
///
/// `rows` and `default` come from the `ReadWatermark` response; a keyspace
/// the response does not list uses `default`.
pub fn replica_is_current(
    applied: &AppliedWatermarks,
    rows: &[(String, u64)],
    default: u64,
    keyspaces: &[String],
) -> bool {
    keyspaces.iter().all(|ks| {
        let need = rows
            .iter()
            .find(|(name, _)| name == ks)
            .map_or(default, |(_, w)| *w);
        applied.get(ks) >= need
    })
}

/// Builds the `meta` key of the watermark row of `keyspace`.
pub(super) fn watermark_key(keyspace: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(WATERMARK_PREFIX.len() + keyspace.len());
    out.extend_from_slice(WATERMARK_PREFIX.as_bytes());
    out.extend_from_slice(keyspace.as_bytes());
    out
}

/// The applied watermarks of one node.
#[derive(Debug, Default)]
pub struct AppliedWatermarks {
    /// Last applied index per keyspace.
    rows: DashMap<String, u64>,
    /// Index of the last restore or snapshot install, which replaces every
    /// keyspace. Persisted under [`FLOOR_KEY`]: a lower value after a
    /// restart would let the leader under-report `W[K]`.
    floor: std::sync::atomic::AtomicU64,
}

impl AppliedWatermarks {
    /// Loads the persisted rows and floor.
    ///
    /// A node with no floor row (data written before watermarks existed, or
    /// a build that kept the floor in memory only) cannot tell when its
    /// keyspaces were last replaced, so it takes `last_applied` as the floor,
    /// persisted so that it survives the first apply after the upgrade.
    pub fn from_meta(meta: &Keyspace, last_applied: u64) -> Result<Self, fjall::Error> {
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
        // No usable floor row: either data from before watermarks, or a node
        // that ran a build keeping the floor in memory only and may have lost
        // a restore. `last_applied` is true on a follower (everything up to
        // it is applied) and only raises `W[K]` on a leader, so it is safe.
        let floor = match meta.get(FLOOR_KEY)? {
            Some(raw) => decode(&raw).unwrap_or(last_applied),
            None => last_applied,
        };
        if meta.get(FLOOR_KEY)?.is_none() {
            meta.insert(FLOOR_KEY, encode(floor))?;
        }
        Ok(Self {
            rows,
            floor: std::sync::atomic::AtomicU64::new(floor),
        })
    }

    /// `A[keyspace]`, `0` when the keyspace was never touched.
    pub fn get(&self, keyspace: &str) -> u64 {
        let row = self.rows.get(keyspace).map_or(0, |v| *v);
        row.max(self.floor.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Names of the keyspaces with a row.
    pub fn keyspaces(&self) -> Vec<String> {
        self.rows.iter().map(|r| r.key().clone()).collect()
    }

    /// Every keyspace was replaced at `index` (restore, snapshot install).
    pub fn raise_floor(&self, index: u64) {
        self.floor
            .fetch_max(index, std::sync::atomic::Ordering::AcqRel);
    }

    /// Records that entry `index` touched `keyspaces`. Call after the batch
    /// that holds the matching rows committed.
    pub fn record(&self, keyspaces: &[String], index: u64) {
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
pub(crate) fn touched_keyspaces(command: &StoreCommand) -> Vec<String> {
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
                // reads both; it is tracked per keyspace.
                push(keyspace);
                push(&record_meta_keyspace(keyspace));
            }
            MutationInner::DropKeyspace { keyspace } => {
                push(keyspace);
                push(&record_meta_keyspace(keyspace));
            }
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
    fn committed_watermark_is_capped_at_the_read_index() {
        assert_eq!(committed_watermark(3, 7, 10), 7);
        assert_eq!(committed_watermark(8, 7, 10), 8);
        assert_eq!(committed_watermark(3, 20, 10), 10);
        assert_eq!(committed_watermark(0, 0, 10), 0);
    }

    #[test]
    fn read_watermarks_lists_known_keyspaces_and_caps_at_r() {
        let applied = AppliedWatermarks::default();
        let logged = LoggedWatermarks::default();
        applied.record(&["a".to_string()], 4);
        logged.record(&["a".to_string(), "b".to_string()], 12);
        applied.raise_floor(2);

        let (rows, default) = read_watermarks(&applied, &logged, 10, &[]);
        assert_eq!(rows, vec![("a".to_string(), 10), ("b".to_string(), 10)]);
        assert_eq!(default, 2);

        let (rows, _) = read_watermarks(&applied, &logged, 10, &["zzz".to_string()]);
        assert_eq!(rows, vec![("zzz".to_string(), 2)]);
    }

    #[test]
    fn replica_is_current_checks_every_keyspace() {
        let applied = AppliedWatermarks::default();
        applied.record(&["a".to_string()], 10);
        applied.record(&["b".to_string()], 1);
        let rows = vec![("a".to_string(), 8), ("b".to_string(), 8)];
        let a = ["a".to_string()];
        let ab = ["a".to_string(), "b".to_string()];
        assert!(replica_is_current(&applied, &rows, 0, &a));
        // `a` being far ahead must not hide that `b` is behind.
        assert!(!replica_is_current(&applied, &rows, 0, &ab));
        // An unlisted keyspace uses the default.
        assert!(!replica_is_current(&applied, &rows, 5, &["c".to_string()]));
        assert!(replica_is_current(&applied, &rows, 0, &["c".to_string()]));
    }

    #[test]
    fn logged_is_monotone() {
        let w = LoggedWatermarks::default();
        w.record(&["a".to_string()], 9);
        w.record(&["a".to_string()], 4);
        assert_eq!(w.get("a"), 9);
        assert_eq!(w.get("b"), 0);
    }

    #[test]
    fn undecodable_entry_raises_every_keyspace() {
        let entry = crate::pb::raft::Entry {
            term: 1,
            index: 9,
            membership: None,
            app_data: Some(vec![0xff, 0xfe, 0xfd]),
        };
        let logged = LoggedWatermarks::default();
        let touched = entry_keyspaces(&entry);
        assert_eq!(touched, vec![KS_ALL.to_string()]);
        logged.record(&touched, 9);
        assert_eq!(logged.get("anything"), 9);
        let (_, default) = read_watermarks(&AppliedWatermarks::default(), &logged, 20, &[]);
        assert_eq!(default, 9);
    }

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
        assert_eq!(touched_keyspaces(&cmd), vec!["k", "meta:k"]);
    }

    #[test]
    fn index_and_drop() {
        let cmd = StoreCommand::Transaction(vec![
            MutationInner::SetIndex { key: vec![1] },
            MutationInner::DropKeyspace {
                keyspace: "x".into(),
            },
        ]);
        assert_eq!(touched_keyspaces(&cmd), vec!["index", "x", "meta:x"]);
    }
}
