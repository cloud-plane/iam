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

//! Feed outbox (ADR 0045 section 3, M4).
//!
//! [`MutationInner::Emit`] appends an event to `meta` under
//! `_meta:outbox:<log index u64 BE><position u16 BE>` in the same batch as the
//! mutation it describes. The log index is the same on every voter, so any
//! voter can serve the feed and a cursor survives a leader change. The value
//! is `dek_version u32 BE`, `applied_at u64 BE` (Unix seconds on the applying
//! node, for retention) and the event encrypted under that epoch with the
//! outbox key as associated data.

use std::collections::BTreeSet;

use openstack_keystone_storage_api::FeedOp;

use super::*;

/// Fjall meta key prefix of outbox events.
pub(crate) const OUTBOX_PREFIX: &str = "_meta:outbox:";

/// Fjall meta key of the feed epoch: the log index of the first `Emit`, or of
/// the last restore. A consumer cursor is only valid within one epoch, because
/// a restore restarts the Raft indexes the cursors count in.
pub(crate) const META_FEED_EPOCH: &[u8] = b"_meta:feed:epoch";

/// Fjall meta key of the feed floor: the oldest log index still in the outbox.
pub(crate) const META_FEED_FLOOR: &[u8] = b"_meta:feed:floor";

/// Fjall meta key prefix of feed grants:
/// `_meta:feed:grant:<svid>\0<kind>\0<domain>`, with no value. `<domain>` is
/// `*` for every domain or `=<domain id>` for one. Grants are replicated
/// state, so every voter serves a subscriber the same set, and a revocation
/// takes effect at its log index.
pub(crate) const FEED_GRANT_PREFIX: &str = "_meta:feed:grant:";

/// Partition name under which outbox events are encrypted and quarantined.
const OUTBOX_PARTITION: &[u8] = b"outbox";

/// Position of an event in the feed: the Raft log index of the entry that
/// carried it and its place inside that entry.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeedCursor {
    /// Raft log index.
    pub index: u64,
    /// Position among the entry's events.
    pub position: u16,
}

/// One feed event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboxEvent {
    /// Feed kind.
    pub kind: String,
    /// Owning domain, if any.
    pub domain_id: Option<String>,
    /// Key of the changed record.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    /// What happened to it.
    pub op: FeedOp,
    /// Plaintext value of a `Set`.
    pub value: Option<serde_bytes::ByteBuf>,
}

/// What a subscriber identity may receive: per kind, the domains allowed, or
/// `None` for every domain.
pub type FeedGrants = std::collections::BTreeMap<String, Option<BTreeSet<String>>>;

fn grant_key(svid: &str, kind: &str, domain: Option<&str>) -> Vec<u8> {
    let mut key = grant_prefix(svid);
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    match domain {
        None => key.push(b'*'),
        Some(d) => {
            key.push(b'=');
            key.extend_from_slice(d.as_bytes());
        }
    }
    key
}

fn grant_prefix(svid: &str) -> Vec<u8> {
    let mut key = FEED_GRANT_PREFIX.as_bytes().to_vec();
    key.extend_from_slice(svid.as_bytes());
    key.push(0);
    key
}

/// Splits the part of a grant key after the SVID into `(kind, domain)`.
fn parse_grant(rest: &[u8]) -> Option<(String, Option<String>)> {
    let split = rest.iter().position(|b| *b == 0)?;
    let kind = std::str::from_utf8(&rest[..split]).ok()?;
    let domain = match rest[split + 1..].split_first()? {
        (b'*', []) => None,
        (b'=', d) => Some(std::str::from_utf8(d).ok()?.to_owned()),
        _ => return None,
    };
    Some((kind.to_owned(), domain))
}

pub(super) fn outbox_key(cursor: FeedCursor) -> Vec<u8> {
    let mut key = OUTBOX_PREFIX.as_bytes().to_vec();
    key.extend_from_slice(&cursor.index.to_be_bytes());
    key.extend_from_slice(&cursor.position.to_be_bytes());
    key
}

/// An `Emit` this node refuses to propose.
pub(crate) struct EmitRefusal {
    /// Violation type reported to the caller.
    pub violation_type: &'static str,
    /// The kind of the refused event.
    pub subject: String,
    /// Human readable reason.
    pub description: String,
}

fn cursor_from_key(key: &[u8]) -> Option<FeedCursor> {
    let rest = key.strip_prefix(OUTBOX_PREFIX.as_bytes())?;
    let (index, position) = rest.split_at_checked(8)?;
    Some(FeedCursor {
        index: u64::from_be_bytes(index.try_into().ok()?),
        position: u16::from_be_bytes(position.try_into().ok()?),
    })
}

/// Splits a stored outbox value into `(dek_version, applied_at, ciphertext)`.
fn split_entry(value: &[u8]) -> Result<(u32, u64, &[u8]), StoreError> {
    let short = || StoreError::Other(eyre::eyre!("short outbox entry"));
    let (version, rest) = value.split_first_chunk::<4>().ok_or_else(short)?;
    let (at, body) = rest.split_first_chunk::<8>().ok_or_else(short)?;
    Ok((u32::from_be_bytes(*version), u64::from_be_bytes(*at), body))
}

impl FjallStateMachine {
    /// Kinds that `Emit` may write; empty disables the feed.
    pub fn set_feed_kinds(&self, kinds: impl IntoIterator<Item = String>) {
        *self.feed_kinds.write().unwrap_or_else(|p| p.into_inner()) = kinds.into_iter().collect();
    }

    /// Largest feed event this node accepts.
    pub fn set_feed_max_event_bytes(&self, bytes: usize) {
        self.feed_max_event_bytes
            .store(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// The first `Emit` in `cmd` that this node refuses: a kind it does not
    /// enable, or an event over `feed_max_event_bytes`.
    ///
    /// Both limits are node-local configuration, so they are enforced where a
    /// transaction is proposed and never on apply: every voter must apply a
    /// committed `Emit` the same way.
    pub(crate) fn refused_emit(
        &self,
        cmd: &crate::store_command::StoreCommand,
    ) -> Option<EmitRefusal> {
        let crate::store_command::StoreCommand::Transaction(muts) = cmd else {
            return None;
        };
        let kinds = self.feed_kinds.read().unwrap_or_else(|p| p.into_inner());
        let max = self
            .feed_max_event_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        muts.iter().find_map(|m| match m {
            MutationInner::Emit {
                kind,
                domain_id,
                key,
                value,
                ..
            } => {
                if !kinds.contains(kind.as_str()) {
                    return Some(EmitRefusal {
                        violation_type: "FEED_KIND_DISABLED",
                        subject: kind.clone(),
                        description: format!("feed kind '{kind}' is not enabled"),
                    });
                }
                let size = kind.len()
                    + domain_id.as_ref().map_or(0, |d| d.len())
                    + key.len()
                    + value.as_ref().map_or(0, |v| v.len());
                (size > max).then(|| EmitRefusal {
                    violation_type: "FEED_EVENT_TOO_LARGE",
                    subject: kind.clone(),
                    description: format!("feed event of {size} bytes exceeds the {max} byte limit"),
                })
            }
            _ => None,
        })
    }

    /// Stages `event` at `cursor`. Returns `QUARANTINED` as an error like any
    /// encrypted write.
    pub(super) fn stage_outbox_event(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        cursor: FeedCursor,
        event: &OutboxEvent,
    ) -> Result<(), StoreError> {
        let key = outbox_key(cursor);
        let plain = rmp_serde::to_vec(event)?;
        let (encrypted, dek_version) =
            self.encrypt_and_store(&self.meta, &key, OUTBOX_PARTITION, 1, &plain)?;
        let mut stored = dek_version.to_be_bytes().to_vec();
        stored.extend_from_slice(&unix_now().to_be_bytes());
        stored.extend_from_slice(&encrypted);
        batch.insert(&self.meta, key, stored);
        Ok(())
    }

    fn meta_u64(&self, key: &[u8]) -> Result<Option<u64>, StoreError> {
        Ok(self
            .meta
            .get(key)?
            .and_then(|v| v.as_ref().try_into().ok().map(u64::from_be_bytes)))
    }

    /// The feed epoch, if any event was ever emitted.
    pub fn feed_epoch(&self) -> Result<Option<u64>, StoreError> {
        self.meta_u64(META_FEED_EPOCH)
    }

    /// The oldest log index a cursor can still resume from (0 if nothing was
    /// pruned).
    pub fn feed_floor(&self) -> Result<u64, StoreError> {
        Ok(self.meta_u64(META_FEED_FLOOR)?.unwrap_or(0))
    }

    /// Stages the epoch for the first event of a feed.
    pub(super) fn stage_feed_epoch(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        index: u64,
    ) -> Result<(), StoreError> {
        if self.feed_epoch()?.is_none() {
            batch.insert(&self.meta, META_FEED_EPOCH, index.to_be_bytes());
        }
        Ok(())
    }

    /// Stages `epoch` as the feed epoch, replacing any current one.
    pub(super) fn stage_feed_epoch_value(&self, batch: &mut fjall::OwnedWriteBatch, epoch: u64) {
        batch.insert(&self.meta, META_FEED_EPOCH, epoch.to_be_bytes());
    }

    /// Stages a grant of `kind` to `svid`, for one domain or (`None`) all.
    pub(super) fn stage_feed_grant(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        svid: &str,
        kind: &str,
        domain: Option<&str>,
    ) {
        batch.insert(&self.meta, grant_key(svid, kind, domain), []);
    }

    /// Stages the removal of one grant. Removing one that does not exist is a
    /// no-op.
    pub(super) fn stage_feed_revoke(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        svid: &str,
        kind: &str,
        domain: Option<&str>,
    ) {
        batch.remove(&self.meta, grant_key(svid, kind, domain));
    }

    /// The grants of `svid`. A kind with a grant for every domain allows every
    /// domain, whatever other rows it has.
    pub fn feed_grants(&self, svid: &str) -> Result<FeedGrants, StoreError> {
        let prefix = grant_prefix(svid);
        let mut out = FeedGrants::new();
        for item in self.meta.prefix(&prefix) {
            let key = item.key()?;
            let Some((kind, domain)) = parse_grant(&key[prefix.len()..]) else {
                continue;
            };
            match (
                out.entry(kind).or_insert_with(|| Some(BTreeSet::new())),
                domain,
            ) {
                (slot, None) => *slot = None,
                (Some(set), Some(d)) => {
                    set.insert(d);
                }
                (None, Some(_)) => {}
            }
        }
        Ok(out)
    }

    /// Every grant as `(svid, kind, domain)`, or those of one `svid`.
    pub fn list_feed_grants(
        &self,
        svid: Option<&str>,
    ) -> Result<Vec<(String, String, Option<String>)>, StoreError> {
        let prefix = svid.map_or_else(|| FEED_GRANT_PREFIX.as_bytes().to_vec(), grant_prefix);
        let mut out = Vec::new();
        for item in self.meta.prefix(&prefix) {
            let key = item.key()?;
            let Some(rest) = key.strip_prefix(FEED_GRANT_PREFIX.as_bytes()) else {
                continue;
            };
            let Some(split) = rest.iter().position(|b| *b == 0) else {
                continue;
            };
            let (Ok(id), Some((kind, domain))) = (
                std::str::from_utf8(&rest[..split]),
                parse_grant(&rest[split + 1..]),
            ) else {
                continue;
            };
            out.push((id.to_owned(), kind, domain));
        }
        Ok(out)
    }

    /// Stages the removal of every outbox event up to and including
    /// `upto_index` and raises the floor past it.
    pub(super) fn stage_outbox_prune(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        upto_index: u64,
    ) -> Result<(), StoreError> {
        for item in self.meta.prefix(OUTBOX_PREFIX.as_bytes()) {
            let key = item.key()?;
            match cursor_from_key(&key) {
                Some(c) if c.index <= upto_index => batch.remove(&self.meta, key),
                _ => break,
            }
        }
        let floor = self.feed_floor()?.max(upto_index.saturating_add(1));
        batch.insert(&self.meta, META_FEED_FLOOR, floor.to_be_bytes());
        Ok(())
    }

    /// The newest log index the retention rules allow to delete: events
    /// applied before `now - retention_secs` (`0` disables the age rule) and
    /// the oldest ones beyond `max_events` (`0` disables the count rule).
    pub fn outbox_prune_point(
        &self,
        now: u64,
        retention_secs: u64,
        max_events: u64,
    ) -> Result<Option<u64>, StoreError> {
        let mut entries: Vec<(u64, u64)> = Vec::new();
        for item in self.meta.prefix(OUTBOX_PREFIX.as_bytes()) {
            let (key, value) = item.into_inner()?;
            if let Some(c) = cursor_from_key(&key) {
                // An entry that cannot be read must not stop retention for
                // good: count it as the oldest, so the age rule removes it.
                let at = match split_entry(&value) {
                    Ok((_, at, _)) => at,
                    Err(e) => {
                        tracing::warn!(
                            index = c.index,
                            position = c.position,
                            error = %e,
                            "malformed outbox entry, pruning it as the oldest"
                        );
                        0
                    }
                };
                entries.push((c.index, at));
            }
        }
        let mut upto = None;
        if retention_secs > 0 {
            let cutoff = now.saturating_sub(retention_secs);
            upto = entries
                .iter()
                .filter(|(_, at)| *at < cutoff)
                .map(|(i, _)| *i)
                .max();
        }
        if max_events > 0 && entries.len() as u64 > max_events {
            // Cut at a log index boundary that deletes no more than the
            // excess, so events sharing an index are never split.
            let excess = entries.len() - max_events as usize;
            let mut by_count = None;
            let mut start = 0;
            while start < entries.len() {
                let index = entries[start].0;
                let end = entries[start..]
                    .iter()
                    .position(|(i, _)| *i != index)
                    .map_or(entries.len(), |n| start + n);
                if end > excess {
                    break;
                }
                by_count = Some(index);
                start = end;
            }
            upto = upto.max(by_count);
        }
        Ok(upto)
    }

    /// Stages the removal of the events encrypted under `dek_version`, which
    /// an emergency rotation revoked, and starts a new epoch so consumers
    /// reload instead of resuming over the gap.
    pub(super) fn stage_outbox_revoke(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        dek_version: u32,
        index: u64,
    ) -> Result<(), StoreError> {
        let mut removed = false;
        for item in self.meta.prefix(OUTBOX_PREFIX.as_bytes()) {
            let (key, value) = item.into_inner()?;
            // An entry that cannot be read cannot be decrypted either, so a
            // revocation removes it.
            let revoked = split_entry(&value).map_or(true, |(v, _, _)| v == dek_version);
            if revoked {
                batch.remove(&self.meta, key);
                removed = true;
            }
        }
        if removed {
            batch.insert(&self.meta, META_FEED_EPOCH, index.to_be_bytes());
        }
        Ok(())
    }

    /// Starts a new feed after a restore replaced `meta`: drops the restored
    /// outbox and begins a new epoch, so cursors of the old epoch are
    /// refused. A live restore (applied through the log) passes the restore
    /// entry's log index, which is unique across the cluster. A restore into
    /// an uninitialized node passes a provisional node-local value instead,
    /// since the nodes cannot agree on one before they form a cluster; the
    /// elected node later proposes the real epoch through Raft
    /// (`SetFeedEpoch`).
    pub(crate) fn reset_feed(&self, epoch: u64) -> Result<(), StoreError> {
        let mut batch = self.db.batch();
        for item in self.meta.prefix(OUTBOX_PREFIX.as_bytes()) {
            batch.remove(&self.meta, item.key()?);
        }
        batch.remove(&self.meta, META_FEED_FLOOR);
        // Always start a new epoch, even if the restored state never emitted,
        // so a cursor from the replaced cluster is never mistaken for current.
        batch.insert(&self.meta, META_FEED_EPOCH, epoch.to_be_bytes());
        batch.commit()?;
        Ok(())
    }

    /// Up to `limit` events after `after` (all if `None`), oldest first.
    pub fn outbox_events_after(
        &self,
        after: Option<FeedCursor>,
        limit: usize,
    ) -> Result<Vec<(FeedCursor, OutboxEvent)>, StoreError> {
        let start = match after {
            Some(c) => outbox_key(c),
            None => OUTBOX_PREFIX.as_bytes().to_vec(),
        };
        let mut out = Vec::new();
        for item in self.meta.range(start..) {
            if out.len() >= limit {
                break;
            }
            let (key, value) = item.into_inner()?;
            let Some(cursor) = cursor_from_key(&key) else {
                break;
            };
            if after == Some(cursor) {
                continue;
            }
            let (version, _, body) = split_entry(&value)?;
            let plain = self.decrypt_state(body, 1, OUTBOX_PARTITION, &key, Some(version))?;
            out.push((cursor, rmp_serde::from_slice(&plain)?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;

    #[test]
    fn grant_keys_round_trip() {
        for domain in [None, Some("d1"), Some("a=b*")] {
            let key = grant_key("spiffe://a/b", "registry", domain);
            let rest = key
                .strip_prefix(grant_prefix("spiffe://a/b").as_slice())
                .unwrap();
            assert_eq!(
                Some(("registry".to_owned(), domain.map(str::to_owned))),
                parse_grant(rest)
            );
        }
    }

    #[test]
    fn grant_prefix_does_not_match_a_longer_svid() {
        let longer = grant_key("spiffe://a/bc", "registry", None);
        assert!(!longer.starts_with(&grant_prefix("spiffe://a/b")));
    }
}
