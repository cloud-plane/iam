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

//! # OpenStack Keystone Raft driver for the token revocation events
//!
//! Revocation events live in the `revocation_event` keyspace, keyed
//! `<revoked_at, microseconds, 20 digits>:<event id>`, so the events of a
//! period are a key range and expiry is a range delete. Every create and
//! every delete also emits a `revocation` event into the priority outbox of
//! the change feed (ADR 0045 section 9), in the same transaction, when the
//! node enables that feed kind.
//!
//! Events of other authorities arrive over their priority feed (see
//! [`RevocationFeedSink`]) and are kept apart in the `revocation_event_mirror`
//! keyspace, keyed `<authority length>:<authority>:<event id>`. The authority comes from the
//! subscription, never from the event, and a mirrored event revokes only the
//! tokens that authority issued.
//!
//! The check of a token runs on every validation, so it is answered from an
//! in-memory copy of the (short lived) events. The copy is valid for one
//! revision of the keyspace: the leader vouches for the revision after a
//! `ReadIndex`, and a node that cannot reads the keyspace through.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use openstack_keystone_core::auth::ValidatedSecurityContext;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::revoke::{RevokeProviderError, STREAM_HEALTH, backend::RevokeBackend};
use openstack_keystone_core_types::revoke::*;
use openstack_keystone_core_types::token::FernetToken;
use openstack_keystone_distributed_storage::feed_consumer::{
    FeedConsumerConfig, FeedEventData, FeedSink,
};
use openstack_keystone_distributed_storage::{
    ApiStoreError, DataTier, FeedOp, Metadata, Mutation, ReadConsistency, StorageApi, StoreError,
};

mod matching;

/// Keyspace of the revocation events.
const KEYSPACE: &str = "revocation_event";

/// Keyspace of the events received from other authorities.
const MIRROR_KEYSPACE: &str = "revocation_event_mirror";

/// Events removed per transaction by the expiry cleanup.
const DELETE_CHUNK: usize = 500;

/// Feed kind of the revocation events.
pub const FEED_KIND: &str = "revocation";

/// A stored revocation event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventRecord {
    /// Access token id.
    pub access_token_id: Option<String>,
    /// Audit id of the revoked token.
    pub audit_id: Option<String>,
    /// Audit chain id.
    pub audit_chain_id: Option<String>,
    /// Consumer id.
    pub consumer_id: Option<String>,
    /// Domain the revoked tokens are scoped to.
    pub domain_id: Option<String>,
    /// Expiry of the revoked token, microseconds since the epoch.
    pub expires_at: Option<i64>,
    /// Event id, unique and part of the storage key.
    pub id: String,
    /// Tokens issued before this moment are revoked, microseconds.
    pub issued_before: i64,
    /// The authority that issued the event; `None` for an event of this
    /// authority.
    #[serde(default)]
    pub origin: Option<String>,
    /// Domain that owns the event in the feed, when it differs from the
    /// scope. Kept with the record so a set and its removal reach the same
    /// subscribers.
    #[serde(default)]
    pub owner_domain_id: Option<String>,
    /// Project the revoked tokens are scoped to.
    pub project_id: Option<String>,
    /// When the event was recorded, microseconds.
    pub revoked_at: i64,
    /// Role of a revoked assignment.
    pub role_id: Option<String>,
    /// Trust of the revoked tokens.
    pub trust_id: Option<String>,
    /// Revoked user.
    pub user_id: Option<String>,
}

fn micros(t: DateTime<Utc>) -> i64 {
    t.timestamp_micros()
}

fn from_micros(v: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(v).unwrap_or_default()
}

impl From<EventRecord> for RevocationEvent {
    fn from(r: EventRecord) -> Self {
        Self {
            access_token_id: r.access_token_id,
            audit_id: r.audit_id,
            audit_chain_id: r.audit_chain_id,
            consumer_id: r.consumer_id,
            domain_id: r.domain_id,
            expires_at: r.expires_at.map(from_micros),
            issued_before: from_micros(r.issued_before),
            project_id: r.project_id,
            revoked_at: from_micros(r.revoked_at),
            role_id: r.role_id,
            trust_id: r.trust_id,
            user_id: r.user_id,
        }
    }
}

impl EventRecord {
    fn new(event: &RevocationEventCreate) -> Self {
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            access_token_id: event.access_token_id.clone(),
            audit_id: event.audit_id.clone(),
            audit_chain_id: event.audit_chain_id.clone(),
            consumer_id: event.consumer_id.clone(),
            domain_id: event.domain_id.clone(),
            expires_at: event.expires_at.map(micros),
            issued_before: micros(event.issued_before),
            project_id: event.project_id.clone(),
            revoked_at: micros(event.revoked_at),
            role_id: event.role_id.clone(),
            trust_id: event.trust_id.clone(),
            user_id: event.user_id.clone(),
            origin: None,
            owner_domain_id: event.owner_domain_id.clone(),
        }
    }

    /// Domain of the feed event of this record.
    fn feed_domain(&self) -> Option<String> {
        self.owner_domain_id
            .clone()
            .or_else(|| self.domain_id.clone())
    }

    /// Storage key: time ordered, so a range delete expires old events.
    fn key(&self) -> String {
        key(self.revoked_at, &self.id)
    }
}

fn key(revoked_at: i64, id: &str) -> String {
    format!("{:020}:{id}", revoked_at.max(0))
}

fn driver<E: std::fmt::Display>(e: E) -> RevokeProviderError {
    RevokeProviderError::Driver(e.to_string())
}

/// Commits `mutations`, failing on any violation.
async fn commit(
    storage: &dyn StorageApi,
    mutations: Vec<Mutation>,
) -> Result<(), RevokeProviderError> {
    let response = storage.transaction(mutations).await.map_err(driver)?;
    match response.violations.first() {
        Some(v) => Err(RevokeProviderError::Driver(format!(
            "{}: {}",
            v.r#type, v.description
        ))),
        None => Ok(()),
    }
}

/// The events in memory, valid for one revision of the keyspace.
#[derive(Default)]
struct Snapshot {
    /// Revisions of the local and the mirror keyspace, as the storage
    /// reported them.
    revision: Option<Vec<u64>>,
    events: Arc<Vec<EventRecord>>,
}

/// Raft revocation backend.
#[derive(Default)]
pub struct RaftBackend {
    snapshot: RwLock<Snapshot>,
}

impl RaftBackend {
    async fn load(storage: &dyn StorageApi) -> Result<Vec<EventRecord>, StoreError> {
        let mut events = Vec::new();
        for keyspace in [KEYSPACE, MIRROR_KEYSPACE] {
            for (_, envelope) in storage.prefix(b"", Some(keyspace)).await? {
                events.push(envelope.try_deserialize::<EventRecord>()?.data);
            }
        }
        Ok(events)
    }

    /// The events, from memory when neither keyspace changed.
    async fn events(
        &self,
        storage: &dyn StorageApi,
    ) -> Result<Arc<Vec<EventRecord>>, RevokeProviderError> {
        // Always linearizable: a revocation must be honoured by the next
        // check. One call covers both keyspaces, and a follower gets the
        // revisions from the leader instead of reading the events through.
        let revision = storage
            .keyspace_revisions(&[KEYSPACE, MIRROR_KEYSPACE], ReadConsistency::Linearizable)
            .await
            .map_err(driver)?;
        if let Some(revision) = &revision
            && let snapshot = self.snapshot.read().unwrap_or_else(|p| p.into_inner())
            && snapshot.revision.as_ref() == Some(revision)
        {
            return Ok(snapshot.events.clone());
        }
        let events = Arc::new(Self::load(storage).await.map_err(driver)?);
        if let Some(revision) = revision {
            // The revisions were read before the events, so a write in
            // between only makes the next check reload.
            *self.snapshot.write().unwrap_or_else(|p| p.into_inner()) = Snapshot {
                revision: Some(revision),
                events: events.clone(),
            };
        }
        Ok(events)
    }

    fn storage(state: &ServiceState) -> Result<&dyn StorageApi, RevokeProviderError> {
        state.storage.as_deref().ok_or_else(|| {
            RevokeProviderError::Driver("distributed storage is not available".into())
        })
    }

    async fn create_impl(
        storage: &dyn StorageApi,
        event: RevocationEventCreate,
    ) -> Result<RevocationEvent, RevokeProviderError> {
        let record = EventRecord::new(&event);
        let mut mutations = vec![
            Mutation::set(record.key(), &record, Metadata::new(), Some(KEYSPACE), None)
                .map_err(driver)?,
        ];
        mutations.extend(Self::emit(storage, &record, FeedOp::Set)?);
        commit(storage, mutations).await?;
        Ok(record.into())
    }

    async fn delete_expired_impl(
        storage: &dyn StorageApi,
        revoked_before: DateTime<Utc>,
    ) -> Result<u64, RevokeProviderError> {
        let cutoff = key(micros(revoked_before), "");
        // One transaction carries at most `DELETE_CHUNK` events, so the emits
        // stay below the limit of the state machine and the raft entry stays
        // small. A chunk that is committed stays deleted if a later one fails;
        // the next run continues.
        let mut mutations = Vec::new();
        let mut pending = 0usize;
        let mut deleted = 0u64;
        for (stored_key, envelope) in storage.prefix(b"", Some(KEYSPACE)).await.map_err(driver)? {
            if stored_key.as_str() >= cutoff.as_str() {
                continue;
            }
            let record = envelope
                .try_deserialize::<EventRecord>()
                .map_err(driver)?
                .data;
            mutations.push(Mutation::remove(stored_key, Some(KEYSPACE), None));
            mutations.extend(Self::emit(storage, &record, FeedOp::Remove)?);
            pending += 1;
            deleted += 1;
            if pending >= DELETE_CHUNK {
                commit(storage, std::mem::take(&mut mutations)).await?;
                pending = 0;
            }
        }
        // The source removes the events it expires, but a source that is gone
        // would leave its events here for good.
        let cutoff_micros = micros(revoked_before);
        for (stored_key, envelope) in storage
            .prefix(b"", Some(MIRROR_KEYSPACE))
            .await
            .map_err(driver)?
        {
            let record = envelope
                .try_deserialize::<EventRecord>()
                .map_err(driver)?
                .data;
            if record.revoked_at < cutoff_micros {
                mutations.push(Mutation::remove(stored_key, Some(MIRROR_KEYSPACE), None));
                pending += 1;
                deleted += 1;
                if pending >= DELETE_CHUNK {
                    commit(storage, std::mem::take(&mut mutations)).await?;
                    pending = 0;
                }
            }
        }
        if !mutations.is_empty() {
            commit(storage, mutations).await?;
        }
        Ok(deleted)
    }

    async fn is_revoked_impl(
        &self,
        storage: &dyn StorageApi,
        params: &RevocationEventListParameters,
    ) -> Result<bool, RevokeProviderError> {
        let events = self.events(storage).await?;
        Ok(events.iter().any(|e| matching::revokes(e, params)))
    }

    /// An `Emit` for `record`, if the node enables the feed kind.
    fn emit(
        storage: &dyn StorageApi,
        record: &EventRecord,
        op: FeedOp,
    ) -> Result<Option<Mutation>, RevokeProviderError> {
        if !storage.feed_kind_enabled(FEED_KIND) {
            return Ok(None);
        }
        let value = match op {
            FeedOp::Set => Some(rmp_serde::to_vec(record).map_err(driver)?),
            FeedOp::Remove => None,
        };
        Ok(Some(Mutation::Emit {
            kind: FEED_KIND.to_owned(),
            domain_id: record.feed_domain(),
            key: record.id.as_bytes().to_vec(),
            op,
            value,
            tier: DataTier::Internal,
            priority: true,
        }))
    }
}

#[async_trait]
impl RevokeBackend for RaftBackend {
    #[tracing::instrument(
        name = "driver.raft.revoke.create_revocation_event",
        level = "debug",
        skip_all
    )]
    async fn create_revocation_event(
        &self,
        state: &ServiceState,
        event: RevocationEventCreate,
    ) -> Result<RevocationEvent, RevokeProviderError> {
        Self::create_impl(Self::storage(state)?, event).await
    }

    #[tracing::instrument(
        name = "driver.raft.revoke.delete_expired_revocation_events",
        level = "debug",
        skip_all
    )]
    async fn delete_expired_revocation_events(
        &self,
        state: &ServiceState,
        revoked_before: DateTime<Utc>,
    ) -> Result<u64, RevokeProviderError> {
        Self::delete_expired_impl(Self::storage(state)?, revoked_before).await
    }

    #[tracing::instrument(
        name = "driver.raft.revoke.is_token_revoked",
        level = "debug",
        skip_all
    )]
    async fn is_token_revoked(
        &self,
        state: &ServiceState,
        token_security_context: &ValidatedSecurityContext,
    ) -> Result<bool, RevokeProviderError> {
        let params =
            RevocationEventListParametersBuilder::try_from(token_security_context)?.build()?;
        self.is_revoked_impl(Self::storage(state)?, &params).await
    }

    #[tracing::instrument(name = "driver.raft.revoke.revoke_token", level = "debug", skip_all)]
    async fn revoke_token(
        &self,
        state: &ServiceState,
        token: &FernetToken,
    ) -> Result<(), RevokeProviderError> {
        self.create_revocation_event(state, token.try_into()?)
            .await
            .map(|_| ())
    }
}

/// Prefix of the mirror keys of `authority`. The length comes first, so no
/// authority name, however it is spelled, can run into another's keys.
fn mirror_prefix(authority: &str) -> String {
    format!("{}:{authority}:", authority.len())
}

fn mirror_key(authority: &str, id: &[u8]) -> String {
    format!(
        "{}{}",
        mirror_prefix(authority),
        String::from_utf8_lossy(id)
    )
}

/// The feed subscription that receives the revocation events of one other
/// authority, over its priority stream.
///
/// The consumer reconnects within seconds and keeps a cursor of its own, so a
/// restart resumes where the stream stopped.
pub fn feed_consumer_config(authority: &str, source_addr: &str) -> FeedConsumerConfig {
    FeedConsumerConfig {
        domains: Vec::new(),
        kinds: vec![FEED_KIND.to_owned()],
        name: authority.to_owned(),
        priority: true,
        source_addr: source_addr.to_owned(),
    }
}

/// Applies the revocation events of one other authority to the local mirror.
///
/// The authority is the one the subscription was configured for. The body of
/// an event cannot name another origin: it is overwritten, so a source cannot
/// speak for any authority but its own.
pub struct RevocationFeedSink {
    authority: String,
    storage: Arc<dyn StorageApi>,
}

impl RevocationFeedSink {
    /// A sink for the events of `authority`.
    pub fn new(authority: impl Into<String>, storage: Arc<dyn StorageApi>) -> Self {
        let authority = authority.into();
        // Until its stream is heard from, tokens of the authority are stale.
        STREAM_HEALTH.register(&authority);
        Self { authority, storage }
    }
}

#[async_trait]
impl FeedSink for RevocationFeedSink {
    fn mutations(&self, event: &FeedEventData) -> Result<Vec<Mutation>, ApiStoreError> {
        if event.kind != FEED_KIND {
            return Ok(Vec::new());
        }
        let key = mirror_key(&self.authority, &event.key);
        if event.removed {
            return Ok(vec![Mutation::remove(key, Some(MIRROR_KEYSPACE), None)]);
        }
        let Some(value) = &event.value else {
            return Err(ApiStoreError::Other(
                "a revocation event without a value".to_owned().into(),
            ));
        };
        let mut record: EventRecord = rmp_serde::from_slice(value).map_err(|e| {
            ApiStoreError::Other(format!("decoding a revocation event: {e}").into())
        })?;
        record.origin = Some(self.authority.clone());
        STREAM_HEALTH.record_event(&self.authority, from_micros(record.revoked_at));
        // Setting replaces, so a replay of the event is harmless.
        Ok(vec![Mutation::set(
            key,
            &record,
            Metadata::new(),
            Some(MIRROR_KEYSPACE),
            None,
        )?])
    }

    fn on_head(&self) {
        STREAM_HEALTH.record_head(&self.authority);
    }

    /// The cursor is gone: drop what this authority sent, the new
    /// subscription replays what the source still holds.
    async fn reseed(&self) -> Result<(), ApiStoreError> {
        let prefix = mirror_prefix(&self.authority);
        let removals: Vec<_> = self
            .storage
            .prefix(prefix.as_bytes(), Some(MIRROR_KEYSPACE))
            .await?
            .into_iter()
            .map(|(key, _)| Mutation::remove(key, Some(MIRROR_KEYSPACE), None))
            .collect();
        if !removals.is_empty() {
            self.storage.transaction(removals).await?;
        }
        Ok(())
    }
}

/// Linkage anchor — see ADR-0018.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    BackendRegistration::<dyn RevokeBackend> {
        name: "raft",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(RaftBackend::default()) as Arc<dyn RevokeBackend>)
        }),
    }
}

#[cfg(test)]
mod tests;
