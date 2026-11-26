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

//! Feed consumer (ADR 0045 section 3, R6).
//!
//! Subscribes to another authority's feed and applies the events to local
//! storage through a [`FeedSink`], which turns each event into mutations of the
//! consumer's own drivers' keyspaces. The cursor is stored with the data, in
//! the same transaction as the mutations of the events it covers, so an event
//! is applied once even if the process dies between two events, and a replay
//! is skipped.

use std::sync::Arc;
use std::time::Duration;

use openstack_keystone_storage_api::{Metadata, Mutation, StorageApi, StoreError};
use serde::{Deserialize, Serialize};

use crate::grpc::authz::PeerRole;
use crate::network::RaftTlsClient;
use crate::pb::raft::SubscribeRequest;
use crate::pb::raft::feed_message::Message;
use crate::pb::raft::feed_service_client::FeedServiceClient;

/// Keyspace holding one cursor record per source.
pub const FEED_CURSOR_KEYSPACE: &str = "feed_cursor";

fn other(msg: String) -> StoreError {
    StoreError::Other(msg.into())
}

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A session that lasted this long, after receiving from the source, resets
/// the reconnect backoff.
const HEALTHY_SESSION: Duration = Duration::from_secs(10);
/// Reconnect cap of a priority stream: the revocation bound is 30 s, so a
/// dropped stream must be back well within it.
const PRIORITY_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// One feed event, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedEventData {
    /// Raft log index at the source.
    pub index: u64,
    /// Position among the events of that log entry.
    pub position: u16,
    /// Feed kind.
    pub kind: String,
    /// Owning domain, if any.
    pub domain_id: Option<String>,
    /// Key of the changed record at the source.
    pub key: Vec<u8>,
    /// Whether the record was removed.
    pub removed: bool,
    /// Plaintext value of a set.
    pub value: Option<Vec<u8>>,
}

/// Applies events to local storage.
#[async_trait::async_trait]
pub trait FeedSink: Send + Sync {
    /// The mutations that make `event` visible locally.
    ///
    /// They must be idempotent: a `Remove` of a missing record is a no-op in
    /// storage, and a `Set` replaces. The consumer adds its cursor update to
    /// the same transaction.
    fn mutations(&self, event: &FeedEventData) -> Result<Vec<Mutation>, StoreError>;

    /// The stream has caught up with the source: a heartbeat arrived, which
    /// the source sends only when it has no event left for this consumer, and
    /// every batch before it is applied. A sink that tracks how fresh its
    /// mirror is records it here.
    fn on_head(&self) {}

    /// Called when the source says the cursor cannot be resumed, before the
    /// consumer subscribes afresh. A sink that mirrors a kind clears or
    /// reloads it here.
    async fn reseed(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// Stored position of a consumer in a source's feed.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CursorRecord {
    /// Feed epoch of the source.
    pub epoch: u64,
    /// Log index of the last applied event.
    pub index: u64,
    /// Its position.
    pub position: u16,
}

/// How [`FeedConsumer::run_once`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// The source closed the stream.
    Ended,
    /// The cursor could not be resumed; the sink was reseeded and the stored
    /// cursor cleared.
    Reset,
}

/// What a consumer subscribes to.
#[derive(Clone, Debug, Default)]
pub struct FeedConsumerConfig {
    /// Domains to receive; empty for the ones the grants allow.
    pub domains: Vec<String>,
    /// Kinds to receive; empty for the ones the grants allow.
    pub kinds: Vec<String>,
    /// Identifies the source in the cursor keyspace.
    pub name: String,
    /// Subscribe to the priority outbox of the source (revocations). It has
    /// a cursor of its own, and the consumer reconnects within seconds.
    pub priority: bool,
    /// `host:port` of any voter of the source authority.
    pub source_addr: String,
}

/// A subscription to one source's feed.
pub struct FeedConsumer {
    config: FeedConsumerConfig,
    sink: Arc<dyn FeedSink>,
    storage: Arc<dyn StorageApi>,
    tls: RaftTlsClient,
}

impl FeedConsumer {
    /// A consumer that stores its cursor in `storage` and applies events
    /// through `sink`. Use [`crate::Storage::feed_consumer`] to build one
    /// with the node's own TLS identity.
    pub fn new(
        config: FeedConsumerConfig,
        tls: RaftTlsClient,
        storage: Arc<dyn StorageApi>,
        sink: Arc<dyn FeedSink>,
    ) -> Self {
        Self {
            config,
            sink,
            storage,
            tls,
        }
    }

    /// Key of the cursor record: the two outboxes of a source have separate
    /// positions and epochs.
    fn cursor_key(&self) -> Vec<u8> {
        if self.config.priority {
            format!("{}#priority", self.config.name).into_bytes()
        } else {
            self.config.name.clone().into_bytes()
        }
    }

    /// The stored cursor and its record revision.
    pub async fn load_cursor(&self) -> Result<Option<(CursorRecord, u64)>, StoreError> {
        let Some(env) = self
            .storage
            .get_by_key(&self.cursor_key(), Some(FEED_CURSOR_KEYSPACE))
            .await?
        else {
            return Ok(None);
        };
        let record = rmp_serde::from_slice(&env.data)
            .map_err(|e| other(format!("decoding the feed cursor: {e}")))?;
        Ok(Some((record, env.metadata.revision)))
    }

    /// Applies `events` of `epoch`: skips what the cursor already covers and
    /// writes the rest together with the new cursor. Fails if the stored
    /// cursor is of another epoch.
    pub async fn apply(&self, epoch: u64, events: Vec<FeedEventData>) -> Result<(), StoreError> {
        let stored = self.load_cursor().await?;
        if let Some((cursor, _)) = stored
            && cursor.epoch != epoch
        {
            // The source started a new epoch between the subscription and
            // this batch. Applying over the old mirror would keep records
            // the new epoch no longer has; fail so the next subscription
            // presents the stored epoch and gets a Reset and a reseed.
            return Err(other(format!(
                "feed epoch changed from {} to {epoch}",
                cursor.epoch
            )));
        }
        let covered = stored.map(|(c, _)| (c.index, c.position));
        let mut mutations = Vec::new();
        let mut last = None;
        for event in &events {
            let at = (event.index, event.position);
            if covered.is_some_and(|c| at <= c) {
                continue;
            }
            mutations.extend(self.sink.mutations(event)?);
            last = Some(at);
        }
        let Some((index, position)) = last else {
            return Ok(());
        };
        let record = rmp_serde::to_vec(&CursorRecord {
            epoch,
            index,
            position,
        })
        .map_err(|e| other(format!("encoding the feed cursor: {e}")))?;
        mutations.push(Mutation::Set {
            expected_revision: stored.map(|(_, rev)| rev),
            key: self.cursor_key(),
            keyspace: FEED_CURSOR_KEYSPACE.to_owned(),
            metadata: Metadata::new(),
            value: record,
        });
        self.storage.transaction(mutations).await?;
        Ok(())
    }

    /// Connects, resumes from the stored cursor and applies events until the
    /// stream ends or the source resets the cursor.
    pub async fn run_once(&self) -> Result<RunOutcome, StoreError> {
        self.session(&mut false, &mut false).await
    }

    /// [`Self::run_once`], setting `progressed` once an event was applied and
    /// `heard` once the source sent anything.
    async fn session(
        &self,
        progressed: &mut bool,
        heard: &mut bool,
    ) -> Result<RunOutcome, StoreError> {
        let cursor = self.load_cursor().await?.map(|(c, _)| c);
        let channel = self
            .tls
            .connect_as(&self.config.source_addr, PeerRole::FeedConsumer)
            .await?;
        let mut client = FeedServiceClient::new(channel);
        let mut stream = client
            .subscribe(SubscribeRequest {
                epoch: cursor.map_or(0, |c| c.epoch),
                has_cursor: cursor.is_some(),
                cursor_index: cursor.map_or(0, |c| c.index),
                cursor_position: cursor.map_or(0, |c| u32::from(c.position)),
                kinds: self.config.kinds.clone(),
                domains: self.config.domains.clone(),
                priority: self.config.priority,
            })
            .await
            .map_err(|e| other(format!("subscribing to the feed: {e}")))?
            .into_inner();
        loop {
            let message = stream
                .message()
                .await
                .map_err(|e| other(format!("feed stream: {e}")))?;
            match message.and_then(|m| m.message) {
                None => return Ok(RunOutcome::Ended),
                Some(Message::Head(_)) => {
                    *heard = true;
                    self.sink.on_head();
                }
                Some(Message::Events(batch)) => {
                    *heard = true;
                    let events = batch
                        .events
                        .into_iter()
                        .map(|e| {
                            Ok(FeedEventData {
                                index: e.index,
                                position: u16::try_from(e.position)
                                    .map_err(|_| other("event position out of range".to_owned()))?,
                                kind: e.kind,
                                domain_id: e.has_domain.then_some(e.domain_id),
                                key: e.key,
                                removed: e.removed,
                                value: e.has_value.then_some(e.value),
                            })
                        })
                        .collect::<Result<Vec<_>, StoreError>>()?;
                    let applied = !events.is_empty();
                    self.apply(batch.epoch, events).await?;
                    *progressed |= applied;
                }
                Some(Message::Reset(reset)) => {
                    tracing::warn!(
                        source = %self.config.name,
                        reason = %reset.reason,
                        "feed cursor reset; reseeding"
                    );
                    self.sink.reseed().await?;
                    if let Some((_, revision)) = self.load_cursor().await? {
                        self.storage
                            .transaction(vec![Mutation::Remove {
                                key: self.cursor_key(),
                                keyspace: FEED_CURSOR_KEYSPACE.to_owned(),
                                expected_revision: Some(revision),
                            }])
                            .await?;
                    }
                    return Ok(RunOutcome::Reset);
                }
            }
        }
    }

    /// Keeps the subscription running until `stop` completes. A session that
    /// fails, ends or is reset waits before the next one, longer each time
    /// (up to a minute, five seconds on a priority stream) until a session
    /// applies an event or stays up for a while.
    pub async fn run(&self, stop: impl std::future::Future<Output = ()>) {
        tokio::pin!(stop);
        let mut backoff = BACKOFF_MIN;
        let max_backoff = if self.config.priority {
            PRIORITY_BACKOFF_MAX
        } else {
            BACKOFF_MAX
        };
        loop {
            let mut progressed = false;
            let mut heard = false;
            let started = tokio::time::Instant::now();
            let outcome = tokio::select! {
                () = &mut stop => return,
                r = self.session(&mut progressed, &mut heard) => r,
            };
            if let Err(e) = &outcome {
                tracing::warn!(
                    source = %self.config.name,
                    error = %e,
                    "feed subscription failed"
                );
            }
            // A stream that was healthy for a while and then dropped is not a
            // failing source: reconnect at once rather than after a long wait.
            // A session that never heard from the source (a connect or a
            // subscribe that hung) is not healthy, however long it took.
            progressed |= heard && started.elapsed() > HEALTHY_SESSION;
            if progressed {
                backoff = BACKOFF_MIN;
            }
            tokio::select! {
                () = &mut stop => return,
                () = tokio::time::sleep(backoff) => {}
            }
            if !progressed {
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}
