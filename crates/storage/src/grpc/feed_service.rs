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

//! Inter-authority change feed (ADR 0045 section 3, M4).
//!
//! Streams the events of the replicated outbox after a cursor. The caller
//! needs the `feed-consumer` role and grants set through `SetFeedGrant`; its
//! request is intersected with those grants. Any voter serves, and a node that
//! lost its leader for longer than the staleness bound ends the stream.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use openraft::async_runtime::WatchReceiver;
use tonic::{Request, Response, Status};

use crate::grpc::authz::{PeerAuthz, PeerRole};
use crate::leader_contact::LeaderContact;
use crate::pb;
use crate::store::state_machine::{FeedCursor, FeedGrants, OutboxClass, OutboxEvent};
use crate::types::{Raft, StateMachineStore};

/// Events read from the outbox per batch.
const BATCH: usize = 256;

/// Longest a voter may be out of contact with the leader and still serve the
/// feed, when `local_read_max_staleness_ms` sets no bound. Grants and
/// revocations are replicated state, so a cut-off voter must stop serving.
const DEFAULT_MAX_STALENESS: Duration = Duration::from_secs(30);

/// How often an idle stream looks for new events.
const POLL: Duration = Duration::from_millis(200);

/// Heartbeat of the priority stream.
const PRIORITY_HEARTBEAT: Duration = Duration::from_secs(1);

/// Longest a voter may have gone without hearing from the leader and still
/// serve the priority stream.
const PRIORITY_MAX_STALENESS: Duration = Duration::from_secs(2);

/// What one request asks for; empty narrows nothing.
#[derive(Debug, Default)]
struct Filter {
    kinds: BTreeSet<String>,
    domains: BTreeSet<String>,
}

/// Whether `grants` (what the identity may receive) and `filter` (what it
/// asks for) both allow `event`. A request narrows the grants and never
/// widens them.
fn wanted(event: &OutboxEvent, grants: &FeedGrants, filter: &Filter) -> bool {
    let Some(allowed) = grants.get(&event.kind) else {
        return false;
    };
    if !filter.kinds.is_empty() && !filter.kinds.contains(&event.kind) {
        return false;
    }
    match &event.domain_id {
        // The emitting driver named no owner, so the event cannot be shown to
        // belong to an allowed domain: only a grant for every domain, and a
        // request that names no domain, reach it.
        None => allowed.is_none() && filter.domains.is_empty(),
        Some(d) => {
            allowed.as_ref().is_none_or(|a| a.contains(d))
                && (filter.domains.is_empty() || filter.domains.contains(d))
        }
    }
}

fn to_pb(cursor: FeedCursor, event: OutboxEvent) -> pb::raft::FeedEvent {
    pb::raft::FeedEvent {
        index: cursor.index,
        position: u32::from(cursor.position),
        kind: event.kind,
        has_domain: event.domain_id.is_some(),
        domain_id: event.domain_id.unwrap_or_default(),
        key: event.key,
        removed: event.op == openstack_keystone_storage_api::FeedOp::Remove,
        has_value: event.value.is_some(),
        value: event.value.map(|v| v.into_vec()).unwrap_or_default(),
    }
}

/// The feed gRPC service.
pub struct FeedServiceImpl {
    authz: Arc<PeerAuthz>,
    heartbeat: Duration,
    leader_contact: Arc<LeaderContact>,
    max_staleness: Option<Duration>,
    node_id: u64,
    raft: Raft,
    sm: Arc<StateMachineStore>,
}

impl FeedServiceImpl {
    /// Creates the service.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        raft: Raft,
        node_id: u64,
        sm: Arc<StateMachineStore>,
        authz: Arc<PeerAuthz>,
        leader_contact: Arc<LeaderContact>,
        heartbeat: Duration,
        max_staleness: Option<Duration>,
    ) -> Self {
        Self {
            authz,
            heartbeat,
            leader_contact,
            max_staleness,
            node_id,
            raft,
            sm,
        }
    }
}

type FeedStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<pb::raft::FeedMessage, Status>> + Send>>;

#[tonic::async_trait]
impl pb::raft::feed_service_server::FeedService for FeedServiceImpl {
    type SubscribeStream = FeedStream;

    async fn subscribe(
        &self,
        request: Request<pb::raft::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let (identity, _) = self.authz.require(&request, &[PeerRole::FeedConsumer])?;
        let grants = self
            .sm
            .feed_grants(&identity)
            .map_err(|e| Status::internal(e.to_string()))?;
        if grants.is_empty() {
            return Err(Status::permission_denied("this identity has no feed grant"));
        }
        let req = request.into_inner();
        let filter = Filter {
            kinds: req.kinds.iter().cloned().collect(),
            domains: req.domains.iter().cloned().collect(),
        };
        let mut cursor = req.has_cursor.then_some(FeedCursor {
            index: req.cursor_index,
            position: u16::try_from(req.cursor_position)
                .map_err(|_| Status::invalid_argument("cursor_position is out of range"))?,
        });
        let requested_epoch = req.epoch;
        let req_has_cursor = req.has_cursor;

        let sm = self.sm.clone();
        let raft = self.raft.clone();
        let class = OutboxClass::from_priority(req.priority);
        // The priority stream carries revocations, which are acted on within
        // seconds: its heartbeat is short and a voter must have heard from the
        // leader recently to serve it.
        let (heartbeat, limit) = if req.priority {
            (
                PRIORITY_HEARTBEAT.min(self.heartbeat),
                self.max_staleness
                    .unwrap_or(DEFAULT_MAX_STALENESS)
                    .min(PRIORITY_MAX_STALENESS),
            )
        } else {
            (
                self.heartbeat,
                self.max_staleness.unwrap_or(DEFAULT_MAX_STALENESS),
            )
        };
        let leader_contact = self.leader_contact.clone();
        let node_id = self.node_id;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<pb::raft::FeedMessage, Status>>(4);

        tokio::spawn(async move {
            use pb::raft::feed_message::Message;
            let send = |m: Message| {
                let tx = tx.clone();
                async move {
                    tx.send(Ok(pb::raft::FeedMessage { message: Some(m) }))
                        .await
                        .is_ok()
                }
            };
            let fail = |s: Status| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(Err(s)).await;
                }
            };
            let mut last_head: Option<std::time::Instant> = None;
            let mut stream_epoch: Option<u64> = None;
            let mut scanned: Option<FeedCursor> = None;
            loop {
                // Read on every pass, so a revoked grant ends the stream
                // within one poll and a new one takes effect without a
                // resubscription.
                // The reads are blocking disk reads, so they leave the async
                // workers alone.
                let pass = {
                    let sm = sm.clone();
                    let identity = identity.clone();
                    tokio::task::spawn_blocking(move || {
                        Ok::<_, crate::error::StoreError>((
                            sm.feed_grants(&identity)?,
                            sm.feed_epoch()?.unwrap_or(0),
                            sm.feed_floor_in(class)?,
                        ))
                    })
                    .await
                };
                let (grants, epoch, floor) = match pass {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => return fail(Status::internal(e.to_string())).await,
                    Err(e) => return fail(Status::internal(e.to_string())).await,
                };
                if grants.is_empty() {
                    return fail(Status::permission_denied(
                        "the feed grants of this identity were revoked",
                    ))
                    .await;
                }
                // The epoch a stream runs in is the one the consumer's cursor
                // belongs to, or the current one for a fresh subscription.
                let expected = *stream_epoch.get_or_insert(if req_has_cursor {
                    requested_epoch
                } else {
                    epoch
                });
                // A fresh subscription that began before the first event adopts
                // the epoch that event creates.
                if !req_has_cursor && expected == 0 {
                    stream_epoch = Some(epoch);
                }
                let expected = stream_epoch.unwrap_or(expected);
                let epoch_changed = epoch != 0 && expected != epoch;
                // A cursor on the last pruned index also resets: prune cuts at
                // whole log indexes, so a later position of that index may be
                // gone with it.
                let below_floor = cursor.is_some_and(|c| c.index < floor);
                if epoch_changed || below_floor {
                    let reason = if epoch_changed {
                        "the feed epoch changed"
                    } else {
                        "the cursor is older than the oldest retained event"
                    };
                    let _ = send(Message::Reset(pb::raft::FeedReset {
                        epoch,
                        floor,
                        reason: reason.to_owned(),
                    }))
                    .await;
                    return;
                }
                let age = if raft.metrics().borrow_watched().current_leader == Some(node_id) {
                    Some(Duration::ZERO)
                } else {
                    leader_contact.age()
                };
                // Fail closed: a voter that never heard from a leader, or lost
                // it for too long, may miss a revoked grant, so it must not
                // keep serving. The bound applies even when local reads have
                // none configured.
                if age.is_none_or(|age| age > limit) {
                    return fail(Status::unavailable(
                        "this voter has lost contact with the leader for longer than the \
                         staleness bound",
                    ))
                    .await;
                }
                // The epoch and floor can change between the check above and
                // the batch read: a restore, an emergency rotation or a prune
                // may land in between. Read them again after the batch, and if
                // either moved, the batch belongs to no consistent view, so
                // the consumer reloads. A read that fails because the events
                // went away is treated the same way.
                let read = {
                    let sm = sm.clone();
                    tokio::task::spawn_blocking(move || {
                        let batch = sm.outbox_events_after_in(class, cursor, BATCH);
                        let epoch = sm.feed_epoch()?.unwrap_or(0);
                        let floor = sm.feed_floor_in(class)?;
                        Ok::<_, crate::error::StoreError>((batch, epoch, floor))
                    })
                    .await
                };
                let (batch, epoch_after, floor_after) = match read {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => return fail(Status::internal(e.to_string())).await,
                    Err(e) => return fail(Status::internal(e.to_string())).await,
                };
                if epoch_after != epoch || floor_after != floor {
                    let _ = send(Message::Reset(pb::raft::FeedReset {
                        epoch: epoch_after,
                        floor: floor_after,
                        reason: "the feed changed while it was being read".to_owned(),
                    }))
                    .await;
                    return;
                }
                let batch = match batch {
                    Ok(b) => b,
                    Err(e) => return fail(Status::internal(e.to_string())).await,
                };
                if let Some((last, _)) = batch.last() {
                    let last = *last;
                    scanned = Some(last);
                    let events: Vec<_> = batch
                        .into_iter()
                        .filter(|(_, e)| wanted(e, &grants, &filter))
                        .map(|(c, e)| to_pb(c, e))
                        .collect();
                    cursor = Some(last);
                    if !events.is_empty()
                        && !send(Message::Events(pb::raft::FeedEvents {
                            epoch,
                            events,
                            scanned_index: last.index,
                            scanned_position: u32::from(last.position),
                        }))
                        .await
                    {
                        return;
                    }
                    continue;
                }
                if last_head.is_none_or(|t| t.elapsed() >= heartbeat) {
                    last_head = Some(std::time::Instant::now());
                    let applied = raft
                        .metrics()
                        .borrow_watched()
                        .last_applied
                        .map(|l| l.index)
                        .unwrap_or(0);
                    let head = pb::raft::FeedHead {
                        epoch,
                        applied_index: applied,
                        leader_contact_age_ms: age.map_or(u64::MAX, |a| {
                            u64::try_from(a.as_millis()).unwrap_or(u64::MAX)
                        }),
                        has_scanned: scanned.is_some(),
                        scanned_index: scanned.map_or(0, |c| c.index),
                        scanned_position: scanned.map_or(0, |c| u32::from(c.position)),
                    };
                    if !send(Message::Head(head)).await {
                        return;
                    }
                }
                tokio::time::sleep(POLL).await;
            }
        });

        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn event(kind: &str, domain: Option<&str>) -> OutboxEvent {
        OutboxEvent {
            kind: kind.into(),
            domain_id: domain.map(str::to_owned),
            key: vec![],
            op: openstack_keystone_storage_api::FeedOp::Set,
            value: None,
        }
    }

    fn grants(rows: &[(&str, Option<&[&str]>)]) -> FeedGrants {
        rows.iter()
            .map(|(k, d)| {
                (
                    k.to_string(),
                    d.map(|d| d.iter().map(|s| s.to_string()).collect()),
                )
            })
            .collect()
    }

    #[test]
    fn grants_decide_kind_and_domain() {
        let g = grants(&[("registry", Some(&["d1"])), ("revocation", None)]);
        let f = Filter::default();
        assert!(wanted(&event("registry", Some("d1")), &g, &f));
        assert!(!wanted(&event("registry", Some("d2")), &g, &f));
        assert!(wanted(&event("revocation", Some("d9")), &g, &f));
        assert!(!wanted(&event("other", Some("d1")), &g, &f));
    }

    #[test]
    fn a_request_narrows_and_never_widens() {
        let g = grants(&[("registry", Some(&["d1"])), ("revocation", None)]);
        let ask = |kinds: &[&str], domains: &[&str]| Filter {
            kinds: strings(kinds),
            domains: strings(domains),
        };
        // Asking for a domain that is not granted yields nothing.
        assert!(!wanted(
            &event("registry", Some("d2")),
            &g,
            &ask(&["registry"], &["d1", "d2"])
        ));
        // Asking for a kind narrows the grants.
        assert!(!wanted(
            &event("revocation", Some("d1")),
            &g,
            &ask(&["registry"], &[])
        ));
        // A grant for every domain still honors the requested domains.
        assert!(wanted(
            &event("revocation", Some("d1")),
            &g,
            &ask(&[], &["d1"])
        ));
        assert!(!wanted(
            &event("revocation", Some("d2")),
            &g,
            &ask(&[], &["d1"])
        ));
    }

    #[test]
    fn events_without_a_domain_reach_only_unrestricted_grants() {
        let g = grants(&[("registry", Some(&["d1"])), ("revocation", None)]);
        let f = Filter::default();
        assert!(!wanted(&event("registry", None), &g, &f));
        assert!(wanted(&event("revocation", None), &g, &f));
        // A request that names domains excludes them again.
        let named = Filter {
            domains: strings(&["d1"]),
            ..Default::default()
        };
        assert!(!wanted(&event("revocation", None), &g, &named));
    }
}
