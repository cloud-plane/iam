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

use chrono::Duration;
use openstack_keystone_distributed_storage::mock::MockStorage;

use super::*;

fn create_for_user(user: &str, at: DateTime<Utc>) -> RevocationEventCreate {
    RevocationEventCreate {
        owner_domain_id: Some("d1".into()),
        ..RevocationEventCreate::for_user(user, at)
    }
}

fn token(user: &str, issued: DateTime<Utc>) -> RevocationEventListParameters {
    RevocationEventListParametersBuilder::default()
        .audit_id("audit")
        .issued_before(issued)
        .user_ids(vec![user.to_owned()])
        .build()
        .unwrap()
}

#[tokio::test]
async fn a_user_event_revokes_that_users_older_tokens_only() {
    let storage = MockStorage::default();
    let backend = RaftBackend::default();
    let now = Utc::now();
    RaftBackend::create_impl(&storage, create_for_user("u1", now))
        .await
        .unwrap();

    let old = now - Duration::seconds(10);
    assert!(
        backend
            .is_revoked_impl(&storage, &token("u1", old))
            .await
            .unwrap()
    );
    assert!(
        !backend
            .is_revoked_impl(&storage, &token("u2", old))
            .await
            .unwrap()
    );
    // A token issued after the event is fine.
    assert!(
        !backend
            .is_revoked_impl(&storage, &token("u1", now + Duration::seconds(10)))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_audit_id_event_revokes_one_token() {
    let storage = MockStorage::default();
    let backend = RaftBackend::default();
    let now = Utc::now();
    RaftBackend::create_impl(
        &storage,
        RevocationEventCreate {
            audit_id: Some("audit".into()),
            issued_before: now,
            revoked_at: now,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let params = token("u1", now - Duration::seconds(1));
    assert!(backend.is_revoked_impl(&storage, &params).await.unwrap());
    let mut other = params.clone();
    other.audit_id = Some("another".into());
    assert!(!backend.is_revoked_impl(&storage, &other).await.unwrap());
}

#[tokio::test]
async fn the_check_reloads_only_when_the_keyspace_changed() {
    let storage = MockStorage::default();
    let backend = RaftBackend::default();
    let now = Utc::now();
    let params = token("u1", now - Duration::seconds(10));

    assert!(!backend.is_revoked_impl(&storage, &params).await.unwrap());
    let reads = storage.prefix_reads();
    for _ in 0..5 {
        assert!(!backend.is_revoked_impl(&storage, &params).await.unwrap());
    }
    assert_eq!(reads, storage.prefix_reads(), "served from memory");

    // A new event is seen by the next check.
    RaftBackend::create_impl(&storage, create_for_user("u1", now))
        .await
        .unwrap();
    assert!(backend.is_revoked_impl(&storage, &params).await.unwrap());
    assert!(storage.prefix_reads() > reads);
}

#[tokio::test]
async fn expired_events_are_removed_and_no_longer_revoke() {
    let storage = MockStorage::default();
    storage.enable_feed_kind(FEED_KIND);
    let backend = RaftBackend::default();
    let now = Utc::now();
    RaftBackend::create_impl(&storage, create_for_user("old", now - Duration::hours(3)))
        .await
        .unwrap();
    RaftBackend::create_impl(&storage, create_for_user("new", now))
        .await
        .unwrap();

    let deleted = RaftBackend::delete_expired_impl(&storage, now - Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(1, deleted);
    let before = now - Duration::hours(4);
    assert!(
        !backend
            .is_revoked_impl(&storage, &token("old", before))
            .await
            .unwrap()
    );
    assert!(
        backend
            .is_revoked_impl(&storage, &token("new", before))
            .await
            .unwrap()
    );
    // The removal of the old one is on the feed.
    let removed: Vec<_> = storage
        .emitted()
        .into_iter()
        .filter(|e| e.op == FeedOp::Remove)
        .collect();
    assert_eq!(1, removed.len());
    assert!(removed[0].priority);
}

#[tokio::test]
async fn a_created_event_is_emitted_to_the_priority_outbox() {
    let storage = MockStorage::default();
    storage.enable_feed_kind(FEED_KIND);
    let now = Utc::now();
    RaftBackend::create_impl(&storage, create_for_user("u1", now))
        .await
        .unwrap();
    let emitted = storage.emitted();
    assert_eq!(1, emitted.len());
    let e = &emitted[0];
    assert_eq!(FEED_KIND, e.kind);
    assert_eq!(Some("d1"), e.domain_id.as_deref());
    assert_eq!(FeedOp::Set, e.op);
    assert!(e.priority);
    // The value is the stored record, which a consumer applies as it is.
    let record: EventRecord = rmp_serde::from_slice(e.value.as_deref().unwrap()).unwrap();
    assert_eq!(Some("u1".to_owned()), record.user_id);
    assert_eq!(e.key, record.id.as_bytes());
    assert_eq!(None, record.origin);
}

#[tokio::test]
async fn a_node_without_the_feed_kind_still_revokes() {
    let storage = MockStorage::default();
    let backend = RaftBackend::default();
    let now = Utc::now();
    RaftBackend::create_impl(&storage, create_for_user("u1", now))
        .await
        .unwrap();
    assert!(storage.emitted().is_empty());
    assert!(
        backend
            .is_revoked_impl(&storage, &token("u1", now - Duration::seconds(5)))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_event_without_an_owner_domain_carries_its_scope_domain() {
    let storage = MockStorage::default();
    storage.enable_feed_kind(FEED_KIND);
    let now = Utc::now();
    RaftBackend::create_impl(
        &storage,
        RevocationEventCreate {
            domain_id: Some("scope".into()),
            issued_before: now,
            revoked_at: now,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(Some("scope"), storage.emitted()[0].domain_id.as_deref());
}

#[test]
fn keys_sort_by_time() {
    assert!(key(5, "b") < key(10, "a"));
    assert!(key(99, "a") < key(100, "a"));
}

fn as_feed_event(
    authority_body: Option<&str>,
    record: &EventRecord,
    removed: bool,
) -> FeedEventData {
    let mut record = record.clone();
    record.origin = authority_body.map(str::to_owned);
    FeedEventData {
        index: 1,
        position: 0,
        kind: FEED_KIND.to_owned(),
        domain_id: None,
        key: record.id.as_bytes().to_vec(),
        removed,
        value: (!removed).then(|| rmp_serde::to_vec(&record).unwrap()),
    }
}

fn record_for_user(user: &str, at: DateTime<Utc>) -> EventRecord {
    EventRecord::new(&create_for_user(user, at))
}

async fn apply(storage: &MockStorage, sink: &RevocationFeedSink, event: &FeedEventData) {
    let mutations = sink.mutations(event).unwrap();
    storage.transaction(mutations).await.unwrap();
}

fn issued_by(authority: &str, user: &str, issued: DateTime<Utc>) -> RevocationEventListParameters {
    RevocationEventListParameters {
        issuer: Some(authority.to_owned()),
        ..token(user, issued)
    }
}

#[tokio::test]
async fn a_foreign_event_revokes_only_tokens_of_its_origin() {
    let storage = Arc::new(MockStorage::default());
    let sink = RevocationFeedSink::new("eu", storage.clone());
    let backend = RaftBackend::default();
    let now = Utc::now();
    let old = now - Duration::seconds(10);

    // The body claims a different origin; the subscription decides.
    let event = as_feed_event(Some("us"), &record_for_user("u1", now), false);
    apply(&storage, &sink, &event).await;

    assert!(
        backend
            .is_revoked_impl(&*storage, &issued_by("eu", "u1", old))
            .await
            .unwrap()
    );
    assert!(
        !backend
            .is_revoked_impl(&*storage, &issued_by("us", "u1", old))
            .await
            .unwrap(),
        "the origin named in the body is ignored"
    );
    assert!(
        !backend
            .is_revoked_impl(&*storage, &token("u1", old))
            .await
            .unwrap(),
        "a token of this authority is not revoked by another authority"
    );
}

#[tokio::test]
async fn a_local_event_does_not_revoke_foreign_tokens() {
    let storage = MockStorage::default();
    let backend = RaftBackend::default();
    let now = Utc::now();
    RaftBackend::create_impl(&storage, create_for_user("u1", now))
        .await
        .unwrap();
    let old = now - Duration::seconds(10);
    assert!(
        backend
            .is_revoked_impl(&storage, &token("u1", old))
            .await
            .unwrap()
    );
    assert!(
        !backend
            .is_revoked_impl(&storage, &issued_by("eu", "u1", old))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_replayed_or_removed_foreign_event_is_applied_once() {
    let storage = Arc::new(MockStorage::default());
    let sink = RevocationFeedSink::new("eu", storage.clone());
    let backend = RaftBackend::default();
    let now = Utc::now();
    let old = now - Duration::seconds(10);
    let record = record_for_user("u1", now);
    let set = as_feed_event(None, &record, false);

    apply(&storage, &sink, &set).await;
    apply(&storage, &sink, &set).await;
    assert_eq!(
        1,
        storage
            .prefix(b"", Some(MIRROR_KEYSPACE))
            .await
            .unwrap()
            .len()
    );
    assert!(
        backend
            .is_revoked_impl(&*storage, &issued_by("eu", "u1", old))
            .await
            .unwrap()
    );

    let remove = as_feed_event(None, &record, true);
    apply(&storage, &sink, &remove).await;
    apply(&storage, &sink, &remove).await;
    assert!(
        !backend
            .is_revoked_impl(&*storage, &issued_by("eu", "u1", old))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_reseed_drops_only_that_authoritys_events() {
    let storage = Arc::new(MockStorage::default());
    let eu = RevocationFeedSink::new("eu", storage.clone());
    let us = RevocationFeedSink::new("us", storage.clone());
    let now = Utc::now();
    apply(
        &storage,
        &eu,
        &as_feed_event(None, &record_for_user("u1", now), false),
    )
    .await;
    apply(
        &storage,
        &us,
        &as_feed_event(None, &record_for_user("u2", now), false),
    )
    .await;

    eu.reseed().await.unwrap();
    let keys: Vec<_> = storage
        .prefix(b"", Some(MIRROR_KEYSPACE))
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(1, keys.len());
    assert!(keys[0].starts_with(&mirror_prefix("us")));
}

#[tokio::test]
async fn expiry_also_drops_mirrored_events_of_a_vanished_source() {
    let storage = Arc::new(MockStorage::default());
    let sink = RevocationFeedSink::new("eu", storage.clone());
    let now = Utc::now();
    let old = record_for_user("u1", now - Duration::hours(2));
    let fresh = record_for_user("u2", now);
    apply(&storage, &sink, &as_feed_event(None, &old, false)).await;
    apply(&storage, &sink, &as_feed_event(None, &fresh, false)).await;

    let deleted = RaftBackend::delete_expired_impl(&*storage, now - Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(1, deleted);
    assert_eq!(
        1,
        storage
            .prefix(b"", Some(MIRROR_KEYSPACE))
            .await
            .unwrap()
            .len()
    );
}

#[test]
fn the_consumer_follows_the_priority_stream_of_revocations() {
    let config = feed_consumer_config("eu", "10.0.0.1:8443");
    assert!(config.priority);
    assert_eq!(vec![FEED_KIND.to_owned()], config.kinds);
    assert_eq!("eu", config.name);
}

#[tokio::test]
async fn the_sink_reports_the_freshness_of_its_stream() {
    let storage = Arc::new(MockStorage::default());
    let max = std::time::Duration::from_secs(30);
    let sink = RevocationFeedSink::new("fresh-test", storage.clone());

    // Registered, but nothing arrived yet: stale.
    assert!(STREAM_HEALTH.is_stale(Some("fresh-test"), max));
    sink.on_head();
    assert!(!STREAM_HEALTH.is_stale(Some("fresh-test"), max));
    // A token of this authority is never affected.
    assert!(!STREAM_HEALTH.is_stale(None, max));

    // An event does not: only the heartbeat after it says the stream has
    // caught up.
    let other = RevocationFeedSink::new("fresh-test-2", storage);
    let event = as_feed_event(None, &record_for_user("u1", Utc::now()), false);
    other.mutations(&event).unwrap();
    assert!(STREAM_HEALTH.is_stale(Some("fresh-test-2"), max));
    other.on_head();
    assert!(!STREAM_HEALTH.is_stale(Some("fresh-test-2"), max));
}

#[tokio::test]
async fn the_removal_reaches_the_subscribers_the_set_reached() {
    let storage = MockStorage::default();
    storage.enable_feed_kind(FEED_KIND);
    let now = Utc::now();
    // Owner domain `d1` (see `create_for_user`), scope domain differs.
    RaftBackend::create_impl(
        &storage,
        RevocationEventCreate {
            domain_id: Some("scope".into()),
            ..create_for_user("u1", now - Duration::hours(2))
        },
    )
    .await
    .unwrap();
    RaftBackend::delete_expired_impl(&storage, now - Duration::hours(1))
        .await
        .unwrap();
    let emitted = storage.emitted();
    assert_eq!(2, emitted.len());
    assert_eq!(FeedOp::Remove, emitted[1].op);
    assert_eq!(emitted[0].domain_id, emitted[1].domain_id);
    assert_eq!(Some("d1"), emitted[1].domain_id.as_deref());
}

#[tokio::test]
async fn authorities_with_a_colon_do_not_share_keys() {
    let storage = Arc::new(MockStorage::default());
    let eu = RevocationFeedSink::new("eu", storage.clone());
    let ops = RevocationFeedSink::new("eu:ops", storage.clone());
    let now = Utc::now();
    let record = record_for_user("u1", now);
    apply(&storage, &ops, &as_feed_event(None, &record, false)).await;

    // `eu` sends a removal of a key that looks like one of `eu:ops`.
    let mut forged = as_feed_event(None, &record, true);
    forged.key = format!("ops:{}", record.id).into_bytes();
    apply(&storage, &eu, &forged).await;
    assert_eq!(
        1,
        storage
            .prefix(b"", Some(MIRROR_KEYSPACE))
            .await
            .unwrap()
            .len()
    );

    // A reseed of `eu` leaves `eu:ops` alone.
    eu.reseed().await.unwrap();
    assert_eq!(
        1,
        storage
            .prefix(b"", Some(MIRROR_KEYSPACE))
            .await
            .unwrap()
            .len()
    );
}

#[tokio::test]
async fn expiry_deletes_a_large_backlog_in_chunks() {
    let storage = MockStorage::default();
    storage.enable_feed_kind(FEED_KIND);
    let now = Utc::now();
    let total = DELETE_CHUNK * 2 + 7;
    for i in 0..total {
        RaftBackend::create_impl(
            &storage,
            create_for_user(&format!("u{i}"), now - Duration::hours(2)),
        )
        .await
        .unwrap();
    }
    let deleted = RaftBackend::delete_expired_impl(&storage, now - Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(total as u64, deleted);
    assert!(
        storage
            .prefix(b"", Some(KEYSPACE))
            .await
            .unwrap()
            .is_empty()
    );
}
