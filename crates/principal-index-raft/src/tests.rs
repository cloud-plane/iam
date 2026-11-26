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

use openstack_keystone_distributed_storage::mock::MockStorage;

use super::*;

const ISS: &str = "https://eu.example.com/v4/oauth2/d1";

fn grant(principal: &str, kind: PrincipalKind, grant: &str) -> GrantPointer {
    GrantPointer {
        issuer: ISS.into(),
        principal: principal.into(),
        kind,
        domain_id: "d1".into(),
        grant_id: grant.into(),
    }
}

fn user(principal: &str, grant_id: &str) -> GrantPointer {
    grant(principal, PrincipalKind::User, grant_id)
}

/// The source side: a publisher whose feed kind is enabled.
fn source() -> (Arc<MockStorage>, PointerPublisher) {
    let storage = Arc::new(MockStorage::default());
    storage.enable_feed_kind(FEED_KIND);
    (storage.clone(), PointerPublisher::new(storage))
}

/// The home: an index fed through the sink of `authority`.
struct Home {
    storage: Arc<MockStorage>,
    index: PointerIndex,
}

impl Home {
    fn new() -> Self {
        let storage = Arc::new(MockStorage::default());
        Self {
            index: PointerIndex::new(storage.clone()),
            storage,
        }
    }

    fn sink(&self, authority: &str) -> PointerSink {
        PointerSink::new(
            authority,
            Arc::new(|d: &str| d == "d1"),
            self.storage.clone(),
        )
    }

    /// Delivers what `source` emitted to the sink of `authority`.
    async fn deliver(&self, authority: &str, source: &MockStorage) {
        let sink = self.sink(authority);
        for (i, e) in source.emitted().into_iter().enumerate() {
            let mutations = sink
                .mutations(&FeedEventData {
                    index: i as u64,
                    position: 0,
                    kind: e.kind,
                    domain_id: e.domain_id,
                    key: e.key,
                    removed: e.op == FeedOp::Remove,
                    value: e.value,
                })
                .unwrap();
            if !mutations.is_empty() {
                self.storage.transaction(mutations).await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn a_grant_makes_its_authority_known_at_the_home() {
    let (src, publisher) = source();
    publisher.grant_created(&user("u1", "g1")).await.unwrap();
    let home = Home::new();
    home.deliver("us", &src).await;

    let found = home
        .index
        .authorities_for(ISS, PrincipalKind::User, "u1")
        .await
        .unwrap();
    assert_eq!(BTreeSet::from(["us".to_owned()]), found);
    // Not another principal, nor the group of the same name.
    for (kind, principal) in [(PrincipalKind::User, "u2"), (PrincipalKind::Group, "u1")] {
        assert!(
            home.index
                .authorities_for(ISS, kind, principal)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn the_pointer_stays_until_the_last_grant_is_revoked() {
    let (src, publisher) = source();
    publisher.grant_created(&user("u1", "g1")).await.unwrap();
    publisher.grant_created(&user("u1", "g2")).await.unwrap();
    publisher.grant_revoked(&user("u1", "g1")).await.unwrap();
    let home = Home::new();
    home.deliver("us", &src).await;
    assert_eq!(
        1,
        home.index
            .authorities_for(ISS, PrincipalKind::User, "u1")
            .await
            .unwrap()
            .len()
    );

    publisher.grant_revoked(&user("u1", "g2")).await.unwrap();
    let home = Home::new();
    // A fresh replay of the whole feed leaves nothing.
    home.deliver("us", &src).await;
    assert!(
        home.index
            .authorities_for(ISS, PrincipalKind::User, "u1")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_replayed_event_changes_nothing() {
    let (src, publisher) = source();
    publisher.grant_created(&user("u1", "g1")).await.unwrap();
    let home = Home::new();
    home.deliver("us", &src).await;
    home.deliver("us", &src).await;
    assert_eq!(
        1,
        home.index
            .authorities_for(ISS, PrincipalKind::User, "u1")
            .await
            .unwrap()
            .len()
    );
}

#[tokio::test]
async fn pointers_of_several_authorities_are_kept_apart() {
    let (us, us_pub) = source();
    let (ap, ap_pub) = source();
    us_pub.grant_created(&user("u1", "g1")).await.unwrap();
    ap_pub.grant_created(&user("u1", "g1")).await.unwrap();
    let home = Home::new();
    home.deliver("us", &us).await;
    home.deliver("ap", &ap).await;
    assert_eq!(
        BTreeSet::from(["ap".to_owned(), "us".to_owned()]),
        home.index
            .authorities_for(ISS, PrincipalKind::User, "u1")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_pointer_for_a_foreign_domain_is_dropped() {
    let home = Home::new();
    let sink = home.sink("us");
    let event = FeedEventData {
        index: 1,
        position: 0,
        kind: FEED_KIND.into(),
        domain_id: Some("somebody-elses".into()),
        key: user("u1", "g1").key().into_bytes(),
        removed: false,
        value: Some(Vec::new()),
    };
    assert!(sink.mutations(&event).unwrap().is_empty());
    // Without a domain too.
    let no_domain = FeedEventData {
        domain_id: None,
        ..event
    };
    assert!(sink.mutations(&no_domain).unwrap().is_empty());
}

#[tokio::test]
async fn the_authority_comes_from_the_subscription() {
    let (src, publisher) = source();
    publisher.grant_created(&user("u1", "g1")).await.unwrap();
    let home = Home::new();
    // Whatever the key says, the entry is filed under the subscription.
    home.deliver("mallory", &src).await;
    assert_eq!(
        BTreeSet::from(["mallory".to_owned()]),
        home.index
            .authorities_for(ISS, PrincipalKind::User, "u1")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_reseed_drops_only_the_authority_that_lost_its_cursor() {
    let (us, us_pub) = source();
    let (ap, ap_pub) = source();
    us_pub.grant_created(&user("u1", "g1")).await.unwrap();
    ap_pub.grant_created(&user("u1", "g1")).await.unwrap();
    let home = Home::new();
    home.deliver("us", &us).await;
    home.deliver("ap", &ap).await;

    home.sink("us").reseed().await.unwrap();

    assert_eq!(
        BTreeSet::from(["ap".to_owned()]),
        home.index
            .authorities_for(ISS, PrincipalKind::User, "u1")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_mesh_token_carries_only_the_groups_of_its_audience() {
    let (us, us_pub) = source();
    let (ap, ap_pub) = source();
    us_pub
        .grant_created(&grant("ops", PrincipalKind::Group, "g1"))
        .await
        .unwrap();
    ap_pub
        .grant_created(&grant("dev", PrincipalKind::Group, "g1"))
        .await
        .unwrap();
    let home = Home::new();
    home.deliver("us", &us).await;
    home.deliver("ap", &ap).await;

    let groups = vec!["ops".to_owned(), "dev".to_owned(), "none".to_owned()];
    assert_eq!(
        vec!["ops".to_owned()],
        home.index
            .groups_for_audience(ISS, &groups, "us")
            .await
            .unwrap()
    );
    assert_eq!(
        vec!["dev".to_owned()],
        home.index
            .groups_for_audience(ISS, &groups, "ap")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn the_feed_stays_quiet_when_its_kind_is_off() {
    let storage = Arc::new(MockStorage::default());
    let publisher = PointerPublisher::new(storage.clone());
    publisher.grant_created(&user("u1", "g1")).await.unwrap();
    assert!(storage.emitted().is_empty());
    // The local record is kept for a later reconcile.
    assert_eq!(
        1,
        storage.prefix(b"", Some(OUT_KEYSPACE)).await.unwrap().len()
    );
}

#[tokio::test]
async fn parts_with_the_separator_or_empty_are_refused() {
    let (_, publisher) = source();
    for bad in [
        user("", "g"),
        user("u", ""),
        user("u\u{1f}x", "g"),
        GrantPointer {
            issuer: String::new(),
            ..user("u", "g")
        },
        GrantPointer {
            domain_id: String::new(),
            ..user("u", "g")
        },
    ] {
        assert!(matches!(
            publisher.grant_created(&bad).await,
            Err(PointerError::Invalid(_))
        ));
    }
}

#[tokio::test]
async fn a_reconcile_repairs_the_published_set() {
    let (src, publisher) = source();
    publisher.grant_created(&user("u1", "stale")).await.unwrap();
    publisher.grant_created(&user("u1", "kept")).await.unwrap();

    let (added, removed) = publisher
        .reconcile(&[user("u1", "kept"), user("u2", "missed")])
        .await
        .unwrap();
    assert_eq!((1, 1), (added, removed));

    let home = Home::new();
    home.deliver("us", &src).await;
    assert_eq!(
        1,
        home.index
            .authorities_for(ISS, PrincipalKind::User, "u2")
            .await
            .unwrap()
            .len()
    );
    // A second pass has nothing to do.
    assert_eq!(
        (0, 0),
        publisher
            .reconcile(&[user("u1", "kept"), user("u2", "missed")])
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_issuer_of_another_domain_is_dropped() {
    let home = Home::new();
    let event = FeedEventData {
        index: 1,
        position: 0,
        kind: FEED_KIND.into(),
        domain_id: Some("d1".into()),
        key: GrantPointer {
            issuer: "https://eu.example.com/v4/oauth2/d2".into(),
            ..user("u1", "g1")
        }
        .key()
        .into_bytes(),
        removed: false,
        value: Some(Vec::new()),
    };
    assert!(home.sink("us").mutations(&event).unwrap().is_empty());
}
