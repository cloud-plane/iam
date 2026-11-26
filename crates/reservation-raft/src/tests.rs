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

fn store() -> ReservationStore {
    ReservationStore::new(Arc::new(MockStorage::default()))
}

fn claim(kind: ReservationKind, value: &str, authority: &str) -> Claim {
    Claim {
        kind,
        value: value.into(),
        authority: authority.into(),
        reference: format!("ref-{value}"),
    }
}

#[tokio::test]
async fn a_free_value_is_claimed_pending() {
    let store = store();
    let r = store
        .claim(&claim(ReservationKind::DomainName, "Acme", "eu"))
        .await
        .unwrap();
    assert_eq!(ReservationState::Pending, r.state);
    assert_eq!("eu", r.authority);
}

#[tokio::test]
async fn a_held_value_fails_with_the_holder() {
    let store = store();
    store
        .claim(&claim(ReservationKind::DomainId, "d1", "eu"))
        .await
        .unwrap();
    match store
        .claim(&claim(ReservationKind::DomainId, "d1", "us"))
        .await
    {
        Err(ReservationError::Held(holder)) => assert_eq!("eu", holder.authority),
        other => panic!("expected the holder, got {other:?}"),
    }
}

#[tokio::test]
async fn the_same_claim_again_is_idempotent() {
    let store = store();
    let c = claim(ReservationKind::DomainId, "d1", "eu");
    let first = store.claim(&c).await.unwrap();
    assert_eq!(first, store.claim(&c).await.unwrap());
}

#[tokio::test]
async fn the_same_authority_cannot_take_a_value_for_another_record() {
    let store = store();
    store
        .claim(&claim(ReservationKind::DomainName, "acme", "eu"))
        .await
        .unwrap();
    let other = Claim {
        reference: "another-domain".into(),
        ..claim(ReservationKind::DomainName, "acme", "eu")
    };
    assert!(matches!(
        store.claim(&other).await,
        Err(ReservationError::Held(_))
    ));
}

#[tokio::test]
async fn names_compare_case_insensitively_and_ids_exactly() {
    let store = store();
    store
        .claim(&claim(ReservationKind::DomainName, "Acme", "eu"))
        .await
        .unwrap();
    assert!(matches!(
        store
            .claim(&claim(ReservationKind::DomainName, "ACME", "us"))
            .await,
        Err(ReservationError::Held(_))
    ));
    store
        .claim(&claim(ReservationKind::DomainId, "ABC", "eu"))
        .await
        .unwrap();
    store
        .claim(&claim(ReservationKind::DomainId, "abc", "us"))
        .await
        .unwrap();
}

#[tokio::test]
async fn kinds_do_not_share_values() {
    let store = store();
    store
        .claim(&claim(ReservationKind::DomainName, "x", "eu"))
        .await
        .unwrap();
    store
        .claim(&claim(ReservationKind::RoleName, "x", "us"))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_authority_url_ignores_the_trailing_slash() {
    let store = store();
    store
        .claim(&claim(
            ReservationKind::AuthorityUrl,
            "https://eu.example.com/",
            "eu",
        ))
        .await
        .unwrap();
    assert!(matches!(
        store
            .claim(&claim(
                ReservationKind::AuthorityUrl,
                "https://EU.example.com",
                "us"
            ))
            .await,
        Err(ReservationError::Held(_))
    ));
}

#[tokio::test]
async fn invalid_values_are_refused() {
    let store = store();
    for value in ["", "a\nb", &"x".repeat(MAX_VALUE_LEN + 1)] {
        assert!(matches!(
            store
                .claim(&claim(ReservationKind::DomainName, value, "eu"))
                .await,
            Err(ReservationError::InvalidValue(_))
        ));
    }
}

#[tokio::test]
async fn only_the_holder_confirms_and_releases() {
    let store = store();
    let kind = ReservationKind::DomainName;
    store.claim(&claim(kind, "acme", "eu")).await.unwrap();

    assert!(matches!(
        store.confirm(kind, "acme", "us").await,
        Err(ReservationError::NotHolder(h)) if h == "eu"
    ));
    assert!(matches!(
        store.release(kind, "acme", "us").await,
        Err(ReservationError::NotHolder(_))
    ));

    let confirmed = store.confirm(kind, "acme", "eu").await.unwrap();
    assert_eq!(ReservationState::Confirmed, confirmed.state);
    // Confirming again changes nothing.
    assert_eq!(confirmed, store.confirm(kind, "acme", "eu").await.unwrap());

    store.release(kind, "acme", "eu").await.unwrap();
    assert!(store.get(kind, "acme").await.unwrap().is_none());
    assert!(matches!(
        store.release(kind, "acme", "eu").await,
        Err(ReservationError::NotFound)
    ));
    // The value is free again.
    store.claim(&claim(kind, "acme", "us")).await.unwrap();
}

#[tokio::test]
async fn a_rename_moves_the_reservation() {
    let store = store();
    let kind = ReservationKind::DomainName;
    store.claim(&claim(kind, "old", "eu")).await.unwrap();
    store.confirm(kind, "old", "eu").await.unwrap();

    let renamed = store.rename(kind, "old", "new", "eu").await.unwrap();
    assert_eq!("new", renamed.value);
    assert_eq!(ReservationState::Confirmed, renamed.state);
    assert!(store.get(kind, "old").await.unwrap().is_none());
    assert!(store.get(kind, "new").await.unwrap().is_some());
}

#[tokio::test]
async fn a_rename_to_a_taken_name_keeps_the_old_one() {
    let store = store();
    let kind = ReservationKind::DomainName;
    store.claim(&claim(kind, "old", "eu")).await.unwrap();
    store.claim(&claim(kind, "taken", "us")).await.unwrap();

    assert!(matches!(
        store.rename(kind, "old", "taken", "eu").await,
        Err(ReservationError::Held(h)) if h.authority == "us"
    ));
    assert!(store.get(kind, "old").await.unwrap().is_some());
}

#[tokio::test]
async fn only_the_holder_renames() {
    let store = store();
    let kind = ReservationKind::DomainName;
    store.claim(&claim(kind, "old", "eu")).await.unwrap();
    assert!(matches!(
        store.rename(kind, "old", "new", "us").await,
        Err(ReservationError::NotHolder(_))
    ));
}

#[tokio::test]
async fn a_rename_may_change_only_the_case() {
    let store = store();
    let kind = ReservationKind::DomainName;
    store.claim(&claim(kind, "acme", "eu")).await.unwrap();
    let renamed = store.rename(kind, "acme", "ACME", "eu").await.unwrap();
    assert_eq!("ACME", renamed.value);
    assert_eq!(
        "ACME",
        store.get(kind, "acme").await.unwrap().unwrap().value
    );
}

#[tokio::test]
async fn an_authority_lists_its_own_reservations() {
    let store = store();
    store
        .claim(&claim(ReservationKind::DomainName, "a", "eu"))
        .await
        .unwrap();
    store
        .claim(&claim(ReservationKind::RoleName, "b", "eu"))
        .await
        .unwrap();
    store
        .claim(&claim(ReservationKind::DomainName, "c", "us"))
        .await
        .unwrap();
    assert_eq!(2, store.list_by_authority("eu").await.unwrap().len());
}

/// Records exist for the values in the list.
struct Published(Vec<&'static str>);

#[async_trait]
impl RecordLookup for Published {
    async fn exists(&self, r: &Reservation) -> Result<bool, String> {
        Ok(self.0.contains(&r.value.as_str()))
    }
}

struct Failing;

#[async_trait]
impl RecordLookup for Failing {
    async fn exists(&self, _: &Reservation) -> Result<bool, String> {
        Err("registry unreachable".into())
    }
}

#[tokio::test]
async fn the_reconciler_confirms_published_and_releases_orphans() {
    let store = store();
    let kind = ReservationKind::DomainName;
    store.claim(&claim(kind, "published", "eu")).await.unwrap();
    store.claim(&claim(kind, "orphan", "eu")).await.unwrap();
    store.claim(&claim(kind, "theirs", "us")).await.unwrap();
    let later = now() + 600;

    let report = store
        .reconcile(
            "eu",
            Duration::from_secs(300),
            &Published(vec!["published"]),
            later,
        )
        .await
        .unwrap();

    assert_eq!(
        ReconcileReport {
            confirmed: 1,
            released: 1,
            waiting: 0
        },
        report
    );
    assert_eq!(
        ReservationState::Confirmed,
        store.get(kind, "published").await.unwrap().unwrap().state
    );
    assert!(store.get(kind, "orphan").await.unwrap().is_none());
    // Another authority's claim is not ours to touch.
    assert!(store.get(kind, "theirs").await.unwrap().is_some());
}

#[tokio::test]
async fn a_young_claim_is_left_to_finish_publishing() {
    let store = store();
    let kind = ReservationKind::DomainName;
    store.claim(&claim(kind, "fresh", "eu")).await.unwrap();

    let report = store
        .reconcile("eu", Duration::from_secs(300), &Published(vec![]), now())
        .await
        .unwrap();

    assert_eq!(1, report.waiting);
    assert!(store.get(kind, "fresh").await.unwrap().is_some());
}

#[tokio::test]
async fn a_failed_lookup_keeps_the_claim() {
    let store = store();
    let kind = ReservationKind::DomainName;
    store.claim(&claim(kind, "x", "eu")).await.unwrap();

    let report = store
        .reconcile("eu", Duration::ZERO, &Failing, now() + 1)
        .await
        .unwrap();

    assert_eq!(ReconcileReport::default(), report);
    assert!(store.get(kind, "x").await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_claims_have_one_winner() {
    let store = Arc::new(store());
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .claim(&claim(ReservationKind::DomainId, "d1", &format!("a{i}")))
                    .await
            })
        })
        .collect();
    let mut winners = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => winners += 1,
            Err(ReservationError::Held(_)) => {}
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(1, winners);
}
