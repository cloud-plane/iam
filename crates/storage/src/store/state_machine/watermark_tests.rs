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

use futures::stream;
use openraft::storage::RaftStateMachine;

use super::watermark::{WATERMARK_PREFIX, watermark_key};
use super::*;
use crate::store_command::{MutationInner, StoreCommand};

/// Applies one transaction as log entry `index` through the real `apply()`.
fn apply_tx(sm: &FjallStateMachine, index: u64, muts: Vec<MutationInner>) {
    let cmd = StoreCommand::Transaction(muts);
    let entry = crate::pb::raft::Entry {
        term: 1,
        index,
        membership: None,
        app_data: Some(cmd.pack().expect("pack")),
    };
    let mut handle = Arc::new(sm.clone());
    block_on(handle.apply(stream::iter(vec![Ok((entry, None))]))).expect("apply");
}

fn remove(keyspace: &str, key: u8) -> MutationInner {
    MutationInner::Remove {
        key: vec![key],
        keyspace: keyspace.to_string(),
        expected_revision: None,
    }
}

fn row(sm: &FjallStateMachine, keyspace: &str) -> Option<u64> {
    sm.meta
        .get(watermark_key(keyspace))
        .expect("read row")
        .map(|v| u64::from_be_bytes(v.as_ref().try_into().expect("8 bytes")))
}

#[test]
fn apply_bumps_every_touched_keyspace_and_only_those() {
    let (sm, _td) = make_seeded_sm(0x0a);
    apply_tx(&sm, 5, vec![remove("a", 1)]);
    apply_tx(&sm, 6, vec![remove("b", 1), remove("a", 2)]);
    apply_tx(&sm, 7, vec![MutationInner::SetIndex { key: vec![9] }]);

    assert_eq!(sm.watermarks.get("a"), 6);
    assert_eq!(sm.watermarks.get("b"), 6);
    assert_eq!(sm.watermarks.get("meta:a"), 6);
    assert_eq!(sm.watermarks.get("meta:b"), 6);
    assert_eq!(sm.watermarks.get("index"), 7);
    assert_eq!(sm.watermarks.get("untouched"), 0);
    // The persisted rows agree with memory.
    assert_eq!(row(&sm, "a"), Some(6));
    assert_eq!(row(&sm, "b"), Some(6));
    assert_eq!(row(&sm, "index"), Some(7));
    assert_eq!(row(&sm, "untouched"), None);
}

#[test]
fn watermarks_survive_a_reload_from_meta() {
    let (sm, _td) = make_seeded_sm(0x0a);
    apply_tx(&sm, 3, vec![remove("a", 1)]);
    let reloaded = super::watermark::AppliedWatermarks::from_meta(&sm.meta, 3).expect("load");
    assert_eq!(reloaded.get("a"), 3);
    assert_eq!(reloaded.get("b"), 0);
}

#[test]
fn node_without_rows_floors_at_last_applied() {
    let (sm, _td) = make_seeded_sm(0x0a);
    // A node from before watermarks: no rows and no floor row.
    sm.meta.remove(super::watermark::FLOOR_KEY).expect("remove");
    let w = super::watermark::AppliedWatermarks::from_meta(&sm.meta, 50).expect("load");
    assert_eq!(w.get("anything"), 50);
    // The floor is persisted, so a later reload keeps it once rows exist.
    apply_tx(&sm, 60, vec![remove("a", 1)]);
    let again = super::watermark::AppliedWatermarks::from_meta(&sm.meta, 60).expect("load");
    assert_eq!(again.get("untouched"), 50);
    assert_eq!(again.get("a"), 60);
}

#[test]
fn missing_floor_with_rows_floors_at_last_applied() {
    let (sm, _td) = make_seeded_sm(0x0a);
    apply_tx(&sm, 3, vec![remove("a", 1)]);
    sm.meta.remove(super::watermark::FLOOR_KEY).expect("remove");
    let w = super::watermark::AppliedWatermarks::from_meta(&sm.meta, 40).expect("load");
    assert_eq!(w.get("a"), 40);
    assert_eq!(w.get("untouched"), 40);
}

#[test]
fn floor_survives_a_reload() {
    let (sm, _td) = make_seeded_sm(0x0a);
    sm.meta
        .insert(super::watermark::FLOOR_KEY, super::watermark::encode(100))
        .expect("write floor");
    let reloaded = super::watermark::AppliedWatermarks::from_meta(&sm.meta, 0).expect("load");
    assert_eq!(reloaded.get("never-written"), 100);
}

#[test]
fn rejected_transaction_does_not_move_a_watermark() {
    let (sm, _td) = make_seeded_sm(0x0a);
    // `meta` is reserved: apply() reports a violation and commits nothing.
    apply_tx(&sm, 4, vec![remove("meta", 1)]);
    assert_eq!(sm.watermarks.get("meta:meta"), 0);
    assert_eq!(row(&sm, "meta:meta"), None);
}

#[test]
fn watermark_rows_do_not_collide_with_record_metadata() {
    assert!(!WATERMARK_PREFIX.as_bytes().contains(&0u8));
}
