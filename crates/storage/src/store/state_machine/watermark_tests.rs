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

/// Applies any command as log entry `index` through the real `apply()`.
fn apply_cmd(sm: &FjallStateMachine, index: u64, cmd: StoreCommand) {
    let entry = crate::pb::raft::Entry {
        term: 1,
        index,
        membership: None,
        app_data: Some(cmd.pack().expect("pack")),
    };
    let mut handle = Arc::new(sm.clone());
    block_on(handle.apply(stream::iter(vec![Ok((entry, None))]))).expect("apply");
}

fn set(keyspace: &str, key: u8, metadata: Metadata) -> MutationInner {
    MutationInner::Set {
        cipher: b"value".to_vec(),
        expected_revision: None,
        key: vec![key],
        keyspace: keyspace.to_string(),
        metadata,
        tier: DataTier::Internal as u8,
    }
}

fn create_if_absent(keyspace: &str, key: u8) -> MutationInner {
    MutationInner::CreateIfAbsent {
        cipher: b"value".to_vec(),
        key: vec![key],
        keyspace: keyspace.to_string(),
        metadata: Metadata::with_tier(DataTier::Internal),
        tier: DataTier::Internal as u8,
    }
}

#[test]
fn set_bumps_its_keyspace_and_its_record_metadata() {
    let (sm, _td) = make_seeded_sm(0x0a);
    apply_tx(
        &sm,
        5,
        vec![set("ks", 1, Metadata::with_tier(DataTier::Internal))],
    );
    assert_eq!(sm.watermarks.get("ks"), 5);
    assert_eq!(sm.watermarks.get("meta:ks"), 5);
    assert_eq!(row(&sm, "ks"), Some(5));
    assert_eq!(row(&sm, "meta:ks"), Some(5));
    assert_eq!(sm.watermarks.get("other"), 0);
}

#[test]
fn create_if_absent_bumps_only_when_it_creates() {
    let (sm, _td) = make_seeded_sm(0x0a);
    apply_tx(&sm, 5, vec![create_if_absent("ks", 1)]);
    assert_eq!(sm.watermarks.get("ks"), 5);
    // The key exists now: the transaction is rejected and moves nothing,
    // not even for the other keyspace in the same transaction.
    apply_tx(
        &sm,
        6,
        vec![create_if_absent("other", 2), create_if_absent("ks", 1)],
    );
    assert_eq!(sm.watermarks.get("ks"), 5);
    assert_eq!(sm.watermarks.get("other"), 0);
    assert_eq!(row(&sm, "other"), None);
}

#[test]
fn ephemeral_set_bumps_its_keyspace() {
    let (sm, _td) = make_seeded_sm(0x0a);
    // The in-memory ephemeral map is not shared between clones, so apply on
    // the handle that is then inspected.
    let mut handle = Arc::new(sm);
    let cmd = StoreCommand::Transaction(vec![set("eph", 1, Metadata::ephemeral())]);
    let entry = crate::pb::raft::Entry {
        term: 1,
        index: 5,
        membership: None,
        app_data: Some(cmd.pack().expect("pack")),
    };
    block_on(handle.apply(stream::iter(vec![Ok((entry, None))]))).expect("apply");
    assert!(handle.is_ephemeral_keyspace("eph"));
    assert_eq!(handle.watermarks.get("eph"), 5);
    assert_eq!(row(&handle, "eph"), Some(5));
}

#[test]
fn drop_keyspace_bumps_the_dropped_keyspace() {
    let (sm, _td) = make_seeded_sm(0x0a);
    let name = format!(
        "{}probe_7",
        super::keyspace_drop::SINGLE_USE_KEYSPACE_PREFIX
    );
    assert!(super::keyspace_drop::keyspace_drop_allowed(&name));
    apply_tx(
        &sm,
        5,
        vec![set(&name, 1, Metadata::with_tier(DataTier::Internal))],
    );
    assert_eq!(sm.watermarks.get(&name), 5);
    apply_tx(
        &sm,
        6,
        vec![MutationInner::DropKeyspace {
            keyspace: name.clone(),
        }],
    );
    assert!(!sm.keyspace_exists(&name), "the keyspace must be gone");
    assert_eq!(sm.watermarks.get(&name), 6);
    assert_eq!(row(&sm, &name), Some(6));
}

#[test]
fn refused_drop_keyspace_moves_nothing() {
    let (sm, _td) = make_seeded_sm(0x0a);
    apply_tx(
        &sm,
        5,
        vec![set("ks", 1, Metadata::with_tier(DataTier::Internal))],
    );
    apply_tx(
        &sm,
        6,
        vec![MutationInner::DropKeyspace {
            keyspace: "ks".to_string(),
        }],
    );
    assert!(sm.keyspace_exists("ks"));
    assert_eq!(sm.watermarks.get("ks"), 5);
}

#[test]
fn restore_apply_raises_the_floor_for_every_keyspace() {
    let (source, _td1) = make_seeded_sm(0x21);
    let mut source = Arc::new(source);
    block_on(async { source.build_snapshot().await.expect("build") });
    let blob = std::fs::read(
        source
            .latest_snapshot_path()
            .expect("lookup")
            .expect("some"),
    )
    .expect("read backup");

    let (target, _td2) = make_seeded_sm(0x77);
    let chunks: Vec<&[u8]> = blob.chunks(blob.len() / 3 + 1).collect();
    for (seq, chunk) in chunks.iter().enumerate() {
        apply_cmd(
            &target,
            10 + seq as u64,
            StoreCommand::RestoreChunk {
                restore_id: "r1".to_string(),
                seq: seq as u32,
                data: chunk.to_vec(),
            },
        );
    }
    assert_eq!(target.watermarks.get("never-written"), 0);
    let apply_at = 10 + chunks.len() as u64;
    apply_cmd(
        &target,
        apply_at,
        StoreCommand::RestoreApply {
            restore_id: "r1".to_string(),
            chunks: chunks.len() as u32,
            total_len: blob.len() as u64,
        },
    );
    assert_eq!(target.watermarks.get("never-written"), apply_at);
    let reloaded =
        super::watermark::AppliedWatermarks::from_meta(&target.meta, apply_at).expect("load");
    assert_eq!(reloaded.get("never-written"), apply_at);
}

#[test]
fn rejected_restore_does_not_raise_the_floor() {
    let (target, _td) = make_seeded_sm(0x0a);
    apply_cmd(
        &target,
        3,
        StoreCommand::RestoreChunk {
            restore_id: "r1".to_string(),
            seq: 0,
            data: b"not a backup".to_vec(),
        },
    );
    apply_cmd(
        &target,
        4,
        StoreCommand::RestoreApply {
            restore_id: "r1".to_string(),
            chunks: 1,
            total_len: 12,
        },
    );
    assert_eq!(target.watermarks.get("never-written"), 0);
}

#[test]
fn install_snapshot_raises_the_floor_to_the_snapshot_index() {
    let (leader, _td1) = make_seeded_sm(0x21);
    apply_tx(&leader, 7, vec![remove("a", 1)]);
    let mut leader = Arc::new(leader);
    let snapshot = block_on(async { leader.build_snapshot().await.expect("build") });
    assert_eq!(
        snapshot.meta.last_log_id.as_ref().map(|l| l.index()),
        Some(7)
    );

    let (follower, _td2) = make_seeded_sm(0x21);
    let mut follower = Arc::new(follower);
    assert_eq!(follower.watermarks.get("anything"), 0);
    block_on(async {
        follower
            .install_snapshot(&snapshot.meta, snapshot.snapshot)
            .await
            .expect("install")
    });
    assert_eq!(follower.watermarks.get("anything"), 7);
    assert_eq!(follower.watermarks.get("a"), 7);
}
