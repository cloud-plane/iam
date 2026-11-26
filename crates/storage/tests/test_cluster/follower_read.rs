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
//! Follower-served linearizable reads (ADR 0048).

use super::harness::*;
use super::*;
use crate::common::make_sensitive_env;

const FOLLOWER_READ_PORT_BASE: u16 = 2450;

/// With `follower_linearizable_reads` a follower answers a linearizable read
/// itself once its copy is current, and never returns a value older than the
/// acknowledged write.
#[serial_test::serial]
#[test]
fn test_follower_serves_linearizable_reads_after_acknowledged_writes() {
    TypeConfig::run(test_follower_serves_inner()).unwrap();
}

async fn test_follower_serves_inner() -> Result<()> {
    let nodes = start_three_node_cluster_with(FOLLOWER_READ_PORT_BASE, |config| {
        config.follower_linearizable_reads = true;
    })
    .await?;

    let leader_id = nodes[0]
        .storage()
        .current_leader()
        .ok_or_else(|| eyre::eyre!("no leader"))?;
    let leader = nodes
        .iter()
        .map(|n| n.storage().clone())
        .find(|s| s.node_id() == leader_id)
        .ok_or_else(|| eyre::eyre!("leader not among the nodes"))?;
    let follower = nodes
        .iter()
        .map(|n| n.storage().clone())
        .find(|s| s.node_id() != leader_id)
        .ok_or_else(|| eyre::eyre!("no follower"))?;

    // Read-your-writes through the follower, right after each write.
    for i in 0..20 {
        let key = format!("k{i}");
        let value = format!("v{i}");
        set_value_retrying(&leader, &key, &value).await?;
        let got = get_by_key_retrying(&follower, key.as_bytes(), None)
            .await?
            .ok_or_else(|| eyre::eyre!("follower lost the acknowledged write {key}"))?;
        assert_eq!(value, got.try_deserialize::<String>()?.data);
    }

    // A Tier 3 record is read through the follower as well.
    leader
        .set_value(
            "sec:a".to_string(),
            make_sensitive_env("secret-a")?,
            None,
            None,
        )
        .await?;
    let got = get_by_key_retrying(&follower, b"sec:a", None)
        .await?
        .ok_or_else(|| eyre::eyre!("follower lost the sensitive record"))?;
    assert_eq!("secret-a", got.try_deserialize::<String>()?.data);

    // Once the writes stopped the follower catches up and serves reads itself.
    let metrics = follower.state_machine_store().raft_prometheus_metrics();
    let before = metrics.follower_reads_served_total.get();
    for _ in 0..10 {
        assert!(
            get_by_key_retrying(&follower, b"k0", None).await?.is_some(),
            "follower lost k0"
        );
    }
    assert!(
        metrics.follower_reads_served_total.get() > before,
        "the follower never served a read from its own copy"
    );
    Ok(())
}

const FOLLOWER_FAILOVER_PORT_BASE: u16 = 2500;

/// Kill the leader while it takes writes. Whichever survivor leads, no
/// replica may serve a value older than an acknowledged write, and a new
/// write on the new leader must be visible on the other survivor at once.
#[serial_test::serial]
#[test]
fn test_follower_reads_never_older_than_acknowledged_writes_across_failover() {
    TypeConfig::run(test_follower_failover_inner()).unwrap();
}

async fn test_follower_failover_inner() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut nodes = start_three_node_cluster_with(FOLLOWER_FAILOVER_PORT_BASE, |config| {
        config.follower_linearizable_reads = true;
    })
    .await?;

    let old_leader = nodes[0].storage().clone();
    let stop = Arc::new(AtomicBool::new(false));
    let acked: Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::default();
    let writers: Vec<_> = (0..4)
        .map(|w| {
            let target = old_leader.clone();
            let stop = stop.clone();
            let acked = acked.clone();
            tokio::spawn(async move {
                let mut i = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    let key = format!("failover-{w}-{i}");
                    let value = format!("val-{w}-{i}");
                    i += 1;
                    let Ok(env) = make_env(&value) else { return };
                    let res = tokio::time::timeout(
                        Duration::from_secs(5),
                        target.set_value(key.clone(), env, None, None),
                    )
                    .await;
                    // Only a positive acknowledgement is a promise.
                    if let Ok(Ok(_)) = res
                        && let Ok(mut guard) = acked.lock()
                    {
                        guard.push((key, value));
                    }
                }
            })
        })
        .collect();

    TypeConfig::sleep(Duration::from_millis(1500)).await;
    nodes[0].kill().await;
    stop.store(true, Ordering::Relaxed);
    for w in writers {
        let _ = w.await;
    }

    let mut new_leader_id = 0;
    for _ in 0..300 {
        if let Some(l) = nodes[1].storage().current_leader()
            && l != 1
        {
            new_leader_id = l;
            break;
        }
        TypeConfig::sleep(Duration::from_millis(100)).await;
    }
    assert_ne!(0, new_leader_id, "no new leader within 30 seconds");

    let survivors = [nodes[1].storage().clone(), nodes[2].storage().clone()];
    let acked = acked.lock().map(|g| g.clone()).unwrap_or_default();
    assert!(
        !acked.is_empty(),
        "no write was acknowledged before the kill"
    );
    for storage in &survivors {
        for (key, value) in &acked {
            let got = get_by_key_retrying(storage, key.as_bytes(), None)
                .await?
                .ok_or_else(|| eyre::eyre!("survivor lost acknowledged write {key}"))?;
            assert_eq!(*value, got.try_deserialize::<String>()?.data);
        }
    }

    // A new write on the new leader is visible on the other survivor at once.
    let new_leader = survivors
        .iter()
        .find(|s| s.node_id() == new_leader_id)
        .ok_or_else(|| eyre::eyre!("new leader is not a survivor"))?
        .clone();
    let other = survivors
        .iter()
        .find(|s| s.node_id() != new_leader_id)
        .ok_or_else(|| eyre::eyre!("no other survivor"))?
        .clone();
    let (key, _) = &acked[0];
    set_value_retrying(&new_leader, key, "rewritten").await?;
    let got = get_by_key_retrying(&other, key.as_bytes(), None)
        .await?
        .ok_or_else(|| eyre::eyre!("rewritten key vanished"))?;
    assert_eq!("rewritten", got.try_deserialize::<String>()?.data);
    Ok(())
}
