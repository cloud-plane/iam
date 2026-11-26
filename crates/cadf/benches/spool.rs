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
//! Cost of the audit path: dispatcher, critical channel and spool writer.
//!
//! ADR 0023 promises a sub-millisecond provider call: a critical event is
//! queued in memory and written to the spool in the background. These
//! benchmarks check the promise on a real file system (the spool lives under
//! `AUDIT_BENCH_DIR`, default the system temp dir; point it at the disk the
//! service spool uses, a tmpfs hides the fsync):
//!
//! - `critical_only`: `C` concurrent callers send critical events (the two
//!   `audited_op!` events of a write) into the writer. Time covers the
//!   callers and the writer finishing the spool, so it is the sustained
//!   events/s the writer can take.
//! - `critical_with_perimeter`: the same while a flood of perimeter events
//!   (token validations) goes through the same writer.
//!
//! Besides the criterion numbers every scenario prints the per-call latency
//! of `dispatch_critical` (p50/p99/max) and the deepest critical queue
//! seen, which is what a request waits for.
//!
//! ```text
//! AUDIT_BENCH_DIR=/var/log/keystone cargo bench -p cadf --bench spool
//! ```

#![allow(clippy::expect_used, clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use cadf::SpoolConfig;
use cadf::dispatcher::AuditDispatcher;
use cadf::spool::{run_spool_writer, start_spool_writer};
use cadf::types::{CadfEvent, CadfEventPayload, Initiator, Observer, Target};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::runtime::Runtime;

/// Critical events per scenario iteration unit.
const CRITICAL_EVENTS: u64 = 2_000;

fn base_dir() -> PathBuf {
    std::env::var_os("AUDIT_BENCH_DIR").map_or_else(std::env::temp_dir, PathBuf::from)
}

fn template(dispatcher: &AuditDispatcher, action: &str) -> CadfEvent {
    CadfEventPayload::new(
        format!("{}:{}", dispatcher.node_id(), uuid_like(action)),
        "1.1".to_string(),
        "7d9a1f1c-3a53-4b6c-a9c8-3f3b2a0f3a11".to_string(),
        chrono::Utc::now().to_rfc3339(),
        action.to_string(),
        cadf::types::Outcome::Success,
        None,
        Initiator::new("user-id".to_string(), None, None, None),
        Target::new("project-id", "data/security/project"),
        Observer::new(
            dispatcher.node_id(),
            format!("service/security/keystone/{}", dispatcher.node_id()),
        ),
    )
    .sign(dispatcher)
}

fn uuid_like(seed: &str) -> String {
    format!("{seed}-0000")
}

struct Outcome {
    elapsed: Duration,
    latencies: Vec<Duration>,
    max_depth: usize,
}

/// One run: `callers` tasks send `events` critical events in total while
/// `flood` perimeter producers push as fast as the channel takes them.
fn run(rt: &Runtime, callers: usize, events: u64, flood: usize) -> Outcome {
    let dir = tempfile::tempdir_in(base_dir()).expect("spool dir");
    let path = dir.path().to_path_buf();
    rt.block_on(async move {
        let (dispatcher, receivers) = AuditDispatcher::new(
            "bench-node",
            "boot".to_string(),
            Arc::from(&b"0123456789abcdef0123456789abcdef"[..]),
            1,
        );
        let bytes = Arc::new(AtomicU64::new(0));
        let writer = start_spool_writer(
            path,
            "bench-node".to_string(),
            SpoolConfig::default(),
            bytes,
        )
        .expect("spool opens");
        let writer_task = tokio::spawn(run_spool_writer(
            receivers.perimeter,
            receivers.critical,
            writer,
            std::future::pending(),
        ));

        let stop = Arc::new(AtomicBool::new(false));
        let mut floods = Vec::new();
        for _ in 0..flood {
            let dispatcher = Arc::clone(&dispatcher);
            let stop = Arc::clone(&stop);
            let event = template(&dispatcher, "authenticate");
            floods.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    dispatcher.dispatch(event.clone());
                    tokio::task::yield_now().await;
                }
            }));
        }

        let max_depth = Arc::new(AtomicU64::new(0));
        let sampler = {
            let dispatcher = Arc::clone(&dispatcher);
            let stop = Arc::clone(&stop);
            let max_depth = Arc::clone(&max_depth);
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let (_, critical) = dispatcher.channel_depths();
                    max_depth.fetch_max(critical as u64, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };

        let per_caller = events / callers as u64;
        let started = Instant::now();
        let mut senders = Vec::new();
        for _ in 0..callers {
            let dispatcher = Arc::clone(&dispatcher);
            let event = template(&dispatcher, "create/project");
            senders.push(tokio::spawn(async move {
                let mut latencies = Vec::with_capacity(per_caller as usize);
                for _ in 0..per_caller {
                    let call = Instant::now();
                    dispatcher
                        .dispatch_critical(event.clone())
                        .await
                        .expect("writer alive");
                    latencies.push(call.elapsed());
                }
                latencies
            }));
        }
        let mut latencies = Vec::new();
        for sender in senders {
            latencies.extend(sender.await.expect("sender"));
        }
        stop.store(true, Ordering::Relaxed);
        for flood in floods {
            let _ = flood.await;
        }
        let _ = sampler.await;
        // Close the channels: the writer drains what is queued and ends.
        drop(dispatcher);
        writer_task.await.expect("writer");
        Outcome {
            elapsed: started.elapsed(),
            latencies,
            max_depth: max_depth.load(Ordering::Relaxed) as usize,
        }
    })
}

fn report(name: &str, callers: usize, outcome: &mut Outcome) {
    outcome.latencies.sort_unstable();
    let at = |q: f64| {
        let i = ((outcome.latencies.len() as f64 * q) as usize).min(outcome.latencies.len() - 1);
        outcome.latencies[i]
    };
    eprintln!(
        "{name} callers={callers}: {:.0} events/s, dispatch_critical p50={:?} p99={:?} max={:?}, max critical depth={}",
        outcome.latencies.len() as f64 / outcome.elapsed.as_secs_f64(),
        at(0.5),
        at(0.99),
        at(1.0),
        outcome.max_depth,
    );
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");
    for (name, flood) in [("critical_only", 0), ("critical_with_perimeter", 2)] {
        let mut g = c.benchmark_group(name);
        g.sample_size(10);
        g.throughput(Throughput::Elements(CRITICAL_EVENTS));
        for callers in [1usize, 16, 128] {
            g.bench_with_input(
                BenchmarkId::from_parameter(callers),
                &callers,
                |b, &callers| {
                    let mut last = None;
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let outcome = run(&rt, callers, CRITICAL_EVENTS, flood);
                            total += outcome.elapsed;
                            last = Some(outcome);
                        }
                        total
                    });
                    if let Some(mut outcome) = last {
                        report(name, callers, &mut outcome);
                    }
                },
            );
        }
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
