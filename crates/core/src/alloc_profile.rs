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
//! # Allocation profiling of the request hot paths (test only)
//!
//! Installs the counting allocator for the unit tests of this crate. The
//! `alloc_profile` test modules next to the code they measure (token
//! validation, catalog) count the allocations of every stage of a request and
//! check them against a budget, so a change that adds copies to a hot path
//! fails a test instead of showing up later as a latency regression.
//!
//! Print the figures with:
//!
//! ```text
//! cargo test -p openstack-keystone-core alloc_profile -- --nocapture
//! ```
//!
//! The counters are per thread, see `openstack_keystone_alloc_profile`.
//! Dependencies are mocked, so the figures cover the code of the provider
//! itself plus what the mocks return, which is constant across changes.

use openstack_keystone_alloc_profile::CountingAlloc;
pub(crate) use openstack_keystone_alloc_profile::{AllocStats, measure, measure_async};

#[global_allocator]
static ALLOCATOR: CountingAlloc = CountingAlloc;

/// Silence `tracing` on the current thread for as long as the guard lives.
///
/// Other tests of this crate install a global subscriber that records the
/// spans and events of whatever runs in the process, which costs allocations
/// that depend on the tests that happened to run before. Production does not
/// record the debug spans of the providers either, so measure without.
pub(crate) fn quiet_tracing() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default())
}

/// Print the figures of a stage.
pub(crate) fn report(label: &str, stats: &AllocStats) {
    eprintln!("ALLOC {label:<46} {stats}");
}

/// Fail when a stage needs more allocations than its budget allows.
///
/// A budget is the measured value plus a small margin; lower it when a stage
/// gets cheaper.
#[track_caller]
pub(crate) fn assert_budget(label: &str, stats: &AllocStats, max_allocs: u64) {
    report(label, stats);
    assert!(
        stats.allocs <= max_allocs,
        "{label}: {} allocations, budget is {max_allocs}",
        stats.allocs
    );
}
