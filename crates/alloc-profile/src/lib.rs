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
//! # Allocation counting for tests
//!
//! A counting wrapper around the system allocator, to be installed as the
//! `#[global_allocator]` of a *test* binary, and helpers measuring how many
//! allocations, how many bytes and how much transient memory a piece of code
//! needs.
//!
//! ```ignore
//! use openstack_keystone_alloc_profile::{CountingAlloc, measure};
//!
//! #[global_allocator]
//! static ALLOC: CountingAlloc = CountingAlloc;
//!
//! let (value, stats) = measure(|| work());
//! eprintln!("{stats}");
//! ```
//!
//! The counters are **per thread**: only the allocations made by the thread
//! running the measured code are counted, so tests running in parallel do not
//! disturb each other. Measure async code on a current-thread runtime
//! (`#[tokio::test]` is one), where everything runs on the test thread.
//! Allocations made on other threads (a `spawn_blocking` worker, for
//! example) are not seen.
//!
//! Measurements must not be nested.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fmt;
use std::future::Future;

/// Per-thread counters. Plain `Cell`s without a destructor, const-initialised:
/// accessing them never allocates, which a global allocator must guarantee.
struct Counters {
    /// Number of allocations (including reallocations).
    allocs: Cell<u64>,
    /// Total number of bytes requested.
    bytes: Cell<u64>,
    /// Currently live bytes relative to the thread start.
    live: Cell<i64>,
    /// Highest `live` value since the last reset.
    peak: Cell<i64>,
}

thread_local! {
    static COUNTERS: Counters = const {
        Counters {
            allocs: Cell::new(0),
            bytes: Cell::new(0),
            live: Cell::new(0),
            peak: Cell::new(0),
        }
    };
}

fn on_alloc(size: usize) {
    let _ = COUNTERS.try_with(|c| {
        c.allocs.set(c.allocs.get() + 1);
        c.bytes.set(c.bytes.get() + size as u64);
        let live = c.live.get() + size as i64;
        c.live.set(live);
        if live > c.peak.get() {
            c.peak.set(live);
        }
    });
}

fn on_dealloc(size: usize) {
    let _ = COUNTERS.try_with(|c| c.live.set(c.live.get() - size as i64));
}

/// The system allocator counting the allocations of the calling thread.
pub struct CountingAlloc;

// SAFETY: every call is forwarded unchanged to `System`, which upholds the
// `GlobalAlloc` contract; the bookkeeping only touches thread-local `Cell`s
// and never allocates.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        on_alloc(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        on_alloc(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        on_dealloc(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A reallocation is one allocation of the new size and the release of
        // the old block.
        on_dealloc(layout.size());
        on_alloc(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// What a measured piece of code allocated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocStats {
    /// Number of allocations and reallocations.
    pub allocs: u64,
    /// Total number of bytes requested.
    pub bytes: u64,
    /// Highest number of bytes live at once above the starting level.
    pub peak_bytes: u64,
}

impl fmt::Display for AllocStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "allocs={:>6}  bytes={:>8}  peak_live={:>8}",
            self.allocs, self.bytes, self.peak_bytes
        )
    }
}

fn begin() -> (u64, u64, i64) {
    COUNTERS
        .try_with(|c| {
            c.peak.set(c.live.get());
            (c.allocs.get(), c.bytes.get(), c.live.get())
        })
        .unwrap_or_default()
}

fn end(start: (u64, u64, i64)) -> AllocStats {
    COUNTERS
        .try_with(|c| AllocStats {
            allocs: c.allocs.get() - start.0,
            bytes: c.bytes.get() - start.1,
            peak_bytes: (c.peak.get() - start.2).max(0) as u64,
        })
        .unwrap_or_default()
}

/// Run `f` and report what it allocated on this thread.
///
/// The result is returned together with the statistics, so that it is not
/// dropped (and its deallocations are not counted as part of the work) until
/// the caller decides.
pub fn measure<R>(f: impl FnOnce() -> R) -> (R, AllocStats) {
    let start = begin();
    let result = f();
    (result, end(start))
}

/// Await `fut` and report what it allocated on this thread.
///
/// The future itself must have been created beforehand: its own state is not
/// part of the measurement unless it allocates while being polled.
pub async fn measure_async<F: Future>(fut: F) -> (F::Output, AllocStats) {
    let start = begin();
    let result = fut.await;
    (result, end(start))
}
