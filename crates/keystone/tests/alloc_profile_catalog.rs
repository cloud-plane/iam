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
//! Allocation profile of the response-shaped catalog cache.
//!
//! Token responses embed the service catalog. The cache must pay the
//! `Catalog::from` conversion once per catalog generation and nothing
//! (beyond an `Arc` bump) per response. Run with:
//!
//! ```text
//! cargo test -p openstack-keystone --test alloc_profile_catalog -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use openstack_keystone_alloc_profile::{AllocStats, CountingAlloc, measure};
use openstack_keystone_core::catalog::CatalogEntries;
use openstack_keystone_core_types::catalog::{Endpoint, Service};

use openstack_keystone::catalog::CatalogResponseCache;

#[global_allocator]
static ALLOCATOR: CountingAlloc = CountingAlloc;

const SERVICES: usize = 20;
const INTERFACES: [&str; 3] = ["public", "internal", "admin"];

fn hex_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn sample_catalog() -> Arc<CatalogEntries> {
    Arc::new(
        (0..SERVICES)
            .map(|n| {
                let id = hex_id();
                let endpoints = INTERFACES
                    .iter()
                    .map(|interface| Endpoint {
                        id: hex_id(),
                        interface: (*interface).to_string(),
                        region_id: Some("RegionOne".to_string()),
                        service_id: id.clone(),
                        url: format!("https://service{n}.{interface}.cloud.example.com:8774/v2.1"),
                        enabled: true,
                        extra: Default::default(),
                    })
                    .collect();
                let service = Service {
                    enabled: true,
                    extra: Default::default(),
                    id,
                    r#type: Some(format!("type{n}")),
                };
                (service, endpoints)
            })
            .collect(),
    )
}

/// Print the figures of a stage.
fn report(label: &str, stats: &AllocStats) {
    eprintln!("ALLOC {label:<46} {stats}");
}

/// Fail when a stage needs more allocations than its budget allows.
#[track_caller]
fn assert_budget(label: &str, stats: &AllocStats, max_allocs: u64) {
    report(label, stats);
    assert!(
        stats.allocs <= max_allocs,
        "{label}: {} allocations, budget is {max_allocs}",
        stats.allocs
    );
}

#[test]
fn alloc_profile_catalog_response_cache() {
    let shared = sample_catalog();
    let cache = CatalogResponseCache::default();

    // First request for this catalog generation pays the conversion.
    let (first, stats) = measure(|| cache.get_or_build(&shared, true));
    assert_eq!(first.0.len(), SERVICES);
    assert_budget(
        "catalog response (build, 20 services x 3 endpoints)",
        &stats,
        400,
    );

    // Every later request for the same generation shares the Arc.
    let (second, stats) = measure(|| cache.get_or_build(&shared, true));
    assert!(
        Arc::ptr_eq(&first, &second),
        "the cached Arc must be handed out, not rebuilt"
    );
    assert_budget("catalog response (cache hit)", &stats, 2);

    // A new generation (catalog mutation) rebuilds exactly once more.
    let next = sample_catalog();
    let (third, stats) = measure(|| cache.get_or_build(&next, true));
    assert!(!Arc::ptr_eq(&first, &third));
    assert_budget("catalog response (rebuild, new generation)", &stats, 400);
}
