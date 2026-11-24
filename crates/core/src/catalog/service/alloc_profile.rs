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
//! Allocation profile of `CatalogApi::get_catalog` on a cache hit.
//!
//! The catalog is assembled once per cache lifetime. What every request pays
//! is handing the cached value to the caller, which is what is measured here
//! for a catalog of 20 services with 3 endpoints each.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use uuid::Uuid;

use openstack_keystone_api_types::catalog::Catalog;
use openstack_keystone_core_types::catalog::{Endpoint, Service};

use super::*;
use crate::alloc_profile::{assert_budget, measure, measure_async, quiet_tracing};
use crate::catalog::backend::MockCatalogBackend;
use crate::tests::get_mocked_state;

const SERVICES: usize = 20;
const INTERFACES: [&str; 3] = ["public", "internal", "admin"];

fn hex_id() -> String {
    Uuid::new_v4().simple().to_string()
}

fn sample_catalog() -> Vec<(Service, Vec<Endpoint>)> {
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
                    extra: HashMap::new(),
                })
                .collect();
            let service = Service {
                enabled: true,
                extra: HashMap::from([("name".to_string(), json!(format!("service{n}")))]),
                id,
                r#type: Some(format!("type{n}")),
            };
            (service, endpoints)
        })
        .collect()
}

#[tokio::test]
async fn alloc_profile_get_catalog_cache_hit() {
    let _quiet = quiet_tracing();
    let mut backend = MockCatalogBackend::default();
    backend
        .expect_get_catalog()
        .returning(|_, _| Ok(sample_catalog()));
    let service = CatalogService {
        backend_driver: Arc::new(backend),
        cache: CatalogCache::new(Duration::from_secs(600)),
    };
    let state = get_mocked_state(None, None).await;
    let exec = ExecutionContext::internal(&state);

    // The first call loads and caches the catalog, the second one is a hit.
    service.get_catalog(&exec, true).await.unwrap();
    let (catalog, stats) = measure_async(service.get_catalog(&exec, true)).await;
    let catalog = catalog.unwrap();
    assert_eq!(catalog.len(), SERVICES);

    // Handing the shared catalog over must not depend on its size.
    assert_budget(
        "get_catalog (cache hit, 20 services x 3 endpoints)",
        &stats,
        5,
    );

    // What the handlers then build the response catalog with.
    let (response, stats) = measure(|| Catalog::from(catalog.as_slice()));
    assert_eq!(response.0.len(), SERVICES);
    // One copy of the strings the response carries, nothing else.
    assert_budget("response catalog from the shared catalog", &stats, 420);
}
