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
//! # Response-shaped catalog cache
//!
//! Token responses embed the service catalog. Building it from the driver's
//! shared catalog copies every service/endpoint string on every request
//! (the `Catalog::from` conversion measured by the catalog allocation
//! profile). The catalog itself only changes on catalog mutations, and the
//! driver signals that by handing out a *new* `Arc<CatalogEntries>` — so the
//! response-shaped conversion can be built once per catalog generation and
//! shared (`Arc<Catalog>`) across every token response until the catalog
//! changes again.

use std::sync::{Arc, LazyLock, RwLock};

use openstack_keystone_api_types::catalog::Catalog;
use openstack_keystone_core::catalog::CatalogEntries;

/// Process-wide cache of the response-shaped service catalog.
///
/// Single slot: a production process serves one catalog, and the slot is
/// rebuilt (at most once per catalog generation) when the driver hands out a
/// different shared catalog.
#[derive(Default)]
pub struct CatalogResponseCache {
    entry: RwLock<Option<Entry>>,
}

struct Entry {
    /// The `get_catalog(enabled)` filter the entry was built for.
    enabled: bool,
    /// The shared driver catalog the entry was built from. Pointer identity
    /// is the invalidation signal: a catalog mutation yields a new `Arc`.
    shared: Arc<CatalogEntries>,
    /// The response-shaped catalog, shared with every token response.
    api: Arc<Catalog>,
}

impl CatalogResponseCache {
    /// The response-shaped catalog for `shared`, building (and caching) it
    /// the first time this catalog generation is seen.
    ///
    /// Hits only take a read lock. A miss converts the catalog *outside* any
    /// lock, so a cache that cannot hit (driver caching disabled, so every
    /// call hands out a fresh `Arc`) costs one conversion per request, as
    /// before, and never serializes concurrent token issuance.
    #[must_use]
    pub fn get_or_build(&self, shared: &Arc<CatalogEntries>, enabled: bool) -> Arc<Catalog> {
        // A poisoned lock cannot leave the slot inconsistent (it is only ever
        // replaced wholesale), so recover it.
        if let Some(e) = self
            .entry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            && e.enabled == enabled
            && Arc::ptr_eq(&e.shared, shared)
        {
            return Arc::clone(&e.api);
        }
        let api = Arc::new(Catalog::from(shared.as_slice()));
        *self
            .entry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Entry {
            enabled,
            shared: Arc::clone(shared),
            api: Arc::clone(&api),
        });
        api
    }
}

/// The process-wide instance.
pub static CATALOG_RESPONSE_CACHE: LazyLock<CatalogResponseCache> =
    LazyLock::new(CatalogResponseCache::default);

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::catalog::{Endpoint, Service};

    use super::*;

    fn entries() -> Arc<CatalogEntries> {
        Arc::new(vec![(
            Service {
                enabled: true,
                extra: Default::default(),
                id: "svc".into(),
                r#type: Some("compute".into()),
            },
            vec![Endpoint {
                id: "ep".into(),
                interface: "public".into(),
                region_id: None,
                service_id: "svc".into(),
                url: "https://compute.example.com".into(),
                enabled: true,
                extra: Default::default(),
            }],
        )])
    }

    #[test]
    fn same_shared_catalog_shares_one_api_catalog() {
        let cache = CatalogResponseCache::default();
        let shared = entries();

        let first = cache.get_or_build(&shared, true);
        let second = cache.get_or_build(&shared, true);

        assert!(Arc::ptr_eq(&first, &second), "hit must share the Arc");
    }

    #[test]
    fn a_new_shared_catalog_rebuilds() {
        let cache = CatalogResponseCache::default();

        let first = cache.get_or_build(&entries(), true);
        let second = cache.get_or_build(&entries(), true);

        assert!(
            !Arc::ptr_eq(&first, &second),
            "a new catalog generation must rebuild"
        );
    }

    #[test]
    fn a_different_enabled_filter_rebuilds() {
        let cache = CatalogResponseCache::default();
        let shared = entries();

        let disabled = cache.get_or_build(&shared, false);
        let enabled = cache.get_or_build(&shared, true);

        assert!(
            !Arc::ptr_eq(&disabled, &enabled),
            "different filters must not share an entry"
        );
    }
}
