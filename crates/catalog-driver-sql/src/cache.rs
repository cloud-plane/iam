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
//! # Projection cache of the catalog driver
//!
//! The assembled service catalog (the services with their endpoints) is
//! embedded into every token response, is small and changes rarely. It
//! depends on the `service` and `endpoint` tables only, which the watermark
//! triggers watch, so it is kept until one of them changes, here or anywhere
//! else. The read is linearizable: a service or an endpoint changed
//! anywhere is visible to the next read.

use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core::projection_cache::{CacheKind, CacheLimits, ProjectionCache};
use openstack_keystone_core::table_watermark::CATALOG_TABLES;
use openstack_keystone_core_types::catalog::{Endpoint, Service};

/// Catalog content as returned by `get_catalog`, shared between the readers.
pub type CatalogEntries = Arc<openstack_keystone_core::catalog::CatalogEntries>;

/// Cache key of the catalog of the enabled (or the disabled) entities.
pub fn key(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}

/// Approximate heap bytes of the catalog: what it takes serialized plus the
/// structures around it.
fn catalog_heap(catalog: &CatalogEntries) -> usize {
    catalog
        .iter()
        .map(|(service, endpoints)| {
            std::mem::size_of::<(Service, Vec<Endpoint>)>()
                + serde_json::to_string(service).map_or(0, |s| s.len())
                + endpoints
                    .iter()
                    .map(|endpoint| {
                        std::mem::size_of::<Endpoint>()
                            + serde_json::to_string(endpoint).map_or(0, |s| s.len())
                    })
                    .sum::<usize>()
        })
        .sum()
}

/// The projection caches of one catalog driver instance.
pub struct CatalogCaches {
    /// The assembled catalog by [`key`].
    pub catalog: ProjectionCache<CatalogEntries>,
}

impl Default for CatalogCaches {
    /// The default configuration.
    fn default() -> Self {
        Self::new(&Config::default())
    }
}

impl CatalogCaches {
    /// Cache limited by the `[database] projection_cache_*` options;
    /// `[catalog] caching = false` or `cache_time = 0` switch it off.
    pub fn new(config: &Config) -> Self {
        let limits = CacheLimits::from_config(config, CacheKind::Catalog)
            .capped(config.catalog.caching, config.catalog.cache_time);
        Self {
            catalog: ProjectionCache::new(CATALOG_TABLES, limits, catalog_heap),
        }
    }

    /// Forget the catalog after a service or an endpoint was written.
    pub fn invalidate(&self) {
        self.catalog.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_tells_the_flags_apart() {
        assert_ne!(key(true), key(false));
    }

    #[test]
    fn caching_switch_disables_the_cache() {
        let mut config = Config::default();
        config.catalog.caching = false;
        let caches = CatalogCaches::new(&config);
        assert!(caches.catalog.is_empty());
    }
}
