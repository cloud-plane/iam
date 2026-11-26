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
//! # Projection caches of the role driver
//!
//! Two facts of the role tables are read by every token validation, and both
//! are small and change rarely:
//!
//! - the names of the roles a user holds, and
//! - the role inference: the roles each role implies, directly or not. The
//!   rules are stored as a graph, so the transitive closure is **resolved
//!   once per version of the rules** ([`RoleInference::from_rules`]) and the
//!   result is shared, instead of walking the graph for every request.
//!
//! Both depend on the `role` and `implied_role` tables only, which the
//! watermark triggers watch. The reads are linearizable: a rule or a role
//! changed anywhere is visible to the next read.

use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core::projection_cache::{CacheKind, CacheLimits, ProjectionCache};
use openstack_keystone_core::table_watermark::ROLE_TABLES;
use openstack_keystone_core_types::role::{Role, RoleImply, RoleInference, RoleOptions, RoleRef};

/// Key of the only entry of the inference cache.
pub const INFERENCE_KEY: &str = "all";

/// Heap bytes of a role (without the options).
fn role_heap(role: &Role) -> usize {
    role.id.capacity()
        + role.name.capacity()
        + role.description.as_ref().map_or(0, String::capacity)
        + role.domain_id.as_ref().map_or(0, String::capacity)
        + role
            .extra
            .iter()
            .map(|(key, value)| key.capacity() + value.to_string().len())
            .sum::<usize>()
}

/// Heap bytes of a role reference.
fn role_ref_heap(role: &RoleRef) -> usize {
    role.id.capacity()
        + role.name.as_ref().map_or(0, String::capacity)
        + role.domain_id.as_ref().map_or(0, String::capacity)
}

/// Heap bytes of the imply rules.
fn rules_heap(rules: &Arc<Vec<RoleImply>>) -> usize {
    rules.capacity() * std::mem::size_of::<RoleImply>()
        + rules
            .iter()
            .map(|rule| role_ref_heap(&rule.prior_role) + role_ref_heap(&rule.implied_role))
            .sum::<usize>()
}

/// Key of the only entry of the rules cache.
pub const RULES_KEY: &str = "all";

/// The projection caches of one role driver instance.
pub struct RoleCaches {
    /// Roles with their options, by the role ID.
    pub roles: ProjectionCache<Role>,
    /// The imply rules as stored, under [`RULES_KEY`]. The single and the
    /// filtered reads of the rules are answered from it.
    pub rules: ProjectionCache<Arc<Vec<RoleImply>>>,
    /// Roles without their options, by the role ID.
    pub names: ProjectionCache<Role>,
    /// The resolved role inference, under [`INFERENCE_KEY`].
    pub inference: ProjectionCache<Arc<RoleInference>>,
}

impl Default for RoleCaches {
    /// The default configuration.
    fn default() -> Self {
        Self::new(&Config::default())
    }
}

/// The limits of a cache of the role driver: `[role] caching = false` or
/// `cache_time = 0` switch the role caches off.
fn limits(config: &Config, kind: CacheKind) -> CacheLimits {
    CacheLimits::from_config(config, kind).capped(config.role.caching, config.role.cache_time)
}

impl RoleCaches {
    /// Caches limited by the `[database] projection_cache_*` options.
    pub fn new(config: &Config) -> Self {
        Self {
            roles: ProjectionCache::new(
                ROLE_TABLES,
                limits(config, CacheKind::RoleNames),
                |role: &Role| role_heap(role) + std::mem::size_of::<RoleOptions>(),
            ),
            rules: ProjectionCache::new(
                ROLE_TABLES,
                limits(config, CacheKind::RoleInference),
                rules_heap,
            ),
            names: ProjectionCache::new(
                ROLE_TABLES,
                limits(config, CacheKind::RoleNames),
                role_heap,
            ),
            inference: ProjectionCache::new(
                ROLE_TABLES,
                limits(config, CacheKind::RoleInference),
                |inference: &Arc<RoleInference>| inference.heap_size(),
            ),
        }
    }

    /// Forget the inference: a rule or a role name changed.
    pub fn invalidate_inference(&self) {
        self.rules.invalidate();
        self.inference.invalidate();
    }

    /// Forget a role after it was created. A new role is in no imply rule,
    /// so the resolved inference stays valid.
    pub fn invalidate_created_role(&self, role_id: &str) {
        self.names.invalidate_key(role_id);
        self.roles.invalidate_key(role_id);
    }

    /// Forget a role after it was written (its name may be part of the
    /// resolved inference).
    pub fn invalidate_role(&self, role_id: &str) {
        self.names.invalidate_key(role_id);
        self.roles.invalidate_key(role_id);
        self.rules.invalidate();
        self.inference.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caching_switch_disables_the_caches() {
        let mut config = Config::default();
        assert!(!limits(&config, CacheKind::RoleNames).ttl.is_zero());
        config.role.caching = false;
        assert!(limits(&config, CacheKind::RoleNames).ttl.is_zero());
        config.role.caching = true;
        config.role.cache_time = 0;
        assert!(limits(&config, CacheKind::RoleInference).ttl.is_zero());
    }
}
