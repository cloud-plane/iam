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
//! # Projection cache of the assignment driver
//!
//! The role assignments of a set of actors on a set of targets (the most
//! frequent read of the token validation) depend on the `assignment` and
//! `system_assignment` tables only. The implied roles and the role names are
//! not part of the cached value: they come from the role provider.
//!
//! The reads are linearizable: an entry is served only after the counters of
//! the tables were brought up to date and are unchanged since the entry was
//! loaded, so a grant or a revocation is visible to the next read.

use std::mem::size_of;

use openstack_keystone_config::Config;
use openstack_keystone_core::projection_cache::{CacheKind, CacheLimits, ProjectionCache};
use openstack_keystone_core::table_watermark::ASSIGNMENT_TABLES;
use openstack_keystone_core_types::assignment::{
    Assignment, RoleAssignmentListForMultipleActorTargetParameters,
};

/// Heap bytes of the cached assignments.
fn assignments_heap(assignments: &Vec<Assignment>) -> usize {
    assignments.capacity() * size_of::<Assignment>()
        + assignments
            .iter()
            .map(|a| {
                a.actor_id.capacity()
                    + a.role_id.capacity()
                    + a.target_id.capacity()
                    + a.role_name.as_ref().map_or(0, String::capacity)
                    + a.implied_via.as_ref().map_or(0, String::capacity)
            })
            .sum::<usize>()
}

/// The projection caches of one assignment driver instance.
pub struct AssignmentCaches {
    /// The assignments of a request by its canonical key, see [`key`].
    pub lists: ProjectionCache<Vec<Assignment>>,
}

impl Default for AssignmentCaches {
    /// The default configuration.
    fn default() -> Self {
        Self::new(&Config::default())
    }
}

impl AssignmentCaches {
    /// Caches limited by the `[database] projection_cache_*` options.
    pub fn new(config: &Config) -> Self {
        let limits = CacheLimits::from_config(config, CacheKind::Assignments)
            .capped(config.assignment.caching, config.assignment.cache_time);
        Self::with_limits(limits)
    }

    fn with_limits(lists: CacheLimits) -> Self {
        Self {
            lists: ProjectionCache::new(ASSIGNMENT_TABLES, lists, assignments_heap),
        }
    }
}

/// Canonical cache key of a request: the order of the actors and the targets
/// does not matter to the result.
///
/// `resolve_implied_roles` is not part of it: the cached rows are the ones
/// stored in the tables, before any role inference.
pub fn key(params: &RoleAssignmentListForMultipleActorTargetParameters) -> String {
    let mut actors: Vec<&str> = params.actors.iter().map(String::as_str).collect();
    actors.sort_unstable();
    actors.dedup();
    let mut targets: Vec<String> = params
        .targets
        .iter()
        .map(|t| format!("{}/{:?}/{:?}", t.id, t.r#type, t.inherited))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    // Every component is length-prefixed: an ID may contain any separator.
    let mut key = String::new();
    push_component(&mut key, params.role_id.as_deref().unwrap_or(""));
    for actor in &actors {
        push_component(&mut key, actor);
    }
    key.push('|');
    for target in &targets {
        push_component(&mut key, target);
    }
    key
}

fn push_component(key: &mut String, component: &str) {
    key.push_str(&component.len().to_string());
    key.push(':');
    key.push_str(component);
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::assignment::{
        RoleAssignmentTarget, RoleAssignmentTargetType,
    };

    use super::*;

    fn target(id: &str) -> RoleAssignmentTarget {
        RoleAssignmentTarget {
            id: id.into(),
            r#type: RoleAssignmentTargetType::Project,
            inherited: Some(false),
        }
    }

    #[test]
    fn test_key_ignores_order_and_implied_roles() {
        let a = RoleAssignmentListForMultipleActorTargetParameters {
            actors: vec!["u".into(), "g1".into(), "g2".into()],
            targets: vec![target("p1"), target("p2")],
            resolve_implied_roles: true,
            ..Default::default()
        };
        let b = RoleAssignmentListForMultipleActorTargetParameters {
            actors: vec!["g2".into(), "u".into(), "g1".into()],
            targets: vec![target("p2"), target("p1")],
            resolve_implied_roles: false,
            ..Default::default()
        };
        assert_eq!(key(&a), key(&b));
    }

    #[test]
    fn test_key_is_not_fooled_by_separators_in_ids() {
        let a = RoleAssignmentListForMultipleActorTargetParameters {
            actors: vec!["a,b".into()],
            targets: vec![target("p")],
            ..Default::default()
        };
        let b = RoleAssignmentListForMultipleActorTargetParameters {
            actors: vec!["a".into(), "b".into()],
            targets: vec![target("p")],
            ..Default::default()
        };
        assert_ne!(key(&a), key(&b));
    }

    #[test]
    fn test_key_tells_requests_apart() {
        let a = RoleAssignmentListForMultipleActorTargetParameters {
            actors: vec!["u".into()],
            targets: vec![target("p1")],
            ..Default::default()
        };
        let mut b = a.clone();
        b.actors.push("g".into());
        let mut c = a.clone();
        c.role_id = Some("r".into());
        let mut d = a.clone();
        d.targets[0].inherited = Some(true);
        let keys = [key(&a), key(&b), key(&c), key(&d)];
        for (i, left) in keys.iter().enumerate() {
            for right in &keys[i + 1..] {
                assert_ne!(left, right);
            }
        }
    }
}
