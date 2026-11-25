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
//! # Projection caches of the identity driver
//!
//! Only non-secret, rarely changing projections of a user are cached, and only
//! for readers that state a [`Freshness`](openstack_keystone_core_types::freshness::Freshness)
//! tolerance:
//!
//! | Projection | Depends on | Notes |
//! |---|---|---|
//! | domain of a user | `user` | immutable while the row exists: dropped by the driver's own deletes, and after the age limit (`projection_cache_ttl_ms`) when another process deleted and recreated the user |
//! | user options | `user_option` | `ignore_password_expiry`, `ignore_user_inactivity`, MFA rules |
//! | password expiry | `password` | the expiry of the latest password only |
//! | groups of a user | `group`, `user_group_membership`, `expiring_user_group_membership` | read linearizably; users with expiring (federated) memberships are not cached, their membership depends on the clock |
//!
//! | user record | `user` | linearizable reads only: `enabled` and `last_active_at` decide whether the user may act, a relaxed tolerance would honour a disabled user late |
//! | local user row | `local_user` | linearizable reads only: the name of a user and its authentication counters. A failed login rewrites the row and drops the cached local users |
//!
//! Never cached: every secret, in particular the password hash. Authentication
//! reads the local user (and its authentication counters) straight from the
//! database.

use openstack_keystone_config::Config;
use openstack_keystone_core::projection_cache::{CacheKind, CacheLimits, ProjectionCache};
use openstack_keystone_core_types::identity::{Group, UserOptions};

use crate::entity::local_user as db_local_user;
use crate::entity::user as db_user;
use crate::password::PasswordExpiry;

/// Tables the user record depends on.
pub const USER_TABLES: &[&str] = &["user"];

/// Tables the local user row depends on.
pub const LOCAL_USER_TABLES: &[&str] = &["local_user"];

/// Tables the user options depend on.
pub const OPTION_TABLES: &[&str] = &["user_option"];

/// Tables the password expiry depends on.
///
/// Not `local_user`: the expiry is a column of the `password` row.
pub const PASSWORD_EXPIRY_TABLES: &[&str] = &["password"];

/// Tables the groups of a user depend on.
pub const GROUP_TABLES: &[&str] = &[
    "group",
    "user_group_membership",
    "expiring_user_group_membership",
];

/// Heap bytes of the cached groups. The `extra` map is charged a flat amount
/// per entry.
fn groups_heap(groups: &Vec<Group>) -> usize {
    use std::mem::size_of;
    const EXTRA_ENTRY: usize = 128;
    groups.capacity() * size_of::<Group>()
        + groups
            .iter()
            .map(|g| {
                g.id.capacity()
                    + g.name.capacity()
                    + g.domain_id.capacity()
                    + g.description.as_ref().map_or(0, String::capacity)
                    + g.extra.len() * EXTRA_ENTRY
            })
            .sum::<usize>()
}

/// Heap bytes of the user row.
fn user_heap(user: &db_user::Model) -> usize {
    user.id.capacity()
        + user.domain_id.capacity()
        + user.default_project_id.as_ref().map_or(0, String::capacity)
        + user.extra.as_ref().map_or(0, String::capacity)
}

/// Heap bytes of the local user row.
fn local_user_heap(local_user: &db_local_user::Model) -> usize {
    local_user.user_id.capacity() + local_user.domain_id.capacity() + local_user.name.capacity()
}

/// Heap bytes of the options: the MFA rules are the only unbounded part.
fn options_heap(options: &UserOptions) -> usize {
    use std::mem::size_of;
    options.multi_factor_auth_rules.as_ref().map_or(0, |rules| {
        rules.capacity() * size_of::<Vec<String>>()
            + rules
                .iter()
                .map(|rule| {
                    rule.capacity() * size_of::<String>()
                        + rule.iter().map(String::capacity).sum::<usize>()
                })
                .sum::<usize>()
    })
}

/// The projection caches of one identity driver instance.
pub struct UserCaches {
    /// Domain of a user by user ID. The domain of a user never changes while
    /// the row exists, so only its deletion (and the age limit) drops it.
    pub domain_id: ProjectionCache<String>,
    /// Options of a user by user ID.
    pub options: ProjectionCache<UserOptions>,
    /// Expiry of the latest password by user ID.
    pub password_expiry: ProjectionCache<PasswordExpiry>,
    /// Groups of a user by user ID.
    pub groups: ProjectionCache<Vec<Group>>,
    /// The `user` row by user ID. Only linearizable reads use it.
    pub user: ProjectionCache<db_user::Model>,
    /// The `local_user` row by user ID. Only linearizable reads use it.
    pub local_user: ProjectionCache<db_local_user::Model>,
}

impl Default for UserCaches {
    /// The default configuration.
    fn default() -> Self {
        Self::new(&Config::default())
    }
}

impl UserCaches {
    /// Caches limited by the `[database] projection_cache_*` options.
    pub fn new(config: &Config) -> Self {
        let limits = |kind| {
            CacheLimits::from_config(config, kind)
                .capped(config.identity.caching, config.identity.cache_time)
        };
        Self::with_limits(
            limits(CacheKind::UserDomain),
            limits(CacheKind::UserOptions),
            limits(CacheKind::PasswordExpiry),
            limits(CacheKind::UserGroups),
            limits(CacheKind::User),
            limits(CacheKind::LocalUser),
        )
    }

    fn with_limits(
        domain_id: CacheLimits,
        options: CacheLimits,
        password_expiry: CacheLimits,
        groups: CacheLimits,
        user: CacheLimits,
        local_user: CacheLimits,
    ) -> Self {
        Self {
            domain_id: ProjectionCache::new(USER_TABLES, domain_id, String::capacity),
            options: ProjectionCache::new(OPTION_TABLES, options, options_heap),
            password_expiry: ProjectionCache::new(PASSWORD_EXPIRY_TABLES, password_expiry, |_| 0),
            groups: ProjectionCache::new(GROUP_TABLES, groups, groups_heap),
            user: ProjectionCache::new(USER_TABLES, user, user_heap),
            local_user: ProjectionCache::new(LOCAL_USER_TABLES, local_user, local_user_heap),
        }
    }

    /// Forget the projections of one user: this replica wrote to the user,
    /// its options, its password or its group memberships and must see the
    /// result immediately. (A cascaded delete of the memberships fires no
    /// trigger on MySQL, so a deleted user's groups must not wait for the
    /// counters.)
    pub fn invalidate_user(&self, user_id: &str) {
        self.domain_id.invalidate_key(user_id);
        self.options.invalidate_key(user_id);
        self.password_expiry.invalidate_key(user_id);
        self.user.invalidate_key(user_id);
        self.local_user.invalidate_key(user_id);
        self.groups.invalidate_key(user_id);
    }
}
