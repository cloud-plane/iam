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
//
//! # Projection cache of the revocation driver
//!
//! Whether a token is revoked depends on the `revocation_event` table only.
//! The answer is cached per token (the parameters of the check) and served
//! only after the counters were brought up to date, so a revocation is
//! visible to the next check on every replica. A revocation or a cleanup
//! moves the counter and drops every cached answer.

use openstack_keystone_config::Config;
use openstack_keystone_core::projection_cache::{CacheKind, CacheLimits, ProjectionCache};
use openstack_keystone_core::table_watermark::REVOCATION_TABLES;
use openstack_keystone_core_types::revoke::RevocationEventListParameters;

/// The projection caches of one revocation driver instance.
pub struct RevokeCaches {
    /// Whether the token described by the parameters is revoked.
    pub revoked: ProjectionCache<bool>,
}

impl Default for RevokeCaches {
    /// The default configuration.
    fn default() -> Self {
        Self::new(&Config::default())
    }
}

impl RevokeCaches {
    /// Caches limited by the `[database] projection_cache_*` options.
    pub fn new(config: &Config) -> Self {
        let limits = CacheLimits::from_config(config, CacheKind::Revocation)
            .capped(config.revoke.caching, config.revoke.cache_time);
        Self::with_limits(limits)
    }

    fn with_limits(revoked: CacheLimits) -> Self {
        Self {
            revoked: ProjectionCache::new(REVOCATION_TABLES, revoked, |_| 0),
        }
    }

    /// Forget every answer: this replica wrote a revocation event and must
    /// see it immediately.
    pub fn invalidate(&self) {
        self.revoked.invalidate();
    }
}

/// The cache key of a revocation check: every parameter of the query.
///
/// It is the derived `Debug` output, so a field added to the parameters is part
/// of the key automatically. The key is long and nearly unique per token; it is
/// not hashed so that two different checks can never share an answer.
pub fn key(params: &RevocationEventListParameters) -> String {
    format!("{params:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_covers_every_parameter() {
        let base = RevocationEventListParameters::default();
        let variants = [
            RevocationEventListParameters {
                audit_id: Some("a".into()),
                ..Default::default()
            },
            RevocationEventListParameters {
                project_id: Some("p".into()),
                ..Default::default()
            },
            RevocationEventListParameters {
                trust_id: Some("t".into()),
                ..Default::default()
            },
            RevocationEventListParameters {
                user_ids: Some(vec!["u".into()]),
                ..Default::default()
            },
            RevocationEventListParameters {
                role_ids: Some(vec!["r".into()]),
                ..Default::default()
            },
            RevocationEventListParameters {
                domain_ids: Some(vec!["d".into()]),
                ..Default::default()
            },
        ];
        let keys: std::collections::HashSet<_> = std::iter::once(&base)
            .chain(variants.iter())
            .map(key)
            .collect();
        assert_eq!(keys.len(), variants.len() + 1);
    }
}
