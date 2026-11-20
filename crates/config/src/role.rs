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
use serde::Deserialize;

use crate::common::{default_cache_time, default_sql_driver, default_true};
use crate::pagination::ListLimitConfig;

/// Role Provider.
#[derive(Debug, Deserialize, Clone)]
pub struct RoleProvider {
    /// Toggle for role caching.
    ///
    /// When enabled the SQL driver caches the names of the roles and the
    /// resolved role inference (the roles every role implies) in memory,
    /// within the `[database] projection_cache_*` limits. The caches are
    /// kept while the `role` and `implied_role` tables are unchanged, as
    /// told by the table version watermarks.
    #[serde(default = "default_true")]
    pub caching: bool,

    /// Maximum age of an entry of the role caches of the SQL
    /// driver, in seconds. Caps `[database] projection_cache_ttl_ms`, the
    /// smaller one wins; `0` disables the caches. A change of the tables is
    /// noticed through the watermarks before this time. Only effective when
    /// `caching` is enabled.
    #[serde(default = "default_cache_time")]
    pub cache_time: u64,

    /// Role provider driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// `GET /v3/roles` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,
}

impl Default for RoleProvider {
    fn default() -> Self {
        Self {
            caching: default_true(),
            cache_time: default_cache_time(),
            driver: default_sql_driver(),
            list_limit: ListLimitConfig::default(),
        }
    }
}
