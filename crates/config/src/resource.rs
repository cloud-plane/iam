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

/// Resource provider (domain, project).
#[derive(Debug, Deserialize, Clone)]
pub struct ResourceProvider {
    /// Maximum age of an entry of the project and domain caches of the SQL
    /// driver, in seconds. Caps `[database] projection_cache_ttl_ms`, the
    /// smaller one wins; `0` disables the caches. A change of the tables is
    /// noticed through the watermarks before this time. Only effective when
    /// `caching` is enabled.
    #[serde(default = "default_cache_time")]
    pub cache_time: u64,

    /// Caching. Toggles the caches of the SQL driver: the domain and the
    /// parents of a project, the project and domain references. They are
    /// kept while the `project` table is unchanged, as told by the table
    /// version watermarks, so a change made by another process is noticed.
    #[serde(default = "default_true")]
    pub caching: bool,

    /// Resource provider backend.
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// `GET /v3/projects` and `/v3/domains` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,
}

impl Default for ResourceProvider {
    fn default() -> Self {
        Self {
            cache_time: default_cache_time(),
            caching: default_true(),
            driver: default_sql_driver(),
            list_limit: ListLimitConfig::default(),
        }
    }
}
