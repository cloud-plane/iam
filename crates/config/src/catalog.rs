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

/// Catalog provider.
#[derive(Debug, Deserialize, Clone)]
pub struct CatalogProvider {
    /// Maximum age of an entry of the catalog cache of the SQL
    /// driver, in seconds. Caps `[database] projection_cache_ttl_ms`, the
    /// smaller one wins; `0` disables the caches. A change of the tables is
    /// noticed through the watermarks before this time. Only effective when
    /// `caching` is enabled.
    #[serde(default = "default_cache_time")]
    pub cache_time: u64,

    /// Toggle for catalog caching.
    ///
    /// When enabled the SQL driver caches the assembled service catalog in
    /// memory, within the `[database] projection_cache_*` limits. The cache
    /// is kept while the `service` and `endpoint` tables are unchanged, as
    /// told by the table version watermarks.
    #[serde(default = "default_true")]
    pub caching: bool,

    /// Catalog provider driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,

    /// `GET /v3/services`, `/v3/regions`, `/v3/endpoints` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,
}

impl Default for CatalogProvider {
    fn default() -> Self {
        Self {
            cache_time: default_cache_time(),
            caching: default_true(),
            driver: default_sql_driver(),
            list_limit: ListLimitConfig::default(),
        }
    }
}
