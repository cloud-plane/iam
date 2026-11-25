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

/// Revoke provider configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct RevokeProvider {
    /// Maximum age of an entry of the revocation check cache of the SQL
    /// driver, in seconds. Caps `[database] projection_cache_ttl_ms`, the
    /// smaller one wins; `0` disables the caches. A change of the tables is
    /// noticed through the watermarks before this time. Only effective when
    /// `caching` is enabled.
    #[serde(default = "default_cache_time")]
    pub cache_time: u64,

    /// Toggle for caching of the token revocation check.
    ///
    /// When enabled the SQL driver caches the answer of the check in
    /// memory, within the `[database] projection_cache_*` limits. The check
    /// is linearizable: the answer is kept only while the revocation tables
    /// are unchanged, as told by the table version watermarks.
    #[serde(default = "default_true")]
    pub caching: bool,

    /// Entry point for the token revocation backend driver in the
    /// `keystone.revoke` namespace. Keystone only provides a `sql` driver.
    #[serde(default = "default_sql_driver")]
    pub driver: String,
    /// The number of seconds after a token has expired before a corresponding
    /// revocation event may be purged from the backend.
    #[serde(default = "default_expiration_buffer")]
    pub expiration_buffer: usize,
}

impl Default for RevokeProvider {
    fn default() -> Self {
        Self {
            cache_time: default_cache_time(),
            caching: default_true(),
            driver: default_sql_driver(),
            expiration_buffer: default_expiration_buffer(),
        }
    }
}

fn default_expiration_buffer() -> usize {
    1800
}
