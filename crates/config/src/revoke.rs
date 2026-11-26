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
use std::collections::HashMap;

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
    /// `keystone.revoke` namespace: `sql` (the default) or `raft`, which keeps
    /// the events in the distributed storage and emits them to the priority
    /// outbox of the change feed when `feed_kinds` lists `revocation`.
    #[serde(default = "default_sql_driver")]
    pub driver: String,
    /// The number of seconds after a token has expired before a corresponding
    /// revocation event may be purged from the backend.
    #[serde(default = "default_expiration_buffer")]
    pub expiration_buffer: usize,

    /// Seconds after which the revocation stream of another authority counts
    /// as stale, when no heartbeat arrived from it after the events before it
    /// were applied. While it is stale, the policies of sensitive actions deny
    /// requests that carry a token issued by that authority
    /// (`input.credentials.revocation_stale`). The revocation bound of the
    /// mesh is 30 seconds.
    ///
    /// Effective for the authorities of `peer_authorities`, with tokens of
    /// the JWS provider that name the authority in `[jws_tokens]
    /// trusted_authorities`. A token of an authority this node receives no
    /// stream from is stale as well.
    #[serde(default = "default_revocation_max_staleness")]
    pub revocation_max_staleness: u64,

    /// `[revoke.peer_authorities]`: the other authorities whose revocations
    /// this node applies, as `<authority> = <host:port>` where `<authority>`
    /// is the `iss` of their tokens and `<host:port>` the Raft address of any
    /// voter of theirs. Every node of the authority starts one priority feed
    /// consumer per entry, which needs `driver = raft`. The source must grant
    /// this node the `revocation` kind (`keystone-manage storage
    /// feed-grants`). An event is applied only to the tokens of the authority
    /// it came from.
    #[serde(default)]
    pub peer_authorities: HashMap<String, String>,
}

impl Default for RevokeProvider {
    fn default() -> Self {
        Self {
            cache_time: default_cache_time(),
            caching: default_true(),
            driver: default_sql_driver(),
            expiration_buffer: default_expiration_buffer(),
            revocation_max_staleness: default_revocation_max_staleness(),
            peer_authorities: HashMap::new(),
        }
    }
}

fn default_revocation_max_staleness() -> u64 {
    30
}

fn default_expiration_buffer() -> usize {
    1800
}
