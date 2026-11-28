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
//! Allocation profile of decrypting a fernet token.
//!
//! Run with `cargo test -p openstack-keystone-token-driver-fernet --test
//! alloc_profile -- --nocapture` to print the figures.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::File;
use std::io::Write;

use tempfile::tempdir;

use openstack_keystone_alloc_profile::{CountingAlloc, measure};
use openstack_keystone_config::Config;
use openstack_keystone_token_driver_fernet::FernetTokenProvider;

#[global_allocator]
static ALLOCATOR: CountingAlloc = CountingAlloc;

/// A project scoped token issued by the python implementation with the key
/// written by [`provider`].
const TOKEN: &str = "gAAAAABns2ixy75K_KfoosWLrNNqG6KW8nm3Xzv0_2dOx8ODWH7B8i2g8CncGLO6XBEH_TYLg83P6XoKQ5bU8An8Kqgw9WX3bvmEQXphnwPM6aRAOQUSdVhTlUm_8otDG9BS2rc70Q7pfy57S3_yBgimy-174aKdP8LPusvdHZsQPEJO9pfeXWw";

async fn provider() -> FernetTokenProvider {
    let tmp_dir = tempdir().unwrap();
    let mut key_file = File::create(tmp_dir.path().join("0")).unwrap();
    write!(key_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();

    let builder = config::Config::builder()
        .set_override("auth.methods", "password,token")
        .unwrap()
        .set_override("database.connection", "dummy")
        .unwrap();
    let mut config: Config = Config::try_from(builder).expect("can build a valid config");
    config.fernet_tokens.key_repository = tmp_dir.keep();

    let mut provider = FernetTokenProvider::new(config);
    provider.load_keys().await.unwrap();
    provider
}

#[tokio::test]
async fn alloc_profile_fernet_decrypt() {
    let provider = provider().await;

    provider.decrypt(TOKEN).unwrap();
    let (token, stats) = measure(|| provider.decrypt(TOKEN));
    token.unwrap();

    eprintln!(
        "ALLOC {:<46} {stats}",
        "fernet decrypt (project scoped token)"
    );
    // Measured value plus about 10% of slack.
    assert!(
        stats.allocs <= 12,
        "fernet decrypt: {} allocations, budget is 12",
        stats.allocs
    );
}
