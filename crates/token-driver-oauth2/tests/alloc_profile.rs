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
// Crypto inventory: TOK-3; see doc/src/contributor/crypto-inventory.md
//! Allocation profile of validating an OAuth2 JWT Keystone token.
//!
//! The per-request cost of the format the token was detected as: the shape
//! detection of the credential, and the verification and decode (which also
//! recovers the sender constraint out of the verified claims). The keys are
//! mocked, so the figures cover the parsing and verification bookkeeping,
//! not the key storage.
//!
//! Run with `cargo test -p openstack-keystone-token-driver-oauth2 --test
//! alloc_profile -- --nocapture` to print the figures.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::{SubsecRound, TimeDelta, Utc};

use openstack_keystone_alloc_profile::{AllocStats, CountingAlloc, measure, measure_async};
use openstack_keystone_config::Config;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_key::{MockOauth2KeyProvider, jwks::active_keys_to_jwk_set};
use openstack_keystone_core::provider::Provider;
use openstack_keystone_core::tests::get_mocked_state;
use openstack_keystone_core::token::format::detect_format;
use openstack_keystone_core_types::token::ProjectScopePayload;
use openstack_keystone_key_repository::asymmetric::{
    ActiveKeys, SigningAlgorithm, generate_keypair,
};
use openstack_keystone_token_driver_oauth2::{decode, encode};

#[global_allocator]
static ALLOCATOR: CountingAlloc = CountingAlloc;

/// A project scoped token, as the service issues it.
fn payload() -> openstack_keystone_core_types::token::TokenPayload {
    openstack_keystone_core_types::token::TokenPayload::ProjectScope(ProjectScopePayload {
        user_id: "u1".into(),
        methods: vec!["password".into()],
        audit_ids: vec!["dkpM2xhJSlWwcxgcxu_EXw".into()],
        expires_at: Utc::now().trunc_subsecs(0) + TimeDelta::hours(1),
        project_id: "p1".into(),
        issued_at: Utc::now().trunc_subsecs(0),
    })
}

/// The service state with the OAuth2 key provider mocked.
async fn state() -> ServiceState {
    let mut config = Config::default();
    config.default.public_endpoint = Some("https://ks.example".parse().unwrap());

    let keys = generate_keypair(SigningAlgorithm::Es256).unwrap();
    let signing = keys.clone();
    let jwks = active_keys_to_jwk_set(&ActiveKeys {
        primary: keys,
        previous: None,
    })
    .unwrap();
    let mut key_mock = MockOauth2KeyProvider::default();
    key_mock
        .expect_active_signing_key()
        .returning(move |_, _| Ok(signing.clone()));
    key_mock
        .expect_jwks()
        .returning(move |_, _| Ok(jwks.clone()));
    key_mock
        .expect_revoked_jtis()
        .returning(|_, _| Ok(std::collections::HashSet::new()));
    let provider = Provider::mocked_builder().mock_oauth2_key(key_mock);
    get_mocked_state(Some(config), Some(provider)).await
}

fn report(label: &str, stats: &AllocStats) {
    eprintln!("ALLOC {label:<48} {stats}");
}

/// Fail when a stage needs more allocations than its budget allows.
///
/// A budget is the measured value plus slack for dependency upgrades; lower
/// it when a stage gets cheaper.
#[track_caller]
fn assert_budget(label: &str, stats: &AllocStats, max_allocs: u64) {
    report(label, stats);
    assert!(
        stats.allocs <= max_allocs,
        "{label}: {} allocations, budget is {max_allocs}",
        stats.allocs
    );
}

#[tokio::test]
async fn alloc_profile_oauth2_token_validation() {
    let state = state().await;
    let token = payload();
    let credential = encode(&state, &token, Some("d1".into()), None)
        .await
        .unwrap();

    // The first pass initialises lazily created statics and is not measured.
    decode(&state, &credential).await.unwrap();

    let (_, stats) = measure(|| detect_format(&credential));
    assert_budget("detect_format (OAuth2 credential)", &stats, 14);

    let (_, stats) = measure_async(decode(&state, &credential)).await;
    assert_budget("decode (verify + claims + cnf)", &stats, 150);
}
