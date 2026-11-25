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
//! Evaluation cost of the in-process enforcer.
//!
//! Compare with the OPA sidecar by timing the same input against
//! `POST /v1/data/identity/role/show` (see `doc/src/contributor`).

#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{Criterion, criterion_group, criterion_main};
use openstack_keystone_core::api::tests::test_fixture_scoped;
use openstack_keystone_core::policy::PolicyEnforcer;
use openstack_keystone_policy_regorus::RegorusPolicyEnforcer;
use serde_json::json;

/// The layout under test: the working tree `policy/` directory.
fn current_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy")
}

/// The layout to compare with: a directory named by `POLICY_BASELINE_DIR`,
/// e.g. the policies of an older commit:
///
/// ```text
/// git archive <rev> policy | tar -x -C /tmp/baseline
/// POLICY_BASELINE_DIR=/tmp/baseline/policy cargo bench -p \
///     openstack-keystone-policy-regorus
/// ```
///
/// Without it only the current layout is measured. Both run the same
/// enforcer and the same inputs, so the difference is the policy files alone
/// (what a rule imports and how many modules an entrypoint compiles).
fn layouts() -> Vec<(&'static str, PathBuf)> {
    let mut layouts = vec![("new", current_dir())];
    if let Some(dir) = std::env::var_os("POLICY_BASELINE_DIR") {
        layouts.insert(0, ("old", PathBuf::from(dir)));
    }
    layouts
}

fn bench(c: &mut Criterion) {
    for (name, dir) in layouts() {
        let enforcer = RegorusPolicyEnforcer::new(&dir).expect("policies compile");
        let mut g = c.benchmark_group(name);
        let manager = json!({
            "credentials": {"roles": ["manager"], "is_admin": false, "domain_id": "d"},
            "target": null,
            "existing": {"role": {"id": "r", "domain_id": "d"}}
        });
        let denied = json!({
            "credentials": {"roles": ["member"], "is_admin": false, "domain_id": "d"},
            "target": null,
            "existing": {"role": {"id": "r", "domain_id": "d"}}
        });
        g.bench_function("evaluate allow (identity/role/show)", |b| {
            b.iter(|| enforcer.evaluate("identity/role/show", black_box(manager.clone())))
        });
        g.bench_function("evaluate deny (identity/role/show)", |b| {
            b.iter(|| enforcer.evaluate("identity/role/show", black_box(denied.clone())))
        });
        // Token validation is ~73% of the load profile: the admin validates a
        // subject token. Credentials mirror `core::policy::Credentials`.
        let token_admin = json!({
            "credentials": {
                "is_admin": false, "user_id": "0123456789abcdef0123456789abcdef",
                "roles": ["admin", "member", "reader"],
                "project_id": "fedcba9876543210fedcba9876543210",
                "domain_id": null, "project_domain_id": "default", "system": null,
                "trust": null, "auth_type": "password", "is_delegated": false,
                "delegated_project_id": null
            },
            "target": null,
            "existing": {"token": {
                "audit_ids": ["a1b2c3d4e5f60718293a4b5c6d7e8f"],
                "methods": ["password"],
                "expires_at": "2026-11-25T12:00:00Z", "issued_at": "2026-11-25T11:00:00Z",
                "user": {"id": "0123456789abcdef0123456789abcdef", "name": "u",
                         "domain": {"id": "default", "name": "Default"}},
                "project": {"id": "fedcba9876543210fedcba9876543210", "name": "p",
                            "domain": {"id": "default", "name": "Default"}},
                "roles": [{"id": "r1", "name": "admin"}, {"id": "r2", "name": "member"},
                          {"id": "r3", "name": "reader"}]
            }}
        });
        let mut token_owner = token_admin.clone();
        token_owner["credentials"]["roles"] = json!(["member"]);
        let mut token_deny = token_owner.clone();
        token_deny["credentials"]["user_id"] = json!("someoneelse");
        g.bench_function("evaluate token show, admin (allow first rule)", |b| {
            b.iter(|| enforcer.evaluate("identity/auth/token/show", black_box(token_admin.clone())))
        });
        g.bench_function("evaluate token show, owner (allow last rule)", |b| {
            b.iter(|| enforcer.evaluate("identity/auth/token/show", black_box(token_owner.clone())))
        });
        g.bench_function("evaluate token show, deny", |b| {
            b.iter(|| enforcer.evaluate("identity/auth/token/show", black_box(token_deny.clone())))
        });
        // Full production path: serialize the input to a JSON string, parse it
        // into the regorus value and evaluate (`enforce_serialized` without the
        // credentials conversion and the metrics).
        g.bench_function("full path token show, admin", |b| {
            b.iter(|| {
                let input = serde_json::to_string(black_box(&token_admin)).expect("serialize");
                enforcer.evaluate_json("identity/auth/token/show", &input)
            })
        });
        // A policy with a `violation` rule: `evaluate` also evaluates it on allow,
        // `evaluate_json` does not.
        let project_admin = json!({
            "credentials": {"roles": ["admin"], "is_admin": true, "system": "all",
                "domain_id": null, "project_id": "p", "user_id": "u"},
            "target": null,
            "existing": {"project": {"id": "p", "domain_id": "d"}}
        });
        g.bench_function("evaluate project show allow (violation on allow)", |b| {
            b.iter(|| {
                enforcer.evaluate(
                    "identity/resource/project/show",
                    black_box(project_admin.clone()),
                )
            })
        });
        g.bench_function("full path project show allow (violation skipped)", |b| {
            b.iter(|| {
                let input = serde_json::to_string(black_box(&project_admin)).expect("serialize");
                enforcer.evaluate_json("identity/resource/project/show", &input)
            })
        });
        g.bench_function("clone input only (token admin)", |b| {
            b.iter(|| black_box(token_admin.clone()))
        });
        g.bench_function("load all policies", |b| {
            b.iter(|| RegorusPolicyEnforcer::new(&dir).expect("policies compile"))
        });
        g.finish();
    }
}

/// The complete flow a handler pays through the [`PolicyEnforcer`] trait:
/// credentials conversion, delegation pre-check, input serialization, parse,
/// evaluation and result handling. Current layout only: the layout comparison
/// is the engine level above.
///
/// `enforce` takes owned `serde_json` trees (what the mock and the HTTP
/// enforcer need), `enforce_serialized` borrows the caller's objects.
fn bench_trait(c: &mut Criterion) {
    let enforcer = RegorusPolicyEnforcer::new(&current_dir()).expect("policies compile");
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let vsc = test_fixture_scoped();
    let token = json!({"token": {
        "audit_ids": ["a1b2c3d4e5f60718293a4b5c6d7e8f"], "methods": ["password"],
        "expires_at": "2026-11-25T12:00:00Z", "issued_at": "2026-11-25T11:00:00Z",
        "user": {"id": "uid", "name": "u", "domain": {"id": "domain_id", "name": "d"}},
        "project": {"id": "project_id", "name": "p",
                    "domain": {"id": "domain_id", "name": "d"}},
        "roles": [{"id": "admin", "name": "admin"}]
    }});
    let project = json!({"project": {"id": "project_id", "domain_id": "domain_id"}});
    let role = json!({"role": {"id": "r", "domain_id": "domain_id"}});
    let cases = [
        ("identity/auth/token/show", &token),
        ("identity/resource/project/show", &project),
        ("identity/role/show", &role),
    ];
    let mut g = c.benchmark_group("trait");
    for (policy, existing) in cases {
        // A denial would measure the error path: fail loudly instead.
        rt.block_on(enforcer.enforce(policy, &vsc, json!(null), Some(existing.clone())))
            .unwrap_or_else(|e| panic!("`{policy}` must allow the fixture: {e}"));
        g.bench_function(format!("enforce {policy}"), |b| {
            b.iter(|| {
                rt.block_on(enforcer.enforce(
                    policy,
                    black_box(&vsc),
                    json!(null),
                    Some(black_box(existing).clone()),
                ))
            })
        });
        g.bench_function(format!("enforce_serialized {policy}"), |b| {
            b.iter(|| {
                rt.block_on(enforcer.enforce_serialized(
                    policy,
                    black_box(&vsc),
                    &(),
                    Some(black_box(existing)),
                ))
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench, bench_trait);
criterion_main!(benches);
