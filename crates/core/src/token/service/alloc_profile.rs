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
//! Allocation profile of `GET /v3/auth/tokens`, the token validation request.
//!
//! Measures, one stage after the other, what the provider side of the request
//! costs for a project-scoped token with three roles:
//!
//! * the validation of the subject token (`validate_to_context`);
//! * the validation of the caller's own token (`authorize_request_token`);
//! * the conversions the handler and the drivers build from the validated
//!   context: revocation query parameters, the token response and the policy
//!   input.

use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use secrecy::SecretString;
use serde_json::Value;
use uuid::Uuid;

use openstack_keystone_api_types::v3::auth::token::TokenBuilder;
use openstack_keystone_core_types::assignment::*;
use openstack_keystone_core_types::identity::{UserCore, UserResponseBuilder};
use openstack_keystone_core_types::resource::*;
use openstack_keystone_core_types::revoke::RevocationEventListParametersBuilder;
use openstack_keystone_core_types::token::ProjectScopePayload;

use super::*;
use crate::alloc_profile::{
    AllocStats, assert_budget, measure, measure_async, quiet_tracing, report,
};
use crate::assignment::MockAssignmentProvider;
use crate::identity::MockIdentityProvider;
use crate::policy::{Credentials, PolicyInput};
use crate::provider::Provider;
use crate::resource::MockResourceProvider;
use crate::revoke::MockRevokeProvider;
use crate::tests::get_mocked_state;
use crate::token::backend::{MockTokenBackend, MockTokenRestrictionBackend};

const ROLES: [&str; 3] = ["member", "reader", "load-balancer_member"];

/// Allocation budgets per stage: the measured value plus about 10% of slack.
///
/// The figures include what the mocks return, which does not change with the
/// code under test. When a legitimate change needs more, re-measure with
/// `--nocapture` and raise the budget on purpose.
const BUDGETS: [(&str, u64); 7] = [
    ("mocked token decode (constant floor)", 8),
    ("validate_to_context (subject token)", 92),
    ("authorize_request_token (caller token)", 84),
    ("revocation query parameters", 18),
    ("token response build", 27),
    ("policy input: credentials", 20),
    ("policy input: whole document, borrowed", 10),
];

fn hex_id() -> String {
    Uuid::new_v4().simple().to_string()
}

fn project_scoped_token() -> FernetToken {
    FernetToken::ProjectScope(ProjectScopePayload {
        methods: vec!["password".into()],
        user_id: hex_id(),
        project_id: hex_id(),
        // A url-safe base64 encoded 16 bytes audit id, as real tokens carry.
        audit_ids: vec!["dkpM2xhJSlWwcxgcxu_EXw".into()],
        expires_at: Utc::now() + TimeDelta::hours(1),
        ..Default::default()
    })
}

/// The service state with every dependency of the token validation mocked.
async fn mocked_state(token: &FernetToken, config: &Config) -> ServiceState {
    let mut revoke_mock = MockRevokeProvider::default();
    revoke_mock
        .expect_is_token_revoked()
        .returning(|_, _| Ok(false));

    let mut identity_mock = MockIdentityProvider::default();
    identity_mock.expect_get_user().returning(|_, id: &'_ str| {
        Ok(Some(
            UserResponseBuilder::default()
                .domain_id("user_domain_id")
                .enabled(true)
                .name("name")
                .id(id)
                .build()
                .unwrap(),
        ))
    });
    identity_mock.expect_get_user_core().returning(|_, id| {
        Ok(Some(UserCore {
            id: id.to_string(),
            domain_id: "user_domain_id".into(),
            enabled: true,
        }))
    });

    let mut resource_mock = MockResourceProvider::default();
    resource_mock.expect_get_domain_ref().returning(|_, id| {
        Ok(Some(DomainRef {
            id: id.to_string(),
            name: "domain".to_string(),
            enabled: true,
        }))
    });
    let project_id = token.project_id().unwrap().clone();
    resource_mock
        .expect_get_project_ref()
        .returning(move |_, _| {
            Ok(Some(ProjectRef {
                id: project_id.clone(),
                name: "project".to_string(),
                enabled: true,
                ..Default::default()
            }))
        });

    let mut assignment_mock = MockAssignmentProvider::default();
    assignment_mock.expect_list_role_assignments().returning(
        |_, q: &RoleAssignmentListParameters| {
            Ok(ROLES
                .iter()
                .map(|name| Assignment {
                    role_id: hex_id(),
                    role_name: Some((*name).to_string()),
                    actor_id: q.user_id.clone().unwrap(),
                    target_id: q.project_id.clone().unwrap(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                })
                .collect())
        },
    );

    let provider = Provider::mocked_builder()
        .mock_assignment(assignment_mock)
        .mock_identity(identity_mock)
        .mock_revoke(revoke_mock)
        .mock_resource(resource_mock);
    get_mocked_state(Some(config.clone()), Some(provider)).await
}

/// Run every stage once and return their figures.
async fn run_stages(
    service: &TokenService,
    state: &ServiceState,
) -> Vec<(&'static str, AllocStats)> {
    let ctx = ExecutionContext::internal(state);
    let bearer = SecretString::from("token".to_string());
    let mut stages = Vec::new();

    let (_, stats) = measure(|| service.backend_driver.decode("token"));
    stages.push(("mocked token decode (constant floor)", stats));

    let (vsc, stats) = measure_async(service.validate_to_context(&ctx, "token", None, None)).await;
    let vsc = vsc.unwrap();
    stages.push(("validate_to_context (subject token)", stats));

    let (_, stats) = measure_async(service.authorize_request_token(&ctx, &bearer)).await;
    stages.push(("authorize_request_token (caller token)", stats));

    let (_, stats) = measure(|| {
        RevocationEventListParametersBuilder::try_from(&vsc)
            .unwrap()
            .build()
            .unwrap()
    });
    stages.push(("revocation query parameters", stats));

    let (token_response, stats) =
        measure(|| TokenBuilder::try_from(&vsc).unwrap().build().unwrap());
    stages.push(("token response build", stats));

    let (credentials, stats) = measure(|| Credentials::try_from(&vsc).unwrap());
    stages.push(("policy input: credentials", stats));

    // What the enforcers do: serialize the borrowed credentials, target and
    // existing objects into the document handed to the policy engine. Unlike
    // a `serde_json::Value` tree it does not depend on the `serde_json`
    // features other crates of the workspace switch on.
    let (_, stats) = measure(|| {
        serde_json::to_string(&PolicyInput {
            credentials: &credentials,
            target: &Value::Null,
            existing: Some(&crate::policy_object!({"token": token_response})),
        })
        .unwrap()
    });
    stages.push(("policy input: whole document, borrowed", stats));

    stages
}

#[tokio::test]
async fn alloc_profile_token_validation() {
    let _quiet = quiet_tracing();
    let token = project_scoped_token();
    let config = super::super::tests::setup_config();
    let mut backend = MockTokenBackend::default();
    let decoded = token.clone();
    backend
        .expect_decode()
        .returning(move |_| Ok(decoded.clone()));
    let service = TokenService {
        config: config.clone(),
        backend_driver: Arc::new(backend),
        tr_backend_driver: Arc::new(MockTokenRestrictionBackend::default()),
    };
    let state = mocked_state(&token, &config).await;

    // The first pass initialises lazily created statics and is not measured.
    run_stages(&service, &state).await;
    let stages = run_stages(&service, &state).await;

    for (label, stats) in &stages {
        let (_, budget) = BUDGETS
            .iter()
            .find(|(name, _)| name == label)
            .unwrap_or_else(|| panic!("no allocation budget for the stage `{label}`"));
        assert_budget(label, stats, *budget);
    }
    let total = stages
        .iter()
        .skip(1)
        .fold(AllocStats::default(), |acc, (_, s)| AllocStats {
            allocs: acc.allocs + s.allocs,
            bytes: acc.bytes + s.bytes,
            peak_bytes: acc.peak_bytes.max(s.peak_bytes),
        });
    report("TOTAL (all stages above, without the floor)", &total);
}
