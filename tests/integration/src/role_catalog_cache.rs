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
//! Driver-side caches of the role and catalog drivers on the real backend.
//!
//! A *foreign* write is a raw statement: it bypasses the driver, so only the
//! table watermark can tell. The reads are linearizable, so every committed
//! write must be visible to the next read, and an unchanged table must be
//! served without resolving the data again.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use eyre::Result;
use sea_orm::ConnectionTrait;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::{EndpointCreate, ServiceCreate};
use openstack_keystone_core_types::role::{RoleInference, RoleListParameters};

use crate::catalog::{create_endpoint, create_service};
use crate::common::get_state;
use crate::create_role;

fn rule_target(inference: &RoleInference, prior: &str) -> BTreeSet<String> {
    inference
        .implied(prior)
        .iter()
        .map(|r| r.id.clone())
        .collect()
}

async fn inference(state: &ServiceState) -> Result<Arc<RoleInference>> {
    Ok(state
        .provider
        .get_role_provider()
        .get_role_inference(&ExecutionContext::internal(state))
        .await?)
}

async fn imply(state: &ServiceState, prior: &str, implied: &str) -> Result<()> {
    state
        .provider
        .get_role_provider()
        .create_role_imply_rule(&ExecutionContext::internal(state), prior, implied)
        .await?;
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_role_inference_is_resolved_once_and_follows_every_write() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    state.db.watermarks().configure(Duration::from_secs(1));
    let a = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let b = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let c = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let d = create_role!(state, Uuid::new_v4().simple().to_string())?;
    imply(&state, &a.id, &b.id).await?;
    imply(&state, &b.id, &c.id).await?;

    let first = inference(&state).await?;
    assert_eq!(
        BTreeSet::from([b.id.clone(), c.id.clone()]),
        rule_target(&first, &a.id)
    );
    assert_eq!(
        Some(b.name.as_str()),
        first
            .implied(&a.id)
            .iter()
            .find(|role| role.id == b.id)
            .and_then(|role| role.name.as_deref())
    );
    assert!(
        Arc::ptr_eq(&first, &inference(&state).await?),
        "unchanged tables: the resolved inference is shared, not recalculated"
    );

    // A write of this process is visible at once.
    imply(&state, &c.id, &d.id).await?;
    let second = inference(&state).await?;
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(
        BTreeSet::from([b.id.clone(), c.id.clone(), d.id.clone()]),
        rule_target(&second, &a.id)
    );

    // A foreign write is noticed through the watermark.
    db.execute_unprepared(&format!(
        "DELETE FROM implied_role WHERE prior_role_id = '{}'",
        b.id
    ))
    .await?;
    let third = inference(&state).await?;
    assert_eq!(BTreeSet::from([b.id.clone()]), rule_target(&third, &a.id));
    assert!(Arc::ptr_eq(&third, &inference(&state).await?));

    // A foreign rename is part of the resolved closure.
    db.execute_unprepared(&format!(
        "UPDATE role SET name = 'renamed' WHERE id = '{}'",
        b.id
    ))
    .await?;
    assert_eq!(
        Some("renamed"),
        inference(&state).await?.implied(&a.id)[0].name.as_deref()
    );
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_role_names_follow_foreign_writes() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    state.db.watermarks().configure(Duration::from_secs(1));
    let a = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let b = create_role!(state, Uuid::new_v4().simple().to_string())?;
    let names = || async {
        let ctx = ExecutionContext::internal(&state);
        let mut roles = state
            .provider
            .get_role_provider()
            .list_roles(
                &ctx,
                &RoleListParameters {
                    ids: Some(vec![a.id.clone(), b.id.clone()]),
                    skip_options: true,
                    ..Default::default()
                },
            )
            .await?;
        roles.sort_by(|x, y| x.id.cmp(&y.id));
        Ok::<_, eyre::Report>(
            roles
                .into_iter()
                .map(|r| (r.id, r.name))
                .collect::<Vec<_>>(),
        )
    };
    let before = names().await?;
    assert_eq!(2, before.len());
    assert_eq!(before, names().await?);

    db.execute_unprepared(&format!(
        "UPDATE role SET name = 'renamed' WHERE id = '{}'",
        a.id
    ))
    .await?;
    let after = names().await?;
    assert!(
        after
            .iter()
            .any(|(id, name)| *id == a.id && name == "renamed")
    );
    assert!(
        after
            .iter()
            .any(|(id, name)| *id == b.id && *name == b.name)
    );

    // A deleted role is gone from the next read.
    db.execute_unprepared(&format!("DELETE FROM role WHERE id = '{}'", b.id))
        .await?;
    assert_eq!(1, names().await?.len());
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_catalog_follows_foreign_writes() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    state.db.watermarks().configure(Duration::from_secs(1));
    let service = create_service(
        &state,
        ServiceCreate {
            enabled: true,
            extra: Default::default(),
            id: None,
            r#type: Some("compute".to_string()),
        },
    )
    .await?;
    // A service without an endpoint is not part of the catalog.
    let _endpoint = create_endpoint(
        &state,
        EndpointCreate {
            enabled: true,
            extra: Default::default(),
            id: None,
            interface: "public".to_string(),
            region_id: None,
            service_id: service.id.clone(),
            url: "http://localhost:8774".to_string(),
        },
    )
    .await?;
    let listed = |enabled: bool| {
        let state = state.clone();
        let id = service.id.clone();
        async move {
            let catalog = state
                .provider
                .get_catalog_provider()
                .get_catalog(&ExecutionContext::internal(&state), enabled)
                .await?;
            Ok::<_, eyre::Report>(catalog.iter().any(|(s, _)| s.id == id))
        }
    };
    assert!(listed(true).await?);
    assert!(listed(true).await?);

    db.execute_unprepared(&format!(
        "UPDATE service SET enabled = FALSE WHERE id = '{}'",
        service.id
    ))
    .await?;
    db.execute_unprepared(&format!(
        "UPDATE endpoint SET enabled = FALSE WHERE service_id = '{}'",
        service.id
    ))
    .await?;
    assert!(!listed(true).await?, "a foreign write must be visible");
    assert!(listed(false).await?);
    Ok(())
}
