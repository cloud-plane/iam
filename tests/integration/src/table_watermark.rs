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
//
// SPDX-License-Identifier: Apache-2.0
//! Table version watermarks on the real backend.
//!
//! The triggers are backend specific (statement level on PostgreSQL, row
//! level on MySQL and SQLite), so these tests run against whatever
//! `DATABASE_URL` points to.

use std::time::Duration;

use eyre::Result;
use sea_orm::{ConnectionTrait, DatabaseBackend, TransactionTrait};
use tracing_test::traced_test;

use openstack_keystone_core::table_watermark::{IDENTITY_TABLES, PROJECT_TABLES, TableWatermarks};

use crate::common::get_state;
use crate::{create_domain, create_project};

fn registry() -> TableWatermarks {
    let wm = TableWatermarks::new();
    wm.configure(Duration::from_secs(1));
    wm
}

async fn stamps(wm: &TableWatermarks, db: &sea_orm::DatabaseConnection) -> [u64; 2] {
    wm.poll(db).await.unwrap();
    [PROJECT_TABLES, IDENTITY_TABLES]
        .map(|tables| wm.stamp(tables).expect("counters of the watched tables"))
}

/// A raw `INSERT` of a project into a domain that is created raw as well.
///
/// The domain is a row of its own: a project that is its own domain
/// references itself and MySQL cannot delete such a row, and a domain created
/// by the provider is followed by asynchronous writes (hooks) that would move
/// the counters in the middle of a test.
async fn project_insert(
    state: &openstack_keystone_core::keystone::ServiceState,
) -> Result<&'static str> {
    state
        .db
        .connection()
        .execute_unprepared(
            "INSERT INTO project (id, name, domain_id, is_domain, enabled, extra) \
             VALUES ('wm-dom', 'wm-dom', 'wm-dom', true, true, '{}')",
        )
        .await?;
    Ok(
        "INSERT INTO project (id, name, domain_id, is_domain, enabled, extra) \
        VALUES ('wm-raw', 'wm-raw', 'wm-dom', false, true, '{}')",
    )
}

/// An `UPDATE` of the row [`project_insert`] creates. An insert into `project`
/// does not move the counter (`INSERT_NEUTRAL_TABLES`), an update does.
const UPDATE_PROJECT: &str = "UPDATE project SET description = 'changed' WHERE id = 'wm-raw'";

/// Create the row and change it: a committed write that moves the counter of
/// `project` on every backend.
async fn write_project(db: &impl ConnectionTrait, insert: &str) -> Result<()> {
    db.execute_unprepared(insert).await?;
    db.execute_unprepared(UPDATE_PROJECT).await?;
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_provider_writes_move_only_their_watermark() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    let wm = registry();
    let [project, identity] = stamps(&wm, &db).await;

    let domain = create_domain!(state)?;
    let created = create_project!(state, domain.id.clone())?;
    let [project_1, identity_1] = stamps(&wm, &db).await;
    assert_eq!(
        project, project_1,
        "creating a project is insert neutral: other entries stay valid"
    );
    assert_eq!(identity, identity_1);

    state
        .provider
        .get_resource_provider()
        .delete_project(
            &openstack_keystone_core::auth::ExecutionContext::internal(&state),
            &created.id,
        )
        .await?;
    let [project_2, identity_2] = stamps(&wm, &db).await;
    assert!(project_2 > project_1);
    assert_eq!(identity, identity_2);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_raw_statements_move_the_watermark() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let insert = project_insert(&state).await?;
    let db = state.db.connection();
    let wm = registry();
    let mut last = stamps(&wm, &db).await[0];

    // A new row of `project` changes no cached entry: it does not move the
    // counter.
    db.execute_unprepared(&insert).await?;
    assert_eq!(last, stamps(&wm, &db).await[0], "an insert is neutral");

    for sql in [UPDATE_PROJECT, "DELETE FROM project WHERE id = 'wm-raw'"] {
        db.execute_unprepared(sql).await?;
        let now = stamps(&wm, &db).await[0];
        assert!(now > last, "`{sql}` did not move the watermark");
        last = now;
    }

    // A statement touching no row does not have to move it (statement
    // level triggers do, row level ones do not); it must never go backwards.
    db.execute_unprepared("DELETE FROM project WHERE id = 'wm-none'")
        .await?;
    assert!(stamps(&wm, &db).await[0] >= last);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_rolled_back_write_is_not_visible() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let insert = project_insert(&state).await?;
    let db = state.db.connection();
    let wm = registry();
    let before = stamps(&wm, &db).await;

    let txn = db.begin().await?;
    write_project(&txn, &insert).await?;
    txn.rollback().await?;

    assert_eq!(before, stamps(&wm, &db).await);
    write_project(&db, &insert).await?;
    assert!(stamps(&wm, &db).await[0] > before[0]);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_sync_sees_every_committed_write() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let insert = project_insert(&state).await?;
    let db = state.db.connection();
    let wm = registry();
    assert!(wm.sync(&db).await);
    let before = wm.stamp(PROJECT_TABLES).expect("synced");
    write_project(&db, &insert).await?;
    // No poll in between: the sync alone must observe the write.
    assert!(wm.sync(&db).await);
    assert!(wm.stamp(PROJECT_TABLES).expect("synced") > before);
    // A disabled registry never syncs.
    assert!(!TableWatermarks::new().sync(&db).await);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_truncate_moves_the_watermark_on_postgres() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let db = state.db.connection();
    if db.get_database_backend() != DatabaseBackend::Postgres {
        // MySQL does not fire triggers for TRUNCATE and SQLite has none.
        return Ok(());
    }
    let wm = registry();
    let before = stamps(&wm, &db).await[0];
    db.execute_unprepared("TRUNCATE project CASCADE").await?;
    assert!(stamps(&wm, &db).await[0] > before);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_setup_is_idempotent() -> Result<()> {
    use openstack_keystone_core::table_watermark::install;

    let (state, _tmp) = get_state().await?;
    let insert = project_insert(&state).await?;
    let db = state.db.connection();
    let wm = registry();
    let before = stamps(&wm, &db).await;
    // Installing again keeps the triggers. The counters never go back (the
    // backends that replace the triggers one by one move them forward).
    install(&db, IDENTITY_TABLES).await?;
    install(&db, PROJECT_TABLES).await?;
    let after = stamps(&wm, &db).await;
    assert!(after[0] >= before[0] && after[1] >= before[1]);
    let before = after;

    write_project(&db, &insert).await?;
    assert!(stamps(&wm, &db).await[0] > before[0]);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_table_exists_and_reinstall() -> Result<()> {
    use openstack_keystone_core::table_watermark::{VERSION_TABLE, table_exists, uninstall};

    let (state, _tmp) = get_state().await?;
    let insert = project_insert(&state).await?;
    let db = state.db.connection();
    // The check the migrations rely on, on every backend.
    assert!(table_exists(&db, "project").await?);
    assert!(table_exists(&db, VERSION_TABLE).await?);
    assert!(!table_exists(&db, "no_such_table").await?);

    // Down, then up again (a migration revert and re-apply).
    uninstall(&db, PROJECT_TABLES).await?;
    let wm = registry();
    wm.poll(&db).await?;
    assert!(wm.stamp(PROJECT_TABLES).is_none());
    db.execute_unprepared(&insert).await?;
    db.execute_unprepared("DELETE FROM project WHERE id = 'wm-raw'")
        .await?;

    openstack_keystone_core::table_watermark::install(&db, PROJECT_TABLES).await?;
    let before = stamps(&wm, &db).await[0];
    write_project(&db, &insert).await?;
    assert!(stamps(&wm, &db).await[0] > before);
    Ok(())
}
