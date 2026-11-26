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
//! # Table version watermarks
//!
//! A driver that caches *projections* of its tables (see
//! [`crate::projection_cache`]) needs to know whether the tables changed since
//! it loaded a value, without reading them. This module provides that with a
//! *watermark* per table:
//!
//! - the `table_version` table holds one counter per watched table;
//! - database triggers (installed by [`install`]) bump the counter on every
//!   `INSERT`, `UPDATE` and `DELETE` of the watched table, in the same
//!   transaction as the change;
//! - [`spawn`] polls the whole `table_version` table with one cheap query per
//!   interval and publishes the counters into [`TableWatermarks`];
//! - a cache remembers [`TableWatermarks::stamp`] of its tables when the
//!   value was loaded and serves the value for as long as the stamp is
//!   unchanged.
//!
//! A reader that tolerates staleness validates against the polled counters
//! (staleness bounded by the poll interval). A *linearizable* reader first
//! calls [`TableWatermarks::sync`]: one `SELECT` of the counter table, shared
//! between concurrent readers, instead of one query per cached fact. The
//! entry is served only if the counters are unchanged, so an unchanged
//! table costs one cheap query rather than several.
//!
//! While the poller is not healthy (disabled, never polled, failing,
//! triggers not installed) [`TableWatermarks::stamp`] returns `None` and the
//! caches read through, so the feature can only ever tighten the staleness.
//!
//! ## Trigger flavours
//!
//! | Backend    | Triggers per table                                    |
//! | ---------- | ----------------------------------------------------- |
//! | PostgreSQL | one `FOR EACH STATEMENT` trigger (also `TRUNCATE`)    |
//! | MySQL      | three `FOR EACH ROW` triggers (no statement triggers) |
//! | SQLite     | three `FOR EACH ROW` triggers (no statement triggers) |
//!
//! `TRUNCATE` does not fire triggers in MySQL and SQLite has none. Creating
//! triggers on MySQL with binary logging enabled requires the `TRIGGER`
//! privilege and, without `SUPER`, `log_bin_trust_function_creators=1`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use sea_orm::sea_query::{Alias, ColumnDef, Table};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement};
use tracing::{debug, info, warn};

use openstack_keystone_core_types::freshness::Freshness;

use crate::error::{DatabaseError, DbContextExt};
use crate::keystone::ServiceState;

/// Name of the table holding the counters.
pub const VERSION_TABLE: &str = "table_version";

/// Tables the projections of the `project` row alone (the short project, the
/// domain of a project, its parents) depend on.
pub const PROJECT_ROW_TABLES: &[&str] = &["project"];

/// Tables a project with its options and tags is read from.
pub const PROJECT_TABLES: &[&str] = &["project", "project_option", "project_tag"];

/// The tolerance of the token validation path reads: what
/// `[database] projection_max_staleness_ms` allows (the config validator
/// caps it at 300000 ms); linearizable when unset.
pub fn validation_freshness(config: &openstack_keystone_config::Config) -> Freshness {
    match config.database.projection_max_staleness_ms {
        0 => Freshness::Linearizable,
        ms => Freshness::MaxStaleness(Duration::from_millis(ms)),
    }
}

/// Tables the identity driver caches projections of: the user options and
/// the passwords (only the expiry of the latest one; the hash is never
/// cached).
///
/// `local_user` is watched for the cache of the local user row (the name of
/// a user), which every request reads. A failed login rewrites the
/// authentication counters of the row and so moves the counter: that drops
/// the cached local users only, the other projections do not depend on it.
/// The counter has several rows, so concurrent logins do not queue on one
/// of them. A password row changes only through its own table.
///
/// The group tables back the cache of the groups of a user: a membership
/// changes rarely, unlike `local_user`. The `user` table backs the cache of
/// the user record; it is written by a successful authentication (the
/// `last_active_at` reset) and by the user management, not by token
/// validation.
pub const IDENTITY_TABLES: &[&str] = &[
    "user",
    "local_user",
    "nonlocal_user",
    "federated_user",
    "user_option",
    "password",
    "group",
    "user_group_membership",
    "expiring_user_group_membership",
];

/// The table the revocation driver caches the answer of the revocation
/// check for.
///
/// Revocation events are written when a token is revoked (a logout, a
/// password change, a role removal), not when it is validated, and removed
/// by the periodic cleanup.
pub const REVOCATION_TABLES: &[&str] = &["revocation_event"];

/// Tables the assignment driver caches the role assignments of.
pub const ASSIGNMENT_TABLES: &[&str] = &["assignment", "system_assignment"];

/// Tables the role driver caches projections of: the names of the roles and
/// the imply rules the inference is resolved from.
pub const ROLE_TABLES: &[&str] = &["role", "implied_role", "role_option"];

/// Tables the catalog driver caches the assembled catalog of.
pub const CATALOG_TABLES: &[&str] = &["service", "endpoint"];

/// Tables whose counter ignores inserts.
///
/// Every cache over these tables holds rows that exist (a missing row is
/// never cached), and a new row changes none of them: an insert must not
/// drop the entries of the other rows. Updates and deletes still do. Adding
/// a cache of a list or of an absence over one of these tables breaks this
/// rule.
///
/// `project`: a request creating a project must not make every other
/// request read its project again. `local_user`: a new user changes no
/// cached local user. `role`: a new role is in no imply rule yet, so it
/// changes neither the names of the other roles nor the resolved inference,
/// which is built from the rules (`implied_role`, whose inserts do move its
/// counter).
pub const INSERT_NEUTRAL_TABLES: &[&str] = &["project", "local_user", "role"];

/// Whether a new row of `table` moves its counter.
fn bumps_on_insert(table: &str) -> bool {
    !INSERT_NEUTRAL_TABLES.contains(&table)
}

/// Number of counter rows per watched table.
///
/// A trigger bumps one of them, so concurrent writers of a table do not queue
/// on one row lock until their transaction ends (see
/// [`PG_FUNCTION`]). The counter of a table is the sum of its rows.
pub const COUNTER_SHARDS: usize = 8;

/// Longest a counter read may take. A hung database must not stall the
/// readers queued behind the poller (the caches fall back to the database).
const POLL_TIMEOUT: Duration = Duration::from_secs(3);

/// Poll interval used while the poller is disabled to notice a
/// configuration change.
const DISABLED_RECHECK: Duration = Duration::from_secs(5);

/// The poller is considered unhealthy once its last successful poll is older
/// than this many intervals.
const HEALTHY_INTERVALS: u64 = 3;

/// Lower bound of the health window, so a very short interval does not flap
/// on a slow poll.
const MIN_HEALTH_WINDOW_MS: u64 = 1000;

// ----------------------------------------------------------------------
// Installation (DDL)
// ----------------------------------------------------------------------

/// Reject names that could not be used as plain, unquoted identifiers. The
/// names come from constants, but they are interpolated into DDL.
fn check_identifier(name: &str) -> Result<(), DatabaseError> {
    if !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    {
        Ok(())
    } else {
        Err(DatabaseError::Sql {
            message: format!("`{name}` is not a valid table name for a watermark trigger"),
            context: "installing table watermark".to_string(),
        })
    }
}

/// Reject backends without trigger support in this module.
fn check_backend(backend: DatabaseBackend) -> Result<(), DatabaseError> {
    match backend {
        DatabaseBackend::Postgres | DatabaseBackend::MySql | DatabaseBackend::Sqlite => Ok(()),
        other => Err(DatabaseError::Sql {
            message: format!("table watermarks are not supported on {other:?}"),
            context: "installing table watermark".to_string(),
        }),
    }
}

/// Statement that increments the counter of `table`.
fn bump_sql(table: &str) -> String {
    format!("UPDATE {VERSION_TABLE} SET version = version + 1 WHERE table_name = '{table}'")
}

/// The per-event triggers of `table` on the backends without multi-event
/// triggers: the suffix of the trigger name and the event.
fn trigger_events(table: &str) -> Vec<(&'static str, &'static str)> {
    let mut events = Vec::new();
    if bumps_on_insert(table) {
        events.push(("ins", "INSERT"));
    }
    events.push(("upd", "UPDATE"));
    events.push(("del", "DELETE"));
    events
}

/// The statements that create the triggers bumping the counter of `table`.
///
/// Every statement is idempotent: an existing trigger is dropped first.
pub fn create_trigger_statements(backend: DatabaseBackend, table: &str) -> Vec<String> {
    let mut statements = drop_trigger_statements(backend, table);
    match backend {
        DatabaseBackend::Postgres => {
            let events = if bumps_on_insert(table) {
                "INSERT OR UPDATE OR DELETE OR TRUNCATE"
            } else {
                "UPDATE OR DELETE OR TRUNCATE"
            };
            statements.push(format!(
                "CREATE TRIGGER wm_{table} AFTER {events} \
                 ON \"{table}\" FOR EACH STATEMENT EXECUTE PROCEDURE keystone_bump_table_version('{table}')"
            ));
        }
        DatabaseBackend::MySql => {
            // A random counter row, so concurrent writers rarely queue on
            // the same row lock.
            let counters = counter_names(table)
                .iter()
                .map(|counter| format!("'{counter}'"))
                .collect::<Vec<_>>()
                .join(", ");
            // The counter is picked once into a variable. `RAND()` in the
            // `WHERE` of the `UPDATE` would be evaluated again for every row
            // of `table_version`: each of them would match with a probability
            // of `1 / COUNTER_SHARDS` and the write bumped no counter at all
            // in about a third of the cases.
            let bump = format!(
                "BEGIN DECLARE counter VARCHAR(64); \
                 SET counter = ELT(FLOOR(RAND() * {COUNTER_SHARDS}) + 1, {counters}); \
                 UPDATE {VERSION_TABLE} SET version = version + 1 \
                 WHERE table_name = counter; END"
            );
            for (suffix, event) in trigger_events(table) {
                statements.push(format!(
                    "CREATE TRIGGER wm_{table}_{suffix} AFTER {event} ON `{table}` \
                     FOR EACH ROW {bump}"
                ));
            }
        }
        DatabaseBackend::Sqlite => {
            for (suffix, event) in trigger_events(table) {
                statements.push(format!(
                    "CREATE TRIGGER wm_{table}_{suffix} AFTER {event} ON \"{table}\" \
                     FOR EACH ROW BEGIN {}; END",
                    bump_sql(table)
                ));
            }
        }
        // Rejected by `check_backend` before any statement is run.
        _ => {}
    }
    statements
}

/// The statements that drop the triggers of `table` (when present).
pub fn drop_trigger_statements(backend: DatabaseBackend, table: &str) -> Vec<String> {
    match backend {
        DatabaseBackend::Postgres => {
            vec![format!("DROP TRIGGER IF EXISTS wm_{table} ON \"{table}\"")]
        }
        DatabaseBackend::MySql | DatabaseBackend::Sqlite => ["ins", "upd", "del"]
            .iter()
            .map(|suffix| format!("DROP TRIGGER IF EXISTS wm_{table}_{suffix}"))
            .collect(),
        _ => Vec::new(),
    }
}

/// Names of the counter rows of `table`: the table name itself and
/// `table:1` .. `table:N-1`.
pub fn counter_names(table: &str) -> Vec<String> {
    (0..COUNTER_SHARDS)
        .map(|shard| {
            if shard == 0 {
                table.to_string()
            } else {
                format!("{table}:{shard}")
            }
        })
        .collect()
}

/// The table a counter row belongs to.
fn counter_table(counter: &str) -> &str {
    counter.split(':').next().unwrap_or(counter)
}

/// The PostgreSQL trigger function shared by all the watched tables.
///
/// It bumps a random counter row of the table that no other transaction has
/// locked (`SKIP LOCKED`), so writers neither wait for each other nor
/// deadlock on the counters. Only when every row is locked it falls back to
/// waiting for the base row. A table without counter rows is not counted.
const PG_FUNCTION: &str = "CREATE OR REPLACE FUNCTION keystone_bump_table_version() \
     RETURNS trigger LANGUAGE plpgsql AS $$ \
     DECLARE counter text; \
     BEGIN \
     SELECT table_name INTO counter FROM table_version \
     WHERE table_name = TG_ARGV[0] \
     OR left(table_name, length(TG_ARGV[0]) + 1) = TG_ARGV[0] || ':' \
     ORDER BY random() LIMIT 1 FOR UPDATE SKIP LOCKED; \
     UPDATE table_version SET version = version + 1 \
     WHERE table_name = COALESCE(counter, TG_ARGV[0]); \
     RETURN NULL; END $$";

/// The leader of a shared counter read. On drop it releases the lock and then
/// wakes the followers, also when the leader's future is dropped mid-read
/// (client disconnect, timeout): they elect a new leader instead of waiting
/// forever.
struct SyncLeader<'a> {
    guard: Option<tokio::sync::MutexGuard<'a, ()>>,
    done: &'a tokio::sync::Notify,
}

impl Drop for SyncLeader<'_> {
    fn drop(&mut self) {
        // Release first: a woken follower must be able to take the lock.
        self.guard.take();
        self.done.notify_waiters();
    }
}

/// Serializes concurrent installers (replicas starting together).
const PG_INSTALL_LOCK: i64 = 4_747_001;

/// Create the `table_version` table (when missing).
async fn ensure_version_table<C: ConnectionTrait>(conn: &C) -> Result<(), DatabaseError> {
    let stmt = Table::create()
        .table(Alias::new(VERSION_TABLE))
        .if_not_exists()
        .col(
            ColumnDef::new(Alias::new("table_name"))
                .string_len(64)
                .not_null()
                .primary_key(),
        )
        .col(
            ColumnDef::new(Alias::new("version"))
                .big_integer()
                .not_null()
                .default(0),
        )
        .to_owned();
    conn.execute(&stmt)
        .await
        .context("creating the table_version table")?;
    Ok(())
}

/// The statement that creates the counter row of `table` unless it exists.
///
/// Written out per backend: sea-query renders `do_nothing()` as the invalid
/// `ON DUPLICATE KEY IGNORE` on MySQL.
///
/// The counter starts at the current Unix time in milliseconds rather than at
/// a small constant: after an uninstall/install cycle or a rebuilt
/// `table_version` table it then cannot count up to a value that an older
/// cache entry was stamped with.
pub fn seed_counter_statement(backend: DatabaseBackend, table: &str) -> String {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(1);
    match backend {
        DatabaseBackend::MySql => {
            format!(
                "INSERT IGNORE INTO {VERSION_TABLE} (table_name, version) VALUES ('{table}', {seed})"
            )
        }
        _ => format!(
            "INSERT INTO {VERSION_TABLE} (table_name, version) VALUES ('{table}', {seed}) \
             ON CONFLICT (table_name) DO NOTHING"
        ),
    }
}

/// Install the watermark of the `tables`: the `table_version` table, a
/// counter row and the triggers.
///
/// The tables must exist. The call is idempotent and is made from both the
/// `SqlDriver::setup` of a driver (fresh databases) and its migration
/// (upgraded databases).
pub async fn install<C: ConnectionTrait>(conn: &C, tables: &[&str]) -> Result<(), DatabaseError> {
    for table in tables {
        check_identifier(table)?;
    }
    let backend = conn.get_database_backend();
    check_backend(backend)?;
    ensure_version_table(conn).await?;
    let mut statements = Vec::new();
    for table in tables {
        for counter in counter_names(table) {
            statements.push(seed_counter_statement(backend, &counter));
        }
        statements.extend(create_trigger_statements(backend, table));
    }
    if backend == DatabaseBackend::Postgres {
        // One batch is one implicit transaction: concurrent installers are
        // serialized by the lock and no write slips in between the DROP and
        // the CREATE of a trigger.
        let mut batch = format!("SELECT pg_advisory_xact_lock({PG_INSTALL_LOCK}); {PG_FUNCTION}");
        for statement in &statements {
            batch.push_str("; ");
            batch.push_str(statement);
        }
        conn.execute_unprepared(&batch)
            .await
            .context("installing the table watermark")?;
        return Ok(());
    }
    for statement in statements {
        conn.execute_unprepared(&statement)
            .await
            .context("installing the table watermark")?;
    }
    // The triggers were dropped and created one by one: a write that
    // committed in between bumped nothing. Move every counter so that no
    // entry stamped during the window stays valid.
    let counters = tables
        .iter()
        .flat_map(|table| counter_names(table))
        .map(|counter| format!("'{counter}'"))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute_unprepared(&format!(
        "UPDATE {VERSION_TABLE} SET version = version + 1 WHERE table_name IN ({counters})"
    ))
    .await
    .context("moving the table watermark")?;
    Ok(())
}

/// Remove the triggers and the counters of the `tables`.
pub async fn uninstall<C: ConnectionTrait>(conn: &C, tables: &[&str]) -> Result<(), DatabaseError> {
    for table in tables {
        check_identifier(table)?;
    }
    let backend = conn.get_database_backend();
    check_backend(backend)?;
    for table in tables {
        for statement in drop_trigger_statements(backend, table) {
            conn.execute_unprepared(&statement)
                .await
                .context("dropping the watermark trigger")?;
        }
        let counters = counter_names(table)
            .iter()
            .map(|counter| format!("'{counter}'"))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute_unprepared(&format!(
            "DELETE FROM {VERSION_TABLE} WHERE table_name IN ({counters})"
        ))
        .await
        .context("removing the table_version counter")?;
    }
    Ok(())
}

/// SQL that returns a row when the table `table` exists.
fn table_exists_statement(backend: DatabaseBackend, table: &str) -> String {
    match backend {
        DatabaseBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = '{table}'"
        ),
        DatabaseBackend::MySql => format!(
            "SELECT 1 FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_name = '{table}'"
        ),
        _ => format!("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '{table}'"),
    }
}

/// Whether the table exists in the current schema.
pub async fn table_exists<C: ConnectionTrait>(conn: &C, table: &str) -> Result<bool, DbErr> {
    let backend = conn.get_database_backend();
    let sql = table_exists_statement(backend, table);
    Ok(conn
        .query_one_raw(Statement::from_string(backend, sql))
        .await?
        .is_some())
}

/// [`install`] for a migration. Tables that do not exist (yet) are skipped:
/// on a database created by `keystone-manage db sync` the driver `setup`
/// installs them, and a deployment that does not use the driver has none.
pub async fn install_migration(
    manager: &sea_orm_migration::SchemaManager<'_>,
    tables: &[&str],
) -> Result<(), DbErr> {
    let mut present = Vec::new();
    for table in tables {
        if table_exists(manager.get_connection(), table).await? {
            present.push(*table);
        }
    }
    install(manager.get_connection(), &present)
        .await
        .map_err(|err| DbErr::Custom(err.to_string()))
}

/// [`uninstall`] for a migration.
pub async fn uninstall_migration(
    manager: &sea_orm_migration::SchemaManager<'_>,
    tables: &[&str],
) -> Result<(), DbErr> {
    if !table_exists(manager.get_connection(), VERSION_TABLE).await? {
        return Ok(());
    }
    uninstall(manager.get_connection(), tables)
        .await
        .map_err(|err| DbErr::Custom(err.to_string()))
}

// ----------------------------------------------------------------------
// Runtime registry
// ----------------------------------------------------------------------

/// Milliseconds since the process-local epoch.
fn now_ms() -> u64 {
    static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
    u64::try_from(EPOCH.elapsed().as_millis()).unwrap_or(u64::MAX)
}

tokio::task_local! {
    /// The read scope of the request the current task serves.
    static READ_SCOPE: Arc<ReadScope>;
}

/// The linearization point of the reads of one request.
///
/// A linearizable read must see every write committed before it. Taken per
/// read, that costs a counter sync for each cache the request touches. A
/// request that enters a scope with [`ReadScope::run`] is linearizable as of
/// the scope's point instead: the first read syncs the counters and every
/// later read finds that snapshot (or a newer one) and skips its own sync.
///
/// A write moves the point forward ([`ReadScope::advance`]), so the reads that
/// follow it sync again and see it. [`crate::projection_cache::ProjectionCache`]
/// does that on its own whenever a driver invalidates it after a write; a
/// write to a table without such a cache calls [`ReadScope::advance`] itself.
///
/// The scope is task-local. Work spawned onto another task, or a request
/// that never entered a scope, keeps the sync-per-read behavior.
pub struct ReadScope {
    /// `now_ms()` of the linearization point. Strictly grows on every
    /// [`ReadScope::advance`].
    since: AtomicU64,
    /// `since + 1` of the point a sync of this scope already covered; `0`
    /// when there was none. The clock has millisecond resolution, so a
    /// snapshot read in the very millisecond of the point does not count as
    /// "after" it; the scope remembers its own sync instead.
    synced_for: AtomicU64,
}

impl ReadScope {
    /// Run `future` with a scope whose linearization point is now.
    pub async fn run<F: Future>(future: F) -> F::Output {
        let scope = Arc::new(Self {
            since: AtomicU64::new(now_ms()),
            synced_for: AtomicU64::new(0),
        });
        READ_SCOPE.scope(scope, future).await
    }

    /// Move the linearization point of the current scope to now.
    ///
    /// Call it after a write committed so the reads that follow see it. It
    /// does nothing outside a scope, where every read syncs anyway.
    pub fn advance() {
        let _ = READ_SCOPE.try_with(|scope| {
            // Strictly after the previous point, even within one millisecond.
            let mut current = scope.since.load(Ordering::Acquire);
            loop {
                let next = now_ms().max(current + 1);
                match scope.since.compare_exchange_weak(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => current = actual,
                }
            }
        });
    }

    /// The current scope and its point.
    fn current() -> Option<(Arc<Self>, u64)> {
        READ_SCOPE
            .try_with(|scope| (Arc::clone(scope), scope.since.load(Ordering::Acquire)))
            .ok()
    }

    /// The linearization point of the current scope, if any.
    #[cfg(test)]
    pub(crate) fn point() -> Option<u64> {
        READ_SCOPE
            .try_with(|scope| scope.since.load(Ordering::Acquire))
            .ok()
    }
}

/// The last observed counters of the watched tables.
pub struct TableWatermarks {
    versions: ArcSwap<HashMap<String, i64>>,
    /// `now_ms() + 1` of the last successful poll; `0` when there was none.
    last_ok: AtomicU64,
    /// Configured poll interval in milliseconds; `0` when disabled.
    interval_ms: AtomicU64,
    /// Whether the previous poll failed; used to log transitions only.
    failing: AtomicBool,
    /// `now_ms() + 1` of the moment the published counters were *read*; `0`
    /// when there was no poll. A write committed after it is not part of the
    /// counters, so `now - snapshot` bounds how stale they can be.
    snapshot_ms: AtomicU64,
    /// Bumped by [`Self::reset`]: a poll that started in an earlier epoch
    /// read another connection and must not publish.
    epoch: AtomicU64,
    /// Serializes the writers (publish, reset, mirror) so the epoch check and
    /// the stores of a publish are atomic with respect to a reset.
    write_lock: std::sync::Mutex<()>,
    /// Lets concurrent [`Self::sync`] calls share one counter read.
    sync_lock: tokio::sync::Mutex<()>,
    /// Wakes the callers waiting for the counter read of another caller, all
    /// at once (a queue on `sync_lock` would pass them through one by one).
    sync_done: tokio::sync::Notify,
    /// `snapshot`-style timestamp (`now_ms() + 1`) of the start of the last
    /// failed counter read; `0` when none failed.
    sync_failed_at: AtomicU64,
}

impl Default for TableWatermarks {
    fn default() -> Self {
        Self::new()
    }
}

impl TableWatermarks {
    /// Create an inactive registry: [`Self::stamp`] returns `None` until the
    /// poller is configured and has polled successfully.
    pub fn new() -> Self {
        Self {
            versions: ArcSwap::from_pointee(HashMap::new()),
            last_ok: AtomicU64::new(0),
            interval_ms: AtomicU64::new(0),
            failing: AtomicBool::new(false),
            snapshot_ms: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            write_lock: std::sync::Mutex::new(()),
            sync_lock: tokio::sync::Mutex::new(()),
            sync_done: tokio::sync::Notify::new(),
            sync_failed_at: AtomicU64::new(0),
        }
    }

    /// Set the poll interval; zero disables the watermarks.
    pub fn configure(&self, interval: Duration) {
        let ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        if self.interval_ms.swap(ms, Ordering::AcqRel) != ms && ms == 0 {
            // Counters of a disabled poller must not be trusted again.
            self.last_ok.store(0, Ordering::Release);
        }
    }

    /// Publish the counters of a successful poll.
    pub fn publish(&self, versions: HashMap<String, i64>) {
        self.publish_read_at(versions, now_ms());
    }

    /// Publish counters that were read at `read_at` (see [`now_ms`]).
    fn publish_read_at(&self, versions: HashMap<String, i64>, read_at: u64) {
        let epoch = self.epoch.load(Ordering::Acquire);
        self.publish_in_epoch(versions, read_at, epoch);
    }

    /// Publish counters read in `epoch`; dropped when a reset happened since.
    fn publish_in_epoch(&self, versions: HashMap<String, i64>, read_at: u64, epoch: u64) {
        let _guard = self.write_lock.lock();
        if self.epoch.load(Ordering::Acquire) != epoch {
            return;
        }
        // A slower poll must not replace newer counters.
        if self.snapshot_ms.load(Ordering::Acquire) > read_at + 1 {
            return;
        }
        self.versions.store(Arc::new(versions));
        self.snapshot_ms.store(read_at + 1, Ordering::Release);
        self.last_ok.store(now_ms() + 1, Ordering::Release);
    }

    /// Forget the published counters, e.g. after the connection was replaced
    /// by one that may point to another database.
    pub fn reset(&self) {
        let _guard = self.write_lock.lock();
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.last_ok.store(0, Ordering::Release);
        self.snapshot_ms.store(0, Ordering::Release);
        self.versions.store(Arc::new(HashMap::new()));
    }

    /// The configured poll interval; zero when the poller is disabled.
    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.load(Ordering::Acquire))
    }

    /// How long ago the published counters were read.
    pub fn snapshot_age(&self) -> Option<Duration> {
        match self.snapshot_ms.load(Ordering::Acquire) {
            0 => None,
            read_at => Some(Duration::from_millis(now_ms().saturating_sub(read_at - 1))),
        }
    }

    /// Whether the counters are recent enough to be trusted.
    pub fn is_healthy(&self) -> bool {
        let interval = self.interval_ms.load(Ordering::Acquire);
        let last_ok = self.last_ok.load(Ordering::Acquire);
        if interval == 0 || last_ok == 0 {
            return false;
        }
        let window = interval
            .saturating_mul(HEALTHY_INTERVALS)
            .max(MIN_HEALTH_WINDOW_MS);
        now_ms().saturating_sub(last_ok - 1) <= window
    }

    /// Combined counter of the `tables`.
    ///
    /// The counters only grow, so their sum changes whenever any of them
    /// does. `None` when the poller is not healthy or a table has no counter
    /// (the triggers are not installed): the caller must then rely on its
    /// TTL.
    pub fn stamp(&self, tables: &[&str]) -> Option<u64> {
        if !self.is_healthy() {
            return None;
        }
        let versions = self.versions.load();
        let mut stamp = 0u64;
        for table in tables {
            let version = versions.get(*table)?;
            stamp = stamp.wrapping_add(u64::try_from(*version).ok()?);
        }
        Some(stamp)
    }

    /// The stamp a read that tolerates `freshness` may validate its cache
    /// entry against; `None` when the read has to go to the database.
    ///
    /// - [`Freshness::Linearizable`] never uses a stamp.
    /// - A tolerance below the poll interval cannot be guaranteed by a poller
    ///   that looks every interval, so it is a forced read.
    /// - A tolerance the current snapshot is already older than is a forced
    ///   read as well (a late or failing poller).
    pub fn stamp_for(&self, tables: &[&str], freshness: Freshness) -> Option<u64> {
        match freshness {
            Freshness::Linearizable => None,
            Freshness::MaxStaleness(bound) => {
                if bound.is_zero() || bound < self.interval() {
                    return None;
                }
                if self.snapshot_age()? > bound {
                    return None;
                }
                self.stamp(tables)
            }
            Freshness::Any => self.stamp(tables),
        }
    }

    /// Bring the counters up to date for a linearizable read.
    ///
    /// Returns `true` when the published counters were read after this call
    /// started, so every write committed before the call is part of them and
    /// a cache entry stamped with the same counters is current. Concurrent
    /// callers share one `SELECT` of the `table_version` table: a caller
    /// that finds a snapshot read after its own arrival uses it. Returns
    /// `false` (the caller must read the database) when the watermarks are
    /// disabled or the counters cannot be read.
    ///
    /// Inside a [`ReadScope`] the "arrival" is the scope's linearization
    /// point, so a snapshot read after it satisfies every read of the request.
    pub async fn sync(&self, conn: &DatabaseConnection) -> bool {
        if self.interval().is_zero() {
            return false;
        }
        let scope = ReadScope::current();
        let arrival = scope.as_ref().map_or_else(now_ms, |(_, point)| *point);
        if let Some((scope, point)) = &scope
            && scope.synced_for.load(Ordering::Acquire) == point + 1
            && self.is_healthy()
        {
            return true;
        }
        if self.snapshot_ms.load(Ordering::Acquire) > arrival + 1 && self.is_healthy() {
            return true;
        }
        loop {
            // Register for the wake-up before looking at the state, so a read
            // finishing in between is not missed.
            let notified = self.sync_done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.snapshot_ms.load(Ordering::Acquire) > arrival + 1 && self.is_healthy() {
                return true;
            }
            // The leader of this request's scope marks it synced even when its
            // snapshot is not strictly newer than the scope point (same
            // millisecond).
            if let Some((scope, point)) = &scope
                && scope.synced_for.load(Ordering::Acquire) == point + 1
                && self.is_healthy()
            {
                return true;
            }
            let failed_at = self.sync_failed_at.load(Ordering::Acquire);
            if failed_at > arrival + 1 {
                // A read that started after this caller arrived failed.
                return false;
            }
            // The counters cannot be read (e.g. the `table_version` table is
            // not installed): do not send the failing query with every
            // request, the poller retries once per interval.
            if failed_at != 0 && now_ms() + 1 < failed_at.saturating_add(self.back_off_ms()) {
                return false;
            }
            let Ok(guard) = self.sync_lock.try_lock() else {
                // Another caller reads the counters; share its result.
                notified.await;
                continue;
            };
            let _leader = SyncLeader {
                guard: Some(guard),
                done: &self.sync_done,
            };
            let started = now_ms() + 1;
            let epoch = self.current_epoch();
            let result = self.poll_in_epoch(conn, epoch).await;
            self.record_poll(&result);
            // The poll started after the arrival; only a reset in between (a
            // replaced connection) makes its counters worthless.
            let synced = result.is_ok() && self.epoch.load(Ordering::Acquire) == epoch;
            if result.is_err() {
                self.sync_failed_at.fetch_max(started, Ordering::AcqRel);
            }
            if synced && let Some((scope, point)) = &scope {
                scope.synced_for.fetch_max(point + 1, Ordering::AcqRel);
            }
            return synced;
        }
    }

    /// How long after a failed counter read the next request does not try
    /// again: the poll interval, at least a second.
    fn back_off_ms(&self) -> u64 {
        self.interval_ms.load(Ordering::Acquire).max(1000)
    }

    /// The current epoch. Read it *before* fetching the connection the
    /// counters are read through, and pass it to [`Self::poll_in_epoch`], so
    /// counters of a replaced connection are dropped.
    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Read the counters and publish them.
    pub async fn poll(&self, conn: &DatabaseConnection) -> Result<(), DbErr> {
        self.poll_in_epoch(conn, self.current_epoch()).await
    }

    /// Read the counters through `conn` and publish them unless a reset
    /// happened since `epoch` was read.
    pub async fn poll_in_epoch(&self, conn: &DatabaseConnection, epoch: u64) -> Result<(), DbErr> {
        let backend = conn.get_database_backend();
        let read_at = now_ms();
        let query = conn.query_all_raw(Statement::from_string(
            backend,
            format!("SELECT table_name, version FROM {VERSION_TABLE}"),
        ));
        let rows = tokio::time::timeout(POLL_TIMEOUT, query)
            .await
            .map_err(|_| DbErr::Custom("reading the table counters timed out".to_string()))??;
        // The counter of a table is the sum of its rows.
        let mut versions: HashMap<String, i64> = HashMap::with_capacity(rows.len());
        for row in rows {
            let name: String = row.try_get("", "table_name")?;
            let version: i64 = row.try_get("", "version")?;
            let entry = versions
                .entry(counter_table(&name).to_string())
                .or_default();
            *entry = entry.wrapping_add(version);
        }
        self.publish_in_epoch(versions, read_at, epoch);
        Ok(())
    }

    /// Log poll failures and recoveries once per transition.
    fn record_poll(&self, result: &Result<(), DbErr>) {
        match result {
            Ok(()) => {
                if self.failing.swap(false, Ordering::AcqRel) {
                    info!("table watermark poll recovered");
                }
            }
            Err(error) => {
                if !self.failing.swap(true, Ordering::AcqRel) {
                    warn!(%error, "table watermark poll failed, caches fall back to their TTL");
                } else {
                    debug!(%error, "table watermark poll failed");
                }
            }
        }
    }
}

/// Start the poller of the global registry.
///
/// The interval is re-read from `[database] table_watermark_interval_ms` on
/// every round, so the poller can be enabled, retuned or disabled with a
/// configuration reload.
pub fn spawn(state: ServiceState) {
    tokio::spawn(async move {
        let watermarks = state.db.watermarks();
        loop {
            let interval = Duration::from_millis(
                state
                    .config_manager
                    .config
                    .read()
                    .await
                    .database
                    .table_watermark_interval_ms,
            );
            watermarks.configure(interval);
            if interval.is_zero() {
                tokio::time::sleep(DISABLED_RECHECK).await;
                continue;
            }
            let epoch = watermarks.current_epoch();
            let result = watermarks
                .poll_in_epoch(&state.db.connection(), epoch)
                .await;
            watermarks.record_poll(&result);
            tokio::time::sleep(interval).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;

    use super::*;

    /// The project row caches stay valid across a project insert only while
    /// they depend on nothing but insert neutral tables.
    #[test]
    fn test_project_row_tables_are_insert_neutral() {
        assert!(PROJECT_ROW_TABLES.iter().all(|t| !bumps_on_insert(t)));
        assert!(PROJECT_TABLES.contains(&"project_option"));
        assert!(!PROJECT_ROW_TABLES.contains(&"project_option"));
    }

    fn registry(interval_ms: u64) -> TableWatermarks {
        let wm = TableWatermarks::new();
        wm.configure(Duration::from_millis(interval_ms));
        wm
    }

    fn versions(pairs: &[(&str, i64)]) -> HashMap<String, i64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn test_publish_from_before_a_reset_is_dropped() {
        let wm = registry(100);
        let epoch = wm.epoch.load(Ordering::Acquire);
        wm.reset();
        wm.publish_in_epoch(versions(&[("a", 1)]), now_ms(), epoch);
        assert!(wm.stamp(&["a"]).is_none());
    }

    #[test]
    fn test_inactive_until_polled() {
        let wm = registry(100);
        assert!(wm.stamp(&["a"]).is_none());
        wm.publish(versions(&[("a", 1)]));
        assert_eq!(Some(1), wm.stamp(&["a"]));
    }

    #[test]
    fn test_disabled_registry_has_no_stamp() {
        let wm = registry(0);
        wm.publish(versions(&[("a", 1)]));
        assert!(wm.stamp(&["a"]).is_none());
    }

    #[test]
    fn test_missing_table_has_no_stamp() {
        let wm = registry(100);
        wm.publish(versions(&[("a", 1)]));
        assert!(wm.stamp(&["a", "b"]).is_none());
    }

    #[test]
    fn test_stamp_changes_with_any_table() {
        let wm = registry(100);
        wm.publish(versions(&[("a", 1), ("b", 5)]));
        let before = wm.stamp(&["a", "b"]);
        wm.publish(versions(&[("a", 1), ("b", 6)]));
        assert_ne!(before, wm.stamp(&["a", "b"]));
        // An unrelated table does not move the stamp.
        wm.publish(versions(&[("a", 2), ("b", 6)]));
        assert_eq!(wm.stamp(&["b"]), Some(6));
    }

    #[test]
    fn test_unhealthy_after_missed_polls() {
        let wm = registry(1);
        wm.publish(versions(&[("a", 1)]));
        assert!(wm.is_healthy());
        std::thread::sleep(Duration::from_millis(MIN_HEALTH_WINDOW_MS + 100));
        assert!(!wm.is_healthy());
        assert!(wm.stamp(&["a"]).is_none());
    }

    #[test]
    fn test_invalid_identifier_is_rejected() {
        assert!(check_identifier("role_option").is_ok());
        assert!(check_identifier("a; DROP TABLE x").is_err());
        assert!(check_identifier("Role").is_err());
        assert!(check_identifier("").is_err());
    }

    #[test]
    fn test_trigger_statements_per_backend() {
        let pg = create_trigger_statements(DatabaseBackend::Postgres, "assignment");
        assert_eq!(2, pg.len());
        assert_eq!(
            "DROP TRIGGER IF EXISTS wm_assignment ON \"assignment\"",
            pg[0]
        );
        assert!(pg[1].contains("FOR EACH STATEMENT"));
        assert!(pg[1].contains("keystone_bump_table_version('assignment')"));

        let mysql = create_trigger_statements(DatabaseBackend::MySql, "assignment");
        assert_eq!(6, mysql.len());
        assert!(
            mysql[3].starts_with("CREATE TRIGGER wm_assignment_ins AFTER INSERT ON `assignment`")
        );
        assert!(mysql[4].contains("AFTER UPDATE"));
        assert!(mysql[5].contains("AFTER DELETE"));
        // A random counter row of the table, not the base row only, chosen
        // once per statement (a `RAND()` in the `WHERE` is evaluated per row
        // and bumps nothing in a third of the cases).
        assert!(
            mysql[3]
                .contains("SET counter = ELT(FLOOR(RAND() * 8) + 1, 'assignment', 'assignment:1'")
        );
        assert!(mysql[3].contains("'assignment:7');"));
        assert!(mysql[3].contains("WHERE table_name = counter; END"));
        assert!(!mysql[3].contains("table_name = ELT"));

        let sqlite = create_trigger_statements(DatabaseBackend::Sqlite, "assignment");
        assert_eq!(6, sqlite.len());
        assert!(sqlite[3].contains("BEGIN UPDATE table_version"));
        assert!(sqlite[3].ends_with("END"));
    }

    #[test]
    fn test_insert_neutral_tables_have_no_insert_trigger() {
        let pg = create_trigger_statements(DatabaseBackend::Postgres, "project");
        assert!(pg[1].contains("AFTER UPDATE OR DELETE OR TRUNCATE"));
        assert!(!pg[1].contains("INSERT"));
        for backend in [DatabaseBackend::MySql, DatabaseBackend::Sqlite] {
            let statements = create_trigger_statements(backend, "project");
            // Three drops, two triggers: the drop of the insert trigger
            // stays, it removes the one an older install created.
            assert_eq!(5, statements.len(), "{backend:?}");
            assert!(
                statements
                    .iter()
                    .any(|s| s.starts_with("DROP TRIGGER IF EXISTS wm_project_ins"))
            );
            assert!(
                !statements
                    .iter()
                    .any(|s| s.starts_with("CREATE TRIGGER wm_project_ins"))
            );
        }
    }

    #[tokio::test]
    async fn test_sqlite_insert_into_insert_neutral_table_keeps_the_counter() {
        let conn = sqlite_with_role_table().await;
        conn.execute_unprepared("CREATE TABLE project (id TEXT PRIMARY KEY, name TEXT)")
            .await
            .unwrap();
        install(&conn, &["project"]).await.unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        let before = wm.stamp(&["project"]).unwrap();

        conn.execute_unprepared("INSERT INTO project (id, name) VALUES ('a', 'x')")
            .await
            .unwrap();
        wm.poll(&conn).await.unwrap();
        assert_eq!(before, wm.stamp(&["project"]).unwrap());

        for sql in [
            "UPDATE project SET name = 'y' WHERE id = 'a'",
            "DELETE FROM project WHERE id = 'a'",
        ] {
            let last = wm.stamp(&["project"]).unwrap();
            conn.execute_unprepared(sql).await.unwrap();
            wm.poll(&conn).await.unwrap();
            assert!(wm.stamp(&["project"]).unwrap() > last, "`{sql}`");
        }
    }

    #[test]
    fn test_counter_names_cover_every_shard() {
        let names = counter_names("user_option");
        assert_eq!(COUNTER_SHARDS, names.len());
        assert_eq!("user_option", names[0]);
        assert_eq!("user_option:1", names[1]);
        assert!(
            names
                .iter()
                .all(|name| counter_table(name) == "user_option")
        );
    }

    #[test]
    fn test_reserved_word_tables_are_quoted() {
        let pg = create_trigger_statements(DatabaseBackend::Postgres, "group");
        assert!(pg[1].contains("ON \"group\" FOR EACH STATEMENT"));
    }

    #[tokio::test]
    async fn test_sqlite_counter_is_the_sum_of_the_shards() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        // The count of rows: one per shard.
        let rows = conn
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT table_name FROM table_version".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(COUNTER_SHARDS, rows.len());
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        let before = wm.stamp(&["assignment"]).unwrap();
        // A write to the base shard (SQLite triggers bump it) moves the sum.
        conn.execute_unprepared("INSERT INTO assignment (id, name) VALUES ('a', 'x')")
            .await
            .unwrap();
        wm.poll(&conn).await.unwrap();
        assert!(wm.stamp(&["assignment"]).unwrap() > before);
        // Uninstall removes every shard.
        uninstall(&conn, &["assignment"]).await.unwrap();
        let rows = conn
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT table_name FROM table_version".to_string(),
            ))
            .await
            .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_seed_statement_per_backend() {
        assert!(
            seed_counter_statement(DatabaseBackend::MySql, "assignment").starts_with(
                "INSERT IGNORE INTO table_version (table_name, version) VALUES ('assignment', "
            )
        );
        for backend in [DatabaseBackend::Postgres, DatabaseBackend::Sqlite] {
            assert!(
                seed_counter_statement(backend, "assignment")
                    .ends_with("ON CONFLICT (table_name) DO NOTHING")
            );
        }
    }

    async fn sqlite_with_role_table() -> DatabaseConnection {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        conn.execute_unprepared("CREATE TABLE assignment (id TEXT PRIMARY KEY, name TEXT)")
            .await
            .unwrap();
        conn
    }

    #[tokio::test]
    async fn test_sqlite_triggers_bump_counter() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        // Idempotent.
        install(&conn, &["assignment"]).await.unwrap();

        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        let mut last = wm.stamp(&["assignment"]).unwrap();

        for sql in [
            "INSERT INTO assignment (id, name) VALUES ('a', 'x')",
            "UPDATE assignment SET name = 'y' WHERE id = 'a'",
            "DELETE FROM assignment WHERE id = 'a'",
        ] {
            conn.execute_unprepared(sql).await.unwrap();
            wm.poll(&conn).await.unwrap();
            let stamp = wm.stamp(&["assignment"]).unwrap();
            assert!(stamp > last, "`{sql}` did not bump the counter");
            last = stamp;
        }
    }

    #[tokio::test]
    async fn test_sqlite_rolled_back_change_is_not_visible() {
        use sea_orm::TransactionTrait;
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        let before = wm.stamp(&["assignment"]);

        let txn = conn.begin().await.unwrap();
        txn.execute_unprepared("INSERT INTO assignment (id, name) VALUES ('a', 'x')")
            .await
            .unwrap();
        txn.rollback().await.unwrap();

        wm.poll(&conn).await.unwrap();
        assert_eq!(before, wm.stamp(&["assignment"]));
    }

    #[tokio::test]
    async fn test_sqlite_uninstall_stops_bumping() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        uninstall(&conn, &["assignment"]).await.unwrap();
        conn.execute_unprepared("INSERT INTO assignment (id, name) VALUES ('a', 'x')")
            .await
            .unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        // The counter row is gone, so the table has no stamp.
        assert!(wm.stamp(&["assignment"]).is_none());
    }

    /// Pause long enough for the millisecond clock to tick.
    async fn tick() {
        tokio::time::sleep(Duration::from_millis(3)).await;
    }

    #[tokio::test]
    async fn test_read_scope_shares_one_sync() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        tick().await;

        ReadScope::run(async {
            tick().await;
            assert!(wm.sync(&conn).await);
            let first = wm.snapshot_ms.load(Ordering::Acquire);
            tick().await;
            // Later reads of the request find that snapshot.
            assert!(wm.sync(&conn).await);
            assert!(wm.sync(&conn).await);
            assert_eq!(first, wm.snapshot_ms.load(Ordering::Acquire));
        })
        .await;
    }

    #[tokio::test]
    async fn test_read_scope_remembers_its_sync_within_one_millisecond() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();

        ReadScope::run(async {
            assert!(wm.sync(&conn).await);
            let first = wm.snapshot_ms.load(Ordering::Acquire);
            for _ in 0..5 {
                assert!(wm.sync(&conn).await);
            }
            assert_eq!(first, wm.snapshot_ms.load(Ordering::Acquire));
            // A write forgets it, even within the same millisecond.
            ReadScope::advance();
            assert!(wm.sync(&conn).await);
            assert!(wm.snapshot_ms.load(Ordering::Acquire) >= first);
        })
        .await;
    }

    #[tokio::test]
    async fn test_cancelled_leader_wakes_the_followers() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        tick().await;

        // A leader that never finishes its read.
        let guard = wm.sync_lock.try_lock().unwrap();
        let leader = SyncLeader {
            guard: Some(guard),
            done: &wm.sync_done,
        };
        let follower = tokio::time::timeout(Duration::from_secs(5), wm.sync(&conn));
        tokio::pin!(follower);
        // The follower waits for the leader.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut follower)
                .await
                .is_err()
        );
        // The leader is cancelled: the follower takes over and reads.
        drop(leader);
        assert_eq!(Ok(true), follower.await);
    }

    #[tokio::test]
    async fn test_without_scope_every_read_syncs() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        tick().await;
        assert!(wm.sync(&conn).await);
        let first = wm.snapshot_ms.load(Ordering::Acquire);
        tick().await;
        assert!(wm.sync(&conn).await);
        assert!(wm.snapshot_ms.load(Ordering::Acquire) > first);
    }

    #[tokio::test]
    async fn test_a_write_in_the_scope_forces_a_new_sync() {
        let conn = sqlite_with_role_table().await;
        install(&conn, &["assignment"]).await.unwrap();
        let wm = registry(1000);
        wm.poll(&conn).await.unwrap();
        tick().await;

        ReadScope::run(async {
            tick().await;
            assert!(wm.sync(&conn).await);
            let first = wm.snapshot_ms.load(Ordering::Acquire);
            let before = wm.stamp(&["assignment"]).unwrap();

            tick().await;
            conn.execute_unprepared("INSERT INTO assignment (id, name) VALUES ('a', 'x')")
                .await
                .unwrap();
            ReadScope::advance();
            tick().await;

            // The snapshot predates the write: a new read of the counters.
            assert!(wm.sync(&conn).await);
            assert!(wm.snapshot_ms.load(Ordering::Acquire) > first);
            assert!(wm.stamp(&["assignment"]).unwrap() > before);
        })
        .await;
    }

    #[tokio::test]
    async fn test_a_spawned_task_has_no_scope() {
        ReadScope::run(async {
            assert!(ReadScope::point().is_some());
            let spawned = tokio::spawn(async { ReadScope::point().is_none() });
            assert!(spawned.await.unwrap());
        })
        .await;
        assert!(ReadScope::point().is_none());
        // No scope: advancing is a no-op.
        ReadScope::advance();
    }

    #[tokio::test]
    async fn test_poll_without_version_table_fails() {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        let wm = registry(100);
        assert!(wm.poll(&conn).await.is_err());
        assert!(wm.stamp(&["assignment"]).is_none());
    }

    #[tokio::test]
    async fn test_sync_without_version_table_does_not_retry_per_request() {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        let wm = registry(60_000);
        assert!(!wm.sync(&conn).await);
        // The table appears, but the failed read is not repeated by every
        // request: the poller retries once per interval.
        install(&conn, &[]).await.unwrap();
        assert!(!wm.sync(&conn).await);
        assert!(wm.stamp(&["assignment"]).is_none());
    }
}
