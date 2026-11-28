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
//! # Index migrations
//!
//! Helpers for the migrations that add a plain index to a table of a driver:
//! the lookups the deletes of an entity cascade into (by project, role, local
//! user, ...) scan the whole table without one.

use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement};
use sea_orm_migration::prelude::*;

use crate::table_watermark::table_exists;

/// Whether a MySQL table has an index that starts with `column`. InnoDB
/// creates one for a foreign key already, and `SchemaManager::has_index` is not
/// implemented for MySQL.
async fn mysql_has_leading_index(
    manager: &SchemaManager<'_>,
    table: &str,
    column: &str,
) -> Result<bool, DbErr> {
    let row = manager
        .get_connection()
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::MySql,
            "SELECT COUNT(*) FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND table_name = ? \
             AND column_name = ? AND seq_in_index = 1",
            [table.into(), column.into()],
        ))
        .await?;
    match row {
        Some(row) => Ok(row.try_get_by_index::<i64>(0)? > 0),
        None => Ok(false),
    }
}

/// Create the index `name` on `columns` of `table`.
///
/// A table that does not exist is skipped (a deployment that does not use the
/// driver has none). On MySQL nothing is created when the first column is
/// indexed already (a foreign key), elsewhere the creation is idempotent.
pub async fn create_index(
    manager: &SchemaManager<'_>,
    table: &str,
    name: &str,
    columns: &[&str],
) -> Result<(), DbErr> {
    if !table_exists(manager.get_connection(), table).await? {
        return Ok(());
    }
    let is_mysql = manager.get_database_backend() == DatabaseBackend::MySql;
    if is_mysql
        && let Some(first) = columns.first()
        && mysql_has_leading_index(manager, table, first).await?
    {
        return Ok(());
    }
    let mut index = Index::create();
    index.name(name).table(Alias::new(table));
    for column in columns {
        index.col(Alias::new(*column));
    }
    if !is_mysql {
        index.if_not_exists();
    }
    manager.create_index(index.to_owned()).await
}

/// Drop the index `name` of `table`. On MySQL it stays: a foreign key may
/// rely on it.
pub async fn drop_index(manager: &SchemaManager<'_>, table: &str, name: &str) -> Result<(), DbErr> {
    if manager.get_database_backend() == DatabaseBackend::MySql
        || !table_exists(manager.get_connection(), table).await?
    {
        return Ok(());
    }
    manager
        .drop_index(
            Index::drop()
                .name(name)
                .table(Alias::new(table))
                .if_exists()
                .to_owned(),
        )
        .await
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;

    use super::*;

    async fn index_count(db: &sea_orm::DatabaseConnection, name: &str) -> i64 {
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='{name}'"),
            ))
            .await
            .ok()
            .flatten();
        row.and_then(|row| row.try_get_by_index::<i64>(0).ok())
            .unwrap_or(-1)
    }

    #[tokio::test]
    async fn test_create_index_is_idempotent_and_skips_missing_tables() {
        let db = Database::connect("sqlite::memory:")
            .await
            .unwrap_or_else(|_| panic!("connect"));
        db.execute_unprepared("CREATE TABLE t (id TEXT PRIMARY KEY, target_id TEXT)")
            .await
            .unwrap_or_else(|_| panic!("create table"));
        let manager = SchemaManager::new(&db);

        create_index(&manager, "t", "ix_t_target_id", &["target_id"])
            .await
            .unwrap_or_else(|_| panic!("create"));
        create_index(&manager, "t", "ix_t_target_id", &["target_id"])
            .await
            .unwrap_or_else(|_| panic!("create twice"));
        assert_eq!(index_count(&db, "ix_t_target_id").await, 1);

        // A table of a driver that is not deployed is skipped.
        create_index(&manager, "missing", "ix_missing", &["x"])
            .await
            .unwrap_or_else(|_| panic!("missing table"));

        drop_index(&manager, "t", "ix_t_target_id")
            .await
            .unwrap_or_else(|_| panic!("drop"));
        assert_eq!(index_count(&db, "ix_t_target_id").await, 0);
    }
}
