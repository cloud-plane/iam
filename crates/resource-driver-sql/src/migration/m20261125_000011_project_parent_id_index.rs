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
//
//! Index `project.parent_id`.
//!
//! Deleting a project checks the `parent_id` foreign key of its children, and
//! the subtree and parents queries walk the hierarchy by it. Without an index
//! each of those scans the whole table.
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

use crate::entity::{prelude::Project, project::Column};

/// Name of the index.
const INDEX: &str = "ix_project_parent_id";

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Check whether the table has an index starting with `parent_id`. InnoDB
/// creates one for the foreign key already, and `SchemaManager::has_index` is
/// not implemented for MySQL.
async fn mysql_has_parent_index(manager: &SchemaManager<'_>) -> Result<bool, DbErr> {
    let row = manager
        .get_connection()
        .query_one_raw(Statement::from_string(
            DatabaseBackend::MySql,
            "SELECT COUNT(*) FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND table_name = 'project' \
             AND column_name = 'parent_id' AND seq_in_index = 1",
        ))
        .await?;
    match row {
        Some(row) => Ok(row.try_get_by_index::<i64>(0)? > 0),
        None => Ok(false),
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let is_mysql = manager.get_database_backend() == DatabaseBackend::MySql;
        if is_mysql && mysql_has_parent_index(manager).await? {
            return Ok(());
        }
        let mut index = Index::create();
        index.name(INDEX).table(Project).col(Column::ParentId);
        if !is_mysql {
            index.if_not_exists();
        }
        manager.create_index(index.to_owned()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::MySql {
            // The foreign key may rely on the index: leave it in place.
            return Ok(());
        }
        manager
            .drop_index(
                Index::drop()
                    .name(INDEX)
                    .table(Project)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}
