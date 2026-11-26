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
//! Index the target and the role of the assignments.
//!
//! Deleting a project or a domain revokes the grants on it (by `target_id`)
//! and deleting a role revokes the grants of it (by `role_id`). The primary
//! key starts with the type and the actor, so without these indexes each of
//! those scans the whole table.
use openstack_keystone_core::migration_index::{create_index, drop_index};
use sea_orm_migration::prelude::*;

/// The indexes: table, name and columns.
const INDEXES: &[(&str, &str, &[&str])] = &[
    ("assignment", "ix_assignment_target_id", &["target_id"]),
    ("assignment", "ix_assignment_role_id", &["role_id"]),
    (
        "system_assignment",
        "ix_system_assignment_role_id",
        &["role_id"],
    ),
];

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, name, columns) in INDEXES {
            create_index(manager, table, name, columns).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, name, _) in INDEXES {
            drop_index(manager, table, name).await?;
        }
        Ok(())
    }
}
