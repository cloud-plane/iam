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
//! Index `implied_role.implied_role_id`.
//!
//! The primary key starts with `prior_role_id`. Deleting a role checks the
//! foreign key of the rules that imply it, and the inference reads the rules
//! by the implied role.
use openstack_keystone_core::migration_index::{create_index, drop_index};
use sea_orm_migration::prelude::*;

/// The indexes: table, name and columns.
const INDEXES: &[(&str, &str, &[&str])] = &[(
    "implied_role",
    "ix_implied_role_implied_role_id",
    &["implied_role_id"],
)];

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
