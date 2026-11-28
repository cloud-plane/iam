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
//! Index the lookups of `application_credential`.
//!
//! Deleting a project removes its application credentials by `project_id`.
//! A login and the validation of an application credential token look the
//! credential up by its public `id`, the table is keyed by `internal_id`.
//! Without the indexes each of these scans the whole table.
use openstack_keystone_core::migration_index::{create_index, drop_index};
use sea_orm_migration::prelude::*;

/// Table of the indexes.
const TABLE: &str = "application_credential";

/// The indexes: name and columns.
const INDEXES: &[(&str, &[&str])] = &[
    ("ix_application_credential_project_id", &["project_id"]),
    ("ix_application_credential_id", &["id"]),
];

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (name, columns) in INDEXES {
            create_index(manager, TABLE, name, columns).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (name, _) in INDEXES {
            drop_index(manager, TABLE, name).await?;
        }
        Ok(())
    }
}
