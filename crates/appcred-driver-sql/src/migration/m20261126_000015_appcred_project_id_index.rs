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
//! Index `application_credential.project_id`.
//!
//! Deleting a project removes its application credentials by `project_id`. Without an index
//! each delete scans the whole table.
use sea_orm_migration::prelude::*;

use crate::entity::{application_credential, prelude::ApplicationCredential};

/// Name of the index.
const INDEX: &str = "ix_application_credential_project_id";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(INDEX)
                    .table(ApplicationCredential)
                    .col(application_credential::Column::ProjectId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(INDEX)
                    .table(ApplicationCredential)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}
