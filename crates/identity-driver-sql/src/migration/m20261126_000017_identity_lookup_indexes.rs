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
//! Index the columns the identity lookups and deletes filter by.
//!
//! `password.local_user_id` is read for every login and password expiry check
//! and removed with the user. `federated_user.user_id` and
//! `expiring_user_group_membership.group_id` are foreign keys the deletes of a
//! user and a group check. Listing the users of a domain filters by
//! `domain_id` and orders by `id`: `user(domain_id, id)` serves both, the
//! existing `(id, domain_id)` index leads with `id` and cannot.
use openstack_keystone_core::migration_index::{create_index, drop_index};
use sea_orm_migration::prelude::*;

/// The indexes: table, name and columns.
const INDEXES: &[(&str, &str, &[&str])] = &[
    ("password", "ix_password_local_user_id", &["local_user_id"]),
    ("federated_user", "ix_federated_user_user_id", &["user_id"]),
    (
        "expiring_user_group_membership",
        "ix_expiring_user_group_membership_group_id",
        &["group_id"],
    ),
    ("user", "ix_user_domain_id_id", &["domain_id", "id"]),
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
