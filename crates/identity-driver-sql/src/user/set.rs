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
//! Set user properties.

use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;

use crate::entity::user as db_user;

/// Reset the `user.last_active_at` to the specified date.
///
/// The column holds a date: a user that already is marked active on that day
/// is returned as is. Every write moves the `user` table version and so drops
/// the cached users, and a login would otherwise do it each time.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user`: The user model to update.
/// - `last_active_at`: The date to set as the user's last active date.
///
/// # Returns
/// A `Result` containing the updated `db_user::Model` if successful, or an
/// `Error`.
pub async fn reset_last_active(
    db: &DatabaseConnection,
    user: &db_user::Model,
    last_active_at: DateTime<Utc>,
) -> Result<db_user::Model, IdentityProviderError> {
    let day = last_active_at.date_naive();
    if user.last_active_at == Some(day) {
        return Ok(user.clone());
    }
    let mut update: db_user::ActiveModel = user.clone().into();
    update.last_active_at = Set(Some(day));

    Ok(update
        .update(db)
        .await
        .context("resetting user's last_active_at")?)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::*;
    use crate::user::tests::get_user_mock;

    #[tokio::test]
    async fn test_reset_last_active_same_day_writes_nothing() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        let now = Utc::now();
        let mut user = get_user_mock("user_id");
        user.last_active_at = Some(now.date_naive());

        assert_eq!(
            reset_last_active(&db, &user, now).await.unwrap().id,
            "user_id"
        );
        assert!(db.into_transaction_log().is_empty());
    }

    #[tokio::test]
    async fn test_reset_last_active() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_user_mock("user_id")]])
            .into_connection();
        let now = Utc::now();
        assert!(
            reset_last_active(&db, &get_user_mock("user_id"), now)
                .await
                .is_ok()
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"UPDATE "user" SET "last_active_at" = $1 WHERE "user"."id" = $2 RETURNING "created_at", "default_project_id", "domain_id", "enabled", "extra", "id", "last_active_at""#,
                [now.date_naive().into(), "user_id".into()]
            ),]
        );
    }
}
