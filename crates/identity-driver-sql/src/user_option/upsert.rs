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

use sea_orm::ConnectionTrait;
use sea_orm::QueryFilter;
use sea_orm::entity::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::UserOptions;

use crate::entity::prelude::UserOption as DbUserOption;
use crate::entity::user_option as db_user_option;
use crate::user_option::UserOptionIntoModelIterator;

/// Set the given user options, replacing the stored value of each.
///
/// Options that are not set in `opts` are left untouched.
///
/// # Parameters
/// - `db`: The database connection.
/// - `user_id`: The user ID.
/// - `opts`: The user options to set.
///
/// # Returns
/// A `Result` containing `()` if successful, or an `Error`.
pub async fn upsert<C, U>(
    db: &C,
    user_id: U,
    opts: &UserOptions,
) -> Result<(), IdentityProviderError>
where
    C: ConnectionTrait,
    U: Into<String>,
{
    let rows: Vec<db_user_option::Model> = opts.to_model_iter(user_id)?.into_iter().collect();
    if rows.is_empty() {
        return Ok(());
    }
    DbUserOption::delete_many()
        .filter(db_user_option::Column::UserId.eq(rows[0].user_id.clone()))
        .filter(
            db_user_option::Column::OptionId.is_in(rows.iter().map(|row| row.option_id.clone())),
        )
        .exec(db)
        .await
        .context("removing replaced user options")?;
    DbUserOption::insert_many(
        rows.into_iter()
            .map(Into::<db_user_option::ActiveModel>::into),
    )
    .exec_without_returning(db)
    .await
    .context("inserting user options")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    use super::*;

    #[tokio::test]
    async fn test_upsert_empty() {
        let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
        upsert(&db, "1", &UserOptions::default()).await.unwrap();
        assert!(db.into_transaction_log().is_empty());
    }

    #[tokio::test]
    async fn test_upsert_replaces_set_options() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: 1,
                },
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: 1,
                },
            ])
            .into_connection();
        let opts = UserOptions {
            lock_password: Some(false),
            ..Default::default()
        };
        upsert(&db, "1", &opts).await.unwrap();
        let log: Vec<Transaction> = db.into_transaction_log();
        assert_eq!(2, log.len());
        let stmts = format!("{log:?}");
        assert!(stmts.contains("DELETE FROM"), "{stmts}");
        assert!(stmts.contains("INSERT INTO"), "{stmts}");
        assert!(stmts.contains("1003"), "{stmts}");
    }
}
