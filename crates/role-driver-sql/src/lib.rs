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
//! # OpenStack Keystone SQL driver for the role provider
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_config::Config;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core::role::backend::RoleBackend;
use openstack_keystone_core::table_watermark;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::freshness::Freshness;
use openstack_keystone_core_types::role::*;

mod cache;
pub mod entity;
mod implied_role;
mod migration;
mod role;
mod role_option;
#[cfg(test)]
mod sqlite_tests;
//mod role_imply;

#[derive(Default)]
pub struct SqlBackend {
    /// Per driver instance: it belongs to the connection it reads through.
    caches: OnceLock<cache::RoleCaches>,
}

impl SqlBackend {
    /// A backend whose projection caches follow the configuration.
    fn new(config: &Config) -> Self {
        Self {
            caches: OnceLock::from(cache::RoleCaches::new(config)),
        }
    }

    fn caches(&self) -> &cache::RoleCaches {
        self.caches.get_or_init(cache::RoleCaches::default)
    }

    /// All imply rules, kept while the `role` and `implied_role` tables are
    /// unchanged. The reads of single and filtered rules are answered from
    /// this list: the table is small and the callers (role assignment
    /// checks) run on the request path.
    async fn cached_rules(
        &self,
        state: &ServiceState,
    ) -> Result<Arc<Vec<RoleImply>>, RoleProviderError> {
        let db = state.db.connection();
        let watermarks = state.db.watermarks();
        self.caches()
            .rules
            .get_or_load(
                &watermarks,
                &db,
                cache::RULES_KEY,
                Freshness::Linearizable,
                || async { Ok(Arc::new(implied_role::list(&db).await?)) },
            )
            .await
    }
}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {
    caches: OnceLock::new(),
};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}
inventory::submit! {
    BackendRegistration::<dyn RoleBackend> {
        name: "sql",
        selected: |_| true,
        build: |cfg| {
            let backend = SqlBackend::new(cfg.core);
            Box::pin(async move { Ok(Arc::new(backend) as Arc<dyn RoleBackend>) })
        },
    }
}

/// Expand implied roles by resolving role inheritance and populating
/// missing role metadata.
///
/// # Parameters
/// - `db`: The database connection.
/// - `roles`: The list of roles to expand.
///
/// # Returns
/// A `Result` indicating success or an `Error`.
pub async fn expand_implied_roles(
    db: &DatabaseConnection,
    roles: &mut Vec<RoleRef>,
) -> Result<(), RoleProviderError> {
    let rules = implied_role::get_inference_tree(db, true).await?;
    let mut role_ids: HashSet<String> =
        HashSet::from_iter(roles.iter().map(|role| role.id.clone()));
    let mut implied_roles: Vec<RoleRef> = Vec::new();
    // iterate over all implied role ids for every role in the initial list
    for implied_role in roles
        .iter()
        .filter_map(|role| rules.get(&role.id))
        .flat_map(|val| val.iter())
    {
        // Add the role that was not processed yet (present in the `role_ids`
        // into the temporary list and save the processed id.
        if !role_ids.contains(&implied_role.id) {
            implied_roles.push(implied_role.clone());
            role_ids.insert(implied_role.id.clone());
        }
    }
    roles.extend(implied_roles);
    // The request list may only contain role IDs. In the response we need to
    // make sure name and domain_id are populated.
    for role in roles.iter_mut() {
        if role.name.is_none() {
            // The role was not resolved and only has the ID. Re-fetch it
            let full_role = role::get(db, &role.id)
                .await?
                .ok_or(RoleProviderError::RoleNotFound(role.id.clone()))?;
            role.name = Some(full_role.name.clone());
            role.domain_id = full_role.domain_id;
        }
    }
    Ok(())
}

#[async_trait]
impl RoleBackend for SqlBackend {
    /// Create role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The role creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Role`, or an `Error`.
    #[tracing::instrument(name = "driver.sql.role.create_role", level = "debug", skip_all)]
    async fn create_role(
        &self,
        state: &ServiceState,
        params: RoleCreate,
    ) -> Result<Role, RoleProviderError> {
        let role = role::create(&state.db.connection(), params).await?;
        self.caches().invalidate_created_role(&role.id);
        Ok(role)
    }

    /// Create a role imply rule.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_id`: The ID of the prior role.
    /// - `implied_role_id`: The ID of the implied role.
    ///
    /// # Returns
    /// A `Result` containing the created `RoleImply`, or an `Error`.
    #[tracing::instrument(name = "driver.sql.role.create_role_imply_rule", level = "debug", skip_all, fields(prior_role_id = %prior_role_id, implied_role_id = %implied_role_id))]
    async fn create_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<RoleImply, RoleProviderError> {
        let rule =
            implied_role::create(&state.db.connection(), prior_role_id, implied_role_id).await;
        // Whatever the outcome, the next read must look at the tables.
        self.caches().invalidate_inference();
        Ok(rule?)
    }

    /// Check if a role imply rule exists.
    ///
    /// # Arguments
    /// * `state` - The current service state.
    /// * `prior_role_id` - The ID of the prior role.
    /// * `implied_role_id` - The ID of the implied role.
    #[tracing::instrument(name = "driver.sql.role.check_role_imply_rule", level = "debug", skip_all, fields(prior_role_id = %prior_role_id, implied_role_id = %implied_role_id))]
    async fn check_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<bool, RoleProviderError> {
        Ok(implied_role::check(&state.db.connection(), prior_role_id, implied_role_id).await?)
    }

    /// Update a role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `role_id`: The ID of the role to update.
    /// - `role`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Role`, or an `Error`.
    #[tracing::instrument(name = "driver.sql.role.update_role", level = "debug", skip_all, fields(role_id = %role_id))]
    async fn update_role<'a>(
        &self,
        state: &ServiceState,
        role_id: &'a str,
        role: RoleUpdate,
    ) -> Result<Role, RoleProviderError> {
        let role = role::update(&state.db.connection(), role_id, role).await;
        self.caches().invalidate_role(role_id);
        Ok(role?)
    }

    /// Delete a role by the ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The role ID.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    #[tracing::instrument(name = "driver.sql.role.delete_role", level = "debug", skip_all, fields(id = %id))]
    async fn delete_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), RoleProviderError> {
        let deleted = role::delete(&state.db.connection(), id).await;
        self.caches().invalidate_role(id);
        Ok(deleted?)
    }

    /// Delete a role imply rule.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_id`: The ID of the prior role.
    /// - `implied_role_id`: The ID of the implied role.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    #[tracing::instrument(name = "driver.sql.role.delete_role_imply_rule", level = "debug", skip_all, fields(prior_role_id = %prior_role_id, implied_role_id = %implied_role_id))]
    async fn delete_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<(), RoleProviderError> {
        let deleted =
            implied_role::delete(&state.db.connection(), prior_role_id, implied_role_id).await;
        self.caches().invalidate_inference();
        Ok(deleted?)
    }

    /// Expand implied roles.
    ///
    /// Modify the list of roles resolving the role inheritance.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `roles`: The list of roles to expand.
    ///
    /// # Returns
    /// A `Result` indicating success or an `Error`.
    #[tracing::instrument(
        name = "driver.sql.role.expand_implied_roles",
        level = "debug",
        skip_all
    )]
    async fn expand_implied_roles(
        &self,
        state: &ServiceState,
        roles: &mut Vec<RoleRef>,
    ) -> Result<(), RoleProviderError> {
        // The resolved inference and the role names are cached; this runs on
        // every token validation, so it must not read the rule tables.
        let inference = self.get_role_inference(state).await?;
        let mut role_ids: HashSet<String> =
            HashSet::from_iter(roles.iter().map(|role| role.id.clone()));
        let mut implied_roles: Vec<RoleRef> = Vec::new();
        for implied in roles
            .iter()
            .flat_map(|role| inference.implied(&role.id).iter())
        {
            if role_ids.insert(implied.id.clone()) {
                implied_roles.push(implied.clone());
            }
        }
        roles.extend(implied_roles);
        // The request list may only contain role IDs: populate name and
        // domain from the names cache.
        let unnamed: Vec<String> = roles
            .iter()
            .filter(|role| role.name.is_none())
            .map(|role| role.id.clone())
            .collect();
        if !unnamed.is_empty() {
            let found: std::collections::HashMap<String, Role> = self
                .list_roles(
                    state,
                    &RoleListParameters {
                        ids: Some(unnamed),
                        skip_options: true,
                        ..Default::default()
                    },
                )
                .await?
                .into_iter()
                .map(|role| (role.id.clone(), role))
                .collect();
            for role in roles.iter_mut().filter(|role| role.name.is_none()) {
                let full = found
                    .get(&role.id)
                    .ok_or_else(|| RoleProviderError::RoleNotFound(role.id.clone()))?;
                role.name = Some(full.name.clone());
                role.domain_id = full.domain_id.clone();
            }
        }
        Ok(())
    }

    /// Get the resolved role inference.
    ///
    /// The closure of every role is computed when the rules are loaded and
    /// kept while the `role` and `implied_role` tables are unchanged.
    ///
    /// # Parameters
    /// - `state`: The service state.
    #[tracing::instrument(name = "driver.sql.role.get_role_inference", level = "debug", skip_all)]
    async fn get_role_inference(
        &self,
        state: &ServiceState,
    ) -> Result<Arc<RoleInference>, RoleProviderError> {
        let db = state.db.connection();
        let watermarks = state.db.watermarks();
        self.caches()
            .inference
            .get_or_load(
                &watermarks,
                &db,
                cache::INFERENCE_KEY,
                Freshness::Linearizable,
                || async {
                    let rules = self.cached_rules(state).await?;
                    Ok(Arc::new(RoleInference::from_rules(&rules)))
                },
            )
            .await
    }

    /// Get single role by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The role ID.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Role` if found, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.role.get_role", level = "debug", skip_all, fields(id = %id))]
    async fn get_role<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Role>, RoleProviderError> {
        let db = state.db.connection();
        let watermarks = state.db.watermarks();
        self.caches()
            .roles
            .get_or_load_some(&watermarks, &db, id, Freshness::Linearizable, || async {
                role::get(&db, id).await
            })
            .await
    }

    /// Get a role imply rule.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_id`: The ID of the prior role.
    /// - `implied_role_id`: The ID of the implied role.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `RoleImply` if found, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.role.get_role_imply_rule", level = "debug", skip_all, fields(prior_role_id = %prior_role_id, implied_role_id = %implied_role_id))]
    async fn get_role_imply_rule<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
        implied_role_id: &'a str,
    ) -> Result<Option<RoleImply>, RoleProviderError> {
        Ok(self
            .cached_rules(state)
            .await?
            .iter()
            .find(|rule| {
                rule.prior_role.id == prior_role_id && rule.implied_role.id == implied_role_id
            })
            .cloned())
    }

    /// List role imply rules.
    ///
    /// # Parameters
    /// - `state`: The service state.
    ///
    /// # Returns
    /// A `Result` containing a list of `RoleImply`, or an `Error`.
    #[tracing::instrument(
        name = "driver.sql.role.list_role_imply_rules",
        level = "debug",
        skip_all
    )]
    async fn list_role_imply_rules(
        &self,
        state: &ServiceState,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        Ok(self.cached_rules(state).await?.as_ref().clone())
    }

    /// List role imply rules for a specific prior role.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_id`: The ID of the prior role.
    ///
    /// # Returns
    /// A `Result` containing a list of `RoleImply`, or an `Error`.
    #[tracing::instrument(name = "driver.sql.role.list_role_imply_rules_by_prior", level = "trace", skip_all, fields(prior_role_id = %prior_role_id))]
    async fn list_role_imply_rules_by_prior<'a>(
        &self,
        state: &ServiceState,
        prior_role_id: &'a str,
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        Ok(self
            .cached_rules(state)
            .await?
            .iter()
            .filter(|rule| rule.prior_role.id == prior_role_id)
            .cloned()
            .collect())
    }

    /// List role imply rules for any of the given prior roles.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `prior_role_ids`: The IDs of the prior roles.
    ///
    /// # Returns
    /// A `Result` containing a list of `RoleImply`, or an `Error`.
    #[tracing::instrument(name = "driver.sql.role.list_role_imply_rules_by_priors", level = "debug", skip_all, fields(count = prior_role_ids.len()))]
    async fn list_role_imply_rules_by_priors<'a>(
        &self,
        state: &ServiceState,
        prior_role_ids: &[&'a str],
    ) -> Result<Vec<RoleImply>, RoleProviderError> {
        Ok(self
            .cached_rules(state)
            .await?
            .iter()
            .filter(|rule| prior_role_ids.contains(&rule.prior_role.id.as_str()))
            .cloned()
            .collect())
    }

    /// List roles.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters.
    ///
    /// # Returns
    /// A `Result` containing a list of `Role`s, or an `Error`.
    #[tracing::instrument(name = "driver.sql.role.list_roles", level = "debug", skip_all, fields(params = ?params))]
    async fn list_roles(
        &self,
        state: &ServiceState,
        params: &RoleListParameters,
    ) -> Result<Vec<Role>, RoleProviderError> {
        let db = state.db.connection();
        // The lookup of the names of the assigned roles (every token
        // validation): served from the cache, the roles it does not know are
        // read with one query.
        if let Some(ids) = &params.ids
            && params.skip_options
            && params.domain_id.is_none()
            && params.name.is_none()
            && params.pagination == Default::default()
        {
            let watermarks = state.db.watermarks();
            return self
                .caches()
                .names
                .get_or_load_many(
                    &watermarks,
                    &db,
                    ids,
                    Freshness::Linearizable,
                    |missing| async {
                        let roles = role::list(
                            &db,
                            &RoleListParameters {
                                ids: Some(missing),
                                skip_options: true,
                                ..Default::default()
                            },
                        )
                        .await?;
                        Ok::<_, RoleProviderError>(
                            roles
                                .into_iter()
                                .map(|role| (role.id.clone(), role))
                                .collect(),
                        )
                    },
                )
                .await;
        }
        // TODO: Add possibility to list roles with expansion and filter (e.g.,
        // token_restriction has list of roles that need to be returned
        // resolved)
        Ok(role::list(&db, params).await?)
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Set up the database schema.
    ///
    /// # Parameters
    /// - `connection`: The database connection.
    /// - `schema`: The database schema.
    ///
    /// # Returns
    /// A `Result` indicating success or a `DatabaseError`.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::Role).await?;
        create_table(connection, schema, crate::entity::prelude::RoleOption).await?;
        create_table(connection, schema, crate::entity::prelude::ImpliedRole).await?;
        table_watermark::install(connection, table_watermark::ROLE_TABLES).await?;
        Ok(())
    }

    fn migrations(&self) -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
        crate::migration::migrations()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, MockRow};

    use crate::role::NULL_DOMAIN_ID;
    use crate::role::tests::get_role_mock;

    use super::*;
    use openstack_keystone_core_types::role::RoleRefBuilder;

    fn mock_role_with_domain(id: &str, name: &str, domain: &str) -> crate::entity::role::Model {
        crate::entity::role::Model {
            id: id.into(),
            name: name.into(),
            extra: None,
            domain_id: domain.into(),
            description: None,
        }
    }

    fn mock_flat_imply_row(
        prior_id: &str,
        prior_name: &str,
        prior_domain: &str,
        implied_id: &str,
        implied_name: &str,
        implied_domain: &str,
    ) -> MockRow {
        BTreeMap::from([
            ("prior_role_id", prior_id.into()),
            ("prior_role_name", prior_name.into()),
            ("prior_role_domain_id", prior_domain.into()),
            ("implied_role_id", implied_id.into()),
            ("implied_role_name", implied_name.into()),
            ("implied_role_domain_id", implied_domain.into()),
        ])
        .into_mock_row()
    }

    fn mock_flat_imply(
        prior_id: &str,
        prior_name: &str,
        implied_id: &str,
        implied_name: &str,
    ) -> MockRow {
        mock_flat_imply_row(
            prior_id,
            prior_name,
            NULL_DOMAIN_ID,
            implied_id,
            implied_name,
            NULL_DOMAIN_ID,
        )
    }

    #[tokio::test]
    async fn test_expand_no_implies_no_domain_populates_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .append_query_results([Vec::<crate::entity::role_option::Model>::new()])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("foo_domain"));
    }

    #[tokio::test]
    async fn test_expand_adds_implied_roles_and_resolves_names() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![mock_flat_imply("r1", "admin", "r2", "reader")]])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .append_query_results([Vec::<crate::entity::role_option::Model>::new()])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("foo_domain"));
        assert_eq!(roles[1].id, "r2");
        assert_eq!(roles[1].name.as_deref(), Some("reader"));
        assert_eq!(roles[1].domain_id, None);
    }

    #[tokio::test]
    async fn test_expand_recursive_implied_roles_no_duplicates() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                mock_flat_imply("r1", "admin", "r2", "member"),
                mock_flat_imply("r2", "member", "r3", "reader"),
            ]])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .append_query_results([Vec::<crate::entity::role_option::Model>::new()])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 3);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("foo_domain"));
        assert_eq!(roles[1].id, "r2");
        assert_eq!(roles[1].name.as_deref(), Some("member"));
        assert_eq!(roles[2].id, "r3");
        assert_eq!(roles[2].name.as_deref(), Some("reader"));
    }

    #[tokio::test]
    async fn test_expand_preserves_existing_name() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
            .into_connection();

        let mut roles = vec![
            RoleRefBuilder::default()
                .id("r1")
                .name("admin")
                .domain_id("d1")
                .build()
                .unwrap(),
        ];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("d1"));
    }

    #[tokio::test]
    async fn test_expand_empty_roles_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
            .into_connection();

        let mut roles: Vec<RoleRef> = vec![];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn test_expand_implied_role_not_in_rules_skipped() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![mock_flat_imply("r2", "member", "r3", "reader")]])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .append_query_results([Vec::<crate::entity::role_option::Model>::new()])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn test_expand_global_role_has_no_domain_in_output() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<MockRow>::new()])
            .append_query_results([vec![mock_role_with_domain("r1", "admin", "<<null>>")]])
            .append_query_results([Vec::<crate::entity::role_option::Model>::new()])
            .into_connection();

        let mut roles = vec![RoleRef {
            id: "r1".into(),
            name: None,
            domain_id: None,
        }];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id, None);
    }

    #[tokio::test]
    async fn test_expand_multiple_roles_with_mixed_name_states() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![mock_flat_imply("r1", "admin", "r3", "viewer")]])
            .append_query_results([vec![get_role_mock("r1", "admin")]])
            .append_query_results([Vec::<crate::entity::role_option::Model>::new()])
            .into_connection();

        let mut roles = vec![
            RoleRef {
                id: "r1".into(),
                name: None,
                domain_id: None,
            },
            RoleRefBuilder::default()
                .id("r2")
                .name("member")
                .domain_id("d1")
                .build()
                .unwrap(),
        ];

        expand_implied_roles(&db, &mut roles).await.unwrap();

        assert_eq!(roles.len(), 3);
        assert_eq!(roles[0].id, "r1");
        assert_eq!(roles[0].name.as_deref(), Some("admin"));
        assert_eq!(roles[0].domain_id.as_deref(), Some("foo_domain"));
        assert_eq!(roles[1].id, "r2");
        assert_eq!(roles[1].name.as_deref(), Some("member"));
        assert_eq!(roles[1].domain_id.as_deref(), Some("d1"));
        assert_eq!(roles[2].id, "r3");
        assert_eq!(roles[2].name.as_deref(), Some("viewer"));
    }
}
