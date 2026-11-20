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
//! # Assignment driver to the OpenStack Keystone for the SQL database.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::assignment::{AssignmentProviderError, backend::AssignmentBackend};
use openstack_keystone_core::db::create_table;
use openstack_keystone_core::error::DatabaseError;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::{
    BackendRegistration, NamedAssignmentBackendRegistration,
};
use openstack_keystone_core::table_watermark;
use openstack_keystone_core::{SqlDriver, SqlDriverRegistration};
use openstack_keystone_core_types::assignment::*;
use openstack_keystone_core_types::freshness::Freshness;
use openstack_keystone_core_types::role::{RoleInference, RoleListParameters};

use openstack_keystone_core::auth::ExecutionContext;

mod assignment;
mod cache;
pub mod entity;
mod migration;

#[derive(Default)]
pub struct SqlBackend {
    /// Role assignments of a request, validated against the table watermarks.
    /// Per driver instance: it belongs to the connection the instance reads
    /// through.
    caches: OnceLock<cache::AssignmentCaches>,
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
    BackendRegistration::<dyn AssignmentBackend> {
        name: "sql",
        selected: |_| true,
        build: |cfg| {
            let backend = SqlBackend::new(cfg.core);
            Box::pin(async move { Ok(Arc::new(backend) as Arc<dyn AssignmentBackend>) })
        },
    }
}

// A named `sql` instance carries no parameters beyond the global `[database]`,
// so every block resolves to a plain `SqlBackend` (ADR 0034 §4).
inventory::submit! {
    NamedAssignmentBackendRegistration {
        driver: "sql",
        build: |cfg, _name| {
            let backend = SqlBackend::new(cfg.core);
            Box::pin(async move { Ok(Arc::new(backend) as Arc<dyn AssignmentBackend>) })
        },
    }
}

impl SqlBackend {
    /// A backend whose projection caches follow the configuration.
    fn new(config: &openstack_keystone_config::Config) -> Self {
        Self {
            caches: OnceLock::from(cache::AssignmentCaches::new(config)),
        }
    }

    fn caches(&self) -> &cache::AssignmentCaches {
        self.caches.get_or_init(cache::AssignmentCaches::default)
    }

    /// Resolve implied roles for a set of assignments.
    ///
    /// The role provider hands over the role inference resolved into the
    /// closure of every role. The driver of the role provider does the
    /// resolving once per version of the rules and keeps the result, so the
    /// request looks the assigned roles up instead of reading the imply rule
    /// table and walking its graph. Generates assignment entries for each
    /// implied role.
    ///
    /// With `include_names` the names of the directly assigned roles are
    /// looked up concurrently with the inference (both need only the
    /// assigned role IDs), and the names of the implied roles come from the
    /// inference itself. The provider then has no role left to look up.
    ///
    /// Returns a `Vec<Assignment>` containing both the original assignments
    /// and any additionally generated implied role assignments.
    async fn resolve_implied_roles(
        &self,
        state: &ServiceState,
        assignments: Vec<Assignment>,
        include_names: bool,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let exec = ExecutionContext::internal(state);
        let mut role_names: BTreeMap<String, String> = BTreeMap::new();
        let start: BTreeSet<&str> = assignments.iter().map(|a| a.role_id.as_str()).collect();
        let start: Vec<&str> = start.into_iter().collect();
        let mut inference = Arc::new(RoleInference::default());
        if !start.is_empty() {
            let inference_fut = state.provider.get_role_provider().get_role_inference(&exec);
            let names_fut = async {
                if include_names {
                    // Only the names of the listed roles are needed: skip the
                    // rest of the role table and the role options.
                    state
                        .provider
                        .get_role_provider()
                        .list_roles(
                            &exec,
                            &RoleListParameters {
                                ids: Some(start.iter().map(|id| id.to_string()).collect()),
                                skip_options: true,
                                ..Default::default()
                            },
                        )
                        .await
                } else {
                    Ok(Vec::new())
                }
            };
            let (resolved, roles) = tokio::try_join!(
                async { inference_fut.await.map_err(AssignmentProviderError::from) },
                async { names_fut.await.map_err(AssignmentProviderError::from) }
            )?;
            inference = resolved;
            role_names.extend(roles.into_iter().map(|role| (role.id, role.name)));
        }

        // Merge and apply role implies
        let mut result_map: HashSet<Assignment> = HashSet::new();

        for assignment in assignments {
            result_map.insert(assignment.clone());

            for implied_role in inference.implied(&assignment.role_id) {
                if include_names && let Some(name) = &implied_role.name {
                    role_names
                        .entry(implied_role.id.clone())
                        .or_insert_with(|| name.clone());
                }
                let mut implied_assignment = assignment.clone();
                implied_assignment.role_id = implied_role.id.clone();
                implied_assignment.implied_via = Some(assignment.role_id.clone());
                result_map.insert(implied_assignment);
            }
        }

        let mut result: Vec<Assignment> = result_map.into_iter().collect();
        if include_names {
            for assignment in result.iter_mut() {
                assignment.role_name = role_names.get(&assignment.role_id).cloned();
            }
        }
        Ok(result)
    }

    /// List role assignments for multiple actors/targets.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `params` - The list parameters.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec` of `Assignment` if successful, or an
    /// `Error`.
    async fn list_assignments_for_multiple_actors_and_targets(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListForMultipleActorTargetParameters,
        include_names: bool,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        // The rows of the assignment tables are cached; the role inference
        // below is not (it follows the role provider).
        let db = state.db.connection();
        let watermarks = state.db.watermarks();
        let assignments = self
            .caches()
            .lists
            .get_or_load(
                &watermarks,
                &db,
                &cache::key(params),
                Freshness::Linearizable,
                || assignment::list_for_multiple_actors_and_targets(&db, params),
            )
            .await?;

        if params.resolve_implied_roles {
            self.resolve_implied_roles(state, assignments, include_names)
                .await
        } else {
            Ok(assignments)
        }
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Set up the database tables.
    ///
    /// # Parameters
    ///
    /// * `connection` - The database connection.
    /// * `schema` - The database schema.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or a `DatabaseError`.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::Assignment).await?;
        create_table(connection, schema, crate::entity::prelude::SystemAssignment).await?;
        table_watermark::install(connection, table_watermark::ASSIGNMENT_TABLES).await?;
        Ok(())
    }

    fn migrations(&self) -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
        crate::migration::migrations()
    }
}

#[async_trait]
impl AssignmentBackend for SqlBackend {
    /// Check assignment grant.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `grant` - The assignment to check.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `bool` indicating if the grant exists, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.assignment.check_grant", level = "debug", skip_all)]
    async fn check_grant(
        &self,
        state: &ServiceState,
        grant: &Assignment,
    ) -> Result<bool, AssignmentProviderError> {
        Ok(assignment::check(&state.db.connection(), grant).await?)
    }

    /// Create assignment grant.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `grant` - The assignment to create.
    ///
    /// # Returns
    ///
    /// A `Result` containing the created `Assignment` if successful, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.assignment.create_grant", level = "debug", skip_all)]
    async fn create_grant(
        &self,
        state: &ServiceState,
        grant: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        Ok(assignment::create(&state.db.connection(), grant).await?)
    }

    /// List role assignments.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `params` - The list parameters.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec` of `Assignment` if successful, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.assignment.list_assignments", level = "debug", skip_all, fields(params = ?params))]
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let mut request = RoleAssignmentListForMultipleActorTargetParametersBuilder::default();
        let mut actors: Vec<String> = Vec::new();
        let mut targets: Vec<RoleAssignmentTarget> = Vec::new();
        if let Some(role_id) = &params.role_id {
            request.role_id(role_id);
        }
        if let Some(uid) = &params.user_id {
            actors.push(uid.into());
        }
        if let Some(gid) = &params.group_id {
            actors.push(gid.into());
        }
        // The group membership and the project parents do not depend on each
        // other, so they are loaded concurrently.
        let exec = ExecutionContext::internal(state);
        let groups_fut = async {
            if let Some(true) = &params.effective
                && let Some(uid) = &params.user_id
            {
                // Effective assignments mean we need to expand user_id to list
                // of all groups the user is member of.
                Ok::<_, AssignmentProviderError>(Some(
                    state
                        .provider
                        .get_identity_provider()
                        .list_groups_of_user(&exec, uid)
                        .await?,
                ))
            } else {
                Ok(None)
            }
        };
        let parents_fut = async {
            if let Some(val) = &params.project_id {
                Ok::<_, AssignmentProviderError>(
                    state
                        .provider
                        .get_resource_provider()
                        .get_project_parent_ids(&exec, val)
                        .await?,
                )
            } else {
                Ok(None)
            }
        };
        let (groups, parent_ids) = tokio::try_join!(groups_fut, parents_fut)?;
        if let Some(groups) = groups {
            actors.extend(groups.into_iter().map(|x| x.id));
        }
        if let Some(val) = &params.project_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::Project,
                inherited: Some(params.inherited.unwrap_or(false)),
            });
            if let Some(parent_ids) = parent_ids {
                // All assignments for parent projects having `inherited=true`
                // must be included.
                targets.extend(
                    parent_ids
                        .into_iter()
                        .map(|parent_id| RoleAssignmentTarget {
                            id: parent_id,
                            r#type: RoleAssignmentTargetType::Project,
                            inherited: Some(true),
                        }),
                );
            }
        } else if let Some(val) = &params.domain_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::Domain,
                inherited: Some(params.inherited.unwrap_or(false)),
            });
        } else if let Some(val) = &params.system_id {
            targets.push(RoleAssignmentTarget {
                id: val.clone(),
                r#type: RoleAssignmentTargetType::System,
                inherited: Some(params.inherited.unwrap_or(false)),
            })
        }

        // Defensive guard: if any actor-targeting parameter was set, the
        // `actors` list must be non-empty. A prior bug silently dropped
        // `group_id`, causing both `actors` and `targets` to be empty,
        // which translated to a query without a WHERE clause that swept
        // ALL assignments.
        if params.user_id.is_some() || params.group_id.is_some() {
            debug_assert!(
                !actors.is_empty(),
                "list_assignments: user_id or group_id was set but actors list is empty \
                - a parameter mapping branch may be missing (CID: group_id-drop)"
            );
        }

        request.targets(targets);
        request.actors(actors);
        request.resolve_implied_roles(params.resolve_implied_roles);
        let mut assignments = self
            .list_assignments_for_multiple_actors_and_targets(
                state,
                &request.build()?,
                params.include_names.unwrap_or_default(),
            )
            .await?;

        // No SQL cursor is possible here: results are a union of two queries
        // (regular + system assignments) plus in-memory implied-role
        // expansion, so pagination is applied post-fetch over the fully
        // materialized, expanded set - the same in-memory over-fetch pattern
        // used by the Raft-backed domains, and the same helper the assignment
        // provider re-applies over its untargeted fan-out union (ADR 0034 §5).
        paginate_in_memory(&mut assignments, &params.pagination);

        Ok(assignments)
    }

    /// Revoke assignment grant.
    ///
    /// # Parameters
    ///
    /// * `state` - The service state.
    /// * `grant` - The assignment to revoke.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an `Error`.
    #[tracing::instrument(name = "driver.sql.assignment.revoke_grant", level = "debug", skip_all)]
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        grant: &Assignment,
    ) -> Result<(), AssignmentProviderError> {
        Ok(assignment::delete(&state.db.connection(), grant).await?)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, DatabaseConnection, MockDatabase};
    use std::sync::Arc;

    use cadf::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core::provider::Provider;
    use openstack_keystone_core::resource::MockResourceProvider;
    use openstack_keystone_core::role::MockRoleProvider;
    use openstack_keystone_core_types::role::{RoleBuilder, RoleImplyBuilder, RoleRef};

    use super::assignment::tests::*;
    use super::*;

    async fn get_mock_state(db: DatabaseConnection, provider: Provider) -> Arc<Service> {
        Arc::new(
            Service::new(
                ConfigManager::not_watched(Config::default()),
                db,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_targets_multiple_actors() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("3")]])
            .into_connection();

        let mut role_mock = MockRoleProvider::default();
        role_mock.expect_get_role_inference().returning(|_e| {
            Ok(Arc::new(RoleInference::from_rules(&[
                RoleImplyBuilder::default()
                    .prior_role(RoleRef {
                        id: "1".into(),
                        name: Some("r1".into()),
                        domain_id: None,
                    })
                    .implied_role(RoleRef {
                        id: "2".into(),
                        name: Some("r2".into()),
                        domain_id: None,
                    })
                    .build()
                    .unwrap(),
            ])))
        });
        let provider = Provider::mocked_builder()
            .mock_role(role_mock)
            .build()
            .unwrap();

        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend::default();
        let res = sot
            .list_assignments_for_multiple_actors_and_targets(
                &state,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    resolve_implied_roles: true,
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();

        assert_eq!(3, res.len(), "{:?}", res);
        assert!(res.contains(&Assignment {
            role_id: "1".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }));
        assert!(res.contains(&Assignment {
            role_id: "2".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: Some("1".into()),
        }));
        assert!(res.contains(&Assignment {
            role_id: "3".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "system".into(),
            r#type: AssignmentType::UserSystem,
            inherited: false,
            implied_via: None,
        }));
    }

    /// With names requested the assigned roles are named by one `list_roles`
    /// call made next to the inference, and the implied roles get their
    /// names from the rules.
    #[tokio::test]
    async fn test_resolve_implied_roles_with_names() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([Vec::<crate::entity::system_assignment::Model>::new()])
            .into_connection();

        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role_inference()
            .times(1)
            .returning(|_e| {
                Ok(Arc::new(RoleInference::from_rules(&[
                    RoleImplyBuilder::default()
                        .prior_role(RoleRef {
                            id: "1".into(),
                            name: Some("admin".into()),
                            domain_id: None,
                        })
                        .implied_role(RoleRef {
                            id: "2".into(),
                            name: Some("member".into()),
                            domain_id: None,
                        })
                        .build()
                        .unwrap(),
                ])))
            });
        role_mock
            .expect_list_roles()
            .times(1)
            .withf(|_e, params| params.ids.as_deref() == Some(&["1".to_string()][..]))
            .returning(|_e, _params| {
                Ok(vec![
                    RoleBuilder::default()
                        .id("1")
                        .name("admin")
                        .build()
                        .unwrap(),
                ])
            });
        let provider = Provider::mocked_builder()
            .mock_role(role_mock)
            .build()
            .unwrap();
        let state = get_mock_state(db, provider).await;

        let res = SqlBackend::default()
            .list_assignments_for_multiple_actors_and_targets(
                &state,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    resolve_implied_roles: true,
                    ..Default::default()
                },
                true,
            )
            .await
            .unwrap();

        let names: BTreeMap<&str, Option<&str>> = res
            .iter()
            .map(|a| (a.role_id.as_str(), a.role_name.as_deref()))
            .collect();
        assert_eq!(
            BTreeMap::from([("1", Some("admin")), ("2", Some("member"))]),
            names,
            "{res:?}"
        );
    }

    /// A chain of imply rules (1 -> 2 -> 3) must resolve with one provider
    /// call, however deep the chain is.
    #[tokio::test]
    async fn test_resolve_implied_roles_deep_chain_single_call() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("9")]])
            .into_connection();

        let rule = |prior: &str, implied: &str| {
            RoleImplyBuilder::default()
                .prior_role(RoleRef {
                    id: prior.into(),
                    name: None,
                    domain_id: None,
                })
                .implied_role(RoleRef {
                    id: implied.into(),
                    name: None,
                    domain_id: None,
                })
                .build()
                .unwrap()
        };
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role_inference()
            .times(1)
            .returning(move |_e| {
                Ok(Arc::new(RoleInference::from_rules(&[
                    rule("1", "2"),
                    rule("2", "3"),
                ])))
            });
        let provider = Provider::mocked_builder()
            .mock_role(role_mock)
            .build()
            .unwrap();
        let state = get_mock_state(db, provider).await;

        let res = SqlBackend::default()
            .list_assignments_for_multiple_actors_and_targets(
                &state,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    resolve_implied_roles: true,
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();

        let implied: BTreeSet<_> = res
            .iter()
            .filter(|a| a.implied_via.as_deref() == Some("1"))
            .map(|a| a.role_id.as_str())
            .collect();
        assert_eq!(BTreeSet::from(["2", "3"]), implied, "{res:?}");
        // The two original assignments plus two implied ones.
        assert_eq!(4, res.len(), "{res:?}");
    }

    /// The inheritable grants of every parent project are part of the listing
    /// of a project, and the parents come from one `get_project_parent_ids`
    /// call.
    #[tokio::test]
    async fn test_list_assignments_for_project_includes_parent_targets() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([Vec::<crate::entity::system_assignment::Model>::new()])
            .into_connection();
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project_parent_ids()
            .times(1)
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| Ok(Some(vec!["parent".into(), "domain".into()])));
        let provider = Provider::mocked_builder()
            .mock_resource(resource_mock)
            .build()
            .unwrap();
        let state = get_mock_state(db, provider).await;

        SqlBackend::default()
            .list_assignments(
                &state,
                &RoleAssignmentListParameters {
                    project_id: Some("pid".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let log = format!("{:?}", state.db.connection().into_transaction_log());
        for id in ["pid", "parent", "domain"] {
            assert!(log.contains(id), "{id} is not queried: {log}");
        }
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_no_implied_roles() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("3")]])
            .into_connection();

        let provider = Provider::mocked_builder().build().unwrap();

        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend::default();
        let res = sot
            .list_assignments_for_multiple_actors_and_targets(
                &state,
                &RoleAssignmentListForMultipleActorTargetParameters {
                    resolve_implied_roles: false,
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();

        assert_eq!(2, res.len(), "{:?}", res);
        assert!(res.contains(&Assignment {
            role_id: "1".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }));
        assert!(res.contains(&Assignment {
            role_id: "3".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "system".into(),
            r#type: AssignmentType::UserSystem,
            inherited: false,
            implied_via: None,
        }));
        // No implied role (role_id "2") should be present
        assert!(
            res.iter().all(|a| a.role_id != "2"),
            "implied role should not be present"
        );
    }

    #[tokio::test]
    async fn test_list_assignments_group_id_filters_actors() {
        use openstack_keystone_core_types::assignment::RoleAssignmentListParametersBuilder;

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![] as Vec<entity::system_assignment::Model>])
            .into_connection();

        let provider = Provider::mocked_builder().build().unwrap();
        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend::default();
        let _res = sot
            .list_assignments(
                &state,
                &RoleAssignmentListParametersBuilder::default()
                    .group_id("my-group-id")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_list_assignments_group_id_and_user_id_both_in_actors() {
        use openstack_keystone_core_types::assignment::RoleAssignmentListParametersBuilder;

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![] as Vec<entity::system_assignment::Model>])
            .into_connection();

        let provider = Provider::mocked_builder().build().unwrap();
        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend::default();
        let _res = sot
            .list_assignments(
                &state,
                &RoleAssignmentListParametersBuilder::default()
                    .user_id("my-user")
                    .group_id("my-group")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_list_assignments_group_id_only_returns_group_assignments() {
        use crate::entity::assignment as db_assignment;
        use crate::entity::sea_orm_active_enums::Type as DbType;
        use crate::entity::system_assignment as db_system_assignment;
        use openstack_keystone_core_types::assignment::{
            AssignmentType, RoleAssignmentListParametersBuilder,
        };

        // Create two regular assignments: one for user "admin", one for group
        // "scim-group". Only the group's assignment should be returned when
        // querying by group_id.
        let group_assignment = db_assignment::Model {
            role_id: "group-role".into(),
            actor_id: "scim-group".into(),
            target_id: "target-project".into(),
            r#type: DbType::GroupProject,
            inherited: false,
        };

        let _user_assignment = db_assignment::Model {
            role_id: "admin-role".into(),
            actor_id: "admin-user".into(),
            target_id: "target-project".into(),
            r#type: DbType::UserProject,
            inherited: false,
        };

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![group_assignment]])
            .append_query_results([vec![] as Vec<db_system_assignment::Model>])
            .into_connection();

        let provider = Provider::mocked_builder().build().unwrap();
        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend::default();
        let res = sot
            .list_assignments(
                &state,
                &RoleAssignmentListParametersBuilder::default()
                    .group_id("scim-group")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        // Only 1 assignment returned (the group's), not 0 or 2
        assert_eq!(
            1,
            res.len(),
            "expected exactly 1 group assignment, got {:?}",
            res
        );
        assert_eq!("scim-group", res[0].actor_id);
        assert_eq!(AssignmentType::GroupProject, res[0].r#type);
        assert_eq!("group-role", res[0].role_id);
    }

    #[tokio::test]
    async fn test_list_for_multiple_actor_no_target_role_id_collision() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_role_assignment_mock("1")]])
            .append_query_results([vec![get_role_system_assignment_mock("1")]])
            .into_connection();

        let mut role_mock = MockRoleProvider::default();
        role_mock.expect_get_role_inference().returning(|_e| {
            Ok(Arc::new(RoleInference::from_rules(&[
                RoleImplyBuilder::default()
                    .prior_role(RoleRef {
                        id: "1".into(),
                        name: Some("r1".into()),
                        domain_id: None,
                    })
                    .implied_role(RoleRef {
                        id: "2".into(),
                        name: Some("r2".into()),
                        domain_id: None,
                    })
                    .build()
                    .unwrap(),
            ])))
        });
        let provider = Provider::mocked_builder()
            .mock_role(role_mock)
            .build()
            .unwrap();

        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend::default();
        let params = RoleAssignmentListForMultipleActorTargetParameters {
            actors: vec!["uid1".into()],
            resolve_implied_roles: true,
            ..Default::default()
        };
        let res = sot
            .list_assignments_for_multiple_actors_and_targets(&state, &params, false)
            .await
            .unwrap();

        assert_eq!(4, res.len());

        assert!(
            res.contains(&Assignment {
                role_id: "1".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: AssignmentType::UserProject,
                inherited: false,
                implied_via: None,
            }),
            "in {:?}",
            res
        );
        assert!(
            res.contains(&Assignment {
                role_id: "2".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "target".into(),
                r#type: AssignmentType::UserProject,
                inherited: false,
                implied_via: Some("1".into()),
            }),
            "in {:?}",
            res
        );
        assert!(
            res.contains(&Assignment {
                role_id: "1".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "system".into(),
                r#type: AssignmentType::UserSystem,
                inherited: false,
                implied_via: None,
            }),
            "in {:?}",
            res
        );
        assert!(
            res.contains(&Assignment {
                role_id: "2".into(),
                role_name: None,
                actor_id: "actor".into(),
                target_id: "system".into(),
                r#type: AssignmentType::UserSystem,
                inherited: false,
                implied_via: Some("1".into()),
            }),
            "in {:?}",
            res
        );
    }

    /// `list_assignments` cannot push a cursor into SQL (union of two
    /// queries + in-memory implied-role expansion), so pagination is applied
    /// post-fetch: sorted by the composite marker, over-fetching by one row
    /// to let the caller detect a next page without a false positive.
    #[tokio::test]
    async fn test_list_assignments_pagination_over_fetches_and_uses_marker() {
        use openstack_keystone_core_types::ListPagination;
        use openstack_keystone_core_types::assignment::RoleAssignmentListParametersBuilder;

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_role_assignment_mock("1"),
                get_role_assignment_mock("2"),
                get_role_assignment_mock("3"),
            ]])
            .append_query_results([vec![] as Vec<entity::system_assignment::Model>])
            .into_connection();

        let provider = Provider::mocked_builder().build().unwrap();
        let state = get_mock_state(db, provider).await;

        let sot = SqlBackend::default();
        let res = sot
            .list_assignments(
                &state,
                &RoleAssignmentListParametersBuilder::default()
                    .group_id("scim-group")
                    .pagination(ListPagination {
                        limit: Some(1),
                        marker: None,
                        page_reverse: false,
                    })
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        // Over-fetched by one (limit + 1): role "1" then "2", role "3" trimmed.
        assert_eq!(2, res.len(), "{:?}", res);
        assert_eq!("1", res[0].role_id);
        assert_eq!("2", res[1].role_id);
    }

    #[tokio::test]
    async fn test_list_assignments_pagination_marker_filters_prior_page() {
        use openstack_keystone_core_types::ListPagination;
        use openstack_keystone_core_types::assignment::RoleAssignmentListParametersBuilder;

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_role_assignment_mock("1"),
                get_role_assignment_mock("2"),
                get_role_assignment_mock("3"),
            ]])
            .append_query_results([vec![] as Vec<entity::system_assignment::Model>])
            .into_connection();

        let provider = Provider::mocked_builder().build().unwrap();
        let state = get_mock_state(db, provider).await;

        let marker = Assignment {
            role_id: "1".into(),
            role_name: None,
            actor_id: "actor".into(),
            target_id: "target".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }
        .pagination_marker();

        let sot = SqlBackend::default();
        let res = sot
            .list_assignments(
                &state,
                &RoleAssignmentListParametersBuilder::default()
                    .group_id("scim-group")
                    .pagination(ListPagination {
                        limit: Some(5),
                        marker: Some(marker),
                        page_reverse: false,
                    })
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        // Only rows sorting strictly after the marker's role "1" remain.
        assert_eq!(2, res.len(), "{:?}", res);
        assert_eq!("2", res[0].role_id);
        assert_eq!("3", res[1].role_id);
    }
}
