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

use std::ops::Deref;

use openstack_keystone_api_types::scope as api_scope;
use openstack_keystone_api_types::v3::auth::token::{System, TokenConfirmation};
use openstack_keystone_api_types::v3::auth::token::{TokenBuilder, UserBuilder};
use openstack_keystone_core_types::auth::ScopeInfo;
use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::error::BuilderError;

use crate::auth::ValidatedSecurityContext;

impl TryFrom<&ValidatedSecurityContext> for TokenBuilder {
    type Error = BuilderError;

    fn try_from(vsc: &ValidatedSecurityContext) -> Result<Self, Self::Error> {
        let ctx = vsc.deref();

        let fernet = ctx.token().ok_or_else(|| {
            BuilderError::Validation("security context does not contain a FernetToken".to_string())
        })?;

        let mut methods: Vec<String> = ctx.auth_methods().iter().cloned().collect();
        methods.sort();
        let response = TokenBuilder::default()
            .issued_at(*fernet.issued_at())
            .expires_at(*fernet.expires_at())
            .audit_ids(ctx.audit_ids().to_vec())
            .methods(methods);

        let response = match ctx.confirmation() {
            Some(cnf) => response.cnf(TokenConfirmation {
                jkt: cnf.jkt.clone(),
            }),
            None => response,
        };

        let response = fill_identity_info(response, ctx)?;

        match ctx.authorization() {
            Some(authz) => fill_scope(response, authz),
            None => Ok(response),
        }
    }
}

/// Fill identity information in the Token response.
fn fill_identity_info(
    response: TokenBuilder,
    ctx: &SecurityContext,
) -> Result<TokenBuilder, BuilderError> {
    match &ctx.principal().identity {
        IdentityInfo::User(user) => {
            let mut user_builder = UserBuilder::default();
            user_builder.id(user.user_id.clone());
            if let Some(user_name) = user.user.as_ref().map(|u| u.name.clone()) {
                user_builder.name(user_name);
            }
            if let Some(password_expires_at) =
                user.user.as_ref().and_then(|u| u.password_expires_at)
            {
                user_builder.password_expires_at(password_expires_at);
            }
            let user_domain: openstack_keystone_api_types::scope::Domain =
                user.user_domain.as_ref().map(Into::into).ok_or_else(|| {
                    BuilderError::Validation("user identity: user_domain not populated".to_string())
                })?;
            user_builder.domain(user_domain);
            Ok(response.user(user_builder.build()?))
        }
        IdentityInfo::Principal(principal) => {
            let mut user_builder = UserBuilder::default();
            user_builder.id(ctx.principal().get_user_id().clone());
            // Use resolved user name from mapping rule if available, fall back
            // to id
            user_builder.name(
                principal
                    .resolved_user_name
                    .clone()
                    .unwrap_or_else(|| principal.id.clone()),
            );
            let identity_domain: openstack_keystone_api_types::scope::Domain =
                principal.domain.as_ref().map(Into::into).ok_or_else(|| {
                    BuilderError::Validation("principal identity: domain not populated".to_string())
                })?;
            user_builder.domain(identity_domain);
            Ok(response.user(user_builder.build()?))
        }
    }
}

/// Fill the scope information in the Token response.
fn fill_scope(response: TokenBuilder, authz: &AuthzInfo) -> Result<TokenBuilder, BuilderError> {
    let response = match &authz.scope {
        ScopeInfo::Domain(core_domain) => {
            let api_domain: api_scope::Domain = core_domain.clone().into();
            response.domain(api_domain)
        }
        ScopeInfo::Project {
            project,
            project_domain,
        } => response.project(api_scope::Project {
            id: project.id.clone(),
            name: project.name.clone(),
            domain: project_domain.into(),
        }),
        ScopeInfo::System(_system_id) => response.system(System { all: true }),
        ScopeInfo::TrustProject(tpi) => response
            .project(api_scope::Project {
                id: tpi.project.id.clone(),
                name: tpi.project.name.clone(),
                domain: tpi.project_domain.clone().into(),
            })
            .trust(&tpi.trust),
        ScopeInfo::Unscoped => response,
    };

    Ok(match authz.effective_roles() {
        Some(roles) => response.roles(roles.iter().cloned().map(Into::into).collect::<Vec<_>>()),
        None => response,
    })
}
