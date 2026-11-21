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
//! Test that user update persists the user options.

use eyre::Result;
use secrecy::SecretString;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core_types::identity::*;

use crate::common::get_state;
use crate::create_domain;

/// Create a user with a password and the given options.
async fn create_with_options(
    state: &ServiceState,
    domain_id: &str,
    options: Option<UserOptions>,
) -> Result<UserResponse> {
    let mut builder = UserCreateBuilder::default();
    builder
        .id(Uuid::new_v4().simple().to_string())
        .name(Uuid::new_v4().simple().to_string())
        .domain_id(domain_id)
        .enabled(true)
        .password("old_pass");
    if let Some(opts) = options {
        builder.options(opts);
    }
    Ok(state
        .provider
        .get_identity_provider()
        .create_user(&ExecutionContext::internal(state), builder.build()?)
        .await?)
}

#[tokio::test]
#[traced_test]
async fn test_update_options_persisted() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_with_options(&state, &domain.id, None).await?;
    let prov = state.provider.get_identity_provider();

    let updated = prov
        .update_user(
            &ExecutionContext::internal(&state),
            &user.id,
            UserUpdateBuilder::default()
                .options(UserOptions {
                    lock_password: Some(true),
                    ..Default::default()
                })
                .build()?,
        )
        .await?;
    assert_eq!(updated.options.lock_password, Some(true));

    let fetched = prov
        .get_user(&ExecutionContext::internal(&state), &user.id)
        .await?
        .expect("user found");
    assert_eq!(fetched.options.lock_password, Some(true), "persisted");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_options_replaces_and_keeps_others() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_with_options(
        &state,
        &domain.id,
        Some(UserOptions {
            lock_password: Some(true),
            ignore_password_expiry: Some(true),
            ..Default::default()
        }),
    )
    .await?;
    let prov = state.provider.get_identity_provider();

    // Only `lock_password` is sent: it is replaced, the rest is kept.
    prov.update_user(
        &ExecutionContext::internal(&state),
        &user.id,
        UserUpdateBuilder::default()
            .options(UserOptions {
                lock_password: Some(false),
                ..Default::default()
            })
            .build()?,
    )
    .await?;

    let fetched = prov
        .get_user(&ExecutionContext::internal(&state), &user.id)
        .await?
        .expect("user found");
    assert_eq!(fetched.options.lock_password, Some(false));
    assert_eq!(fetched.options.ignore_password_expiry, Some(true));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_update_without_options_keeps_options() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_with_options(
        &state,
        &domain.id,
        Some(UserOptions {
            lock_password: Some(true),
            ..Default::default()
        }),
    )
    .await?;
    let prov = state.provider.get_identity_provider();

    prov.update_user(
        &ExecutionContext::internal(&state),
        &user.id,
        UserUpdateBuilder::default().enabled(false).build()?,
    )
    .await?;

    let fetched = prov
        .get_user(&ExecutionContext::internal(&state), &user.id)
        .await?
        .expect("user found");
    assert_eq!(fetched.options.lock_password, Some(true));
    Ok(())
}

/// The lock blocks the self-service change until it is cleared by an update.
#[tokio::test]
#[traced_test]
async fn test_update_options_clears_lock_password() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_with_options(
        &state,
        &domain.id,
        Some(UserOptions {
            lock_password: Some(true),
            ..Default::default()
        }),
    )
    .await?;
    let prov = state.provider.get_identity_provider();

    let res = prov
        .update_user_password(
            &ExecutionContext::internal(&state),
            &user.id,
            SecretString::from("old_pass"),
            SecretString::from("new_pass"),
        )
        .await;
    assert!(
        matches!(res, Err(IdentityProviderError::PasswordLocked(_))),
        "{res:?}"
    );

    prov.update_user(
        &ExecutionContext::internal(&state),
        &user.id,
        UserUpdateBuilder::default()
            .options(UserOptions {
                lock_password: Some(false),
                ..Default::default()
            })
            .build()?,
    )
    .await?;

    prov.update_user_password(
        &ExecutionContext::internal(&state),
        &user.id,
        SecretString::from("old_pass"),
        SecretString::from("new_pass"),
    )
    .await?;
    Ok(())
}
