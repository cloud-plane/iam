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
//! # Catalog provider
//!
//! Catalog provider takes care of returning the list of the service endpoints
//! that the API user is able to use according to the valid authentication.
//!
//! Following Keystone concepts are covered:
//!
//! ## Endpoint
//!
//! A network-accessible address, usually a URL, through which you can access a
//! service. If you are using an extension for templates, you can create an
//! endpoint template that represents the templates of all consumable services
//! that are available across the regions.
//!
//! ## Service
//!
//! An OpenStack service, such as Compute (nova), Object Storage (swift), or
//! Image service (glance), that provides one or more endpoints through which
//! users can access resources and perform operations.
mod response_cache;

pub use openstack_keystone_core::catalog::*;
pub use response_cache::{CATALOG_RESPONSE_CACHE, CatalogResponseCache};

use std::sync::Arc;

use openstack_keystone_api_types::catalog::Catalog;
use openstack_keystone_core::auth::ExecutionContext;

use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Fetch the catalog of enabled services and return it in its shared,
/// response-shaped form.
///
/// Single place that chooses the `enabled` filter, so the driver call and the
/// response cache key cannot drift apart.
pub async fn response_catalog(
    state: &ServiceState,
    exec: &ExecutionContext<'_>,
) -> Result<Arc<Catalog>, KeystoneApiError> {
    const ENABLED: bool = true;
    let shared = state
        .provider
        .get_catalog_provider()
        .get_catalog(exec, ENABLED)
        .await?;
    Ok(CATALOG_RESPONSE_CACHE.get_or_build(&shared, ENABLED))
}
