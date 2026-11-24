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

pub use openstack_keystone_api_types::v3::auth::token::*;

/// The policy `existing` object of the token show and revoke policies.
///
/// Borrows the response token, so the policy input is serialized straight from
/// it instead of from an intermediate JSON value tree.
#[derive(serde::Serialize)]
pub(super) struct ExistingToken<'a> {
    /// The stored token.
    pub token: &'a Token,
}
