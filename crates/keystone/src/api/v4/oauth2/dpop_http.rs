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
//! HTTP-level DPoP rules shared by the `/token` endpoint and the resource
//! endpoints (RFC 9449, ADR 0043). They live in core, because the `Auth`
//! extractor verifies proofs too (ADR 0049).

pub(super) use openstack_keystone_core::oauth2_client::dpop_resource::{
    charge_key, proof_header, replay_retry_after,
};
