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

//! The rule that decides whether a stored event revokes a token.
//!
//! The same rule as the SQL driver: every dimension an event sets must equal
//! the value of the token, and a dimension the event leaves empty matches
//! everything. The token side comes from `RevocationEventListParameters`.
//!
//! An event also has an origin, and only revokes tokens of that origin: an
//! event of another authority revokes the tokens that authority issued and
//! nothing else, so a compromised or mistaken authority cannot revoke the
//! tokens of a different one.

use openstack_keystone_core_types::revoke::RevocationEventListParameters;

use crate::EventRecord;

/// Whether `event` revokes the token described by `params`.
pub(crate) fn revokes(event: &EventRecord, params: &RevocationEventListParameters) -> bool {
    let one = |event: &Option<String>, token: &Option<String>| match event {
        None => true,
        Some(e) => token.as_ref() == Some(e),
    };
    let any = |event: &Option<String>, token: &Option<Vec<String>>| match event {
        None => true,
        Some(e) => token.as_ref().is_some_and(|t| t.contains(e)),
    };
    event.origin == params.issuer
        && one(&event.audit_id, &params.audit_id)
        && one(&event.audit_chain_id, &params.audit_chain_id)
        && one(&event.access_token_id, &params.access_token_id)
        && any(&event.domain_id, &params.domain_ids)
        && one(&event.trust_id, &params.trust_id)
        && one(&event.project_id, &params.project_id)
        && any(&event.role_id, &params.role_ids)
        && any(&event.user_id, &params.user_ids)
        && params
            .expires_at
            .is_none_or(|v| event.expires_at == Some(v.timestamp_micros()))
        && params
            .issued_before
            .is_none_or(|v| event.issued_before >= v.timestamp_micros())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use openstack_keystone_core_types::revoke::{
        RevocationEventCreate, RevocationEventListParametersBuilder,
    };

    use super::*;

    fn record(chain: Option<&str>, access: Option<&str>) -> EventRecord {
        EventRecord::new(&RevocationEventCreate {
            audit_chain_id: chain.map(Into::into),
            access_token_id: access.map(Into::into),
            issued_before: Utc::now(),
            revoked_at: Utc::now(),
            ..Default::default()
        })
    }

    fn token(chain: Option<&str>, access: Option<&str>) -> RevocationEventListParameters {
        let mut builder = RevocationEventListParametersBuilder::default();
        builder.audit_id("a");
        if let Some(chain) = chain {
            builder.audit_chain_id(chain);
        }
        if let Some(access) = access {
            builder.access_token_id(access);
        }
        builder.build().unwrap()
    }

    #[test]
    fn test_chain_and_access_token_must_equal() {
        let chain = record(Some("c1"), None);
        assert!(revokes(&chain, &token(Some("c1"), None)));
        assert!(!revokes(&chain, &token(Some("c2"), None)));
        assert!(!revokes(&chain, &token(None, None)));

        let access = record(None, Some("at1"));
        assert!(revokes(&access, &token(None, Some("at1"))));
        assert!(!revokes(&access, &token(None, Some("at2"))));
        assert!(!revokes(&access, &token(Some("c1"), None)));

        // An event naming neither applies to every token.
        assert!(revokes(
            &record(None, None),
            &token(Some("c1"), Some("at1"))
        ));
    }
}
