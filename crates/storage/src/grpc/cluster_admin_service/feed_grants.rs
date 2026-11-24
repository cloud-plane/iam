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

//! Feed subscriber grants (ADR 0045 section 3, M4).
//!
//! Which kinds and domains a subscriber may receive is tenant data, so it is
//! replicated state set at runtime, not node configuration. The identity and
//! its `feed-consumer` role still come from `peers`.

use super::*;

use crate::config::FEED_GRANT_MAX_FIELD as MAX_FIELD;

fn field(name: &str, value: &str) -> Result<(), Status> {
    if value.is_empty() || value.len() > MAX_FIELD || value.contains('\0') {
        return Err(Status::invalid_argument(format!(
            "{name} must be 1 to {MAX_FIELD} bytes with no NUL"
        )));
    }
    Ok(())
}

/// Checks a grant and returns `(svid, kind, domain)`.
fn checked(grant: Option<pb::raft::FeedGrant>) -> Result<(String, String, Option<String>), Status> {
    let g = grant.ok_or_else(|| Status::invalid_argument("grant is required"))?;
    if !g.svid.starts_with("spiffe://") {
        return Err(Status::invalid_argument("svid must be a SPIFFE ID"));
    }
    field("svid", &g.svid)?;
    field("kind", &g.kind)?;
    let domain = g.has_domain.then_some(g.domain_id);
    if let Some(d) = &domain {
        field("domain_id", d)?;
    }
    Ok((g.svid, g.kind, domain))
}

impl ClusterAdminServiceImpl {
    async fn commit_feed_grant(
        &self,
        request: Request<pb::raft::FeedGrantRequest>,
        revoke: bool,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
        self.ensure_leader()?;
        let (svid, kind, domain) = checked(request.into_inner().grant)?;
        let details = serde_json::json!({ "svid": svid, "kind": kind, "domain": domain });
        let m = if revoke {
            MutationInner::RevokeFeedGrant { svid, kind, domain }
        } else {
            MutationInner::SetFeedGrant { svid, kind, domain }
        };
        let payload = pb::api::CommandRequest::try_from(StoreCommand::Transaction(vec![m]))
            .map_err(|e| Status::internal(e.to_string()))?;
        let write = self
            .raft_node
            .client_write(payload)
            .await
            .map_err(|e| raft_write_status("Raft write failed", e));
        let dek_version = self
            .current_dek
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .version;
        let event = if revoke {
            "FEED_GRANT_REVOKED"
        } else {
            "FEED_GRANT_SET"
        };
        self.audit_outcome(event, &actor, dek_version, details, &write);
        write?;
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }

    pub(super) async fn handle_set_feed_grant(
        &self,
        request: Request<pb::raft::FeedGrantRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        self.commit_feed_grant(request, false).await
    }

    pub(super) async fn handle_revoke_feed_grant(
        &self,
        request: Request<pb::raft::FeedGrantRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        self.commit_feed_grant(request, true).await
    }

    pub(super) async fn handle_list_feed_grants(
        &self,
        request: Request<pb::raft::ListFeedGrantsRequest>,
    ) -> Result<Response<pb::raft::ListFeedGrantsResponse>, Status> {
        require_operator(&request, &self.authz)?;
        self.ensure_leader()?;
        // The leader check reads cached metrics, so a deposed leader still
        // passes it. A ReadIndex read confirms the leadership and that the
        // applied state includes every grant already committed.
        self.raft_node
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(|e| Status::unavailable(format!("not linearizable leader: {e}")))?;
        let svid = request.into_inner().svid;
        let grants = self
            .sm
            .list_feed_grants((!svid.is_empty()).then_some(svid.as_str()))
            .map_err(|e| Status::internal(e.to_string()))?
            .into_iter()
            .map(|(svid, kind, domain)| pb::raft::FeedGrant {
                svid,
                kind,
                has_domain: domain.is_some(),
                domain_id: domain.unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(pb::raft::ListFeedGrantsResponse { grants }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(svid: &str, kind: &str, domain: Option<&str>) -> Option<pb::raft::FeedGrant> {
        Some(pb::raft::FeedGrant {
            svid: svid.into(),
            kind: kind.into(),
            has_domain: domain.is_some(),
            domain_id: domain.unwrap_or_default().into(),
        })
    }

    #[test]
    fn checked_accepts_a_grant() {
        assert_eq!(
            ("spiffe://a/b".into(), "registry".into(), Some("d1".into())),
            checked(grant("spiffe://a/b", "registry", Some("d1"))).unwrap()
        );
        assert_eq!(
            None,
            checked(grant("spiffe://a/b", "registry", None)).unwrap().2
        );
    }

    #[test]
    fn checked_refuses_bad_fields() {
        assert!(checked(None).is_err());
        assert!(checked(grant("not-a-svid", "registry", None)).is_err());
        assert!(checked(grant("spiffe://a/b", "", None)).is_err());
        assert!(checked(grant("spiffe://a/b", "re\0g", None)).is_err());
        assert!(checked(grant("spiffe://a/b", "registry", Some(""))).is_err());
    }
}
