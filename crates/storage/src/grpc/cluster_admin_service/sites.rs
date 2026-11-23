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

//! Per-site KEK administration (ADR 0045 §11.2).

use std::collections::HashSet;
use std::sync::Mutex;

use openstack_keystone_storage_crypto::{SiteEntry, SiteKek, site_fingerprint, site_list_digest};

use super::*;
use crate::store_command::SiteRecord;

/// How long a staged site change waits for its second operator, the same
/// window as an emergency DEK rotation.
pub(crate) const PENDING_SITE_CHANGE_TTL_SECS: u64 = 300;

/// A site list that adds or replaces a site key, staged until a second
/// operator confirms it.
#[derive(Debug, Clone)]
pub(super) struct PendingSiteChange {
    id: String,
    sites: Vec<SiteRecord>,
    allow_site_removal: bool,
    initiator: String,
    expires_at: u64,
    /// `site_list_digest` of `sites`, fixed at staging.
    digest: String,
}

/// The one staged site change. Held in the leader's memory only: a leader
/// change drops it and the operator stages it again, which fails closed.
#[derive(Debug, Default)]
pub(super) struct PendingSiteChanges(Mutex<Option<PendingSiteChange>>);

impl PendingSiteChanges {
    /// Stage `change`. Refused while another change is still waiting.
    fn stage(&self, change: PendingSiteChange, now: u64) -> Result<(), Status> {
        let mut slot = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if slot.as_ref().is_some_and(|c| c.expires_at > now) {
            return Err(Status::failed_precondition(
                "another site change is already pending; confirm it or wait for it to expire",
            ));
        }
        *slot = Some(change);
        Ok(())
    }

    /// The staged change, if it has not expired.
    fn peek(&self, now: u64) -> Option<PendingSiteChange> {
        let slot = self.0.lock().unwrap_or_else(|p| p.into_inner());
        slot.clone().filter(|c| c.expires_at > now)
    }

    /// Take the change `id` for `confirmer`. The confirmer must differ from
    /// the initiator and must present the staged list's `digest`; a refused
    /// confirmation leaves the change in place.
    fn take(
        &self,
        id: &str,
        digest: &str,
        confirmer: &str,
        now: u64,
    ) -> Result<PendingSiteChange, Status> {
        let mut slot = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match slot.as_ref() {
            Some(c) if c.id == id => {
                if c.expires_at <= now {
                    *slot = None;
                    return Err(Status::deadline_exceeded(format!(
                        "pending site change {id} has expired"
                    )));
                }
                if c.initiator == confirmer {
                    return Err(Status::permission_denied(
                        "the confirming operator must be different from the initiator \
                         (dual-control requirement)",
                    ));
                }
                if c.digest != digest {
                    return Err(Status::failed_precondition(
                        "the digest does not match the staged site list; compare it with \
                         `GetPendingSiteChange` and confirm again",
                    ));
                }
                slot.take()
                    .ok_or_else(|| Status::internal("pending site change vanished"))
            }
            _ => Err(Status::not_found(format!(
                "no pending site change with id {id}"
            ))),
        }
    }
}

/// Whether `new` gives a site a key the registry does not hold yet: a new
/// site, or a site whose public key or key version differs. Removing sites
/// grants nobody access and needs no second operator.
fn grants_access(current: &[SiteEntry], new: &[SiteRecord]) -> bool {
    new.iter().any(|n| {
        !current.iter().any(|c| {
            c.name == n.name
                && c.public_key_der == n.public_key_der
                && c.key_version == n.key_version
        })
    })
}

/// Per-site name, key version and key fingerprint, for audit details.
fn site_details(records: &[SiteRecord]) -> serde_json::Value {
    records
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "key_version": s.key_version,
                "fingerprint": site_fingerprint(&s.public_key_der),
            })
        })
        .collect()
}

fn entries(records: &[SiteRecord]) -> Vec<SiteEntry> {
    records.iter().map(SiteEntry::from).collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl ClusterAdminServiceImpl {
    /// Dry run on the leader: the keys must be usable, this site must stay in
    /// the list and open what it wraps, the current DEK must be re-wrappable,
    /// and no site the current DEK is wrapped for may be dropped without
    /// `allow_site_removal`. Otherwise the apply would leave the other sites
    /// with envelopes that exclude them. Returns the current DEK version.
    async fn check_site_list(
        &self,
        kek: &SiteKek,
        records: &[SiteRecord],
        allow_site_removal: bool,
    ) -> Result<u32, Status> {
        let entries = entries(records);
        let (version, wrapped) = self
            .sm
            .current_dek_wrapped()
            .map_err(|e| Status::internal(format!("reading the current DEK: {e}")))?;
        kek.rewrap_for(&entries, &wrapped).await.map_err(|e| {
            // An unreachable key store says nothing about the list.
            if e.is_transient() {
                Status::unavailable(format!("the key store is unavailable, retry: {e}"))
            } else {
                Status::invalid_argument(format!("the site list is not usable: {e}"))
            }
        })?;

        // Every other site that holds a voting node applies this list too;
        // once its site is gone it can neither open nor wrap a DEK. Which
        // sites run nodes is not known here, so a site the current envelope
        // names is treated as live until the operator says otherwise.
        let names: HashSet<&str> = records.iter().map(|s| s.name.as_str()).collect();
        let dropped: Vec<String> = openstack_keystone_storage_crypto::envelope_sites(&wrapped)
            .map_err(|e| Status::internal(format!("reading the current DEK envelope: {e}")))?
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| !names.contains(name.as_str()) && kek.escrow_name() != Some(name))
            .collect();
        if !dropped.is_empty() && !allow_site_removal {
            return Err(Status::failed_precondition(format!(
                "the list drops site(s) {dropped:?} that the current DEK is wrapped for; nodes of \
                 a dropped site can no longer open or wrap a DEK. Set allow_site_removal once no \
                 node of those sites remains"
            )));
        }
        Ok(version)
    }

    /// Propose `records` through Raft and audit the outcome.
    async fn commit_sites(
        &self,
        actor: &str,
        dek_version: u32,
        records: Vec<SiteRecord>,
        extra: serde_json::Value,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let mut details = serde_json::json!({ "sites": site_details(&records) });
        if let (Some(d), Some(e)) = (details.as_object_mut(), extra.as_object()) {
            d.extend(e.clone());
        }
        let cmd = StoreCommand::Transaction(vec![MutationInner::SetSites { sites: records }]);
        let payload =
            pb::api::CommandRequest::try_from(cmd).map_err(|e| Status::internal(e.to_string()))?;
        let write = self
            .raft_node
            .client_write(payload)
            .await
            .map_err(|e| raft_write_status("Raft write failed", e));
        self.audit_outcome("SITES_SET", actor, dek_version, details, &write);
        write?;
        Ok(Response::new(pb::raft::AdminResponse::default()))
    }

    pub(super) async fn handle_set_sites(
        &self,
        request: Request<pb::raft::SetSitesRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
        self.ensure_leader()?;
        let req = request.into_inner();

        let kek = self.kek.as_site_kek().ok_or_else(|| {
            Status::failed_precondition("SetSites needs kek_provider = \"per_site\"")
        })?;
        if req.sites.is_empty() {
            return Err(Status::invalid_argument("the site list must not be empty"));
        }
        let mut names = HashSet::new();
        for s in &req.sites {
            if s.name.is_empty() || s.name.len() > 255 || s.key_version == 0 {
                return Err(Status::invalid_argument(format!(
                    "site '{}': the name must be 1 to 255 bytes and the key version at least 1",
                    s.name
                )));
            }
            if !names.insert(s.name.as_str()) {
                return Err(Status::invalid_argument(format!(
                    "site '{}' is listed twice",
                    s.name
                )));
            }
        }
        self.set_sites_limiter.check_key(&actor).map_err(|_| {
            Status::resource_exhausted("SetSites rate limit exceeded; try again later")
        })?;
        let records: Vec<SiteRecord> = req
            .sites
            .iter()
            .map(|s| SiteRecord {
                name: s.name.clone(),
                public_key_der: s.public_key_der.clone(),
                key_version: s.key_version,
            })
            .collect();

        let version = self
            .check_site_list(kek, &records, req.allow_site_removal)
            .await?;

        if !grants_access(&kek.registry().list(), &records) {
            return self
                .commit_sites(&actor, version, records, serde_json::json!({}))
                .await;
        }

        // The list gives a site a key it did not have: whoever holds that
        // private key can open the DEK. A second operator must confirm.
        let now = now_secs();
        let digest = site_list_digest(&entries(&records), req.allow_site_removal);
        let change = PendingSiteChange {
            id: uuid::Uuid::new_v4().to_string(),
            sites: records,
            allow_site_removal: req.allow_site_removal,
            initiator: actor.clone(),
            expires_at: now + PENDING_SITE_CHANGE_TTL_SECS,
            digest: digest.clone(),
        };
        let (id, expires_at) = (change.id.clone(), change.expires_at);
        let details = serde_json::json!({
            "change_id": id,
            "sites": site_details(&change.sites),
            "allow_site_removal": change.allow_site_removal,
            "digest": digest,
            "expires_at": expires_at,
        });
        self.pending_site_changes.stage(change, now)?;
        self.audit_outcome(
            "SITES_CHANGE_STAGED",
            &actor,
            version,
            details,
            &Ok::<(), Status>(()),
        );
        tracing::warn!(
            change_id = id,
            initiator = actor,
            "SECURITY: site list change adds or replaces a site key; awaiting dual-control \
             confirmation"
        );
        Ok(Response::new(pb::raft::AdminResponse {
            pending_site_change_id: id,
            pending_site_change_expires_at: expires_at,
            pending_site_change_digest: digest,
            ..Default::default()
        }))
    }

    pub(super) async fn handle_confirm_set_sites(
        &self,
        request: Request<pb::raft::ConfirmSetSitesRequest>,
    ) -> Result<Response<pb::raft::AdminResponse>, Status> {
        let actor = require_operator(&request, &self.authz)?;
        // The staged change lives in the leader's memory.
        self.ensure_leader()?;
        let req = request.into_inner();
        if req.change_id.is_empty() {
            return Err(Status::invalid_argument("change_id must not be empty"));
        }
        let kek = self.kek.as_site_kek().ok_or_else(|| {
            Status::failed_precondition("ConfirmSetSites needs kek_provider = \"per_site\"")
        })?;
        let change =
            self.pending_site_changes
                .take(&req.change_id, &req.digest, &actor, now_secs())?;
        // The cluster may have changed since the change was staged.
        let version = self
            .check_site_list(kek, &change.sites, change.allow_site_removal)
            .await?;
        tracing::warn!(
            change_id = change.id,
            initiator = change.initiator,
            confirmer = actor,
            "SECURITY: site list change confirmed via dual-control"
        );
        let extra = serde_json::json!({
            "change_id": change.id,
            "digest": change.digest,
            "initiator": change.initiator,
            "confirmer": actor,
        });
        self.commit_sites(&actor, version, change.sites, extra)
            .await
    }

    pub(super) async fn handle_get_pending_site_change(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::PendingSiteChange>, Status> {
        require_operator(&request, &self.authz)?;
        self.ensure_leader()?;
        let kek = self.kek.as_site_kek().ok_or_else(|| {
            Status::failed_precondition("GetPendingSiteChange needs kek_provider = \"per_site\"")
        })?;
        let change = self
            .pending_site_changes
            .peek(now_secs())
            .ok_or_else(|| Status::not_found("no site change is pending"))?;
        let current = kek.registry().list();
        let changed = change
            .sites
            .iter()
            .filter(|n| grants_access(&current, std::slice::from_ref(*n)))
            .map(|s| s.name.clone())
            .collect();
        let removed = current
            .iter()
            .filter(|c| !change.sites.iter().any(|n| n.name == c.name))
            .map(|c| c.name.clone())
            .collect();
        let sites = change
            .sites
            .iter()
            .map(|s| pb::raft::SiteSummary {
                name: s.name.clone(),
                key_version: s.key_version,
                fingerprint: site_fingerprint(&s.public_key_der),
            })
            .collect();
        Ok(Response::new(pb::raft::PendingSiteChange {
            change_id: change.id,
            initiator: change.initiator,
            expires_at: change.expires_at,
            sites,
            changed,
            removed,
            allow_site_removal: change.allow_site_removal,
            digest: change.digest,
        }))
    }

    pub(super) async fn handle_list_sites(
        &self,
        request: Request<()>,
    ) -> Result<Response<pb::raft::ListSitesResponse>, Status> {
        require_operator(&request, &self.authz)?;
        let kek = self.kek.as_site_kek().ok_or_else(|| {
            Status::failed_precondition("ListSites needs kek_provider = \"per_site\"")
        })?;
        let sites = kek
            .registry()
            .list()
            .into_iter()
            .map(|s| pb::raft::Site {
                name: s.name,
                public_key_der: s.public_key_der,
                key_version: s.key_version,
            })
            .collect();
        Ok(Response::new(pb::raft::ListSitesResponse { sites }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, key: u8, version: u32) -> SiteRecord {
        SiteRecord {
            name: name.into(),
            public_key_der: vec![key],
            key_version: version,
        }
    }

    fn entry(name: &str, key: u8, version: u32) -> SiteEntry {
        SiteEntry::from(&record(name, key, version))
    }

    fn change(id: &str, initiator: &str, expires_at: u64) -> PendingSiteChange {
        PendingSiteChange {
            id: id.into(),
            sites: vec![record("a", 1, 1)],
            allow_site_removal: false,
            initiator: initiator.into(),
            expires_at,
            digest: "d".into(),
        }
    }

    #[test]
    fn confirmation_needs_the_staged_digest() {
        let p = PendingSiteChanges::default();
        p.stage(change("x", "op-a", 10), 1).unwrap();
        assert_eq!(
            p.take("x", "other", "op-b", 1).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            p.take("x", "", "op-b", 1).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        // A wrong digest leaves the change in place.
        assert!(p.peek(1).is_some());
        assert!(p.take("x", "d", "op-b", 1).is_ok());
    }

    #[test]
    fn adding_or_replacing_a_key_needs_confirmation() {
        let current = [entry("a", 1, 1), entry("b", 2, 1)];
        // Unchanged, or only removing a site: no new access.
        assert!(!grants_access(
            &current,
            &[record("a", 1, 1), record("b", 2, 1)]
        ));
        assert!(!grants_access(&current, &[record("a", 1, 1)]));
        // A new site.
        assert!(grants_access(
            &current,
            &[record("a", 1, 1), record("c", 3, 1)]
        ));
        // Another public key under a known name, or a bumped key version.
        assert!(grants_access(&current, &[record("a", 9, 1)]));
        assert!(grants_access(&current, &[record("a", 1, 2)]));
    }

    #[test]
    fn the_initiator_cannot_confirm() {
        let p = PendingSiteChanges::default();
        p.stage(change("x", "op-a", 1000), 0).unwrap();
        let err = p.take("x", "d", "op-a", 1).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        // The refusal leaves the change for the other operator.
        assert_eq!(p.take("x", "d", "op-b", 1).unwrap().initiator, "op-a");
        // Taken once.
        assert_eq!(
            p.take("x", "d", "op-b", 1).unwrap_err().code(),
            tonic::Code::NotFound
        );
    }

    #[test]
    fn an_expired_or_unknown_change_cannot_be_confirmed() {
        let p = PendingSiteChanges::default();
        assert_eq!(
            p.take("x", "d", "op-b", 1).unwrap_err().code(),
            tonic::Code::NotFound
        );
        p.stage(change("x", "op-a", 10), 0).unwrap();
        assert_eq!(
            p.take("y", "d", "op-b", 1).unwrap_err().code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            p.take("x", "d", "op-b", 10).unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        assert_eq!(
            p.take("x", "d", "op-b", 11).unwrap_err().code(),
            tonic::Code::NotFound
        );
    }

    #[test]
    fn only_one_change_is_pending_until_it_expires() {
        let p = PendingSiteChanges::default();
        p.stage(change("x", "op-a", 10), 0).unwrap();
        assert_eq!(
            p.stage(change("y", "op-a", 20), 5).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        p.stage(change("y", "op-a", 30), 10).unwrap();
        assert_eq!(p.take("y", "d", "op-b", 11).unwrap().id, "y");
    }
}
