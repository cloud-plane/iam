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

//! # Reverse index of principals at their home
//!
//! Grants are keyed by their target, so a question keyed by the actor ("where
//! can this user act", the groups of a mesh token) would scatter over every
//! authority. ADR 0045 section 8 answers it with a pointer event
//! `(issuer, principal) -> authority`: the authority that holds a grant for a
//! principal publishes a pointer to the principal's home, which keeps the
//! index and answers locally.
//!
//! * [`PointerPublisher`] runs at the authority that holds the grant. It
//!   records one pointer per grant in its own keyspace and emits it into the
//!   change feed (kind [`FEED_KIND`], owned by the domain of the principal, so
//!   the feed grants of the home decide who receives it).
//! * [`PointerSink`] runs at the home, once per source authority. It folds the
//!   pointers into the index. The authority comes from the subscription, never
//!   from the event, and a pointer is kept only for a domain the home serves,
//!   so a peer can point only at itself and only for principals of the home.
//! * [`PointerIndex`] answers the queries.
//!
//! A pointer is per grant, so removing one of two grants of a principal at an
//! authority keeps the pointer of the other. The index is a hint that can lag
//! or miss a pointer (the grant is written in its own backend, not in the same
//! transaction as the pointer), so a caller treats a miss as "ask the parts of
//! the domain" and [`PointerPublisher::reconcile`] repairs the source side from
//! the authoritative list of grants.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use openstack_keystone_distributed_storage::feed_consumer::{FeedEventData, FeedSink};
use openstack_keystone_distributed_storage::{
    ApiStoreError, DataTier, FeedOp, Metadata, Mutation, StorageApi,
};

/// Feed kind of the pointer events.
pub const FEED_KIND: &str = "principal_pointer";

/// Keyspace of the pointers an authority publishes.
const OUT_KEYSPACE: &str = "principal_pointer_out";

/// Keyspace of the index at the home.
const INDEX_KEYSPACE: &str = "principal_pointer_index";

/// Separates the parts of a key. Parts cannot contain it.
const SEP: char = '\u{1f}';

/// What a pointer is for.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A user.
    User,
    /// A group.
    Group,
}

impl PrincipalKind {
    fn tag(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }
}

/// Failures of the index.
#[derive(Debug, thiserror::Error)]
pub enum PointerError {
    /// A part of the pointer is empty or holds the separator.
    #[error("invalid {0}")]
    Invalid(&'static str),

    /// The storage failed.
    #[error(transparent)]
    Store(#[from] ApiStoreError),
}

/// A grant of an authority to a principal of another one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantPointer {
    /// Issuer of the principal, which names its home.
    pub issuer: String,
    /// The principal.
    pub principal: String,
    /// Whether the principal is a user or a group.
    pub kind: PrincipalKind,
    /// Domain of the principal; it owns the event in the feed.
    pub domain_id: String,
    /// Identifies the grant at this authority.
    pub grant_id: String,
}

fn part(value: &str, what: &'static str) -> Result<(), PointerError> {
    if value.is_empty() || value.contains(SEP) {
        return Err(PointerError::Invalid(what));
    }
    Ok(())
}

impl GrantPointer {
    fn validate(&self) -> Result<(), PointerError> {
        part(&self.issuer, "issuer")?;
        part(&self.principal, "principal")?;
        part(&self.domain_id, "domain id")?;
        part(&self.grant_id, "grant id")
    }

    /// The key at the source, which is also the key of the feed event:
    /// `issuer, kind, principal, grant`.
    fn key(&self) -> String {
        format!(
            "{}{SEP}{}{SEP}{}{SEP}{}",
            self.issuer,
            self.kind.tag(),
            self.principal,
            self.grant_id
        )
    }
}

/// The value of a pointer.
#[derive(Debug, Deserialize, Serialize)]
struct PointerValue {
    domain_id: String,
}

/// The publisher at the authority that holds the grants.
pub struct PointerPublisher {
    storage: Arc<dyn StorageApi>,
}

impl PointerPublisher {
    /// A publisher on the storage of this authority.
    pub fn new(storage: Arc<dyn StorageApi>) -> Self {
        Self { storage }
    }

    /// The mutations that publish `pointer`, or retract it.
    fn mutations(&self, pointer: &GrantPointer, op: FeedOp) -> Result<Vec<Mutation>, PointerError> {
        pointer.validate()?;
        let key = pointer.key();
        let value = PointerValue {
            domain_id: pointer.domain_id.clone(),
        };
        let mut mutations = vec![match op {
            FeedOp::Set => Mutation::set(
                key.clone(),
                &value,
                Metadata::new(),
                Some(OUT_KEYSPACE),
                None,
            )?,
            FeedOp::Remove => Mutation::remove(key.clone(), Some(OUT_KEYSPACE), None),
        }];
        if self.storage.feed_kind_enabled(FEED_KIND) {
            mutations.push(Mutation::Emit {
                kind: FEED_KIND.to_owned(),
                domain_id: Some(pointer.domain_id.clone()),
                key: key.into_bytes(),
                op,
                value: match op {
                    FeedOp::Set => Some(rmp_serde::to_vec(&value).map_err(ApiStoreError::from)?),
                    FeedOp::Remove => None,
                },
                tier: DataTier::Internal,
                priority: false,
            });
        }
        Ok(mutations)
    }

    async fn commit(&self, mutations: Vec<Mutation>) -> Result<(), PointerError> {
        let response = self.storage.transaction(mutations).await?;
        match response.violations.into_iter().next() {
            Some(v) => Err(PointerError::Store(ApiStoreError::Rejected {
                violation_type: v.r#type,
                subject: v.subject,
                description: v.description,
            })),
            None => Ok(()),
        }
    }

    /// A grant was created: publish its pointer. Idempotent.
    pub async fn grant_created(&self, pointer: &GrantPointer) -> Result<(), PointerError> {
        self.commit(self.mutations(pointer, FeedOp::Set)?).await
    }

    /// A grant was revoked: retract its pointer. Idempotent.
    pub async fn grant_revoked(&self, pointer: &GrantPointer) -> Result<(), PointerError> {
        self.commit(self.mutations(pointer, FeedOp::Remove)?).await
    }

    /// Makes the published pointers equal `current`, the authoritative list
    /// of the grants of principals of other authorities: publishes the missing
    /// ones and retracts the ones whose grant is gone. Returns
    /// `(published, retracted)`.
    pub async fn reconcile(
        &self,
        current: &[GrantPointer],
    ) -> Result<(usize, usize), PointerError> {
        let mut wanted = std::collections::BTreeMap::new();
        for pointer in current {
            pointer.validate()?;
            wanted.insert(pointer.key(), pointer);
        }
        let published: BTreeSet<String> = self
            .storage
            .prefix(b"", Some(OUT_KEYSPACE))
            .await?
            .into_iter()
            .map(|(key, _)| key)
            .collect();

        let mut mutations = Vec::new();
        let (mut added, mut removed) = (0, 0);
        for (key, pointer) in &wanted {
            if !published.contains(key) {
                mutations.extend(self.mutations(pointer, FeedOp::Set)?);
                added += 1;
            }
        }
        for key in published.iter().filter(|k| !wanted.contains_key(*k)) {
            let Some(pointer) = parse_source_key(key) else {
                continue;
            };
            let stored = self
                .storage
                .get_by_key(key.as_bytes(), Some(OUT_KEYSPACE))
                .await?;
            let Some(stored) = stored else { continue };
            let value: PointerValue = stored.try_deserialize()?.data;
            mutations.extend(self.mutations(
                &GrantPointer {
                    domain_id: value.domain_id,
                    ..pointer
                },
                FeedOp::Remove,
            )?);
            removed += 1;
        }
        if !mutations.is_empty() {
            self.commit(mutations).await?;
        }
        Ok((added, removed))
    }
}

/// `issuer, kind, principal, grant` of a source key; the domain is not part
/// of it.
fn parse_source_key(key: &str) -> Option<GrantPointer> {
    let mut parts = key.split(SEP);
    let (issuer, kind, principal, grant) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    Some(GrantPointer {
        issuer: issuer.to_owned(),
        principal: principal.to_owned(),
        kind: match kind {
            "user" => PrincipalKind::User,
            "group" => PrincipalKind::Group,
            _ => return None,
        },
        domain_id: String::new(),
        grant_id: grant.to_owned(),
    })
}

/// Which domains the home serves.
pub trait HomeDomains: Send + Sync {
    /// Whether this authority is the home of `domain_id`.
    fn is_home(&self, domain_id: &str) -> bool;
}

impl<F: Fn(&str) -> bool + Send + Sync> HomeDomains for F {
    fn is_home(&self, domain_id: &str) -> bool {
        self(domain_id)
    }
}

/// Key of a pointer in the index: the principal first, so that its pointers
/// are one prefix.
fn index_prefix(issuer: &str, kind: PrincipalKind, principal: &str) -> String {
    format!("{issuer}{SEP}{}{SEP}{principal}{SEP}", kind.tag())
}

/// Folds the pointers of one source authority into the index.
pub struct PointerSink {
    authority: String,
    home: Arc<dyn HomeDomains>,
    storage: Arc<dyn StorageApi>,
}

impl PointerSink {
    /// A sink for the pointers of `authority`.
    pub fn new(
        authority: impl Into<String>,
        home: Arc<dyn HomeDomains>,
        storage: Arc<dyn StorageApi>,
    ) -> Self {
        Self {
            authority: authority.into(),
            home,
            storage,
        }
    }

    /// `<principal prefix><authority><SEP><grant>` of an event key.
    ///
    /// The issuer of a domain is `<base url>/v4/oauth2/<domain id>`
    /// (ADR 0026), so one that does not end in the owning domain is not the
    /// issuer of its principals and is refused.
    fn index_key(&self, event_key: &[u8], domain: &str) -> Option<String> {
        let pointer = parse_source_key(std::str::from_utf8(event_key).ok()?)?;
        if !pointer.issuer.ends_with(&format!("/{domain}")) {
            return None;
        }
        Some(format!(
            "{}{}{SEP}{}",
            index_prefix(&pointer.issuer, pointer.kind, &pointer.principal),
            self.authority,
            pointer.grant_id
        ))
    }
}

#[async_trait]
impl FeedSink for PointerSink {
    fn mutations(&self, event: &FeedEventData) -> Result<Vec<Mutation>, ApiStoreError> {
        if event.kind != FEED_KIND {
            return Ok(Vec::new());
        }
        // Only the principals of the domains this authority is home of.
        let Some(domain) = event.domain_id.as_deref().filter(|d| self.home.is_home(d)) else {
            tracing::warn!(
                authority = self.authority,
                "ignoring a principal pointer for a domain this authority does not serve"
            );
            return Ok(Vec::new());
        };
        let Some(key) = self.index_key(&event.key, domain) else {
            tracing::warn!(
                authority = self.authority,
                "ignoring a malformed principal pointer"
            );
            return Ok(Vec::new());
        };
        if event.removed {
            return Ok(vec![Mutation::remove(key, Some(INDEX_KEYSPACE), None)]);
        }
        Ok(vec![Mutation::set(
            key,
            &PointerValue {
                domain_id: domain.to_owned(),
            },
            Metadata::new(),
            Some(INDEX_KEYSPACE),
            None,
        )?])
    }

    /// The cursor is gone: drop what this authority sent, the new
    /// subscription replays what the source still holds.
    async fn reseed(&self) -> Result<(), ApiStoreError> {
        let mut removals = Vec::new();
        for (key, _) in self.storage.prefix(b"", Some(INDEX_KEYSPACE)).await? {
            if key.split(SEP).nth(3) == Some(self.authority.as_str()) {
                removals.push(Mutation::remove(key, Some(INDEX_KEYSPACE), None));
            }
        }
        if !removals.is_empty() {
            self.storage.transaction(removals).await?;
        }
        Ok(())
    }
}

/// Questions the home answers about its principals.
pub struct PointerIndex {
    storage: Arc<dyn StorageApi>,
}

impl PointerIndex {
    /// An index on the storage of the home.
    pub fn new(storage: Arc<dyn StorageApi>) -> Self {
        Self { storage }
    }

    /// The authorities that hold a grant for the principal: where it can
    /// act. A principal nobody points at gets an empty set, which a caller
    /// takes as "unknown", not "nowhere".
    pub async fn authorities_for(
        &self,
        issuer: &str,
        kind: PrincipalKind,
        principal: &str,
    ) -> Result<BTreeSet<String>, PointerError> {
        let prefix = index_prefix(issuer, kind, principal);
        Ok(self
            .storage
            .prefix(prefix.as_bytes(), Some(INDEX_KEYSPACE))
            .await?
            .into_iter()
            .filter_map(|(key, _)| {
                key.strip_prefix(&prefix)
                    .and_then(|rest| rest.split(SEP).next())
                    .map(str::to_owned)
            })
            .collect())
    }

    /// The groups, out of `groups`, that hold a grant at `authority`: the
    /// groups a mesh token for that audience carries, and no others.
    pub async fn groups_for_audience(
        &self,
        issuer: &str,
        groups: &[String],
        authority: &str,
    ) -> Result<Vec<String>, PointerError> {
        let mut found = Vec::new();
        for group in groups {
            if self
                .authorities_for(issuer, PrincipalKind::Group, group)
                .await?
                .contains(authority)
            {
                found.push(group.clone());
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests;
