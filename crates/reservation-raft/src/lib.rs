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

//! # Mesh-wide name reservations
//!
//! The reservation group of ADR 0045 section 4: a dedicated Raft group with
//! one voter per authority whose state machine holds only reservations
//! `(kind, value) -> (authority, reference)`. A claim commits if the value is
//! free and otherwise fails with the holder.
//!
//! The store runs on any [`StorageApi`]; production wires it to the second
//! Raft group of the process (`init_reservation_storage`), never to the
//! authority core, so the group shares no log, DEK or keyspace with it.
//!
//! ## Lifecycle
//!
//! A claim commits as [`ReservationState::Pending`]. The home confirms it once
//! the registry record is published. [`ReservationStore::reconcile`] runs at
//! start and on a timer: it confirms the pending claims whose record exists
//! and releases the rest, so a crash between claim and publication does not
//! hold a name forever. Only the holder releases, on deletion of the domain
//! or role. A rename claims the new name and releases the old one in one
//! entry.
//!
//! ## Values
//!
//! Domain names, role names and authority base URLs are compared case
//! insensitively, an authority base URL also without a trailing slash. The
//! reservation keeps the value as it was claimed.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use openstack_keystone_distributed_storage::{
    ApiStoreError, Metadata, Mutation, StorageApi, StoreDataEnvelope, require_no_conflict,
};

/// Keyspace of the reservations.
pub const KEYSPACE: &str = "reservation";

/// Longest reserved value, in bytes.
pub const MAX_VALUE_LEN: usize = 255;

/// What is reserved.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationKind {
    /// A domain id.
    DomainId,
    /// A domain name.
    DomainName,
    /// A global role name.
    RoleName,
    /// The base URL of an authority; derives its issuers.
    AuthorityUrl,
}

impl ReservationKind {
    /// Prefix of the storage key.
    fn tag(self) -> &'static str {
        match self {
            Self::DomainId => "domain_id",
            Self::DomainName => "domain_name",
            Self::RoleName => "role_name",
            Self::AuthorityUrl => "authority_url",
        }
    }

    /// The value as it is compared.
    fn normalize(self, value: &str) -> Result<String, ReservationError> {
        if value.is_empty() || value.len() > MAX_VALUE_LEN || value.chars().any(char::is_control) {
            return Err(ReservationError::InvalidValue(value.to_string()));
        }
        Ok(match self {
            Self::DomainId => value.to_string(),
            Self::DomainName | Self::RoleName => value.to_lowercase(),
            Self::AuthorityUrl => value.trim_end_matches('/').to_lowercase(),
        })
    }
}

/// Where a reservation is in its lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// Claimed; the registry record is not published yet.
    Pending,
    /// The registry record is published.
    Confirmed,
}

/// What a holder asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    /// What is reserved.
    pub kind: ReservationKind,
    /// The value, as the holder spells it.
    pub value: String,
    /// The holding authority.
    pub authority: String,
    /// Names the domain, role or authority record the value belongs to.
    pub reference: String,
}

/// A stored reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reservation {
    /// What is reserved.
    pub kind: ReservationKind,
    /// The value, as it was claimed.
    pub value: String,
    /// The holding authority.
    pub authority: String,
    /// The record the value belongs to.
    pub reference: String,
    /// Lifecycle state.
    pub state: ReservationState,
    /// When the value was claimed, seconds since the epoch.
    #[serde(default)]
    pub claimed_at: i64,
}

/// Reservation failures.
#[derive(Debug, thiserror::Error)]
pub enum ReservationError {
    /// The value is held by another claim.
    #[error("{} {:?} is held by authority {}", .0.kind.tag(), .0.value, .0.authority)]
    Held(Box<Reservation>),

    /// A concurrent change won; read again and retry.
    #[error("concurrent change of a reservation")]
    Conflict,

    /// The reservation is held by another authority.
    #[error("reservation is held by authority {0}")]
    NotHolder(String),

    /// There is no such reservation.
    #[error("no such reservation")]
    NotFound,

    /// The value is empty, too long or has control characters.
    #[error("invalid value {0:?}")]
    InvalidValue(String),

    /// The record lookup of the reconciler failed.
    #[error("record lookup failed: {0}")]
    Lookup(String),

    /// The group could not be read or written.
    #[error(transparent)]
    Store(#[from] ApiStoreError),
}

/// Reservations of mesh-wide names.
#[async_trait]
pub trait ReservationBackend: Send + Sync {
    /// Claims a value. Claiming again with the same authority and reference
    /// returns the existing reservation, so a retry after a timeout is safe.
    async fn claim(&self, claim: &Claim) -> Result<Reservation, ReservationError>;

    /// The reservation of a value, if any.
    async fn get(
        &self,
        kind: ReservationKind,
        value: &str,
    ) -> Result<Option<Reservation>, ReservationError>;

    /// Marks a pending claim as confirmed. Only the holder confirms.
    async fn confirm(
        &self,
        kind: ReservationKind,
        value: &str,
        authority: &str,
    ) -> Result<Reservation, ReservationError>;

    /// Releases a reservation. Only the holder releases; releasing a value
    /// nobody holds is [`ReservationError::NotFound`].
    async fn release(
        &self,
        kind: ReservationKind,
        value: &str,
        authority: &str,
    ) -> Result<(), ReservationError>;

    /// Claims `to` and releases `from` in one entry; both are of the same
    /// kind and held by `authority`. The reservation keeps its state.
    async fn rename(
        &self,
        kind: ReservationKind,
        from: &str,
        to: &str,
        authority: &str,
    ) -> Result<Reservation, ReservationError>;

    /// All reservations of an authority.
    async fn list_by_authority(
        &self,
        authority: &str,
    ) -> Result<Vec<Reservation>, ReservationError>;
}

/// The registry side of the reconciler: whether the record a reservation
/// stands for was published.
#[async_trait]
pub trait RecordLookup: Send + Sync {
    /// Whether the record exists.
    async fn exists(&self, reservation: &Reservation) -> Result<bool, String>;
}

/// What a [`ReservationStore::reconcile`] pass did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    /// Pending claims confirmed.
    pub confirmed: usize,
    /// Pending claims released.
    pub released: usize,
    /// Pending claims younger than the grace period, left alone.
    pub waiting: usize,
}

/// [`ReservationBackend`] on a Raft group's storage.
#[derive(Clone)]
pub struct ReservationStore {
    storage: Arc<dyn StorageApi>,
}

impl ReservationStore {
    /// A store on the storage of the reservation group.
    pub fn new(storage: Arc<dyn StorageApi>) -> Self {
        Self { storage }
    }

    fn key(kind: ReservationKind, value: &str) -> Result<String, ReservationError> {
        Ok(format!("{}:{}", kind.tag(), kind.normalize(value)?))
    }

    /// The reservation with the revision it was read at.
    async fn read(
        &self,
        kind: ReservationKind,
        value: &str,
    ) -> Result<Option<StoreDataEnvelope<Reservation>>, ReservationError> {
        let key = Self::key(kind, value)?;
        match self
            .storage
            .get_by_key(key.as_bytes(), Some(KEYSPACE))
            .await?
        {
            Some(envelope) => Ok(Some(envelope.try_deserialize::<Reservation>()?)),
            None => Ok(None),
        }
    }

    /// The reservation, if `authority` holds it.
    async fn held_by(
        &self,
        kind: ReservationKind,
        value: &str,
        authority: &str,
    ) -> Result<StoreDataEnvelope<Reservation>, ReservationError> {
        let current = self
            .read(kind, value)
            .await?
            .ok_or(ReservationError::NotFound)?;
        if current.data.authority != authority {
            return Err(ReservationError::NotHolder(current.data.authority));
        }
        Ok(current)
    }

    /// Confirms the pending claims of `authority` whose record exists and
    /// releases the others, once they are older than `grace`.
    ///
    /// The grace period keeps a claim whose publication is still under way
    /// from being released. A claim whose lookup fails is left alone for the
    /// next pass.
    pub async fn reconcile(
        &self,
        authority: &str,
        grace: Duration,
        lookup: &dyn RecordLookup,
        now: i64,
    ) -> Result<ReconcileReport, ReservationError> {
        let mut report = ReconcileReport::default();
        let grace = i64::try_from(grace.as_secs()).unwrap_or(i64::MAX);
        for pending in self
            .list_by_authority(authority)
            .await?
            .into_iter()
            .filter(|r| r.state == ReservationState::Pending)
        {
            if now.saturating_sub(pending.claimed_at) < grace {
                report.waiting += 1;
                continue;
            }
            let exists = match lookup.exists(&pending).await {
                Ok(exists) => exists,
                Err(e) => {
                    tracing::warn!(
                        kind = pending.kind.tag(),
                        value = pending.value,
                        error = e,
                        "cannot tell whether the record of a pending reservation exists"
                    );
                    continue;
                }
            };
            let outcome = if exists {
                self.confirm(pending.kind, &pending.value, authority)
                    .await
                    .map(|_| report.confirmed += 1)
            } else {
                self.release(pending.kind, &pending.value, authority)
                    .await
                    .map(|_| report.released += 1)
            };
            match outcome {
                // Released or changed meanwhile: the next pass sees the new state.
                Ok(()) | Err(ReservationError::NotFound | ReservationError::Conflict) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }
}

/// A committed transaction, or the reason it was not.
async fn commit(
    storage: &dyn StorageApi,
    mutations: Vec<Mutation>,
) -> Result<(), ReservationError> {
    require_no_conflict(storage.transaction(mutations).await, || {
        ReservationError::Conflict
    })
    .map(|_| ())
}

fn now() -> i64 {
    Metadata::new().created_at
}

#[async_trait]
impl ReservationBackend for ReservationStore {
    async fn claim(&self, claim: &Claim) -> Result<Reservation, ReservationError> {
        if let Some(held) = self.read(claim.kind, &claim.value).await? {
            return if held.data.authority == claim.authority
                && held.data.reference == claim.reference
            {
                Ok(held.data)
            } else {
                Err(ReservationError::Held(Box::new(held.data)))
            };
        }
        let reservation = Reservation {
            kind: claim.kind,
            value: claim.value.clone(),
            authority: claim.authority.clone(),
            reference: claim.reference.clone(),
            state: ReservationState::Pending,
            claimed_at: now(),
        };
        let key = Self::key(claim.kind, &claim.value)?;
        let create =
            Mutation::create_if_absent(key, &reservation, Metadata::new(), Some(KEYSPACE))?;
        match commit(self.storage.as_ref(), vec![create]).await {
            Ok(()) => Ok(reservation),
            // Another claim committed first: report its holder.
            Err(ReservationError::Conflict) => match self.read(claim.kind, &claim.value).await? {
                Some(held)
                    if held.data.authority == claim.authority
                        && held.data.reference == claim.reference =>
                {
                    Ok(held.data)
                }
                Some(held) => Err(ReservationError::Held(Box::new(held.data))),
                None => Err(ReservationError::Conflict),
            },
            Err(e) => Err(e),
        }
    }

    async fn get(
        &self,
        kind: ReservationKind,
        value: &str,
    ) -> Result<Option<Reservation>, ReservationError> {
        Ok(self.read(kind, value).await?.map(|e| e.data))
    }

    async fn confirm(
        &self,
        kind: ReservationKind,
        value: &str,
        authority: &str,
    ) -> Result<Reservation, ReservationError> {
        let current = self.held_by(kind, value, authority).await?;
        if current.data.state == ReservationState::Confirmed {
            return Ok(current.data);
        }
        let confirmed = Reservation {
            state: ReservationState::Confirmed,
            ..current.data
        };
        let set = Mutation::set(
            Self::key(kind, value)?,
            &confirmed,
            current.metadata.new_revision(),
            Some(KEYSPACE),
            Some(current.metadata.revision),
        )?;
        commit(self.storage.as_ref(), vec![set]).await?;
        Ok(confirmed)
    }

    async fn release(
        &self,
        kind: ReservationKind,
        value: &str,
        authority: &str,
    ) -> Result<(), ReservationError> {
        let current = self.held_by(kind, value, authority).await?;
        let remove = Mutation::remove(
            Self::key(kind, value)?,
            Some(KEYSPACE),
            Some(current.metadata.revision),
        );
        commit(self.storage.as_ref(), vec![remove]).await
    }

    async fn rename(
        &self,
        kind: ReservationKind,
        from: &str,
        to: &str,
        authority: &str,
    ) -> Result<Reservation, ReservationError> {
        let current = self.held_by(kind, from, authority).await?;
        let (from_key, to_key) = (Self::key(kind, from)?, Self::key(kind, to)?);
        if from_key == to_key {
            // Only the spelling changes.
            let renamed = Reservation {
                value: to.to_string(),
                ..current.data
            };
            let set = Mutation::set(
                from_key,
                &renamed,
                current.metadata.new_revision(),
                Some(KEYSPACE),
                Some(current.metadata.revision),
            )?;
            commit(self.storage.as_ref(), vec![set]).await?;
            return Ok(renamed);
        }
        if let Some(held) = self.read(kind, to).await? {
            return Err(ReservationError::Held(Box::new(held.data)));
        }
        let renamed = Reservation {
            value: to.to_string(),
            ..current.data
        };
        // One entry: either the new name is claimed and the old released, or
        // neither. The create fails if a concurrent claim took the new name.
        let mutations = vec![
            Mutation::create_if_absent(to_key, &renamed, Metadata::new(), Some(KEYSPACE))?,
            Mutation::remove(from_key, Some(KEYSPACE), Some(current.metadata.revision)),
        ];
        match commit(self.storage.as_ref(), mutations).await {
            Ok(()) => Ok(renamed),
            Err(ReservationError::Conflict) => match self.read(kind, to).await? {
                Some(held) => Err(ReservationError::Held(Box::new(held.data))),
                None => Err(ReservationError::Conflict),
            },
            Err(e) => Err(e),
        }
    }

    async fn list_by_authority(
        &self,
        authority: &str,
    ) -> Result<Vec<Reservation>, ReservationError> {
        let mut found = Vec::new();
        for (_, envelope) in self.storage.prefix(b"", Some(KEYSPACE)).await? {
            let reservation = envelope.try_deserialize::<Reservation>()?.data;
            if reservation.authority == authority {
                found.push(reservation);
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests;
