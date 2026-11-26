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

//! Node-local keyspace revisions.
//!
//! A driver that keeps a projection of a small keyspace in memory (the
//! revocation events) needs to know whether the keyspace changed since it
//! loaded the projection, without reading it. Every apply that writes or
//! drops a keyspace gives it a new revision from a counter that only grows on
//! this node; a snapshot or restore install moves every keyspace past it.
//! Revisions are only comparable on the node that reported them, and are not
//! replicated.

use std::sync::atomic::Ordering;

use super::*;

/// Revision source of a state machine.
#[derive(Debug)]
pub(super) struct KeyspaceRevisions {
    /// Random per process: the counters restart from zero with the process,
    /// so a revision is only meaningful together with this value.
    instance: u64,
    /// Source of new revisions.
    clock: std::sync::atomic::AtomicU64,
    /// Revision the last snapshot or restore install set for every keyspace.
    installed: std::sync::atomic::AtomicU64,
    /// Revision of the last write to each keyspace.
    written: RwLock<HashMap<String, u64>>,
}

impl Default for KeyspaceRevisions {
    fn default() -> Self {
        Self {
            instance: rand::random(),
            clock: Default::default(),
            installed: Default::default(),
            written: Default::default(),
        }
    }
}

impl KeyspaceRevisions {
    /// Gives `keyspaces` a new revision.
    pub(super) fn touch<'a>(&self, keyspaces: impl IntoIterator<Item = &'a str>) {
        let mut keyspaces = keyspaces.into_iter().peekable();
        if keyspaces.peek().is_none() {
            return;
        }
        let revision = self.clock.fetch_add(1, Ordering::SeqCst) + 1;
        let mut written = self.written.write().unwrap_or_else(|p| p.into_inner());
        for keyspace in keyspaces {
            written.insert(keyspace.to_owned(), revision);
        }
    }

    /// Moves every keyspace past all revisions handed out so far.
    pub(super) fn install(&self) {
        let revision = self.clock.fetch_add(1, Ordering::SeqCst) + 1;
        self.installed.store(revision, Ordering::SeqCst);
    }

    /// The current revision of `keyspace`.
    pub(super) fn get(&self, keyspace: &str) -> u64 {
        let written = self.written.read().unwrap_or_else(|p| p.into_inner());
        written
            .get(keyspace)
            .copied()
            .unwrap_or(0)
            .max(self.installed.load(Ordering::SeqCst))
    }
}

impl FjallStateMachine {
    /// Identifies this state machine instance; revisions of two instances are
    /// not comparable.
    pub fn revision_instance(&self) -> u64 {
        self.revisions.instance
    }

    /// The revision of `keyspace` on this node. Equal values mean the
    /// keyspace did not change in between.
    pub fn keyspace_revision(&self, keyspace: &str) -> u64 {
        self.revisions.get(keyspace)
    }
}

/// The keyspaces a transaction writes or drops.
pub(super) fn written_keyspaces(muts: &[MutationInner]) -> Vec<&str> {
    muts.iter()
        .filter_map(|m| match m {
            MutationInner::Set { keyspace, .. }
            | MutationInner::Remove { keyspace, .. }
            | MutationInner::CreateIfAbsent { keyspace, .. }
            | MutationInner::DropKeyspace { keyspace } => Some(keyspace.as_str()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_moves_only_its_keyspace() {
        let r = KeyspaceRevisions::default();
        let (a0, b0) = (r.get("a"), r.get("b"));
        r.touch(["a"]);
        assert!(r.get("a") > a0);
        assert_eq!(b0, r.get("b"));
    }

    #[test]
    fn an_install_moves_every_keyspace() {
        let r = KeyspaceRevisions::default();
        r.touch(["a"]);
        let (a, b) = (r.get("a"), r.get("b"));
        r.install();
        assert!(r.get("a") > a);
        assert!(r.get("b") > b);
        // A later write still moves past the install.
        let after = r.get("a");
        r.touch(["a"]);
        assert!(r.get("a") > after);
    }

    #[test]
    fn nothing_written_keeps_the_revision() {
        let r = KeyspaceRevisions::default();
        r.touch(["a"]);
        let a = r.get("a");
        r.touch([]);
        assert_eq!(a, r.get("a"));
    }
}
