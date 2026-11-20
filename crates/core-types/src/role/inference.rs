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
//! # Resolved role inference
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::{RoleImply, RoleRef};

/// The role inference graph resolved into the transitive closure of every
/// role that implies another one.
///
/// Resolving walks the whole rule graph, so it is done once per version of
/// the rules and shared (see the role driver caches), not per request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoleInference {
    /// Roles implied by a role, directly or not, sorted by the ID. A role
    /// that implies itself through a cycle is part of its own closure.
    implied: HashMap<String, Vec<RoleRef>>,
}

impl RoleInference {
    /// Resolve the closures of the roles from the imply `rules`.
    ///
    /// The names of the roles are taken from the rules, so that the
    /// consumer needs no further lookup for the implied roles.
    pub fn from_rules(rules: &[RoleImply]) -> Self {
        let mut direct: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut refs: HashMap<&str, &RoleRef> = HashMap::new();
        for rule in rules {
            direct
                .entry(rule.prior_role.id.as_str())
                .or_default()
                .insert(rule.implied_role.id.as_str());
            for role in [&rule.prior_role, &rule.implied_role] {
                // A rule that knows the name wins over one that does not.
                let known = refs.entry(role.id.as_str()).or_insert(role);
                if known.name.is_none() && role.name.is_some() {
                    *known = role;
                }
            }
        }
        let mut implied = HashMap::with_capacity(direct.len());
        for start in direct.keys() {
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            let mut stack: Vec<&str> = direct[start].iter().copied().collect();
            while let Some(role_id) = stack.pop() {
                if seen.insert(role_id)
                    && let Some(next) = direct.get(role_id)
                {
                    stack.extend(next.iter().copied());
                }
            }
            implied.insert(
                (*start).to_string(),
                seen.into_iter()
                    .filter_map(|id| refs.get(id).map(|role| (*role).clone()))
                    .collect(),
            );
        }
        Self { implied }
    }

    /// The roles `role_id` implies, directly or not.
    pub fn implied(&self, role_id: &str) -> &[RoleRef] {
        self.implied.get(role_id).map_or(&[], Vec::as_slice)
    }

    /// Whether no role implies another one.
    pub fn is_empty(&self) -> bool {
        self.implied.is_empty()
    }

    /// Approximate bytes the closures hold on the heap.
    pub fn heap_size(&self) -> usize {
        self.implied
            .iter()
            .map(|(id, roles)| {
                id.capacity()
                    + std::mem::size_of::<(String, Vec<RoleRef>)>()
                    + roles.capacity() * std::mem::size_of::<RoleRef>()
                    + roles
                        .iter()
                        .map(|role| {
                            role.id.capacity()
                                + role.name.as_ref().map_or(0, String::capacity)
                                + role.domain_id.as_ref().map_or(0, String::capacity)
                        })
                        .sum::<usize>()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(id: &str) -> RoleRef {
        RoleRef {
            id: id.into(),
            name: Some(format!("name-{id}")),
            domain_id: None,
        }
    }

    fn rule(prior: &str, implied: &str) -> RoleImply {
        RoleImply {
            prior_role: role(prior),
            implied_role: role(implied),
        }
    }

    fn ids(inference: &RoleInference, id: &str) -> Vec<String> {
        inference.implied(id).iter().map(|r| r.id.clone()).collect()
    }

    #[test]
    fn closure_is_transitive_and_named() {
        let inference =
            RoleInference::from_rules(&[rule("a", "b"), rule("b", "c"), rule("b", "d")]);
        assert_eq!(ids(&inference, "a"), ["b", "c", "d"]);
        assert_eq!(ids(&inference, "b"), ["c", "d"]);
        assert!(inference.implied("c").is_empty());
        assert_eq!(inference.implied("a")[0].name.as_deref(), Some("name-b"));
    }

    #[test]
    fn cycle_includes_the_role_itself() {
        let inference = RoleInference::from_rules(&[rule("a", "b"), rule("b", "a")]);
        assert_eq!(ids(&inference, "a"), ["a", "b"]);
    }

    #[test]
    fn unknown_role_and_no_rules() {
        let inference = RoleInference::from_rules(&[]);
        assert!(inference.is_empty());
        assert!(inference.implied("x").is_empty());
        assert_eq!(inference.heap_size(), 0);
    }

    #[test]
    fn name_is_taken_from_any_rule_that_knows_it() {
        let nameless = RoleRef {
            id: "b".into(),
            name: None,
            domain_id: None,
        };
        let inference = RoleInference::from_rules(&[
            RoleImply {
                prior_role: role("a"),
                implied_role: nameless,
            },
            rule("b", "c"),
        ]);
        assert_eq!(inference.implied("a")[0].name.as_deref(), Some("name-b"));
    }
}
