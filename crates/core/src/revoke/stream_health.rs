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

//! Freshness of the revocation streams of other authorities (ADR 0045
//! section 9).
//!
//! A token issued by another authority is revoked there, and the revocation
//! reaches this authority over a priority stream. A request that carries such
//! a token can be trusted only as far as that stream is up to date. The
//! consumer of a stream reports every heartbeat and event here; a decision
//! that depends on the token asks whether the stream is [stale]
//! (`StreamHealth::is_stale`) and, if it is, the policy of a sensitive action
//! denies it (`input.credentials.revocation_stale`).
//!
//! A stream that was never heard from counts as stale: failing closed is the
//! safe reading of "nothing arrived".
//!
//! [stale]: StreamHealth::is_stale

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use openstack_keystone_telemetry::metrics::{self, CounterVec, GaugeVec, Label, Meter};

/// Default of `[revoke] revocation_max_staleness`.
pub const DEFAULT_MAX_STALENESS: Duration = Duration::from_secs(30);

/// Metrics of the revocation streams.
pub struct StreamMetrics {
    /// `keystone_revocation_event_age_seconds{authority}`: the age of the
    /// last revocation event when it arrived, that is how long the event took
    /// to reach this authority.
    event_age: GaugeVec<1>,
    /// `keystone_revocation_head_age_seconds{authority}`: how long ago the
    /// last heartbeat or event arrived, as seen at the last decision.
    head_age: GaugeVec<1>,
    /// `keystone_revocation_stale_decisions_total{authority}`: requests that
    /// were marked stale.
    stale_decisions: CounterVec<1>,
}

impl StreamMetrics {
    /// Create the instruments on `meter`.
    pub fn new(meter: &Meter) -> Self {
        Self {
            event_age: GaugeVec::new(
                meter,
                "keystone_revocation_event_age_seconds",
                "Age of the last revocation event of an authority when it arrived.",
                ["authority"],
            ),
            head_age: GaugeVec::new(
                meter,
                "keystone_revocation_head_age_seconds",
                "Time since the last heartbeat or event of the revocation stream of an authority.",
                ["authority"],
            ),
            stale_decisions: CounterVec::new(
                meter,
                "keystone_revocation_stale_decisions_total",
                "Requests marked as depending on a stale revocation stream, by authority.",
                ["authority"],
            ),
        }
    }
}

/// When each authority's stream was last heard from.
///
/// Only registered authorities, the ones a consumer is configured for, are
/// tracked and exported as metrics: the issuer of a token is not a bounded
/// set, the configured authorities are.
pub struct StreamHealth {
    heard: RwLock<HashMap<String, Option<Instant>>>,
    metrics: Option<Arc<StreamMetrics>>,
}

impl StreamHealth {
    /// A tracker that reports to the process-wide metrics.
    fn global() -> Self {
        Self {
            heard: RwLock::new(HashMap::new()),
            metrics: Some(Arc::new(StreamMetrics::new(&metrics::meter()))),
        }
    }

    /// Start tracking `authority`. Until its stream is heard from it is
    /// stale.
    pub fn register(&self, authority: &str) {
        if let Ok(mut heard) = self.heard.write() {
            heard.entry(authority.to_owned()).or_insert(None);
        }
    }

    /// A tracker without metrics, for tests.
    #[cfg(test)]
    pub fn detached() -> Self {
        Self {
            heard: RwLock::new(HashMap::new()),
            metrics: None,
        }
    }

    /// The stream of `authority` has caught up: its heartbeat arrived after
    /// every earlier event was applied.
    pub fn record_head(&self, authority: &str) {
        self.record_head_at(authority, Instant::now());
    }

    fn record_head_at(&self, authority: &str, at: Instant) {
        if let Ok(mut heard) = self.heard.write() {
            heard.insert(authority.to_owned(), Some(at));
        }
        if let Some(metrics) = &self.metrics {
            metrics.head_age.set(0, [Label::bounded(authority)]);
        }
    }

    /// An event revoked at `revoked_at` arrived from `authority`: only its
    /// age is recorded. An event is not proof that the stream has caught up,
    /// so it does not count as a heartbeat; see [`Self::record_head`].
    pub fn record_event(&self, authority: &str, revoked_at: DateTime<Utc>) {
        if let Some(metrics) = &self.metrics {
            let age = (Utc::now() - revoked_at).num_seconds().max(0);
            metrics.event_age.set(age, [Label::bounded(authority)]);
        }
    }

    /// How long ago the stream of `authority` was last heard from; `None` if
    /// it never was.
    pub fn head_age(&self, authority: &str) -> Option<Duration> {
        self.heard
            .read()
            .ok()?
            .get(authority)
            .copied()
            .flatten()
            .map(|at| at.elapsed())
    }

    /// Whether the revocation state behind a token issued by `issuer` may be
    /// out of date by more than `max`.
    ///
    /// `None` is a token of this authority, whose revocations are local and
    /// current. An authority never heard from is stale.
    pub fn is_stale(&self, issuer: Option<&str>, max: Duration) -> bool {
        let Some(authority) = issuer else {
            return false;
        };
        let age = self.head_age(authority);
        let stale = age.is_none_or(|age| age > max);
        let registered = self
            .heard
            .read()
            .is_ok_and(|heard| heard.contains_key(authority));
        if registered && let Some(metrics) = &self.metrics {
            if let Some(age) = age {
                let secs = i64::try_from(age.as_secs()).unwrap_or(i64::MAX);
                metrics.head_age.set(secs, [Label::bounded(authority)]);
            }
            if stale {
                metrics.stale_decisions.inc([Label::bounded(authority)]);
            }
        }
        stale
    }
}

/// The tracker of this process.
pub static STREAM_HEALTH: LazyLock<StreamHealth> = LazyLock::new(StreamHealth::global);

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: Duration = Duration::from_secs(30);

    #[test]
    fn a_local_token_is_never_stale() {
        let health = StreamHealth::detached();
        assert!(!health.is_stale(None, MAX));
    }

    #[test]
    fn a_stream_never_heard_from_is_stale() {
        let health = StreamHealth::detached();
        assert!(health.is_stale(Some("eu"), MAX));
    }

    #[test]
    fn a_fresh_stream_is_not_stale_and_an_old_one_is() {
        let health = StreamHealth::detached();
        health.register("eu");
        health.record_head("eu");
        assert!(!health.is_stale(Some("eu"), MAX));
        // Another authority is judged by its own stream.
        assert!(health.is_stale(Some("us"), MAX));

        let old = Instant::now()
            .checked_sub(Duration::from_secs(31))
            .unwrap_or_else(Instant::now);
        health.record_head_at("us", old);
        assert!(health.is_stale(Some("us"), MAX));
        assert!(!health.is_stale(Some("us"), Duration::from_secs(60)));
    }

    #[test]
    fn an_event_is_not_a_heartbeat() {
        let health = StreamHealth::detached();
        health.register("eu");
        health.record_event("eu", Utc::now());
        assert!(health.is_stale(Some("eu"), MAX));
    }

    #[test]
    fn metrics_are_exposed_per_authority() {
        use openstack_keystone_telemetry::metrics::MetricsPipeline;
        let pipeline = MetricsPipeline::new();
        let health = StreamHealth {
            heard: RwLock::new(HashMap::new()),
            metrics: Some(Arc::new(StreamMetrics::new(&pipeline.meter()))),
        };
        health.register("us");
        health.record_event("eu", Utc::now() - chrono::Duration::seconds(3));
        health.record_head("eu");
        assert!(!health.is_stale(Some("eu"), MAX));
        assert!(health.is_stale(Some("us"), MAX));
        let text = pipeline.render();
        assert!(text.contains("keystone_revocation_event_age_seconds{authority=\"eu\"} 3\n"));
        assert!(text.contains("keystone_revocation_head_age_seconds{authority=\"eu\"} 0\n"));
        assert!(text.contains("keystone_revocation_stale_decisions_total{authority=\"us\"} 1\n"));
        assert!(!text.contains("keystone_revocation_stale_decisions_total{authority=\"eu\"}"));

        // An issuer nobody configured is stale but never becomes a label.
        assert!(health.is_stale(Some("attacker"), MAX));
        assert!(!pipeline.render().contains("attacker"));
    }
}
