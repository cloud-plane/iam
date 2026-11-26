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
//! # Driver-side projection cache
//!
//! A SQL driver caches *projections*: small, derived, non-secret facts (a
//! password expiry, the options of a user, the domain of a project), never the
//! rows they were computed from and never secret material.
//!
//! An entry is served only when the reader's [`Freshness`] allows it:
//!
//! - [`Freshness::Linearizable`] first syncs the counters
//!   ([`TableWatermarks::sync`], one `SELECT` shared by concurrent readers)
//!   and serves an entry only if they are unchanged since it was loaded.
//! - With the table watermark poller running, an entry is valid while the
//!   counters of the tables it depends on are unchanged *and* the counters
//!   themselves are recent enough for the requested tolerance. A tolerance
//!   below the poll interval is a forced read (see
//!   [`TableWatermarks::stamp_for`]).
//! - Without the poller a tolerance is honoured by the age of the entry.
//!
//! A read that is not served from the cache still refreshes it, so a tight
//! reader keeps the entries warm for the relaxed ones.
//!
//! # Memory and age
//!
//! A cache never grows past its share of `[database]
//! projection_cache_max_memory_mib` (like `memcached -m`): every entry is
//! charged its approximate size and, when a new entry does not fit, expired
//! entries are dropped first, then arbitrary ones. The total is split among
//! all projection caches by [`weight`]. Independently of the freshness of the
//! reader an entry is never served older than `[database]
//! projection_cache_ttl_ms`, so a missed invalidation heals itself.
//!
//! The driver invalidates the cache itself on the writes it performs
//! ([`ProjectionCache::invalidate_key`], or [`ProjectionCache::invalidate`]
//! when the affected keys are unknown): the watermark only reaches this replica
//! after the next poll, and a replica must see its own writes.

use std::collections::HashMap;
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use openstack_keystone_config::Config;
use sea_orm::DatabaseConnection;
use tokio::sync::Semaphore;

use openstack_keystone_core_types::freshness::Freshness;

use crate::table_watermark::{ReadScope, TableWatermarks};

/// Accounting overhead per entry on top of the key and the value: the map
/// slot, the hash and the allocation headers.
const ENTRY_OVERHEAD: usize = 64;

/// The projection caches that share the memory budget.
///
/// Every cache of every driver is listed here so that the shares add up to
/// the whole budget whichever drivers are built. The weights are the
/// `[database] projection_cache_weight_*` options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheKind {
    /// Options of a user: small, one per active user.
    UserOptions,
    /// Password expiry of a user: tiny.
    PasswordExpiry,
    /// Domain of a project: tiny.
    ProjectDomain,
    /// Domain of a user: tiny.
    UserDomain,
    /// Parents of a project: a list of IDs.
    ProjectParents,
    /// Short project: a few strings.
    ProjectRef,
    /// Short domain: a few strings.
    DomainRef,
    /// Groups of a user: a list of group records.
    UserGroups,
    /// Role assignments of the actors of a request on its targets.
    Assignments,
    /// The user record.
    User,
    /// The local user row: the name of a local user.
    LocalUser,
    /// Answer of the token revocation check.
    Revocation,
    /// Names of roles: a few strings per role.
    RoleNames,
    /// The role inference graph resolved into closures: one entry.
    RoleInference,
    /// The assembled service catalog: one entry per `enabled` flag.
    Catalog,
}

impl CacheKind {
    /// All the caches.
    pub const ALL: [CacheKind; 15] = [
        Self::UserOptions,
        Self::PasswordExpiry,
        Self::ProjectDomain,
        Self::UserDomain,
        Self::ProjectParents,
        Self::ProjectRef,
        Self::DomainRef,
        Self::UserGroups,
        Self::Assignments,
        Self::User,
        Self::LocalUser,
        Self::Revocation,
        Self::RoleNames,
        Self::RoleInference,
        Self::Catalog,
    ];

    /// The configured weight of the cache.
    pub fn weight(self, config: &Config) -> u64 {
        let db = &config.database;
        u64::from(match self {
            Self::UserOptions => db.projection_cache_weight_user_options,
            Self::PasswordExpiry => db.projection_cache_weight_password_expiry,
            Self::ProjectDomain => db.projection_cache_weight_project_domain,
            Self::UserDomain => db.projection_cache_weight_user_domain,
            Self::ProjectParents => db.projection_cache_weight_project_parents,
            Self::ProjectRef => db.projection_cache_weight_project_ref,
            Self::DomainRef => db.projection_cache_weight_domain_ref,
            Self::UserGroups => db.projection_cache_weight_user_groups,
            Self::Assignments => db.projection_cache_weight_assignments,
            Self::User => db.projection_cache_weight_user,
            Self::LocalUser => db.projection_cache_weight_local_user,
            Self::Revocation => db.projection_cache_weight_revocation,
            Self::RoleNames => db.projection_cache_weight_role_names,
            Self::RoleInference => db.projection_cache_weight_role_inference,
            Self::Catalog => db.projection_cache_weight_catalog,
        })
    }
}

/// Memory and age limits of one cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheLimits {
    /// Approximate bytes the entries may take. `0` disables the cache.
    pub max_bytes: usize,
    /// Hard maximum age of an entry. Zero disables the cache.
    pub ttl: Duration,
    /// How long an entry is trusted for [`Freshness::Any`] when there is no
    /// watermark poller to say that it is outdated.
    pub any_ttl_without_poller: Duration,
}

impl CacheLimits {
    /// Apply the `caching` and `cache_time` options of a provider: the
    /// maximum age is capped by `cache_time` seconds, and `caching = false`
    /// or `cache_time = 0` disable the cache.
    pub fn capped(mut self, caching: bool, cache_time: u64) -> Self {
        self.ttl = if caching {
            self.ttl.min(Duration::from_secs(cache_time))
        } else {
            Duration::ZERO
        };
        self
    }

    /// The limits of the cache `kind`: its share of
    /// `[database] projection_cache_max_memory_mib` by the weights, and the
    /// configured ages.
    pub fn from_config(config: &Config, kind: CacheKind) -> Self {
        let db = &config.database;
        let total = usize::try_from(
            db.projection_cache_max_memory_mib
                .saturating_mul(1024 * 1024),
        )
        .unwrap_or(usize::MAX);
        let share = total as u128 * u128::from(kind.weight(config))
            / u128::from(db.projection_cache_weight_total().max(1));
        Self {
            max_bytes: usize::try_from(share).unwrap_or(usize::MAX),
            ttl: Duration::from_millis(db.projection_cache_ttl_ms),
            any_ttl_without_poller: Duration::from_millis(db.projection_any_ttl_without_poller_ms),
        }
    }
}

impl Default for CacheLimits {
    /// The whole default budget as one cache.
    fn default() -> Self {
        let mut config = Config::default();
        config.database.projection_cache_weight_user_options = 1;
        let db = &mut config.database;
        db.projection_cache_weight_password_expiry = 0;
        db.projection_cache_weight_project_domain = 0;
        db.projection_cache_weight_user_domain = 0;
        db.projection_cache_weight_project_parents = 0;
        db.projection_cache_weight_project_ref = 0;
        db.projection_cache_weight_domain_ref = 0;
        db.projection_cache_weight_user_groups = 0;
        db.projection_cache_weight_assignments = 0;
        db.projection_cache_weight_user = 0;
        db.projection_cache_weight_local_user = 0;
        db.projection_cache_weight_revocation = 0;
        db.projection_cache_weight_role_names = 0;
        db.projection_cache_weight_role_inference = 0;
        db.projection_cache_weight_catalog = 0;
        Self::from_config(&config, CacheKind::UserOptions)
    }
}

/// Shortest time between two scans for expired entries of a full cache.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Number of invalidation shards. A write to one key also drops the entries
/// loaded concurrently for keys of the same shard, which is harmless.
const SHARDS: usize = 64;

struct Entry<V> {
    /// Counters of the tables before the load, `None` without a poller.
    stamp: Option<u64>,
    /// Invalidation generation of the key's shard before the load.
    generation: u64,
    loaded_at: Instant,
    /// Approximate bytes charged to the cache.
    size: usize,
    value: V,
}

struct Inner<V> {
    map: HashMap<String, Entry<V>>,
    /// Sum of the `size` of the entries.
    bytes: usize,
    last_sweep: Instant,
}

impl<V> Inner<V> {
    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.map.remove(key) {
            self.bytes = self.bytes.saturating_sub(entry.size);
        }
    }

    /// Drop the entries older than `ttl`.
    fn sweep(&mut self, ttl: Duration) {
        self.last_sweep = Instant::now();
        let mut freed = 0usize;
        self.map.retain(|_, entry| {
            let keep = entry.loaded_at.elapsed() <= ttl;
            if !keep {
                freed += entry.size;
            }
            keep
        });
        self.bytes = self.bytes.saturating_sub(freed);
    }
}

/// A map of projections of the `tables`, bounded in memory and age.
pub struct ProjectionCache<V> {
    tables: &'static [&'static str],
    limits: CacheLimits,
    /// Heap bytes of a value, see [`entry_size`].
    weigh: fn(&V) -> usize,
    generations: Vec<AtomicU64>,
    inner: RwLock<Inner<V>>,
    /// The loads in progress by key, see [`Self::begin_flight`].
    flights: Mutex<HashMap<String, Arc<Semaphore>>>,
}

/// The load of a key in progress. Dropping it (also when the load is
/// cancelled) releases the readers waiting for the result.
/// Times a reader waits for a load of its key before it loads on its own.
const MAX_FLIGHT_WAITS: u32 = 3;

struct FlightGuard<'a> {
    flights: &'a Mutex<HashMap<String, Arc<Semaphore>>>,
    key: String,
    done: Arc<Semaphore>,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut flights) = self.flights.lock()
            && flights
                .get(&self.key)
                .is_some_and(|running| Arc::ptr_eq(running, &self.done))
        {
            flights.remove(&self.key);
        }
        // A closed semaphore wakes every waiter, and one that arrives later
        // does not wait at all.
        self.done.close();
    }
}

/// Approximate bytes an entry takes: the entry itself, the key and the heap
/// of the value (`heap`).
fn entry_size<V>(key: &str, heap: usize) -> usize {
    std::mem::size_of::<Entry<V>>() + ENTRY_OVERHEAD + key.len() + heap
}

impl<V: Clone> ProjectionCache<V> {
    /// Create a cache of projections that depend on the `tables`.
    ///
    /// `weigh` returns the bytes a value holds on the heap (`0` for plain
    /// data). When the entries do not fit the `limits`, expired entries are
    /// dropped and then arbitrary ones are evicted.
    pub fn new(
        tables: &'static [&'static str],
        limits: CacheLimits,
        weigh: fn(&V) -> usize,
    ) -> Self {
        Self {
            tables,
            limits,
            weigh,
            generations: (0..SHARDS).map(|_| AtomicU64::new(0)).collect(),
            inner: RwLock::new(Inner {
                map: HashMap::new(),
                bytes: 0,
                last_sweep: Instant::now(),
            }),
            flights: Mutex::new(HashMap::new()),
        }
    }

    /// Become the reader that loads `key`, or get the semaphore to wait for
    /// the reader that already does.
    ///
    /// After a write moves the counters every concurrent reader misses at
    /// once; without this each of them would run the same query. `Ok(None)`
    /// is a load nobody can wait for (the registry is unusable).
    fn begin_flight(&self, key: &str) -> Result<Option<FlightGuard<'_>>, Arc<Semaphore>> {
        let Ok(mut flights) = self.flights.lock() else {
            return Ok(None);
        };
        if let Some(running) = flights.get(key) {
            return Err(running.clone());
        }
        let done = Arc::new(Semaphore::new(0));
        flights.insert(key.to_string(), done.clone());
        Ok(Some(FlightGuard {
            flights: &self.flights,
            key: key.to_string(),
            done,
        }))
    }

    /// The cached value, or the right to load it.
    ///
    /// The reader that claims the key is the only one to load it; the others
    /// wait for it and look again. Both the claimant and a woken reader look
    /// at the cache once more: a flight that ended between the first miss and
    /// the claim has stored the value, and loading it again would let a
    /// stream of readers reload it one after another. After
    /// [`MAX_FLIGHT_WAITS`] rounds a reader loads on its own, so a value that
    /// is never stored does not queue the readers.
    ///
    /// `Err` carries the flight (none for a reader that loads on its own)
    /// and the generation to store the loaded value with.
    async fn hit_or_flight(
        &self,
        watermarks: &TableWatermarks,
        synced: bool,
        key: &str,
        freshness: Freshness,
    ) -> Result<V, (Option<FlightGuard<'_>>, u64)> {
        let mut waits = 0;
        loop {
            let generation = self.shard(key).load(Ordering::Acquire);
            if let Some(hit) = self.lookup(watermarks, synced, key, freshness, generation) {
                return Ok(hit);
            }
            match self.begin_flight(key) {
                Ok(flight) => {
                    let generation = self.shard(key).load(Ordering::Acquire);
                    if let Some(hit) = self.lookup(watermarks, synced, key, freshness, generation) {
                        return Ok(hit);
                    }
                    return Err((flight, generation));
                }
                Err(running) => {
                    let _ = running.acquire().await;
                    waits += 1;
                    if waits >= MAX_FLIGHT_WAITS {
                        let generation = self.shard(key).load(Ordering::Acquire);
                        return Err((None, generation));
                    }
                }
            }
        }
    }

    fn shard(&self, key: &str) -> &AtomicU64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        // The modulo keeps the value below SHARDS, so the index is in range.
        let index = usize::try_from(hasher.finish() % SHARDS as u64).unwrap_or(0);
        &self.generations[index]
    }

    /// Drop everything, e.g. after the driver wrote rows whose keys it does
    /// not know.
    ///
    /// A load that started before the call cannot repopulate the cache with a
    /// result that predates the write.
    pub fn invalidate(&self) {
        // A write just committed: the reads of its request must see it.
        ReadScope::advance();
        for generation in &self.generations {
            generation.fetch_add(1, Ordering::AcqRel);
        }
        if let Ok(mut inner) = self.inner.write() {
            inner.map.clear();
            inner.bytes = 0;
        }
    }

    /// Drop the projection of one `key`, e.g. after the driver wrote it.
    ///
    /// A load of the key that started before the call cannot store a result
    /// that predates the write.
    pub fn invalidate_key(&self, key: &str) {
        ReadScope::advance();
        self.shard(key).fetch_add(1, Ordering::AcqRel);
        if let Ok(mut inner) = self.inner.write() {
            inner.remove(key);
        }
    }

    /// Number of entries, for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.inner.read().map(|i| i.map.len()).unwrap_or(0)
    }

    /// Approximate bytes the entries take, for tests and diagnostics.
    pub fn bytes(&self) -> usize {
        self.inner.read().map(|i| i.bytes).unwrap_or(0)
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lookup(
        &self,
        watermarks: &TableWatermarks,
        synced: bool,
        key: &str,
        freshness: Freshness,
        generation: u64,
    ) -> Option<V> {
        let current = if freshness.is_linearizable() {
            // Only the counters of a sync made for this read prove that the
            // entry is current; without them the database is read.
            if !synced {
                return None;
            }
            Some(watermarks.stamp(self.tables)?)
        } else if watermarks.interval().is_zero() {
            None
        } else {
            Some(watermarks.stamp_for(self.tables, freshness)?)
        };
        // Lookups only read: concurrent requests share the lock.
        let inner = self.inner.read().ok()?;
        let entry = inner.map.get(key)?;
        let age = entry.loaded_at.elapsed();
        if age > self.limits.ttl {
            drop(inner);
            self.remove_expired(key);
            return None;
        }
        if entry.generation != generation {
            return None;
        }
        let valid = match current {
            Some(current) => entry.stamp == Some(current),
            None => {
                let ttl = freshness
                    .bound()
                    .unwrap_or(self.limits.any_ttl_without_poller);
                age <= ttl
            }
        };
        valid.then(|| entry.value.clone())
    }

    /// Drop the entry of `key` if it is still expired (it may have been
    /// replaced between releasing the read lock and taking the write lock).
    fn remove_expired(&self, key: &str) {
        if let Ok(mut inner) = self.inner.write()
            && inner
                .map
                .get(key)
                .is_some_and(|entry| entry.loaded_at.elapsed() > self.limits.ttl)
        {
            inner.remove(key);
        }
    }

    /// Serve an entry of an *immutable* fact: it is neither validated against
    /// the counters nor does it need a counter sync, only its age
    /// (`projection_cache_ttl_ms`, capped by the provider's `cache_time`),
    /// and the invalidation of the driver's own writes, decide.
    fn lookup_immutable(&self, key: &str, generation: u64) -> Option<V> {
        let inner = self.inner.read().ok()?;
        let entry = inner.map.get(key)?;
        if entry.loaded_at.elapsed() > self.limits.ttl {
            drop(inner);
            self.remove_expired(key);
            return None;
        }
        (entry.generation == generation).then(|| entry.value.clone())
    }

    /// Like [`Self::get_or_load_some`] for a fact that never changes while the
    /// row exists (e.g. the domain and the parents of a project).
    ///
    /// Writes to the table do not drop the entry, so a busy table does not
    /// make the fact reload. Only the deletion of the row matters: the driver
    /// invalidates on its own deletes, and one made by another process is
    /// noticed after the age limit. A missing value is returned but never
    /// stored.
    ///
    /// Like every projection cache it is off (every read loads) while the
    /// watermarks are disabled (`table_watermark_interval_ms = 0`).
    pub async fn get_or_load_some_immutable<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        key: &str,
        load: F,
    ) -> Result<Option<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<V>, E>>,
    {
        if watermarks.interval().is_zero() {
            return load().await;
        }
        let generation = self.shard(key).load(Ordering::Acquire);
        if let Some(hit) = self.lookup_immutable(key, generation) {
            return Ok(Some(hit));
        }
        let value = load().await?;
        if let Some(value) = &value {
            self.store(key, None, generation, value);
        }
        Ok(value)
    }

    /// Get the projection for the `key` or load it.
    ///
    /// # Parameters
    /// - `watermarks`: counters of the connection the loader reads through.
    /// - `key`: what the projection is about, e.g. a user ID.
    /// - `freshness`: how stale the result may be.
    /// - `load`: reads the projection from the database. It must not
    ///   depend on anything but the `tables` of the cache.
    ///
    /// Concurrent misses of one key share a single load: the others wait for
    /// it and are served from the entry it stores. A reader the entry does not
    /// satisfy (the counters moved again, a write invalidated the key) loads
    /// on its own after the wait, so a waiter never waits for more than one
    /// load.
    pub async fn get_or_load<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        db: &DatabaseConnection,
        key: &str,
        freshness: Freshness,
        load: F,
    ) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let synced = self.sync_if_linearizable(watermarks, db, freshness).await;
        self.get_or_load_with(watermarks, synced, key, freshness, load)
            .await
    }

    /// A linearizable read brings the counters up to date first (one
    /// shared `SELECT`), so an unchanged table is served from the cache.
    async fn sync_if_linearizable(
        &self,
        watermarks: &TableWatermarks,
        db: &DatabaseConnection,
        freshness: Freshness,
    ) -> bool {
        freshness.is_linearizable() && watermarks.sync(db).await
    }

    async fn get_or_load_with<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        synced: bool,
        key: &str,
        freshness: Freshness,
        load: F,
    ) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let (_flight, generation) =
            match self.hit_or_flight(watermarks, synced, key, freshness).await {
                Ok(hit) => return Ok(hit),
                Err(claimed) => claimed,
            };
        // The stamp is taken before the load: the value is at least as new
        // as the counters it is labelled with.
        let stamp = watermarks.stamp(self.tables);
        let value = load().await?;
        if Self::storable(watermarks, stamp, freshness) {
            self.store(key, stamp, generation, &value);
        }
        Ok(value)
    }

    /// Like [`Self::get_or_load`] for a loader that also says whether the
    /// value may be kept: a value that depends on something the tables do
    /// not tell (e.g. the clock) is returned but not stored.
    pub async fn get_or_load_if<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        db: &DatabaseConnection,
        key: &str,
        freshness: Freshness,
        load: F,
    ) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(V, bool), E>>,
    {
        let synced = self.sync_if_linearizable(watermarks, db, freshness).await;
        self.get_or_load_if_with(watermarks, synced, key, freshness, load)
            .await
    }

    async fn get_or_load_if_with<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        synced: bool,
        key: &str,
        freshness: Freshness,
        load: F,
    ) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(V, bool), E>>,
    {
        let (_flight, generation) =
            match self.hit_or_flight(watermarks, synced, key, freshness).await {
                Ok(hit) => return Ok(hit),
                Err(claimed) => claimed,
            };
        let stamp = watermarks.stamp(self.tables);
        let (value, keep) = load().await?;
        if keep && Self::storable(watermarks, stamp, freshness) {
            self.store(key, stamp, generation, &value);
        }
        Ok(value)
    }

    /// Like [`Self::get_or_load`] for a loader that may find nothing.
    ///
    /// A missing value is returned but never stored: a stale "does not
    /// exist" is worse than a stale value, and misses are cheap to repeat.
    pub async fn get_or_load_some<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        db: &DatabaseConnection,
        key: &str,
        freshness: Freshness,
        load: F,
    ) -> Result<Option<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<V>, E>>,
    {
        let synced = self.sync_if_linearizable(watermarks, db, freshness).await;
        self.get_or_load_some_with(watermarks, synced, key, freshness, load)
            .await
    }

    async fn get_or_load_some_with<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        synced: bool,
        key: &str,
        freshness: Freshness,
        load: F,
    ) -> Result<Option<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<V>, E>>,
    {
        let (_flight, generation) =
            match self.hit_or_flight(watermarks, synced, key, freshness).await {
                Ok(hit) => return Ok(Some(hit)),
                Err(claimed) => claimed,
            };
        let stamp = watermarks.stamp(self.tables);
        let value = load().await?;
        if let Some(value) = &value
            && Self::storable(watermarks, stamp, freshness)
        {
            self.store(key, stamp, generation, value);
        }
        Ok(value)
    }

    /// Like [`Self::get_or_load`] for a set of `keys` loaded with one query.
    ///
    /// The keys that are not served from the cache are handed to `load`
    /// together; it returns the projections it found by key, and each is
    /// stored under its key. A key `load` finds nothing for is absent from
    /// the result and not stored. A repeated key yields one value. The order of
    /// the result is unspecified.
    pub async fn get_or_load_many<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        db: &DatabaseConnection,
        keys: &[String],
        freshness: Freshness,
        load: F,
    ) -> Result<Vec<V>, E>
    where
        F: FnOnce(Vec<String>) -> Fut,
        Fut: Future<Output = Result<Vec<(String, V)>, E>>,
    {
        let synced = self.sync_if_linearizable(watermarks, db, freshness).await;
        self.get_or_load_many_with(watermarks, synced, keys, freshness, load)
            .await
    }

    async fn get_or_load_many_with<E, F, Fut>(
        &self,
        watermarks: &TableWatermarks,
        synced: bool,
        keys: &[String],
        freshness: Freshness,
        load: F,
    ) -> Result<Vec<V>, E>
    where
        F: FnOnce(Vec<String>) -> Fut,
        Fut: Future<Output = Result<Vec<(String, V)>, E>>,
    {
        let mut values = Vec::with_capacity(keys.len());
        // The invalidation generation of every missing key before the load.
        let mut missing: HashMap<&str, u64> = HashMap::new();
        // A repeated key is answered once, whatever the cache holds.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for key in keys {
            if !seen.insert(key.as_str()) {
                continue;
            }
            let generation = self.shard(key).load(Ordering::Acquire);
            match self.lookup(watermarks, synced, key, freshness, generation) {
                Some(hit) => values.push(hit),
                None => {
                    missing.insert(key.as_str(), generation);
                }
            }
        }
        if missing.is_empty() {
            return Ok(values);
        }
        let stamp = watermarks.stamp(self.tables);
        let loaded = load(missing.keys().map(|k| (*k).to_string()).collect()).await?;
        let storable = Self::storable(watermarks, stamp, freshness);
        for (key, value) in loaded {
            if storable && let Some(generation) = missing.get(key.as_str()) {
                self.store(&key, stamp, *generation, &value);
            }
            values.push(value);
        }
        Ok(values)
    }

    /// Whether an entry loaded with `stamp` can ever be served. Without a
    /// stamp (counters unavailable, e.g. the triggers are not installed) a
    /// running poller makes every lookup a miss, so storing would only cost.
    ///
    /// Without a poller a linearizable read never finds an entry (it
    /// cannot sync), so such an entry is not stored either.
    fn storable(watermarks: &TableWatermarks, stamp: Option<u64>, freshness: Freshness) -> bool {
        stamp.is_some() || (watermarks.interval().is_zero() && !freshness.is_linearizable())
    }

    fn store(&self, key: &str, stamp: Option<u64>, generation: u64, value: &V) {
        let size = entry_size::<V>(key, (self.weigh)(value));
        if size > self.limits.max_bytes || self.limits.ttl.is_zero() {
            return;
        }
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        // An invalidation since the load started: the value may predate it.
        if self.shard(key).load(Ordering::Acquire) != generation {
            return;
        }
        inner.remove(key);
        if inner.bytes + size > self.limits.max_bytes {
            // At most one scan per second (or TTL), however often the cache
            // is full.
            if inner.last_sweep.elapsed() >= self.limits.ttl.min(SWEEP_INTERVAL) {
                inner.sweep(self.limits.ttl);
            }
            while inner.bytes + size > self.limits.max_bytes {
                let Some(victim) = inner.map.keys().next().cloned() else {
                    break;
                };
                inner.remove(&victim);
            }
        }
        inner.bytes += size;
        inner.map.insert(
            key.to_string(),
            Entry {
                stamp,
                generation,
                loaded_at: Instant::now(),
                size,
                value: value.clone(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cache_time_caps_the_ttl() {
        let base = CacheLimits {
            ttl: Duration::from_secs(300),
            ..CacheLimits::default()
        };
        assert_eq!(Duration::from_secs(10), base.capped(true, 10).ttl);
        assert_eq!(Duration::from_secs(300), base.capped(true, 600).ttl);
        assert!(base.capped(true, 0).ttl.is_zero());
        assert!(base.capped(false, 10).ttl.is_zero());
    }

    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    const TABLES: &[&str] = &["t"];
    const SEC: Duration = Duration::from_secs(1);

    /// A cache that holds `entries` entries with a one-byte key.
    fn cache(entries: usize) -> ProjectionCache<u32> {
        ProjectionCache::new(
            TABLES,
            CacheLimits {
                max_bytes: entries * entry_size::<u32>("k", 0),
                ttl: Duration::from_secs(60),
                ..CacheLimits::default()
            },
            |_| 0,
        )
    }

    fn watermarks(interval_ms: u64, version: i64) -> TableWatermarks {
        let wm = TableWatermarks::new();
        wm.configure(Duration::from_millis(interval_ms));
        wm.publish(HashMap::from([("t".to_string(), version)]));
        wm
    }

    async fn load(
        cache: &ProjectionCache<u32>,
        wm: &TableWatermarks,
        f: Freshness,
        calls: &AtomicUsize,
    ) -> u32 {
        cache
            .get_or_load_with::<(), _, _>(wm, false, "k", f, || async {
                Ok(u32::try_from(calls.fetch_add(1, Ordering::SeqCst)).unwrap_or(u32::MAX) + 1)
            })
            .await
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_load() {
        let cache = Arc::new(cache(8));
        let wm = Arc::new(watermarks(1000, 1));
        let calls = Arc::new(AtomicUsize::new(0));
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let (cache, wm, calls) = (cache.clone(), wm.clone(), calls.clone());
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_load_with::<(), _, _>(&wm, false, "k", relaxed, || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(7u32)
                    })
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.ok(), Some(Ok(7)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.flights.lock().map(|f| f.is_empty()).unwrap_or(false));
    }

    #[tokio::test]
    async fn a_waiter_loads_on_its_own_when_the_result_is_not_stored() {
        let cache = Arc::new(cache(8));
        let wm = Arc::new(watermarks(1000, 1));
        let calls = Arc::new(AtomicUsize::new(0));
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let (cache, wm, calls) = (cache.clone(), wm.clone(), calls.clone());
            tasks.push(tokio::spawn(async move {
                // The value is volatile: it is never stored.
                cache
                    .get_or_load_if_with::<(), _, _>(&wm, false, "k", relaxed, || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok((7u32, false))
                    })
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.ok(), Some(Ok(7)));
        }
        // Every reader got an answer; none of them waited for a result that
        // was never stored beyond one load.
        assert!(calls.load(Ordering::SeqCst) >= 2);
        assert!(cache.flights.lock().map(|f| f.is_empty()).unwrap_or(false));
    }

    #[tokio::test]
    async fn a_cancelled_load_releases_the_waiters() {
        let cache = Arc::new(cache(8));
        let wm = Arc::new(watermarks(1000, 1));
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        let leader = {
            let (cache, wm) = (cache.clone(), wm.clone());
            tokio::spawn(async move {
                cache
                    .get_or_load_with::<(), _, _>(&wm, false, "k", relaxed, || async {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        Ok(1u32)
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let waiter = {
            let (cache, wm) = (cache.clone(), wm.clone());
            tokio::spawn(async move {
                cache
                    .get_or_load_with::<(), _, _>(&wm, false, "k", relaxed, || async { Ok(2u32) })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        leader.abort();
        let got = tokio::time::timeout(Duration::from_secs(5), waiter).await;
        assert_eq!(got.ok().and_then(Result::ok), Some(Ok(2)));
    }

    #[tokio::test]
    async fn many_loads_only_the_missing_keys_in_one_call() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        let calls = AtomicUsize::new(0);
        let keys = |ks: &[&str]| ks.iter().map(|k| k.to_string()).collect::<Vec<_>>();
        let loader = |ks: Vec<String>| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok::<_, ()>(
                    ks.into_iter()
                        .filter(|k| k != "none")
                        .map(|k| (k, 7u32))
                        .collect::<Vec<_>>(),
                )
            }
        };
        let got = cache
            .get_or_load_many_with(&wm, false, &keys(&["a", "b", "none"]), relaxed, loader)
            .await;
        assert_eq!(got.map(|v| v.len()), Ok(2));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // "a" and "b" are cached, only "c" and "none" are loaded; a missing
        // key is not stored.
        let got = cache
            .get_or_load_many_with(&wm, false, &keys(&["a", "b", "c", "none"]), relaxed, loader)
            .await;
        assert_eq!(got.map(|v| v.len()), Ok(3));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len(), 3);
        // Everything cached: no load.
        let got = cache
            .get_or_load_many_with(&wm, false, &keys(&["c", "a"]), relaxed, loader)
            .await;
        assert_eq!(got.map(|v| v.len()), Ok(2));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // A repeated key yields one value, cold or warm.
        let got = cache
            .get_or_load_many_with(&wm, false, &keys(&["c", "c", "d", "d"]), relaxed, loader)
            .await;
        assert_eq!(got.map(|v| v.len()), Ok(2));
        let got = cache
            .get_or_load_many_with(&wm, false, &keys(&["c", "c", "d", "d"]), relaxed, loader)
            .await;
        assert_eq!(got.map(|v| v.len()), Ok(2));
    }

    #[tokio::test]
    async fn immutable_fact_survives_table_writes() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let loader = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(Some(7u32))
        };
        assert_eq!(
            cache.get_or_load_some_immutable(&wm, "k", loader).await,
            Ok(Some(7))
        );
        // The counters of the table are not consulted: any number of writes
        // to the table leaves the entry in place, and no sync is needed.
        assert_eq!(
            cache.get_or_load_some_immutable(&wm, "k", loader).await,
            Ok(Some(7))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The driver's own delete drops it.
        cache.invalidate_key("k");
        assert_eq!(
            cache.get_or_load_some_immutable(&wm, "k", loader).await,
            Ok(Some(7))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        cache.invalidate();
        assert_eq!(
            cache.get_or_load_some_immutable(&wm, "k", loader).await,
            Ok(Some(7))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn immutable_fact_is_not_cached_while_the_watermarks_are_off() {
        let cache = cache(8);
        let wm = TableWatermarks::new();
        let calls = AtomicUsize::new(0);
        let loader = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(Some(7u32))
        };
        for _ in 0..2 {
            assert_eq!(
                cache.get_or_load_some_immutable(&wm, "k", loader).await,
                Ok(Some(7))
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn immutable_fact_is_not_served_past_the_age_limit_and_misses_are_not_stored() {
        let cache = ProjectionCache::<u32>::new(
            TABLES,
            CacheLimits {
                max_bytes: 8 * entry_size::<u32>("k", 0),
                ttl: Duration::from_millis(20),
                ..CacheLimits::default()
            },
            |_| 0,
        );
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let loader = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(Some(1u32))
        };
        let _ = cache.get_or_load_some_immutable(&wm, "k", loader).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        let _ = cache.get_or_load_some_immutable(&wm, "k", loader).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let none = cache
            .get_or_load_some_immutable(&wm, "gone", || async { Ok::<_, ()>(None) })
            .await;
        assert_eq!(none, Ok(None));
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn invalidating_moves_the_read_scope_forward() {
        let cache = cache(10);
        ReadScope::run(async {
            let before = ReadScope::point().unwrap();
            tokio::time::sleep(Duration::from_millis(3)).await;
            cache.invalidate_key("k");
            let after = ReadScope::point().unwrap();
            assert!(after > before);
            tokio::time::sleep(Duration::from_millis(3)).await;
            cache.invalidate();
            assert!(ReadScope::point().unwrap() > after);
        })
        .await;
    }

    #[tokio::test]
    async fn invalidating_a_key_keeps_the_others() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        for key in ["a", "b"] {
            let _ = cache
                .get_or_load_with::<(), _, _>(&wm, false, key, relaxed, || async { Ok(1u32) })
                .await;
        }
        cache.invalidate_key("a");
        assert_eq!(cache.len(), 1);
        let hit = cache
            .get_or_load_with::<(), _, _>(&wm, false, "b", relaxed, || async { Ok(2u32) })
            .await;
        assert_eq!(hit, Ok(1));
    }

    #[tokio::test]
    async fn full_cache_evicts_one_entry() {
        let cache = cache(2);
        let wm = watermarks(1000, 1);
        for key in ["a", "b", "c"] {
            let _ = cache
                .get_or_load_with::<(), _, _>(&wm, false, key, Freshness::Any, || async {
                    Ok(1u32)
                })
                .await;
        }
        assert_eq!(cache.len(), 2);
    }

    #[tokio::test]
    async fn synced_linearizable_read_serves_unchanged_counters() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let lin = Freshness::Linearizable;
        let load = |n: u32| async move { Ok::<_, ()>(n) };
        assert_eq!(
            cache
                .get_or_load_with(&wm, true, "k", lin, || load(1))
                .await,
            Ok(1)
        );
        // counters unchanged since the load: served
        assert_eq!(
            cache
                .get_or_load_with(&wm, true, "k", lin, || load(2))
                .await,
            Ok(1)
        );
        // not synced: always read through
        assert_eq!(
            cache
                .get_or_load_with(&wm, false, "k", lin, || load(3))
                .await,
            Ok(3)
        );
        // a write moved the counters: reloaded
        wm.publish(HashMap::from([("t".to_string(), 2)]));
        assert_eq!(
            cache
                .get_or_load_with(&wm, true, "k", lin, || load(4))
                .await,
            Ok(4)
        );
    }

    #[tokio::test]
    async fn linearizable_always_reads_through() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        assert_eq!(load(&cache, &wm, Freshness::Linearizable, &calls).await, 1);
        assert_eq!(load(&cache, &wm, Freshness::Linearizable, &calls).await, 2);
        // the linearizable reads refreshed the cache for the relaxed ones
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn relaxed_reads_hit_while_the_watermark_is_unchanged() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // a foreign write moves the counter
        wm.publish(HashMap::from([("t".to_string(), 2)]));
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
    }

    #[tokio::test]
    async fn tolerance_below_the_poll_interval_is_a_forced_read() {
        let cache = cache(8);
        let wm = watermarks(5000, 1);
        let calls = AtomicUsize::new(0);
        let tight = Freshness::MaxStaleness(Duration::from_millis(100));
        assert_eq!(load(&cache, &wm, tight, &calls).await, 1);
        assert_eq!(load(&cache, &wm, tight, &calls).await, 2);
        assert_eq!(load(&cache, &wm, tight, &calls).await, 3);
    }

    #[tokio::test]
    async fn tolerance_at_the_poll_interval_may_hit() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let at = Freshness::MaxStaleness(SEC);
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
    }

    #[tokio::test]
    async fn an_old_snapshot_is_a_forced_read() {
        let cache = cache(8);
        let wm = watermarks(10, 1);
        let calls = AtomicUsize::new(0);
        let at = Freshness::MaxStaleness(Duration::from_millis(20));
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
        // the poller stalls: the counters get older than the tolerance
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(load(&cache, &wm, at, &calls).await, 2);
    }

    #[tokio::test]
    async fn local_invalidation_is_immediate() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        cache.invalidate();
        assert!(cache.is_empty());
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
    }

    #[tokio::test]
    async fn a_volatile_value_is_returned_but_not_stored() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        let value = cache
            .get_or_load_if_with::<(), _, _>(&wm, false, "k", relaxed, || async {
                Ok((7u32, false))
            })
            .await;
        assert_eq!(value, Ok(7));
        assert!(cache.is_empty());
        let value = cache
            .get_or_load_if_with::<(), _, _>(&wm, false, "k", relaxed, || async {
                Ok((8u32, true))
            })
            .await;
        assert_eq!(value, Ok(8));
        assert_eq!(1, cache.len());
    }

    #[tokio::test]
    async fn a_load_racing_an_invalidation_is_not_stored() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        let value = cache
            .get_or_load_with::<(), _, _>(&wm, false, "k", relaxed, || async {
                cache.invalidate();
                Ok(7u32)
            })
            .await;
        assert_eq!(value, Ok(7));
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn without_a_poller_the_age_decides() {
        let cache = cache(8);
        let wm = TableWatermarks::new();
        let calls = AtomicUsize::new(0);
        let at = Freshness::MaxStaleness(Duration::from_millis(30));
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
        assert_eq!(load(&cache, &wm, at, &calls).await, 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(load(&cache, &wm, at, &calls).await, 2);
        assert_eq!(load(&cache, &wm, Freshness::Linearizable, &calls).await, 3);
    }

    #[tokio::test]
    async fn an_unhealthy_poller_is_a_forced_read() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        wm.reset();
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 3);
    }

    #[tokio::test]
    async fn a_missing_value_is_not_stored() {
        let cache = cache(8);
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        for _ in 0..2 {
            let value = cache
                .get_or_load_some_with::<(), _, _>(&wm, false, "k", relaxed, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(None)
                })
                .await;
            assert_eq!(value, Ok(None));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(cache.is_empty());
        let value = cache
            .get_or_load_some_with::<(), _, _>(&wm, false, "k", relaxed, || async { Ok(Some(3)) })
            .await;
        assert_eq!(value, Ok(Some(3)));
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn the_cache_is_bounded() {
        let cache = cache(2);
        let wm = watermarks(1000, 1);
        for key in ["a", "b", "c"] {
            let _ = cache
                .get_or_load_with::<(), _, _>(&wm, false, key, Freshness::Any, || async { Ok(1) })
                .await;
        }
        assert!(cache.len() <= 2);
    }

    #[tokio::test]
    async fn the_budget_is_charged_for_the_heap_of_the_values() {
        let cache = ProjectionCache::<String>::new(
            TABLES,
            CacheLimits {
                max_bytes: 2 * entry_size::<String>("k", 100),
                ttl: Duration::from_secs(60),
                ..CacheLimits::default()
            },
            |v| v.len(),
        );
        let wm = watermarks(1000, 1);
        for key in ["a", "b", "c"] {
            let _ = cache
                .get_or_load_with::<(), _, _>(&wm, false, key, Freshness::Any, || async {
                    Ok("x".repeat(100))
                })
                .await;
        }
        assert_eq!(cache.len(), 2);
        assert!(cache.bytes() <= 2 * entry_size::<String>("k", 100));
        cache.invalidate();
        assert_eq!(cache.bytes(), 0);
    }

    #[tokio::test]
    async fn a_value_larger_than_the_budget_is_not_stored() {
        let cache = ProjectionCache::<String>::new(
            TABLES,
            CacheLimits {
                max_bytes: entry_size::<String>("k", 10),
                ttl: Duration::from_secs(60),
                ..CacheLimits::default()
            },
            |v| v.len(),
        );
        let wm = watermarks(1000, 1);
        let value = cache
            .get_or_load_with::<(), _, _>(&wm, false, "k", Freshness::Any, || async {
                Ok("x".repeat(1000))
            })
            .await;
        assert_eq!(value.map(|v| v.len()), Ok(1000));
        assert!(cache.is_empty());
        assert_eq!(cache.bytes(), 0);
    }

    #[tokio::test]
    async fn replacing_an_entry_does_not_leak_its_charge() {
        let cache = cache(4);
        let wm = watermarks(1000, 1);
        for n in 0..5u32 {
            wm.publish(HashMap::from([("t".to_string(), i64::from(n) + 2)]));
            let _ = cache
                .get_or_load_with::<(), _, _>(
                    &wm,
                    false,
                    "k",
                    Freshness::MaxStaleness(10 * SEC),
                    || async { Ok(n) },
                )
                .await;
        }
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.bytes(), entry_size::<u32>("k", 0));
    }

    #[tokio::test]
    async fn an_entry_is_not_served_past_the_ttl() {
        let cache = ProjectionCache::<u32>::new(
            TABLES,
            CacheLimits {
                max_bytes: 10 * entry_size::<u32>("k", 0),
                ttl: Duration::from_millis(30),
                ..CacheLimits::default()
            },
            |_| 0,
        );
        let wm = watermarks(1000, 1);
        let calls = AtomicUsize::new(0);
        let relaxed = Freshness::MaxStaleness(10 * SEC);
        // the counters never change, only the TTL can expire the entry
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(load(&cache, &wm, relaxed, &calls).await, 2);
        assert_eq!(load(&cache, &wm, Freshness::Any, &calls).await, 2);
    }

    #[tokio::test]
    async fn expired_entries_are_dropped_before_live_ones() {
        let cache = ProjectionCache::<u32>::new(
            TABLES,
            CacheLimits {
                max_bytes: 2 * entry_size::<u32>("k", 0),
                ttl: Duration::from_millis(20),
                ..CacheLimits::default()
            },
            |_| 0,
        );
        let wm = watermarks(1000, 1);
        let any = |key| {
            cache.get_or_load_with::<(), _, _>(&wm, false, key, Freshness::Any, || async { Ok(1) })
        };
        let _ = any("a").await;
        let _ = any("b").await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let _ = any("c").await;
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn the_memory_budget_is_split_by_weight() {
        let mut config = Config::default();
        config.database.projection_cache_max_memory_mib = 64;
        let limits: Vec<_> = CacheKind::ALL
            .iter()
            .map(|k| CacheLimits::from_config(&config, *k))
            .collect();
        // user options weigh twice the password expiry
        assert!(limits[0].max_bytes.abs_diff(2 * limits[1].max_bytes) <= 1);
        assert!(limits.iter().map(|l| l.max_bytes).sum::<usize>() <= 64 * 1024 * 1024);
        assert_eq!(limits[0].ttl, Duration::from_secs(300));
        assert_eq!(limits[0].any_ttl_without_poller, Duration::from_secs(60));
        config.database.projection_cache_weight_password_expiry = 0;
        assert_eq!(
            CacheLimits::from_config(&config, CacheKind::PasswordExpiry).max_bytes,
            0
        );
        config.database.projection_cache_max_memory_mib = 0;
        config.database.projection_cache_ttl_ms = 5;
        let off = CacheLimits::from_config(&config, CacheKind::UserOptions);
        assert_eq!(off.max_bytes, 0);
        assert_eq!(off.ttl, Duration::from_millis(5));
    }

    /// The triggers are not installed (no counters while the poller runs):
    /// the loader runs on every read, nothing is stored, nothing fails.
    #[tokio::test]
    async fn test_without_counters_loads_every_time_and_stores_nothing() {
        let wm = TableWatermarks::new();
        wm.configure(Duration::from_millis(100));
        let cache = cache(4);
        let calls = AtomicUsize::new(0);
        for _ in 0..3 {
            let v = cache
                .get_or_load_some_with(&wm, false, "k", Freshness::Any, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(Some(1))
                })
                .await
                .unwrap();
            assert_eq!(Some(1), v);
        }
        assert_eq!(3, calls.load(Ordering::SeqCst));
        assert!(cache.is_empty());
    }

    /// An immutable fact still lives for its TTL without counters.
    #[tokio::test]
    async fn test_immutable_is_served_by_ttl_without_counters() {
        let wm = TableWatermarks::new();
        wm.configure(Duration::from_millis(100));
        let cache = cache(4);
        let calls = AtomicUsize::new(0);
        for _ in 0..3 {
            cache
                .get_or_load_some_immutable(&wm, "k", || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(Some(1))
                })
                .await
                .unwrap();
        }
        assert_eq!(1, calls.load(Ordering::SeqCst));
    }

    /// With the poller off a linearizable read can never hit: nothing is
    /// stored for it.
    #[tokio::test]
    async fn test_disabled_poller_stores_only_tolerant_reads() {
        let wm = TableWatermarks::new();
        let cache = cache(4);
        cache
            .get_or_load_some_with(&wm, false, "lin", Freshness::Linearizable, || async {
                Ok::<_, ()>(Some(1))
            })
            .await
            .unwrap();
        assert!(cache.is_empty());
        cache
            .get_or_load_some_with(&wm, false, "any", Freshness::Any, || async {
                Ok::<_, ()>(Some(1))
            })
            .await
            .unwrap();
        assert!(!cache.is_empty());
    }
}
