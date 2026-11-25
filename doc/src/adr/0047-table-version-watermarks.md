# 47. Table version watermarks for driver-side caches

**Date:** 2026-11-20

## Status

Proposed

## Reference

Related: ADR 0042 (event delivery and delete cascades), ADR 0045 (evaluation
plane).

## Context

A write made elsewhere (another replica, `keystone-manage`, a co-deployed Python
Keystone, direct SQL) cannot be noticed by a local cache except by asking the
database. A TTL bounds the staleness but costs a reload every few seconds, and a
long TTL does the opposite. The most frequent request, token validation,
otherwise spends several queries on facts that almost never change.

## Decision

Keep one version counter per watched table in a `table_version` table:

```text
table_version(table_name VARCHAR(64) PRIMARY KEY, version BIGINT NOT NULL)
```

Database triggers bump the counter of a table on every `INSERT`, `UPDATE` and
`DELETE`, in the same transaction as the change (a rolled back change leaves no
trace). The tables listed in `INSERT_NEUTRAL_TABLES` (`project`, `local_user`)
have no insert trigger: every cache over them holds rows that exist and never an
absence or a list, so a new row changes no entry, while a busy tenant creating
projects would otherwise drop every cached project on each request. Updates and
deletes still bump. Counters start at the current Unix time in milliseconds so a
reinstalled counter cannot repeat an older stamp. A cache records the combined
counter (the sum of the counters of the tables it depends on, the counters only
grow) before it loads a value and serves the value for as long as the counter is
unchanged.

Two ways to obtain the current counters:

- A background poller (`[database] table_watermark_interval_ms`, default 1000,
  `0` = off) reads the whole table with one query per interval. Readers that
  tolerate staleness validate against this snapshot.
- A **linearizable** reader first calls `TableWatermarks::sync`: one `SELECT` of
  the counter table, shared between concurrent readers (a reader reuses a
  snapshot read after it arrived). If the counters are unchanged since the entry
  was loaded the entry is served; otherwise the driver reads the tables. A token
  validation therefore costs one counter query plus the rows that must always be
  read, instead of one query per cached fact.
- A request may run inside a `ReadScope` (task-local; token validation does).
  Its reads are linearizable as of the scope's point, the request start: a
  snapshot read after that point satisfies every read of the request, so all
  providers share one sync without changing their `Freshness` handling. A write
  moves the point forward (`ReadScope::advance`), so the reads after it sync
  again and see it; `ProjectionCache::invalidate*` does that, and a write to a
  table without such a cache calls `advance` itself. Work spawned onto another
  task has no scope and syncs per read.

| Cache (driver)                                           | Tables                                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------ |
| user options                                             | `user_option`                                                      |
| password expiry                                          | `password`                                                         |
| project domain and parents                               | `project`                                                          |
| project reference (domain, id, name, parent)             | `project`                                                          |
| domain reference (id, name; a domain is a `project` row) | `project`                                                          |
| groups of a user                                         | `group`, `user_group_membership`, `expiring_user_group_membership` |
| role assignments (assignment driver)                     | `assignment`, `system_assignment`                                  |
| role names (role driver)                                 | `role`                                                             |
| resolved role inference (role driver)                    | `role`, `implied_role`                                             |
| assembled catalog (catalog driver)                       | `service`, `endpoint`                                              |
| user record (`user` row)                                 | `user`                                                             |
| revocation check (revoke driver)                         | `revocation_event`                                                 |

### Safety properties

- While the poller is disabled, has not polled yet, is failing (no poll for
  three intervals) or a table has no counter row (triggers not installed), no
  stamp exists and every read goes to the database.
- The stamp is taken _before_ the load. A change committed during the load moves
  the stamp on and costs one extra reload, never a stale hit.
- Local writes invalidate the affected key immediately.
- A poll that started before a connection swap is dropped and a slower poll
  never replaces newer counters.

### Triggers per backend

| Backend    | Triggers per table                                                  |
| ---------- | ------------------------------------------------------------------- |
| PostgreSQL | one `FOR EACH STATEMENT` trigger (insert, update, delete, truncate) |
| MySQL      | three `FOR EACH ROW` triggers (no statement-level triggers)         |
| SQLite     | three `FOR EACH ROW` triggers (no statement-level triggers)         |

The triggers are installed by `table_watermark::install` from the driver
`SqlDriver::setup` (fresh databases, `keystone-manage db sync`) and from a
versioned migration per driver (`keystone-manage db up`). Both are idempotent,
and the migration skips tables that do not exist. `down` drops the triggers and
the counter rows.

## Consequences

- A table has several counter rows (`table`, `table:1` .. `table:7`) and its
  counter is their sum. The PostgreSQL trigger bumps a random row that no other
  transaction has locked (`FOR UPDATE SKIP LOCKED`), so concurrent writers
  neither queue on one row lock nor deadlock when they touch several watched
  tables in a different order; only when every row is locked it waits for the
  base row. MySQL triggers bump a random row (`ELT(FLOOR(RAND() * 8) + 1, ...)`,
  picked once into a variable: in the `WHERE` of the `UPDATE` the
  non-deterministic `RAND()` would be evaluated per row of `table_version`, and
  a write would bump no counter in about a third of the cases); without
  `SKIP LOCKED` two writers can still pick the same row, and a transaction that
  writes several watched tables in a different order than another may wait for
  it, like for any two rows, and two such transactions can deadlock on the
  counter rows (the database aborts one, as for any row-lock deadlock, and the
  write needs a retry). SQLite triggers bump the base row (SQLite serializes
  writers anyway). This is acceptable for the read-mostly tables above; it must
  not be extended to hot write tables (tokens). `revocation_event` is written on
  a revocation only, `user` on a successful authentication (the `last_active_at`
  reset) and on user management.
- The caches work only with the poller on (`table_watermark_interval_ms` > 0,
  the default is 1000). With `0` every read goes to the database, the caches of
  the immutable project facts included. The process-wide TTL caches of earlier
  releases (`[resource] caching`, the catalog and role caches) are gone, and
  `caching`/`cache_time` of a provider now cap the entries of its driver caches.
  On a database without the triggers (`db sync` not run) the poll fails and the
  caches stay unused. The default of `[identity] caching` is now `true`, since
  it gates the identity driver caches.
- The domain and the parents of a project are immutable facts and are not
  validated against the counters. A project deleted by another process or by
  direct SQL is noticed after `projection_cache_ttl_ms` only. This is
  acceptable: the linearizable `project_ref` read does notice the delete, so the
  stale facts only matter to a caller that asks about a project that no longer
  exists.
- A leader of a shared counter read that is cancelled (client disconnect) wakes
  the waiting readers, and one of them reads the counters.
- The poll and the counter sync are bounded (3 s): a hung database makes the
  caches fall back to reading the tables instead of stalling the readers.
- Table granularity: any change of a watched table drops all cached entries that
  depend on it. Facts that never change while the row exists (the domain and the
  parents of a project) are the exception: they are not validated against the
  counters and need no counter sync. Only the age limit and the driver's own
  deletes drop them, so a busy `project` table (projects created and deleted all
  the time) does not make them reload; a project deleted by another process is
  noticed after `projection_cache_ttl_ms` (capped by `[resource] cache_time`).
  Mutable facts, such as a role by ID (its name can change), stay on the
  counters.
- `TRUNCATE` is covered on PostgreSQL only (MySQL does not fire triggers for it,
  SQLite has none).
- MySQL with binary logging needs the `TRIGGER` privilege and, without `SUPER`,
  `log_bin_trust_function_creators=1` to create triggers.
- The poll query runs every interval on every node, regardless of traffic; a
  linearizable read adds at most one counter query per request burst.
- Raft-backed drivers do not use this; their log index is the natural watermark.

## Projection caches and read freshness

Caching in the provider on data the driver already combined from several tables
cannot be validated by a table counter, and the provider cannot know which
tables a driver read. Raft drivers have no tables at all. The SQL drivers
therefore cache **projections** themselves: small, derived, non-secret facts,
each declaring the tables it depends on.

| Projection                | Depends on    | Never cached                                      |
| ------------------------- | ------------- | ------------------------------------------------- |
| user options              | `user_option` | the `user` row (`enabled`, `last_active_at`)      |
| expiry of latest password | `password`    | the password hash                                 |
| local user row            | `local_user`  | missing local users (linearizable reads only)     |
| domain of a project       | none          | missing projects (a stale "not found" is refused) |
| parent IDs of a project   | none          |                                                   |
| project reference         | `project`     | missing projects                                  |
| domain reference          | `project`     | missing domains                                   |

The domain of a project and its parent IDs are **immutable facts**: neither
changes while the project row exists, so their entries are not validated against
a counter at all. They live until the age cap (`projection_cache_ttl_ms`) or the
invalidation of their own key by a delete of the project. A busy tenant writing
other projects therefore never drops them. The price: a project deleted and
recreated with the same ID elsewhere (another replica, a direct SQL statement)
is seen with its old domain and parents for up to the age cap. The same holds
for the domain of a user. The immutable entries never serve a linearizable read
from a counter; the age cap is their only bound. The local user row is read
linearizably only (the name and the authentication counters decide who the user
is and whether it is locked); a failed login rewrites it and drops the cached
local users, and only them.

The reader states how stale the result may be (`Freshness` in `core-types`):
`Linearizable` (the default of every `ExecutionContext`), `MaxStaleness(d)` or
`Any`. The backend traits gain `*_with_freshness` methods whose default ignores
the tolerance and reads through, so a driver without a cache (LDAP, Raft) stays
correct. On MySQL and SQLite `install` replaces the triggers one statement at a
time, so it moves every counter once at the end: a write that committed between
the `DROP` and the `CREATE` bumped nothing and no entry stamped meanwhile may
survive. PostgreSQL installs in one transaction and needs no such bump. The
installation needs the privilege to create triggers (`TRIGGER` on MySQL, plus
`log_bin_trust_function_creators=1` when binary logging is on and the user has
no `SUPER`); it is part of `db sync` and `db up` whatever the poll interval is.

A SQL driver serves a cached projection only when

- the counters of its tables are unchanged since the entry was loaded, **and**
- the counters are recent enough for the tolerance: a tolerance below the poll
  interval cannot be guaranteed by a poller that looks once per interval and is
  a **forced read**, as is a snapshot older than the tolerance (stalled poller),
  and an unhealthy poller or a missing trigger.

Without the poller the age of the entry decides. A read that is not served from
the cache still refreshes it. The driver invalidates its caches on its own
writes (a replica sees its own writes at once), and a load that started before
an invalidation cannot repopulate the cache.

Who relaxes the tolerance is the owner of the endpoint, never a request:
`ExecutionContext::with_freshness` sets it (token validation, from
`[database] projection_max_staleness_ms`, capped at 5 minutes, `0` = off);
`tighten_freshness` is what a client-supplied hint may use. Password expiry is
served stale only on the token validation path. Authentication, password
verification and every write path read the database. This follows ADR 0045:
validation belongs to the evaluation plane (bounded staleness), authentication
to the core plane (linearizable).

Security consequence: an administrator who shortens or forces a password expiry
on one replica is not honoured by token validation on another one for up to the
poll interval plus the tolerance (the same bound as the revocation events of ADR
0045). Extending an expiry fails closed for that long.

Linearizable reads (the default) use the cache after a counter sync, so they
stay linearizable. The groups of a user and the role assignments are cached this
way only (no relaxed tolerance): a grant, a revocation or a membership change is
visible to the next read once the poll or sync has seen the counter. A user with
expiring (federated) memberships is never cached, its groups depend on the
clock. The cached assignments are the rows of the tables; the implied roles and
the role names come from the role provider. The project and domain references
(rebuilt on every token validation to fill the scope) are cached the same way:
their backend methods take no `ExecutionContext`, so they are always
linearizable (one shared counter sync per request through the `ReadScope`) and
every update or delete of a project or domain invalidates them (an insert does
not, see `INSERT_NEUTRAL_TABLES`). The process-wide caches of the resource
provider only store values read linearizably, so a relaxed read cannot leak into
a strict one. Not covered yet: the assignment driver reads the project parents
with an internal context and does not use the project cache.

The **user record** and the **revocation check** are cached linearizably only,
whatever tolerance the reader states: `enabled` and `last_active_at` decide
whether a user may act, and a revocation must be honoured by the next check. The
counter sync is shared by the request through the `ReadScope`, so both cost no
extra query. The revocation answer is keyed by every parameter of the check (the
audit ID makes it per token); a revocation event, a cleanup or any write to
`user` drops the affected entries through the counter. Every successful
authentication writes `user`, so a login-heavy workload lowers the hit ratio of
the user cache, never its correctness.

### Roles and catalog

The role driver caches two facts, both read by every token validation. The names
of the assigned roles are cached per role ID (one query loads all the IDs that
are missing). The **role inference** is stored as a graph of rules; the driver
resolves it into the transitive closure of every role (`RoleInference`) once per
version of the `role` and `implied_role` tables and keeps the shared result, so
a request looks its roles up instead of reading the rule table and walking the
graph. The assignment driver asks the role provider for it
(`get_role_inference`); a backend without a cache gets a default that resolves
it from the rules on every call. The catalog driver keeps the assembled catalog
per `enabled` flag while `service` and `endpoint` are unchanged. All three are
read linearizably (one shared counter sync per request) and are dropped by the
writes of the driver. `[role] caching` and `[catalog] caching` (or a
`cache_time` of `0`) switch them off; the age is bounded by
`projection_cache_ttl_ms`, not by `cache_time`.

### Memory and age

The caches are bounded like `memcached -m`:
`[database] projection_cache_max_memory_mib` (default 64) is the budget of all
projection caches together, split among the caches by the
`projection_cache_weight_*` options (weight `0` disables a cache). Every entry
is charged its approximate size (entry, key and heap of the value); a full cache
drops expired entries first (at most one scan per second), then arbitrary ones,
and an entry larger than the cache's share is not stored.
`projection_cache_ttl_ms` (default 5 minutes) is a hard maximum age whatever the
watermarks and the reader's freshness say, so a missed invalidation (e.g. a
MySQL cascade delete, which fires no triggers) heals itself. `0` for either
option disables the caches.

## Open points

- Column-aware triggers (a watermark that ignores `failed_auth_*` churn) would
  keep the cached local users across failed logins: today every failed login
  drops them (and only them), so a password guessing flood degrades the
  `local_user` cache to a read per request, as before it existed.
- Deleting a project drops every cached project reference: the trigger cannot
  say which row went. A deployment that deletes projects continuously (the load
  test does) reads them again after each delete.
- MySQL does not fire triggers for rows removed by `ON DELETE CASCADE`; the
  projections tolerate it today because the parents (`user`, `project`) are
  always read or part of the set, but it needs a test per backend.

- Enable by default and raise the cache TTLs once the poller has proven itself.
- Extend to further read-mostly tables (domains are rows of `project`, so they
  are already covered; `assignment` would need a per-table review).
- Expose the poller health and the cache hit ratio as metrics.
