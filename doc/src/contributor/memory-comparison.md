# Rust vs Python Keystone comparison

This page compares the Rust Keystone (`keystone-rs`) with the Python Keystone
(`keystone-py`) under the same synthetic load on the same machine. It answers
one question: how much more load does the Rust implementation serve than the
Python one on the same hardware, and what does it cost in memory.

The numbers are a snapshot from one development machine. Each load step ran
once, so differences of a few percent are noise. Treat the figures as relative,
not absolute.

## Summary

One pod of each implementation, both with `limits = 24` CPU on a single-node
k3s host with 16 physical cores (32 threads), the same Postgres, and a
closed-loop virtual-user (VU) load that is stepped up until the 95th percentile
(p95) latency reaches 500 ms.

The Rust figures were measured again after the projection caches, the watermark
tables, the lookup indexes and the audit spool fix (audit on). The Python
figures are from the earlier measurement; Python did not change.

|                                              |            Rust |         Python | Rust advantage |
| -------------------------------------------- | --------------: | -------------: | -------------: |
| VUs at p95 = 500 ms, default mix (3% logins) |     > 1,050 (1) |           ~188 |         > 5.6x |
| Throughput, default mix                      |    ~2,800 req/s |     ~515 req/s |           5.4x |
| VUs at p95 = 500 ms, no password logins      |          ~3,418 |           ~187 |          18.3x |
| Throughput at that point, no password logins |   ~12,200 req/s |     ~475 req/s |          25.7x |
| VUs per CPU core, no password logins         |           142.4 |            7.8 |          18.3x |
| Memory, idle                                 |        ~260 MiB |       ~2.7 GiB |      ~10x less |
| Memory, 600 VUs (average / max)              |   445 / 488 MiB |              - |                |
| Memory, 2,100 VUs (average / max)            |   562 / 756 MiB |              - |                |
| Memory, 3,900 VUs (average / max)            | 640 / 1,018 MiB |              - |                |
| Memory, 50 to 400 VUs (range of averages)    |               - | 2.6 to 2.8 GiB |                |

(1) The default-mix p95 stays at 16 to 22 ms up to 1,050 VUs, the highest step.
The limit is the hashing of the logins, not the latency, see
[Default mix](#default-mix).

What this shows:

- **Capacity.** Without password logins Rust carries about 18x the VUs and about
  26x the throughput of Python at the same p95 limit. With the default mix the
  hashing is the limit and Rust serves about 5.4x the throughput of Python. The
  no-login figures are the better comparison of the implementations, see [Why
  password hashing is
  reduced](#why-password-hashing-is-reduced-for-the-comparison). Python does not
  move between the two mixes (~188 to ~187), which means its limit is not the
  hashing.
- **Memory.** Rust runs in one process and shares everything between async
  tasks. Python pays a full copy of the application for each of its 24 worker
  processes. The Rust figure grows with the load, from about 450 MiB at 600 VUs
  to about 1 GiB at 3,900 VUs, and stays far below Python's 2.7 GiB. The
  projection caches and the allocator keep memory after a run: the pod showed
  about 600 MiB right after the last step.
- **Reliability.** Rust had no failed requests at any step of the sweeps. Python
  returned about 2% HTTP 500 and 502 responses under load.
- **Equal load.** At the same 20 and 50 VUs, Rust answers token validation in
  4.3 and 3.9 ms (p50) and 5.5 and 4.9 ms (p95); Python with its shared cache
  needs 16 to 55 ms and 90 to 159 ms, and 740 to 1,650 ms without the cache. See
  [Equal-load comparison](#equal-load-comparison).
- **Python ceiling.** Python's throughput is flat at about 500 req/s regardless
  of the VU count. It may not be CPU-bound.

## Why password hashing is reduced for the comparison

Password hashing is an external load, not a property of either implementation.
Verifying a password costs a fixed amount of CPU, set by the hashing algorithm
and its cost parameters (the configured work factor), and it deliberately takes
tens of milliseconds. Both servers have to do the same work for every login, and
the cost does not depend on the language, the web framework, the database access
or the caching.

When logins are a noticeable share of the mix, that fixed cost dominates the CPU
budget. In the default mix only 3% of the operations are logins, but each one
costs far more CPU than any other operation (removing them multiplies the
throughput Rust reaches by more than four), so the result of the default mix
mostly measures how many hashes the machine can compute. The other operations
(token validation, reads, role assignment) are what the implementations differ
in, and their differences are hidden behind the hashing.

The comparison therefore reports two views:

- **Default mix (3% logins).** Closer to a deployment where users log in with
  passwords all the time. It shows the result with the hashing cost included.
- **No password logins (`LOADTEST_VU_HASH_PCT=0`).** Isolates the logic and the
  framework: request handling, authorization, database round trips and
  revocation checks. This is the better measure of the performance benefit of
  the implementation, and it is the figure used for the VUs-per-core comparison.

Production deployments also reduce the share of password logins by design:
clients keep a token until it expires instead of a password for each request. A
mix dominated by hashing is not typical of the steady state, so the
reduced-hashing numbers are the more realistic indication of the benefit.

The Rust implementation also bounds the hashing in a separate pool (with the
queue set to `wait` in these runs), so that hashing does not starve the other
requests; the Python implementation hashes in the request worker. This is one
more reason the default mix mixes two effects: the cost of the hash itself and
how each implementation schedules it.

## Method

- Cluster: single-node k3s on an AMD EPYC 7313P (16 cores, 32 threads)
  deployed with skaffold, see [Local development](development.md). Both
  implementations use the same Postgres (CloudNativePG). Keystone, Postgres,
  the load generator and k3s share this one host; `limits = 24` counts
  threads, not physical cores.
- Rust: StatefulSet with one pod, `--release` build, policies evaluated in the
  process by regorus (`[api_policy] engine = regorus`), jemalloc via
  `LD_PRELOAD`, telemetry off, `[database] max_pool_size` as in the skaffold
  setup, password hashing pool queue full behaviour set to `wait` (queue instead
  of answering 503), CPU `requests = 4`, `limits = 24` (the `loadtest` skaffold
  profile; the older sweeps used `requests = limits = 24`), audit logging on.
- Python: Deployment with one pod, uwsgi with 24 single-threaded processes, one
  memcached shared by all workers, CPU `requests = limits = 24`.
- Python threads (`--enable-threads`) were tried earlier and are not
  recommended: a 4-process x 4-thread variant used less memory per pod but
  returned thousands of HTTP 502 responses returned by the wsgi server.
- Load: `tests/loadtest` (Goose 0.19) with `LOADTEST_PROFILE=vu`. Every VU is an
  end user of a tenant of its own, with its own project, role assignments and
  token, so the caches of the server see realistic variety. Operations are
  picked per request according to the mix below.
- Sweep: the VU count is raised step by step (600, 900, 1200, 1500, 1800, 2100,
  2400, 2700, 3300, 3900, 4500, 5100 for Rust without logins; 300 to 1,050 with
  the default mix; much lower for Python), 2 minutes per step, users started at
  100 per second. The sweep stops when p95 exceeds 800 ms. The VU count at
  p95 = 500 ms is interpolated between the two steps that bracket it.
- Between steps the `revocation_event` table is emptied, so every step starts
  with the same revocation check cost. The `password` table held about 4,800
  rows throughout.
- Metric: per-pod working set from `kubectl top`, sampled every 3 seconds during
  the run.

### VU operation mix

The mix is configurable through environment variables. Defaults:

| Variable                     | Default | Operation                                |
| ---------------------------- | ------: | ---------------------------------------- |
| `LOADTEST_VU_VALIDATE_PCT`   |      75 | Validate a token (`GET /v3/auth/tokens`) |
| `LOADTEST_VU_ADMIN_READ_PCT` |      13 | Admin read                               |
| `LOADTEST_VU_HASH_PCT`       |       3 | Password login (hashing)                 |
| `LOADTEST_VU_ASSIGN_PCT`     |       2 | Role assignment                          |
| `LOADTEST_VU_CREATE_PCT`     |     0.2 | Create resources                         |
| `LOADTEST_VU_REVOKE_PCT`     |    0.02 | Revoke a token                           |

The remainder is spread over other reads. "No password logins" means
`LOADTEST_VU_HASH_PCT=0`.

## Rust results

### Default mix

The p95 never reaches 500 ms: it stays at 20 to 22 ms from 300 to 1,050 VUs. The
throughput is flat at about 2,800 req/s from the lowest step. That is the
hashing limit: about 87 logins per second at about 270 ms of CPU each come to
roughly 23 of the 24 cores. The pod was seen using all 24 cores during these
runs (observed, not logged). The bounded hashing pool queues the rest (queue set
to `wait`). A VU waiting for its login does not send other requests, so the
login latency grows with the VU count (p50 of 3.3 s at 300 VUs, 12.1 s at
1,050) while every other request stays fast.
The p99 of all requests is the login queue. There were no failed requests at any
step.

|   VUs | req/s | p50 (ms) | p95 (ms) | p99 (ms) | Login p50 (ms) |
| ----: | ----: | -------: | -------: | -------: | -------------: |
|   300 | 2,780 |      6.8 |       20 |    3,326 |          3,293 |
|   450 | 2,833 |      7.1 |       21 |    5,079 |          5,079 |
|   600 | 2,811 |      7.4 |       21 |    6,849 |          6,849 |
|   750 | 2,826 |      7.5 |       23 |    8,716 |          8,585 |
|   900 | 2,803 |      7.1 |       21 |   10,420 |         10,420 |
| 1,050 | 2,795 |      7.3 |       22 |   12,255 |         12,124 |

The earlier measurement (before the caches and indexes) reached p95 = 500 ms at
about 719 VUs and 1,955 req/s: the other requests were slow because they shared
the CPU with the hashing. They no longer are, so the p95 limit does not describe
the default mix any more. Compare it by throughput and by the login latency.

### No password logins

Throughput and latency per step. There were no failed requests at any step.

|   VUs |  req/s | p50 (ms) | p95 (ms) | p99 (ms) |
| ----: | -----: | -------: | -------: | -------: |
|   600 | 20,486 |       25 |       54 |       73 |
|   900 | 18,924 |       40 |       89 |      120 |
| 1,200 | 15,970 |       66 |      138 |      183 |
| 1,500 | 16,317 |       79 |      173 |      234 |
| 1,800 | 14,732 |      107 |      224 |      305 |
| 2,100 | 13,855 |      134 |      276 |      383 |
| 2,400 | 13,600 |      153 |      330 |      477 |
| 2,700 | 13,624 |      173 |      362 |      537 |
| 3,300 | 12,318 |      239 |      477 |    1,073 |
| 3,900 | 11,814 |      289 |      594 |    1,368 |
| 4,500 | 11,221 |      346 |      709 |    2,089 |
| 5,100 |  9,902 |      453 |      889 |    2,507 |

p95 = 500 ms at about 3,418 VUs (142.4 VUs per core) and about 12,200 req/s.
Throughput falls as VUs grow while the latency rises: extra VUs only queue. The
tail is wide at high load: p99 is 2 to 3 times p95 above 3,300 VUs. It was not
investigated. Throughput of the steps is not monotonic (1,200 to 1,500 VUs
rises), which is the run-to-run noise of one run per step.

#### Why throughput falls as VUs grow

The no-login run uses fewer cores than the pod limit (keystone about 14 to 16 of
24), yet the host is close to its capacity. Measured over 60 s of steady load
(separate runs, so the figures are comparable only roughly):

|                                        | 600 VUs | 3,300 VUs |
| -------------------------------------- | ------: | --------: |
| req/s                                  |  20,455 |    12,089 |
| keystone CPU, cores                    |    16.3 |      14.0 |
| keystone CPU per request (ms)          |    0.80 |      1.16 |
| voluntary context switches per request |     1.5 |       3.5 |
| mean latency, client (ms)              |      29 |       274 |
| mean latency, keystone middleware (ms) |    24.8 |     252.5 |

- The host was 82 to 86% busy (user, system, iowait and softirq, over 32
  threads). With 16 physical cores, both threads of most cores were running, so
  the host was effectively saturated. Besides keystone, Postgres used about 1.4
  cores at 600 VUs and about 5 at 3,300 (separate runs), the load generator 2 to
  3, and the rest is kernel networking and the cluster components.
- CPU per request rose by 46% from 600 to 3,300 VUs. The cause was not
  measured; more runnable tasks sharing the physical cores, worse cache
  locality and the per-connection network work are candidates.
- The wait is inside keystone. The request duration measured by the
  `keystone_http_request_duration_seconds` middleware accounts for about 92% of
  the latency the client sees at 3,300 VUs; the rest is network and the
  generator. A request takes about 250 ms, of which about 1.1 ms is CPU time.
- Postgres was not the limit. 1 to 5 backends were active, nearly all other
  sessions waited for the client (`ClientRead`), there were no lock waits and no
  slow statement. The cgroup was not throttled (`nr_throttled` did not change).
- The on-CPU profile (perf, 30 s at 3,300 VUs) put 59% in the keystone binary,
  22% in the kernel, 7% in jemalloc and 6% in libc. Futex symbols were under
  0.5%. A profile of running threads cannot show time spent blocked, and the
  binary was stripped, so locks inside keystone are not excluded.
- Raising the database pool from 60 to 180 connections at 3,300 VUs gave 13,701
  req/s (one run, against 11,940 to 12,350 in four runs with 60) and a mean
  latency of 240 ms. The pool was a minor limit, not the main one.

### Where the CPU goes

This section is a profile of the build **before** the projection caches, the
watermark tables and the lookup indexes. It was not repeated: the query counts
and the 3.6 ms per request below describe that build. The query counts were not
measured again. The sweep above serves about 3.5x the throughput of the 3,455
req/s measured then.

A request cost about 3.6 ms of CPU without hashing. From the CPU profile under
load:

- Around 12.6% of CPU is in the kernel, mostly socket I/O to Postgres.
- A validate that uses two tokens (one to authenticate, one to validate) issues
  15 database queries with a cold role cache: 4 for the authenticating token and
  11 for the validated one. The database spends 0.005 to 0.4 ms per query and
  about 0.7 ms in total. The queries are round trips, not work.
- For comparison, Python Keystone validating the same token with a cold cache
  (memcached flushed, caller and subject being the same token) issues 36 to 39
  data `SELECT` statements (36 with the catalog, 39 with `nocatalog`, measured
  once each). They run in about 20 transactions, each with a connection
  pre-ping, so Postgres sees about 99 statements (`BEGIN`, `ROLLBACK`,
  `SELECT 1` and the data queries) and the validation takes 70 to 290 ms. Per
  resource it loads the project, its options and tags, the role, its options and
  the implied roles four times each, the assignments three times, the user and
  its options twice, then groups, federation data, endpoint filters and the
  revocation events. With a warm cache the same validation issues no queries at
  all (29 ms); everything comes from memcached. At the time of the profile Rust
  Keystone had no cross-request cache and paid its 15 queries on every request,
  while Python pays 36 to 39 only on a miss. The current build keeps small
  projection caches that the watermark triggers of the tables invalidate on
  every write, so a read never sees a stale row.
  This is why the cache hit rate (64% in the earlier shared-memcached runs,
  where the load creates new keys faster than any cache size keeps them) decides
  how much database work Python does per request.
- The revocation check is one `SELECT EXISTS` over a `UNION ALL` of one branch
  per token dimension (audit id, user, project, domain, role, trust).

Removing latency alone does not raise the ceiling of a CPU-bound server. Fewer
queries per request reduce client and kernel CPU and would, by a few percent.

## Python results

Python reached p95 = 500 ms at about 188 VUs (default mix) and about 187 VUs (no
logins), at about 7.8 VUs per core. Throughput at that point is about 515 req/s
with the default mix and about 475 req/s without password logins; it is the same
within noise because Python does not spend its limit on hashing. About 2% of the
requests failed with HTTP 500 or 502 under load.

No password logins, per step (one run each):

| VUs | Throughput (req/s) | p95 (ms) | p99 (ms) | Failed |
| --: | -----------------: | -------: | -------: | -----: |
| 100 |                517 |      282 |      323 |   2.0% |
| 200 |                471 |      532 |      581 |   1.8% |
| 300 |                460 |      778 |      868 |   2.0% |
| 400 |                434 |    1,064 |    1,343 |   2.0% |

Throughput is flat to slowly falling while the latency grows with the VU count,
as for Rust. Python's memory stays at about 2.7 GiB at every step.

A shared cache is the only valid Python topology, see
[Python cache topology](#python-cache-topology).

## Equal-load comparison

The sweeps above load each side up to its own latency limit, so the VU counts
differ. This run puts the same number of VUs on both sides: 20 and 50 VUs, 2
minutes each, no password logins, one pod per side with `requests = 4` and
`limits = 24` CPU (the `loadtest` skaffold profile). All Python requests go
through the traefik ingress. The Rust figures were measured again on the current
build (in-process regorus, audit on); the load generator reached it through the
cluster IP of the service, not the ingress. The Rust OPA sidecar column and the
Python columns are from the earlier measurement. Values are p50 / p95 / p99 in
ms.

| 20 VUs                               | Rust (regorus) | Rust (OPA sidecar, earlier) | Python (cache) | Python (no cache) |
| ------------------------------------ | -------------: | --------------------------: | -------------: | ----------------: |
| Throughput (req/s)                   |          4,363 |                       1,668 |            668 |                30 |
| Failed requests                      |              0 |                           0 |          1,853 |                13 |
| All requests                         |    4.4/7.1/8.6 |                    12/15/19 |      16/88/109 |       729/851/868 |
| Token validate                       |    4.3/5.5/6.2 |                    13/16/17 |      16/90/103 |       741/856/872 |
| Role assignments, `effective`        |    5.7/7.3/7.9 |                 5.7/8.1/9.4 |      36/71/117 |       362/469/483 |
| Role assignments, `scope.project.id` |    4.1/5.4/6.0 |                 5.0/7.3/8.6 |       18/51/60 |       342/453/457 |
| Memory (MiB)                         |        370-403 |                     150-225 |    2,414-2,668 |       2,306-2,744 |

| 50 VUs                               | Rust (regorus) | Rust (OPA sidecar, earlier) | Python (cache) | Python (no cache) |
| ------------------------------------ | -------------: | --------------------------: | -------------: | ----------------: |
| Throughput (req/s)                   |         11,924 |                       1,960 |            634 |                33 |
| Failed requests                      |              0 |                           0 |          1,633 |                27 |
| All requests                         |    4.0/6.4/7.5 |                    25/33/37 |     56/157/196 | 1,605/1,769/1,818 |
| Token validate                       |    3.9/4.9/5.6 |                    27/34/38 |     55/159/189 | 1,647/1,794/1,843 |
| Role assignments, `effective`        |    5.5/6.6/7.2 |                    15/20/23 |     73/136/167 | 1,253/1,335/1,369 |
| Role assignments, `scope.project.id` |    3.9/4.8/5.3 |                    14/18/21 |     55/118/148 | 1,204/1,319/1,367 |
| Memory (MiB)                         |        383-436 |                     208-241 |    2,683-2,750 |       2,672-2,698 |

- With the shared cache on, Python's median is no longer close to Rust's: token
  validate p50 is 16 vs 4.3 ms at 20 VUs and 55 vs 3.9 ms at 50 VUs. The
  difference in the tail is 16 to 32x at p95 for token validation, and in
  throughput 6.5x at 20 VUs and 18.8x at 50 VUs. Listing role assignments is 4
  to 14x slower at p50 in Python.
- Rust's latency does not grow from 20 to 50 VUs (p50 4.4 to 4.0 ms) while its
  throughput grows 2.7x: the server is far from its ceiling at 50 VUs. Python's
  throughput is about 650 req/s at both load levels, so it is already at its
  ceiling at 20 VUs.
- With the cache off, Python falls to about 30 req/s, 20x lower, and latency
  grows with the VU count: the server is saturated. Memory does not change with
  the cache, so the cache is not what costs Python its memory.
- Almost all Python failures with the cache on are HTTP 502 (1,806 at 20 VUs,
  1,544 at 50 VUs), about 2% of requests. uwsgi `--http-socket` closes the
  connection after every response, and a client that reuses a pooled connection
  fails with `IncompleteMessage` when it talks to uwsgi directly. This is the
  likely source of the 502s behind traefik, but it was not confirmed.
- The earlier Rust runs compared regorus with the OPA sidecar and found no
  difference in the result. That comparison was not repeated on the current
  build. The earlier Rust column differs from the new one by the caches and
  indexes, and also by the route (ingress against the cluster IP), so the two
  are not a like-for-like pair. Rust memory (370 to 436 MiB) is higher than in
  the earlier run (150 to 241 MiB). The causes were not separated; the build
  now has the projection caches and the audit spool, and serves a 2.6 to 6x
  higher request rate.

The Python no-cache column was measured with `OS_CACHE__ENABLED=false` on the
same pod. It is a measurement of the cost of the cache, not a supported
topology.

## Memory

| State                     | Rust (1 pod)    | Python (1 pod, 24 processes) |
| ------------------------- | --------------- | ---------------------------- |
| Idle                      | ~260 MiB (1)    | ~2.7 GiB                     |
| 600 VUs (average / max)   | 445 / 488 MiB   | -                            |
| 2,100 VUs (average / max) | 562 / 756 MiB   | -                            |
| 3,900 VUs (average / max) | 640 / 1,018 MiB | -                            |
| 5,100 VUs (average / max) | 726 / 1,230 MiB | -                            |
| 50 VUs (average / max)    | -               | 2,635 / 2,727 MiB            |
| 200 VUs (average / max)   | -               | 2,762 / 2,768 MiB            |
| 400 VUs (average / max)   | -               | 2,768 / 2,769 MiB            |

The Rust rows are from the no-login sweep of the current build and include the
warm-up of each step. The compiled policies live in the process, which is part
of the footprint.

(1) Idle is the earlier measurement and was not repeated. A pod that had just
finished the sweep showed about 600 MiB, so the allocator and the caches keep
memory after the load.

The Python rows are from the default-mix sweep; the no-login sweep gives the
same values (2.74 to 2.76 GiB at 200 to 400 VUs). The Python loads are lower
because that is where Python reaches its latency limit, so the two sides are not
measured at the same VU count.

Rust memory grows with the number of connections and in-flight requests, not
with the number of workers. Python memory is dominated by the per-process copy
of the application and does not depend on the cache: earlier 15-minute runs with
three pods and 10 processes each measured 1.2 GiB per pod with the cache off,
with a small cache and with a large one.

To deploy `keystone-rs` with a small footprint: set a CPU limit (tokio sizes its
pool from the cgroup quota), keep telemetry sampled or off, and use jemalloc
(tested through `LD_PRELOAD` of the Debian `libjemalloc2`; shipping it would
mean using `tikv-jemallocator` as the global allocator).

## Python cache topology

Python Keystone must use **one cache shared by all pods**. Token validation
relies on the revocation events being visible to every API instance. A memcached
instance per pod gives every pod a private cache: a token revoked through one
pod stays valid in the caches of the others until it expires. That breaks token
revocation, is an anti-pattern, and must not be used in a real deployment. All
Python figures on this page use the shared memcached, except the explicit
no-cache column of the [equal-load comparison](#equal-load-comparison).

## Limitations

- Single run per load step, on one development machine. The load generator runs
  on the same host as both servers and Postgres. The host has 16 physical
  cores and was 82 to 86% busy at 3,300 VUs without logins, so the no-login
  ceiling is partly a property of the test host. A separate generator host
  would likely raise it.
- The load is closed-loop, so request counts depend on latency. The VU count at
  a fixed p95 is the comparison metric, not the raw request count.
- The two sides do not serve identical APIs: the load is restricted to `/v3`
  operations that both implement.
- The Python failures (about 2% HTTP 500 and 502) and its flat ~500 req/s
  ceiling were not investigated deeper other than reproduced in different
  constellations.
- Rust and Python run with telemetry off. The Rust runs have audit logging on.
  The audit spool buffers the critical events and flushes them every 500 ms, so
  a hard crash can lose the last half second of audit records.
- The Rust figures were measured on the current build in one session, one run
  per step; the Python figures were not measured again.
- The mass delete of a tenant with the watermark triggers was not part of the
  load.
- The `password` table held about 4,800 rows. `revocation_event` was emptied
  between the Rust steps. It is not known whether the earlier Python runs did
  the same.
- The earlier sweeps ran with `requests = limits = 24` CPU; the current Rust
  sweeps and the equal-load run used `requests = 4`, `limits = 24` so both
  versions can be deployed at the same time. The limit, which decides the
  throughput ceiling, is the same.

## Reproducing

```bash
cd tests/loadtest
# needs the admin credentials in OS_* variables or OS_CLOUD
LOADTEST_PROFILE=vu \
LOADTEST_VU_HASH_PCT=0 \
cargo run --release -- --host <url> --users 1200 --run-time 2m \
  --report-file reports/<name>.md
```

Raise `--users` step by step, keep each step in its own report, and read the p95
from the report. Sample memory during the run with
`tests/loadtest/sample_metrics.sh`. Redirect the output to a file and do not
pipe the run through `tail`.
