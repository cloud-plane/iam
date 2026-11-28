# Load tests

`tests/loadtest` is a [Goose](https://book.goose.rs/) load generator. It drives
a running keystone over HTTP, so the same binary measures a local process, the
skaffold k3s deployment, or the Python keystone.

Use it to compare a change against a baseline, to find the saturation point of a
deployment and to watch memory. For single functions or the request middleware
use the criterion benches instead (`cargo bench -p <crate>`); a load test only
tells you that something got slower, not where.

## Where to run

| Target          | When                              | How                           |
| --------------- | --------------------------------- | ----------------------------- |
| Local processes | quick check, no cluster needed    | `tools/run-loadtest-local.sh` |
| skaffold k3s    | numbers to compare, rs against py | see [k3s](#k3s-deployment)    |

`tests/loadtest` is excluded from the main workspace. Build it from its own
directory, never with `cargo build -p load_test` from the repository root:

```console
cd tests/loadtest
cargo build --release
```

## Local run

```console
tools/run-loadtest-local.sh --users 20 --increase-rate 4 --run-time 30s \
  --report-file reports/run.md
```

The script starts Postgres (docker; on a podman-only host alias `docker` to
`podman`, and use fully-qualified image references such as
`docker.io/postgres:17`, an unqualified name does not resolve without configured
search registries), SPIRE and a keystone with the embedded policy engine,
bootstraps the admin user, seeds data, builds the load generator and runs it
against `http://localhost:8080`. Extra arguments go to `load_test`.
`tools/teardown-loadtest.sh` stops everything, and the script calls it itself at
the start of each run.

Against a fresh Postgres run `keystone-manage db sync` before
`keystone-manage db up`: `up` alone only applies the versioned migrations of the
drivers that ship them (credential, federation, k8s-auth, token-restriction,
webauthn), while identity, role, assignment, resource and catalog create their
schema through `sync`. The script does both.

It points `load_test` at an isolated `$HOME`. `openstack_sdk` caches tokens
under `$HOME/.osc`, and every local run bootstraps a new admin user, so a stale
cache entry makes the SDK replay a token of a user that no longer exists and
shows up as random 401 and 500 answers. If you start the load generator some
other way and see `user cannot be found`, check `~/.osc` first.

### Finding the knee locally

`tools/loadtest-local-knee.sh [OUTDIR]` runs the local setup without a cluster
and steps the virtual users of the `vu` profile (`STEPS`, default 100 to 3300,
`HOLD` seconds each). The server, the database and the load generator are
pinned to separate CPU sets (`KEYSTONE_CPUS`, `POSTGRES_CPUS`, `LOAD_CPUS`;
default half, quarter and quarter of the CPUs), so the process that saturates
is visible. Per step it prints requests per second, failures, p95 of all
requests and of the token validation, CPU of the three processes, the
utilisation of their CPU sets and the busiest server thread; `top_sql.txt`
holds the statements of the whole run. Logins are off (`LOADTEST_VU_HASH_PCT=0`).

The server is built with line tables (`LOADTEST_DEBUG_SYMBOLS=1` of
`tools/run-loadtest-local.sh`), so `PERF_STEPS="400 3300"` also records a
`perf` profile of the server during each of those steps (needs
`sudo sysctl kernel.perf_event_paranoid=1`). Compare the two profiles with
`perf report -i OUTDIR/perf-3300.data --no-children`. Reading the result:
a set of the server near 100% means it is CPU bound; one thread near one core
points at a serialised section; a low server CPU with growing latency means
waiting (database pool, locks, the load generator's own set).

## k3s deployment

### Deploy

Use the `loadtest` skaffold profile. It is the one the rs against py comparison
in [Rust vs Python comparison](memory-comparison.md) uses: one pod of each
implementation, `requests = 4` and `limits = 24` CPU, jemalloc, no WASM auth
plugins (their invocation limits answer 429 to application credential logins)
and the tracing exporter off.

```console
skaffold run -m keystone --cleanup=false -p local,loadtest \
  --default-repo localhost:5000
```

Profiles replace the single kustomize path, so `local,otel` or `local,soak`
select a different overlay and do not combine with `loadtest`.

Without `loadtest` the default overlay runs two `keystone-rs` and two
`keystone-py` pods without resource settings. Numbers from it are not comparable
with the documented ones. Do not scale the StatefulSet down by hand to get one
pod, see [Raft state after a scale change](#raft-state-after-a-scale-change).

Check that the pod is ready and runs the image you expect:

```console
kubectl get pods
kubectl get sts keystone-rs \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

### Raft state after a scale change

`keystone-rs` is a StatefulSet with a Raft volume (`raft-storage-keystone-rs-N`)
per pod. Every pod remembers the membership it last ran with. After a run with
two replicas, a single pod keeps asking the missing second node for votes
(`Unreachable node ... failed to lookup address information`), never becomes
ready, and the rollout of the new revision never starts.

To go back to one node, delete the volumes and the pod. This removes everything
that lives in Raft (API keys, OAuth2 clients, SCIM realms); the Postgres data
stays:

```console
kubectl delete pvc raft-storage-keystone-rs-0 raft-storage-keystone-rs-1 --wait=false
kubectl delete pod keystone-rs-0
```

The StatefulSet creates a fresh volume and the pod bootstraps as a single node.
Redeploying with the `loadtest` profile in the first place avoids the problem.

### Credentials and access

The deployment is bootstrapped with the development admin user `admin` (password
`password`) in the domain `default` and the project `admin`, the same as in the
OpenStackClient example of `CONTRIBUTING.md`. Give `load_test` the credentials
with `OS_*` variables (or `OS_CLOUD` with an entry of `clouds.yaml`):

```console
export OS_AUTH_URL=http://localhost:8080
export OS_USERNAME=admin OS_PASSWORD=password
export OS_USER_DOMAIN_NAME=Default OS_PROJECT_DOMAIN_NAME=Default
export OS_PROJECT_NAME=admin
```

`load_test` prefers the `OS_*` variables whenever `OS_AUTH_URL` is set. These
are throwaway development credentials: for any other deployment keep the
password out of committed files and shared reports.

Expose the service on the host, or use the ingress name `keystone-rs.local`
(needs an `/etc/hosts` entry):

```console
kubectl port-forward svc/keystone-rs 8080:8080
```

A port-forward carries every request of the run through `kubectl`. For high
request rates use the ingress name or run the load generator inside the cluster,
otherwise the forward is what you measure.

## Profiles

`LOADTEST_PROFILE` selects the scenario mix:

| Profile        | Mix                                                                                    |
| -------------- | -------------------------------------------------------------------------------------- |
| unset (stress) | Every scenario, flat out. Password hashing and resource churn dominate.                |
| `realistic`    | Reads and token validation weigh most, hashing scenarios wait 2 to 4 s.                |
| `vu`           | Every virtual user is an end user of a tenant of its own. Use it for capacity numbers. |

`LOADTEST_THINK_MS=<ms>` adds a think time (0.5x to 1.5x of the value) between
the transactions of the read scenarios. `LOADTEST_V3_ONLY=1` leaves out the
`/v4` and SCIM scenarios so the mix can run against the Python keystone.

### The `vu` profile

Before the measurement a domain is created per ten virtual users, each virtual
user gets a user, two projects, a group, a role and an application credential.
During the run it only acts as that user, so the caches of the server see
realistic variety. Operations are picked per request. The shares are set with
variables:

| Variable                     | Default | Operation                                                             |
| ---------------------------- | ------: | --------------------------------------------------------------------- |
| `LOADTEST_VU_VALIDATE_PCT`   |      75 | The admin validates a token of the user (`GET /v3/auth/tokens`)       |
| `LOADTEST_VU_ADMIN_READ_PCT` |      13 | Administrative reads (project, user, group, role, assignments, lists) |
| `LOADTEST_VU_HASH_PCT`       |       3 | Logins: password and application credential 2:1, both hash a password |
| `LOADTEST_VU_ASSIGN_PCT`     |       2 | Role assignment writes and checks                                     |
| `LOADTEST_VU_CREATE_PCT`     |     0.2 | Create a project or a role                                            |
| `LOADTEST_VU_REVOKE_PCT`     |    0.02 | Deletions, which add revocation records                               |
| `LOADTEST_VU_REVOKE_OP`      |     all | `0..4` restricts the deletions to one operation                       |

The rest is split between rescope, `GET /v3/auth/projects` and the application
credential list. Every non 2xx response counts as a failure in the report.

Logins hash a password on the server (about 270 ms of CPU each with bcrypt) and
dominate the CPU use of a run. To measure everything else, switch them off:

```console
LOADTEST_PROFILE=vu LOADTEST_VU_HASH_PCT=0 \
cargo run --release -- --host http://localhost:8080 \
  --users 1200 --run-time 2m --report-file reports/vu-1200-nohash.md
```

Other variables: `LOADTEST_NO_KEEPALIVE=1` sends `Connection: close` with every
request, for servers that drop the connection after each response (uwsgi behind
`--http-socket`). `LOADTEST_ADMIN_USERNAME`, `LOADTEST_ADMIN_PASSWORD` and
`LOADTEST_ADMIN_DOMAIN` set the admin identity of the system scope scenario when
it differs from `OS_*` (default `admin`, `password`, `default`).
`LOADTEST_SUMMARY_FILE` writes the totals as JSON for the soak controller.

## Reading a run

Keep each run in its own report file under `reports/`. A sweep raises `--users`
step by step (600, 900, 1200, 1500, ...), two minutes per step, and stops when
the p95 passes 800 ms. The VU count at p95 = 500 ms is interpolated between the
two steps around it. Look at:

- the failure rate first: a run with failures is not a throughput number,
- p95 and the request rate of the validation request (`GET /v3/auth/tokens`),
- the pod CPU against its limit: the request rate flattens when the 24 CPU limit
  is reached, and
- working set memory, sampled during the run.

Sample the pods in the background around the run:

```console
tests/loadtest/sample_metrics.sh /tmp/metrics.log 3 &
SAMPLER=$!
# ... run load_test ...
kill "$SAMPLER"
```

It needs a working `kubectl top`. See the header of the script for the output
format and an `awk` one-liner for the per-pod minimum, maximum and average.

`tools/compare-memory.sh` runs rs and py one after the other (or together),
samples memory and CPU and writes the reports. `--ramp-time` starts the users
evenly over a time and writes the Goose graph data, and `tools/ramp-knee.py`
turns it into requests per second against the user count to show where a target
saturates. Both are described at the top of the scripts.

## Comparing two builds

Change one thing between two runs and keep the rest: the same profile, user
count, run time, deployment profile and, for the `vu` profile, the same
`LOADTEST_VU_*` values. Run the baseline and the change back to back, on a quiet
machine. The run itself adds noise, so repeat a run that looks like a win or a
loss of a few percent before you believe it.

The database accumulates rows (`password`, revocation records, assignments)
across runs. Compare runs that started from a similar state, or note the sizes.

## Pitfalls

- **Never pipe the run through `tail`.** Daemons started by the scripts inherit
  the write end of the pipe, so the pipe never closes and the command looks
  hung. Redirect to a file, run it in the background and read the file:

  ```console
  nohup tools/run-loadtest-local.sh ... > /tmp/out.log 2>&1 &
  ```

- A negative test (wrong password, rescope to a missing project) has to call
  `user.set_success(&mut goose.request)` once it has confirmed the expected
  rejection. Goose counts every non 2xx response as an error otherwise and the
  failure rate looks higher than it is.
- The load generator is a client with a CPU and memory budget of its own. Watch
  it (`LOAD_MEM_MAX` of `compare-memory.sh` caps it) so that it is not the
  bottleneck of a 1200 user run.
- A stale `$HOME/.osc` token cache makes runs against a fresh bootstrap fail
  with `user cannot be found`.
- An overloaded server answers the login with 5xx. The load generator retries
  five times and then counts the following requests as failures instead of
  stopping.
