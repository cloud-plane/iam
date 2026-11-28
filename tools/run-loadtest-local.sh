#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/tmp/loadtest/keystone"
CONFIG_FILE="${STATE_DIR}/etc/keystone.conf"
REAL_HOME="$HOME"
DATABASE_URL="postgres://postgres:password@127.0.0.1:15432/postgres"
SPIRE_SOCKET="/tmp/spire-ci-test-harness/agent.sock"
SPIFFE_ENDPOINT_SOCKET="unix:///${SPIRE_SOCKET}"
KEYSTONE_PID=""

cleanup() {
  echo "Tearing down loadtest environment..." >&2
  if [ -n "$KEYSTONE_PID" ]; then kill "$KEYSTONE_PID" 2>/dev/null || true; fi
  pkill -f "opa run -s .* --addr unix://${STATE_DIR}/opa.sock" 2>/dev/null || true
}
trap cleanup ERR INT TERM

tools/teardown-loadtest.sh || true
rm -rf "$STATE_DIR"
mkdir -p "${STATE_DIR}/etc/fernet-keys"

# openstack_sdk caches auth tokens per cloud-config hash under
# $HOME/.osc, surviving across server restarts. Since we bootstrap a
# brand new admin user/token every run, a stale cache entry would make the
# SDK replay a token for a user id that no longer exists in the fresh DB
# (500s downstream). Point load_test at an isolated HOME (reset alongside
# the rest of STATE_DIR above) instead of touching the real ~/.osc.
LOADTEST_HOME="${STATE_DIR}/home"
mkdir -p "$LOADTEST_HOME"

tools/start-spire.sh

# The database gets the settings of the k3s deployment plus
# `pg_stat_statements`. LOADTEST_PG_CPUS pins it, see below.
docker run -d --name loadtest_postgres \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password \
    -p 15432:5432 mirror.gcr.io/library/postgres:18-alpine \
    -c max_connections=200 -c shared_buffers=128MB \
    -c shared_preload_libraries=pg_stat_statements

for i in {1..30}; do
    if docker exec loadtest_postgres pg_isready -U postgres > /dev/null 2>&1; then
        echo "✅ Postgres is ready!"
        break
    fi
    sleep 1
done

# LOADTEST_PG_CPUS (`0-7`, `8,9`) pins the database so that the processes of a
# run do not compete for the same cores. `--cpuset-cpus` is not available to
# rootless podman, so the processes of the container are pinned from outside;
# the backends of later connections inherit the set from the postmaster.
if [ -n "${LOADTEST_PG_CPUS:-}" ]; then
  PG_PID="$(docker inspect -f '{{.State.Pid}}' loadtest_postgres)"
  for pid in $PG_PID $(pgrep -P "$PG_PID" || true); do
    taskset -a -cp "$LOADTEST_PG_CPUS" "$pid" > /dev/null \
      || echo "could not pin postgres process $pid to $LOADTEST_PG_CPUS" >&2
  done
fi

cat <<EOF > "$CONFIG_FILE"
[api_policy]
opa_base_url = unix://${STATE_DIR}/opa.sock
opa_policies_path = policy

# The load generator sends every request from 127.0.0.1.
[rate_limit_global_ip]
enabled = false

[rate_limit_user_auth]
enabled = false

[auth]
methods = password,token,openid,application_credential,x509

[DEFAULT]
debug = ${KEYSTONE_DEBUG:-true}
use_stderr = false
log_dir = ${STATE_DIR}

# Dev/test only: derive the OAuth2 issuer from the Host header instead of
# pinning [DEFAULT] public_endpoint (OAuth2 OP endpoints 503 without one).
[oauth2]
allow_host_header_issuer = true

[database]
connection = ${DATABASE_URL}

[fernet_receipts]
key_repository = ${STATE_DIR}/etc/fernet-keys
[fernet_tokens]
key_repository = ${STATE_DIR}/etc/fernet-keys

[interface_admin]
socket_path = ${STATE_DIR}/keystone.sock
trust_domains = example.org
admin_svid = spiffe://example.org/keystone

[audit]
spool_dir = ${STATE_DIR}/audit
node_id = loadtest-node
EOF

echo "2Rlc-npWYOGqqG1zM-bmfBj2apLacLXhIbBsdyqQ0zg=" > "${STATE_DIR}/etc/fernet-keys/0"

# LOADTEST_DEBUG_SYMBOLS=1 keeps line tables in the release binaries so that
# `perf` and flamegraphs show function names and lines (the profile strips
# symbols otherwise; the code generated stays the same).
if [ -n "${LOADTEST_DEBUG_SYMBOLS:-}" ]; then
  export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only CARGO_PROFILE_RELEASE_STRIP=false
fi
cargo build --release --bins

./target/release/keystone-manage -c "$CONFIG_FILE" db sync
./target/release/keystone-manage -c "$CONFIG_FILE" db up

# LOADTEST_KEYSTONE_CPUS pins the server (`taskset` list), KEYSTONE_VERBOSITY
# replaces the default `-vv` (empty: warnings only, what a capacity run wants).
KEYSTONE_TASKSET=()
if [ -n "${LOADTEST_KEYSTONE_CPUS:-}" ]; then KEYSTONE_TASKSET=(taskset -c "$LOADTEST_KEYSTONE_CPUS"); fi
KEYSTONE_DEV_KEK=4242424242424242424242424242424242424242424242424242424242424242 \
KEYSTONE_ALLOW_ENV_KEK=1 \
SPIFFE_ENDPOINT_SOCKET=$SPIFFE_ENDPOINT_SOCKET \
"${KEYSTONE_TASKSET[@]}" ./target/release/keystone -c "$CONFIG_FILE" ${KEYSTONE_VERBOSITY--vv} > "${STATE_DIR}/rust.log" 2>&1 &
KEYSTONE_PID=$!
echo "$KEYSTONE_PID" > "${STATE_DIR}/keystone.pid"

URL_METRICS="http://127.0.0.1:8099"
for i in {1..30}; do
    if curl -s "${URL_METRICS}/health" > /dev/null; then
        echo "✅ Keystone health url started responding!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "Server failed to start." >&2
        cat "${STATE_DIR}/rust.log" >&2
        exit 1
    fi
    sleep 0.5
done

until [ -S "${STATE_DIR}/keystone.sock" ]; do
    sleep 0.5
done
echo "✅ Keystone admin socket appeared!"

KEYSTONE_DEV_KEK=4242424242424242424242424242424242424242424242424242424242424242 \
KEYSTONE_ALLOW_ENV_KEK=1 \
SPIFFE_ENDPOINT_SOCKET=$SPIFFE_ENDPOINT_SOCKET \
./target/release/keystone-manage -c "$CONFIG_FILE" bootstrap --bootstrap-password password

echo "✅ Keystone bootstrap completed!"

docker exec loadtest_postgres psql -U postgres -c \
    "CREATE EXTENSION IF NOT EXISTS pg_stat_statements" > /dev/null

# tools/loadtest-local-knee.sh starts the load generator itself.
if [ -n "${LOADTEST_SETUP_ONLY:-}" ]; then exit 0; fi

(cd tests/loadtest && cargo build --release)

mkdir -p tests/loadtest/reports
(cd tests/loadtest && \
    HOME="$LOADTEST_HOME" \
    OS_AUTH_URL="http://localhost:8080/v3" \
    OS_USERNAME=admin \
    OS_PASSWORD=password \
    OS_USER_DOMAIN_NAME=default \
    OS_PROJECT_NAME=admin \
    OS_PROJECT_DOMAIN_NAME=default \
    ./target/release/load_test \
    --host http://localhost:8080 \
    "$@")
