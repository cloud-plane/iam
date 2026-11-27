#!/usr/bin/env bash
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#
# Find the knee of a local keystone: step the virtual users of the `vu`
# profile and record throughput, p95 and the CPU of the server, the database
# and the load generator, each pinned to a CPU set of its own so that a
# saturated process is visible. No cluster is involved.
#
#   tools/loadtest-local-knee.sh [OUTDIR]
#
# Variables (defaults in brackets):
#   STEPS            users of the steps [100 200 400 800 1200 1800 2400 3300]
#   HOLD             seconds measured per step [60]
#   PERF_STEPS       steps that also get a `perf` profile of the server []
#   KEYSTONE_CPUS    CPU list of the server [first half of the CPUs]
#   POSTGRES_CPUS    CPU list of the database [next quarter]
#   LOAD_CPUS        CPU list of the load generator [last quarter]
#   LOADTEST_VU_HASH_PCT  share of logins, 0 keeps bcrypt out of the run [0]
#   LOADTEST_PROFILE profile of the load generator [vu]
#
# The server is built with line tables (`LOADTEST_DEBUG_SYMBOLS=1`) so `perf
# report` shows functions and lines. Extra environment variables such as
# `OS_DATABASE__MAX_POOL_SIZE` or `OS_REVOKE__CACHING` reach the server.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-/tmp/loadtest/knee-$(date +%Y%m%d-%H%M%S)}"
STEPS="${STEPS:-100 200 400 800 1200 1800 2400 3300}"
HOLD="${HOLD:-60}"
PERF_STEPS="${PERF_STEPS:-}"
STATE_DIR="/tmp/loadtest/keystone"

NCPU="$(nproc)"
HALF=$((NCPU / 2))
QUARTER=$((NCPU / 4))
KEYSTONE_CPUS="${KEYSTONE_CPUS:-0-$((HALF - 1))}"
POSTGRES_CPUS="${POSTGRES_CPUS:-${HALF}-$((HALF + QUARTER - 1))}"
LOAD_CPUS="${LOAD_CPUS:-$((HALF + QUARTER))-$((NCPU - 1))}"
MAX_USERS="${STEPS##* }"
export LOADTEST_PROFILE="${LOADTEST_PROFILE:-vu}"
export LOADTEST_VU_HASH_PCT="${LOADTEST_VU_HASH_PCT:-0}"

LOAD_PID=""
cleanup() {
  if [ -n "$LOAD_PID" ]; then kill "$LOAD_PID" 2>/dev/null || true; fi
  tools/teardown-loadtest.sh > /dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if [ -n "$PERF_STEPS" ] && [ "$(cat /proc/sys/kernel/perf_event_paranoid)" -gt 1 ]; then
  echo "PERF_STEPS needs: sudo sysctl kernel.perf_event_paranoid=1" >&2
  exit 1
fi

mkdir -p "$OUT"
echo "cpu sets: keystone=$KEYSTONE_CPUS postgres=$POSTGRES_CPUS load=$LOAD_CPUS; output $OUT"
# 3300 users hold thousands of sockets open on one host.
ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)"

LOADTEST_SETUP_ONLY=1 LOADTEST_DEBUG_SYMBOLS=1 KEYSTONE_VERBOSITY= KEYSTONE_DEBUG=false \
LOADTEST_KEYSTONE_CPUS="$KEYSTONE_CPUS" LOADTEST_PG_CPUS="$POSTGRES_CPUS" \
OS_DATABASE__MAX_POOL_SIZE="${OS_DATABASE__MAX_POOL_SIZE:-60}" \
  tools/run-loadtest-local.sh

(cd tests/loadtest && cargo build --release)

# A fresh HOME: the SDK caches tokens of an earlier admin user per cloud.
LOAD_HOME="${STATE_DIR}/home"
mkdir -p "$LOAD_HOME"
(
  cd tests/loadtest
  HOME="$LOAD_HOME" OS_AUTH_URL="http://localhost:8080/v3" OS_USERNAME=admin \
  OS_PASSWORD=password OS_USER_DOMAIN_NAME=default OS_PROJECT_NAME=admin \
  OS_PROJECT_DOMAIN_NAME=default \
  exec taskset -c "$LOAD_CPUS" ./target/release/load_test --host http://localhost:8080 \
    --users "$MAX_USERS" --no-autostart --no-print-metrics \
    --report-file "$OUT/report.json" --report-file "$OUT/report.html"
) > "$OUT/load.log" 2>&1 &
LOAD_PID=$!

PERF_ARGS=()
if [ -n "$PERF_STEPS" ]; then PERF_ARGS=(--perf-steps $PERF_STEPS); fi
python3 -I tools/loadtest-knee.py "$OUT" \
  --keystone-pid "$(cat "${STATE_DIR}/keystone.pid")" --load-pid "$LOAD_PID" \
  --keystone-cpus "$KEYSTONE_CPUS" --postgres-cpus "$POSTGRES_CPUS" --load-cpus "$LOAD_CPUS" \
  --steps $STEPS --hold "$HOLD" "${PERF_ARGS[@]}" | tee "$OUT/knee.log"

echo "results in $OUT (steps.jsonl, samples.jsonl, top_sql.txt, perf-*.data, report.html)"
