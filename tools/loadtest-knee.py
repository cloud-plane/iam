#!/usr/bin/env python3
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
"""Step the user count of a running load generator and record where time goes.

The load generator (goose) must run with `--no-autostart --users <max>`; this
script drives it through the telnet controller (`users N`, `start`,
`metrics-json`, `shutdown`) and, per step, records

  * requests per second, failures and p95 (all requests and the token
    validation request) from the histogram deltas of the step window,
  * CPU of the server, the load generator and the database (cores of process
    time; the utilisation of the CPU sets also counts the kernel network work
    done for them, so it is higher), the
    busiest threads of the server, and the utilisation of the CPU set of each
    of the three, and
  * database statements (`pg_stat_statements`) and wait events.

`--perf-steps` also records a `perf` profile of the server during the second
half of the named steps.

    tools/loadtest-knee.py OUTDIR --keystone-pid PID --load-pid PID \\
        --steps 100 200 400 800 --hold 60 [--perf-steps 400 800]
"""
import argparse
import collections
import json
import os
import socket
import subprocess
import threading
import time

VALIDATE = "(admin validates)"
HZ = os.sysconf("SC_CLK_TCK")


def parse_cpus(spec):
    cpus = set()
    for part in filter(None, (spec or "").split(",")):
        lo, _, hi = part.partition("-")
        cpus.update(range(int(lo), int(hi or lo) + 1))
    return cpus


class Controller:
    def __init__(self, port):
        for _ in range(300):
            try:
                self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                break
            except OSError:
                time.sleep(2)
        else:
            raise SystemExit("load generator controller not reachable")
        self.sock.settimeout(1.0)

    def cmd(self, line, wait=1.5):
        self.sock.sendall((line + "\n").encode())
        time.sleep(wait)
        data = b""
        try:
            while True:
                chunk = self.sock.recv(1 << 20)
                if not chunk:
                    break
                data += chunk
                if len(chunk) < 1 << 20:
                    time.sleep(0.2)
        except socket.timeout:
            pass
        return data.decode(errors="replace")

    def metrics(self):
        raw = self.cmd("metrics-json", 2)
        try:
            return json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
        except ValueError:
            return {"requests": {}}


def proc_ticks(pid):
    """Total user+system ticks of the process and per thread."""
    total, threads = 0, {}
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            raw = open(f"/proc/{pid}/task/{tid}/stat").read()
        except OSError:
            continue
        name = raw[raw.index("(") + 1:raw.rindex(")")]
        fields = raw[raw.rindex(")") + 2:].split()
        ticks = int(fields[11]) + int(fields[12])
        threads[f"{name}/{tid}"] = ticks
        total += ticks
    return total, threads


def cpu_times():
    """(busy, total) jiffies per CPU from /proc/stat."""
    out = {}
    for line in open("/proc/stat"):
        if line.startswith("cpu") and line[3].isdigit():
            f = line.split()
            vals = [int(x) for x in f[1:]]
            idle = vals[3] + vals[4]
            out[int(f[0][3:])] = (sum(vals) - idle, sum(vals))
    return out


def psql(args, sql):
    return subprocess.run(
        ["docker", "exec", args.postgres, "psql", "-U", "postgres", "-Atc", sql],
        capture_output=True, text=True, timeout=60).stdout


def descendants(root):
    """The pid and every descendant process of it."""
    children = collections.defaultdict(list)
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            raw = open(f"/proc/{pid}/stat").read()
        except OSError:
            continue
        children[int(raw[raw.rindex(")") + 2:].split()[1])].append(int(pid))
    found, todo = [], [root]
    while todo:
        pid = todo.pop()
        found.append(pid)
        todo.extend(children[pid])
    return found


def pg_ticks(root):
    """User+system ticks of the database processes (the container's pid tree)."""
    total = 0
    for pid in descendants(root):
        try:
            f = open(f"/proc/{pid}/stat").read()
            f = f[f.rindex(")") + 2:].split()
            total += int(f[11]) + int(f[12])
        except OSError:
            pass
    return total


def sampler(args, stop, out):
    groups = {"keystone": parse_cpus(args.keystone_cpus), "load": parse_cpus(args.load_cpus),
              "postgres": parse_cpus(args.postgres_cpus)}
    prev_k, prev_kt = proc_ticks(args.keystone_pid)
    prev_l, _ = proc_ticks(args.load_pid)
    pg_root = int(subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Pid}}", args.postgres],
        capture_output=True, text=True).stdout.strip() or 0)
    prev_p = pg_ticks(pg_root)
    prev_c, prev_t = cpu_times(), time.time()
    while not stop.wait(5):
        ts = time.time()
        k, kt = proc_ticks(args.keystone_pid)
        lo, _ = proc_ticks(args.load_pid)
        pg = pg_ticks(pg_root)
        cur = cpu_times()
        dt = ts - prev_t
        util = {}
        for name, cpus in groups.items():
            busy = sum(cur[c][0] - prev_c[c][0] for c in cpus if c in cur)
            tot = sum(cur[c][1] - prev_c[c][1] for c in cpus if c in cur)
            util[name] = round(100 * busy / tot, 1) if tot else None
        hot = sorted(((kt[n] - prev_kt.get(n, 0)) / HZ / dt, n) for n in kt)[-4:]
        act = psql(args, "select coalesce(wait_event_type,'cpu')||':'||coalesce(wait_event,'-'), count(*) "
                         "from pg_stat_activity where state='active' and pid<>pg_backend_pid() "
                         "group by 1 order by 2 desc limit 6")
        out.write(json.dumps({
            "ts": ts, "keystone": (k - prev_k) / HZ / dt, "load": (lo - prev_l) / HZ / dt,
            "postgres": (pg - prev_p) / HZ / dt, "util": util,
            "hot_threads": [[n, round(c, 2)] for c, n in hot], "pg_active": act}) + "\n")
        out.flush()
        prev_k, prev_kt, prev_l, prev_p, prev_c, prev_t = k, kt, lo, pg, cur, ts


def hist_delta(before, after):
    d = collections.Counter()
    for k, v in after.items():
        d[int(k)] += v - before.get(k, 0)
    return d


def p95(hist):
    n, seen = sum(hist.values()), 0
    for k in sorted(hist):
        seen += hist[k]
        if seen >= 0.95 * n:
            return round(k / 1000, 1)
    return None


def window(m0, m1):
    allh, val = collections.Counter(), collections.Counter()
    fails = 0
    codes = collections.Counter()
    for name, r1 in m1["requests"].items():
        r0 = m0["requests"].get(name)
        h = hist_delta(r0["raw_data"]["times_us"] if r0 else {}, r1["raw_data"]["times_us"])
        allh.update(h)
        if VALIDATE in name:
            val.update(h)
        fails += r1["fail_count"] - (r0["fail_count"] if r0 else 0)
        for code, n in r1["status_code_counts"].items():
            if not code.startswith("2"):
                codes[code] += n - (r0["status_code_counts"].get(code, 0) if r0 else 0)
    return sum(allh.values()), fails, p95(allh), p95(val), {c: n for c, n in codes.items() if n}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--steps", type=int, nargs="+", required=True)
    ap.add_argument("--hold", type=int, default=60)
    ap.add_argument("--keystone-pid", type=int, required=True)
    ap.add_argument("--load-pid", type=int, required=True)
    ap.add_argument("--postgres", default="loadtest_postgres")
    ap.add_argument("--keystone-cpus", default="")
    ap.add_argument("--load-cpus", default="")
    ap.add_argument("--postgres-cpus", default="")
    ap.add_argument("--port", type=int, default=5116)
    ap.add_argument("--perf-steps", type=int, nargs="*", default=[])
    ap.add_argument("--perf-seconds", type=int, default=20)
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    ctl = Controller(args.port)
    psql(args, "select pg_stat_statements_reset()")
    stop = threading.Event()
    samples = open(f"{args.outdir}/samples.jsonl", "w")
    threading.Thread(target=sampler, args=(args, stop, samples), daemon=True).start()

    ctl.cmd(f"users {args.steps[0]}")
    ctl.cmd("increaserate 50")
    ctl.cmd("start", 3)
    rows = []
    for users in args.steps:
        ctl.cmd(f"users {users}")
        time.sleep(max(15, users / 50 + 5))
        t0, m0 = time.time(), ctl.metrics()
        perf = None
        if users in args.perf_steps:
            time.sleep(max(0, args.hold - args.perf_seconds))
            perf = subprocess.Popen(
                ["perf", "record", "-F", "99", "-g", "-p", str(args.keystone_pid),
                 "-o", f"{args.outdir}/perf-{users}.data", "--", "sleep", str(args.perf_seconds)],
                stdout=subprocess.DEVNULL, stderr=open(f"{args.outdir}/perf-{users}.log", "w"))
            time.sleep(args.perf_seconds)
            perf.wait()
        else:
            time.sleep(args.hold)
        t1, m1 = time.time(), ctl.metrics()
        n, fails, all95, val95, codes = window(m0, m1)
        mine = [json.loads(line) for line in open(f"{args.outdir}/samples.jsonl")]
        mine = [s for s in mine if t0 <= s["ts"] <= t1]

        def avg(key):
            vals = [s[key] for s in mine if s.get(key) is not None]
            return round(sum(vals) / len(vals), 1) if vals else None

        util = {g: round(sum(s["util"][g] for s in mine if s["util"].get(g) is not None)
                         / max(1, len(mine)), 1) for g in ("keystone", "load", "postgres")}
        threads = collections.defaultdict(float)
        for s in mine:
            for name, c in s["hot_threads"]:
                threads[name.rsplit("/", 1)[0]] = max(threads[name.rsplit("/", 1)[0]], c)
        row = {"users": users, "rps": round(n / (t1 - t0)), "fail_pct": round(100 * fails / max(n, 1), 2),
               "errors": codes, "validate_p95_ms": val95, "all_p95_ms": all95,
               "keystone_cores": avg("keystone"), "load_cores": avg("load"), "postgres_cores": avg("postgres"),
               "util_pct": util, "hottest_thread_cores": max(threads.values(), default=0), "t0": t0, "t1": t1}
        rows.append(row)
        with open(f"{args.outdir}/steps.jsonl", "a") as f:
            f.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)

    top = psql(args, "select calls, round(total_exec_time::numeric), round(mean_exec_time::numeric,2), "
                     "left(regexp_replace(query,'\\s+',' ','g'),110) from pg_stat_statements "
                     "order by total_exec_time desc limit 15")
    open(f"{args.outdir}/top_sql.txt", "w").write(top)
    stop.set()
    ctl.cmd("stop", 3)
    ctl.cmd("shutdown", 2)

    print("\nusers   rps  fail%  val_p95  all_p95  ks_cores load_cores pg_cores  util% ks/load/pg  hottest_thread")
    for r in rows:
        u = r["util_pct"]
        print(f"{r['users']:5d} {r['rps']:6d} {r['fail_pct']:6} {r['validate_p95_ms']!s:>8} {r['all_p95_ms']!s:>8}"
              f" {r['keystone_cores']!s:>9} {r['load_cores']!s:>10} {r['postgres_cores']!s:>8}"
              f"  {u['keystone']}/{u['load']}/{u['postgres']}  {r['hottest_thread_cores']:.2f}")


if __name__ == "__main__":
    main()
