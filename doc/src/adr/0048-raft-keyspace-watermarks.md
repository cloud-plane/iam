# 48. Raft keyspace watermarks for linearizable reads

**Date:** 2026-11-25

## Status

Proposed (design exploration; nothing is implemented).

## Reference

Related: ADR 0016-v2 (Raft storage, read tiers, invariant 4), ADR 0045 (global
IAM mesh, bounded staleness), ADR 0047 (table version watermarks for SQL
drivers), `doc/src/contributor/security-model.md`.

## Context

ADR 0047 gives the SQL drivers a per-table version counter so a cache, or a
reader, can tell whether the data it holds is still current without reading it.
It states that Raft-backed drivers do not use it because "their log index is the
natural watermark". That sentence is true of the global log index only. A
Raft read today cannot use it per table:

- **Every linearizable read is served by the leader.** `Storage::route_read`
  calls `raft.ensure_linearizable(ReadPolicy::ReadIndex)`. On a follower that
  returns `ForwardToLeader`, and the whole read (request and response, up to
  Tier 3 plaintext) is forwarded to the leader. Followers add no read capacity
  for anything but `ReadConsistency::Local`.
- **The only local-read path is not linearizable.** `ReadConsistency::Local` is
  honoured only with `local_reads_mode = local_for_public`, for Tier 0/1
  records, and when `within_max_staleness()` holds. That check is node-wide:
  `last_applied` against `local_committed` plus the age of the last leader
  contact. It says nothing about the keyspace being read, so a node that is one
  entry behind on an unrelated keyspace is treated as stale for all of them.
- **No keyspace-level progress is recorded.** The state machine persists the
  global `last_applied_log`. `Metadata` is per key and carries no log index.
- **A ReadIndex read has two costs.** The leadership confirmation is a quorum
  round trip. The apply wait (`applied >= read_index`) is the time the local
  state machine needs to catch up with entries that are already committed. The
  second cost is paid on entries the read does not care about.

The goal is a table of watermarks, like ADR 0047's `table_version`, that lets a
replica decide whether its local copy of a keyspace is current for a given read,
without waiting for unrelated entries and without forwarding the read.

## Decision

Keep two watermarks per keyspace. Both are log indexes. They answer different
questions and live in different places.

| Watermark                | Meaning                                                                                           | Where                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **Applied** `A[K]`       | Index of the last **applied** entry that touched keyspace `K`.                                    | Every node, in `meta` under `_wm:<keyspace>`, persisted.               |
| **Committed** `W[K](R)`  | Index of the latest entry at or below read index `R` that touches `K`, applied or not.            | The leader, in memory, updated when an entry is proposed or appended.  |

`A[K]` is deterministic: every node derives it from the same log, so two nodes
that have applied the same index hold the same table. `W[K]` is the cluster's
answer to "how far must a replica have applied to be current for `K`?".

### Read protocol

A linearizable read of keyspace set `S` (one keyspace for `get_by_key`, the
union of those touched for `prefix_index` and for tier lookups through `meta`):

1. The reader asks the leader for `(R, W[S])`. The leader runs ReadIndex
   (leadership confirmed by a quorum), then returns `R` and
   `W[S] = max over K in S of W[K](R)`.
2. The reader compares with its own table. It may read locally when
   `max over K in S of A[K] >= W[S]` **and** its `last_applied >= W[S]`.
   Then no entry at or below `R` that touches `S` is unapplied here, even if the
   global `last_applied < R`. This is the skip.
3. Otherwise it waits until `last_applied >= W[S]` (not `R`), bounded by the
   existing retry budget, or forwards the read to the leader as today.

The leader uses the same rule against its own `A`. The apply wait it skips is
usually short, so the gain is on followers.

What is **not** skipped: the leadership confirmation in step 1. Without it a
partitioned old leader could answer with a stale `W[K]`. Removing the round
trip needs a leader lease (`ReadPolicy::LeaseRead`), which adds a clock-skew
assumption. That is a separate decision and out of scope here. ADR 0016-v2
invariant 4 (no stale reads of Tier 2/3 data) stays unchanged.

### Maintaining `A[K]`

`apply()` in `state_machine.rs` is the single choke point. In the same fjall
batch that advances `last_applied_log`, it writes `A[K] = log index` for every
keyspace the entry mutates:

- put, delete and batch commands, including a batch spanning several keyspaces
  (each is bumped);
- `drop_keyspace` (the row for `K` is bumped, then removed with the keyspace);
- writes to ephemeral (in-memory) keyspaces, which are rebuilt from the log on
  restart: their `A[K]` is held in memory and is `last_applied` after a
  restart;
- writes to `meta`. A tier lookup reads `meta` and the data keyspace, so a read
  includes both in `S`;
- snapshot install sets `A[K] = snapshot.last_applied` for every keyspace.

Writing the table in the same batch as `last_applied_log` makes a crash leave
both or neither, so `A[K]` can never be ahead of the data.

### Maintaining `W[K]` on the leader

The log index of an entry is only known once it is appended, so the map is
filled by the log store's `append`, on every node, not on the propose path.
`last_logged[K]` is the index of the latest appended entry that touches `K`.
It is recorded before the append callback fires, so no entry can commit
without its keyspaces being in the map.

A read at index `R` uses
`W[K](R) = min(R, max(A_leader[K], last_logged[K]))`. `A_leader[K]` stands for
every entry the leader already applied, which the log scan below does not
cover. Entries beyond `R` make the bound larger than the true value up to `R`,
never smaller, so the error is extra waiting, not staleness. A truncated
entry is never removed from the map, for the same reason.

On start the log store scans the retained log after `last_applied` and fills
the map before the node serves reads. A node that becomes leader already holds
the map, because every node appends. `R` is always a safe answer, which is
today's behaviour.

### Wire

A new unary `StorageService` RPC, `ReadWatermark`, runs the leader's ReadIndex
and returns `R` with `(keyspace, W)` pairs. The request carries a keyspace
filter; an empty filter means all keyspaces, and that is the default. It
replaces forwarding the read when the follower can serve it locally. The
existing forwarding path stays as the fallback.

It is unary, not a stream, for these reasons:

- The quorum round trip dominates the cost and is paid once per call. One call
  for all keyspaces replaces the one-per-keyspace calls of a request that reads
  about a dozen (token validation).
- All keyspaces of a request are judged against one `R`. Separate calls could
  return different read indexes and lose the consistent view.
- The response is small: the keyspace count is bounded and each entry is a name
  and a `u64`. Nothing arrives incrementally.
- A leader-to-follower push of `W` is rejected. A pushed `W` can be stale, and
  skipping the ReadIndex on it would break invariant 4 for Tier 2/3 data.

The client keeps the response for the request (the equivalent of ADR 0047's
`ReadScope`) and reuses it for every read in it. A write of the request moves
the point forward, so the reads after it call `ReadWatermark` again and see the
write. The keyspace filter is an optimization for callers that touch one
keyspace.

## Consequences

- **Followers can serve linearizable reads** for keyspaces that did not change
  recently, for any tier. The cost is one small RPC to the leader instead of
  the full read and response, and the plaintext of Tier 2/3 records never
  crosses the network for a read the follower can serve.
- **The leadership round trip stays.** The saving is the apply wait and the
  forwarded payload, not a quorum round. A hot keyspace (frequent writes) gains
  little, because `W[K]` is close to `R`.
- **Correctness depends on completeness of the update path.** If a command
  mutates a keyspace without bumping `A[K]` or `last_proposed[K]`, a replica
  can serve a stale linearizable read of Tier 2/3 data. The single choke point
  in `apply()`, and a test that enumerates every `StoreCommand` variant and
  asserts each one touches the watermark, are required, not optional. This is a
  security-model concern; the reviewer checklist in `security-model.md`
  applies.
- **Torn reads stay possible** unless the read holds a consistent view:
  `local_get` reads `meta` and data separately and may race a concurrent apply
  (it already notes this). A local linearizable read must check `A[S]` before
  and after the read, and retry or forward if it moved.
- **Cost of the table.** One extra small write per applied entry (a row per
  touched keyspace), in the batch that already exists. The in-memory leader map
  is bounded by the number of keyspaces.
- **Rolling upgrade.** An old node has no `_wm:` rows. A node treats a missing
  `A[K]` as `0`, which never satisfies `A[K] >= W[S]` for `W > 0`, so it falls
  back to waiting or forwarding. The rows live in `meta` under
  `_wm:`, which has no NUL byte and so cannot collide with a record's
  `<keyspace>\0<key>` metadata key. Leaders that do not serve
  `ReadWatermark` make the follower forward as today.
- **Relation to ADR 0047.** Both answer "is my copy current?" with a monotone
  counter per unit of data. The SQL counters are bumped by triggers and polled;
  these are derived from the Raft log and need no triggers, no poller and no
  `table_version`-style counter rows. The Raft drivers do not use `TableWatermarks`,
  and the SQL drivers do not use this.
- **Crypto.** The table holds log indexes only. No cryptographic primitive is
  added or moved, so `crypto-inventory.md` is unaffected.

## Alternatives considered

- **Leader lease reads (`ReadPolicy::LeaseRead`).** Removes the quorum round
  trip, but trades it for a clock-skew assumption on a path that gates
  authorization decisions. Can be added later on top of the watermark; the
  watermark is useful with or without it.
- **Use the global `last_applied` only.** What `within_max_staleness()` does
  today. It is correct but treats every unrelated write as staleness, so a busy
  cluster never qualifies and the follower serves nothing.
- **Compute `W[K]` on the follower by scanning its own unapplied log.** Needs
  the follower to hold the log up to `R`, which the leader does not guarantee,
  and makes the read cost grow with the backlog. The leader already knows.
- **Per-key log index in `Metadata`.** Finer than a keyspace, but a prefix or
  list read would need the maximum over all keys it covers, and the leader
  would need an index of it. A keyspace is the unit the rest of the design
  (`drop_keyspace`, tiers, ephemeral keyspaces) already uses.

## Open points

- Expose the follower-served ratio and the wait the watermark avoided as
  metrics, before any default is changed. The mode would be opt-in
  (`[distributed_storage] follower_linearizable_reads`) at first.
- A test per backend of the failover rebuild: kill the leader mid-write and
  assert no replica serves a value older than the acknowledged write.
