# 0006 — the flow stats value carries window features, memset-built keys

Status: accepted

## Context

TR-31 (issue #31) needs the behavioural DoS detections to read per-flow
evidence. This record was drafted as 0004 while in review; the TR-46 lane
(#222) landed its record-topology ADR as 0004 first, so this record
renumbers to 0006 before merge (numbering never recycles; no accepted
record changed). The shield's per-flow map (`flow_stats`, bpf/flow_tc.c) carried
only `syn_ts`, `req_bytes` and `seg_count` — no window: the engine could
not tell a trickle from a burst. The §13.7 engine-plane duty (slowloris
shape over kernel features) requires the first and last counted-segment
timestamps. Changing the map value layout is a persistent-kernel-artifact
change, so the decision gets a record. The layout change is not a wire
contract change: `flow_stats` is a shield-internal map; nothing rides the
ring buffer or userspace wire differently.

A second constraint surfaced when the first feature-carrying object ran
under the TR-31 gate: one 5-tuple split across several map rows. The
kernel compares the full padded key size (40 bytes); the stack slot for
`struct flow_key` carried garbage in its 3 pad bytes, and each lookup or
update read a different key. The same split appeared in the 2026-10-25
probe run before the fix. Keys must be fully determined bytes.

## Decision

`struct flow_stat` grows `first_seg_ts` and `last_seg_ts` (u64, kernel
clock nanoseconds) ahead of the existing `req_bytes` and `seg_count`
counter fields. The kernel counts and stamps per packet (O(1) map work):
it never computes a ratio, a span decision or a score — the engine reads
the map (pinned per §-cross-plane share) and decides through the ban
plane (the engine's counters-only escalation row, kernelBurstFlag).

Both `flow_key` constructions (IPv4 and IPv6 legs) build the key with an
explicit `__builtin_memset` before field stores, so every key byte is
determined — the IPv6 leg gains the accounting in the same change (the
family byte in `flow_key` carries the discriminator, defect #62).

The BTF-verified Go mirrors are the bpf2go-generated bindings (the
`-output-suffix ""` generate flag pins the committed file names under
cilium/ebpf v0.22, whose generate otherwise suffixes outputs from
$GOFILE). The live read of the generated mirrors is the layout proof;
the gate that reads them is `TestFlowStatsDoSFeaturesE2E`
(`internal/engine/ingest`, tag `ingest4d`).

## Consequences

The engine can read a per-flow time window without new enforcement
surface (the feature path never writes bans; the map keeps its fail-open
shape: a failed lookup or update passes the packet). The 32-byte value is
committed in the regenerated objects; a stray pre-2026 object in the
kernel still serves reads (the reader sizes to the object, and stale
objects fail the gate, not the traffic). Future per-flow features join
`flow_stat` under this record; anything beyond counters and stamps
belongs to a new debate at the decision line.
