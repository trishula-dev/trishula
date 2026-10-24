# Academy Module 3 — eBPF as a platform

Module 3 of the teach-the-web curriculum. The curriculum map entry
lives in
[spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches).
The pedagogy rules live in
[spec §7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules).

The module map entry carries three topics: the XDP/TC hooks, the maps
and the ring buffers, and the verifier bounds. A fourth lesson closes
the loop: why L7 parsing does not live in the kernel.

## The lessons

| # | Topic | The object it teaches |
|---|---|---|
| 1 | The two planes | kernel duty is verdict-cheap; userspace duty is full parse |
| 2 | XDP/TC hooks | where packets meet programs, and what each hook does |
| 3 | Maps and state | the seven maps, their producers and consumers |
| 4 | Ring buffers | the event path and its backpressure |
| 5 | Verifier bounds | why bounded programs shape bounded designs |
| 6 | Why no kernel L7 | verifier cost and ciphertext |
| 7 | The ban path example | one verdict from the engine to the NIC |
| 8 | The lab | attach, map state, and the verdict path |

## Lesson 1 — the two planes

Trishula splits its work by altitude (the two-plane principle,
[spec §9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle)).

- The kernel plane holds the shield. The duties: L3/L4 ACLs, flood
  defense, ban-table enforcement, flow classification. The work per
  packet stays O(1).
- The userspace plane holds the engine. The duties: full HTTP
  reconstruction, CRS evaluation, CEL rules, the rate and ban state.
  Full parsing happens exactly once per request, here.

The split is a design law, not a tuning choice. Two hard reasons keep
L7 parsing out of the kernel (lesson 6).

## Lesson 2 — XDP/TC hooks: where packets meet programs

The hook inventory
([spec §9.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory)):

| Hook | Where | v1 duties |
|---|---|---|
| XDP | shield node NICs | L3/L4 ACL (LPM trie maps), SYN/UDP flood tarpits, verdict cache, ban-table enforcement |
| TC ingress/egress | engine-node veths and node eth0 | flow classification, mark-based steering, per-flow counters, ringbuf events |
| cgroup/connect hooks | engine pods | upstream connect-time policy |
| kprobes/uprobes | nodes, optional per workload | conntrack quality; SSL tracing where the app terminates |

The shield C sources live in
[`bpf/`](../../bpf/): `shield_xdp.c` carries the XDP program; `flow_tc.c`
carries the TC ringbuf producer. Both compile CO-RE against
`vmlinux.h` from BTF. The compiled objects are committed artifacts:
`bpf2go` generates both architecture objects, and CI builds from the
committed objects (`*_bpfel.o`). New kernel programs are sibling `.c`
files; the frozen contracts never take an edit.

The hook attach path is the lab's attach leg (lesson 8): compile the
probe, load it under the verifier, pin it, attach it to a live
interface, detach it clean.

## Lesson 3 — maps and state

The state table
([spec §9.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state)):

| Map | Type | Producer → consumer |
|---|---|---|
| `acl4`, `acl6` | LPM trie, 1M prefixes | operator → shield (compiled from CRDs) |
| `verdict_cache` | LRU hash, 1M entries | engine → shield (block/allow with expiry) |
| `ban_table` | LRU hash + array, 1M entries | ban engine → shield (banned keys with expiry and reason) |
| `src_rep` | LRU hash, 256k | engine → shield (reputation scores) |
| `flow_stats` | LRU hash, 256k | shield → shield (per-flow counters) |
| `rate_windows` | per-CPU array + LRU | shield (kernel-side rate accounting, [§9.5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#95-kernel-side-rate-accounting-feed-13)) |
| `events` | ring buffer, 16 MiB per node | shield → engine or relay (lesson 4) |

The shield pins its maps on BPFFS. Engine pods that sit node-adjacent
open the pinned maps and ring directly; non-adjacent engines take the
gRPC relay with sampling under load. One rule stands over all of it:
**verdict authority stays userspace**. The kernel applies the verdicts
it receives; it never computes one.

## Lesson 4 — ring buffers and backpressure

One map is the wire between planes: the `events` ring buffer.

- Ring events carry a fixed 128-byte header plus bounded slices (a
  path hint, fingerprint fields).
- The default ring is 16 MiB per node.
- When a consumer lags, the relay samples (one of every 2^k events).
- Loss is a telemetry-quality signal, not a payload-path signal: the
  ring is never the request path. A metric counts the drops
  (`trishula_shield_ring_dropped_total`).

## Lesson 5 — verifier bounds

The eBPF verifier rejects programs it cannot prove safe. The proofs it
asks for: no unbounded loops, an instruction budget, no unbounded
allocation, load-time checks on every access. The design consequences
live in the code:

- The kernel parse stays bounded and allocation-free; a hostile peer
  cannot grow kernel allocations.
- Wire contracts are fixed-layout structs, aligned to 200-byte blocks,
  with network-order fields. The Go mirrors are BTF-verified; a wire
  layout test pins every contract
  ([`internal/shield/banwire_test.go`](../../internal/shield/banwire_test.go)).
- The userspace engine mirrors the same discipline on the parse side:
  bounded, allocation-conscious, malformed-input cases explicit
  (Module 1, lesson 3).

## Lesson 6 — why L7 does not live in the kernel

Two hard reasons stand ([spec §9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle)):

- Verifier boundedness. Real L7 parsing needs loops, buffers and
  branch-rich code. The verifier budget turns that into a
  tail-call-bound project with poor maintenance economics.
- Ciphertext. At the NIC the payload is a TLS record. Decisive L7
  analysis needs post-termination plaintext, and the termination hop
  sits above the NIC.

The kernel still gets an honest slice of plaintext work where TLS is
already terminated ([spec §9.6](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest)):
first-line method matching by fixed loads, path-prefix decisions via
trie, duplicate Content-Length detection, and a `fastpath`
classification tag. Every fast-path verdict is advisory. The engine
re-parses authoritatively, and the diffs feed the parity gates
(§11.8). Visibility has contracts per traffic shape
([spec §9.7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode);
the shield measures its tier at boot and refuses to run where the tier
is insufficient — `TierRefusal`, fail-closed).

## Lesson 7 — rule example: the ban path from engine to NIC

The §7.2 rule in action: one decision, named wire anatomy. The ban
write is the product's clearest engine→kernel example.

```
engine: ScoredWindowBan says ACTIVE_BAN(until, tier, reason_codes)   <- 1
        write ban_key {family, addr union, port}                     <- 2
        write ban_entry {expiry, reason codes}                       <- 3
shield: XDP/TC reads ban_table per packet                            <- 4
        hit before expiry -> drop/tarpit (no userspace round trip)   <- 5
```

- Step 2's `ban_key` carries a family-discriminated address union (an
  IPv4 arm and a 16-byte IPv6 arm) plus a family field — the
  dual-stack wire contract the spec's §19.1 sketches and the repo
  pins (`TestBanEntryWireContract`, `TestBansV4WireContract`).
- Step 4's enforcement needs no parse at all: the key lookup is a map
  read. This is what ban enforcement buys at line rate.
- The `ban_table` map is lesson 3's producer→consumer row: the ban
  engine produces; the shield consumes.

## Lesson 8 — the lab: attach, map state, verdict path

Run the lab from a repo checkout:

```bash
bash lab/module-3/run.sh
```

Three legs:

| Leg | Surface | The gate |
|---|---|---|
| wire | `go test ./internal/shield/` — the wire-contract and tier tests | every pinned contract holds |
| attach | `lab/verify-xdp-chain.sh <iface>` — CO-RE compile, verifier load, pin, attach, detach | `XDP-CHAIN-OK` |
| ban-e2e | `go test -tags ban_e2e ./test/banenforce/` — ban publish → kernel drop → expiry → evidence JSONL | the full verdict path, in kernel |

The attach and ban-e2e legs need Linux with root, BTF and BPFFS. On a
macOS host the lab drives them inside an OrbStack VM (set
`TRISHULA_LAB_VM`). A missing kernel environment prints a loud SKIP
line; no leg ever reports a skip as a pass. The full shape:
[`lab/module-3/README.md`](../../lab/module-3/README.md).

## Course links

| Where | Link |
|---|---|
| The academy index | [`docs/academy/README.md`](README.md) |
| This module's lab | [`lab/module-3/README.md`](../../lab/module-3/README.md) |
| The kernel C sources | [`bpf/`](../../bpf/) |
| The shield loaders | [`internal/shield/`](../../internal/shield/) |
| The full packet-path spec | [spec §9](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#9-ebpf-packet-path) |
