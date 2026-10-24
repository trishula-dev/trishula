# Socket-plane fast path — assembled note (TR-39d)

> **Trishula design note TR-39d** — the assembly record of the socket-plane note. Parent
> record: [TR-39 #51](https://github.com/trishula-dev/trishula/issues/51). Three part records
> carry the study: mechanism (part 1), fail-open ladder (part 2), census (part 3). This note
> links the parts and carries the assembly additions: the transport constraints and the
> pre/post performance protocol.
>
> **Spec refs:** [§9.9 socket-plane fast path](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment) ·
> [§17 performance targets & benchmark plan](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#17-performance-targets--benchmark-plan) ·
> [§21 M2 guard row](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates)

Status: design study. The note ships no code and makes no capability claim. The source study is
Beeline — "Enforcing Application-Layer Policies in eBPF" (arXiv:2605.31084). The §9.9 contract
holds across all four records: tracked evaluation, not a v1 commitment. The fail-open ladder
(part 2) carries the enforcement contract.

## 1. Index — the part records

| Part | Record | Question it answers |
| --- | --- | --- |
| 1 | [Mechanism design](socket-plane/1-mechanism.md) | How the plane parses, matches and acts at socket altitude |
| 2 | [Fail-open ladder](socket-plane/2-failopen-ladder.md) | What each failure stage yields: one tier, always |
| 3 | [Census](socket-plane/3-census.md) | How much CRS and CEL the plane can carry |

Reading order: part 1, part 2, part 3, then this assembly record. The parts stay independent
records; no part re-cites another part's prose. Each part owns its own decision rows.

## 2. Decision record — one row per component

The consolidated record. Each row carries the owning record and the decision.

| Component | Record | Decision |
| --- | --- | --- |
| Parse stage: DFAs from the bundle header set | part 1, §2 | adopt |
| Header vector `H`: header-class data only | part 1, §2 | adopt |
| Match stage: compiled `if` chains in bundle priority order | part 1, §3 | adapt |
| Action library: 8 primitives, `drop`/`forward` termination | part 1, §4 | adopt |
| Gated primitives: `encode`/`decode`/`hash` | part 1, §4 | gate-locked; slow path |
| Shared state: get/set over the §9.3 maps | part 1, §5 | adapt |
| Connection pool: lazy fill, `SOCK_OPS`, control plane in the Go shield | part 1, §6 | adopt |
| kTLS/`strparser` handoff: Model A legs only | part 1, §7 | adopt with scope |
| Verifier envelope: per-bundle CI load proof | part 1, §8 | adapt |
| Kernel module: hash/encode helpers | part 1, §9 | reject; upstream trigger recorded |
| Enforcement ladder: T1 → T2 → T3 | part 2, §1 | adopt |
| Failure matrix F1–F5 with next-tier dispositions | part 2, §2 | adopt |
| Degradation rules: forward on miss; no silent drop | part 2, §3 | adopt |
| XDP ban-hit contrast: shield semantics stay | part 2, §4 | keep |
| Verification shapes V1–V5 for the build lane | part 2, §5 | adopt |
| Kernel CRS evaluation | part 3, §3 and §5 | reject; CRS mainline stays at the engine |
| CEL as the fast-path policy source | part 3, §4 | adapt |
| Envoy-config 89% number as a CRD/CEL claim | part 3, §5 | reject; never restate it |
| HTTP/2 header compression | this note, §3 | adapt; no dynamic table, Huffman stays |
| HTTP/3 | this note, §3 | non-goal at the tracked evaluation |
| Performance protocol | this note, §4 | adopt; the TR-40 PR carries the walls |

## 3. Transport constraints

Rule: HTTP/1.1 and HTTP/2 carry synthesized DFAs in the tracked evaluation. HTTP/3 stays out of
scope at socket altitude.

### 3.1 HTTP/2: no HPACK dynamic table on fast-path legs; Huffman stays

The parse DFA treats each message alone (part 1, §2). HPACK (RFC 7541) carries connection-level
state. Its dynamic table — the header cache — stores prior header fields in emission order. A
DFA that skips byte ranges cannot own that ordered history. The mismatch is structural, not a
size question.

Decision: fast-path legs negotiate a zero-size dynamic table. The Huffman code stays. Three
facts make that safe:

1. Huffman coding is per-string and self-contained. It needs no cross-message state.
2. The zero-size table is a SETTINGS value; the control plane sets it at handshake.
3. The engine path (T2) keeps full HPACK. No engine-path change rides on this note.

The fast path receives header sets that skip the cache. The census record (part 3) prices no
band on header compression, so this change moves no census row.

### 3.2 HTTP/3: non-goal at the tracked evaluation

The plane hooks TCP sockets (`SK_SKB`, `SK_MSG`, part 1, §1). QUIC runs over UDP and terminates
in userspace today. No kernel reassembly surface for QUIC reuses this altitude. HTTP/3 requests
route at T2/T3 and reach the engine (part 2, §1).

Decision: record HTTP/3 as a non-goal. The re-evaluation trigger is a kernel reassembly surface
for QUIC at the socket altitude. The trigger is recorded, not claimed; no commitment rides on it.

## 4. Performance protocol — §17 cells, pre and post

Rule: every fast-path latency or throughput claim cites one recorded sweep. No sweep, no claim.

### 4.1 The two sweep states

| State | Enforcement path | Tree state |
| --- | --- | --- |
| PRE (baseline) | XDP → ringbuf → engine evaluation | current tree, before TR-40 kernel work |
| POST (fast-path tiers) | T1 fast-path enforcement + T2/T3 forwards on degradation | TR-40 spike tree, programs attached |

### 4.2 The §17 cells

The PRE sweep records the baseline path. Budgets read from §17.1:

| Tier | §17 cell | Budget (p99, per request) |
| --- | --- | --- |
| XDP | XDP shield (ACL/flood/cache/ban-hit path) | ≤ 10 µs |
| Ringbuf | TC classifier + ringbuf emit | ≤ 20 µs |
| Engine | Engine parse + deep inspect (8KB, full CRS) | ≤ 600 µs |
| Engine | Engine parse + deep inspect (64KB JSON) | ≤ 1.2 ms |
| Cached short-circuit | Kernel-cached verdict/ban short-circuit | ≈ 1 µs; ≤ 100 µs with context fetch |
| End to end | Total inline hop added vs direct (8KB, full CRS) | ≤ 1.5 ms p99 / ≤ 300 µs p50 |
| Throughput | Per engine replica (4 vCPU, CRS + schema) | ≥ 10k req/s |

The POST sweep adds the fast-path measurements:

- Per-message T1 service time at the socket plane, before the loopback hop into the engine.
- The T2/T3 forward share: the fraction of messages that degrade out of T1 (the failure-matrix
  count, part 2, §2).
- The per-altitude split of verdict-resolved requests (the §17.2 cell 4 economics).

### 4.3 The M2 guard row

The end-to-end guard is the M2 adoption gate: p99 added latency (8KB, full CRS) at most 1.5 ms,
CI-blocking on benches. Two protocol rules pin it:

1. The fast path never relaxes the guard. T1 removes engine-path work only. T2 and T3 forwards
   re-enter the full engine budget.
2. The userspace budgets in §17.1 are targets pending a recorded wall. The PRE sweep produces
   the first recorded walls for those cells; the PRD §6.4 target labels hold until then.

### 4.4 The pre-integration baseline sweep

The PRE sweep runs before any TR-40 kernel work lands. It produces the ledger that every later
comparison reads:

- Scenarios: §17.2 cells 1–3 (baseline direct via NGF, inline idle, inline steady state) plus
  cell 4 (short-circuit economics). Harnesses: wrk2 for latency distributions, h2load for
  HTTP/2, vegeta for burst shapes.
- Ledger rows: one row per cell — cell, budget, last recorded wall, verdict. The row matches
  the perf-ledger shape used across the repo's perf content.
- Recording: every wall carries the run that produced it. The no-invented-transcripts rule of
  AGENTS.md applies to these numbers verbatim.

### 4.5 The comparison protocol for the TR-40 PR

The TR-40 spike ([#52](https://github.com/trishula-dev/trishula/issues/52)) proves the mechanism
and the envelope. Its PR evidence follows this protocol:

1. Both walls per cell: PRE and POST, from the same harness version and scenario set.
2. Same node class. Runs stay sequential; concurrent harnesses pollute each other (two harnesses
   at once inflate both).
3. The delta per cell reads against the §17.1 budget, and the end-to-end delta reads against the
   M2 guard row.
4. The T2/T3 forward share rides alongside: degradation cost is part of the verdict, not a
   footnote.
5. A rerun under runner contention: judge attempt 2 before any verdict. Budget rows never
   re-pin to pass a comparison; only the maintainer re-pins.
6. The PR carries walls as recorded-run outputs only. A cell without a live PRE and POST
   pair from one harness and node class renders a PENDING row — never an estimate, never a
   figure borrowed from another run. The parity census and the mismatch budget ride the
   same record, and a budget row re-pins only with a fresh recorded run (rule 5 applies).

## 5. Closure record

- The note closes TR-39: mechanism (part 1), ladder + failure matrix (part 2), census (part 3),
  transport constraints + performance protocol (this note).
- The parent record [TR-39 #51](https://github.com/trishula-dev/trishula/issues/51) stays open
  as the acceptance gate.
- The TR-40 spike inherits §4 of this note and re-reads the kernel-module trigger (part 1, §9).
  Its PR carries the walls before any fast-path claim enters a capability surface.
