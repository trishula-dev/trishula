# Per-component stage stamps — the stamp vocabulary verdict (TR-47)

> **Trishula design note TR-47** — the verdict record for the research item
> [TR-47 #194](https://github.com/trishula-dev/trishula/issues/194). One canonical name per stage
> covers the kernel plane, the ring handoff and the engine plane. The record prices the cost
> tiers, the FlowEvent bitmap layout, the short-circuit rule and the header form. Sibling
> verdicts: [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85) and
> [TR-45 #86](https://github.com/trishula-dev/trishula/issues/86). The header-write contact is the
> TR-40a census ([4-compiler-census.md](socket-plane/4-compiler-census.md)). Implementation slices
> file after this record. This lane merges no code.
>
> **Spec refs:** [§15 OpenTelemetry observability] · [§15.1 the three signals] · [§15.2 the verdict
> record] · [§2.3 D3 — detection depth] · [§2.5 D5 — honesty] · [§8.2 component map] · [§8.3 request
> lifecycle] · [§9.2 hook inventory] · [§9.3 maps and state] · [§9.4 ring sizing] · [§9.6 kernel fast
> path] · [§13.5 observability of bans] · [§15.3 kernel-plane counters] · [§15.4 dashboards &
> redaction] · [§17 performance targets]

[§15]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#15-opentelemetry-observability
[§15.1]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#151-the-three-signals-as-contracts
[§15.2]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#152-the-verdict-record-log-body-schema-versioned
[§2.3]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#23-d3--detection-depth-more-than-negative-signatures
[§2.5]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#25-d5--honesty-as-a-mechanism-shadow-first-and-differential-parity
[§8.2]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#82-component-map
[§8.3]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#83-request-lifecycle
[§9.2]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory
[§9.3]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state
[§9.4]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#94-ring-buffer-sizing-and-backpressure
[§9.6]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest
[§13.5]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#135-observability-of-bans-first-class
[§15.3]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#153-kernel-plane-counters-shield
[§15.4]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#154-dashboards--redaction
[§17]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#17-performance-targets--benchmark-plan

Status: decided verdict record. The record carries no capability claim. No build carries any
stamp at the tracked state.

## 1. The decision

The record decides five points. Each point holds one plane boundary:

1. **Vocabulary.** 22 canonical names cover the three planes, the handoff and the response.
   Section 3 carries the table.
2. **Tiers.** Three cost tiers price the stamps. The kernel bitmap runs always-on. The ladder
   rows run always-on per verdict record. The spans run under the OTel sampler.
3. **Layout.** One `__u64 stages` field appends to the landed FlowEvent wire. Bits 0–6 carry the
   seven kernel-plane stages. 57 bits stay reserved. The wire grows 8 bytes, 4.00% per record.
4. **Honesty rule.** A short-circuited stage reads absent. It never reads passed.
5. **Header form.** W3C trace propagation is the only header form. The opt-in response debug
   header is rejected. Section 9 keeps the frictions on file.

## 2. The question and the method

The request crosses three planes. The kernel shield walks it at XDP and TC ([§8.2], [§8.3]).
The ring hands events to the engine. The engine walks the ladder to the verdict and the
response.

The research question: what stamp vocabulary records per-component traversal? Verbosity carries
cost. The stamp needs cost tiers per plane. The stamp reads back on the layer it prices.

Method:

1. The record reads the landed v0 surfaces at the tracked state: `internal/engine/otel/`,
   `internal/engine/ingest/`, `internal/engine/ladder/`, `bpf/shield_xdp.c`, `bpf/flow_tc.c`.
2. The record reads the spec contracts of [§15.1], [§15.2], [§2.3], [§9.2], [§9.3], [§9.4] and
   [§13.5].
3. The record ties every name to its code surface and prices every tier.
4. The record merges no code and states no measured walls. Numbers absent here wait for the
   implementation slices and their gates.

## 3. The stage taxonomy

The table obeys three rules:

- One stage carries one name. The name never renames. A rename is a wire re-freeze.
- Every name binds to the code at the tracked state. The binding lives in the rows.
- Kernel-plane names carry the plane prefix (`xdp.`, `tc.`). The ladder names carry the
  ladder's own convention. No prefix doubles as a second name.

### 3.1 Kernel plane, XDP at the node NIC

`shield_xdp.c` consults three maps, then passes ([§9.2], [§9.3]). A live drop ends the path at
XDP. No event exists for a dropped packet.

| Bit | Name | What runs | Read-back on a live drop |
| --- | --- | --- | --- |
| 0 | `xdp.ban` | the `ban_table` consult | XDP_DROP; [§15.3] counters; no event |
| 1 | `xdp.acl` | the LPM ACL consult (`acl4`/`acl6`) | XDP_DROP; [§15.3] counters; no event |
| 2 | `xdp.cache` | the `verdict_cache` consult | the cached action applies; a cached drop reads no event |
| 3 | `xdp.pass` | the boundary pass | the packet continues into the stack |

### 3.2 Kernel plane, TC at the engine hop

`flow_tc.c` classifies, probes the ban table, emits the event ([§9.6]).

| Bit | Name | What runs | Read-back on a live drop |
| --- | --- | --- | --- |
| 4 | `tc.classify` | the bounded L4 classify walk | — |
| 5 | `tc.ban` | the `ban_table` probe (the TR-03 authority) | TC_ACT_SHOT; [§13.5] record + counters; no event |
| 6 | `tc.fastpath` | the [§9.6] advisory probe | — |

### 3.3 The handoff

`ring.emit` names the ring handoff. It carries no bit: the event record is its own read-back.
A failed reserve counts in `lost_events` ([§9.4]).

### 3.4 The engine plane

- `ingest.reconstruct` — the transaction assemble in `internal/engine/ingest/`. It carries no
  row: the verdict record's presence is the proof.
- The ladder names carry one row per run stage: `kernel` (S0), `matcher` (S1), `crs` (S2),
  `cel` (S3), `schema` (S4), `bots` (S5), `rate_ban` (S6), `ml` (S7). The tokens mirror the
  `ladder.Stage` constants of `internal/engine/ladder/ladder.go`. Array order is walk order.
  The S-numbering is a wire sorting contract; it never renumbers.
- `verdict.resolve` — the fold into the action. It carries no row: the `verdict` block is the
  read-back.
- The phases: `request_headers`, `request_body`, `response_headers`, `response_body`. The
  tokens are the `ladder.Phase` strings, verbatim. The `verdict.phase` attribute carries the
  phase on the span and on the log record (TR-11a).

### 3.5 The count

22 canonical names in total. Seven carry FlowEvent bits. Three name surfaces the record
itself proves: the handoff, the reconstruct, the resolve. Eight name ladder rows. Four name
the phases.

## 4. The cost tiers

| Tier | Plane | Surface | Cost | Gate |
| --- | --- | --- | --- | --- |
| T0 | kernel | the `stages` bits on every FlowEvent | +8 bytes per event (4.00%); one OR per carried stage; one flow-keyed map lookup per packet on the XDP handoff; no allocation; no packet mutation | always-on |
| T1 | engine | one ladder row per run stage on the verdict record | per-row bytes on the OTLP log; the short-circuit bounds the count | always-on per verdict record |
| T2 | engine | per-stage child spans; shield events as span links | a link carries one context + attributes; a child span carries a full span | OTel sampler |

T2 note: the landed pipeline v0 configures no sampler. The sampler arrives with the collector
cutover (TR-08c/TR-23). Until then no per-stage span emits.

Ring math: the 16 MiB ring holds 83,886 events at 200 bytes. It holds 80,659 at 208 bytes.
Capacity reads −3.85%. No measured wall backs these counts. The arithmetic is structural.

## 5. The bitmap layout

Decision: one `__u64 stages` field, appended last, after the path hint.

The landed contract freezes the wire at `internal/engine/ingest/decode.go`. The freeze-first
standard (the #42 rule) puts the contract on the Go side first. The C mirror at
`bpf/flow_tc.c` must drift-match or the E2E fails.

Layout facts:

- The landed record spans 200 bytes: `EventHdrSize = 200`. A 3-byte pad precedes `mark`; 6
  tail-pad bytes close the struct (align-8 for the leading `__u64`).
- The append keeps bytes 0–199 byte-identical. The 6 tail-pad bytes stay. `stages` rides at
  offset 200. `sizeof` reads 208.
- The decoder reads both sizes. A 200-byte record shows an all-absent bitmap. A 208-byte
  record carries the bits.
- The upgrade order is engine-first. A new engine reads both sizes. An old engine fails the
  size gate and counts the new size in `SkippedTotal`.

Bit semantics: 1 means "the consult ran on a packet that reached the emit point". A live drop
ends the path with no event. [§15.3] counters and the [§13.5] record carry the drops. No bit
ever names a drop. No bit ever names an engine stage.

The XDP handoff:

- XDP consult state reaches the TC emit point through flow-keyed map state (the [§9.3] per-flow
  LRU family). One LRU entry per flow. One lookup and one conditional update per packet. No
  per-packet allocation rides this.
- Rejected carriers: per-CPU scratch (never flow-keyed) and `skb->mark` writes (the gateway
  owns the mark as the steering tag).

Loss honesty: LRU eviction can drop the carried bits on flow churn. The absent read stays
correct but lossy. The loss class matches [§9.4].

Wire cost: +8 bytes per event, 4.00%. The 16 MiB ring drops from 83,886 to 80,659 records
(−3.85%). The implementation slice refreshes the [§9.4] sizing note.

CO-RE gate: the C mirror recompiles through bpf2go in CI. The E2E fails loudly on drift
(`decode_test.go`, `e2e_linux_test.go`). The load gate is TR-40b's.

## 6. The short-circuit honesty rule

The rule: a short-circuited stage reads absent. It never reads passed.

Worked cases (the [§2.3] walk; block > challenge > log > pass):

- A cache hit at S0: the record carries the `kernel` row only. No rows follow for S1–S7.
- A decisive CRS hit at S2: the record carries rows for S0, S1 and S2. S3–S7 carry no rows.
- A TC live-ban hit: `flow_tc.c` returns `TC_ACT_SHOT` before the emit. No event exists. The
  [§13.5] record and the counters carry the evidence.
- An XDP drop: no event exists. The [§15.3] counters carry it.
- A ring loss: no event exists. `lost_events` and the drop counter carry it.

The why:

- The stamp names traversal. It never claims enforcement or detection ([§2.5]).
- The kernel bitmap carries consult context, never engine claims. The event precedes the
  ladder: engine bits cannot exist on this wire.
- The ladder rows never carry kernel enforcement claims. S0 is the engine's own map consult.
- A "passed all layers" stamp is a fake record on any short-circuit walk.

Precedent: the TR-40b split surface carries the same rule in the compile plane. The split
vocabulary names dispositions and never reports `enforced`.

## 7. The verdict record shape

Decision: extend `trishula.verdict.v1`. No v2 bump.

- The extension: one optional root object `"shield": {"stages": <int>}`. The integer carries
  the decoded bitmap.

  ```json
  {
    "schema": "trishula.verdict.v1",
    "shield": {"stages": 127}
  }
  ```

  `127` reads "every consult ran and passed" (bits 0–6 set).
- The absence rule: no FlowEvent for the request reads no `shield` field. Absence carries no
  claim.
- Why no v2 bump: an additive optional field keeps pinned readers valid ([§15.4] pins backends
  explicitly). A backend pin gains one line. A v2 bump costs a migration for one optional
  object.
- The ladder rows keep the v1 row shape `{stage, matched, us}`. The row tokens are the §3.4
  names. The landed [§15.2] example tokens (`matcher`, `crs`, `bot`, `rate`) pre-date this
  record. Implementation aligns the examples with the canonical tokens.

## 8. The span decision

The [§15.1] contract holds: one server span per request (`trishula.verdict`), stages parse →
ladder → verdict → forward. TR-11a lands it with the `verdict.phase` attribute.

- Shield events attach as span links. One link per correlated FlowEvent. The link attributes
  carry the event fields: timestamps, family, ports, TCP flags, payload length, path hint and
  the stages integer.
- Per-stage child spans form the T2 tier. The OTel sampler gates them ([§4] of this record).
- A link carries a context + attributes, not a span. The one-server-span contract holds.

## 9. The header form

Decision: W3C trace propagation only.

Accepted:

- `traceparent` + `tracestate` both ways per [W3C Trace Context]. The [§15.1] contract names
  the shape: the gateway sets `traceparent`; the engine never strips it; upstream forwarding
  preserves the headers.
- These headers carry trace identity. They never carry stage presence.

Rejected: the opt-in response debug header — a `debugBodies`-style CRD flag mounting a stamp
header on the response. The record rejects it. It does not defer it.

The frictions, on the record:

1. **Client disclosure.** The header hands stage presence and rule classes to every client. An
   adversary reads it as route recon.
2. **The disclosure asymmetry.** `debugBodies` verbosity lands in the operator's telemetry
   estate ([§15.4]: per-policy flag + purpose annotation + redaction always on). A response
   header lands on the client's socket. Opt-in never shrinks the leak to the reader it hurts.
3. **Cacheability.** Shared caches store the stamped response. Cached copies keep disclosing
   after the flag flips off.
4. **Bloat.** The vocabulary carries 22 names (§3.5). The header grows with it on every
   response.
5. **Altitude.** The kernel writes no stamp header: XDP runs before the skb exists; TC runs
   before reassembly. Only the engine holds response-stage state. The TR-40a census compiles
   the `header_mutation` class to the kernel — that class rewrites known headers on an
   existing skb. A stamp needs state the kernel never sees.
6. **Hot path.** Header assembly joins every response of the route.

The kernel-header boundary: kernel header writes touch known headers on an existing skb
(the TR-40a `header_mutation` class). Engine stamp writes carry stage state only the engine
holds. No stamp header rides the kernel plane.

The escape hatch stays internal: per-policy verbosity inside the telemetry estate follows the
`debugBodies` pattern. It never reaches the wire.

## 10. The cost gates

What implementation reads against:

- Kernel leg: zero per-packet allocation, zero packet mutation. The TR-40b gate owns the load
  and the envelope.
- Bitmap leg: the [§17] bench reads the TC emit leg. The bench lane's variance rules govern
  every recorded wall.
- Engine leg: rows, the record extension and span links read against the [§17] engine budget.
- Ring leg: the −3.85% capacity delta lands in the implementation slice's [§9.4] refresh.

## 11. Status

Status: decided. The record merges no code. Stamps are observability plumbing, not detection.
No claim moves between planes. [Spec §15] carries this record in one pointer line.
Implementation slices file after this record lands.

[Spec §15]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#15-opentelemetry-observability

## References

- The research issue: [TR-47 #194](https://github.com/trishula-dev/trishula/issues/194)
- The landed pipeline v0: [TR-11a #101](https://github.com/trishula-dev/trishula/issues/101)
- The sibling research verdicts: [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85),
  [TR-45 #86](https://github.com/trishula-dev/trishula/issues/86)
- The compile-split contact: [TR-40 #52](https://github.com/trishula-dev/trishula/issues/52),
  [TR-40a #187](https://github.com/trishula-dev/trishula/issues/187),
  [TR-40b #188](https://github.com/trishula-dev/trishula/issues/188)
- The bench gates: [TR-24 #144](https://github.com/trishula-dev/trishula/issues/144)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [OpenTelemetry span links](https://opentelemetry.io/docs/specs/otel/trace/api/#link)
