# HTTP/3 ingress posture — the tracked-evaluation record (TR-29)

> **Trishula evaluation record TR-29** — the HTTP/3 ingress posture statement. Parent
> record: [TR-29 #29](https://github.com/trishula-dev/trishula/issues/29).
> Spec [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)
> pins the posture rule: the QUIC ingress posture sits as a tracked evaluation, not a
> v1 claim. This record states that posture. It covers what the ingress path carries
> today, the probes the evaluation owes, and the engine-side non-claims. It follows the
> verdict-record shape of [TR-44](protocol-conformance-verdict.md) and the transport
> constraints of [TR-39d](socket-plane-fast-path.md), section 3.2.
>
> **Spec refs:** [Appendix A: roadmap notes](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes) ·
> [§20.2 phasing](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#202-phasing) ·
> [§7.1 curriculum map, Module 5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches) ·
> [§9.2 hook inventory](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory) ·
> [§9.1 the two-plane principle](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle) ·
> [§9.6 plaintext fast path](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest) ·
> [§9.7 visibility contracts per mode](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode) ·
> [§9.9 socket-plane fast path](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment) ·
> [§13.3 the ban algorithm](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified) ·
> [§12 bot defense & anti-automation](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#12-bot-defense--anti-automation)

Status: tracked evaluation delivered as a posture statement. The record ships no code.
It files no capability claim. Every probe row carries a status. A live status cites a
recorded run. A PENDING status names its absent piece.

## 1. The question, restated once

Spec [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)
carries the rule for h3/QUIC: tracked evaluation first, claims after.
[§20.2 Phase 2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#202-phasing)
carries the lane. The curriculum teaches the why first
([§7.1 Module 5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches)).
This record is the lane's first deliverable. It answers two questions:

1. What does each ingress leg cover for h3/QUIC today?
2. What must the tracked evaluation probe, and where does the lab support a probe?

Decision rule: one coverage row per ingress leg. One status row per probe. No row states
a claim that no repo surface pins today. A probe without evidence files a PENDING row and
names its absent piece. A pending row never reads as a pass.

## 2. The posture statement — facts first

The posture rests on 7 wire facts. Each fact comes from the repo, not from an assumption.

| # | Fact | Source |
| --- | --- | --- |
| F1 | h3/QUIC ingress is terminator territory. The terminator and its QUIC stack own the wire grammar. No engine surface reads that wire. | [TR-44](protocol-conformance-verdict.md) verdict row 7; [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes) |
| F2 | The engine reads the gateway's upstream legs only: h1 heads, or h2c frames. The engine holds no h3 request view at any plane. | [§8.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#83-request-lifecycle); [TR-44](protocol-conformance-verdict.md) fact F1 |
| F3 | XDP flood defense holds its L3/L4 altitude. The hook inventory carries SYN/UDP flood tarpits and LPM ACL. QUIC traffic meets these classes as UDP, never as requests. | [§9.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory), the XDP row |
| F4 | The kernel stays decision-free ([§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle)). The §9.6 advisory window serves plaintext TCP legs. h3 reaches the kernel as UDP datagrams, never as requests. | [§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle); [§9.7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode); [TR-44](protocol-conformance-verdict.md) fact F3 |
| F5 | The TC flow classifier parses TCP only at v0. A non-TCP IP protocol value returns before any event. QUIC flows carry no flow view at v0. | `bpf/flow_tc.c`, the bounded-walk guard |
| F6 | The socket plane hooks TCP sockets only (`SK_SKB`, `SK_MSG`). kTLS and `strparser` are TCP material. HTTP/3 stays a non-goal at that plane. | [TR-39d](socket-plane-fast-path.md), section 3.2; [§9.9](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment) |
| F7 | The bot plane carries the QUIC transport code in its JA4 grammar. The golden-vector tests derive the `q` variant. The derivation reads a summary, not a live packet. | `internal/engine/botdef/ja4.go`; the module-2 lab |

### 2.1 The terminator leg

Gateway-owned termination stays the product posture on the client hop
([Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes),
the post-quantum note). QUIC handshake, QUIC frame grammar and h3 message grammar sit
inside that termination. The terminator and its QUIC stack answer for this leg. The
record pins 3 boundary facts on it.

1. The reference lab serves no h3 listener today. The DX1 lab ships a plain-HTTP
   listener. An HTTPS-listener leg stays pending work (the module-2 lab legend).
2. No repo test exercises a QUIC client hop. No verdict row exists for this leg. Its
   probe rows carry PENDING marks.
3. The engine abstraction holds behind any terminator that speaks h1 or h2c upstream.
   The same logical request reconstructs the same view head over both upstream legs. The
   upstream protocol stays invisible to the ladder. Two
   [gateway-conformance](../../test/gateway-conformance/) rows pin that pair:
   `engine:same-view-parity` and `engine:h2c-ingress`.

### 2.2 The ingress-leg coverage map

One row per leg. The "covers today" cell names the only coverage that a repo surface
pins. The sparse coverage is itself the posture statement.

| # | Leg | Altitude | h3/QUIC coverage today | Evidence |
| --- | --- | --- | --- | --- |
| 1 | client → gateway, transport | kernel XDP, L3/L4 | UDP flood tarpits and LPM ACL; no request view | F3 |
| 2 | client → gateway, termination | gateway terminator | terminator territory; no repo test pins it | F1, F2 |
| 3 | client → gateway, flow telemetry | kernel TC | TCP-only walk; QUIC flows emit no event | F5 |
| 4 | gateway → engine, upstream | engine parse layers | h1/h2c legs carry view parity; the engine never sees h3 | F2, fact 3 of §2.1 |
| 5 | gateway → engine, fast path | socket plane | TCP-only; h3 is a non-goal at the tracked evaluation | F6 |
| 6 | client → ban path, identity | bot plane + §13.3 | transport code `q` derives over a summary; the ban keys read one source per key | F7; [§13.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified) |

## 3. The engine-side non-claims

The [TR-44](protocol-conformance-verdict.md) verdict decides the engine altitude for h3.
[TR-39d, section 3.2](socket-plane-fast-path.md) decides the socket altitude. This record
carries both decisions forward. It states each boundary once, with its anchors.

| # | Non-claim | Anchors |
| --- | --- | --- |
| N1 | No engine parse surface for h3 or QPACK exists. No engine claim rides [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) or [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204). | TR-44 verdict row 7 |
| N2 | No kernel parse of QUIC exists at any plane. The kernel stays decision-free. | F4; [§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle) |
| N3 | No socket-plane reassembly surface for QUIC exists. The plane hooks TCP sockets only. | F6; [§9.9](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment) |
| N4 | No per-request or per-stream protection over QUIC is claimed. The XDP classes hold L3/L4 scope only. | F3; [§9.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory) |
| N5 | No h3spec run enters CI. Socket-opening probes stay advisory lab material. Tool output joins no verdict. | TR-44, section 5.1 |
| N6 | No live QUIC fingerprint read is claimed. The `q` derivation runs over a summary struct. No packet reader exists in the tree. | F7 |
| N7 | No ban-identity guarantee covers QUIC connection migration. The ban keys read one source per key. The record files the gap; no row measures it. | F7 + [§13.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified) |
| N8 | No claim rides a gateway's h3 serving. The gateway owns its listener set; the operator owns the topology. | F1; [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes) |

A non-claim moves only on recorded evidence. A probe that measures the boundary files its
run, and the row moves by PR.

## 4. What the tracked evaluation must probe — the probe map

One row per probe. The status column carries 2 values. `live` names a probe whose
harness exists and runs green. `PENDING` names a probe with no real evidence: no harness,
no topology or no recorded run. A live row names its harness. A PENDING row names its
absent piece.

| # | Probe | What it must measure | Harness today | Status |
| --- | --- | --- | --- | --- |
| P1 | UDP flood posture over QUIC ingress | the XDP tarpit/ACL classes hold under QUIC loads, at L3/L4 scope | the kernel evidence gate, on the Linux VM | PENDING — no QUIC-load leg on the VM path |
| P2a | QUIC transport fingerprint derivation | the `q` variant derives under the pinned JA4 grammar | `go test ./internal/engine/botdef/` | live — recorded on the PR that files this record |
| P2b | live QUIC Initial fingerprint read | fingerprint bytes off the wire, with the spoofability caveats | none in the tree | PENDING — no UDP capture feed; the §12 capture slice owns it |
| P3 | h3 grammar corpus rows | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)/[RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) MUST shapes with pinned verdict cells | none | PENDING — no h3 analysis surface; TR-44 row 7 owns the placement |
| P4 | offline h3spec probe at the terminator | advisory conformance signal on the lab leg only | none | PENDING — no QUIC-ingress topology |
| P5 | 0-RTT early-data posture | the replay exposure on the client hop; the engine's reachable surface | none | PENDING — terminator territory; no harness |
| P6 | flow telemetry for UDP/QUIC | the UDP slice of the TC flow classifier | none — the TCP-only guard stands at v0 | PENDING — the §12 UDP slice owns it |
| P7 | ban identity under QUIC connection migration | source-key stability while a live stream re-addresses | none | PENDING — no QUIC-load leg |
| P8 | view parity behind an h3 terminator | the same-view rows hold when the terminator speaks h1/h2c upstream | `go test ./test/gateway-conformance/` | live for the h1/h2c legs; PENDING for the h3 hop |

The live rows: P2a, and the h1/h2c half of P8. Both run green at this record (the PR
evidence carries the transcripts). The PENDING rows: P1, P2b, P3, P4, P5, P6, P7, plus
the h3 hop of P8. 7 rows read PENDING outright.

## 5. The evaluation plan

The plan moves PENDING rows one probe at a time. Each step lands by PR. Every new claim
cites a recorded run (the no-invented-transcripts rule of
[AGENTS.md](../../AGENTS.md)).

1. **Step 1 — keep the live rows live.** Every PR runs the botdef and
   gateway-conformance gates. The nightly jobs keep the module labs timed.
2. **Step 2 — build the QUIC-ingress lab leg.** A kind topology with a gateway that
   serves an h3 listener and speaks h1 or h2c upstream. The HTTPS-listener work in the
   module-2 termination lane is the build seam.
3. **Step 3 — run the topology probes.** P1 on the kernel leg, P4 as the advisory
   h3spec pass, P7 on ban identity. Each run records on the parent record.
4. **Step 4 — add the grammar corpus rows.** P3 lands where the Phase 2 lane builds an
   analysis surface. The TR-44 method carries: rows at the parse layer, pinned verdict
   cells, never kernel work.
5. **Step 5 — re-read the socket plane.** The TR-39d trigger fires: a kernel reassembly
   surface for QUIC at socket altitude. The re-read opens by PR, never in prose.

Plan rules: probes stay advisory until a consuming stage lands. PENDING rows never flip
without a recorded run. A status update appends a dated read; it never edits an earlier
row. A failed probe files a finding, not a pass.

## 6. The honest boundary — this record does NOT

1. Ship code, tests or workflow changes. The deliverable is the statement, the map and
   the plan.
2. Edit a spec line. A spec-side finding files in its own lane.
3. Claim an h3 or QUIC protection class at any altitude. Section 3 holds the
   non-claims.
4. Pin a gateway behavior. The terminator leg stays inside the gateway product surface.
5. File a v1 surface. [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)
   and [§20.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#202-phasing)
   keep the lane at Phase 2.
6. Read a PENDING row as a pass. The academy
   [module-5 lab](../../lab/module-5/README.md) carries the same rule for its legs, and
   this record keeps it.

## 7. Deferrals, each with its reopen gate

| Deferred piece | Reopen gate | Feeds |
| --- | --- | --- |
| the QUIC-ingress lab leg (P1, P4, P5, P7, the h3 hop of P8) | the h3-listener lab leg of section 5, step 2 | the probe map |
| the live QUIC fingerprint read (P2b) | a UDP capture feed; the §12 capture slice | probe P2b |
| the UDP flow slice (P6) | the §12 UDP slice in `bpf/flow_tc.c` | probe P6 |
| the grammar corpus rows (P3) | the Phase 2 h3 analysis surface | probe P3 |
| the socket-plane re-read | a kernel reassembly surface for QUIC at socket altitude | section 5, step 5 |

## 8. Record family

| Record | What it contributes here |
| --- | --- |
| [TR-29 #29](https://github.com/trishula-dev/trishula/issues/29) | the parent question and the posture mandate |
| [TR-44](protocol-conformance-verdict.md), the conformance verdict | the h3 reject verdict (row 7), the h3spec advisory ruling, the honest-boundary method |
| [TR-39d](socket-plane-fast-path.md), the socket-plane note | the transport constraints: TCP hooks only, h3 non-goal, the re-assembly trigger |
| Spec [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes) | the tracked-evaluation pin and the Phase 2 lane |
| [Academy module 5](../../docs/academy/module-5.md), lesson 1 | the posture lesson the record pins |
| [Academy module 2](../../docs/academy/module-2.md), lessons 2 and 5 | the QUIC transport facts and the 0-RTT lesson |
| [TR-28, the module-2 lab](../../lab/module-2/README.md) | the runnable fingerprint-derivation gate behind P2a |
| [TR-26, gateway conformance](../../test/gateway-conformance/) | the view-parity contract rows behind P8 |

## 9. Closure record

- The posture holds 7 facts and 6 coverage rows. The terminator leg stays outside repo
  tests. The engine legs hold the parity abstraction.
- The probe map carries 9 rows. P2a runs live outright. P8 carries a live half and a
  PENDING half. 7 rows read PENDING outright and name their absent pieces.
- The plan files 5 steps. No step opens a build lane in this record.
- The non-claims of section 3 move only on recorded evidence, by PR.
- The parent record [TR-29 #29](https://github.com/trishula-dev/trishula/issues/29)
  closes on this PR. The evaluation continues on the plan of section 5.
