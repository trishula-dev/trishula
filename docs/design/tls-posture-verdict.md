# Kernel-altitude TLS posture — the kTLS/no-key capability matrix (TR-41)

> **Trishula verdict record TR-41** — the research verdict for
> [TR-41 #53](https://github.com/trishula-dev/trishula/issues/53). One question drives the
> record. Which verdicts can the kernel planes detect and enforce on TLS legs, per TLS
> operating model? The matrix (section 4) prices each policy class per model. The
> key-handling boundary (section 5) and the anti-model (section 7) carry the custody facts.
> The posture decision (section 6) composes the [TR-39a](socket-plane/1-mechanism.md)
> mechanism record with the [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85)
> h3/QUIC terminator-territory row. This lane merges no code.
>
> **Spec refs:** [§6.3 non-goals (v1)] · [§9.1 the two-plane principle] ·
> [§9.2 hook inventory] · [§9.3 maps and state] · [§9.4 ring sizing] ·
> [§9.5 kernel-side rate accounting] · [§9.6 plaintext fast path] ·
> [§9.7 visibility contracts per mode] · [§9.9 socket-plane fast path] · [§11.5 positive security] · [§12.1 detector families] ·
> [§12.3 honest limits] · [§13.4 enforcement actions by tier] · [§17 performance targets] ·
> [§18.2 threats and treatments] · [§20.1 risk register] · [Appendix A: roadmap notes]

[§6.3 non-goals (v1)]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#63-non-goals-v1
[§9.2 hook inventory]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory
[§9.1 the two-plane principle]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle
[§9.3 maps and state]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state
[§9.4 ring sizing]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#94-ring-buffer-sizing-and-backpressure
[§9.5 kernel-side rate accounting]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#95-kernel-side-rate-accounting-feed-13
[§9.6 plaintext fast path]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest
[§9.7 visibility contracts per mode]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode
[§9.9 socket-plane fast path]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment
[§11.5 positive security]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#115-positive-security-schema-and-api-discovery
[§12.1 detector families]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#121-detector-families
[§12.3 honest limits]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#123-honest-limits
[§13.4 enforcement actions by tier]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#134-enforcement-actions-by-tier
[§17 performance targets]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#17-performance-targets--benchmark-plan
[§18.2 threats and treatments]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#182-threats-and-treatments
[§20.1 risk register]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#201-risk-register
[Appendix A: roadmap notes]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes

Status: verdict record. The record ships no code and makes no capability claim. The
[§9.9 socket-plane fast path] contract holds across the record family: tracked evaluation,
not a v1 commitment. Model A lands nowhere at this tree. Every cell below prices
availability on the record set. The honest boundary (section 10) files every gap.

## 1. The question and the method

The parent issue asks one question. Which verdicts can the kernel planes detect and enforce
on TLS traffic? The answer depends on one property of the leg: who terminates TLS and where
the session keys live. [§9.7 visibility contracts per mode] pins 2 operating models on that
property. The record prices each policy class per model and records the custody boundary.

Method:

1. The record restates the 2 models once, from [§9.7 visibility contracts per mode]
   (section 2).
2. The record lists the signal facts with sources. No signal enters without a source
   (section 3).
3. The matrix carries one cell per policy class per model. The cell vocabulary carries 4
   values (section 4).
4. The key-handling boundary carries the custody, blast-radius and rotation facts
   (section 5).
5. The posture decision records the Model A/Model B split with rationale (section 6).
6. The record rejects the key-extraction anti-model with no trigger and no build lane
   (section 7).
7. The composition table carries one row per decision. Every row names its owning record
   (section 8).
8. The honest-boundary list states what the record does not claim (section 10).

Cell method (the [TR-47 #194](https://github.com/trishula-dev/trishula/issues/194)
precedent, section 6 of that record): a stamp names traversal and never claims detection.
The matrix uses the same rule. A cell without a landed mechanism reads at most `recorded`.
It never reads `enforce`.

## 2. The two operating models, stated once

[§9.7 visibility contracts per mode] pins the models. The statement here adds no fact.

**Model A — kernel plaintext via the kTLS handoff.** Trishula owns TLS termination on the
leg. The spec scope: the engine secondary mode (TR-34, feature-gated) or pod mTLS. kTLS is
the kernel's TLS record layer on a TCP socket. The control plane performs the handshake and
holds the session keys. It installs the crypto state with the `TLS_TX`/`TLS_RX` upper-layer
protocol (`setsockopt`). strparser then delineates the records and decrypts them. `SK_SKB`
and `SK_MSG` programs read plaintext, message-delineated traffic. The full TR-39 policy
surface applies there ([TR-39a](socket-plane/1-mechanism.md), sections 2 to 4).

**Model B — no-key, metadata-only.** Termination is external to Trishula (the default
gateway leg). The kernel reads ciphertext and metadata only. The signal set: the
pre-encryption ClientHello (the first TLS handshake message; it travels unencrypted by TLS
design), carrying SNI, ALPN and the JA3/JA4 fingerprint bytes (the TLS client fingerprint
formats); certificate-chain metadata after the ServerHello; TLS record framing — record
sizes, timing and inter-arrival. Framing feeds behavioural detectors (TR-31) and the
rate/ban plane (TR-09, TR-10). Header and body bytes stay invisible.

**The leg note.** The matrix prices the kernel planes only. The engine tier sits outside
the matrix. The ladder evaluates every request at one tier, always
([TR-39b](socket-plane/2-failopen-ladder.md), section 1). The [§9.6 plaintext fast path]
serves plaintext legs. It never names TLS-leg work.

## 3. The signal facts, with sources

| # | Fact | Source |
| --- | --- | --- |
| F1 | eBPF cannot decrypt TLS without key custody. Record framing is visible. Payload bytes are not. | [§9.1 the two-plane principle], [§9.7 visibility contracts per mode] |
| F2 | ClientHello bytes precede encryption. SNI, ALPN and fingerprint bytes read at XDP/TC altitude. | [§9.7 visibility contracts per mode] Model B; issue #53 |
| F3 | The Model A handoff: the control plane holds the keys; `TLS_TX`/`TLS_RX` hands crypto state to the kernel; strparser decrypts records for `SK_SKB`/`SK_MSG` programs. | kernel TLS offload docs; [TR-39a](socket-plane/1-mechanism.md) section 7 |
| F4 | The price: session keys turn kernel-resident and process-readable on the node. | [§9.7 visibility contracts per mode]; TR-39a section 7 |
| F5 | Model B enforcement ceiling: connection- and fingerprint-level verdicts (SNI allowlist, JA4 blocking, rate, ban). | [§9.7 visibility contracts per mode] Model B |
| F6 | QUIC runs over UDP and terminates in userspace today. A QUIC leg yields no kernel reassembly surface at socket altitude. | [§9.9 socket-plane fast path] recorded constraints; [TR-39d](socket-plane-fast-path.md) section 3.2 |
| F7 | The always-on set never reads keys: XDP ACL, flood classes, ban-table hits and kernel rate counters. | [§9.1 the two-plane principle], [§9.3 maps and state], [§9.5 kernel-side rate accounting] |
| F8 | CRS payload evaluation stays at the engine on every leg. Kernel CRS evaluation is rejected. | [TR-39c](socket-plane/3-census.md) section 5 |

## 4. The capability matrix

Rule: one cell per policy class per model. The cell states kernel-altitude availability on
the leg each model names. The matrix is the claim surface for TLS posture: every docs or
site claim about TLS-leg capability cites a cell (issue #53, proposal 4).

Cell values:

- `enforce` — a landed record carries the mechanism at kernel altitude on that model.
- `observe` — the leg yields a live kernel signal. The verdict stays userspace.
- `recorded` — the spec or a record pins the class for that model. No mechanism lands. A
  build lane owns the work.
- `none` — no kernel signal exists for the class on that leg.

`recorded` never reads `enforce`. A cell that names no landed mechanism reads at most
`recorded` (the TR-47 cell method). Every `recorded` cell names its gate; the deferrals of
section 9 carry the gates.

| # | Policy class | Model A (kTLS plaintext) | Model B (no-key metadata) | Basis |
| --- | --- | --- | --- | --- |
| 1 | L3/L4 ACL and flood defense | enforce | enforce | F7; [TR-03 #3](https://github.com/trishula-dev/trishula/issues/3) |
| 2 | Ban-table enforcement (engine-issued bans) | enforce | enforce | F7; [§9.3 maps and state], [§13.4 enforcement actions by tier]; [TR-10 #10](https://github.com/trishula-dev/trishula/issues/10) |
| 3 | Rate counters, connection band (SYN, UDP) | enforce | enforce | F7; [§9.5 kernel-side rate accounting] |
| 4 | Rate counters, request band | enforce — plaintext-leg request-start rates | none — a TLS record is not a request | [§9.5 kernel-side rate accounting]; F1 |
| 5 | Route marking | recorded — the TR-40b load gate landed; surface fields pending | none — path bytes are ciphertext | [TR-40a](socket-plane/4-compiler-census.md) class set; F1 |
| 6 | JWT claim allowlists (header-class) | recorded — hash gate locked | none — token bytes are ciphertext | [TR-40a](socket-plane/4-compiler-census.md) gate column; F1 |
| 7 | JWT signature verification | none — no kernel crypto | none — never kernel work | [§9.1 the two-plane principle]; [TR-45](auth-jwt-verdict.md) section 2 |
| 8 | RBAC allowlist, source IP and port | enforce | enforce | F7; [§9.3 maps and state] ACL maps |
| 9 | RBAC allowlist, path | recorded — surface fields pending | none — path bytes are ciphertext | [TR-40a](socket-plane/4-compiler-census.md); F1 |
| 10 | Telemetry counters | recorded — counter declarations pending | observe — metadata-band ring events | [TR-40a](socket-plane/4-compiler-census.md); [§9.4 ring sizing] |
| 11 | Header mutation | recorded — the write primitive bounds the class | none — no header reads exist | [TR-40a](socket-plane/4-compiler-census.md); F1 |
| 12 | CRS payload evaluation | none — engine class on every leg | none — same cell | F8; [TR-39c](socket-plane/3-census.md) section 5 |
| 13 | Positive security (OpenAPI schema) | none — engine class on every leg | none — same cell | [TR-39c](socket-plane/3-census.md); [§11.5 positive security] |
| 14 | Bot defense, ClientHello band (JA3/JA4) | recorded — parser lands in build lane D1 | recorded — [§9.7 visibility contracts per mode] pins the verdict class | F2; F5; [§12.1 detector families]; [§12.3 honest limits] carries the forgeability limit |
| 15 | Bot defense, header-shape band | observe — plaintext headers reach the socket plane | none — HTTP headers are ciphertext | F1; [TR-12 #12](https://github.com/trishula-dev/trishula/issues/12) (the S5 owner) |
| 16 | Bot defense, behavioural band | observe — message shapes at socket altitude | observe — record sizes and timing only | F2; [TR-31 #31](https://github.com/trishula-dev/trishula/issues/31) |

Reading notes:

- Rows 1 to 3 and 8 carry identical cells per model. Those planes never read keys (F7).
- Rows 12 and 13 stay `none` on both models. The engine owns CRS and schema evaluation on
  every leg; the kernel reads no payload bytes (F8, F1).
- Row 14 carries the TR-41 build boundary. The ClientHello signal reads live today. The
  [§9.7 visibility contracts per mode] statement pins the verdict class. The parser rides
  build lane D1. No parser ships in this lane.
- Every `recorded` cell names its gate in section 9. No deferral carries a schedule.

### 4.1 The h3/QUIC gap, stated explicitly

QUIC runs over UDP. No kernel reassembly surface exists at socket altitude (F6). No matrix
cell exists for h3 request classes: on both models the class set reads `none`. The request
never forms at kernel altitude. [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85)
row 7 already places h3/QUIC conformance in terminator and QUIC-stack territory; row 5 of
that table names the territory class ("terminator territory"). This record reuses the
territory rule: the TLS terminator owns what the kernel cannot see. TR-29
([#29](https://github.com/trishula-dev/trishula/issues/29)) owns the h3 posture evaluation.
The gap is explicit here, in [Appendix A: roadmap notes] and in
[TR-39d](socket-plane-fast-path.md) section 3.2.

## 5. The key-handling boundary

Model A moves TLS keys into the kernel and onto the node.
[§9.7 visibility contracts per mode] routes the threat model, the blast radius and the
rotation duties to the design-note gate. This record is that gate. It writes the facts
below.

**Custody.** The control plane performs the handshake. It holds the session keys. It hands
Tx/Rx crypto state to the kernel via the `TLS_TX`/`TLS_RX` upper-layer protocol. After the
handoff, the keys stay kernel-resident on the node (F3, F4). The control plane sits in the
Go shield (TR-39a section 6).

**Blast radius.** The keys read as process state on the node. A node compromise reads every
session key that terminated on that node. Node trust therefore bounds every Model A
guarantee. TLS guarantees degrade to node-trust guarantees on Model A legs.
[§18.2 threats and treatments] carries the node-compromise class. Model A moves TLS state
into that blast radius.

**Rotation.** Session keys are per-connection TLS state. Connection turnover produces
fresh keys. No cross-connection key reuse exists. Certificate and CA custody comes with
termination ownership; mTLS adds the CA-estate duties. The operator extends the secret
estate to every terminating node.

**Ownership.** [§6.3 non-goals (v1)] keeps the gateway as the estate's terminator. The
[§20.1 risk register] R4 row records the cost and the default: engine-owned TLS doubles
certificate management, so it stays optional and feature-gated. Model A rides the TR-34
secondary mode ([#34](https://github.com/trishula-dev/trishula/issues/34)) or pod mTLS.
Termination ownership never flips silently, and never displaces gateway-owned termination.

## 6. The posture decision

Decision: **Model B is the default kernel TLS posture. Model A is the integration mode of
the socket-plane fast path, feature-gated behind TR-34.**

Rationale, stated once:

1. The gateway leg is the estate default ([§6.3 non-goals (v1)]); the kernel posture must
   hold there first, with no key custody.
2. Model A trades key custody for plaintext. The trade is real: the full TR-39 policy
   surface applies nowhere else. The [§20.1 risk register] R4 row prices the operational
   cost (certificate management doubles).
3. The trade needs operator consent through an explicit feature gate. The gate never
   defaults on. TR-34 carries the gate.
4. [§9.9 socket-plane fast path] stays a tracked evaluation. Model A is the integration
   mode of a tracked evaluation, not a v1 commitment.
5. The two models compose with the ladder: the fast path is tier one of enforcement, never
   the enforcement ([TR-39b](socket-plane/2-failopen-ladder.md), section 1). Model B legs
   lose nothing above tier one: evaluation degrades forward, never sideways.

## 7. The anti-model — key extraction, rejected

[§9.7 visibility contracts per mode] states the boundary. This record files it as a
rejection with no trigger.

- The mechanism class: out-of-band harvesting of session keys from application memory —
  SSLKEYLOGFILE-style extraction, memory scraping.
- The verdict: **reject**. It is an anti-pattern for a control-plane product. No
  implementation exists. No claim exists. No build lane exists.
- No re-evaluation trigger files. A posture change needs a new record with a named
  trigger, like the kernel-module trigger of TR-39a section 9.
- Adjacency, clarified once: [§9.2 hook inventory] carries an optional per-workload uprobe
  row for `SSL_read`/`SSL_write` tracing where termination happens inside an app pod. That
  row observes plaintext buffers at an app boundary. It extracts no keys. It stays outside
  this record and outside this matrix.

## 8. The composition record

One row per component. The verdict vocabulary matches the socket-plane record: `adopt`,
`adapt`, `keep`, `reject`, `defer`.

| Component | Record | Verdict | Boundary carried |
| --- | --- | --- | --- |
| kTLS/strparser handoff as the Model A mechanism | [TR-39a](socket-plane/1-mechanism.md) section 7 | adopt with scope | Model A legs only; the gateway leg keeps Model B semantics |
| Model B metadata signal set | [§9.7 visibility contracts per mode]; F2 | adopt | signals only; payload reads stay out |
| Model B enforcement ceiling | [§9.7 visibility contracts per mode]; F5 | adopt | connection- and fingerprint-level verdicts; never header or body classes |
| The capability matrix as the claim surface | this record, section 4 | adopt | every TLS-leg capability claim cites a cell |
| The cell method (absent reads absent) | [TR-47 #194](https://github.com/trishula-dev/trishula/issues/194) section 6 | keep | `recorded` never reads `enforce` |
| Key custody, blast radius and rotation | this record, section 5 | adopt | the design-gate precondition for any Model A slice |
| Termination ownership | [§6.3 non-goals (v1)]; [§20.1 risk register] R4; [TR-34 #34](https://github.com/trishula-dev/trishula/issues/34) | keep | the gateway owns termination by default; Model A stays feature-gated |
| Key-extraction anti-model | [§9.7 visibility contracts per mode]; issue #53 | reject | out of design scope; no implementation, no claim, no trigger |
| JA4 ClientHello parser at TC ingress | issue #53, proposal 3 | defer | build lane D1; feeds the TR-03/TR-12 fingerprint path |
| Record-framing telemetry hooks | issue #53; [TR-31 #31](https://github.com/trishula-dev/trishula/issues/31) | defer | build lane D2 |
| h2 transport constraint (zero-size dynamic table; Huffman stays) | [TR-39d](socket-plane-fast-path.md) section 3.1 | keep | unchanged by this record; Model A legs inherit it on the fast path |
| h3/QUIC at kernel altitude | [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85) row 7; TR-39d section 3.2; [Appendix A: roadmap notes] | keep | terminator territory; [TR-29 #29](https://github.com/trishula-dev/trishula/issues/29) owns the posture evaluation |

## 9. The deferrals and their re-open gates

| Deferred work | Gate | Feeds |
| --- | --- | --- |
| D1: JA4 ClientHello parser at TC ingress | a build slice files from this record; a kind-node run per the exit criteria; the integration point is the shield fingerprint path | [TR-03 #3](https://github.com/trishula-dev/trishula/issues/3), [TR-12 #12](https://github.com/trishula-dev/trishula/issues/12) (the S5 feed) |
| D2: record-framing telemetry hooks (sizes, timing) | a build slice; consumes the F2 framing signals | [TR-31 #31](https://github.com/trishula-dev/trishula/issues/31) behavioural detectors |
| D3: the Model A feature gate | TR-34 lands; the [§9.9 socket-plane fast path] tracked-evaluation bar; a recorded PRE/POST pair per the [TR-39d](socket-plane-fast-path.md) section 4 protocol before any fast-path claim | [TR-39a](socket-plane/1-mechanism.md) section 7 scope |
| D4: the JWT HS256 kernel path | upstream hash/encode kfunc coverage (TR-39a section 9 trigger); never on demand | the [TR-40a](socket-plane/4-compiler-census.md) gate column; row 6 |
| D5: the h3/QUIC posture | the TR-29 #29 evaluation; a QUIC-ingress topology; a kernel QUIC reassembly surface (the TR-39d section 3.2 trigger) | the section 4.1 gap statement |

## 10. The honest boundary — this record does NOT

1. No code, no parser and no kernel program ships. This lane files verdicts only.
2. The `enforce` cells name the landed set only: TR-03 ACL and flood rows, TR-10 ban
   enforcement and the [§9.5 kernel-side rate accounting] counters. No new mechanism rides
   this record.
3. Model A ships nowhere at this tree. The secondary mode stays feature-gated (TR-34).
   The fast path stays a tracked evaluation ([§9.9 socket-plane fast path]).
4. No "decrypt TLS without keys" claim exists in this record, and no surface may cite one.
   F1 states the boundary: no key custody means no payload reads.
5. No key-extraction item files. Section 7 records the rejection with no trigger. A posture
   change needs a new record with a named trigger.
6. No measured number rides this record. No wall, no fraction, no throughput claim. Every
   performance claim follows the [TR-39d](socket-plane-fast-path.md) section 4 protocol,
   after a recorded PRE/POST pair.
7. This record claims no h3 or QUIC kernel capability. Section 4.1 carries the gap. TR-29
   owns the evaluation ([#29](https://github.com/trishula-dev/trishula/issues/29)).
8. No map family and no ladder change rides this record. The matrix adds no map family
   (TR-39a section 5). The [§9.3 maps and state] set stays closed. The TR-39b ladder
   contract stays untouched.
9. The matrix is not an implementation plan. `recorded` and `observe` cells carry unlanded
   work. Section 9 names each gate; no deferral carries a schedule.
10. The engine tier sits outside the matrix. Model B loses nothing engine-side: the ladder
    evaluates every request at one tier, always ([TR-39b](socket-plane/2-failopen-ladder.md)
    section 1).

## 11. The record family

| Record | What it contributes here |
| --- | --- |
| [TR-41 #53](https://github.com/trishula-dev/trishula/issues/53) | the research question; the exit criteria; the capability-model proposal |
| [TR-39a](socket-plane/1-mechanism.md) | the mechanism; the Model A scope; the hash gate; the anti-module decision |
| [TR-39b](socket-plane/2-failopen-ladder.md) | the ladder totality; the fail-open contract |
| [TR-39c](socket-plane/3-census.md) | the CRS altitude rejection (F8) |
| [TR-39d](socket-plane-fast-path.md) | the transport constraints; the performance protocol; the h3 trigger |
| [TR-40a](socket-plane/4-compiler-census.md) | the class set; the gate column; the surface-growth rows |
| [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85) | the terminator-territory rows (5 and 7) |
| [TR-45](auth-jwt-verdict.md) | the auth boundary: verification is a precondition; no kernel crypto |
| [TR-47 #194](https://github.com/trishula-dev/trishula/issues/194) | the stamp honesty rule; the cell method precedent |
| [§9.7 visibility contracts per mode] | the two-model contract; the Model B ceiling; the anti-model statement |

## References

- The research issue: [TR-41 #53](https://github.com/trishula-dev/trishula/issues/53)
- The parent socket-plane record: [TR-39 #51](https://github.com/trishula-dev/trishula/issues/51)
- The sibling research verdicts: [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85),
  [TR-45 #86](https://github.com/trishula-dev/trishula/issues/86),
  [TR-47 #194](https://github.com/trishula-dev/trishula/issues/194)
- The h3 posture item: [TR-29 #29](https://github.com/trishula-dev/trishula/issues/29)
- The source study: Beeline — "Enforcing Application-Layer Policies in eBPF"
  (arXiv:2605.31084)
- [kTLS offload](https://docs.kernel.org/networking/tls-offload.html) — the kernel TLS
  record layer, the `TLS_TX`/`TLS_RX` ULP and the offload constraints
- [strparser](https://docs.kernel.org/networking/strparser.html) — the record delineator
  the Model A path uses
- [JA4 fingerprint](https://github.com/FoxIO-LLC/ja4) — the ClientHello fingerprint format
