# Protocol conformance as a verdict control (TR-44)

> **Trishula verdict record TR-44** — research lane. Parent record:
> [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85). This record
> answers one question: where does protocol conformance sit as a verdict
> control, per protocol version?
>
> **Spec refs:** [§2.3 D3, the ladder](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#23-d3--detection-depth-more-than-negative-signatures) ·
> [§8.3 request lifecycle](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#83-request-lifecycle) ·
> [§9.1 the two-plane principle](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle) ·
> [§9.6 plaintext fast path](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest) ·
> [§9.7 visibility contracts](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode) ·
> [§11.3 CEL as the developer-facing DSL](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#113-cel-as-the-developer-facing-dsl) ·
> [§11.8 CRS differential parity gate](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate) ·
> [§18.2 threats and treatments](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#182-threats-and-treatments) ·
> [Appendix A: roadmap notes](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)

Status: verdict delivered. The record ships no code. It makes no capability claim.

Rule for the word "conformance" in this record: a request that violates HTTP grammar. The
violation itself is an attack signal: request smuggling, frame desync, parser differentials,
malformed frames. Payload attacks inside grammar-legal requests stay CRS material
([§11.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#112-crs-the-correctness-baseline)).

## 1. The question, restated once

The parent record asks three questions. Each answer lands as a table row or a named boundary.

1. Which protocol surfaces does the differential suite cover today?
2. Which verdict class does a conformance violation inherit, per protocol?
3. What does conformance testing add over CRS parity and the spec-anchored tests?

Decision rule: one listed control altitude per protocol surface. No row states a claim that no
repo test pins today. Deferred work names its own build lane, never hides inside prose.

## 2. First fact set: what each plane reads

The verdicts rest on three wire facts. Each fact comes from the repo, not from an assumption.

| # | Fact | Source |
| --- | --- | --- |
| F1 | The engine terminates the steering hop. It reads the protocol the gateway speaks upstream: h1 heads, or h2c frames on `appProtocol: kubernetes.io/h2c` legs. | [§8.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#83-request-lifecycle); `test/gateway-conformance/profile.go` |
| F2 | The parse layers read heads only. No body byte joins a verdict yet. | `internal/engine/http1/http1.go`, `internal/engine/http2/http2.go` (TR-05b, TR-15) |
| F3 | The kernel plane reads no HTTP beyond the advisory window of [§9.6](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest) on plaintext legs. h3 reaches the kernel as datagrams, never as requests. | [§9.7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#97-visibility-contracts-per-mode), [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes) |

### 2.1 The engine parse surfaces today

| Protocol | Package | Grammar the layer rejects (typed errors) | Budget contracts |
| --- | --- | --- | --- |
| HTTP/1.1 | `internal/engine/http1` | 12 error values: empty input, 8 KiB line limit, 100-line limit, 16 KiB head limit, method token, target form, version presence, version slice {HTTP/1.0, HTTP/1.1}, header field grammar, obs-fold, missing CRLF, NUL byte | fixed read budgets; values test with `errors.Is`; no panics |
| HTTP/2 | `internal/engine/http2` | pseudo-header completeness, HPACK stream errors, connection-level frame errors, GOAWAY, mid-frame truncation, read deadline, frame budget | `MaxFrames` walk cap; deadline clock injected; HPACK state on one Framer |

The h2 layer takes its frame codec from `golang.org/x/net/http2` (Framer + `ReadMetaHeaders`).
Frame and HPACK grammar arrive from the maintained stack. The engine adds the head contract:
pseudo headers fold into named fields, housekeeping frames consume silently, DATA never joins a
view.

The h1 layer carries a boundary the record must name now. It rejects token, line and version
classes. It carries no message-framing semantics: `Content-Length` and `Transfer-Encoding` values
travel as map values, unchecked. Verdict row 2 and the boundary list both return to this fact.

## 3. The verdict table

One row per protocol surface. The verdict column uses the design-note vocabulary: adopt, adapt,
keep, reject, defer.

| # | Surface | Control altitude | Verdict |
| --- | --- | --- | --- |
| 1 | h1 head grammar (RFC 9112 line and token classes) | engine parse layer | adopt — live since TR-05b; the 12 typed errors pin the classes |
| 2 | h1 framing semantics (CL/TE conflict, duplicate CL, coding validity) | engine parse layer, next slice | defer — named build item; no check exists today |
| 3 | h1 first-line anomalies at kernel | [§9.6](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest) advisory window | keep — advisory only; the engine re-parses authoritatively |
| 4 | h2 frame and HPACK grammar on the upstream leg | engine parse layer over the x/net stack | adopt — grammar from the stack, head contract from the engine |
| 5 | h2 client-hop grammar (ALPN h2 at the terminator) | terminator territory | keep — the engine never sees those frames (fact F1) |
| 6 | h2 stream and connection error discipline | engine parse layer | adopt — per-stream absorb, terminal connection errors |
| 7 | h3/QUIC conformance as engine work | none | reject — no engine surface exists; terminator and QUIC stack own it ([Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)) |
| 8 | wire-class enforcement of repeat protocol abuse | engine writes [§9.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state) maps, shield enforces | keep — the kernel never parses; the engine never drops on wire alone |
| 9 | external conformance suites (h1spec, h2spec, h3spec) | offline lab probes, advisory | adapt — never runtime verdict inputs ([§5.1](#51-the-tooling-survey-stated-once)) |

## 4. The verdict classes each protocol inherits

The ladder action vocabulary carries 5 values: `allow`, `log`, `block`, `challenge`, `ban`
(`internal/engine/ladder/ladder.go`). One structured view serves all protocols. The
`engine:same-view-parity` row pins that abstraction: the upstream protocol stays invisible to the
ladder.

Enforcement posture at the tracked slice: the reference ladder logs, never enforces (TR-05
posture). The table below states the class mapping. The enforcement flip stays a per-route policy
decision, not a rewrite of the mapping.

| Violation class | Example shapes | Verdict class | Kernel role |
| --- | --- | --- | --- |
| h1 grammar violation | obs-fold line; NUL byte; token outside `tchar` | reject at request: `block`, local 4xx | none |
| h1 framing ambiguity | `Content-Length` + `Transfer-Encoding` together; duplicate CL values | reject at request; close discipline stays at the gateway | none — check absent (row 2) |
| h2 per-stream protocol error | missing pseudo header; HPACK stream error | log-class absorb; the connection keeps its other heads | none |
| h2 connection-level error | header list over budget; HPACK connection failure | close the walk; the gateway sees the teardown | none |
| repeat protocol abuse | grammar-violation rate per source | feeds the S6 ban score; bans flow engine → [§9.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state) map → XDP/TC | enforces |
| advisory window anomaly | duplicate CL in the window; oversize first line | advisory tag; the engine re-parse decides | none ([§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle): decision-free) |

Three boundary statements follow from [§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle).

1. No per-request wire drop exists for a grammar violation. The kernel stays decision-free.
2. The wire-class path holds one entry: engine-written bans. Single violations never reach it;
repeat scores do.
3. The `challenge` action stays bot-plane material ([§12](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#12-bot-defense--anti-automation)).
A parse error carries no evidence-of-work shape. Grammar violations map to `block` only.

## 5. What conformance testing adds over CRS parity and the spec-anchored tests

The repo runs two protocol-adjacent gates today. Name them precisely, then state the addition.

| Gate | What it pins | Coverage class |
| --- | --- | --- |
| CRS differential parity ([§11.8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate); `test/crs-differential`) | verdict-level parity: block/log/pass + rule ids + scores, reference evaluator vs engine mirror and matcher (gate README pins 19/19 runnable parity; matcher 8 active patterns at 100% parity) | payload semantics on grammar-legal requests: 20 h1-shaped corpus cases |
| Engine-leg gateway conformance (`test/gateway-conformance`) | 4 contract rows: `engine:same-view-parity`, `engine:h2c-ingress`, `engine:grpc-recognized`, `engine:plain-backend-view` | protocol abstraction: one view per logical request across h1 and h2c |

Neither gate owns the grammar-illegal request class. The CRS corpus sends clean framing by
construction. The gateway lane reads a shape contract, not a MUST set. Conformance testing adds
the third class: grammar-illegal requests as corpus rows with pinned verdict cells.

| Addition | Corpus source | Gate |
| --- | --- | --- |
| h1 grammar rows: the 12 typed errors ↔ RFC 9112 and RFC 9110 MUST shapes (§5.1 colon-whitespace `400`; §5.2 obs-fold; §6.1 framing-conflict close; §6.3 coding rules) | the `http1_test.go` taxonomy, extended per row | `go test ./internal/engine/http1/`, then the differential corpus once it gains illegal-request rows |
| h2 grammar rows: malformed pseudo headers, HPACK failures, frame floods → absorb-or-terminal cells | `http2_test.go` cases: absorbed stream errors, terminal connection errors, budget yields | `go test ./internal/engine/http2/` |
| framing-semantic rows: CL/TE conflict shapes | a build slice; RFC 9112 §6.1 and §6.3 name each MUST | none today — the row names a missing class, never a fake gate |

The composition rule holds across the three gates: CRS reads payload signals on legal requests.
The conformance rows pin the illegal-request class. Rule families never bridge that gap: the
[socket-plane census, part 3](socket-plane/3-census.md), sizes the 921 protocol-attack family at
2 of 17 rules expressible at kernel altitude, 15 userspace. Grammar checks are parse-layer
material, never rule material.

[§18.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#182-threats-and-treatments)
already names the treatment for parser-differential bypass: strict RFC 9112 normalization,
reject-on-ambiguity, `tx.flags`, smuggling corpus inside the §11.8 suite. This record supplies the
placement decision behind those words: grammar corpus rows live at the parse layer, mapped to the
verdict cells in §4. The
[academy module 1](../../docs/academy/module-1.md) already teaches the desync lessons; the
corpus rows give those lessons runnable pins.

### 5.1 The tooling survey, stated once

| Source | What it carries | Verdict |
| --- | --- | --- |
| RFC 9110 §8.6, RFC 9112 §5–§6 | the MUST set: colon-whitespace `400`, framing-conflict close, non-final chunked `400`, invalid CL `400` + close | corpus-row source of truth for rows 1 and 2 |
| RFC 9113 | the h2 frame contract; the h2 desync context | borrow the stack grammar; pin the absorb-or-terminal behavior |
| RFC 9114, RFC 9204 | h3 message grammar; QPACK | out of engine scope (row 7) |
| PortSwigger desync canon | the attack classes behind CL/TE desync | names row-2 corpus shapes; [§18.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#182-threats-and-treatments) stays the spec anchor |
| h2spec, h3spec, h1spec | offline server conformance probes over live sockets | advisory probes on the lab leg only; never `go test ./...`; never runtime inputs |
| Go `net/http`, the x/net h2 stack | the borrowed strictness: the reject set the engine inherits | pin through parser tests, not through tool output |

The offline-vs-runtime decision, as verdict rows:

1. In-repo corpus rows over the repo's own parser: adopt, as the CI-blocking class.
2. Socket-opening tools (h1spec, h2spec, h3spec): adapt as advisory lab probes. The parse layers
read reassembled bytes, not sockets. Tool output has no path into a verdict.
3. Runtime conformance signal: the parse-error → typed-error → action mapping only.
4. A kernel protocol-conformance mechanism: reject. [§9.6](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest)
stays advisory. [§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle)
holds.

## 6. The honest boundary — this record does NOT

1. No framing-semantic check is built. `Content-Length` + `Transfer-Encoding` conflicts, duplicate
CL values, transfer-coding validity: the header map carries them unchecked today. Row 2 defers
them to a build slice.
2. No body-path surface is claimed. Both parse layers read heads only. TE.CL body desync has no
body reader to attack yet.
3. No `tx.flags` carrier ships here. The spec view names `tx.flags.smuggling_suspect` (§11.3
sketch). The compiled CEL env declares `method`, `path`, `query`, `rate_windows` only. The
`Verdict` struct carries no flags field. Flag material stays spec-view until a consuming stage
lands.
4. No h2 request-smuggling detection is claimed. The engine inherits the vendored stack's
rejections only. The h2 desync literature earns no engine claim from this record.
5. No h3 engine work happens. The kernel sees datagrams only: flood and ACL classes
([Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)).
No request view exists for h3 at any plane of the reference topology.
6. No kernel parse work appears. [§9.6](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#96-plaintext-fast-path-in-kernel-bounded-honest)
stays advisory; [§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle)
keeps the kernel decision-free.
7. No `request.proto_version` field enters the compiled view. The CEL env carries 4 fields. The
engine view structs carry a `Version` (h1 per-request string; h2 constant `HTTP/2.0`). The
view-growth rule gates any addition: a consuming rule names the need first.
8. No socket-opening suite enters CI. h1spec, h2spec and h3spec stay lab-leg probes.
9. No code and no test ships in this lane. The stretch item (h1 RED wiring) is recorded in the
addition table, not executed here.

## 7. Deferrals, each with its reopen gate

| Deferred decision | Reopen gate | Feeds |
| --- | --- | --- |
| h1 framing-semantic checks: CL/TE conflict, duplicate CL, coding validity, as typed errors plus corpus rows | a build issue files the RFC 9112 §6 MUST set | verdict row 2 |
| `request.proto_version` in the compiled view | a consuming rule names the need | [§11.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#113-cel-as-the-developer-facing-dsl) view growth |
| `tx.flags` carrier | a consuming stage lands (ban or telemetry) | §11.3 view sketch |
| advisory h2spec/h3spec runs | a lab leg serves the engine socket | §5.1 |
| h3 posture | a QUIC-ingress topology lands | [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes) |

## 8. Record family

| Record | What it contributes here |
| --- | --- |
| [TR-44 #85](https://github.com/trishula-dev/trishula/issues/85) | the research question and the survey list |
| [TR-39c, socket-plane census part 3](socket-plane/3-census.md) | the 921 family sizing; the CRS/CEL altitude method |
| [TR-07b differential harness](../../test/crs-differential/README.md) | the gate precedent: corpus shape, parity math, pinned census |
| [TR-26 gateway conformance lane](../../test/gateway-conformance/) | the engine-leg view rows the conformance class joins |
| [Academy module 1](../../docs/academy/module-1.md) | the desync lessons the corpus rows will pin |
