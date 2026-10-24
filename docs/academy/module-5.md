# Academy Module 5 — the frontier: HTTP/3, PQ, and AI abuse

Module 5 of the teach-the-web curriculum. The curriculum map entry
lives in
[spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches).
The pedagogy rules live in
[spec §7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules).

Spec §7.2 pins the frontier scope: PQC is in scope from v1 of the
docs, not of the data plane. The module teaches the 2026 reality and
records every unshipped claim as PENDING with its owning item.

## The lessons

| # | Topic | The bytes on the wire |
|---|---|---|
| 1 | HTTP/3 posture | QUIC packets over UDP; the evaluation pin |
| 2 | PQ key exchange | the X25519MLKEM768 share: 1,216 bytes, not 32 |
| 3 | PQ as signal | hello size and fingerprint deltas, and their spoofability |
| 4 | AI abuse classes | the §14 catalog: request and response classes |
| 5 | The hand-off contract | feature views, never raw packets |
| 6 | Rule anatomy | today's view against the AI-abuse needs |
| 7 | The lab | the verdict vocabulary, the compile gate, the fail-closed leg |

## Lesson 1 — HTTP/3 ingress posture

HTTP/3 runs HTTP over QUIC over UDP. The transport move changes one
boundary of the product posture:

- The kernel shield already sees UDP floods the same way as TCP floods
  ([§9.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#92-hook-inventory)).
  Flood defense keeps its L3/L4 altitude.
- QUIC packet framing needs userspace analysis. The flow classifier
  walks TCP only at v0
  ([`bpf/flow_tc.c`](../../bpf/flow_tc.c)).
- Ingress posture is a tracked evaluation, not a v1 claim. The pin is
  [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes)
  and [TR-29](https://github.com/trishula-dev/trishula/issues/29).

The module teaches the why before the product carries the claim. That
order is the curriculum's own rule (§7.2). HTTP over QUIC keeps the
same request semantics; the bytes move plane, so the analysis point
moves plane with them.

## Lesson 2 — PQ key exchange: the numbers

PQ key exchange arrives client-side, independently of Trishula
(Appendix A, note 1):

- X25519MLKEM768 is the IETF-standardized hybrid group (RFC 10024).
- The client share carries 1,216 bytes, against 32 for bare X25519.
- Chrome 124+ defaults the group on; Firefox 132+, Go 1.24 and
  OpenSSL 3.5 follow. Any stack behind the gateway may already
  negotiate PQ key agreement.
- The motivation is harvest-now-decrypt-later: a recorded session
  stays secret only under a PQ-secure key exchange. That decision
  belongs to the gateway operator, not to the WAF.

Termination altitude holds unchanged: the gateway owns the handshake,
and the engine sees post-termination plaintext, whatever group
negotiated (Appendix A, note 2;
[§6.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#63-non-goals-v1)).
The shield and the engine change no shape. v1 carries no PQ data-plane
claims.

## Lesson 3 — PQ as signal, with caveats

The ClientHello changes stay visible on the wire:

- The hybrid share inflates the ClientHello by roughly 1,200 bytes.
  Multi-packet hellos and middlebox effects are recorded in the field
  (Appendix A, note 3).
- The group offer rides the extension list. JA4 hashes that list. A PQ
  offer changes the fingerprint.
- The PQ preference is client signal, and a spoofable one: an attacker
  offers the group bytes without running the math.

The teaching rule: treat the delta as signal with caveats, never as an
anti-spoofing control. The summary struct mirrors the hello as offered
([`ja4.go`](../../internal/engine/botdef/ja4.go)); the in-repo
fingerprint surfaces read the delta the day a PQ stack appears in
front of the termination hop.

## Lesson 4 — the AI request/response abuse classes

The scenario catalog
([§14.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#141-scenario-catalog))
names the classes:

| Class | The signals | Phase | State |
|---|---|---|---|
| S4 prompt injection / jailbreak | token sequences, instruction patterns | P1+ | PENDING — design, no detector |
| S5 response exfiltration | response volumes versus schema, entropy spikes, PII patterns | P2 | PENDING — design, no response view |
| S1 known-attack classifier | decoded payload features, CRS match context | P1 | PENDING — design, no detector |
| S2 zero-day anomaly | the request feature vector | P1 | PENDING — design, no detector |
| S3 bot / ATO / stuffing | fingerprints plus behavior windows | P1+ | shipped as the bot detectors (Module 4) |

The honest read: the catalog is design, not shipped detectors. The
shipped surfaces today: the request rule surfaces (CRS, CEL, schema —
Module 4, lessons 1 and 2), the verdict vocabulary, and the kernel
write-back path (Module 3, lesson 7). S4 and S5 wait on their own
phases and their own views (lesson 6).

## Lesson 5 — the hand-off contract: ML never reads packets

Spec §14.2 binds every model tier to one rule: ML reads feature views
built from engine and eBPF events. Never raw wire data.

- The extractor builds a versioned FeatureView from the parsed request
  view and the kernel counters
  ([§14.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#142-the-hand-off-contract-ml-never-reads-packets)).
- Inline models stay µs-class trees. Heavy models escalate. The LLM
  judge runs async, suspicious-only, with a cached verdict.
- High-confidence verdicts and ban scores write back to the kernel
  maps. That write-back closes the loop with the ban ladder
  (Module 4, lesson 5).

The contract's hard edge: no model tier touches a packet buffer. The
view boundary keeps every model verdict auditable like the rest.

## Lesson 6 — rule anatomy: today's view against the AI-abuse needs

| Need | The view it wants | State |
|---|---|---|
| body-shaped request rules (`size(request.body.messages) > 128`) | the §11.3 body scope | PENDING — the view carries method, path, query, rate windows |
| response-side exfiltration rules | a response view | PENDING — §14.1 S5, P2 |
| prompt-injection classifiers | feature views over token sequences | PENDING — §14.1 S4, P1+ |

The body wall carries live evidence. The DX1 broken-policy fixture
asks for `size(request.body.messages)`, and the operator compile gate
rejects it with `no such key: body`
([`dx1-broken-pack.yaml`](../../deployment/dx1/manifests/dx1-broken-pack.yaml)).
The lab leg replays that evidence on live traffic (lesson 7).

## Lesson 7 — the lab

Run the lab from a repo checkout:

```bash
bash lab/module-5/run.sh
```

| Leg | Surface | The gate |
|---|---|---|
| verdicts | `go test ./internal/engine/ladder/` — the action vocabulary and resolution semantics | every vocabulary and resolution test holds |
| fail-closed | `go test ./internal/operator/` over the uncompilable-rule oracle and the route-class fail-closed test | an uncompilable policy returns its error and stamps nothing |
| dx1 (opt-in) | `KIND_LAB=1`: the shipped apply-effect scenario, then the operator log and the live traffic read | `COMPILE FAILED dx1/broken-rule-gate` logged; the benign pass and the DX-LAB-001 block both survive |

The DX1 leg runs the shipped
[`lab/dx1/apply-effect.sh`](../../lab/dx1/apply-effect.sh) scenario;
its broken-policy leg is this module's body-view wall, live. The
frontier's other surfaces stay PENDING: no HTTP/3 leg and no PQ leg —
the owning evaluations wait
([TR-29](https://github.com/trishula-dev/trishula/issues/29)). The
full shape: [`lab/module-5/README.md`](../../lab/module-5/README.md).

## The product is the textbook

Spec §7.2 names the product's teaching mechanism: the verdict trace
carries the module link, so a developer reads the lesson at incident
time (the DX5 deliverable in
[§7.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#73-deliverables)).
The verdict vocabulary lives in
[`internal/engine/ladder/ladder.go`](../../internal/engine/ladder/ladder.go).
The generator that ties a verdict to its module is a spec deliverable,
not a shipped surface; this row records the boundary.

## Course links

| Where | Link |
|---|---|
| The academy index | [`docs/academy/README.md`](README.md) |
| The DX1 lab | [`lab/dx1/README.md`](../../lab/dx1/README.md) |
| This module's lab | [`lab/module-5/README.md`](../../lab/module-5/README.md) |
| The ML and adaptive-detection spec | [spec §14](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#14-ml--adaptive-detection) |
| The frontier evaluations | [Appendix A](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-a-roadmap-notes) |
| The remaining map entries | [spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches) |
