# Trishula in 10 minutes: two attacks, three altitudes

> What you are looking at: the same two requests an attacker would send,
> seen by the three altitudes Trishula separates — the **wire** (kernel,
> per-flow truth), the **request** (negative security, the CRS layer),
> and the **API** (positive security: is this request allowed *for this
> principal*?). Everything below runs on merged engine code
> ([TR-02](https://github.com/trishula-dev/trishula/issues/2),
> [TR-03](https://github.com/trishula-dev/trishula/issues/3),
> [TR-04](https://github.com/trishula-dev/trishula/issues/4)); the
> transcript of the recorded run is on
> [issue #83](https://github.com/trishula-dev/trishula/issues/83).

## The attacks

**A. Classic payload attack (CRS layer).** `GET /download?file=../../../etc/passwd`
— path traversal, [CRS 930120 / 930100](https://coraza.io/docs/tutorials/walkthrough) class.
No API semantics required; any evaluator holding OWASP CRS rules rejects
it on shape alone. In Trishula this is ladder stage S2: CRS runs as the
community correctness baseline [§11.2](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#112-crs-the-correctness-baseline),
and the verdict joins the ladder's combined decision — the demo shows the
reference verdict Coraza computes for the captured bytes.

**B. BOLA (API1:2023 — the #1 API risk).**
`GET /api/v1/orders/2002` with tenant-a credentials, where order `2002`
belongs to tenant-b. The request is *flawless HTTP* — CRS gives it a
clean bill of health, because object-level authorization is not a
signature problem: it is a policy question only your API can answer
[§11.3](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#113-cel-as-the-developer-facing-dsl).
In Trishula that question is one CEL expression over the request view
(`resource.owner == request.auth.subject`), evaluated cost-budgeted, and
the decision is emitted as a [`trishula.verdict.v1`](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#15-telemetry--observability)
record.

**C. Enforcement (what the attacker experiences next).** Repeat offenders
cross the ban threshold; the shield writes a source ban to the kernel and
the connection dies **in TC, before userspace, before the request ever
reaches the app** — [§13](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#13-the-shield-kernel-plane)
on merged code: `TC_ACT_SHOT`.

## Run it

```sh
# Linux (VM or box): kernel ≥5.15 with BTF, root, Go 1.23+
go build -o /tmp/attackdemo ./cmd/attackdemo      # cross: GOOS=linux
go build -o /tmp/flow_tc.o ./internal/engine/ingest # merged TR-04d object
sudo env DEMO_BIN=/tmp/attackdemo ./lab/demo-attack.sh
```

The script prints, per attack: the wire exchange, the evaluator verdicts,
the kernel's own view of the flow, and the enforcement evidence. The
harness under it (veth pair, TC filter, pinned maps) is the same one the
[E2E tests](https://github.com/trishula-dev/trishula/blob/main/lab/README.md) use.

## What runs merged vs what the demo computes demo-side

| Piece | Status |
|---|---|
| Kernel flow events → ringbuf → decodable `FlowEvent` | **merged** (TR-04) |
| CEL rule engine, cost-budgeted (seed pack) | **merged** (TR-02) |
| Ban map + loader ABI, kernel drop on live ban | **merged** (TR-03) |
| Coraza/CRS verdict for captured bytes | reference-side here; **wired into the ladder by TR-07** |
| BOLA rule as an engine expression | demo-computed; the view it needs lands with **TR-05** |
| Ban *decisions* (thresholds, tiers) | **TR-09/10** — the kernel drop is live, the decider isn't yet |

That honesty table is the point: nothing in the demo pre-tends to be
enforced that isn't; everything labelled merged is [tested](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#19-reference-implementation)
and merged.

## Under the hood (for the curious)

- Events: `flow_tc.c` (TC ingress) parses eth/ip4/tcp, probes the payload
  for an HTTP request line, and emits one `flow_event` per flow into a
  BPF ringbuf. The Go side drains it with
  [cilium/ebpf](https://pkg.go.dev/github.com/cilium/ebpf) and decodes the
  wire struct (`internal/engine/ingest`).
- Verdicts: the CEL engine compiles each rule once (`cel.Program`,
  cost-budgeted at eval time), so a rule can never spin the CPU.
- Bans: `ban_key{addr,family,key_class}` / `ban_val{until_ts,tier,reason}`
  [§19.1](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#191-stage-sketches-from-the-code-v0-poc)
  — dual-stack by construction (family-discriminated union), monotonic
  clock, no infinite bans (loader refuses).
