# Trishula in 10 minutes: two attacks, three altitudes

> This page shows the same 2 requests an attacker sends, as the three
> altitudes see them. The altitudes Trishula separates: the **wire**
> (kernel, per-flow truth), the **request** (negative security, the CRS
> layer) and the **API** (positive security: is this request allowed *for
> this principal*?). Everything below runs on merged engine code
> ([TR-02](https://github.com/trishula-dev/trishula/issues/2),
> [TR-03](https://github.com/trishula-dev/trishula/issues/3),
> [TR-04](https://github.com/trishula-dev/trishula/issues/4)); the
> transcript of the recorded run is on
> [issue #83](https://github.com/trishula-dev/trishula/issues/83).

## The attacks

**A. Classic payload attack (CRS layer).** `GET /download?file=../../../etc/passwd`
is path traversal, in the [CRS 930120 / 930100](https://coraza.io/docs/tutorials/walkthrough) class.
No API semantics are required. Any evaluator holding OWASP CRS rules rejects
the request on shape alone. In Trishula this is ladder stage S2: CRS runs as
the community correctness baseline [§11.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#112-crs-the-correctness-baseline).
The verdict joins the ladder's combined decision. The demo shows the
reference verdict Coraza computes for the captured bytes.

**B. BOLA (API1:2023 — the #1 API risk).**
`GET /api/v1/orders/2002` carries tenant-a credentials; order `2002`
belongs to tenant-b. The request is *flawless HTTP*, and no CRS signature
fires. Object-level authorization is not a signature problem; it is a
policy question only the API's own data answers
[§11.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#113-cel-as-the-developer-facing-dsl).
In Trishula the question is one CEL expression over the request view
(`resource.owner == request.auth.subject`), evaluated cost-budgeted.
The decision is emitted as a
[`trishula.verdict.v1`](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#15-opentelemetry-observability)
record.

**C. Enforcement (what the attacker experiences next).** Repeat offenders
reach the ban threshold. The shield writes a source ban to the kernel, and
the connection dies **in TC, before userspace, before the request reaches
the app** —
[§13](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#13-rate-limiting-dos-response--temporary-bans)
on merged code: `TC_ACT_SHOT`.

## Run it

```sh
# Linux (VM or box): kernel ≥5.15 with BTF, root, Go 1.23+
sudo ./lab/demo-attack.sh
```

## Build path

`lab/demo-attack.sh` carries every artifact prep. The sources: the three
artifacts the run loads.

- `/tmp/flow_tc.o` — the merged TC producer object. The script copies the
  committed bpf2go output for the arch:
  `internal/engine/ingest/ingest_flow_arm64_bpfel.o` (arm64) or
  `ingest_flow_x86_bpfel.o` (amd64). The source file is `bpf/flow_tc.c`; a
  C change goes through the package's `go:generate` first. A `.o` path
  never carries a `go build` artifact.
- `/tmp/attackdemo` — the demo binary. `go build -o /tmp/attackdemo
  ./cmd/attackdemo`; the script runs the build when the file is absent.
  Set `DEMO_BIN` to use a pre-built binary. Cross build:
  `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /tmp/attackdemo
  ./cmd/attackdemo`.
- `/tmp/tfo` — the target listener. It ships in no build. The script
  writes a fallback when `/tmp/tfo` is absent: a small HTTP server on
  the target address. The server answers the wire legs. A real
  order-store listener binary replaces it.

The script prints, per attack: the wire exchange, the evaluator verdicts,
the kernel's own view of the flow and the enforcement evidence. The
harness under it (veth pair, TC filter, pinned maps) is the same harness
the [E2E tests](https://github.com/trishula-dev/trishula/blob/main/lab/README.md) use.

## What runs merged vs what the demo computes demo-side

| Piece | Status |
|---|---|
| Kernel flow events → ringbuf → decodable `FlowEvent` | **merged** (TR-04) |
| CEL rule engine, cost-budgeted (seed pack) | **merged** (TR-02) |
| Ban map + loader ABI, kernel drop on live ban | **merged** (TR-03) |
| Coraza/CRS verdict for captured bytes | reference-side here; **wired into the ladder by TR-07** |
| BOLA rule as an engine expression | demo-computed; the view it needs lands with **TR-05** |
| Ban *decisions* (thresholds, tiers) | **TR-09/10** — the kernel drop is live, the decider is not yet |

The honesty table carries the point: the demo pre-tends no enforcement
that does not exist. Everything labelled merged is
[tested](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#19-reference-implementation)
and merged.

## Under the hood (for the curious)

- Events: `flow_tc.c` (TC ingress) parses eth/ip4/tcp, probes the payload
  for an HTTP request line, and emits one `flow_event` per flow into a
  BPF ringbuf. The Go side drains it with
  [cilium/ebpf](https://pkg.go.dev/github.com/cilium/ebpf) and decodes the
  wire struct (`internal/engine/ingest`).
- Verdicts: the CEL engine compiles each rule once (`cel.Program`), with
  the cost budget at eval time. No rule runs unbounded.
- Bans: `ban_key{addr,family,key_class}` / `ban_val{until_ts,tier,reason}`
  [§19.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#191-stage-sketches-from-the-code-v0-poc)
  — dual-stack by construction (family-discriminated union), monotonic
  clock, no infinite bans (the loader refuses).
