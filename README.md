# Trishula

**eBPF-native, developer-first Web Application and API Firewall for Kubernetes.**
kernel shield · userspace engine · control plane

[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/trishula-dev/trishula/blob/main/LICENSE) [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/trishula-dev/trishula)](https://github.com/trishula-dev/trishula/graphs/commit-activity) [![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/trishula-dev/trishula)](https://libraries.io/github/trishula-dev/trishula) [![GitHub Release](https://img.shields.io/github/v/release/trishula-dev/trishula?include_prereleases)](https://github.com/trishula-dev/trishula/releases)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/trishula-dev/trishula/main.svg)](https://results.pre-commit.ci/latest/github/trishula-dev/trishula/main) [![go-build](https://github.com/trishula-dev/trishula/actions/workflows/go-build.yml/badge.svg)](https://github.com/trishula-dev/trishula/actions/workflows/go-build.yml) [![Dependency Review](https://github.com/trishula-dev/trishula/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/trishula-dev/trishula/actions/workflows/dependency-review.yml) [![cue-gate](https://github.com/trishula-dev/trishula/actions/workflows/cue-gate.yml/badge.svg)](https://github.com/trishula-dev/trishula/actions/workflows/cue-gate.yml) [![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/trishula-dev/trishula?label=OpenSSF%20Scorecard&style=flat)](https://scorecard.dev/viewer/?uri=github.com/trishula-dev/trishula) [![OpenSSF Best Practices](https://img.shields.io/badge/cii%20best%20practices-in%20progress-orange)](https://www.bestpractices.dev/projects/15183)

Trishula protects Kubernetes traffic in three planes. The kernel shield runs
verifier-checked eBPF programs. The userspace engine runs the detection
stack: OWASP CRS, CEL rules, OpenAPI positive security, bot fingerprints and
the ban table. The control plane compiles `WAFPolicy` CRDs into signed policy
bundles. Every verdict is a correlated OpenTelemetry record.

**Status:** the 2026.01-rc3 component set sits merged on `main`. The socket-plane compiler pathway lands its first class (route marking) with a machine-checked verifier gate. The lab
gates run green on a live cluster. The bench harness measures the
[§17 walls](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#171-budgets-by-stage) in CI. The gaps carry their own
list on this page.

## What exists today

Each slice landed as a watched-RED then GREEN leaf PR per [AGENTS.md](AGENTS.md).

| Component | Where | What exists | Evidence |
|---|---|---|---|
| Shield loaders | [`internal/shield/`](https://github.com/trishula-dev/trishula/commit/ed9b2714512ecad1bb6b0960eeeb7951e9693726) | CO-RE XDP + TC objects (arm64, amd64); Go loaders; fail-closed `TierRefusal`; tier measure at boot. | [#80 tier run](https://github.com/trishula-dev/trishula/issues/80#issuecomment-6094023768) · [#10 ban E2E](https://github.com/trishula-dev/trishula/issues/10#issuecomment-6093609582) |
| Kernel C + wire | [`bpf/`](https://github.com/trishula-dev/trishula/commit/ed9b2714512ecad1bb6b0960eeeb7951e9693726) | `shield_xdp.c` (ACL, verdict cache, ban table), `flow_tc.c` (ringbuf); wire layouts test-pinned. | banwire tests in-package |
| Ingest | [`internal/engine/ingest/`](https://github.com/trishula-dev/trishula/commit/17e78d551de26cb0e7243b02247568538b866d2a) | ringbuf drain → decode → per-connection assembly; kernel-free. | [TR-04d merge](https://github.com/trishula-dev/trishula/commit/17e78d551de26cb0e7243b02247568538b866d2a) |
| Detection ladder | [`internal/engine/ladder/`](https://github.com/trishula-dev/trishula/commit/b86cf6f9a5bbff2903fe058980fed39e9f472ab6) | S0–S5 wiring + verdict vocabulary; HTTP/1 and HTTP/2/gRPC parse. | [TR-05 merge](https://github.com/trishula-dev/trishula/commit/b86cf6f9a5bbff2903fe058980fed39e9f472ab6) |
| OTel telemetry | [`internal/engine/otel/`](https://github.com/trishula-dev/trishula/commit/e63d990e4deef8e3ce9e0ed108987b80585dd47e) | span + metric + log record, correlated by request id. | [#11 evidence](https://github.com/trishula-dev/trishula/issues/11#issuecomment-6092518259) |
| Bot fingerprints | [`internal/engine/botdef/`](https://github.com/trishula-dev/trishula/commit/c4f5e7e8bb766ee482aaae59ece5ffacc89020d1) | JA4 + header-plane detector; golden vectors. | [#99](https://github.com/trishula-dev/trishula/pull/99) |
| Positive security | [`internal/engine/positive/`](https://github.com/trishula-dev/trishula/commit/8f4c2f22d39ef52fe5633dafa6949cb47521bb14) | OpenAPI 3.1-subset body gate; fail-closed. | [#13 evidence](https://github.com/trishula-dev/trishula/issues/13#issuecomment-6092602177) |
| CRS evaluator | [`internal/crs/`](https://github.com/trishula-dev/trishula/commit/a1d9b027c983f7da141a4f8f8914bce6eb15c0c0) · [`test/crs-differential/`](https://github.com/trishula-dev/trishula/commit/ec1934616317d966a42156c47cb394593779bf90) | embedded Coraza reference + CI-blocking parity differential. | [#7 parity 19/19](https://github.com/trishula-dev/trishula/issues/7#issuecomment-6092716820) |
| ScoredWindowBan | [`internal/engine/rateban/`](https://github.com/trishula-dev/trishula/commit/f116ded4e093facc7228002d52ced6f06996f9df) | [§13.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified) ban with clock seam + evidence; kernel publish. | [#10 in-VM E2E](https://github.com/trishula-dev/trishula/issues/10#issuecomment-6093609582) |
| Rate algorithms | [`internal/engine/rateban/`](https://github.com/trishula-dev/trishula/tree/main/internal/engine/rateban) | token bucket, multi-window sliding, EWMA per [§13.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#132-the-rate-algorithms-per-route-crd-selected); CRD-selected; Retry-After on every throttle. | [#20](https://github.com/trishula-dev/trishula/issues/20) RED/GREEN tables in-package |
| Behavioural DoS detectors | [`internal/engine/rateban/`](https://github.com/trishula-dev/trishula/tree/main/internal/engine/rateban) · [`bpf/flow_tc.c`](https://github.com/trishula-dev/trishula/tree/main/bpf) | slowloris shape over the kernel's flow-window features + the h2 rapid-reset ratio; cues ride the existing evidence sink, never enforce; kernel counts and stamps only. | [#31](https://github.com/trishula-dev/trishula/issues/31) RED/GREEN tables in-package + the `ingest4d` kernel gate |
| Operator | [`internal/operator/`](https://github.com/trishula-dev/trishula/commit/cb60e2b0cd3463f84e72acf3d07356cacda66f2a) · [`api/v1alpha1/`](https://github.com/trishula-dev/trishula/commit/2826178d6c489df2a785b7b7d9ace0c3a644c494) | `WAFPolicy` CRD → bundle compile (fail closed) → publish. | [#76 M9 evidence](https://github.com/trishula-dev/trishula/issues/76#issuecomment-6093110531) |
| Route-class fast path | [`internal/fastpath/`](https://github.com/trishula-dev/trishula/tree/main/internal/fastpath) · [`bpf/`](https://github.com/trishula-dev/trishula/tree/main/bpf) | TR-40b: the route class compiles through the census into the template, loads through the verifier under `route-gate.yml`, and the split reads back. Tracked evaluation, not a v1 commitment. | [census record §9](https://github.com/trishula-dev/trishula/blob/main/docs/design/socket-plane/4-compiler-census.md#9-the-route-class-template-record-tr-40b) |
| Engine + consult | [`cmd/engine/`](https://github.com/trishula-dev/trishula/commit/cb60e2b0cd3463f84e72acf3d07356cacda66f2a) | transparent proxy; bundle consult; hot reload. | [#6 hop evidence](https://github.com/trishula-dev/trishula/issues/6#issuecomment-6091986517) |
| DX1 lab | [`lab/dx1/`](https://github.com/trishula-dev/trishula/commit/8bc24a27d6b4e0ca839e22453f9c519a13e3000c) · [`lab/demo.sh`](https://github.com/trishula-dev/trishula/commit/ed9b2714512ecad1bb6b0960eeeb7951e9693726) | idempotent bring-up; timed apply→effect; hop verification. | [Proof record](https://github.com/trishula-dev/trishula/issues/6#issuecomment-6091479891) |

## Measured performance

Budgets read off [§17.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#171-budgets-by-stage).
Wall numbers read from the last recorded per-row CI run:
[40147859961](https://github.com/trishula-dev/trishula/actions/runs/40147859961/job/121029622516),
head `05affd9`, the 2026.01-rc3 content with the verbose bench step (#230). The
numbers re-read at each release.

| Cell | Budget p99 | Last build p99 | Verdict |
|---|---|---|---|
| idle-get | 600 µs | 865.0 µs | unmet (1.44x) on this read — runner noise; the quiet rig reads 0.30x |
| attack-sqli-small | 1500 µs | 1029.0 µs | holds (0.69x) |
| attack-xss-small | 1500 µs | 1078.9 µs | holds (0.72x) — variance class, [#147](https://github.com/trishula-dev/trishula/issues/147) |
| ladder-json-1k | 600 µs | 825.7 µs | unmet (1.38x) on this read — runner noise; the quiet rig reads 0.64x |
| ladder-json-8k | 600 µs | 862.1 µs | unmet (1.44x) — variance class, [#147](https://github.com/trishula-dev/trishula/issues/147) |
| ladder-json-64k | 1200 µs | 1096.6 µs | holds (0.91x) |
| ladder-form-dense-1k | 600 µs | 15395.2 µs | pinned open — the [§17.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#171-budgets-by-stage) |
| ladder-form-dense-8k | 600 µs | 135633.1 µs | pinned open — the [§17.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#171-budgets-by-stage) |
| steady-json-8k (the [M2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#171-budgets-by-stage) e2e cell) | 1500 µs | 433.7 µs | holds (0.29x) |
## Upcoming features

The list pairs each not-shipped feature with its tracker.

- [ ] Inline `< 10 ms` walls on the lab plane — the CI harness measures engine-only cells today.
- [ ] Verdicts on live ringbuf traffic inside cluster pods — a later engine slice.
- [ ] HTTP/3 request-path parse — the posture evaluation record publishes (TR-29); the parse is a later engine slice.
- [ ] Socket-plane: more policy classes after route marking, and the kTLS posture — the first class lands as a tracked evaluation ([#52](https://github.com/trishula-dev/trishula/issues/52)).
- [ ] trishulactl full CLI surface — the skeleton exists; the surface is a later phase.
- [ ] OpenAPI promotion gates — learn mode and drift telemetry ship (TR-18); the full gate ladder rides later slices ([#18](https://github.com/trishula-dev/trishula/issues/18)).
- [ ] ML scoring beyond v0 — the ONNX in-band scorer ships (TR-21); the adaptive tier rides later slices ([#21](https://github.com/trishula-dev/trishula/issues/21)).
- [ ] Wire-out OTLP export — the triad verifies in-memory today.
- [ ] The DPU-class port — the evaluation record publishes (TR-32); the port itself rides a later phase ([#32](https://github.com/trishula-dev/trishula/issues/32)). Multi-arch and OpenShift notes ship (TR-33); the rows leave this list.

The board is the [Trishula Roadmap](https://github.com/orgs/trishula-dev/projects/1).

## Layout ([the reference implementation](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#19-reference-implementation))

```
api/v1alpha1/     CRD types (WAFPolicy, BanPolicy, …)
cmd/              engine, operator, shield, trishula, trishulactl, attackdemo, cuegen
bpf/              shield_xdp.c, flow_tc.c (CO-RE, bpf2go)
cue/              CUE definitions — the declarative layer (TR-46), the golden-diff source
internal/         engine (ingest, ladder, cel, http1, http2, otel, botdef, positive, rateban), operator, shield, cuegen
manifests/        install manifests (the CRD only; controller-gen-owned)
deployment/       derived manifests (the dx1 lab tree, written by cmd/cuegen — never hand-edited)
lab/              demo.sh · dx1/ · demo-attack.sh · verify-xdp-chain.sh · tier-gate.sh
test/             crs-differential · ban-conformance · banenforce · tier · bench
docs/             spec, paper, academy
```

## Run the demo (one command)

```bash
bash lab/demo.sh
```

The script brings the DX1 lab up on any Docker-provider host. Needs `go`,
`kubectl`, `helm`, `docker` and `curl`. It builds the engine and operator
binaries, applies the policy and runs the timed apply→effect scenario. The
exit banner reads `DEMO-OK` or `DEMO-FAIL`. The verbatim recorded output sits
on the issue record above.

## Run the timed gate

```bash
bash lab/dx1/dx1-gate.sh
```

The gate asserts: clone → first enforced rule in ≤ 15 min. The
[nightly job](.github/workflows/lab-nightly.yml) keeps the timing asserted.

## Run the tests

```bash
go test ./...
```

The suite gates the bench walls, the CRS parity differential (19/19 corpus
cases), the ban conformance set, the shield tier gate and the docs guards.

## Run the bench on the dev VM

[lab/bench-vm.sh](lab/bench-vm.sh) runs the
[§17.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#172-benchmark-plan)
rig in the dev VM. Start from a VM copy of the tree:

```bash
orb run -m trishula-build-dev -u root bash /mnt/mac/<path-to-clone>/lab/bench-vm.sh
```

The script prints four sections: the new CI shape, the old-shape control, the
walls with the prefilter on and the control with it off. The VM is the A/B
surface. Hosted CI stays the calibration surface.

## Proof

The verbatim `lab/demo.sh` output for the Phase 0 exit sits on the recorded
run at main `ed9b271`. The hop, M9 and parity evidence trails link from the
rows above.

## Shield visibility tiers

The shield measures what the hook sees ([#80](https://github.com/trishula-dev/trishula/issues/80#issuecomment-6094023768)).
On OrbStack-family pod-veths the attach altitude is not the effective
altitude.

| Tier | Meaning | Enforcement posture |
|---|---|---|
| `full` | every packet at both altitudes (XDP + TC) | full payload visibility at TC |
| `first_packet` | first packet only (OrbStack pod-veth posture) | ban/ACL on new connections only; sampled flows |
| `none` | no packets visible | loader refuses and fails loudly (`TierRefusal`) |

## License

MIT — see [LICENSE](LICENSE).
