# Trishula

**eBPF-native, developer-first Web Application and API Firewall for Kubernetes.**
kernel shield · userspace engine · control plane

[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/trishula-dev/trishula/blob/main/LICENSE) [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/trishula-dev/trishula)](https://github.com/trishula-dev/trishula/graphs/commit-activity) [![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/trishula-dev/trishula)](https://libraries.io/github/trishula-dev/trishula) [![GitHub Release](https://img.shields.io/github/v/release/trishula-dev/trishula?include_prereleases)](https://github.com/trishula-dev/trishula/releases)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/trishula-dev/trishula/main.svg)](https://results.pre-commit.ci/latest/github/trishula-dev/trishula/main) [![go-build](https://github.com/trishula-dev/trishula/actions/workflows/go-build.yml/badge.svg)](https://github.com/trishula-dev/trishula/actions/workflows/go-build.yml) [![Dependency Review](https://github.com/trishula-dev/trishula/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/trishula-dev/trishula/actions/workflows/dependency-review.yml) [![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/trishula-dev/trishula?label=OpenSSF%20Scorecard&style=flat)](https://scorecard.dev/viewer/?uri=github.com/trishula-dev/trishula) [![OpenSSF Best Practices](https://img.shields.io/badge/cii%20best%20practices-in%20progress-orange)](https://www.bestpractices.dev/projects/15183)


**Status: Phase 0 (v0.1) delivered** — every component below is merged to
`main` under its signature, with the lab gates green on a live cluster. What
exists today is listed per component with its merge commit; what does **not**
exist yet is listed just as plainly. The §20.2 exit-criteria table is checked
honestly further down, and the [Proof](#proof-labdemosh-output-verbatim)
section is the verbatim output of `lab/demo.sh` — the exit-gate demo, one
command from a fresh clone to the full run.

## The one-sentence design thesis

> The WAF is the last control that never crossed to developer ubiquity — Trishula brings it across, by pairing a kernel-altitude eBPF shield (fail-open by default, bounded parsing, verifier-checked in CI) with the full userspace detection stack (OWASP CRS via embedded Coraza with a CI-blocking parity differential, CEL rules under cost budgets, OpenAPI positive security with promotion gates, JA4/behavioural bot detection, evidence-recorded ScoredWindowBan) and a Kubernetes-native control plane whose every verdict is a correlated OpenTelemetry record.

## What exists today (per component, merge linked)

Everything below is on `main` (from [4161758](https://github.com/trishula-dev/trishula/commit/416175852d3ba843fbefdd6900a6d89c268d6052) onward), GPG-signed
`Shain.Singh@owasp.org`, each slice delivered as watched-RED → GREEN leaf
PRs per [`AGENTS.md`](AGENTS.md).

| Component | Where | What exists | Evidence |
|---|---|---|---|
| Kernel shield loaders | [`internal/shield/`](https://github.com/trishula-dev/trishula/commit/ed9b2714512ecad1bb6b0960eeeb7951e9693726) | CO-RE bpf2go objects (arm64 + amd64) for the XDP shield (ACL + verdict cache + ban table) and the TC flow producer; Go loaders (XDP/TC attach, pinned-prog lifecycle, fail-closed `TierRefusal`); visibility tier measured at boot, emitted as `trishula.shield.visibility_tier`; ban publish/reconcile (`bans_v4`); JSONL evidence sink. | [#80 tier vocabulary + measured tiers](https://github.com/trishula-dev/trishula/issues/80#issuecomment-6094023768); [#10 in-VM ban E2E](https://github.com/trishula-dev/trishula/issues/10#issuecomment-6093609582) |
| Kernel C + wire contracts | [`bpf/`](https://github.com/trishula-dev/trishula/commit/ed9b2714512ecad1bb6b0960eeeb7951e9693726) | `shield_xdp.c` (XDP ACL/verdict-cache/ban table + tier probe counters), `flow_tc.c` (TC ringbuf producer); map keys/event layouts/action codes pinned by object-level contract tests. | contract + banwire tests in-package; [#10 flow/ban E2E](https://github.com/trishula-dev/trishula/issues/10#issuecomment-6093609582) |
| Ingest | [`internal/engine/ingest/`](https://github.com/trishula-dev/trishula/commit/17e78d551de26cb0e7243b02247568538b866d2a) | ringbuf drain → FlowEvent decode → per-connection transaction assembly (kernel-free, CI-runnable). | [#81 TR-04d merge](https://github.com/trishula-dev/trishula/commit/17e78d551de26cb0e7243b02247568538b866d2a, closes TR-04) |
| Detection ladder | [`internal/engine/ladder/`](https://github.com/trishula-dev/trishula/commit/b86cf6f9a5bbff2903fe058980fed39e9f472ab6) | S0–S5 stage wiring + the Verdict/Action/Phase vocabulary (extend, never fork); HTTP/1 parse into the §11.3 request view. | [#91 TR-05 main delivery](https://github.com/trishula-dev/trishula/commit/b86cf6f9a5bbff2903fe058980fed39e9f472ab6) |
| OTel verdict telemetry | [`internal/engine/otel/`](https://github.com/trishula-dev/trishula/commit/e63d990e4deef8e3ce9e0ed108987b80585dd47e) | verdict trace span + `verdicts_total` metric + structured log record, correlated by request id; in-memory exporter snapshot. SDKs pinned v1.47.0. | [#11 evidence comment (the triad)](https://github.com/trishula-dev/trishula/issues/11#issuecomment-6092518259) |
| Bot fingerprints | [`internal/engine/botdef/`](https://github.com/trishula-dev/trishula/commit/c4f5e7e8bb766ee482aaae59ece5ffacc89020d1) | JA4 (FoxIO-faithful assembly) + header-plane fingerprint detector v0, lab-log surface. | [#99 body (watched RED/GREEN + JA4 golden vectors)](https://github.com/trishula-dev/trishula/pull/99) |
| Positive security | [`internal/engine/positive/`](https://github.com/trishula-dev/trishula/commit/8f4c2f22d39ef52fe5633dafa6949cb47521bb14) | OpenAPI 3.1-subset body gate on the demo route: exhaustive field-path diagnostics, fail-closed on undecodable bodies, fail-open on unmatched paths. | [#13 evidence comment](https://github.com/trishula-dev/trishula/issues/13#issuecomment-6092602177) |
| CRS evaluator + parity gate | [`internal/crs/`](https://github.com/trishula-dev/trishula/commit/a1d9b027c983f7da141a4f8f8914bce6eb15c0c0) · [`test/crs-differential/`](https://github.com/trishula-dev/trishula/commit/ec1934616317d966a42156c47cb394593779bf90) | embedded-Coraza reference CRS evaluator + the CI-blocking differential: **19/19 corpus cases at 100% verdict parity** (1 skipped, documented). | [#7 evidence comment (parity 19/19 + 1 skip)](https://github.com/trishula-dev/trishula/issues/7#issuecomment-6092716820) |
| ScoredWindowBan | [`internal/engine/rateban/`](https://github.com/trishula-dev/trishula/commit/f116ded4e093facc7228002d52ced6f06996f9df) | ScoredWindowBan v1 (§13.3) with the Clock seam + evidence records; the `BanEnforcer` adapter publishes bans to the kernel map. | [#10 in-VM E2E](https://github.com/trishula-dev/trishula/issues/10#issuecomment-6093609582): kernel shot 3→4, expiry lift, reconciler, JSONL |
| Operator compile + reconcile | [`internal/operator/`](https://github.com/trishula-dev/trishula/commit/cb60e2b0cd3463f84e72acf3d07356cacda66f2a) · [`api/v1alpha1/`](https://github.com/trishula-dev/trishula/commit/2826178d6c489df2a785b7b7d9ace0c3a644c494) | `WAFPolicy` CRD (controller-gen artifacts committed) → Bundle v1 compile (fail closed) → CRD watch → `bundle.json` publish; sealed in-process compile→load round-trip test. | [#76 M9 evidence](https://github.com/trishula-dev/trishula/issues/76#issuecomment-6093110531): apply→effect 2618 ms + fail-closed; compile→load round-trip test (#98, [https://github.com/trishula-dev/trishula/issues/75](https://github.com/trishula-dev/trishula/issues/75) closed on it) |
| Engine: consult + hot-reload | [`cmd/engine/`](https://github.com/trishula-dev/trishula/commit/cb60e2b0cd3463f84e72acf3d07356cacda66f2a) | transparent proxy host (`--upstream`, `X-Trishula-Hop`) + bundle consult (`--bundle`) with polled hot-reload and `-receive-bundle` in-cluster delivery; engine-local `/healthz`. | [#6 delivery + hop evidence](https://github.com/trishula-dev/trishula/issues/6#issuecomment-6091986517) |
| Operator runtime | [`cmd/operator/`](https://github.com/trishula-dev/trishula/commit/cb60e2b0cd3463f84e72acf3d07356cacda66f2a) | the real CRD watch loop + healthz :1936 (the image the lab deploys). | [#76 M9 E2E](https://github.com/trishula-dev/trishula/issues/76#issuecomment-6093110531) |
| DX1 lab | [`lab/dx1/`](https://github.com/trishula-dev/trishula/commit/8bc24a27d6b4e0ca839e22453f9c519a13e3000c) · [`lab/demo.sh`](https://github.com/trishula-dev/trishula/commit/ed9b2714512ecad1bb6b0960eeeb7951e9693726) | idempotent setup (OrbStack/kind + NGF + engine + echo), apply→effect M9 timer, hop verification — composed by `lab/demo.sh`, one command. | the [Proof](#proof-labdemosh-output-verbatim) below (this run) + [#6 live hop evidence](https://github.com/trishula-dev/trishula/issues/6#issuecomment-6091479891) |

## What does not exist yet (honest)

- **<10 ms inline measurements** — the benchmark harness is TR-24;
  `test/bench/` is an empty placeholder. No latency number on this page is a
  benchmark result. The one timing that exists is the **apply→effect**
  control-plane round trip (M9 ≤ 5 s budget; recorded 2618 ms on https://github.com/trishula-dev/trishula/issues/76,
  1465 ms in the run below) — a config-propagation figure, not an
  inline-processing figure.
- **The engine ladder in-cluster** — in the current demo the engine serves
  its decision surface from bundles delivered via `-receive-bundle`; the
  full ladder serving verdicts on live ringbuf traffic inside the cluster
  pods is TR-15.
- **HTTP/2 + HTTP/3 request paths** — the engine parses HTTP/1.1 only; the
  h2/h3 ingress posture evaluation is the TR-25/TR-29 track.
- **Socket-plane L7 fast path, prefix escalation, async semantic judge** —
  design/evaluation items (the TR-41-range study trio; not built).
- **trishulactl full surface** — the CLI skeleton exists
  (`cmd/trishulactl`); the real surface is a later-phase item.
- **Response-side schema / exfiltration guard** — Phase 2 of the roadmap.
- **Positive-security learn mode + promotion gates** — v0 enforces a static
  OpenAPI subset; the v1 learn/apply pipeline is not built.
- **Production OTLP export** — the triad is verified against an in-memory
  exporter snapshot; the wire-out collector pipeline is not wired.
- **Multi-arch release engineering, DPU (BlueField-class) port,
  OpenShift/multi-arch builds** — release engineering begins at v0.1.0 (PRD
  §9.2); platform breadth is GA-track.

The live board is the [Trishula Roadmap](https://github.com/orgs/trishula-dev/projects/1).

## Layout (PRD v4 §19)

```
api/v1alpha1/     CRD types (WAFPolicy, BanPolicy, …)
cmd/              engine, operator, shield, trishula, trishulactl, attackdemo
bpf/              shield_xdp.c, flow_tc.c (CO-RE, bpf2go)
internal/         engine (ingest, ladder, cel, http1, otel, botdef, positive, rateban), operator, shield
manifests/        install manifests (incl. CRD)
lab/              demo.sh · dx1/ · demo-attack.sh · verify-xdp-chain.sh · tier-gate.sh
test/             crs-differential · ban-conformance · banenforce · tier · bench
docs/             PRD, paper, academy
```

## Run the demo (one command)

```bash
bash lab/demo.sh
```

From a fresh clone on a Docker-provider host (kind or OrbStack Kubernetes)
with `go`, `kubectl`, `helm`, `docker`, `curl`: builds the linux engine +
operator binaries from this tree if missing, brings the DX1 lab up
(idempotent), runs the timed apply→effect scenario (M9 ≤ 5 s budget), and
finishes with the hop-by-hop evidence printed last — each stage passes/fails
loudly (`set -euo pipefail`, per-stage markers, `DEMO-OK` / `DEMO-FAIL`
banner). The kernel-side artifacts (XDP attach, in-VM ban E2E, tier probes)
run on a Linux VM per [`lab/dx1/README.md`](lab/dx1/README.md) and
[`lab/verify-xdp-chain.sh`](lab/verify-xdp-chain.sh) — see the gate table in
[`AGENTS.md`](AGENTS.md).

## Status — Phase 0 exit criteria (PRD §20.2, checked honestly in TR-14)

| §20.2 criterion | Status | Evidence |
|---|---|---|
| < 10 ms inline (unoptimized) | **pending TR-24** | the benchmark harness does not exist yet — `test/bench/` is an empty placeholder. No benchmark number can honestly be reported. The M9 apply→effect figure (2618 ms / 1465 ms ≤ 5 s) is a control-plane propagation timing, NOT inline processing. |
| 100% verdict telemetry (span + metric + log correlated) | **pass** | the OTel triad correlated by request id; [#11 evidence comment](https://github.com/trishula-dev/trishula/issues/11#issuecomment-6092518259); merge [e63d990](https://github.com/trishula-dev/trishula/commit/e63d990e4deef8e3ce9e0ed108987b80585dd47e) (#101); unit-proven (correlation + snapshot tests in-package); wire-out OTLP export not wired (above) |
| CRD round-trip (apply → compile → load) | **pass** | sealed in-process compile→load round-trip test (0.239 s) + live M9 apply→effect 2618 ms ≤ 5 s; [#76 evidence](https://github.com/trishula-dev/trishula/issues/76#issuecomment-6093110531); merges [e221c9f](https://github.com/trishula-dev/trishula/commit/e221c9f7938b84892d2ba66aecd87f850ef967eb) (#98) · [cb60e2b](https://github.com/trishula-dev/trishula/commit/cb60e2b0cd3463f84e72acf3d07356cacda66f2a) (#104) |
| NGF steer-to-engine proven | **pass** | DX1 hop evidence: NGF → engine → echo (`X-Trishula-Hop: engine`, echo pod id in the response body); [#6 live curl transcript](https://github.com/trishula-dev/trishula/issues/6#issuecomment-6091479891); reproduced in the [demo output](#proof-labdemosh-output-verbatim) |
| Engine ladder end-to-end verdict logging | **pass (v0 surfaces)** | S0–S5 verdict vocabulary driving `cmd/engine` decisions — `engine: decision block (rule=DX-LAB-001)` lines in the demo output; positive gate (#102) and botdef fingerprints (#99) land as ladder slices; the in-cluster ladder on ringbuf traffic is TR-15 |
| CRS PL1 differential parity reported (shadow) | **pass** | 19/19 corpus cases at 100% verdict parity (1 skipped, documented), CI-blocking; [#7 evidence comment](https://github.com/trishula-dev/trishula/issues/7#issuecomment-6092716820); merge [ec19346](https://github.com/trishula-dev/trishula/commit/ec1934616317d966a42156c47cb394593779bf90) (#103) |
| Shield attaches on a node; kernel-side ban drop works | **pass (Linux VM)** | XDP attach + ban `TC_ACT_SHOT` (shot 3→4), expiry auto-lift, reconciler lift, JSONL evidence; [#10 in-VM E2E](https://github.com/trishula-dev/trishula/issues/10#issuecomment-6093609582) + [#80 tier vocabulary](https://github.com/trishula-dev/trishula/issues/80#issuecomment-6094023768). NOT evidenced on plain kind nodes: OrbStack-family pod-veth fast paths limit visibility (measured `first_packet` tier) — the loader measures and refuses an invisible shield rather than pretending |

Honesty is the feature: the one **fail**-shaped cell is the pending TR-24
benchmark — named as such instead of hand-waved.

## Proof — lab/demo.sh output (verbatim)

Recorded in the TR-14 lane (main at ed9b271) — `M9_TARGET=5 bash lab/demo.sh`
from the clone. Evidence trail on the issues: https://github.com/trishula-dev/trishula/issues/6 ([steering hop](https://github.com/trishula-dev/trishula/issues/6#issuecomment-6091479891),
[delivery](https://github.com/trishula-dev/trishula/issues/6#issuecomment-6091986517)), https://github.com/trishula-dev/trishula/issues/76 ([M9](https://github.com/trishula-dev/trishula/issues/76#issuecomment-6093110531)), https://github.com/trishula-dev/trishula/issues/7 ([parity](https://github.com/trishula-dev/trishula/issues/7#issuecomment-6092716820)),
https://github.com/trishula-dev/trishula/issues/10 ([ban E2E](https://github.com/trishula-dev/trishula/issues/10#issuecomment-6093609582)), https://github.com/trishula-dev/trishula/issues/80 ([tiers](https://github.com/trishula-dev/trishula/issues/80#issuecomment-6094023768)), https://github.com/trishula-dev/trishula/issues/11 ([OTel](https://github.com/trishula-dev/trishula/issues/11#issuecomment-6092518259)),
https://github.com/trishula-dev/trishula/issues/13 ([positive](https://github.com/trishula-dev/trishula/issues/13#issuecomment-6092602177)).

```text

============================================================
== Trishula v0.1 exit-gate demo (lab/demo.sh) — repo ed9b271, host arch arm64
============================================================

------------------------------------------------------------
| STAGE 1/3 — DX1 lab setup (lab/dx1/setup.sh, idempotent)
------------------------------------------------------------

== cluster (idempotent — skipped if reachable)
cluster already exists (context: orbstack) — kind create cluster skipped

== engine image (build trishula-engine:dx1 from cmd/engine, load into the node's image store)
Image: "trishula-engine:dx1" with ID "sha256:09a43eebf57d71f739f5ab3985b4c80d4b551390620fd899191740fd6e35029b" found to be already present on all nodes.

== Gateway API CRDs (Gateway API v1.5.1 standard channel, the set NGF v2.7.2 installs)
Gateway API CRDs already present

== NGF release dx1 (helm, service.type=NodePort)
helm release dx1 already installed (lab pins 2.7.2)

== NGF images pulled anonymously and loaded (control plane + nginx data plane)
Image: "ghcr.io/nginx/nginx-gateway-fabric:2.7.2" with ID "sha256:27f6253fc8220d0230f34b17fa7d934241bfbcc26537c94edd58f3973040f69c" found to be already present on all nodes.
Image: "ghcr.io/nginx/nginx-gateway-fabric/nginx:2.7.2" with ID "sha256:7c271837efd1acc81f050f729a0f222e156fe3a1c1eaabc71dce67f65bd0e568" found to be already present on all nodes.
Image: "ghcr.io/mendhak/http-https-echo:42" with ID "sha256:d1f6b5907461931fb0d3ee38d8abfee16d5922f4087696dc99875c5f60c8b153" found to be already present on all nodes.

== applying lab manifests (/Users/shsingh/.hermes/profiles/satyayuga-cloud/cache/scratch/tr06-tr14/lab/dx1/manifests)
namespace/dx1 unchanged
deployment.apps/dx1-echo unchanged
service/dx1-echo unchanged
deployment.apps/dx1-engine unchanged
service/dx1-engine unchanged
gateway.gateway.networking.k8s.io/edge-gateway unchanged
httproute.gateway.networking.k8s.io/dx1-direct-echo configured
httproute.gateway.networking.k8s.io/dx1-engine-route configured
deployment "dx1-engine" successfully rolled out
deployment "dx1-echo" successfully rolled out

== DX1 lab setup complete
NAME                                             CLASS   ADDRESS   PROGRAMMED   AGE
gateway.gateway.networking.k8s.io/edge-gateway   nginx             True         4h58m

NAME                               TYPE       CLUSTER-IP        EXTERNAL-IP   PORT(S)                      AGE
service/dx1-nginx-gateway-fabric   NodePort   192.168.194.218   <none>        80:31437/TCP,443:31277/TCP   4h59m
NAME                                READY   STATUS    RESTARTS   AGE
pod/dx1-echo-566884dfc7-9rrfq       1/1     Running   0          5h36m
pod/dx1-engine-85bcbf998d-sqrrk     1/1     Running   0          149m
pod/dx1-operator-7c8f6486cd-fxpnc   1/1     Running   0          152m

NAME                   TYPE        CLUSTER-IP        EXTERNAL-IP   PORT(S)    AGE
service/dx1-echo       ClusterIP   192.168.194.244   <none>        8080/TCP   5h36m
service/dx1-engine     ClusterIP   192.168.194.202   <none>        8080/TCP   5h36m
service/dx1-operator   ClusterIP   192.168.194.237   <none>        1936/TCP   161m

NAME                           READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/dx1-echo       1/1     1            1           5h36m
deployment.apps/dx1-engine     1/1     1            1           5h36m
deployment.apps/dx1-operator   1/1     1            1           161m

NAME                                      DESIRED   CURRENT   READY   AGE
replicaset.apps/dx1-echo-566884dfc7       1         1         1       5h36m
replicaset.apps/dx1-engine-84cd67c44c     0         0         0       5h36m
replicaset.apps/dx1-engine-85bcbf998d     1         1         1       149m
replicaset.apps/dx1-engine-c8ccf9886      0         0         0       151m
replicaset.apps/dx1-operator-56b5f48dbc   0         0         0       158m
replicaset.apps/dx1-operator-56c495d4cf   0         0         0       157m
replicaset.apps/dx1-operator-5f48b9b674   0         0         0       152m
replicaset.apps/dx1-operator-7855f6c8f4   0         0         0       161m
replicaset.apps/dx1-operator-7c8f6486cd   1         1         1       152m
replicaset.apps/dx1-operator-bb566b4d9    0         0         0       153m
| stage 1 PASS — cluster + NGF + engine + echo up (lab left installed)

------------------------------------------------------------
| STAGE 2/3 — apply→effect, M9 timed (lab/dx1/apply-effect.sh)
------------------------------------------------------------

== (a) lab up (lab/dx1/setup.sh, idempotent)

== (pre) CRD + operator image + operator deployment
Image: "trishula-operator:dx1" with ID "sha256:16732a0b2bebf06e806f37c83862bc80f99f23f551aa1a214246d8c9ec5cd360" found to be already present on all nodes.

== pre-policy baseline: the benign probe passes transparently (200)

== (b) t0 — kubectl apply dx1-wafpolicy.yaml

== (c) operator compiled + engine consult active

== (d) effect: SQLi probe → 403
HTTP/1.1 403 Forbidden
Server: nginx
Date: Sat, 10 Oct 2026 05:07:55 GMT

== M9 apply→effect: 1465ms (target ≤ 5s) — PASS

== failure path — apply dx1-wafpolicy-broken.yaml (uncompilable CEL rule)

== operator logged the compile error

== fail-closed scenario: 1102ms from apply(broken) to the logged compile error; traffic unchanged; pods Ready

== TR-08c apply→effect complete — lab left running (no teardown)
| stage 2 PASS — CRD apply → operator compile → engine hot-reload → 403, within budget

------------------------------------------------------------
| STAGE 3/3 — hop evidence (lab/dx1/verify.sh) — the demo's closing transcript
------------------------------------------------------------

== hop 1 — NGF (Gateway edge-gateway, GatewayClass nginx)
NAME           CLASS   ADDRESS   PROGRAMMED   AGE
edge-gateway   nginx             True         4h59m
NAME                   TYPE        CLUSTER-IP        EXTERNAL-IP   PORT(S)    AGE
service/dx1-echo       ClusterIP   192.168.194.244   <none>        8080/TCP   5h36m
service/dx1-engine     ClusterIP   192.168.194.202   <none>        8080/TCP   5h36m
service/dx1-operator   ClusterIP   192.168.194.237   <none>        1936/TCP   161m

NAME                           READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/dx1-echo       1/1     1            1           5h36m
deployment.apps/dx1-engine     1/1     1            1           5h36m
deployment.apps/dx1-operator   1/1     1            1           161m

== Gateway edge-gateway Accepted=True Programmed=True (§10.2: NGF steers to the engine Service as a plain backend)

== hop 2 — request through NGF -> engine (path /v1/chat/completions, Host dx1-routed.dx1.example.com, http://192.168.139.2:31437)
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 10 Oct 2026 05:07:57 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 846
Connection: keep-alive
Etag: W/"34e-RvcHtVgKdCMGVmEXaK1tBKUJEn4"
X-Powered-By: HTTP/2 Express (http2-express)
X-Trishula-Decision: pass
X-Trishula-Hop: engine

{
  "path": "/v1/chat/completions",
  "headers": {
    "host": "dx1-routed.dx1.example.com",
    "user-agent": "curl/8.7.1",
    "accept": "*/*",
    "x-forwarded-for": "192.168.194.1, 192.168.194.79",
    "x-forwarded-host": "dx1-routed.dx1.example.com",
    "x-forwarded-port": "80",
    "x-forwarded-proto": "http",
    "x-real-ip": "192.168.194.1",
    "accept-encoding": "gzip"
  },
  "method": "GET",
  "url": "/v1/chat/completions",
  "body": "",
  "cookies": {},
  "fresh": false,
  "hostname": "dx1-routed.dx1.example.com",
  "ip": "192.168.194.1",
  "ips": [
    "192.168.194.1",
    "192.168.194.79"
  ],
  "protocol": "http",
  "httpVersion": "1.1",
  "query": {},
  "signedCookies": {},
  "subdomains": [
    "dx1",
    "dx1-routed"
  ],
  "xhr": false,
  "os": {
    "hostname": "dx1-echo-566884dfc7-9rrfq"
  },
  "connection": {}
}

== hop 3 — the echo pod responded through the engine (hop-by-hop headers)

== echo response body host (demo pod id): dx1-echo-566884dfc7-9rrfq

== contrast — Host direct-echo.dx1.example.com on the same NGF NodePort lands directly on the echo pod (no X-Trishula-Hop)
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 10 Oct 2026 05:07:57 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 800
Connection: keep-alive
X-Powered-By: HTTP/2 Express (http2-express)
ETag: W/"320-N/NN11Q2y5Gu5Leuf8UlRsDjTRc"

{
  "path": "/anything/at/all",
  "headers": {
    "host": "direct-echo.dx1.example.com",
    "x-forwarded-for": "192.168.194.1",

== engine-local /healthz (readiness gate, answered by the engine itself)
ok <- engine-local /healthz (192.168.194.91:8080)

== DX1 verify: hop 1 NGF -> hop 2 engine -> hop 3 echo pod all evidenced above

== §10.2 variant A reproduced live: gateway -> engine backend -> transparent forward -> demo pool

== Done. The lab remains installed (no teardown).
| stage 3 PASS — NGF → engine → echo pod hop-by-hop evidenced

============================================================
== DEMO-OK — lab/demo.sh complete: setup + M9 apply→effect + hop evidence all PASS (lab left running, no teardown)
============================================================
```

## Shield visibility tiers (issue #80)

The shield's guarantees depend on what the kernel hook actually SEES —
and on OrbStack-family veth fast paths the attach altitude is not the
effective altitude (established-flow segments skip clsact ingress; generic
XDP misses netns-sourced UDP; ICMP invokes XDP reliably). The loader
therefore **measures** the visibility tier at boot
(`internal/shield.ShieldTier`: a 5-packet probe burst, classified from
the programs' per-CPU probe counters) and emits
`trishula.shield.visibility_tier` once per interface (tier literal; the
shield startup attribute on the OTel pipeline — internal/shield/tier_otel.go).
Measured in CI by `lab/tier-gate.sh` (`TIER(<iface>)=<tier>` lines; the
tagged E2E lives in `test/tier/`).

| Tier | Meaning | Enforcement posture |
|---|---|---|
| `full` | every packet observed at both altitudes (XDP + TC) | full payload visibility at TC |
| `first_packet` | only the first packet of a connection reaches TC; XDP none (or ICMP-only) — OrbStack pod-veth posture | ban/ACL on first packet ONLY — enforcement correct for NEW connections (the first packet carries the verdict); payload deep-inspection degraded to sampled flows |
| `none` | no packets visible at any altitude | loader must refuse + fail loudly (`TierRefusal`) — an invisible shield is a false sense of security |

## License

MIT — see [LICENSE](LICENSE).
