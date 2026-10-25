# lab/dx1 — DX1 lab (TR-06)

Three steps from `main` to the live variant-A topology from
[spec §10.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#102-the-contract-trishula-as-a-gateway-api-citizen)
and the walkthrough of
[§10.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#103-the-reference-walkthrough-the-lab-every-claim-is-proven-in),
run on a local Docker provider (kind, or the OrbStack-provided Kubernetes).

```
client ──> NGF (Gateway edge-gateway, class nginx)     hop 1
        ──> dx1/dx1-engine Service (cmd/engine)        hop 2  X-Trishula-Hop: engine
        ──> dx1/dx1-echo Service (demo pool)           hop 3  x-echo-node
```

## Step 1 — setup

```bash
lab/dx1/setup.sh
```

Idempotent: an existing cluster (kind **or** OrbStack-provided Kubernetes)
is reused, the engine image is rebuilt, helm installs / is left alone, and
the Gateway + HTTPRoute + backends are (re-)applied. Requires `docker`,
`crane`, `helm`, `kubectl`, `go`. Knobs: `NGF_CHART_VERSION` (default
2.7.2), `NODE_HTTP_PORT` (31437), `OUT_IMG`, `BIN`, `NGF_RELEASE`, `NGF_NS`.

## Step 2 — verify

```bash
lab/dx1/verify.sh
```

Curls the NodePort with hop-by-hop headers:

- **hop 1** — NGF `edge-gateway` `Accepted`/`Programmed` conditions
  (gateway tier).
- **hop 2** — response carries `X-Trishula-Hop: engine` (the request passed
  through the engine proxy).
- **hop 3** — the echo pod's own response header (`X-Powered-By: HTTP/2
  Express`) + the pod id in the JSON body prove the demo pool answered
  through the engine, not the gateway alone.
- **contrast** — `Host: direct-echo.dx1.example.com` on the same NodePort
  lands on the echo pod directly (no `X-Trishula-Hop`): the engine is the
  steered backend only because the HTTPRoute says so.
- **healthz** — engine-local `/healthz` (readiness = bundle state in the
  real engine; here, proxy liveness) is answered by the engine, not the
  upstream.

## Step 3 — read the evidence

Hop headers in the verify output map 1:1 to the hops in the topology
diagram above; the engine hop's `X-Trishula-Hop` marker and the echo pod's
JSON body are the acceptance evidence for the [DX1 issue](https://github.com/trishula-dev/trishula/issues/6)
(request through NGF reaches the engine → demo pod and returns; the §10.2
variant-A diagram reproduced live).

## TR-198 — the S3 claims gate (the request.auth vocabulary)

```bash
lab/dx1/dx1-auth.sh
```

Runs the design record's example set end to end through the lab (the
[auth/JWT verdict record](https://github.com/trishula-dev/trishula/blob/main/docs/design/auth-jwt-verdict.md)
places the claims policy at S3): an enforced vocabulary rule gates
`/orders/*` on a verified identity carrying the `read:orders` scope; the
pack itself carries the optional in-engine HS256 verifier bundle the
operator supplies (the lab fixture key, never a secret). The script
rebuilds the engine + operator images from the checkout, applies
`dx1-rulepack-auth.yaml` + `dx1-wafpolicy-auth.yaml`, feeds the compiled
bundle to the running engine, and probes through NGF:

| probe | effect |
|---|---|
| no bearer | `403`, `X-Trishula-Decision: block`, `X-Trishula-Rule: auth:scope_insufficient` |
| verified, no `read:orders` | `403`, the same gate (the membership read denies) |
| verified + `read:orders` | `200` forward (the gate opens, not the route) |

Idempotent like apply-effect; the lane replaces the consult bundle —
re-running `just apply-effect` restores the SQLi gate shape afterwards.
The lab is left running.

## TR-08c — apply→effect, the timed M9 test

```bash
lab/dx1/apply-effect.sh
```

The cluster round trip of [issue #76](https://github.com/trishula-dev/trishula/issues/76)'s
M9, on the Step-1 lab (reused; no teardown): `kubectl apply` of a WAFPolicy
CR → the operator pod (cmd/operator, deployed by the script from the repo)
compiles it — rule-pack resolution + CEL compile, fail closed — publishes
`bundle.json` to the `dx1-wafpolicy-bundle` configmap → the script feeds it
to the running engine's polled `-receive-bundle /bundle.json` path (the
engine hot-reloads, no restart) → the effect is visible on traffic through
NGF.

**What the timing means.** `t0` = the `kubectl apply` of
`deployment/dx1/manifests/dx1-wafpolicy.yaml`; `t1` = the first POST through NGF that the
enforced rule `DX-LAB-001` blocks (`403`, `X-Trishula-Decision: block`,
`X-Trishula-Rule: DX-LAB-001`), while a benign POST still passes
(`defaultAction: pass` — the TR-06 transparent forward preserved). The
duration (`t1 − t0`) is the full **policy-authoring → enforcement** latency
an operator would feel end to end: API apply → operator reconcile/compile →
bundle publish → engine pickup + hot-reload → the deciding request. The
script prints it and FAILs above the M9 budget (`M9_TARGET`, default 5s).

Measured on this lab (2026-10-10, NGF 1.6.2 fallback single-pod, kind
provider):

| leg | measured |
|---|---|
| apply → operator compiled → engine `consult active` (live watch) | ~1s |
| **scripted apply→effect, fresh t0→t1** (POST probes) | **2618ms ≤ 5s PASS** |
| failure path: broken apply → `COMPILE FAILED` logged | 1146ms |

**Failure path (fail closed, also timed).** After deleting the good policy,
the script applies `deployment/dx1/manifests/dx1-wafpolicy-broken.yaml`, whose rule set
resolves to the committed uncompilable fixture
`deployment/dx1/manifests/dx1-broken-pack.yaml` (`size(request.body.messages) > 128` —
no body view in the §11.3 structured request yet, so the operator's
compile gate rejects it: `no such key: body`). The operator logs
`COMPILE FAILED dx1/broken-rule-gate … (no bundle published — fail closed)`,
publishes **no** bundle, and the engine keeps the previously loaded bundle:
the SQLi probe stays blocked, the benign request still passes — the traffic
shape is exactly what it was, and both pods stay Ready. A broken policy
never widens enforcement and never takes the route down; it only ever
fails to exist (§8, §2.3).

Idempotent: re-run the script any time — it rebuilds/redeploys the operator,
re-applies the rule-pack configmaps, resets to a clean policy slate, and
re-times the scenario. Probes are POST (`request.method == "POST"` in the
enforced rule); cluster is left running.

## The DX1 timed gate — clone → first enforced rule (M3)

```bash
bash lab/dx1/dx1-gate.sh
```

One command from a repo checkout. The gate builds the linux engine and
operator binaries from the tree when missing, brings the lab up, times
the apply→effect leg and runs the hop evidence. The gate asserts the DX1
charter (§5 DX1) and the M3 gate
([§21 M3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates)):
**clone → first enforced rule ≤ 15 min.**

- `DX1_START` (epoch seconds) — the clock anchor. The nightly job sets it
  right after checkout; the measured window then covers the full clone →
  rule path. A plain run anchors at script start.
- `DX1_TARGET` (seconds, default 900) — the budget: the M3 target of
  ≤ 15 min.

The first-enforced-rule moment comes from the apply-effect leg: the leg's
t0 plus its measured apply→effect latency. The gate prints the leg table
and names the moment (`first enforced rule at Ns`), and FAILs above the
budget. The fail-closed broken-policy path and the hop evidence run after
the M3 moment; they fail the gate, they never inflate the reading.

The nightly job
([.github/workflows/lab-nightly.yml](../../.github/workflows/lab-nightly.yml))
checks this repo out on a hosted runner, anchors the clock and runs this
gate: kind + NGF + Trishula + one CEL rule, anonymous pulls only. The
nightly run is the M3 evidence: the timed schedule stays green under
15 min.

## TR-31 — the behavioural DoS detector features (kernel-gated)

```bash
sudo go test -tags ingest4d -run TestFlowStatsDoSFeaturesE2E ./internal/engine/ingest/ -v
```

The TR-31 gate (in a Linux kernel VM with root: netns + clsact + bpffs)
installs `flow_tc.c` on a veth pair under `/sys/fs/bpf/tr31`, moves real
traffic through the attached hook, drives a paced 28-segment trickle (one
5-tuple, 9-byte payloads), and reads the shield's per-flow map live. What
the run proves, with the 2026-10-24 in-VM reading
(trishula-build-dev, kernel 7.0.14-orbstack, arm64):

| proof | where it reads | recorded run |
|---|---|---|
| the detector map carries the time-window features | `flow_stats` rows via the generated BTF mirrors: `segs=56 bytes=504` over one 5-tuple, `first=/last=` segment stamps spanning the ~2.6 s trickle | burst row: `family=4 daddr=01071f0a segs=56 bytes=504 ...` |
| a SYN-first flow keeps its syn stamp | the GET's flow row: `syn=90295969627444 segs=14 bytes=62` | syn-first row: `sport=47640 ...` |
| fail-open: accounting never enforces | real GET lands through the attached hook; `ban_table` iterates empty; the live features read clean through the real `rateban.SlowlorisSuspect` (the short-window trickle is clean) | `decision read: slowloris_suspect=false ... {Segs:56 Bytes:504 ...}` |
| zero residue after teardown | snapshot (id, name) pairs settle dead + `tc filter show` reads no bpf rows + the pin subtree is gone | `residue: zero — every snapshot identity (maps/progs/filters/pins) left the kernel` |

The decision side (the slowloris shape math, the rapid-reset ratio, the
cue→ban-engine wiring through the existing evidence sink) is kernel-free
by the layer map: its table rows live in `internal/engine/rateban`
(`TestSlowlorisRows`, `TestRapidResetRows`, `TestIngestCueWiring`) and
`internal/engine/http2` (`TestResetAccountingRows`).

**What the DX1 surface does not support.** The DX1 lab attaches no shield:
the NGF hop terminates TLS before the shield would see flow payload, and
the lab carries no `flow_stats` reader. No DX1 transcript is claimed for
the detector path; the kernel-gated gate above is the recorded evidence
(the AGENTS.md gate table carries the row).

## TR-203 L4 — the lab terminator's PQC termination leg

```bash
bash lab/dx1/pqc-termination-read.sh
```

The `https` listener row sits in the committed `dx1-gateway.yaml`
(`tls.mode: Terminate`) and names the `dx1-lab-tls` Secret. setup.sh
creates that Secret. The row = the lab terminator's TLS surface. The read
prints the gateway conditions, the Service's https NodePort row and the
handshake transcript:

- **the transcript row** — `Negotiated TLS1.3 group: X25519MLKEM768`.
  The NGINX dataplane negotiates the hybrid with the stack default. The
  2.7.2 image = OpenSSL 3.5.8.
- **the fallback finding** — the 1.x single-pod dataplane image (1.6.2,
  the OrbStack lane) runs OpenSSL 3.3.2. The read then negotiates
  `X25519` and files the classical finding. The read never reports a
  classical group as a pass.
- **the engine listener's own transcript** — the profile test
  (`docs/deploy/tls-termination-pqc.md`, section 5).

Record: [docs/deploy/tls-termination-pqc.md](../../docs/deploy/tls-termination-pqc.md)
(the TR-203 L4 posture: the surfaces, the chart census, the cloud-LB posture
row).

## TR-203 L2 — the QUIC-ingress leg (the h3 listener + the probes)

```bash
bash lab/dx1/h3-ingress-read.sh          # P4 (the advisory h3spec pass) + the h3 hop of P8
go test ./test/dosrunner/ -run TestUDPBanIdentityRows -v   # P7, in-VM (root)
```

The topology extends the DX1 lab with the h3 client leg. The record:
[../../docs/design/h3-ingress-posture.md](../../docs/design/h3-ingress-posture.md)
is the design record; its plan, step 2, is this leg.

```
h3 client (QUIC) ──UDP:443──> dx1-terminator (the h3 terminator leg)   the leg 1 hop
        ──h1 upstream──> dx1-engine Service (cmd/engine)               the leg 2 hop
        ──h1──> dx1-echo Service (the demo pool)                       the leg 3 hop
```

The rows the setup applies:

| Leg | Surface | The nodePort rows |
| --- | --- | --- |
| the QUIC client hop | `dx1-terminator` pod (the 2.7.2 dataplane image's nginx; the build carries `--with-http_v3_module`) | UDP 443 → `31440` |
| the same listener's TCP side | the same pod (`listen 443 ssl`) | TCP 443 → `31441` |
| the upstream hop | `dx1-engine` (the h1 proxy hop, unchanged) | — |

The read's stages:

1. **the topology leg** — the Service's `quic` UDP row + the fixture
   Secret + the terminator pod's Running row.
2. **probe P4, the advisory h3spec pass** — the pinned `h3spec`
   release binary (v0.1.14; the sha pins the mac arm64 asset). It dials
   the QUIC listener. It prints the error-case set. The tool's output
   joins no verdict (the record's N5). The transcript = the advisory
   signal. The finding: the terminator's QUIC stack answers the strict
   TLS-layer cases. It drops most transport and h3 error-code datagrams
   silently.
3. **the h3 hop of P8** — the script builds the pinned `quic-go` probe
   client (v0.64.1). The client = a temp module; the repo's `go.mod`
   stays untouched. It sends one real GET. The response carries
   `HTTP/3.0`, the engine's `X-Trishula-Hop` marker and the echo body.
   The view parity holds behind the h3 terminator (the record's P8).

Boundary rows:

- NGF carries no h3 listener row (the compatibility page and the
  changelog read none). The terminator leg = the operator's own nginx
  build, the same image the lab's 2.7.2 dataplane runs. The terminator
  image pins the 2.7.2 ref. The h3 leg stays up on both lanes. The
  1.6.2 fallback lane's dataplane serves only the NGF-side TLS leg.
- The fixture Secret (`dx1-lab-tls`) now carries the `127.0.0.1` IP SAN
  next to the DNS rows. The host-side dials dial by address. The
  fixture stays the 30-day lab pair; never a product cert.
- Probe P7 (the ban identity) reads the kernel leg, not this script:
  the L1 UDP leg's own gate. The run: in-VM, root, the command above.
  The row SHOTs its keyed source's QUIC-class flow and never covers the
  re-addressed stream (the record's N7 gap, measured).
- No h3spec run enters CI; the probes stay advisory lab material.
- The setup's `kind-config.yaml` now maps the two new rows
  (`31441/tcp`, `31440/udp`). An existing kind cluster needs a
  re-create to carry the UDP mapping. The OrbStack k8s lane forwards
  the NodePorts to `127.0.0.1` already (measured: the probe dials read
  `127.0.0.1:31440`).

## Notes

- The NGF chart ships from the NGINX OCI registry
  (`oci://ghcr.io/nginx/charts/nginx-gateway-fabric`); the current chart is
  NOT in the legacy `helm.nginx.org` index. `setup.sh` installs via OCI and
  falls back to the official chart package (same bytes, official release)
  on keychain-flaky hosts.
- **k8s-under-OrbStack:** NGF 2.x dataplane registration is agent-based and
  fails there (the agent builds the nginx instance from
  `/proc/<pid>/cmdline`; under OrbStack's containerd the `setproctitle`
  rewrite never lands in `/proc`, the dataplane pod stays 0/1 with
  `timed out waiting for agent to register nginx`). When the 2.x dataplane
  is not ready, `setup.sh` automatically retries with the NGF **1.x
  single-pod architecture** (`NGF_FALLBACK_CHART_VERSION`, default 1.6.2 —
  control + data plane in one pod, no agent handshake) and pins the
  `NODE_HTTP_PORT`. The steering evidence is identical. A direct
  `NGF_CHART_VERSION=1.x` pin rides that lane from the start. The nightly
  CI gate pins `NGF_CHART_VERSION=1.6.2`: the 2.7.2 OCI install misses the
  5m helm deadline on the runner and the chart-package retry gives no
  installable chart (issue #198, run 40077270222). Local labs keep the
  2.7.2-first default, so the 2.x lane keeps its re-entry attempts there.
  (Plain docker
  containers are unaffected; see the filed OrbStack issue for the containerd
  `/proc` title-rewrite reproduction.)
- The chart ships no Gateway API CRDs; CRDs come from the pinned
  Gateway API v1.5.1 sources (matching the NGF v2.7.2 install refs). The
  listener sets `allowedRoutes.namespaces.from: All` — cross-namespace
  HTTPRoute attach (dx1 routes -> nginx-gateway Gateway) would otherwise
  surface `NotAllowedByListeners`.
- The engine image is built locally (`scratch` + the `cmd/engine` Go
  binary) — no registry push needed; swap in a `ko` build for
  registry-direct delivery.
- The engine is the transparent reverse proxy (TR-06); the compiled-bundle
  consult + hot-reload ride the TR-08c leg (the timed test above). The
  rate-enforcement engine (ScoredWindowBan) is TR-09/TR-10.
