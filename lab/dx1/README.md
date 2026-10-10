# lab/dx1 — DX1 lab (TR-06)

Three steps from `main` to the live variant-A topology from
[PRD §10.2](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#102-the-contract-trishula-as-a-gateway-api-citizen)
and the walkthrough of
[§10.3](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#103-the-reference-walkthrough-the-lab-every-claim-is-proven-in),
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
  `NODE_HTTP_PORT`. The steering evidence is identical. (Plain docker
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
- Engine CEL/ladder wiring is a later slice; this lab proves the steering +
  transparent-proxy shape.
