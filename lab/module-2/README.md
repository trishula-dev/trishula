# lab/module-2 — the TLS/QUIC lab (TR-28)

The module-2 lab exercises the TLS/QUIC lessons: the JA4 assembly and
its golden vectors, the header-plane shapes, the h2 head
classification, and the DX1 termination read. The doc side of the
module: [docs/academy/module-2.md](../../docs/academy/module-2.md).
The spec surfaces:
[§7.1 Module 2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches),
[§7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules)
and
[§12](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#12-bot-defense--anti-automation).

## Run it

```bash
bash lab/module-2/run.sh
```

Three hermetic legs. No cluster, no kernel, no network:

| Leg | What runs | The gate |
|---|---|---|
| ja4 | `go test ./internal/engine/botdef/` over the JA4 tests: golden vectors, hash variants, ALPN codes, self-consistency | every golden vector reproduces; the QUIC transport variant derives |
| header-plane | the same package over the header-fingerprint tests | browser and tool shapes classify apart |
| h2 | `go test ./internal/engine/http2/` | stream, gRPC and SSE heads reconstruct on the one request view |

The ja4 leg carries the QUIC-transport derivation: the vector set
flips the summary transport to `q` and re-renders the string, live.

## The optional DX1 leg

```bash
lab/dx1/setup.sh         # the DX1 lab up first (idempotent; reuse, no teardown)
KIND_LAB=1 bash lab/module-2/run.sh
```

The termination leg reads the lab topology of
[Module 2, lesson 2](../../docs/academy/module-2.md):

- **hop shape** — `GET /?q=hello` returns 200 and carries
  `X-Trishula-Hop: engine`: the request passed the engine hop.
- **listener read** — `kubectl` reads
  `gateway.edge-gateway listeners[0].protocol` and prints it. The DX1
  lab ships the plain-HTTP listener row (listeners[0]; the reference
  deployment terminates TLS at this hop). The HTTP-listener row carries
  the read. An HTTPS row exists since TR-203 L4: listener `https` in
  `deployment/dx1/manifests/dx1-gateway.yaml`. Its key-exchange read runs
  separately: `bash lab/dx1/pqc-termination-read.sh`. The record:
  [docs/deploy/tls-termination-pqc.md](../../docs/deploy/tls-termination-pqc.md).
  The h3/QUIC listener leg stays PENDING on the lab itself. The TR-203 L2
  lane owns the build.

Without a reachable cluster the leg prints a loud SKIP line. The
script never reports a skipped leg as a pass.

## Knobs

| Knob | Default | Meaning |
|---|---|---|
| `TRISHULA_ROOT` | the script's grandparent | the repo checkout the legs build and run from |
| `KIND_LAB` | `0` | `1` runs the termination leg |
| `NODE_HTTP_PORT` | `31437` | the DX1 NodePort (matches `lab/dx1/setup.sh`) |
| `DX1_HOST` | `engine.dx1.example.com` | the routed host header (the engine route's hostname) |

## CI surface

The nightly job (`module-2-tls-lab` in
[`.github/workflows/lab-nightly.yml`](../../.github/workflows/lab-nightly.yml))
runs the same script on a hosted runner; the termination leg skips
there by default. Every pull request runs the same packages already:
the go-build workflow carries `go test ./...`.

## Evidence

Transcripts in PR bodies and issue records quote verbatim run output.
The recorded module-2 lab runs sit on the TR-28 record (issue
[#28](https://github.com/trishula-dev/trishula/issues/28)).
