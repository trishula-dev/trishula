# lab/module-1 — the wire lab (TR-27a)

The module-1 lab replays the §11.8 differential corpus. Spec §7.2 pins
Module 1's teaching corpus to exactly that corpus (the
[§7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules)
rule; the corpus record sits on
[spec §11.8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate)).
The doc side of the module:
[docs/academy/module-1.md](../../docs/academy/module-1.md).

## Run it

```bash
bash lab/module-1/run.sh
```

Three hermetic legs. No cluster, no kernel, no network:

| Leg | What runs | The gate |
|---|---|---|
| wire | the converter ([`lab/module-1/wire/`](wire/) main.go) reuses the harness's strict corpus loader (`crsdifferential.LoadCorpus`) and writes one raw HTTP/1.1 request file per case | 20 wire files, one per corpus case |
| replay | `cmd/attackdemo crs` walks every wire file; the embedded-Coraza surface prints its verdicts per case (the demo CRS slice: rule ids print only where that slice matches) | one INTERRUPT or pass verdict per case |
| parity | `go test -tags coraza.rule.no_regex_multiline -count=1 -v -run TestCorpusParity ./test/crs-differential/` | `parity 19/19 ran (1 skipped)` against the full CRS slice |

The corpus carries one explicit skip (case 16, the ARGS-JSON gap; the
reason string lives in the corpus file and on
[`test/crs-differential/README.md`](../../test/crs-differential/README.md)).
The parity denominator is 19.

## The optional kind leg

```bash
lab/dx1/setup.sh         # the DX1 lab up first (idempotent; reuse, no teardown)
KIND_LAB=1 bash lab/module-1/run.sh
```

The cluster leg replays two corpus shapes through the DX1 stack on the
NodePort:

- **clean shape** — `GET /?q=hello` returns 200 and carries
  `X-Trishula-Hop: engine`: the request passed the engine proxy hop.
- **probe shape** — `POST /v1/chat/completions?q=1 UNION SELECT`
  returns 403 and carries `X-Trishula-Rule: DX-LAB-001`: the enforced
  lab rule reads the request line and the query part of the target —
  the module's anatomy lessons, live.

The block assertion reads the cluster's enforced policy state. Run
`lab/dx1/apply-effect.sh` first when the DX1 lab holds no enforced
policy (that script applies the DX1 policy and leaves the engine
enforcing `DX-LAB-001`; the module-1 leg then asserts the blocked
shape). The clean shape asserts on any DX1 lab with the engine hop
wired.

Without a reachable cluster the leg prints a loud SKIP line. The
script never reports a skipped leg as a pass.

## Knobs

| Knob | Default | Meaning |
|---|---|---|
| `TRISHULA_ROOT` | the script's grandparent | the repo checkout the legs build and run from |
| `KIND_LAB` | `0` | `1` runs the cluster leg |
| `NODE_HTTP_PORT` | `31437` | the DX1 NodePort (matches `lab/dx1/setup.sh`) |
| `DX1_HOST` | `engine.dx1.example.com` | the routed host header (the engine route's hostname) |

## CI surface

The nightly job (`module-1-wire-lab` in
[`.github/workflows/lab-nightly.yml`](../../.github/workflows/lab-nightly.yml))
runs the same script on a hosted runner; the cluster leg skips there
by default. Every pull request also runs the parity leg already: the
go-build workflow carries `go test ./...`, and the differential
package sits in that set.

## Evidence

Transcripts in PR bodies and issue records quote verbatim run output.
The recorded module-1 lab runs sit on the TR-27a record (issue
[#169](https://github.com/trishula-dev/trishula/issues/169)).
