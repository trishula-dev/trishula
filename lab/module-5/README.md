# lab/module-5 — the frontier lab (TR-28)

The module-5 lab exercises the frontier lessons that carry shipped
surfaces today: the verdict vocabulary, the operator compile gate, and
the DX1 fail-closed scenario. The doc side of the module:
[docs/academy/module-5.md](../../docs/academy/module-5.md). The spec
surfaces:
[§7.1 Module 5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches),
[§7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules)
and
[§14](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#14-ml--adaptive-detection).

## Run it

```bash
bash lab/module-5/run.sh
```

Two hermetic legs. No cluster, no kernel:

| Leg | What runs | The gate |
|---|---|---|
| verdicts | `go test ./internal/engine/ladder/` | the action vocabulary and the resolution semantics hold |
| fail-closed | `go test ./internal/operator/` over `TestReconcileFailClosedOnUncompilableRule` and `TestCompileRouteClassFailClosed` | an uncompilable policy returns its error and stamps nothing |

The other frontier surfaces carry no lab leg on purpose: the HTTP/3
ingress evaluation ([TR-29](https://github.com/trishula-dev/trishula/issues/29))
and the PQ posture are PENDING tracks. The module doc names each
wall. No leg reports a pending item as a pass.

## The optional DX1 leg

```bash
lab/dx1/setup.sh         # the DX1 lab up first (idempotent; reuse, no teardown)
KIND_LAB=1 bash lab/module-5/run.sh
```

The leg drives the shipped apply-effect scenario and asserts the
body-view wall of [Module 5, lesson 6](../../docs/academy/module-5.md)
on live traffic:

- **apply-effect** — `lab/dx1/apply-effect.sh` runs end to end: the
  enforced `DX-LAB-001` policy, the M9 timed leg, then its fail-closed
  leg: delete the good policy, apply
  [`dx1-wafpolicy-broken.yaml`](../../deployment/dx1/manifests/dx1-wafpolicy-broken.yaml).
- **operator log** — the leg greps the operator pod log for
  `COMPILE FAILED dx1/broken-rule-gate`: the uncompilable body-view
  rule publishes no bundle.
- **traffic read** — the benign POST still passes and the SQLi probe
  still blocks with `X-Trishula-Rule: DX-LAB-001`: the engine kept its
  previous bundle. The broken policy never widened enforcement.

Without a reachable cluster the leg prints a loud SKIP line. The
script never reports a skipped leg as a pass.

## Knobs

| Knob | Default | Meaning |
|---|---|---|
| `TRISHULA_ROOT` | the script's grandparent | the repo checkout the legs build and run from |
| `KIND_LAB` | `0` | `1` runs the DX1 fail-closed leg |
| `NODE_HTTP_PORT` | `31437` | the DX1 NodePort (matches `lab/dx1/setup.sh`) |
| `DX1_HOST` | `engine.dx1.example.com` | the routed host header (the engine route's hostname) |

## CI surface

The nightly job (`module-5-frontier-lab` in
[`.github/workflows/lab-nightly.yml`](../../.github/workflows/lab-nightly.yml))
runs the same script on a hosted runner; the DX1 leg skips there by
default. Every pull request runs the same packages already: the
go-build workflow carries `go test ./...`.

## Evidence

Transcripts in PR bodies and issue records quote verbatim run output.
The recorded module-5 lab runs sit on the TR-28 record (issue
[#28](https://github.com/trishula-dev/trishula/issues/28)).
