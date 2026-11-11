# fixtures/waf-harness — TR-205 (issue #289)

The fixture set of the CI WAF test harness. The workflow
`.github/workflows/waf-harness.yml` builds and deploys it on an ephemeral
kind cluster inside the job, and the smoke probe reads the engine's
verdict on the wire.

## The fixture apps

- `vuln-app/` — the deliberately SQLi-vulnerable app. One stdlib Go
  server. The `/search` route builds its statement by string
  concatenation: a UNION probe in the query reaches the statement. The
  store stays in memory; no real database joins the harness.
- `benign-app/` — the benign traffic app. One stdlib Go server. It
  serves its status record and a health route, and it accepts no query
  input.

`Dockerfile` serves both apps plus the engine and the operator images:
one scratch image per binary, `ARG BIN` picks the file.

## The deploy surface

`manifests/` deploys, in this order:

| file | objects |
|------|---------|
| `namespace.yaml` | the `waf-harness` namespace |
| `benign-app.yaml` | benign-app Deployment + Service |
| `vuln-app.yaml` | vuln-app Deployment + Service |
| `engine.yaml` | engine Deployment + the `waf-harness-engine` Service (the stable job-internal endpoint) |
| `operator-rbac.yaml` | the operator ServiceAccount, Role, RoleBinding |
| `operator.yaml` | operator Deployment + Service |
| `policy-sqli.yaml` | the SQLi rule pack ConfigMap + the `waf-harness-gate` WAFPolicy |

The WAFPolicy CRD applies from the repo's own single source,
`manifests/crd/wafpolicy-crd.yaml` (the harness copies nothing).

The engine forwards transparently to `vuln-app`
(`fixtures/waf-harness` keeps the TR-06 contract hop). The operator
compiles `waf-harness-gate` and publishes the bundle; the policy stage
feeds the bundle to the engine's polled path (the lab's proven receive
step) and the engine logs `consult active`.

The SQLi rule (rule id `WH-SQLI-001`, action enforce):

```
path.matches("/search") && request.query.contains("UNION")
```

The rule set shape follows the compiled lab pack
(`deployment/dx1/manifests/dx1-rulepack-sqli.yaml`). The bundle slot
name `dx1-wafpolicy-bundle` is hard-named in cmd/operator; the harness
waits on that name.

## Run the harness

Open the PR or run the workflow by hand
(`workflow_dispatch`). Each stage's raw output lands in the
`waf-harness-evidence` artifact, and the job summary carries one line
per stage. Local lanes run the same stages from the checkout:

1. `docker build` the four images from the checkout (the recipes below
   stamp the revision label).
2. `kind create cluster` with the pinned node image.
3. `kubectl apply -f` the seven `manifests/` files in the order above.
4. Port-forward `svc/waf-harness-engine` and probe.

Later tool stages (issue #291) call
`.github/actions/waf-harness-up` and dial the engine endpoint from its
outputs.
