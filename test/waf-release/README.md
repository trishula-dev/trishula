# test/waf-release

The release-stage WAF suite (TR-205, issue #293). The workflow
`.github/workflows/waf-release-suite.yml` runs four legs on one
temporary managed Kubernetes cluster. The legs: the full goTestWAF
corpus, the sqlmap SQLi gate, the open-appsec differential and the
report publish. The cluster lives for the run and the teardown job
destroys it. The workflow never gates merges. It runs on
`workflow_dispatch` rehearsal and at release cuts; the nightly
schedule keeps the pins warm.

## The contract map (issue #293, RFC numbered)

1. The run provisions one temporary managed cluster and destroys it
   after. The pipeline holds no standing cluster credentials. The
   operator secret reaches only the job environments. Every job
   re-fetches its kubeconfig from the API with that per-run token. No
   artifact carries a kubeconfig.
2. The corpus job runs the full goTestWAF corpus and compares the pass
   rate against `baseline.yaml`. A regression marks the run red. The
   baseline carries pending-first-run semantics (below).
3. The sqlmap job runs sqlmap 1.10.11 at pinned flags. The target is
   the deliberately SQLi-vulnerable fixture (`vuln-app`, the `/search`
   route) through the enforcing engine. The runtime reads bounded, and
   the gate records 0 successful injections.
4. The differential job runs the same corpus on the open-appsec engine.
   The chart and images carry pinned digests. The diff job joins both
   reports per corpus row and publishes the diff table.
5. The assets job assembles the report set and writes `SHA256SUMS`.
   The sheet runs strict: an empty set fails. The job attaches the set
   to the tag release when the tag input exists. On a rehearsal the
   report set stays a run artifact.
6. Every stage records its wall into the job summary. The
   `wall-times.jsonl` artifacts carry the same lines in machine form.
   The recorded-run form governs: measured readings only, never the
   estimates inside `wall-budget.yaml`.
7. `workflow_dispatch` rehearsal works with the tag input; the
   operator keeps the tag cut. The attach step refuses a missing tag.
   The workflow never creates one (`gh release create --verify-tag`
   creates the release object only).
8. The corpus verdict writes `bypass-findings.md` and names every
   offending row. The change path below lands the rows in the same
   change as the fix.

## Layout

| file | role |
|---|---|
| `pins.yaml` | every tool and image pin for this leaf, with the digest provenance notes |
| `baseline.yaml` | the pinned pass-rate baseline; pending-first-run semantics |
| `corpus-full.yaml` | the full-corpus manifest: flags, bounds, the verdict gates |
| `corpus-rows.yaml` | the six committed rows moved here from `test/waf-gate/gotestwaf-subset.yaml` |
| `corpus-fp.yaml` | the false-pos contract moved here from `test/waf-gate/gotestwaf-fp.yaml` |
| `sqlmap.yaml` | the sqlmap target, the pinned flags, the bounds, the verdict markers |
| `openappsec-differential.yaml` | the open-appsec config plus the routed Ingress object |
| `wall-budget.yaml` | the per-stage budgets and the estimate rows |

The goTestWAF image pin stays in `test/waf-gate/pins.yaml`. The #291
corpus-row change path owns it. This leaf reads that key at run time
and carries no second copy.

## The operator steps

1. Create the DigitalOcean personal access token for the release
   suite. Check the custom scope `kubernetes` with read-write only.
   Leave every other scope unchecked. The token sees the cluster API
   for one run, then the run ends.
2. Set the repository (or environment) Actions secret
   `WAF_RELEASE_DO_TOKEN` to that token. The workflow reads the secret
   in the provision job, the three driver jobs and the teardown job.
   No step prints or stores the token.
3. Cut the release tag when the release work lands. The operator keeps
   the tag cut; the suite attaches at the tag.
4. Rehearse. Run the dispatch on the branch that carries this suite.
   Input validation reads the workflow file at the dispatched ref, so
   a changed workflow must dispatch from the changed ref. Pass the tag
   as the input:

   ```
   gh workflow run waf-release-suite.yml \
     --repo trishula-dev/trishula \
     --ref <branch-or-main> \
     -f tag=<release-tag> \
     -f attach_release=true
   ```

   A first rehearsal runs the record path. The corpus leg records
   `baseline-recorded.json` and stays green (pending-first-run). A
   rehearsal without `-f tag` exercises the current main checkout with
   the artifacts-only record path.
5. After the first rehearsal: open the corpus-row PR. It moves
   `baseline-recorded.json` into `baseline.yaml` (`recorded:` filled,
   `pending_first_run: false`). From that landing on, every corpus run
   gates on the recorded rows and the 1 percentage point floor.
6. Watch the run in job order: provision, corpus, differential, sqlmap,
   diff, assets, teardown. Every job summary carries the recorded stage
   walls and the verdict lines. The teardown job fails the run when the
   cluster delete fails. It also fails when the cluster list still
   carries the cluster (fail on a breach).
7. A run might die before the teardown job (a cancelled run counts).
   The tag sweep in the teardown still deletes the cluster by the run
   id tag. As the manual fallback, use:

   ```
   doctl kubernetes cluster list -o json   # find wafrs-* names
   doctl kubernetes cluster delete <name> --force
   ```

## The change paths

- A bypass or a false positive the corpus finds: an engine fix PR
  carries the fix. The same change edits the matching manifest row
  (`corpus-rows.yaml` ceiling, `corpus-fp.yaml`, or
  `baseline.yaml` recorded rows). `bypass-findings.md` names the
  offenders.
- A tool or image version bump: a pins PR edits `pins.yaml`. The
  goTestWAF scanner key edits in `test/waf-gate/pins.yaml` (the same
  PR). The README table edits with the pins. The workflow picks the
  pins up; no workflow edit.
- A wall-bound or budget change: a manifest PR edits
  `wall-budget.yaml` and the matching `bounds:` block. The first
  rehearsal replaces the estimate rows with measured walls.

## The wall budget and the cost note

`wall-budget.yaml` carries the per-stage bounds. The estimate rows
marked pending-first-run cite no measured number yet. The corpus and
the differential legs run in parallel. The cluster wall reads:

```
provision + max(corpus, differential) + sqlmap + diff + assets + teardown
```

The node pool runs 2 nodes of s-4vcpu-8gb for the run window. No load
balancer service exists on any leg, so the bill reads nodes only. The
cluster exists for the run window only.

## The validation boundary

This leaf was validated locally. The checks:
YAML parses. actionlint runs clean (exit 0; the style notes resolved).
The drivers ran a dry battery against synthetic reports with the
goTestWAF JSON shape. The battery covered the gates, the baseline
record and compare paths, the sqlmap verdict parser, the diff join and
the checksum sheet logic. The sqlmap flag manifest reads against the
pinned flags. Every digest in `pins.yaml` was recorded at authoring
time (2026-11-11) from the live registry API or the upstream checksum
file.

The cluster provisioning, the sqlmap scan and the open-appsec
bring-up prove on the first rehearsal. The operator dispatches that
rehearsal after step 2. No local environment carries the DigitalOcean
credentials. The receipts sit in the `.lane` directory of the
authoring tree.
