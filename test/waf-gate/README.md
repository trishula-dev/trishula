# test/waf-gate

The per-PR adversarial WAF gate (TR-205, issue #291). The workflow
`.github/workflows/waf-gate.yml` calls the shared composite
`.github/actions/waf-harness-up` and opens a port-forward to the live
engine. Four layers run against the engine. The job summary records
the per-layer pass rates plus wall times, and every raw report ships
as a job artifact. The teardown step runs in `always()` and fails on a
delete breach. A red layer fails its step, so the check turns red.

## Layers and config files

| layer | tool (pin) | config file | verdict reads |
|---|---|---|---|
| go-ftw | go-ftw 2.6.2 binary (`pins.yaml`) | `ftw.yaml` + `crs-subset.txt` + `crs-overrides.yaml` | the per-test statuses over the CRS corpus at cloud mode |
| waf-bypass | waf-bypass commit `887f2f9d` (`pins.yaml`) | `waf-bypass-expectations.yaml` | the tool JSON buckets: bypassed, falsed, failed |
| gotestwaf-subset | GoTestWAF image 0.5.8 (`pins.yaml`) | case list `gotestwaf-subset.yaml` | the aggregated per-case JSON reports |
| gotestwaf-fp | GoTestWAF image 0.5.8 (`pins.yaml`) | `gotestwaf-fp.yaml` | the FP report: the blocked count |

`pins.yaml` holds every pin in one table: the workflow reads it and
fetches only the objects at these digests and commits. The gotestwaf
hub tag form is `0.5.8` (the git tag form is `v0.5.8`).

## Engine contract the gate pins

- A CRS-critical row blocks: 403, plus the CRS rule id in
  `X-Trishula-Rule`. The manual rule `WH-SQLI-001` stays separate.
- A no-rule row passes: the engine forwards; the upstream fixture
  answers 200 on every path.
- Benign traffic never blocks: the FP layer asserts a zero block count.
- The goTestWAF pre-check runs on every subset case: it sends one
  known payload (an XSS carrier with a SQLi string) and aborts the run
  when the engine blocks nothing.

## Verdict definitions

| layer | pass X/Y | verdict fail when |
|---|---|---|
| go-ftw | tests passed / tests executed | one test fails, the run exits non-zero, the sample sits under 180 tests, or the corpus probe loses the 403 plus the rule id |
| waf-bypass | PASSED bucket / processed payloads | one bypassed, one falsed, one failed, or a bucket dir outside the manifest |
| gotestwaf-subset | blocked / sent | one bypass, or one case report missing (the pre-check abort) |
| gotestwaf-fp | passed FP payloads / sent FP payloads | one blocked FP payload |

## Wall split (the 30 minute job budget)

| slice | expected wall |
|---|---|
| harness up (composite) | 6-8 min |
| go-ftw layer | 2-3 min |
| waf-bypass layer (15 worker threads) | 4-6 min |
| goTestWAF subset (6 docker runs) | 6-8 min |
| goTestWAF false positives (1 docker run) | 1-2 min |
| summary + teardown | under 1 min |

A green run completes at about 22-25 minutes, inside the
`timeout-minutes: 30` budget.

## go-ftw cloud mode and the overrides file

go-ftw v2.6.2 in cloud mode decides from the expected status only, and
returns pass for a test with no expected status (the schema-v2 CRS
rows carry rule ids, not statuses). The committed `crs-overrides.yaml`
therefore maps every subset test to a status: 403 for the rows whose
stages expect CRS rule ids (the engine block contract), 200 for the
no-expect rows (the engine forwards; the fixture answers 200). The
generator script ran at authoring time from the pinned corpus; the
output sits in the `.lane` receipts (204 tests: 182 block rows plus 22
pass rows). Regenerate on a corpus-row PR; never edit by hand.

## The change path

- Tool or corpus version bump: edit `pins.yaml` and the table above;
  the diff covers the digest or commit lines only.
- go-ftw case change: edit `crs-subset.txt` (one rule id per line) and
  regenerate `crs-overrides.yaml` from the pinned corpus (the generator
  in the `.lane` receipts; the layer floor holds at 180 executed
  tests).
- goTestWAF subset case change: edit `gotestwaf-subset.yaml`.
- Expectation change (a tolerance, an excluded dir, a battery dir
  row): edit the matching manifest and name the reason in the PR.
- A red finding (a bypass, a false positive) lands in an engine fix
  PR; the manifest change then commits the new expectation. This
  follows the corpus-row path (issue #291).

## Pin provenance

Every digest in `pins.yaml` was recorded from an authoring-time fetch
(the CRCS archive, the go-ftw release asset, the docker hub tag index)
and is re-checked by the layer scripts with `sha256sum -c` at run time
and by the docker pull digest match. The full receipts sit in the
`.lane` directory of the authoring tree. The tool runs themselves
prove on the PR CI run: network fetches and image pulls run CI-side.
