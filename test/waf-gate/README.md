# test/waf-gate

The per-PR adversarial WAF gate (TR-205, issue #291). The workflow
`.github/workflows/waf-gate.yml` calls the shared composite
`.github/actions/waf-harness-up` and opens a port-forward to the live
engine. Four layers run against the engine. The job summary records
the per-layer pass rates plus wall times, and every raw report ships
as a job artifact. The teardown step runs in `always()` and fails on a
delete breach. A red layer fails its step, so the check turns red.

## The recast: what the gate pins (the lane-d fix pass)

The live engine's CRS surface is SHADOW-FIRST by the spec: the
`internal/crs` stage is the projected-data evaluator, CRS matches land
in the verdict record as data, and enforcement is the pack rules with
`action: enforce` evaluated by the CEL stage. The CEL request view
carries method/path/query only — no headers, no body — and the CEL env
carries no case-folding (the lower() family does not compile; verified
against the shipped `internal/engine/cel` compile path). The first CI
run (#299) failed the CRS-status layer on exactly this: the go-ftw
status contract expected CRS-critical rows at 403, impossible on the
shadow-first surface. The gate recasts to the honestly-enforceable
surface:

- **Layer 1 runs as the CRS detection-record (shadow, record-only).**
  The go-ftw run feeds the generated override map
  (`crs-overrides.yaml`, the product of `gen-crs-overrides.py`) and its
  never-gates line lands in the summary with the detection counts the
  report shows. The CRS enforcement rides the compiled fast-path lane
  (the shipped rulepack), not this gate.
- **The enforcement pin gates instead:** the WH-SQLI-001 probe
  (403 + `X-Trishula-Rule: WH-SQLI-001`) — the fixture pack's pin rule
  over the `/search` route. The pin verdict is layer 1's red path.
- **Layer 2's verdict reads the plain query leg.** The battery tool
  runs every payload's plain leg AND its evasion legs (Base64/UTF-16/
  HTML-ENTITY) over six channels (URL path, ARGS, BODY, COOKIE,
  USER-AGENT, HEADER). The engine can only answer the query channel's
  literal shapes, so the expectations manifest pins: the
  `expected_blocked_dirs` rows (a bypass on a plain ARGS leg of these
  fails), the `not_enforced_dirs` rows (the measured split plus the
  reason: non-view channels, encoding legs, the path channel, the
  unlisted literal families), the FP row, and the excluded tool dirs.
  The bypass threshold is zero, and it holds only over the blocked
  rows.
- **Layer 3's verdict reads the measured split.** The case ceiling
  (`bypassed_tests_max`) and the blocked floor (`blocked_tests_min`)
  carry the calibration freeze: the tool's encoder × placeholder
  matrix sends every payload once per combination, so the bypass count
  of a case reflects the whole matrix, not the query channel alone.
  A report with no recognized completed tests is rejected and fails
  the layer (the strict report reader).
- **Layer 4 holds the benign zero-block contract** (the FP battery),
  with the same strict report reader.

## Layers and config files

| layer | tool (pin) | config file | verdict reads |
|---|---|---|---|
| go-ftw-shadow | go-ftw 2.6.2 binary (`pins.yaml`) | `ftw.yaml` + `crs-subset.txt` + `crs-overrides.yaml` | record-only: the detection counts from the run log against the override map; NEVER a verdict |
| enforcement-pin | curl | the WH-SQLI-001 shape | 403 + `X-Trishula-Rule: WH-SQLI-001` (layer 1's red path) |
| waf-bypass | waf-bypass commit `887f2f9d` (`pins.yaml`) | `waf-bypass-expectations.yaml` | the tool JSON buckets, leg-first: zero bypassed-on-promised-legs, zero falsed, zero failed, full class coverage |
| gotestwaf-subset (**release stage, #293**) | GoTestWAF image 0.5.8 (`pins.yaml`) | case list `gotestwaf-subset.yaml` | the strict per-case JSON reads: the bypassed ceiling + the blocked floor per case, zero rejected reports |
| gotestwaf-fp (**release stage, #293**) | GoTestWAF image 0.5.8 (`pins.yaml`) | `gotestwaf-fp.yaml` | the FP report: zero blocks, zero rejected reports |

`pins.yaml` holds every pin in one table: the workflow reads it and
fetches only the objects at these digests and commits. The gotestwaf
hub tag form is `0.5.8` (the git tag form is `v0.5.8`).

## Engine contract the gate pins

- The WH-SQLI-001 probe blocks: 403, plus the rule id
  `WH-SQLI-001` in `X-Trishula-Rule`.
- A no-rule row passes: the engine forwards; the upstream fixture
  answers 200 on every path.
- The pack's multi-family query rules block the measured battery
  families (see `waf-bypass-expectations.yaml`: SQLi, CM, LFI, Misc,
  NoSQLi, SSTI, SSI clear at the plain-ARGS legs; RCE and XSS carry
  the measured reasons).
- Benign traffic never blocks: the FP layer asserts a zero block
  count; the gotestwaf false-pos texts and the battery FP dir read
  clean in the calibration.
- The goTestWAF pre-check runs on every subset case: it sends one
  known payload (an XSS carrier with a SQLi string) and aborts the run
  when the engine blocks nothing; the grown pack reads the pre-check
  blocked.

## The fixture pack (fixtures/waf-harness/manifests/policy-sqli.yaml)

The pack carries the pin rule WH-SQLI-001 plus the measured family
rows WH-SQLI-002, WH-XSS-001, WH-LFI-001, WH-RCE-001, WH-SSTI-001,
WH-NOSQLI-001, WH-SHELL-001, WH-SSI-001 — all query-anchored
`contains()` chains, case-sensitive, with per-rule `costBudget`
ceilings (the measured max reads ~20k against the 250k ceiling). The
tokens list every case form explicitly because the CEL env carries no
lower(); the calibration receipt recorded which battery legs each
family reaches.

## The crs-overrides generator (runnable from a clean checkout)

The overrides map regenerates from the pinned corpus. Run from the
repo root (the corpus per `pins.yaml` v4.30.0 tarball):

```
python3 test/waf-gate/gen-crs-overrides.py \
  <corpus>/tests/regression/tests test/waf-gate/crs-overrides.yaml
```

The generator reads `crs-subset.txt`, classifies every test's stages
(expect_ids → 403, else 200) and writes the map; the calibration
receipt shows the committed file reproducing byte-equal on the data
rows (204 tests, 182 block + 22 pass). The map pins the shadow record
only. Never edit by hand.

## Verdict definitions

| layer | pass line | verdict fail when |
|---|---|---|
| go-ftw-shadow | the record-only line + the detection-record line | never (record-only); the enforcement pin's verdict carries the step's red path |
| enforcement-pin | the probe read 403 + the rule header | the probe loses the 403 or the `WH-SQLI-001` header |
| waf-bypass | blocked-plain-legs + surface-gap counts | one bypassed plain-ARGS leg of an expected row, one falsed, one failed, or a bucket dir outside the classes |
| gotestwaf-subset | blocked / sent | one bypass over the case ceiling, one blocked under the case floor, one rejected report, or one case report missing |
| gotestwaf-fp | passed FP payloads / sent FP payloads | one blocked FP payload, one rejected report, or the run nonzero |

## Wall split (the 30 minute job budget)

| slice | expected wall |
|---|---|
| harness up (composite) | 6-8 min |
| go-ftw shadow leg + pin | 2-3 min |
| waf-bypass layer (15 worker threads) | 4-6 min |
| ~~goTestWAF subset~~ (moved to the release stage #293: a full case scan exceeds a per-PR wall — the sql-injection case alone scans minutes — plus the 0.5.8 worker race, the Intn(0) panic on the c4a60cd receipt) | — |
| summary + teardown | under 1 min |

A green run completes at about 22-25 minutes, inside the
`timeout-minutes: 30` budget.

## The change path

- Tool or corpus version bump: edit `pins.yaml` and the table above;
  the diff covers the digest or commit lines only.
- go-ftw case change: edit `crs-subset.txt` (one rule id per line) and
  regenerate `crs-overrides.yaml` with the committed generator (the
  command above).
- goTestWAF subset case change: edit `gotestwaf-subset.yaml`.
- Expectation change (a measured ceiling/floor, a not_enforced row, a
  battery dir row): edit the matching manifest and name the numbers in
  the PR. The not_enforced rows move UP with the surface: a pack
  family row grows the block count, a CEL view field (headers, body)
  unlocks whole channel groups — both are engine PRs and the manifest
  change commits with them (issue #291, the corpus-row change path).
- A red finding (a bypass on a promised leg, a false positive, a
  rejected report) lands in an engine fix PR; the manifest change then
  commits the new expectation.

## Pin provenance

Every digest in `pins.yaml` was recorded from an authoring-time fetch
(the CRCS archive, the go-ftw release asset, the docker hub tag index)
and is re-checked by the layer scripts with `sha256sum -c` at run time
and by the docker pull digest match. The full receipts sit in the
`.lane` directory of the authoring tree; the lane-d fix pass added the
calibration receipts (the offline wire model plus the live cluster
run). The tool runs themselves prove on the PR CI run: the network
fetches and image pulls run CI-side.
