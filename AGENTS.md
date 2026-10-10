# Trishula: guide for contributors and coding agents

This file is the single source of truth for humans and coding agents
(GitHub Copilot, Claude, Cursor, Hermes, etc.) working on Trishula. Tool-specific
files (`CLAUDE.md`, `.github/copilot-instructions.md`) only point here. When
this file and a tool-specific file disagree, this file wins.

Read the [Testing](#testing), [Kernel evidence](#kernel-evidence-and-the-lab),
[Pull requests](#pull-requests) and [Security](#security) sections before
changing anything. The rest is a map of the codebase.

Read the [PRD](docs/PRD.md) before any non-trivial change. The PRD is the design
source: every issue cites its sections, and every claim it makes is proven in
the lab, not asserted.

## Project overview

Trishula is a developer-first, eBPF-native Web Application and API Firewall for
Kubernetes: an **eBPF shield** at kernel altitude (XDP drop + TC flow events,
fail-open by default, bounded parsing, verifier-checked), a **userspace engine**
(OWASP CRS via embedded Coraza with a CI-blocking verdict-parity gate, CEL rules
over a structured request view, OpenAPI positive security, JA4/header bot
fingerprints, evidence-recorded ScoredWindowBan, OpenTelemetry-correlated
verdicts), and a **Kubernetes-native control plane** (`WAFPolicy` CRD → operator
compile → engine bundle, the §8.1 "one policy artifact, many enforcement
altitudes" pipeline).

The delivery unit is an **hour-scale slice** with a watchable RED→GREEN
commit pair ("leaf PR"): [TR-01 … TR-41](https://github.com/orgs/trishula-dev/projects/1)
map the [PRD](docs/PRD.md)'s design sections to runnable artefacts — every claim
is proven in the [DX1 lab](lab/dx1/README.md), not asserted.

Other documents worth knowing:

- [`README.md`](README.md): status, badge rows, layout, the §20.2 exit checklist.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): the working agreement (ground rules, PR template).
- [`SECURITY.md`](SECURITY.md): vulnerability reporting policy. See [Security](#security).
- [`docs/PRD.md`](docs/PRD.md): the design (v4) — **the** design source for every issue.
- [`docs/academy/`](docs/academy/): teach-the-web curriculum artifacts.
- [`docs/paper.md`](docs/paper.md): research paper source.

## Repository structure

| Directory | Purpose |
| --- | --- |
| `api/v1alpha1/` | CRD types: `WAFPolicy` (controller-gen artifacts committed: `zz_generated.deepcopy.go`) |
| `bpf/` | Kernel C sources: `shield_xdp.c` (XDP ACL/verdict-cache/ban table), `flow_tc.c` (TC ringbuf producer) — CO-RE, bpf2go |
| `cmd/` | Command surfaces: `engine` (transparent proxy host + bundle consult), `operator` (CRD watch → compile → bundle), `shield` (eBPF loader), `trishula` (CEL rule engine CLI), `trishulactl`, `attackdemo` (the TR-43 live demo binary) |
| `internal/engine/` | The detection ladder: `ingest/` (ringbuf drain → tx assembly), `ladder/` (S0–S5 verdicts + verdict vocabulary), `cel/` (the CEL rule env + request view), `http1/` (HTTP/1 parse into the §11.3 view), `botdef/` (JA4 + header fingerprints, §12), `rateban/` (ScoredWindowBan v1 + evidence sink, §13), `otel/` (verdict trace/metric/log triad, §15) |
| `internal/crs/` | The embedded Coraza wrapper (reference CRS evaluator, §11.2) + Seclang testdata |
| `internal/operator/` | `compile.go` (WAFPolicy → Bundle wire format v1 + Load verify gates + in-process Eval), `reconcile.go` (CRD watch → compile → bundle publish) |
| `internal/shield/` | Go loaders for the eBPF objects (XDP/TC attach, ban map publish/reconcile, evidence sink) |
| `lab/` | Everything runnable in the lab: `dx1/` (NGF steering + apply→effect + verify.sh), `demo-attack.sh` (TR-43), `verify-xdp-chain.sh` (kernel env gate), `tier-gate.sh` (visibility tier gate) |
| `test/` | Cross-cutting gates: `crs-differential/` (CI-blocking CRS parity harness), `ban-conformance/` (TR-09 oracle suite), `bench/` (TR-24 harness) |
| `docs/` | PRD, paper, academy |
| `.github/workflows/` | CI: `go-build.yml` (build + vet+ test across the module incl. the differential), `dependency-review.yml`, `scorecards.yml` |

## Architecture: request processing pipeline

```text
packet → [XDP on NIC] drop/ban/cache verdicts early → [TC on iface] ringbuf
      → engine: ringbuf drain (ingest) → HTTP/1 parse (per-conn tx) →
        ladder S0..S5 (CEL, CRS, rate/ban, bots, positive) → verdict
      → verdicts correlated (otel triad) + ban decisions published back
        to the kernel ban map → evidence records
```

The **ladder** (TR-05) is the detection mainline: stages S0 (CEL seed),
S1 (rate/ban state), S2 (CRS via Coraza), S3 (CEL rules), S4 (positive
security), S5 (bot fingerprints). **Readiness flips**, not just verdicts:
readiness = bundle load state; unhealthy replicas leave the Service.
Verdict vocabulary lives in `internal/engine/ladder/ladder.go`
(`Verdict`/`Action`/`Phase`) — extend, never fork.

**Key files:** `internal/engine/ladder/engine.go` (stage wiring +
`Use(stage, evaluator)`), `internal/engine/ingest/tx.go` (the per-transaction
context + `Metadata` map), `internal/engine/cel/view.go` (the §11.3 request
view).

## The request view (§11.3) and CEL rules

The `internal/engine/cel/view.go` view is the **only** surface rules see:
method + path + headers + `request.query` (GEP-1897, TR-08b) + body fields.
Rules compiled at bundle load; load ≠ eval: an uncompilable rule fails the
LOAD, never mid-request.

CEL rule wire: `rules/cel/seed.yaml` carries the seed pack (TR02-001), the
byte-identity test `internal/operator/seedpack_test.go` guards it. New rules
extend the pack; a rule's `id` doubles as the rule-pack digest input.

## Kernel plane (bpf/, PRD §9)

- **Objects are committed** (`bpf2go` generated `*_bpfel.o`); regenerate via
  `go generate ./...` and commit both arch objects; tagged releases ship
  byte-identical objects ([§9.2](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#92-hook-inventory)).
- TR-03's `shield_xdp.c` contract is **frozen by test**: new kernel programs are
  **sibling .c files** (see `bpf/ban_xdp.c` from TR-10), never edits of a
  contract-frozen program.
- **Wire contracts are 200-byte aligned structs** with network-order be16 ports
  and BTF-verified Go mirrors; the wire layout test pins them.
- OrbStack substrates have two quirks encoded in the repo:
  [#80](https://github.com/trishula-dev/trishula/issues/80) (established-flow
  TC bypass: only the conn's first packet ingresses; payload inspection
  degrades to sampled flows; ban enforcement unaffected — it drops the SYN)
  and the visibility tier probe (`internal/shield/tier.go`) — loader refuses
  to run where the tier is insufficient.
- On `bpftool`: the VM's bpftool is
  version-mismatched with the OrbStack kernel; `lab/verify-xdp-chain.sh`
  documents the `BPFTOOL=` discovery fallback.

## Kernel evidence and the lab

The lab is where the [PRD](docs/PRD.md)'s claims are proven. **Every kernel
claim needs an in-VM run** (`trishula-build-dev`: `orb run -m trishula-build-dev
bash -cl '...'`), never a mac-only assertion.

| Gate | Script | Proves |
| --- | --- | --- |
| Env gate | `lab/verify-xdp-chain.sh` (sudo, Linux) | CO-RE compile, verifier load, XDP attach/detach |
| Steering | `lab/dx1/verify.sh` | NGF → engine → echo hop-by-hop |
| M9 timing | `lab/dx1/apply-effect.sh` | CRD apply → effect ≤5 s |
| Parity | `go test ./test/crs-differential/` | CRS reference verdict parity (CI-blocking) |
| Ban enforcement | `go test -tags ban_e2e ./test/banenforce/` | kernel shot + expiry + reconciler + evidence JSONL |
| Attack demo | `lab/demo-attack.sh` (sudo, Linux) | full attack replay: CRS + BOLA + kernel drop |
| Exit-gate demo | `lab/demo.sh` | one command: DX1 setup + M9 apply→effect + hop evidence |

**Rule: no invented transcripts.** Any README/PR/issue claim about kernel
behaviour cites a real run: its output verbatim, plus the issue/PR where it
was recorded. Every test claim must have a test; every run needs an evidence
record. A claim without a traceable run is not a claim.

## Testing

Read this whole section before writing a single test. The repo follows the
[hypothesis-first TDD standard](https://github.com/trishula-dev/trishula/issues/42):
**spec (from the PRD) → RED (watched, committed) → GREEN → PR → merge closes the
issue.** The watched-RED discipline is what makes every GREEN commit honest: a
failing test must exist, visibly, before the implementation lands.

### The prime directive

**A behavior has exactly one home.** Before writing a test, find the home; if
it already lives there, add a **row** to it. Do not create a second home.

### Layer map

| What you are testing | Home | Do NOT put it in |
| --- | --- | --- |
| Ladder/rateban/botdef behaviour over a request view | table test in the owning package (`ladder`, `rateban`, `botdef`) | engine-host integration tests |
| CRS rule semantics: rules + request → expected rule ids | `internal/crs` table test | a new package |
| Kernel wire contracts (map keys, event layouts, action codes) | the C contract test pinned at the object (e.g. `bpf/contract_test.go` pattern) | unit tests of the Go loader |
| Go API of a public type (compile/bundle/CRD) | test next to the type | a new package |
| Cluster/lab scenarios (NGF, apply→effect, hop evidence) | `lab/dx1/*.sh` scripts + their verify scripts | Go unit tests |
| CRS regression corpus | `test/crs-differential/corpus/` (the parity gate) | anywhere else |
| Engine↔kernel integration (ringbuf, ban publish) | tagged in-VM E2E (`-tags ban_e2e` / `ingest4d`) | unit tests |

### Decision procedure

1. **Rules + request → expected verdict?** Add a row in the owning package's
   existing table test.
2. **Pure function, several inputs?** Add a **row**. No new function.
3. **Neither?** Write a test function; one-line comment why it couldn't be a
   row; if no reason, it was a row.

### Instructions specific to coding agents

- **Default to zero new test functions.** Most changes are new rows.
- **Search before writing.** Grep for the behaviour and read the neighbours.
- **Watched RED is mandatory in the commit history**: a failing test's output
  appears in the RED commit's body; GREEN follows. Squash-without-RED is a
  review-blocking smell.
- **Bug fixes get one regression case** in the behaviour's home. Not one per
  code path you touched.
- **Never add tests "for completeness"** or to raise coverage — say so and let
  a human decide.
- **Run what CI runs**: `go vet ./... && go build ./... && go test ./... -count=1`
  (the same commands go-build.yml runs). Kernel-side changes additionally need
  the in-VM gate outputs.

## The bundle pipeline (§8.1) and the operator

```text
WAFPolicy CR (apply)
  → cmd/operator watch (client-go ListWatch, 250 ms resync)
  → internal/operator.Compile → Bundle (JSON wire v1, digested)
  → configmap publish + hot reload seam (cmd/engine --bundle path,
    receive mode w/ atomic rename)
  → engine consults the bundle BEFORE forwarding — block/allow real
```

Load-time discipline (from TR-08b, enforce in review): format gate → digest
re-verification per rule pack → compile-probe every CEL rule at load (load ≠
eval — an uncompilable rule fails LOAD, never mid-request). Fail-closed on
apply failure: no bundle published, engine keeps the previous bundle, error
logged — **never** a crash.

## Signing

**Everything is GPG-signed, always.** Commits AND tags
(`git config commit.gpgsign true`). PR CI enforces
`required_signatures`; an unsigned or badly-attributed commit blocks the PR.
The signing key and the commit email must agree with a GitHub-verified
identity or verification fails with `bad_email` and the PR cannot merge.
Release tags are signed tags; `git tag -v` is part of the release checklist.

## Architecture Decision Records

Structural changes (a new subsystem, a public API change, a
performance-characteristic change) carry an ADR in the same PR. Most
slices are leaf-sized — the issue's PRD reference IS the design record,
no ADR needed — write one only when **the change introduces a new
persistent artifact** (a wire format, a kernel map layout, a CRD field,
a gate script) or **removes/changes one**.

The record lives in [`docs/adr/`](docs/adr/):
[`0000-architecture-decision-records.md`](docs/adr/0000-architecture-decision-records.md)
explains the process and
[`0001-record-format.md`](docs/adr/0001-record-format.md) fixes the
format (NNNN-short-slug.md, numbered sequentially, one decision per
file). Rules with teeth:

- **Accepted ADRs are immutable.** A change that contradicts an accepted
  ADR supersedes it with a new one; never rewrite the accepted record.
- **Never invent discussion, deciders or quotes.** Cite commit/issue
  permalinks, or write "No substantive technical discussion recorded".
- Bug fixes, docs, CI and dependency bumps don't need ADRs.

## Pull requests

Follow [`CONTRIBUTING.md`](CONTRIBUTING.md) and treat the PR template checklist
as a contract, not decoration.

### Before opening

- Work happens on a leaf branch cut from **current `origin/main`** — never a
  stacked branch. (TR-05's lesson: the base must be main or the squash misses it.)
- **One logical change per PR.** No drive-by refactors, formatting or dependency bumps.
- TDD: watched RED committed before GREEN (see [Testing](#testing)).
- All commits GPG-signed with a GitHub-verified identity (see [Signing](#signing)).
- Full gates: `go vet ./... && go build ./... && go test ./... -count=1`
  locally, matching what `go-build.yml` runs.
- Kernel-side work: the in-VM evidence in the PR body.

### Title and description

- Title carries the task id: `TR-XXn — summary [child of TR-XX]` (the repo's
  own convention, older than the template's conventional-commit suggestion —
  both are accepted, keep the `TR-XX` id either way).
- Description: **what** changed, **why** (TR issue), **how verified** (watched
  RED output + GREEN output + lab/VM evidence). Reviewers should not have to
  read the diff to know something changed.
- Call out behaviour changes and follow-ups explicitly.

### Commits

- Small, self-contained, same title style; nothing about build artifacts or
  editor settings; no stray scratch files (`x*` test files, probe/ dirs are
  deleted before commit, not gitignored).

## Labels

| Label | Meaning |
| --- | --- |
| `TR-XXn — <summary>` (in the TITLE, not a label) | issue/PR identity |
| `area:ebpf|engine|gateway|crs|cel|botdefense|otlp|positive|rateban|crd|docs|academy|repo|org|testing|h2h3` | component |
| `type:task` | a leaf-sized roadmap slice (RED→GREEN→merge) |
| `type:feature|fix|docs|lab|research|test` | the slice's shape |
| `target:v0.1|v0.2|v0.3` | milestone |
| `complexity:starter|involved` | effort hint |
| `bug`, `documentation`, `ci` | maintenance |
| `upstream` | staged draft for an upstream issue (#97 pattern) |

Agents applying labels: mirror the area from the directory the change lands in,
never invent new `area:*`/`type:*` names (the label catalog is the vocabulary).

## Security

### Vulnerabilities

**Never open a public issue or PR describing an exploitable bug.** Report
through the GitHub security advisory link
(<https://github.com/trishula-dev/trishula/security/advisories/new>); see
[`SECURITY.md`](SECURITY.md). The embedded-CRS reporting rules apply
verbatim: a valid report carries a working reproducer; CVSS preconditions get
verified, not copied; AI involvement is disclosed in the advisory itself.

### Secure coding

- Treat every request byte, rule argument, kernel map value and CRD field as
  attacker-controlled input. Validate it.
- The kernel plane is fail-open by default (§9): a bug in the shield must never
  take down the traffic path — a change to the bpf programs must prove its
  failure modes (verifier-clean, map-update-failure = pass-through).
- Never log sensitive data (tokens, authz headers, request bodies).
- Constant-time comparisons for token/claims equality.
- The engine never panics on a malformed request (library-code rule).
- Kernel maps are bounded: a change that grows a map or an object needs the
  sizing note in the PR.

### Code style and conventions

- `gofmt`/`goimports` clean; standard Go idioms; package-level doc comments on
  every package (the repo's voice: package comment = the design claim + its
  PRD link + the slice boundary).
- camelCase unexported; PascalCase exported; descriptive collection names.
- Errors: `fmt.Errorf("context: %w", err)`; never panic in library code;
  never silently drop an error.
- Prefer the standard library; document why each dependency is needed. New
  deps for a slice get justified in the PR body (the OTel SDKs, client-go,
  Coraza and cilium/ebpf are the justified residents to date).
- No CGO anywhere; C is for the kernel plane only, compiled via bpf2go.
- No `unsafe` in Go code (kernel objects flow through generated BTF bindings).
- Tests in the same package as the code under test.

### Adding a feature

1. The issue exists first (the PRD cites it) — no feature without an issue.
2. Establish the slice: RED→GREEN pair; a lab gate if it changes the pipeline.
3. Update the PRD-facing docs (README status block, lab README) if the feature
   adds a runnable claim.
4. Keep backward compatibility for anything merged.
