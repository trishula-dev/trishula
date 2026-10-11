# Contributing

Contributions are welcome. This document defines the working agreement: how
changes are proposed, reviewed, and merged, and what the continuous-integration
gates enforce.

## Ground rules

1. **Never commit to `main`.** All work happens on a branch, one change per
   branch, merged via pull request. Branch names follow
   `<type>/<short-description>` with kebab-case — e.g. `fix/verifier-reject`,
   `feat/ban-reconciler`, `docs/academy-module-1`.
2. **Conventional Commits.** Every commit subject follows
   the [specification](https://www.conventionalcommits.org/en/v1.0.0):
   `type(scope): subject`.
   - Types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`,
     `perf`, `revert`.
   - `scope` is a component: `engine` (ladder, CEL, ingest), `ebpf` (kernel
     plane), `operator` (CRDs, bundles, reconcile), `crs` (embedded Coraza
     wrapper), `cel` (rules, seed pack), `botdefense`, `positive` (OpenAPI
     positive security), `rateban` (ScoredWindowBan), `gateway` (NGF/Envoy
     steering), `otlp` (verdict telemetry), `docs`, `ci`, `repo`, `deps`.
   - Subject: imperative, lowercase, no trailing period. Body (optional):
     what changed and why; wrap at 72 columns.
   - PR titles follow the same form: `type(scope): subject`; roadmap-slice
     PRs carry the id in the subject — `type(scope): TR-XX — subject`. Squash
     merges use the PR title as the commit subject
     (`squash_merge_commit_title: COMMIT_OR_PR_TITLE`), so the PR title is
     the commit record. A CI gate checks the form on every PR.
3. **Sign everything.** Commits must be GPG- or SSH-signed; branch protection
   requires signatures (`required_signatures`) — an unsigned commit, or one
   signed with an identity GitHub does not verify, blocks the PR. Verify with
   `git log --show-signature`; release tags are signed tags (`git tag -s`).
4. **One logical change per PR.** Small, reviewable diffs merge faster. The PR
   template checklist is a contract, not decoration — see
   [AGENTS.md](AGENTS.md#pull-requests) for the full PR contract.
5. **Pre-commit runs locally.** Install the hooks once per clone —
   `pre-commit install && pre-commit install --hook-type pre-push` —
   then every `git commit` and `git push` runs the same hook set CI runs
   (no-op in clones without a config; bypass with `--no-verify` for the
   rare legitimate exception). pre-commit.ci still gates every PR; local
   hooks just catch violations before the push instead of after.

## Security-sensitive changes

Anything touching the kernel plane, the inspection path, or the policy engine
warrants extra care (see [SECURITY.md](SECURITY.md) for the full posture):

- **Vulnerabilities are not issues.** Follow [SECURITY.md](SECURITY.md) — never
  open a public issue or PR describing an exploitable bug.
- **Kernel plane:** the eBPF programs are fail-open by design (a shield bug
  must never take down the traffic path). A change to `bpf/` must prove its
  failure modes: verifier-clean objects, map-update failure = pass-through.
  Kernel maps stay bounded — a change that grows a map or object carries the
  sizing note in the PR.
- **Detection ladder / policy engine:** treat every request byte, rule
  argument, kernel map value and CRD field as attacker-controlled input.
  The engine never panics on a malformed request and never logs sensitive
  data (tokens, authz headers, request bodies).
- **Secrets:** `detect-private-key` in `.pre-commit-config.yaml` blocks
  committed key material.

## CI gates

Every pull request runs:

| Check | What it does |
|---|---|
| `build` (go-build) | `go build ./...`, `go vet ./...`, `go test ./...` across the module |
| `dependency-review` | flags vulnerable or licence-incompatible dependency changes |
| `scorecard` | OpenSSF Scorecard |
| `pr-title-gate` | PR title matches the Conventional Commits form + `TR-XX` id |
| `pre-commit.ci` | the [.pre-commit-config.yaml](.pre-commit-config.yaml) hook set |

Required status checks on `main`: `build` and `dependency-review` (strict).
The local equivalent of what CI runs:
`go vet ./... && go build ./... && go test ./... -count=1`.

## Commits and pull requests

- Cut the branch from current `origin/main`, push, and open the PR against
  `main`; the description states what changed, why (the `TR-XX` issue), and
  how it was verified (watched RED output, GREEN output, lab/VM evidence).
- The PR title is `type(scope): TR-XX — subject` — on squash merge it becomes
  the commit subject on `main`.
- Merges happen on review; the merge is the maintainer's action.

## Reporting bugs

Open a [GitHub issue](https://github.com/trishula-dev/trishula/issues/new/choose)
using one of the templates:

- **Defect**: observed vs expected, plus the reproducing test (failing first).
- **Feature / build item**: the hypothesis (expected behaviour, assumed
  mechanism, falsifying observation), the test plan (RED first), and the
  acceptance criterion.

Include the Go version from `go.mod`, the deployment shape (kind / cluster /
host), and the relevant log or verdict-record excerpt. Security issues never
go here — [SECURITY.md](SECURITY.md) instead.

## Engineering standard: hypothesis-first TDD

Every feature, fix and refactor follows **hypothesis → failing test → minimal implementation → refactor** (see [#42](https://github.com/trishula-dev/trishula/issues/42) for the standing spec):

1. State the hypothesis in the issue: expected behaviour, assumed mechanism, falsifying observation.
2. **Commit the failing test first** on the feature branch; run it and paste the RED run's failure line into the PR.
3. Implement the minimum that passes; then the suite; then refactor with tests green.
4. Edge/error paths (overflow, malformed input, failure modes) are covered before close.

Where unit tests cannot reach — kernel-attached code, live-cluster behaviour — the issue's acceptance criterion **is** the test: record the EXPECTED-FAIL run before building, re-run green after. Same discipline, different harness.

Exceptions require the user's explicit go-ahead in the issue before work starts.
