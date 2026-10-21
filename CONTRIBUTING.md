# Contributing

Contributions are welcome. This document defines the working agreement. It
states how changes are proposed, reviewed and merged. It states what the CI
gates enforce.

## Ground rules

1. **Never commit to `main`.** All work runs on a branch. One change uses one
   branch. The merge runs through a pull request. Branch names follow
   `<type>/<short-description>` in kebab-case, for example
   `fix/verifier-reject`, `feat/ban-reconciler`, `docs/academy-module-1`.
2. **Conventional Commits.** Every commit subject follows the
   [specification](https://www.conventionalcommits.org/en/v1.0.0):
   `type(scope): subject`.
   - Types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`,
     `perf`, `revert`.
   - `scope` is a component: `engine` (ladder, CEL, ingest), `ebpf` (kernel
     plane), `operator` (CRDs, bundles, reconcile), `crs` (embedded Coraza
     wrapper), `cel` (rules, seed pack), `botdefense`, `positive` (OpenAPI
     positive security), `rateban` (ScoredWindowBan), `gateway` (NGF/Envoy
     steering), `otlp` (verdict telemetry), `lab` (the runnable lab:
     `lab/dx1/` and the demo/verify scripts), `docs`, `ci`, `repo`, `deps`.
   - Subject: imperative and lowercase, with no trailing period. Body
     (optional): what changed and why. Body wraps at 72 columns.
   - PR titles follow the same form. Roadmap-slice PRs carry the id in the
     subject — `type(scope): TR-XX — subject`. Squash merges use the PR title
     as the commit subject (`squash_merge_commit_title: COMMIT_OR_PR_TITLE`).
     The PR title is the commit record. A CI gate checks the form on every PR.
3. **Sign everything.** Commits carry a GPG or SSH signature. Branch
   protection requires signatures (`required_signatures`). An unsigned commit
   blocks the PR. A commit signed under an identity GitHub does not verify
   also blocks the PR. Verify with `git log --show-signature`. Release tags
   run as signed tags (`git tag -s`).
4. **One logical change per PR.** Small, reviewable diffs merge faster. The
   PR template checklist is a contract. See
   [AGENTS.md](AGENTS.md#pull-requests) for the full PR contract.
5. **Pre-commit runs locally.** Install the hooks once per clone —
   `pre-commit install && pre-commit install --hook-type pre-push`.
   Every `git commit` and `git push` then runs the hook set CI runs. The
   hooks no-op in clones without a config. Bypass with `--no-verify` only for
   a rare legitimate exception. pre-commit.ci still gates every PR.

## Security-sensitive changes

Changes touching the kernel plane, the inspection path or the policy engine
carry extra care. See [SECURITY.md](SECURITY.md) for the full posture:

- **Vulnerabilities are not issues.** Follow [SECURITY.md](SECURITY.md).
  Never open a public issue or PR that describes an exploitable bug.
- **Kernel plane:** the eBPF programs are fail-open by design. A shield bug
  must never take down the traffic path. A change to `bpf/` proves its
  failure modes: verifier-clean objects, and a map-update failure leaves
  pass-through. Kernel maps stay bounded. A change that grows a map or object
  carries the sizing note in the PR.
- **Detection ladder / policy engine:** treat every request byte, rule
  argument, kernel map value and CRD field as attacker-controlled input. The
  engine never panics on a malformed request. It never logs sensitive data
  (tokens, authz headers, request bodies).
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
The local equivalent of the CI run:
`go vet ./... && go build ./... && go test ./... -count=1`.

## Commits and pull requests

- Cut the branch from current `origin/main`. Push and open the PR against
  `main`. The description states what changed, why (the `TR-XX` issue) and
  how it was verified. The verification carries the watched RED output, the
  GREEN output and the lab or VM evidence.
- The PR title is `type(scope): TR-XX — subject`. On squash merge it becomes
  the commit subject on `main`.
- Merges happen on review. The merge is the maintainer's action.

## Reporting bugs

Open a [GitHub issue](https://github.com/trishula-dev/trishula/issues/new/choose)
using one of the templates:

- **Defect**: observed vs expected, plus the reproducing test (failing first).
- **Feature / build item**: the hypothesis (expected behaviour, assumed
  mechanism, falsifying observation), the test plan (RED first) and the
  acceptance criterion.

Include the Go version from `go.mod`. Include the deployment shape (kind,
cluster or host). Include the relevant log or verdict-record excerpt.
Security issues never go here. [SECURITY.md](SECURITY.md) is the channel
instead.

## Engineering standard: hypothesis-first TDD

Every feature, fix and refactor runs the flow: hypothesis → failing test →
minimal implementation → refactor. See
[#42](https://github.com/trishula-dev/trishula/issues/42) for the standing
spec:

1. State the hypothesis in the issue: expected behaviour, assumed mechanism,
   falsifying observation.
2. **Commit the failing test first** on the feature branch. Run it and paste
   the RED run's failure line into the PR.
3. Implement the minimum that passes. Run the suite. Refactor with the tests
   green.
4. The repo covers edge and error paths (overflow, malformed input, failure
   modes) before close.

Unit tests cannot reach kernel-attached code and live-cluster behaviour. The
issue's acceptance criterion **is** the test there. Record the EXPECTED-FAIL
run before the build. Re-run green after. The discipline stays the same. The
harness differs.

Exceptions require the user's explicit approval in the issue before work
starts.
