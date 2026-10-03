# Trishula

**eBPF-native, developer-first Web Application and API Firewall for Kubernetes.**
kernel shield · userspace engine · control plane

[![version](https://img.shields.io/badge/version-v0.1.0-blue)](https://github.com/orgs/trishula-dev/projects/1) [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/trishula-dev/trishula)](https://github.com/trishula-dev/trishula/graphs/commit-activity) [![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/trishula-dev/trishula)](https://libraries.io/github/trishula-dev/trishula) [![GitHub Release](https://img.shields.io/github/v/release/trishula-dev/trishula?include_prereleases)](https://github.com/trishula-dev/trishula/releases) [![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/trishula-dev/trishula/blob/main/LICENSE) [![project site](https://img.shields.io/website?down_message=offline&up_message=live&url=https%3A%2F%2Ftrishula.dev&label=site)](https://trishula.dev)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/trishula-dev/trishula/main.svg)](https://results.pre-commit.ci/latest/github/trishula-dev/trishula/main)

[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/trishula-dev/trishula?label=OpenSSF%20Scorecard&style=flat)](https://scorecard.dev/viewer/?uri=github.com/trishula-dev/trishula) [![OpenSSF Best Practices](https://img.shields.io/badge/cii%20best%20practices-in%20progress-orange)](https://www.bestpractices.dev/projects/15183) [![go-build](https://github.com/trishula-dev/trishula/actions/workflows/go-build.yml/badge.svg)](https://github.com/trishula-dev/trishula/actions/workflows/go-build.yml) [![Dependency Review](https://github.com/trishula-dev/trishula/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/trishula-dev/trishula/actions/workflows/dependency-review.yml)

**What exists today:** a signed §19 layout skeleton and the [project site](https://trishula-dev.github.io/trishula-website/) ([source](https://github.com/trishula-dev/trishula-website)). **What does not exist yet:** the shield, engine and operator — implementation starts from the board below, nothing here should be presumed working.

## The one-sentence design thesis

> The WAF is the last control that never crossed to developer ubiquity — Trishula brings it across, by pairing a kernel-altitude eBPF shield (fail-open by default, bounded parsing, verifier-checked in CI) with the full userspace detection stack (OWASP CRS via embedded Coraza with a CI-blocking parity differential, CEL rules under cost budgets, OpenAPI positive security with promotion gates, JA4/behavioural bot detection, evidence-recorded ScoredWindowBan) and a Kubernetes-native control plane whose every verdict is a correlated OpenTelemetry record.

## Layout (PRD v4 §19)

```
api/v1alpha1/     CRD types (WAFPolicy, BanPolicy, …)
cmd/              shield, engine, operator, trishulactl
bpf/              shield_xdp.c, flow_tc.c (CO-RE, bpf2go)
internal/         engine (ingest, ladder, cel, rateban), operator, shield loader
manifests/        install manifests
docs/academy/     teach-the-web labs
lab/              demo + DX1 scenarios (kind + NGF)
test/             crs-differential · ban-conformance · bench
```

## Roadmap board

Work is tracked on the [Trishula — Roadmap board](https://github.com/orgs/trishula-dev/projects/1)
(org project) as issues `TR-01`…`TR-36` with `target:*` (sprint window), `area:*` (component) and
`s:*` (effort) labels. The sprint sequence: shield PoC → ingest → ladder → NGF steering lab →
CRS differential → operator/CRD round-trip → ScoredWindowBan → OTel pipeline → bot v0 →
positive security v0 → honest exit (TR-14).

## Status — Phase 0 exit criteria (checked honestly in TR-14)

| Criterion | Status |
|---|---|
| Shield attaches on a kind node; kernel-side ban drop works | ☐ |
| Engine ladder end-to-end verdict logging | ☐ |
| CRS PL1 differential parity reported (shadow) | ☐ |
| CRD apply → compile → load round-trip ≤ 5 s | ☐ |
| NGF steers to engine as plain backend in kind | ☐ |
| Verdict telemetry correlates span + metric + log | ☐ |

## License

MIT — see [LICENSE](LICENSE).
