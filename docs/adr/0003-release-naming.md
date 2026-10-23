# 0003 — Name releases on the calendar rc ladder

Status: accepted

## Context

The early roadmap named the planned cuts v0.1, v0.2 and v0.3. The
labels carried the same names. That v-series naming is retired. The
release train runs on calendar names: one GA name per month window,
`YYYY.MM`. The first train is `2026.01`.

The kailash-os repo set this scheme on 2026-10-11 (kailash-os#142).
The 2026-10-12 ruling exempted this repo. The labels kept the
v-series names. The operator D-set of 2026-10-23 reverses that
exemption (issue #125, TR-83). The register on #125 splits the
lanes. Issue #129 (TR-87) is this record's lane.

The rename landed on the vocabulary first. The labels and the board
Target options now carry the rc names. The cut ref `v0.1.0` still
carries the old name. The scheme re-points it (Decision item 6).

## Decision

The operator D-set of 2026-10-23 rules this ladder. This record is
the canonical statement of the scheme:

1. Release names follow the calendar train: `YYYY.MM`. The first
   train is `2026.01`; the year rolls at `2027.01`.
2. Every pre-GA cut carries a staged rc name with a per-train index:
   `2026.01-rc1`, then `2026.01-rc2`, then `2026.01-rc3`.
3. The bare `2026.01` name stays reserved for GA. A bare month-tag
   reads as the real release, never as a staged cut.
4. A material re-cut of a shipped artefact adds a third number:
   `2026.01.N` (the kailash-os#142 convention).
5. Labels and board vocabulary carry the same names. Tags map
   one-to-one with the targets: `target:v0.1` → `target:2026.01-rc1`,
   `target:v0.2` → `target:2026.01-rc2`, `target:v0.3` →
   `target:2026.01-rc3`.
6. The cut `v0.1.0` ref re-points to `2026.01-rc1` at the same
   commit: a signed re-tag, a release re-link, and a delete of the
   old ref. URL surfaces update in the same wave.

## Consequences

- One name vocabulary spans tags, labels and board rows. A reader
  maps any surface by name.
- Pre-GA names carry no semver order. The rc index carries the
  order. Release tooling parses the rc form and the re-cut number.
- A bare month-tag now names GA or nothing. Every pre-GA cut takes
  its rc index.
- The `v0.1.0` re-point is the operator's manual, signed step.

Records keep the old names verbatim (the D-set exemption list):

- Demo-transcript comments on #14 and #83.
- Dated timeline rows on the site.
- Merged squash-subject lines on `main`.
- The `design-docs-2026-10` tag and its release.

The PRD carries the pointer row:
[§16.5 Versioning, upgrades, rollback](../PRD.md#165-versioning-upgrades-rollback).
Nothing is deferred.
