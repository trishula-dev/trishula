# Trishula — Architecture Decision Records

This directory holds the project's Architecture Decision Records (ADRs):
short, numbered documents recording a *structural* decision — what was
decided, why, and what it supersedes.

## Index

| Number | Title | Status |
| --- | --- | --- |
| [0000](0000-architecture-decision-records.md) | Architecture decision records (this process) | accepted |
| [0001](0001-record-format.md) | ADR record format | accepted |
| [0002](0002-asd-ste100-standard.md) | Adopt ASD-STE100 for every written text | accepted |
| [0003](0003-release-naming.md) | Name releases on the calendar rc ladder | accepted |
| [0004](0004-cue-declarative-layer.md) | Own the structured artefacts in CUE | accepted |

## When an ADR is required

Most changes are leaf-sized slices whose design record is the roadmap
issue's spec reference (`TR-XXn`); they do **not** need an ADR. Write one
only when the change **introduces a new persistent artifact** or **removes
or changes one** — a wire format, a kernel map layout, a CRD field, a gate
script, or the removal/change of any of these. Bug fixes, dependency
bumps, documentation and CI tweaks never need an ADR.

Rules (full text in
[`0000`](0000-architecture-decision-records.md)): accepted ADRs are
immutable and get superseded, never rewritten; never invent discussion,
deciders or quotes — cite permalinks or say "No substantive technical
discussion recorded"; every ADR lands in the same PR as the change it
records.
