---
adr: 0004
title: Record topology — decisions, topic records, and spec pointers
status: accepted
---

# 0004 — Record topology: decisions, topic records, and spec pointers

Status: accepted.

## Context

Two record homes grew in `docs/` by lane convention: the numbered ADR ladder
(`docs/adr/`) and topic engineering records (`docs/design/`). The spec carries
pointer lines into both. The shape of an individual record follows
[0001](0001-record-format.md), but no record states which home each kind of
writing takes. Lanes made the calls correctly — the rule just was never
written. This record writes it.

## Decision

1. **`docs/adr/` — the decision ledger.** Holds decisions that bind the repo or
   the working process: the writing standard ([0002](0002-asd-ste100-standard.md)),
   release naming ([0003](0003-release-naming.md)), the record format
   ([0001](0001-record-format.md)). Numbered from 0000, immutable once accepted,
   amended only by a superseding ADR. One canonical ladder per org — this tree.

2. **`docs/design/` — topic engineering records.** Hold facts, evidence, and
   topic-scoped verdicts: censuses, mechanism studies, component decisions
   (adopt / adapt / reject), evaluation plans, watch contracts. Mutable through
   the normal PR flow. Never numbered. Each carries a typed status line —
   design study, design record, verdict delivered, decided verdict record,
   research verdict, watch record. Every topic record carries the anti-claim:
   it owns no capability, and it states it.

3. **Capability statements bind in the spec.** A design record that settles a
   design does not thereby claim behaviour. Where the spec must carry the
   binding (a contract, a surface), the spec gains one pointer line naming the
   design record; the prose stays in the design record.

4. **The routing rule for a new record.** Ask, in order:
   - Does it bind how the repo works or its process? → `docs/adr/`, next slot.
   - Is it a spec contract? → the spec's own section, with a pointer line.
   - Otherwise it records facts or decides a topic design → `docs/design/`,
     with the typed status line.

## The estate at adoption (2026-10-24)

| Record | Type |
| --- | --- |
| docs/adr/0000-0003 | decision ledger (accepted) |
| docs/design/socket-plane/1-mechanism.md | mechanism study (fact + study decisions) |
| docs/design/socket-plane/2-failopen-ladder.md | fact record (the failure matrix) |
| docs/design/socket-plane/3-census.md | fact record (measured fractions) |
| docs/design/socket-plane/4-compiler-census.md | design record (facts + the template contract, mutable as work lands) |
| docs/design/socket-plane-fast-path.md | assembled note (transport constraints + the performance protocol) |
| docs/design/auth-jwt-verdict.md | research verdict (boundary decision; CEL names stay proposals) |
| docs/design/protocol-conformance-verdict.md | delivered verdict |
| docs/design/stage-stamps-verdict.md | decided verdict record |
| docs/design/composition-watch.md | watch record (deliberately not settled) |

## Consequences

- Lanes cite this record when choosing a home; no new record invents a home.
- New ADRs take the next slot in the ladder; nothing re-numbers.
- Design records keep their typed status lines; a status change (a watch
  settling into a verdict) is an edit through the normal PR flow.
- The spec keeps carrying pointer lines; spec sections stay the binding home
  for contracts.
