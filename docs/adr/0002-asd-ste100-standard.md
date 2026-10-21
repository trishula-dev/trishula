# 0002 — Adopt ASD-STE100 for every written text

Status: accepted

## Context

The project's written surface grew past the PRD. The README, the
CONTRIBUTING guide, the PRD prose, the site pages, the issue bodies and the
PR bodies all speak to one reader: a developer or platform engineer who
adopts the tool. Voice drift showed the cost. Some prose carries idioms and
metaphors. Some prose speaks in the second person. Some sentences carry 2
thoughts across 30 words.

The operator set the writing standard on 2026-10-20: every written text in
the org follows ASD-STE100 Simplified Technical English. The pqscan project
holds the same decision as its ADR 0004. No substantive technical discussion
recorded; the record cites the operator directive of that date.

## Decision

Every written text in the two repos follows ASD-STE100:

1. The repo documents: `README.md`, `CONTRIBUTING.md` and the PRD prose. The
   contract tables and the requirement rows stay.
2. The site pages: index, roadmap, building, contributing, security and
   code-of-conduct.
3. The issue and PR bodies: forward-written in the standard. The historical
   bodies stay as filed.
4. The user-facing strings: the CLIs' help and output strings convert as code
   changes — watched-RED pairs per the TDD gate; goldens and want-strings
   re-pin in the same change.

The rule set: one thought per sentence and a 20-word cap; active voice and
present tense; one word per meaning; fixed technical names stay exact; digits
for numbers with units adjacent; imperative for instructions; no idioms; no
tracked references in the rendered text.

## Consequences

- The prose gets shorter. The boundary statements get plainer.
- The records keep their contract names; only the prose converts.
- New text starts in the standard. The conversion runs one issue per repo —
  TR-82 in this repo, TR-WS-4 in `trishula-website` — and lands as PRs the
  operator reviews and merges.
- Headings, tables, code blocks and captured transcripts stay byte-identical:
  `go test ./docs/` holds the PRD invariants, and `site-check` holds the
  render gate on the site.
