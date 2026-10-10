# positive

PRD §11.5 positive security — ladder stage **S4**: validate what a request
IS before spending rungs on what it DOES. An allowlist, not another
signature set: a request the schema cannot describe is rejected, so an
attacker's novelty is an error, not a challenge to parse.

## v0 scope (TR-13a)

- **One demo route** `POST /v1/chat/completions`, as an OpenAPI 3.1
  document subset in `testdata/openapi-chat.yaml` (`sigs.k8s.io/yaml`
  strict decode; every doc-level construct outside the subset is a load
  error, never silently ignored).
- **Request-body validation only**: type checks, required-field presence
  (top level and inside array items), enum membership, `maxLength`,
  `pattern` — on `body.model`, `body.messages[i]`, etc. Diagnostics name
  the exact violated field path (`body.messages[2].role: …`).
- **Policy**: route-pattern → schema mapping plus the default action for
  unmatched routes (v0 passes them through — fail-open default per PRD
  §0.1; enforcement flips per policy in v1).
- Verdicts are **shadow**: fragments in the ladder vocabulary
  (`ladder.ActionLog` on violations — decisive `block` arrives with
  enforcement), returned through the generic fragment surface (nil view →
  nil = no opinion), never the engine's typed S4 slot.

## What the operator CRD (APISpec, later) will carry

The v0 in-memory `Policy` is the shape the CRD wraps: an `APISpec` CR
will carry (a) the OpenAPI 3.1 document (or a reference to it), (b) the
host/route-prefix binding the doc applies to, (c) the default action and
per-route overrides, and (d) mode (`shadow` | `enforce`) — learn-mode
discovery (traffic → inferred spec diffs) is §11.5's second half, not
this slice.

## Named follow-ups (not in v0)

- Response-side schema (the §11.5 exfiltration guard) — roadmap Phase 2
  (§20.2).
- Headers, query and path-parameter validation — body-only today.
- `pattern`/`maxLength` coverage beyond strings (array `maxItems`,
  object `maxProperties`), `minLength`, `uniqueItems`.
- Typed S4 ladder wiring once the engine's typed view carries the body
  (until then TR-13a integrates via the fragment surface).
