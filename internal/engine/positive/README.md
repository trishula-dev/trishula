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

## Learn mode and drift telemetry (TR-18)

§11.5's second half runs over the same v0 subset rules on the same
package:

- **Discovery** (`Discoverer`): the caller feeds `Sample` values (method +
  path + encoded body — the body-carrying view shape; deps injected, no
  socket and no clock). Endpoint extraction groups by exact path;
  non-`post` methods land on the `Skipped` record with counts, never
  silently dropped. Undecodable bodies count on their route and never
  abort the window.
- **Schema inference with cardinality tracking**: per schema position,
  the census reads presence (required = full presence in the window),
  the distinct-value census (enum under the 8-value cap; a wider census
  stays a plain string) and the length census (`maxLength`). Shapes the
  v0 subset cannot describe (booleans, nulls, mixed kinds, array element
  shapes never observed) carry `Unrepresentable` records instead of a
  half-expressed schema; patterns are never inferred.
- **Materialize**: one learned route renders into exactly one
  single-route OpenAPI 3.1 document — the strict v0 loader accepts it
  back (the closure seam tying learn output to the enforcement loader).
- **Drift** (`Drift`): the live-vs-reviewed read against the loaded
  policy. The rows (`Diff`) carry the endpoint, the schema position and
  the measured evidence; the per-kind counts are the record source for
  the schema-drift counters (the otel wiring stays the otel slice).

## What the operator CRD (APISpec, later) will carry

The v0 in-memory `Policy` is the shape the CRD wraps: an `APISpec` CR
will carry (a) the OpenAPI 3.1 document (or a reference to it), (b) the
host/route-prefix binding the doc applies to, (c) the default action and
per-route overrides, and (d) mode (`shadow` | `enforce`). The learn
suite above emits its `LearnedSpec` and `DriftReport` values in memory;
applying those diffs into the CR is a named follow-up until the CRD
exists.

## Named follow-ups (not in this package yet)

- APISpec CRD types + application of `Drift` rows into the CR
  (the CR's learn/enforce/report mode rides the same slice).
- Route-prefix binding and parametrized path inference (discovery today
  keys on the exact path, matching the `Policy` match rule).
- Methods beyond `post` (the `Skipped` record names them; their schemas
  stay uninferred).
- Response-side schema (the §11.5 exfiltration guard) — roadmap Phase 2
  (§20.2).
- Headers, query and path-parameter validation — body-only today.
- `pattern`/`maxLength` coverage beyond strings (array `maxItems`,
  object `maxProperties`), `minLength`, `uniqueItems`.
- Typed S4 ladder wiring once the engine's typed view carries the body
  (until then TR-13a integrates via the fragment surface).
- The §11.7 promotion lifecycle (learn → shadow → enforce gates: sample
  volume, convergence, shadow false-positive budget).
