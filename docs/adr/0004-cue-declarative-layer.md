# 0004 — Own the structured artefacts in CUE

Status: accepted

## Context

The structured files of the tree live as hand-maintained YAML. The census
record on TR-46 (issue #192) names eight surfaces: twelve lab manifests, the
committed CRD output, the operator seed pack, the CEL seed rules, the
ban-conformance fixtures, the CRS differential corpus, the engine test
vectors and the positive-security examples. Every hand copy can drift
against the Go types it mirrors; the structural tests validate little. The
operator-directed option set behind TR-46: declare the structure once,
derive the rest.

Two sources already own parts of that graph: controller-gen owns the CRD
bytes (the types in api/v1alpha1 plus the determinism test that pins the
committed CRD), and CEL stays the runtime predicate language (spec section
11.3).

## Decision

CUE (cuelang) is the declarative layer for the structured artefacts, as
TR-46 scopes it. The CUE module `github.com/trishula-dev/trishula`
(`cue.mod`) carries the definitions: `cue/seedpack`, `cue/banconformance`,
`cue/lab/dx1`, `cue/crd` and `cue/k8s`. `internal/cuegen` derives the
artefacts through the CUE Go API; `cmd/cuegen` is the regeneration
command. The CI gate (`cue-gate.yml`) runs `cue vet` plus a golden diff:
the derivation rewrites every derived artefact, and any diff fails the
job. A hand edit to a derived artefact fails CI; the CUE definition is the
accepted source.

Placement rule: generated deployment YAML lands outside the code tree —
`deployment/dx1/manifests/` holds the lab manifests. No hand-written
product YAML sits beside Go code: the two seed-pack copies inside the code
tree derive from `cue/seedpack` and carry the same golden gate.

Surfaces that stay hand-maintained this slice: the CRS differential
corpus (recorded attack traffic), the engine test vectors and the
positive-security examples (OpenAPI stays OpenAPI, per the issue's
friction list). The CRD stays controller-gen-owned: `cue/crd` adds the
validation layer over it, with no CUE ownership of the bytes. CEL stays
the runtime predicate language; CUE defines and validates structure only.

## Consequences

- One definition per structured artefact. A content change is a change in
  `cue/` plus one regeneration command (`go run ./cmd/cuegen`), never a
  hand edit of a derived file.
- The derived artefacts carry a provenance header and fail CI on hand
  edits; reviewers read `cue/` as the source.
- go.mod gains `cuelang.org/go` (build-time and test-time only; no
  product binary links it).
- Deferred (PENDING): JSON-Schema derivation with `cue export`; CUE
  structural checks over the stays rows (CRS corpus, engine vectors); the
  OpenAPI structural validation. The GitHub tenant files keep their tools.
- The bpf2go build is unaffected.
