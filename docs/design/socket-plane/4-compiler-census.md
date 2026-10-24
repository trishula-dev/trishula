# Socket-plane fast path — compiler subset census and template contract (TR-40a)

> **Trishula design note TR-40a** — first leaf of the TR-40 compiler spike
> ([TR-40 #52](https://github.com/trishula-dev/trishula/issues/52); the leaf record is
> [#187](https://github.com/trishula-dev/trishula/issues/187)). The socket-plane note carries
> the mechanism record ([part 1](1-mechanism.md)), the fail-open ladder ([part 2](2-failopen-ladder.md))
> and the CRS/CEL census ([part 3](3-census.md)). The assembly note adds the transport constraints
> and the performance protocol ([socket-plane-fast-path.md](../socket-plane-fast-path.md)). This
> record extends the part-3 census: it reads the `WAFPolicy` CRD surface instead of the rule
> corpora, and it adds the compiler contract.
>
> **Spec refs:** [§9.9 socket-plane fast path](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment) ·
> [§8.1 design principles (P2: one policy artifact, many enforcement altitudes)](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#81-design-principles) ·
> [§17 performance targets & benchmark plan](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#17-performance-targets--benchmark-plan)

Status: design record. The record ships a kernel-free skeleton package and makes no capability
claim. The [§9.9] contract holds across the record: tracked evaluation, not a v1 commitment.
No template, no load and no enforcement exist at this record. Section 9 carries the TR-40b
route-class update: the first kernel-path rows, the template and the load gate.

[§9.9]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment

## 1. Question and method

The compiler spike needs one answer before any template exists. The answer names, per field, the
compile target: the kernel fast path or the engine slow path. One row per CRD field names the
compile class and the split verdict.

Method:

1. The field set comes from `api/v1alpha1` (the TR-08a v0 surface) at the tracked state of this
   repo.
2. The classes come from the class set of section 2. The subset classes carry the kernel-offloadable
   policy set of [§9.9]. The set names 5 classes: JWT HS256 authz, RBAC allowlists, route marking,
   telemetry counters, header mutation. Every other class routes to the slow path with no claim of
   enforcement.
3. The record is executable. The classifier package `internal/fastpath` carries the same rows,
   and its suite walks the CRD spec tree. A surface field without a census row fails the suite.
   A census row without a surface field fails the suite.

Boundary: the census covers the spec-tree leaves plus the two metadata fields the compile stamps
(`metadata.name`, `metadata.namespace`). `ObjectMeta` carries further control fields. The compile
reads none of them, and the census records none of them. The `status` row is this record's own
subject (section 6).

## 2. The class set

The classifier carries 6 classes. Five carry the kernel-offloadable subset; one collects everything
else. The gate column carries the hash/encode kernel-coverage gate. Part 1 owns the gate: the
kernel-module assessment rejects a kernel module at the tracked evaluation, so a gated class
skips the kernel path.

| Class | Subset | Gate state | Split verdict |
| --- | --- | --- | --- |
| `jwt_authz` | yes | locked | gate-locked |
| `rbac_allowlist` | yes | open | kernel |
| `route` (route marking) | yes | open | kernel |
| `telemetry` (counters) | yes | open | kernel |
| `header_mutation` | yes | open | kernel |
| `slow_path` | no | — | slow-path |

The gate owns eligibility. JWT HS256 sits inside the subset. The eBPF runtime lacks hash and
encode helpers on the tracked kernels (part 1, kernel-module assessment). The class stays
gate-locked, so JWT HS256 routes to the slow path today. The gate re-reads on the recorded
upstream trigger, not on demand.

## 3. The v0 census — one row per WAFPolicy field

The rows follow the CRD's JSON tree. The class column names the compile class. The verdict column
carries the split value that the status surface of section 6 records per field.

| Field | Class | Verdict | Census basis |
| --- | --- | --- | --- |
| `spec.ruleSets[].name` | `slow_path` | slow-path | the CRS plane stays at the engine; part 3 rejects kernel CRS evaluation |
| `spec.ruleSets[].source.crsVersion` | `slow_path` | slow-path | the CRS train pin resolves engine-side |
| `spec.ruleSets[].source.profile` | `slow_path` | slow-path | the paranoia profile is an engine input |
| `spec.defaultAction` | `slow_path` | slow-path | engine verdict vocabulary; the fast path forwards on miss (part 2, ladder) |
| `spec.celBudget` | `slow_path` | slow-path | the CEL cost budget rides the engine compile |
| `spec.modeFlags.inline` | `slow_path` | slow-path | engine deep-inspection plane selection |
| `spec.modeFlags.shield` | `slow_path` | slow-path | fast-path candidacy switch; alone it compiles no data-plane artifact |
| `spec.modeFlags.shadow` | `slow_path` | slow-path | verdict-only mode; no enforcement claim |
| `metadata.name` | `slow_path` | slow-path | object identity; control-plane input |
| `metadata.namespace` | `slow_path` | slow-path | tenant binding (TR-25); no enforcement artifact |
| `status` | reserved | reserved | the compile-split honesty surface (section 6) |

**Census statement.** The census carries 10 classified rows and one reserved row. No field of the
v0 surface carries a subset class. The kernel path of the compiler compiles no field at this
surface. The classifier returns the slow-path verdict on every classified field. Marked:
classification record of `api/v1alpha1` at the tracked state of this repo. The suite
(`internal/fastpath`) is the CI guard of the row set.

## 4. The subset classes and the surface growth

The subset classes have no source field at the v0 surface. The table names the gap per class.
The gaps name scope, not a schedule: no row here is a commitment.

| Class | Missing surface input | Record |
| --- | --- | --- |
| `jwt_authz` | issuer/audience claim fields, with the hash gate open | the part-1 kernel-module assessment controls |
| `rbac_allowlist` | source IP, port and path allowlist fields | route-selector fields land with a later TR-08 slice |
| `route` | route-marking fields | route-selector fields land with a later TR-08 slice |
| `telemetry` | counter declarations | counters read the shared map state ([§9.3 maps](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state)) |
| `header_mutation` | add/set/remove header directives | the write primitive bounds the class |

Each class takes its census row when its field lands on the surface; the coverage test extends
then. The compile of a class ahead of its surface stays out of scope.

## 5. The template contract

The contract bounds the synthesized data plane. No template exists at this record; the later
TR-40 leaves instantiate against these bounds.

1. **Shape.** One template carries the control flow and the placeholders. Synthesis fills the
   placeholders from the compiled bundle: match parameters, action parameters, the default
   forward. The library carries the part-1 action primitives: `compare`, `read`/`write`,
   `get`/`set`, `forward`, `drop`.
2. **Size.** Each template stays under 70 lines of C (the source-study bound).
3. **Envelope.** One assembled program targets one loadable unit. The tracked evaluation uses no
   tail calls. Loops carry compile-time bounds or stay out. The instruction budget per program is
   a compile-time constant.
4. **Gated primitives.** Synthesis never inlines a gated primitive. The encode, decode and hash
   classes route to the slow path while their gate stays locked.
5. **Build.** The compiler builds CO-RE objects through bpf2go beside the existing shield build
   (`bpf/`). A new compiler program lands as a sibling `.c` file; the `shield_xdp.c` contract
   stays frozen by test. Generated objects land committed, per architecture, as the shield
   objects do today.
6. **Load proof.** Every synthesized program loads through the verifier in CI, per bundle, before
   merge. A program that fails to load fails the apply — never a request mid-flight.
7. **Honesty.** Instantiation claims nothing beyond the census verdicts of section 3. A subset
   class compiles only at an open gate; a gate-locked or slow-path field never reaches the data
   plane.

No performance claim rides on this contract. The assembly note's performance protocol owns the
walls; the [§17] budgets stay targets until a recorded run.

## 6. The compile-split honesty surface (design)

Rule: the compile reports one verdict per field. The values match this record's vocabulary:
`kernel`, `slow-path`, `gate-locked`. The surface never reports "enforced" for a policy or for a
bundle. A bundle whose half fell back reports the fall.

Two surfaces carry the split. The design adopts both; the implementation lands with the
end-to-end leaf of TR-40. The v0 CRD carries the status subresource only — no Status struct
exists at this state, so the status addition rides that leaf too.

1. **The summary condition.** `WAFPolicy.status.conditions` carries one condition of type
   `FastPathCompiled` in the Gateway API condition vocabulary (the CRD decisions adopt that
   vocabulary). The reasons: `NoKernelFields`, `GateLocked`, `EnvelopeExceeded`,
   `VerifierRejected`, `Compiled`. The condition is a summary; it never substitutes for the
   split.
2. **The per-field split.** The policy `metadata.annotations` carries the annotation
   `trishula.security/compile-split`. The value is a JSON map with one field-to-verdict pair per
   classified field. The compile-to-load round-trip emits it after classification and after the
   verifier proof. Users read the split with `kubectl`; the compile gate reports from it.

| Split surface | Verdict | Why |
| --- | --- | --- |
| summary condition `FastPathCompiled` | adopt | one-glance state in the Gateway API vocabulary |
| per-field annotation `trishula.security/compile-split` | adopt | the split itself; no CRD schema change at v0 |
| a status field carrying the split map | reject at v0 | the status schema waits for its own slice |
| wholesale "enforced" claims | reject | the split exists to block exactly this |

The split surface claims no enforcement. It records per-field dispositions.

## 7. Decision record

| Component | Decision | Record |
| --- | --- | --- |
| Field census over the v0 surface | adopt | section 3, guarded by the classifier suite |
| Class set (6 classes) | adopt | section 2 |
| Fail-closed classifier | adopt | an unknown field errors; no silent slow-path default |
| JWT gate-locked verdict | adopt | the part-1 kernel-module assessment controls |
| Template contract bounds | adopt | section 5; instantiation lands later |
| Summary-condition design | adopt (design) | section 6 |
| Per-field annotation design | adopt (design) | section 6 |
| Status-map field at v0 | reject | section 6 |
| Kernel-module adoption | reject (inherited) | the part-1 trigger is recorded, not claimed |

## 8. Closure record

- The record closes TR-40a: the supported-subset census, the template contract, the compile-split
  design and the kernel-free skeleton package.
- The parent TR-40 record ([#52](https://github.com/trishula-dev/trishula/issues/52)) stays open
  as the acceptance gate. The verifier CI gate, the differential gate and the split implementation
  land with the later leaves.
- No performance claim rides on this record. The assembly note's performance protocol owns the
  walls, and the budgets stay targets until a recorded run.

## 9. The route-class template record (TR-40b)

**Trishula record TR-40b** — the end-to-end leaf of TR-40
([#52](https://github.com/trishula-dev/trishula/issues/52); the leaf record is
[#188](https://github.com/trishula-dev/trishula/issues/188)). This section extends section 3
with the first kernel-path rows and records the template instantiation.

Spec refs: [§9.9] · [§8.2 component map](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#82-component-map) · [§17]

Status: the compile→load round-trip runs in CI, and the compile-split reads back per bundle.
No bench wall rides this section, and no enforcement claim rides the split. The [§9.9]
contract holds across the section: tracked evaluation, not a v1 commitment.

### 9.1 The surface growth

`spec.routes[]` lands on the surface with two rows: the prefix
(`spec.routes[].prefix`) and the action (`spec.routes[].action`). Both carry class `route`
with an open gate, so both carry the kernel verdict. The census now carries 12 classified
rows and the reserved `status` row. The coverage walk still runs over the spec tree only:
`status.conditions` is the split surface itself, not a classified field.

### 9.2 The template

`bpf/route_mark.c` carries the route template v1. It holds one TC program, one LPM route
map (8 rows max) and one rodata placeholder (the miss forward). Bounds: 64 bytes per
prefix, 96 snapshot bytes per read, compile-time loop bounds, no tail calls. The
machine-checked LoC measure is 68: the counter strips comment and blank lines. The compile
stages a bundle's route classes onto the kernel path. `internal/fastpath/routetemplate`
re-checks every bound and names any offending cell. It then loads the committed object
through the verifier. The v1 object carries no pinning and the loader attaches nothing.

The verifier shaped the size word. The load proof failed twice before it loaded: first on
an unbounded size register, then on a zero-sized read. The landed form masks the word and
re-clamps it to the 1-to-96 range before the helper call. Both rejections stayed
fail-closed: the apply failed, and no request saw the program.

### 9.3 The compile-split write

The write rides the existing compile path. The bundle carries the split map. The reconcile
stamps the annotation (`trishula.security/compile-split`) onto the policy object it holds.
The summary condition (`FastPathCompiled`) lands in two stages. The compile stamps only
`NoKernelFields` — classification alone proves it. The round-trip stamps `Compiled` after
a verifier-accepted load, and `VerifierRejected` after a failed load. The write adds no
CRD version and no new write plumbing. A failed compile carries no stamp.

### 9.4 The load gate

The gate is CI-asserted, in the residue-gate posture. `route-gate.yml` (pull_request,
nightly, workflow_dispatch) runs the tagged e2e (`route_e2e`, `ROUTE_E2E_REQUIRED=1`)
under root. A skip never reads green, and an oversized or malformed route list fails the
compile with the offending cell named.

### 9.5 The bench rows — the §4.5 protocol obligation

The assembly note's [§4.5](../socket-plane-fast-path.md#45-the-comparison-protocol-for-the-tr-40-pr)
comparison protocol owns every wall. This record claims no wall. The rows below read
PENDING until a recorded run supplies both walls from one harness and node class. The
capability claim stays out: tracked evaluation, not a v1 commitment.

| Cell | Budget | Recorded wall | Verdict |
| --- | --- | --- | --- |
| Route-mark TC program, per message | the §17.1 TC cell | PENDING | PENDING |
| T2/T3 forward share with the route class | §4.5 rule 4 | PENDING | PENDING |

No measured figure exists for either cell. The one measured number this section carries is
the template's LoC bound above.

[§17]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#17-performance-targets--benchmark-plan
