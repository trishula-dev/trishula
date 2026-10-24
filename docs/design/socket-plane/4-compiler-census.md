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

## 10. The shadow differential record (TR-40d)

**Trishula record TR-40d** — the shadow differential leaf of the TR-40 compiler spike
([TR-40 #52](https://github.com/trishula-dev/trishula/issues/52); the leaf record is
[#190](https://github.com/trishula-dev/trishula/issues/190)). This section extends section 9:
it adds the shadow harness, the match criterion, the mismatch budget and the kernel-gate
posture, and section 11 adds the slow-path limitation list.

Spec refs: [§9.9] · [§17.1 budget](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#17-performance-targets--benchmark-plan)

Status: the record ships a kernel-free shadow harness with a kernel-gated leg. No enforcement
claim and no wall ride the record. The [§9.9] contract holds across the section: tracked
evaluation, not a v1 commitment.

### 10.1 The streams

Rule: the harness runs both decision streams per corpus case.

| Stream | Surface | Home |
| --- | --- | --- |
| Fast-path decision stream | the route template semantics per frame: header checks, the bounded request-line scan, the LPM row match, the action | the committed `route_mark` object on the kernel leg; its userspace projection (`test/fastpath-differential` model) on every host |
| Engine verdict stream | the loaded bundle evaluation: the seed CEL rule over the request view, else the policy default action | `internal/operator` Compile → Load → Eval, with the staged template rows as the compiled row truth |

The decision streams parse one input, never two: the synthetic frame bytes feed the kernel
program and the projection. The engine stream reads the case view. The fast path never
enforces on this record; the shadow reads decisions only.

### 10.2 The match criterion

Rule: one corpus case reads matched when every row below holds for it.

1. Both streams resolve the case.
2. Every fast-path drop carries compiled drop-row backing: the mark names a staged drop row
   (row truth over the staged rows).
3. Every miss reads forward, with no mark (fail-open).
4. On the kernel leg, the program's return value names the same outcome as the projection
   (fidelity).

The plane-split differences are reported, never scored. A compiled drop beside a non-decisive
engine verdict, and a forward beside a decisive one, sit on the class split (section 6): the
engine stays the detection authority, and a forward re-enters the engine budget (part 2,
degradation rules).

### 10.3 The corpus

The corpus carries 19 name-ordered cases over 6 shape classes. The shapes pin the
request-line scan bounds: the snapshot clamp at 96 bytes, the masked size word (a 256-byte
line wraps to a parse miss), the 64-byte copy cap, the NUL-shortened key, the non-IPv4
ethertype, the TCP data offset under 5, and the space-free line. The coverage gate counts
the materialized classes; it never pins a remembered minimum.

| Shape class | Cases |
| --- | --- |
| drop-row | 5 |
| forward-row | 6 |
| miss | 8 |
| malformed-frame | 4 |
| size-quirk | 2 |
| nul-shape | 2 |

### 10.4 The recorded census

The census below is the stable run (3 runs on each leg, both legs green).

The kernel-free gate, `go test ./test/fastpath-differential/ -count=1 -v`:

```text
=== RUN   TestFastPathDifferential
    diffgate_test.go:32: fastpath-differential census: cases 19, ran 19, skipped 0
    diffgate_test.go:34: fastpath-differential census: parity 19/19, pinned deltas 0
    diffgate_test.go:40: fastpath-differential census: shapes drop-row 5 forward-row 6 miss 8 malformed-frame 4 size-quirk 2 nul-shape 2
    diffgate_test.go:41: fastpath-differential census: plane-split 5 (drop-vs-nondecisive 4, forward-vs-decisive 1)
    diffgate_test.go:48: fastpath-differential budget row unexplained: live 0, holds
    diffgate_test.go:48: fastpath-differential budget row failopen-drop: live 0, holds
    diffgate_test.go:48: fastpath-differential budget row unresolved-engine: live 0, holds
    diffgate_test.go:48: fastpath-differential budget row kernel-fidelity: live 0, holds
    diffgate_test.go:48: fastpath-differential budget row plane-split: live 5, holds
--- PASS: TestFastPathDifferential (0.01s)
=== RUN   TestCorpusCoversRouteDecisions
    diffgate_test.go:82: fastpath-differential corpus: class drop-row carries 5 case(s)
    diffgate_test.go:82: fastpath-differential corpus: class forward-row carries 6 case(s)
    diffgate_test.go:82: fastpath-differential corpus: class miss carries 8 case(s)
    diffgate_test.go:82: fastpath-differential corpus: class malformed-frame carries 4 case(s)
    diffgate_test.go:82: fastpath-differential corpus: class size-quirk carries 2 case(s)
    diffgate_test.go:82: fastpath-differential corpus: class nul-shape carries 2 case(s)
--- PASS: TestCorpusCoversRouteDecisions (0.00s)
```

The kernel leg, `go test -tags fastpath_diff_e2e -v ./test/fastpath-differential/` under
root (host: the dev VM, ubuntu 24.04 arm64, kernel 7.0.14-orbstack-00380-ga7e0a2dc9535):

```text
=== RUN   TestKernelDecisionStream
    e2e_diff_linux_test.go:117: fastpath-differential kernel census: frames 19, fidelity 19/19, deltas 0
    e2e_diff_linux_test.go:125: fastpath-differential budget row kernel-fidelity: live 0, holds
--- PASS: TestKernelDecisionStream (2.05s)
```

The kernel leg drives the committed object through the test-run harness. All 19 frames read
one outcome per stream: the userspace projection matches the kernel object, including the
size-word wrap, the NUL-shortened key and the 64-byte copy cap.

### 10.5 The mismatch budget

The budget table carries the shadow mismatch classes. Zero-tolerance classes are recorded by
design; the plane-split class is recorded from the census of section 10.4.

| Class | Boundary | Recorded | Budget | Reads |
| --- | --- | --- | --- | --- |
| unexplained | a fast-path/engine pair outside every named class | 0 | 0 | gate |
| failopen-drop | a drop without compiled drop-row backing | 0 | 0 | gate |
| unresolved-engine | the engine stream fails to resolve a corpus case | 0 | 0 | gate |
| kernel-fidelity | the kernel return value disagrees with the projection | 0 | 0 | gate |
| plane-split | a compiled drop beside a non-decisive verdict, or a forward beside a decisive one | 5 | 5 | reported |

Rules with teeth:

1. The live census over a recorded ceiling reads as a regression and fails the gate.
2. A ceiling never re-pins to pass a comparison; a maintainer re-pins with a fresh recorded
   run.
3. A new mismatch class reads unexplained until a budget row records it.

### 10.6 The kernel gate and the test-run boundary

The kernel leg runs as the tagged e2e: the linux build tag plus the `fastpath_diff_e2e` job
tag plus the root/euid skip gate (BTF present). `FASTPATH_DIFF_E2E_REQUIRED=1` turns every
environment skip into a failure, so a gate job that cannot run the leg never reads green.
Host CI stays kernel-free: the go-build step never sets the tag, and darwin never compiles
the file.

Two boundary rows, recorded honestly:

1. The program runs under the test-run harness only. No attach and no netns ride this leg;
   the plan attaches nothing.
2. The test-run surface returns the TC action only. The skb mark the template writes does
   not read back there. The kernel leg therefore scores the decision outcome; the row-id and
   mark legs stay userspace pins. A kernel mark read rides a later attach surface, not this
   record.

### 10.7 The §4.5 wall rows

Rule: this record records no wall. The section 9.5 rows stay PENDING; the comparison protocol
([§4.5](../socket-plane-fast-path.md#45-the-comparison-protocol-for-the-tr-40-pr)) owns both
walls, and this harness records a verdict census, never a timing. Walls enter the record as
real runs only.

### 10.8 The decision record

| Component | Decision | Record |
| --- | --- | --- |
| Shadow harness over both decision streams | adopt | 10.1–10.4 |
| Match criterion (four rows) | adopt | 10.2 |
| Mismatch budget with the recorded plane-split ceiling | adopt | 10.5 |
| Kernel leg through test runs, no attach | adopt | 10.6 |
| Mark unscoring on the test-run surface | adopt (boundary) | 10.6 |
| Walls for the §4.5 cells | deferred | 10.7 |

## 11. The slow-path limitation list (TR-40d)

Rule: the list names the policy classes the fast path never enforces. Each class routes to
the engine slow path (part 2, the ladder tiers). The list carries no kernel claim, at this
record and at any later one.

| Class | Boundary | Disposition |
| --- | --- | --- |
| Request and response bodies | body inspection never crosses the kernel plane; CRS/Coraza body evaluation is engine work ([§9.9]) | engine slow path, always |
| Compression | gzip, brotli and deflate body (de)compression carry no kernel decode helper | engine slow path |
| Non-event-driven policies | health checks and timer-driven behaviors carry no per-message event to parse | engine slow path (the recorded constraints of [§9.9]) |
| Custom runtimes | WASM and Lua policy extensions carry no interpreter in the data plane | engine slow path |
| Gate-locked classes | the hash/encode gate keeps JWT HS256 off the kernel path (section 2) | slow path; the gate re-reads on the recorded upstream trigger |

The anti-claim rows hold on top of the table:

1. The fast path claims no WAF detection. CRS rule evaluation, the CEL plane and every
   body-carried class stay engine work.
2. A slow-path class never routes back into a kernel claim. The compile-split surface
   (section 6) reports the per-field dispositions, and a bundle never reads "enforced" when
   part of it fell back.
3. The list grows when a new slow-path class lands on the census. A limitation row is a
   boundary statement, never an open capability gap.

[§9.9]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment

[§17]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#17-performance-targets--benchmark-plan
