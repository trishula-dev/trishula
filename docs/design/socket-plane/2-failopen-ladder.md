# Socket-plane fast path — fail-open ladder (TR-39b)

> **Trishula design note TR-39b** — part 2 of 3 of the socket-plane note. Parent record:
> [TR-39 #51](https://github.com/trishula-dev/trishula/issues/51). Mechanism record: part 1
> (parse, match, action, shared maps). Census record: part 3.
>
> **Spec refs:** [§9.9 socket-plane fast path](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment) ·
> [§9.3 maps](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state)
>
> Degradation targets: TR-06 (engine-as-backend), TR-22 (ext_proc no-hop).

## 1. The ladder statement

Rule: the socket-plane fast path is tier one of enforcement. It is not the enforcement.

The enforcement is the ladder itself. Evaluation of a request reaches one tier, always. A failure
at any stage degrades evaluation to the next tier. No failure mode bypasses evaluation.

| Tier | Surface | Record |
| --- | --- | --- |
| T1 | socket-plane fast path: synthesized programs enforce header-class verdicts before the loopback hop | part 1 |
| T2 | engine-as-backend: the engine receives the forwarded message and evaluates the full ladder | TR-06 |
| T3 | ext_proc no-hop variant: evaluation moves into the service-proxy extension stream | TR-22 |

T2 and T3 are evaluation surfaces, not dead-letter queues. A request forwarded at T2 gets the
same verdict vocabulary and the same telemetry as any other engine request. The plane never
answers a request from its own failure state.

## 2. Failure matrix

Each row names one failure mode, its detection signal, and the next enforcement tier. Detection
signals ride existing surfaces: the apply gate, the load gate, the ring events and the verdict
accounting. The signal discipline follows §9.3: the engine decides, the kernel reports.

| # | Failure stage | Trigger | Detection signal | Next tier | Verdict handling |
| --- | --- | --- | --- | --- | --- |
| F1 | control-plane synthesis failure | policy class does not compose into a template sequence | bundle compile gate at apply | T2 for that class | compile output carries the slow-path route for the class; no kernel program exists for it |
| F2 | program load or verifier rejection | synthesized program fails load or exceeds the envelope | load gate at attach, per program | T2 for the class of that program | the class routes T2 at compile time; the recompile removes the rejected program |
| F3 | runtime parse miss | DFA reaches no message boundary; `strparser` signals a malformed or partial stream | per-message miss event on the ring | T2 for the message | forward, then the engine evaluates; the plane never drops on a parse miss |
| F4 | map exhaustion | pool insert, verdict-cache read or rate read fails on a full or missing key | map error path + counter event | T2 for the affected message or key | forward to the engine path; the engine owns the verdict |
| F5 | unsupported policy class | class sits outside the template-expressible set (census, part 3) | compile-time classification | T2 (T3 where the engine backend is not reachable) | class routes to the engine or the ext_proc variant with no kernel program |

Reading of the matrix: F1, F2 and F5 bind whole policy classes at compile time. F3 and F4 bind
single messages or keys at runtime. Compile-time dispositions remove work from the fast path
before it attaches. Runtime dispositions forward and count. Both keep the request inside
evaluated territory.

## 3. Degradation rules

Rule: a runtime parse miss forwards. It never drops silently.

The fast path holds no drop authority over its own failure state. The only drop verdicts at socket
altitude are enforcement reads: a ban-table hit, a block-disposed verdict-cache hit, a compiled
`drop` action of a policy whose match succeeded. Each of those is engine-decided state (§9.3) or a
compiled policy, not a failure response.

| Failure | Fast-path behaviour | Never happens |
| --- | --- | --- |
| F3 parse miss | forward the message; count the miss event | silent drop |
| F4 map exhaustion | forward to the engine path; count the event | substituted allow without evaluation |
| F1/F2/F5 class disposition | route the class to T2 at compile time | enforcement claim for an unroutable class |

Tier escalation state is per class at compile time and per message at runtime. The two never
mix: a runtime miss forwards one message and leaves the class assignment untouched.

## 4. Contrast: XDP ban semantics

Rule: the XDP ban-table hit keeps its drop verdict. That is shield semantics, not failure
handling.

The XDP plane runs pre-TCP, sees no message state, and answers flow keys from the ban and verdict
maps (§9.3). An XDP ban-table hit drops the packet at the NIC. That drop is a recorded,
engine-issued ban enforced at packet altitude. The socket plane inherits the same map state at
message altitude. Neither plane treats its own failure as a drop. The difference sits only in
what each plane sees: packets at XDP, reassembled messages at the socket layer.

## 5. Verification shape

Rule: each failure mode carries one testable shape. The shapes gate a later build lane.

| # | Failure | Injector | Observable | Pass rule |
| --- | --- | --- | --- | --- |
| V1 | F1 synthesis failure | compile a class outside the template set | compile output for that class | output carries the T2 route and carries no kernel program |
| V2 | F2 verifier rejection | force a template past the envelope in CI | load-gate result per program | the class disposition reads T2; the apply fails or reports the rejected program |
| V3 | F3 parse miss | feed malformed and partial message streams | verdict accounting over the differential harness | zero silent drops; every miss carries a forward + a count event |
| V4 | F4 map exhaustion | fill the pool and the cache to capacity | next-miss behaviour on the affected key | the affected traffic reaches the engine path with parity verdicts |
| V5 | F5 unsupported class | compile a census-userspace class | kernel-side program set | no kernel program carries that class; the class routes T2 |

Each shape reuses an existing harness: V3 and V4 reuse the differential corpus harness
(TR-16/TR-24 patterns); V1 and V5 run as pure-Go compile gates in CI; V2 runs the load gate on
the CI node, as the TR-40 plan specifies. The pass rules are assertions, not aspirations: each
one names an artifact the run prints.

## 6. Ladder invariants

The build lane proves four invariants:

1. Evaluation totality: every request ends at a tier that evaluates it. No tier drops without a
   recorded engine disposition or a compiled policy match.
2. Compile-time honesty: a class bound to T2 never claims fast-path enforcement anywhere in the
   bundle, the kernel program set or the status surface.
3. Forward-on-miss: the parse-miss counter and the forward path are the same transaction; the
   counter never rises without the forward.
4. State reuse: fast-path enforcement reads only §9.3 map state. A verdict not present in the
   maps or the compiled set is not enforceable at socket altitude.

These invariants carry into the verification plans of the TR-40 spike and any implementation
slice that follows it.
