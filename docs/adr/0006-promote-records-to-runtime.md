# 0006 — Promote a design record to runtime code

Status: proposed

## Context

The research wave closed as records. The records state designs and carry no
runtime claims: the socket-plane fast path (TR-39/TR-40), the HTTP/3 posture
(TR-29), the DoS detectors (TR-31), the challenge form (the spec), the JWT
boundary (TR-45), the conformance reject classes (TR-44), the TLS posture
(TR-41), the DPU port (TR-32), the stage stamps (TR-47). The board reads Done
on the records. The runtime waits. The operator directs: the capabilities
land as running code. Each capability = its own stream: its own decision, its
own issues, its own PRs.

## Decision

A design record becomes runtime code under one contract:

1. The record names the build leaves. Each leaf lands as code with its gate.
2. A kernel surface ships behind the per-bundle verifier gate (TR-40c) and
   inside the shadow-differential budget (TR-40d) when the class compiles.
   A sensor-only surface ships behind the conformance probes.
3. Every wall reads from a recorded run. No budget row moves without the
   maintainer's hand.
4. The record's stated decision IS the decision. The issue carries it as the
   acceptance contract; the operator amends on review, not by re-design.
5. The promoted surface updates the spec section the record cites.

## Consequences

- The board carries the build leaves, not the record's closed state.
- A record without a passing gate stays a record.
- The ladder of decisions shrinks: the record's decision needs no second
  ruling; the operator reviews it in the issue thread.
