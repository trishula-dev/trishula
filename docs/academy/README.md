# docs/academy

The teach-the-web curriculum lives here. The spec is
[PRD §7](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#7-teach-the-web-curriculum).
Five modules cover the wire, TLS, eBPF, security modeling and the
frontier. The modules land with
[TR-27](https://github.com/trishula-dev/trishula/issues/27) and
[TR-28](https://github.com/trishula-dev/trishula/issues/28).

The developer's first lesson is the DX1 lab
([lab/dx1](../../lab/dx1/README.md)). One scenario: kind + NGF +
Trishula + one CEL rule. The developer applies the rule and reads the
block on live traffic. The timed gate `dx1-gate.sh` asserts the charter
timing: clone → first enforced rule in ≤ 15 min
([PRD §21 M3](https://github.com/trishula-dev/trishula/blob/main/docs/PRD.md#21-success-metrics--adoption-gates)).
The nightly job
([lab-nightly.yml](../../.github/workflows/lab-nightly.yml)) runs the
gate and keeps the timing honest.
