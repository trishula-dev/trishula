# docs/academy

The teach-the-web curriculum lives here. The spec is
[spec §7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#7-teach-the-web-curriculum).
Five modules cover the wire, TLS, eBPF, security modeling and the
frontier. The modules land with
[TR-27](https://github.com/trishula-dev/trishula/issues/27) and
[TR-28](https://github.com/trishula-dev/trishula/issues/28).

The developer's first lesson is the DX1 lab
([lab/dx1](../../lab/dx1/README.md)). One scenario: kind + NGF +
Trishula + one CEL rule. The developer applies the rule and reads the
block on live traffic. The timed gate `dx1-gate.sh` asserts the charter
timing: clone → first enforced rule in ≤ 15 min
([spec §21 M3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates)).
The nightly job
([lab-nightly.yml](../../.github/workflows/lab-nightly.yml)) runs the
gate and keeps the timing honest.

## The modules

The curriculum map
([spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches))
names five modules. Each row below links one landed module doc and its
runnable lab. The module doc carries every §7.1 topic for its map entry,
and every rule example in it cites its wire anatomy.

| Module | Map entry | Doc | Lab |
|---|---|---|---|
| 1 | the wire: HTTP/1.1, HTTP/2, smuggling | [module-1.md](module-1.md) | [lab/module-1](../../lab/module-1/README.md) |
| 3 | eBPF as a platform | [module-3.md](module-3.md) | [lab/module-3](../../lab/module-3/README.md) |
| 4 | security modeling | [module-4.md](module-4.md) | [lab/module-4](../../lab/module-4/README.md) |
