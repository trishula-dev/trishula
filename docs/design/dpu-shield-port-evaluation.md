# The DPU shield port — evaluation record (TR-32)

> **Trishula design note TR-32** — the tracked-evaluation record for the DPU port lane.
> Parent record: [TR-32 #32](https://github.com/trishula-dev/trishula/issues/32). The
> fail-open ladder record owns degradation semantics
> ([part 2](socket-plane/2-failopen-ladder.md)); the mechanism note owns the two-plane
> framing ([part 1](socket-plane/1-mechanism.md)). This record decides one contract: what
> the shield needs on a DPU-attached NIC of the BlueField class. It ships no code and
> makes no capability claim.
>
> **Spec refs:** [§20.2 phasing](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#202-phasing) ·
> [§9.1 the two-plane principle](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle) ·
> [§9.3 maps and state](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#93-maps-and-state) ·
> [§9.5 kernel-side rate accounting](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#95-kernel-side-rate-accounting-feed-13) ·
> [§13.4 enforcement tiers](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#134-enforcement-actions-by-tier) ·
> [§16.3 resource shapes](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#163-scheduling-and-resource-shapes) ·
> [§17.1 budgets](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#171-budgets-by-stage) ·
> [§20.3 open questions](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions)

Status: tracked evaluation, per the §20.2 Phase 1+ lane. The record decides the port
contract. It ships no code. It measures nothing. No hardware runs in this lane, so every
hardware-gated row carries the PENDING status. The plan in section 9 prices each leg; the
register in section 12 keeps each absent measurement on the record.

## 1. The question the record answers

Rule: the record states what the shield needs on a DPU-attached NIC, and nothing more.

The shield is the kernel plane of §9.1: XDP enforcement programs, shared maps and a Go
loader. Offload-capable hardware carries its own Arm cores and its own Linux kernel at the
NIC. The port question is a placement question. Three sub-questions decide it:

1. Where does enforcement run when the NIC kernel sits in path?
2. What moves across the PCIe link, and by which transport?
3. What stays host-side, and under which frozen properties?

The verdict, in one table:

| Question | Verdict | Record section |
| --- | --- | --- |
| Where does enforcement run | On the DPU-side kernel, at NIC ingress | section 4 |
| What moves | The programs, the map instances, the counters | section 4 |
| What stays host-side | Authority, detection, compile, evidence | section 4 |
| Which rows stay open | Every measurement row | section 9 and section 12 |

## 2. What the record does not claim

Rule: this record transfers no number from literature or vendor material to the port.

The honesty rule of [§2.5 D5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#25-d5--honesty-as-a-mechanism-shadow-first-and-differential-parity)
governs the lane. The claims stay within three bounds:

- The record decides contract placement. It asserts no measured performance on any DPU.
- The [§16.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#163-scheduling-and-resource-shapes)
  envelopes (10.1 Mpps/core, 24 Mpps/core, 21.5 Mpps) are literature rows for host NICs.
  They cover no DPU. The port inherits none of them.
- The port moves enforcement, not detection. CRS and Coraza evaluation never run on the
  DPU. The kernel stays decision-free ([§20.3.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions)).

Vendor supply mechanisms — SDK transports, switchdev modes, firmware features — are
record-at-runtime facts. The plan logs them per leg; it never presupposes them.

## 3. The surface today

Rule: the port contract starts from the code, not from the spec sketch. The table records
the owned surface with its file.

| Surface | File | Contract |
| --- | --- | --- |
| `shield_xdp` program | `bpf/shield_xdp.c` | IPv4-only parse; `ban_table`, `verdict_cache`, `acl4` lookups; `XDP_DROP` on a live ban |
| `bans_v4` program | `bpf/ban_xdp.c` | in-kernel auto-lift at expiry; per-CPU verdict stats plus the TR-80 probe counter |
| TC ingress classifier | `bpf/flow_tc.c` | bounded header walk; `flow_event` ring producer; shared ban and verdict maps |
| Route-mark template | `bpf/route_mark.c` | TR-40b compile template; LPM `route_marks`; fail-forward default action |
| Go loader | `internal/shield/loader_linux.go` | bpf2go arm64 and x86 objects; generic-XDP attach; map handles |
| Ban enforcer | `internal/shield/banadapter.go` | engine `would-ban` record to `bans_v4` write at the enforcing clock; evidence per act |
| Wire structs | `internal/shield/bans.go`, `internal/shield/bansv4.go` | `BanKey` 18 bytes, `BanVal` 16 bytes; `BansV4Key` 8 bytes, `BansV4Val` 16 bytes; size asserts |
| Visibility tier | `internal/shield/tier.go`, `internal/shield/probe.go` | full, first_packet, none; probe-burst deltas; refusal on none |
| Ban evidence | `internal/shield/banevidence.go` | append-only JSONL; publish outcome, reason code, expiry |

Three facts anchor the port. Attach is generic XDP today (`link.XDPGenericMode`). The
enforcing program compares expiry against `bpf_ktime_get_ns` in its own kernel. The
publisher rebases the ban window onto that same domain clock at write time. The wire is
frozen by `internal/shield/contract_test.go` and the wire tests; the port never widens it
in silence.

Three frozen properties bind every port decision:

1. The kernel stays decision-free ([§9.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#91-the-two-plane-principle)).
   It enforces engine-written state only.
2. The fail-open ladder owns degradation ([TR-39b](socket-plane/2-failopen-ladder.md)).
   No failure below the engine adds a drop.
3. A publish failure is a failed ban. The evidence row records it. (The `BanRecord`
   contract keeps `publish_err` and the publish outcome.)

## 4. The offload split

Rule: enforcement moves to the DPU-side kernel. Authority, detection and policy compile
stay host-side.

| Component | Today | DPU port contract | Move |
| --- | --- | --- | --- |
| `shield_xdp` program | host NIC, generic XDP | runs at DPU ingress on the DPU kernel | moves |
| `bans_v4` program | host NIC, generic XDP | runs beside `shield_xdp` at DPU ingress | moves |
| `ban_table`, `verdict_cache`, `acl4` | host kernel maps | live on the DPU kernel; one instance family | moves |
| Probe and verdict counters | host kernel, per-CPU | live beside the maps on the DPU | moves |
| Expiry comparison | the enforcing kernel's clock | stays at the enforcing point; see section 6 | moves with the maps |
| TC classifier and ring | engine-node veths | host plane; the ring stays the engine's feed | stays |
| Engine: ladder, CRS, CEL, ML | userspace, host | full parsing freedom per §9.1; never kernel work | stays |
| Bundle compile: CRD to bundle to maps | userspace, host | compiles host-side; publishes through the transport | stays |
| Ban algorithm (§13.3) | engine, host | decides; kernel counters are inputs only (§9.5) | stays |
| Verdict authority | engine, host | the engine decides, both kernels enforce (§9.3) | stays |
| OTel drain and evidence | userspace, host | drains from the host; DPU events ride the transport | stays |
| `MapPublisher` | in-process map writes | interface stays; the write path gains a transport and a DPU-side writer | splits |

The transport carries enforcement state only: ban writes, lifts, verdict rebase. It never
carries policy evaluation, policy bytes or detection work. The port re-uses the §9.3 map
families; no new map family joins under this record (the TR-03 contract rule).

One naming note. The lane speaks of offload; the contract decides placement. Offload of
detection is out of scope by the §9.1 line; this record never proposes it.

## 5. The publish-path contract

Rule: the host keeps the only ban authority. The DPU-side writer publishes what the host
records.

The loop today: the engine decides, `BanEnforcer.Record` rebases the window onto the
kernel clock, the publish writes `bans_v4`, the program enforces and lifts at expiry. The
port keeps the shape and inserts the link. Contract rows:

- C1 — the `MapPublisher` interface stays. The transport sits behind it, swappable.
- C2 — the transport carries enforcement state only (see section 4).
- C3 — a publish failure stays a failed ban. The evidence row records `publish_err`.
- C4 — the DPU-side writer is the only writer of the DPU-side maps. One writer per map
  family.
- C5 — the host reconcile loop keeps lifting expired bans through the same transport;
  the in-kernel lift stays the enforcing decision.

The queueing choice on an outage is a plan leg, not a prose assumption: leg L8 measures
the behavior the ladder requires. The record pre-commits the ladder shape ahead of the
run: a lost publish extends nothing. Enforced state decays by expiry; new bans wait for
the link.

## 6. The clock-domain rule

Rule: the expiry comparison reads the clock of the kernel that enforces the ban.

Today one kernel domain owns the comparison. The loader reads host
`CLOCK_MONOTONIC`; `bpf_ktime_get_ns` compares in the same domain. The port introduces a
second domain. The DPU kernel carries its own monotonic clock. A host-written absolute
`until_ms` reads a foreign domain at the DPU. Two boots, two clocks: the host
boot-relative stamp alone cannot time a DPU lift. The offset between the domains is a
measurement question.

| Option | Contract shape | Verdict |
| --- | --- | --- |
| O1 — rebase at the enforcing side | the DPU-side writer reads its own clock at publish; the wire keeps the absolute ABI | adopt for the tracked evaluation |
| O2 — relative window on the wire | the transport carries a duration; the enforcing side computes its own deadline | recorded alternative; needs a wire change |
| O3 — one shared epoch | both sides read one epoch; the ABI stays absolute | recorded alternative; needs a domain-spread measurement first |

Decision: adopt O1. The decision gates the minimum change. Plan leg L3 measures the
domain offset and drift; the recorded curve decides once whether O1 holds or the ABI
moves to O2 or O3. No drift number enters this record without that run.

## 7. The visibility tier on a DPU

Rule: the TR-80 vocabulary carries. The probe placement gains legs.

The TR-80 tier ([TR-80 #80](https://github.com/trishula-dev/trishula/issues/80)) classifies
effective visibility from probe-counter deltas: full, first_packet, none. The refusal rule
carries unchanged: a none classification at the enforcing altitude refuses silent attach.

The port changes what the probe must measure. Today the burst classifies host veth
altitudes. On a DPU, the enforcing point sits at the NIC. A burst injected host-side does
not measure the DPU altitude; a tier read at host altitude says nothing about the
enforcement leg. The plan owns the placement questions (leg L5): burst source, altitude
set, and the tier the loader logs at boot. The vocabulary stays; the measurement moves.

## 8. Fail-open legs on the split

Rule: a failure below the engine never adds a drop. The ladder
([TR-39b](socket-plane/2-failopen-ladder.md)) holds across the link.

- Publish outage: new writes fail and wait; existing bans age out in-kernel at expiry; the
  lift runs without the host. The DPU extends and invents nothing.
- Program detach at the DPU: ingress traffic passes the removed hook; the host tier
  surface reads none at that altitude; the evidence stream keeps recording.
- Engine outage: no new decisions; cached verdicts age by their `until_ts`; enforcement
  state decays by TTL. The DPU keeps enforcing what exists, as the host path does today.

Every row above states decay behavior, not performance. Leg L8 measures each row on
hardware before any DPU deployment step claims it.

## 9. The evaluation plan

Rule: one leg, one measurement, one recorded run. A row fills from its run artifact alone.

The run environment block logs before the first measurement: DPU model, DPU-side OS and
kernel version, NIC firmware, driver, the XDP support level of the DPU kernel, host
kernel, and the bpf2go object revision under test (arm64 objects already build in-tree).
Vendor supply mechanisms visible at run time log into the same block.

| Leg | Question | Measure | Budget source | Status |
| --- | --- | --- | --- | --- |
| L1 | Load matrix at the DPU | verifier result per attach mode: native, generic, hw-mode flag | load log; no budget | PENDING |
| L2 | Publish latency across the link | wall time from write to first enforcing drop; p50 and p99 | none yet; informs §17.1 | PENDING |
| L3 | Domain offset and drift | host `CLOCK_MONOTONIC` vs DPU `bpf_ktime_get_ns` curve | decides section 6 ABI | PENDING |
| L4 | Ban-hit rate at DPU ingress | `XDP_DROP` rate and core load on the DPU; legit-traffic preservation | §17.1 budgets, restated per leg | PENDING |
| L5 | Tier placement | TR-80 tier literal per altitude with probe evidence counts | tier contract [TR-80](https://github.com/trishula-dev/trishula/issues/80) | PENDING |
| L6 | Event drain across the link | ring drain rate versus the 16 MiB sizing; loss counter | §9.4 sizing | PENDING |
| L7 | Map capacity on the DPU | 1M-entry map fill and eviction behavior under DPU memory | §9.3 sizing | PENDING |
| L8 | Fail-open rows | measured pass behavior per section 8 outage row plus evidence records | ladder contract | PENDING |

Each leg records into its own run artifact. The artifact names the hardware, the software
revisions and the raw numbers. A failed leg is a result; it enters the record with its
failure. Literature and vendor material fill no row. The [§17.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#17-performance-targets--benchmark-plan)
harness shape guides steady-state legs; the DPU legs reuse it where the plane allows.

## 10. Decision record

| Component | Decision | Record |
| --- | --- | --- |
| Enforcement placement | adopt — DPU-side kernel at ingress | section 4 |
| Verdict authority | keep — host engine decides; two kernels enforce | section 4, §20.3.3 |
| Detection altitude | keep — no detection moves down; never does | section 2, §9.1 |
| Publish path | contract fixed; transport choice pending hardware | section 5, L1 and L2 |
| Clock rule | O1 adopted; ABI change gated on L3 | section 6 |
| Tier vocabulary | keep — TR-80 literals carry | section 7 |
| Probe placement | pending — decided at leg L5 | section 7 |
| Fail-open semantics | keep — decay by expiry; extend nothing | section 8 |
| IPv6 normalization slice | build-side prerequisite; the family-discriminated wire already exists (defect #62 discipline) | section 3 |
| Multi-arch objects | exist — bpf2go arm64 and x86 targets in-tree | section 3 |

## 11. What re-opens the record

1. The first named-hardware run fills or refutes a plan leg.
2. The L3 curve selects O2 or O3; the wire change files its own lane.
3. A map-family change on the shield; the frozen TR-03 contract decides its own record.
4. The §20.2 sibling lane (OpenShift and multi-arch builds) shares this environment
   block on its own record.

## 12. The PENDING register

Every hardware-gated leg sits here until a recorded run on named hardware fills it.

| Leg | Open question | Fill trigger | Status |
| --- | --- | --- | --- |
| L1 | Which attach modes load on the DPU kernel | recorded load log | PENDING |
| L2 | Publish-to-enforce latency budget on the link | recorded latency run | PENDING |
| L3 | Host and DPU domain offset and drift | recorded clock curve | PENDING |
| L4 | Ban-hit rate and core load on the DPU | recorded flood run | PENDING |
| L5 | Probe source and tier set per altitude | recorded tier run | PENDING |
| L6 | Ring drain rate and loss across the link | recorded drain run | PENDING |
| L7 | Map fill and eviction at 1M entries on the DPU | recorded capacity run | PENDING |
| L8 | Measured fail-open rows on the split | recorded outage runs | PENDING |

No row in this register fills from literature, vendor material or inference. The register
is the lane's honesty feature: the port contract exists today; the evidence for its
hardware rows does not, by design.
