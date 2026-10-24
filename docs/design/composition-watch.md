# Composition re-evaluation watch — the cousin-layer borrow-versus-build contract (TR-36)

> **Trishula design note TR-36** — the composition re-evaluation watch. Parent record:
> [TR-36 #36](https://github.com/trishula-dev/trishula/issues/36). Spec
> [§20.3 open question 7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions)
> asks a re-run. The trigger: a cousin reaches the Trishula shape before Phase 2. The rule: no
> overlapping code ships meanwhile. This record sets the watch contract. The boundary
> (section 2), the adopt bar (section 3) and the receipts (section 4) carry the state. The
> triggers (section 5) and the keep set (section 6) carry the move rules. It follows the
> socket-plane decision-record shape ([TR-39d](socket-plane-fast-path.md), section 2): one row
> per component, one verdict per row.
>
> **Spec refs:** [§20.3 open questions](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions) ·
> [Appendix E](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-e-similar-projects--and-why-we-did-not-build-on-them)
> ([E.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#e2-ebpf-native-network-security-closest-cousins),
> [E.7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#e7-the-synthesis-rule)) ·
> [§8.1 design principles](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#81-design-principles) ·
> [§18.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#183-abuse-of-trishula-as-vantage)

Status: watch record. The record ships no code and files no adoption. The verdicts in section 2
hold at the receipt read of 2026-10-24. A section 5 trigger re-opens the analysis by PR, with
fresh receipts.

## 1. Question and method

The cousins change fast ([§20.3 open question 7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions)).
Each change can move the borrow-versus-build boundary. The watch asks one question per component:
what must the cousin prove before Trishula adopts from it?

Method:

1. One decision row per component (section 2). The verdict vocabulary matches the socket-plane
   record: `adopt`, `adapt`, `reject`, `keep`.
2. One adoption bar per component (section 3). The bar names the proofs the component carries
   before an adopt verdict moves.
3. One dated receipt read (section 4). A receipt carries the fact, the read date and the source
   link. The read moves a verdict row only through a trigger (section 5).
4. One build boundary (section 6). The pieces the spec pins as keep-regardless stay outside the
   watch's reach.

Boundary rules:

- This record watches the three [E.2 cousins](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#e2-ebpf-native-network-security-closest-cousins):
  Synapse, Moat, MicroWAF. The E.3–E.6 catalogs sit at other layers and stay outside this watch.
- The record reads public facts only. No lab run and no tree change rides on it.
- A receipt update appends a dated read. It never edits an earlier read.
- The record edits no other tree surface. A spec-side finding (section 4.2) files in its own lane.
- No overlapping code ships while the watch runs. This rule is the spec's
  ([§20.3 open question 7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions)).

## 2. Decision record — one row per component

The consolidated record at the 2026-10-24 read. One row per component, in the socket-plane
record's shape. The borrow column carries the idea Trishula takes. The build column carries the
boundary that stays Trishula's.

| Component | Receipts | Verdict now | Borrow (the taken idea) | Build (the boundary that stays) |
| --- | --- | --- | --- | --- |
| Synapse (`FoxIO-LLC/synapse`) | section 4.1 | reject; adapt | The altitudes: kernel enforcement with inline deep inspection. The JA4+ identity posture. | The CRD-to-bundle pipeline ([§8.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#81-design-principles)); Gateway-API steering citizenship; the CRS corpus with the parity gate ([§11.8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate)). |
| Moat (`sitedata/moat`; the cited `arxignis/moat` does not resolve) | section 4.2 | reject; adapt | Fingerprint-identity blocking at kernel speed. | A decision path free of a keyed intel service ([§18.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#183-abuse-of-trishula-as-vantage)); the D1/D2 policy citizenship ([§2.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-d1--kubernetes-native-the-waf-is-crds-not-config-files)). |
| MicroWAF (`dcc-bigfred/microwaf`) | section 4.3 | reject; adapt | CEL as the authoring surface. | Kernel-local ban state with no enforcement-path dependency ([§13.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified)); cluster policy and route classes ([§8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#8-architecture)). |

The verdict rows move only by evidence. A trigger of section 5 re-opens the row; the receipts
of section 4 carry the evidence. The three verdict rows share one shape. The cousin carries a
real idea. The spec's machinery stays build-side ([E.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#e2-ebpf-native-network-security-closest-cousins),
[E.7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#e7-the-synthesis-rule)).

## 3. The adoption bar — the watch contract

The bar names proofs, not hopes. Adoption in this record means one thing. The tree carries the
cousin's component at one altitude. Trishula stops building that piece. The common bar holds
for every cousin.

| # | The component proves | Reads against |
| --- | --- | --- |
| 1 | One declarative policy source compiles the component: `WAFPolicy`, or a Gateway-API extension. | [§8.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#81-design-principles) |
| 2 | The component runs shadow-first: evaluative evidence before any enforcement flip. | [D5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#25-d5--honesty-as-a-mechanism-shadow-first-and-differential-parity), [§9.9](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment) |
| 3 | Verdict work passes the CRS differential: 100% applicable rules. | [§11.8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate), [M1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates) |
| 4 | The decision path stays self-hosted: no keyed third-party service inside it. | [§18.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#183-abuse-of-trishula-as-vantage) |
| 5 | The component holds the inline budget: 1.5 ms p99 or better at the 8 KB full-CRS shape. | [M2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates), [TR-39d section 4](socket-plane-fast-path.md) |
| 6 | The license enters the MIT tree at adopt time, with a redistributable carrier. | the tree [LICENSE](../../LICENSE) |

### 3.1 Synapse — the component bar

- The rule lifecycle enters: CRDs or Gateway-API, one policy artifact, no config-file core
  ([D1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-d1--kubernetes-native-the-waf-is-crds-not-config-files)).
- The promotion gate enters: shadow-first with evidence, before kernel enforcement
  ([D5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#25-d5--honesty-as-a-mechanism-shadow-first-and-differential-parity)).
- The license carrier passes the common bar. At the read it fails (section 4.1).

### 3.2 Moat — the component bar

- The decision path drops the keyed intel service and stays self-hosted
  ([§18.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#183-abuse-of-trishula-as-vantage)).
- The rule lifecycle enters, in the form of the common bar row 1.
- The license carrier passes the common bar. At the read it fails (section 4.2).

### 3.3 MicroWAF — the component bar

- The state model climbs to cluster scale: per-tenant route classes replace per-host state
  ([§8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#8-architecture)).
- The ban state moves kernel-local, with no network call on the enforcement path
  ([§13.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified)).
- The license carrier passes. At the read the record carries MIT (section 4.3).

## 4. The maturity read — receipts

Read rules first. The read date is 2026-10-24 (UTC). Every row carries a source link. The read
is one GitHub REST pass. It clones no cousin and builds no cousin. A README claim is a receipt,
not a proof. The verdicts read only against the Appendix E rows and this record's bar.

### 4.1 Synapse

| Receipt | Reading | Source |
| --- | --- | --- |
| Push state | last push 2026-05-18: 158 days quiet at the read | [repo](https://github.com/FoxIO-LLC/synapse) |
| Tail commits | the 3 newest commits (2026-04-27 to 2026-05-06) carry dependency bumps only | [commits](https://github.com/FoxIO-LLC/synapse/commits) |
| Deliverables | 0 tags and 0 releases at the read | [releases](https://github.com/FoxIO-LLC/synapse/releases) |
| Lineage | the record is a fork of `sitedata/moat` | [repo](https://github.com/FoxIO-LLC/synapse) |
| License | the endpoint reads `NOASSERTION`; the README badge reads ELv2, brand gen0sec | [README](https://github.com/FoxIO-LLC/synapse) |
| Product shape | the description reads: "Active NDR solution with eBPF-powered active fingerprint blocking, firewall and proxy" | [repo](https://github.com/FoxIO-LLC/synapse) |

The read shows quiet, not a shape change. The appliance-shape gap list of
[E.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#e2-ebpf-native-network-security-closest-cousins)
holds. The verdict of section 2 holds.

### 4.2 Moat

| Receipt | Reading | Source |
| --- | --- | --- |
| Citation state | the cited [arxignis/moat](https://github.com/arxignis/moat) does not resolve; the `arxignis` account does not resolve either | [spec citation](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#appendix-c-sources) |
| Lineage | the record lives at [sitedata/moat](https://github.com/sitedata/moat) | [repo](https://github.com/sitedata/moat) |
| Move state | PR #43 rides the `arxignis/daemon_mode` branch; the transfer shows in the history | [commits](https://github.com/sitedata/moat/commits) |
| NOTICE state | the 2025-10-27 commit adds the NOTICE (FoxIO License 1.1) and bumps the version to 0.0.4 | [commits](https://github.com/sitedata/moat/commits) |
| Push state | last push 2025-10-27: 361 days quiet at the read | [repo](https://github.com/sitedata/moat) |
| Deliverables | 0 tags and 0 releases at the read | [releases](https://github.com/sitedata/moat/releases) |
| License | the endpoint reads `NOASSERTION`; the README badge reads ELv2, brand arxignis | [README](https://github.com/sitedata/moat) |

The read shows a move: the record changed carrier. The keyed-intel decision path stays the
structural gap of [E.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#e2-ebpf-native-network-security-closest-cousins).
The verdict of section 2 holds.

One finding files here: the spec's `arxignis/moat` citation does not resolve at the read. The
Appendix E row and the source-entry update belong to a spec maintenance lane. This record edits
no spec line.

### 4.3 MicroWAF

| Receipt | Reading | Source |
| --- | --- | --- |
| Age state | the record starts 2026-08-10: 74 days old at the read | [repo](https://github.com/dcc-bigfred/microwaf) |
| Push state | last push 2026-09-05: 48 days before the read; the newest merge lands PR #1 (`feat/dcc-daemon`) | [commits](https://github.com/dcc-bigfred/microwaf/commits) |
| License | MIT | [repo](https://github.com/dcc-bigfred/microwaf) |
| Deliverables | 0 tags and 0 releases at the read | [releases](https://github.com/dcc-bigfred/microwaf/releases) |
| Audience | 0 issues and 0 subscribers at the read | [repo](https://github.com/dcc-bigfred/microwaf) |

The read shows movement, not a shape change. The small-host state model of
[E.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#e2-ebpf-native-network-security-closest-cousins)
holds. The verdict of section 2 holds.

### 4.4 The verdict at this read

No trigger of section 5 fires at this read. The three verdict rows stand: reject as base, adapt
the ideas, build the boundary. The citation finding of section 4.2 files as a receipt.

## 5. Re-evaluation triggers

A trigger re-opens the analysis for one component layer. The re-run lands as a PR against this
record: fresh receipts, verdict rows by evidence, no silent adoption. The triggers below name
the Trishula-shape pieces piecewise; they read the record's own bar of section 3.

Schedule trigger:

- Re-read the receipts once per quarter. The update appends a dated read block to section 4.

Event triggers:

| # | Trigger | Layer | Moves |
| --- | --- | --- | --- |
| T1 | A cousin ships a declarative cluster policy artifact (CRD or Gateway-API extension), with a public compile-and-enforce proof. | policy | verdict row |
| T2 | A cousin publishes CRS-corpus parity evidence from CI. | verdicts | verdict row |
| T3 | A cousin holds ban state kernel-local, with no network call on the enforcement path. | bans | verdict row |
| T4 | A cousin enforces JA4+-class identity at kernel speed behind a GitOps lifecycle. | bots | verdict row |
| T5 | A citation dies or a record changes carrier. | receipts | receipts only |
| T6 | A cousin's license changes to a redistributable carrier. | license | bar row 6 |

T5 and T6 keep the receipts honest. T1 to T4 move verdict rows, always against the full bar of
section 3.

## 6. What stays regardless

The spec pins the keep-regardless set ([§20.3 open question 7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions)):
the differential suite and the CRD compiler. The record pins four keep rows:

| Keep row | Reads against |
| --- | --- |
| The CRS differential parity gate stays CI-blocking. | [§11.8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate), [M1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates) |
| The `WAFPolicy`-to-bundle compile pipeline stays the one policy artifact path. | [§8.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#81-design-principles) |
| Userspace decides; the kernel enforces; the kernel stays decision-free. | [§20.3 open question 3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions) |
| Shadow-first promotion stays the mechanism, with evidence records. | [D5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#25-d5--honesty-as-a-mechanism-shadow-first-and-differential-parity) |

No cousin carries these four rows at the read of section 4. An adoption claim that touches any
keep row reads against the bar of section 3 first. The append rule of section 1 holds: an update
adds rows, it never removes them.

## 7. Closure record

- The watch contract is set: the boundary (section 2), the bar (section 3), the receipts
  (section 4). The triggers (section 5) and the keep set (section 6) complete it.
- The verdicts stand at the 2026-10-24 read: reject as base, adapt the ideas, build the rest.
- The record files one finding: the spec's `arxignis/moat` citation does not resolve (section
  4.2). The spec-side edit files in its own lane.
- Receipt updates append to section 4 by PR. The parent record
  [TR-36 #36](https://github.com/trishula-dev/trishula/issues/36) closes on this PR; the watch
  continues.
