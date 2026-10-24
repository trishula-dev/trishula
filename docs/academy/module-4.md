# Academy Module 4 — security modeling

Module 4 of the teach-the-web curriculum. The curriculum map entry
lives in
[spec §7.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#71-curriculum-map--what-each-layer-of-the-product-teaches).
The pedagogy rules live in
[spec §7.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#72-the-pedagogy-rules).

The map entry carries four lessons: negative vs positive security;
anomaly scoring (CRS) and the paranoia levels; bots by fingerprints vs
by behavior; and the rate algorithms with the ban ladder.

## The lessons

| # | Topic | The object it teaches |
|---|---|---|
| 1 | Negative vs positive | blocklists of attacks vs allowlists of shapes |
| 2 | Anomaly scoring | the CRS score ladder and the paranoia levels |
| 3 | Bots | fingerprints vs behavior, and the honest limits |
| 4 | Rate algorithms | token bucket, sliding window, EWMA |
| 5 | The ban ladder | ScoredWindowBan v1 and the L0-L4 tiers |
| 6 | Rule anatomy | the view fields each model reads |
| 7 | The lab | the rate tables, the ban oracle, the kernel enforcement |

## Lesson 1 — negative vs positive security

A negative model names bad inputs. Rules carry patterns from recorded
attacks: this query shape is SQLi, this header value is a tool
fingerprint, this body carries a shell payload. Coverage grows with
the corpus; cost sits in false positives.

A positive model names good inputs. The OpenAPI surface
([spec §11.5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#115-positive-security-schema-and-api-discovery))
carries paths, methods, params, types, lengths, patterns. Enforce mode
blocks the unmatched: unknown path or method, param type or length
outside the schema. The attack needs to look like nothing valid, and
the model holds no attack corpus at all.

Both models sit in one ladder
([spec §11.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#11-rule-engine--detection)):
CRS runs S2, CEL rules S3, the schema gate S4. Neither model wins
alone; the ladder runs both.

## Lesson 2 — anomaly scoring and the paranoia levels

CRS is the correctness baseline
([spec §11.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#112-crs-the-correctness-baseline)).
Trishula imports CRS 4.x as first-class RuleSets with a paranoia
level. The paranoia levels (PL1-PL4) are the tuning vocabulary: PL1
keeps the high-confidence rules; every level up adds noisier,
more sensitive families. Exclusions are versioned records, not
inline folklore.

Scoring, not boolean matching, decides:

- Each match adds weight to the transaction score.
- The inbound threshold rule fires when the score crosses the line
  and blocks. Below the line the match logs. Both live in the
  corpus: the attack cases earn the block id; the low-score
  single-surface cases show the block id absent by design.
- Parity is a gate, not an aspiration
  ([spec §11.8](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#118-crs-differential-parity-gate)):
  verdict-level, CI-blocking, and the module-1 lab replays the same
  corpus.

Shadow-first
([spec §11.7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#117-rule-lifecycle-shadow-first))
is the adoption mechanism: a new rule runs verdict-only, promotion
needs evidence, and a dry apply never widens enforcement.

## Lesson 3 — bots: fingerprints vs behavior

The detector families
([spec §12.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#121-detector-families)):

- TLS fingerprints (JA4/JA4S): computed at the termination hop and
  carried as metadata, or engine-computed when the engine terminates.
- Header-plane fingerprints: header order, casing, value entropy,
  version quirks — an ordered hash against browser and tool profiles.
- Behavioral: request pacing, path graphs, session continuity,
  auth-failure ratios — per-source sliding windows fed by the kernel
  counters ([§9.5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#95-kernel-side-rate-accounting-feed-13)).

The merge rule: each detector emits confidence plus evidence, never a
bare boolean; a consensus of two families acts; a single-family hit
logs and scores
([spec §12.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#122-verdict-integration)).

The honest limits
([spec §12.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#123-honest-limits)):
fingerprints are forgeable — JA4 is a cost raiser, not an identity.
The harder-to-forge altitude is behavioral: the kernel observes the
windows, not the client. The design assumes the adversary adapts.

## Lesson 4 — the rate algorithms

Rate limiting limits; bans remove
([spec §13.1](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#131-why-temporary-bans-and-why-kernel-enforcement)).
The per-route, CRD-selected algorithms
([spec §13.2](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#132-the-rate-algorithms-per-route-crd-selected)):

| Algorithm | Best for | Semantics |
|---|---|---|
| token bucket | steady-state per-route budgets | refill rate r, burst b; reject when the bucket empties |
| sliding window | burst-sensitive endpoints | exact windowed count over k samples; no boundary spike |
| EWMA rate | behavioral DoS signals | exponentially weighted arrival rate per source; smooth |

Rate keys compose per CRD: source IP (default), IP plus route class,
JWT identity where it exists, or the JA4 cluster; a route may limit
per IP and per identity at once. The verdict always carries
`Retry-After` on a throttle — the client sees when to retry, from the
component that throttled it.

The repo's own table tests pin each shape with named rows (for
example: a burst drains the bucket and the empty bucket rejects;
refill never exceeds the burst cap; half-life decay releases the key;
a steady sub-limit rate never breaches). The lab runs them verbosely
(lesson 7).

## Lesson 5 — the ban ladder

`ScoredWindowBan v1` is named, versioned and pinned
([spec §13.3](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified)):

- State per source key: a sliding window of weighted events, the ban
  state, and a recidivism count.
- The score sums each event's weight with exponential decay (half-life
  20% of the window).
- A score at or above the threshold bans the key for `bantime ·
  κ^recidivism`, capped at the human-scale max. Every ban carries its
  contributing weights as reason codes.
- The event weights are the ladder's other models, wired into one
  number: a CRS critical match +5, a bot consensus +4, a rate-window
  breach +3, a schema violation +2, an auth failure +2.

Enforcement tiers
([spec §13.4](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#134-enforcement-actions-by-tier)):

| Tier | Trigger | Action |
|---|---|---|
| L0 observe | first breaches | log and score only |
| L1 rate | rate-window breach | throttle: 429 + `Retry-After` |
| L2 ban | score at threshold | kernel drop, 429 mirror at the app layer |
| L3 tarpit | kernel EWMA flood class | kernel tarpit/drop at XDP |
| L4 prefix | the opt-in §13.3 escalation | prefix-level XDP drop |

The kernel computes no scores (the two-plane law; Module 3). The
engine decides; the shield enforces. Every ban emits an evidence
record ([spec §13.5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#135-observability-of-bans-first-class)):
key, score trajectory, contributing weights, expiry. The ban is
auditable without replaying anything.

## Lesson 6 — rule examples and their wire anatomy

The §7.2 rule in action. Each model reads different bytes.

| Model | The rule it reads | Wire anatomy |
|---|---|---|
| negative (CRS) | the phase-2 attack ids on the §11.8 corpus cases | the raw request bytes the CRS operator chain scans: UA header values, query strings, form bodies, cookie values |
| negative (CEL) | `DX-LAB-001` (the DX1 lab's enforced rule) | the request line: the method token, the target, the query part after `?` |
| rate (seed) | `TR02-001` (`request.rate_windows["5m"].requests > 40`) | the request line again, plus the per-source window counters behind `request.rate_windows` ([§9.5](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#95-kernel-side-rate-accounting-feed-13)) |
| ban (ScoredWindowBan) | the event weights above | the verdict evidence the ladder stages emit: CRS rule ids, bot detectors, rate breaches — each tied to the request bytes its detector read |
| positive (schema) | the OpenAPI validators | the method + path + field shape: request line and body bytes against the declared schema |

## Lesson 7 — the lab: the rate tables, the ban oracle, the kernel enforcement

Run the lab from a repo checkout:

```bash
bash lab/module-4/run.sh
```

| Leg | Surface | The gate |
|---|---|---|
| rate-algorithms | `go test -v ./internal/engine/rateban/` over the token bucket, sliding window, EWMA and key composition tables | every named row holds |
| ban-ladder | `go test -v ./test/ban-conformance/` — the ScoredWindowBan v1 oracle over the fixture file | the spec algorithm reproduces from the fixture set alone |
| fingerprints | `go test -v ./internal/engine/botdef/` over the header fingerprint and behavior window tests | browser vs tool shapes classify apart; the merge policy holds |
| verdict-records | `cmd/attackdemo`: the seed rate rule at sub-limit, boundary and over-limit rates; the BOLA decision record | the verdict flips at the boundary; the `verdict.v1` record prints |
| kernel-ban | `go test -tags ban_e2e ./test/banenforce/` — optional, needs the kernel environment (Module 3's lab carries the same gate) | threshold-cross → kernel drop → expiry → evidence JSONL |

The full shape plus the VM mode for the kernel leg:
[`lab/module-4/README.md`](../../lab/module-4/README.md).

## Course links

| Where | Link |
|---|---|
| The academy index | [`docs/academy/README.md`](README.md) |
| This module's lab | [`lab/module-4/README.md`](../../lab/module-4/README.md) |
| The rate plane sources | [`internal/engine/rateban/`](../../internal/engine/rateban/) |
| The ban oracle fixtures | [`test/ban-conformance/`](../../test/ban-conformance/) |
| The rate section of the spec | [spec §13](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#13-rate-limiting-dos-response--temporary-bans) |
