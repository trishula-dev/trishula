# Auth and JWT checks in the engine — the boundary verdict (TR-45)

> **Trishula design note TR-45** — research verdict for the auth/JWT lane
> ([TR-45 #86](https://github.com/trishula-dev/trishula/issues/86)). The
> socket-plane notes carry the mechanism record ([part 1](socket-plane/1-mechanism.md)),
> the fail-open ladder ([part 2](socket-plane/2-failopen-ladder.md)) and the CRS/CEL
> census ([part 3](socket-plane/3-census.md)). The compile census carries the kernel
> split ([TR-40a](socket-plane/4-compiler-census.md)). This record decides one
> question: which auth checks the engine owns, at which ladder site, and with
> which CEL names. It carries no code and makes no capability claim.
>
> **Spec refs:** [§2.3 the detection ladder][d3] ·
> [§11.3 CEL as the developer-facing DSL][cel] ·
> [§13.3 the ban algorithm][ban] · [§15.2 the verdict record][vr] ·
> [§6.3 the non-goals][nongoals]

[d3]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#23-d3--detection-depth-more-than-negative-signatures
[cel]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#113-cel-as-the-developer-facing-dsl
[ban]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#133-the-ban-algorithm-scoredwindowban-v1-specified
[vr]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#152-the-verdict-record-log-body-schema-versioned
[nongoals]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#63-non-goals-v1

Status: research verdict. The record owns no code and lands no enforcement. The
engine's CEL view at the tracked state of this repo carries 4 fields: `method`,
`path`, `query`, `rate_windows` (`internal/engine/cel/rule.go`). No
`request.auth.*` field exists there today. Every name in section 4 is a
proposal. Proposals land with their own slices, one field per landing rule (the
view's no-speculative-fields rule).

## 1. Question and method

The issue asks one question: how much of auth/JWT validation Trishula owns as a
control. The control means 2 things: verdict input and ban participation. The
control never means an identity product. The method follows the
[TR-40a](socket-plane/4-compiler-census.md) record: one decision per row, every
row carries its basis, no row claims a capability.

Method:

1. The boundary table gives every auth duty 1 owner: the verifier, the engine
   or the kernel.
2. The ladder map places each duty at 1 site in S0 to S7, or outside the
   ladder.
3. The vocabulary section names the CEL view of the claims policy.
4. The taxonomy maps each auth failure to 1 reason token, 1 action and 1 ban
   path.
5. The surveys record where the field puts verification and key caching. The
  CEL-extension survey reads upstream extensions, never plans.

## 2. The control boundary

The rule: 1 duty, 1 owner, 1 enforcement site. Verification is a precondition,
not a ladder family. Claims policy is the engine's job. The kernel does only
source-keyed enforcement.

| Duty | Owner | Site | Basis |
| --- | --- | --- | --- |
| TLS termination | gateway (NGF) | pre-ladder | [§9.1]: the kernel plane inspects post-termination plaintext |
| JWT signature check (RS256, ES256, EdDSA) | the verifier (a precondition) | pre-ladder | [§9.1]: no kernel crypto; the surveys, section 8.1 |
| JWKS cache and rotation | the verifier | pre-ladder | section 8.3: the fetch never rides the request path |
| Registered claims: `iss`, `aud`, `exp` | the verifier | pre-ladder | the verifier checks them against its config |
| Claims policy: scopes, tenant, subject | the engine | S3 | [§11.3]: CEL over the structured request view |
| BOLA rule: `resource.owner == request.auth.subject` | the engine | S3 | issue [#83](https://github.com/trishula-dev/trishula/issues/83) |
| Auth-failure outcome counting | the engine | S5 | the detector exists: `bot:authfail` (`internal/engine/botdef/behavior.go`) |
| Auth-failure ban weight | the ban engine | S6 | [§13.3] pins the 401/403 weight at 2 |
| Repeat-offender enforcement | the kernel | S0 | [§9.3] `ban_table`; [§13.4] tiers |
| JWT claims in kernel maps | nothing | — | [§9.3]: maps carry source-keyed state; section 6 |

The 2-plane principle holds across the table ([§9.1]). The verifier and the
engine sit userspace. The kernel never verifies, never parses a token and never
resolves an identity.

## 3. The ladder placement

The ladder carries 8 fixed slots (S0 to S7). The slots form a wire-level
sorting contract; the numbering never renumbers
(`internal/engine/ladder/ladder.go`). This record adds no slot. Signature and
registered-claim checks sit outside the numbered set: they run as the
precondition. The precondition resolves in the headers phase, before S0 reads
the kernel state.

| Site | Auth role | Basis |
| --- | --- | --- |
| precondition | signature check plus `iss`/`aud`/`exp` checks; reason tokens emit here | section 2; outside the 8 slots |
| S0 | kernel bans only; no auth evaluation reads a kernel cache | the cache carries verdicts, never claims ([§9.3]) |
| S1 | none | the matcher reads patterns, not tokens |
| S2 | none | the CRS plane stays at the engine (the [TR-40a](socket-plane/4-compiler-census.md) census, section 3) |
| S3 | the claims-policy stage; the 1 ladder stage that evaluates auth policy | [§11.3]: after the CRS short-circuit, before schema gating |
| S4 | none | schema enforcement inspects shapes, not identities |
| S5 | the auth-failure shape detector | `bot:authfail` exists: 401/403 outcome ratios |
| S6 | the ban weight: 2 per auth failure | [§13.3] pins the weight |
| S7 | none | ML never reads identity ([§14.2]) |

Enforcement posture: every new claims rule ships shadow-first ([§11.7]).
Promotion follows evidence, never a dry `apply`.

## 4. The CEL vocabulary (proposal)

The view grows field by field, as the rules that need a field land. The names
below follow that rule: 1 name per claim class, no speculative field.

| Name | Type | Reads |
| --- | --- | --- |
| `request.auth.verified` | bool | 1 trusted verifier produced the claims; `false` gates every allow path |
| `request.auth.subject` | string | the `sub` claim |
| `request.auth.issuer` | string | the `iss` claim |
| `request.auth.audiences` | list(string) | the `aud` claim |
| `request.auth.scopes` | list(string) | the `scope` claim, split on spaces |
| `request.auth.expiry_epoch` | int | the `exp` claim, epoch seconds |
| `request.auth.claims` | map(string, dyn) | the raw claim map: tenant names and the un-listed classes |

The rules of the vocabulary:

1. The engine fills every name from the precondition channel only.
2. No identity header feeds `request.auth.*`. A self-asserted header is not
   proof. The authorization header carries token bytes to the verifier. It
   never reads as a claim source.
3. The engine leaves `request.auth.verified = false` when the precondition
   misses or fails. CEL reads the miss; no rule panics.
4. Every allow-shaped rule carries `request.auth.verified` in its condition.
5. Rules compare `request.auth.expiry_epoch` against the engine-supplied
   epoch. CEL never reads a clock.

Scope matching rides the native operators first. Membership reads
`"read:orders" in request.auth.scopes`. The comprehension reads
`request.auth.scopes.exists(s, s in ["read:orders"])`. A wildcard scope matcher
is the 1 extension candidate. It rides the same member-overload path as the
seed's `matches(glob)`. It lands when a rule needs it, never ahead of need.

Cost: every proposed comparison is a CEL expression under the per-rule budget
([§11.3]). The budget aborts over-budget rules as errors; errors never read as
clean no-matches (the seed's fail-safe).

## 5. The failure taxonomy and the verdict mapping

The ladder carries 1 action vocabulary: `allow`, `log`, `block`, `challenge`,
`ban`; the first decisive verdict wins. The ladder's `RuleID` tokens carry the
stage prefix (`cel:*`, `crs:*`, `shield:ban:*`). The auth tokens follow the
same shape: `auth:<condition>`.

| Condition | Owner | RuleID (proposal) | Action | Outcome |
| --- | --- | --- | --- | --- |
| token absent | precondition | `auth:token_absent` | block | 401 |
| token expired | precondition | `auth:token_expired` | block | 401 |
| signature invalid | precondition | `auth:signature_invalid` | block | 401 |
| issuer mismatch | precondition | `auth:issuer_mismatch` | block | 401 |
| audience mismatch | precondition | `auth:audience_mismatch` | block | 401 |
| scope insufficient | S3 CEL | `auth:scope_insufficient` | block, policy-selected | 403 |
| subject vs owner mismatch (BOLA) | S3 CEL | `auth:subject_mismatch` | block, policy-selected | 403 |
| brute-force shape | S5 | `bot:authfail` (exists) | bot verdict | feeds S6 |

The taxonomy maps to the verdict record ([§15.2]) in 4 lines:

1. `verdict.reason` carries the plain-language form of the auth condition.
2. The matched-rule set carries the `auth:<condition>` token.
3. The ladder entry names the owner site. The stage name of the precondition
   rides the TR-47 stage-stamp vocabulary
   ([#194](https://github.com/trishula-dev/trishula/issues/194)); this record
   defers the naming there.
4. Logged auth records carry claim names, never claim values ([§15.4]).

Escalation discipline:

1. The ban weight stays at the pinned 2 per 401/403 outcome ([§13.3]). This
   record proposes no new weight.
2. Escalation runs only through the pinned score: the score crosses the
   threshold (default 10) with decay; 1 failure never bans.
3. The S5 detector carries the brute-force shape: a 401/403 ratio of 0.75 or
   more over 6 or more attempts in a 60 s window. The values exist in code
   (`internal/engine/botdef/behavior.go`).
4. The wiring of engine-generated rejections into the outcome counters is an
   implementation question; its own slice owns the wiring. This record claims
   no wiring.

## 6. The kernel participation boundary

Auth state reaches the kernel as enforcement input only. The table:

| Auth state | The kernel sees | Mechanism |
| --- | --- | --- |
| JWT claims | nothing | maps carry source-keyed state ([§9.3]) |
| token bytes | nothing | tokens never leave the verification plane; emission drops token-shaped header values ([§15.4]) |
| 401/403 outcomes | events, not detail | the engine scores them; the kernel never reads the reason class detail |
| ban verdicts | keys | `ban_table`: source key, expiry, numeric reason ([§9.3]) |
| identity | nothing | no kernel component resolves an identity |

2 reasons pin the boundary:

1. Privacy. Claims are identity data.
2. Size. Claim payloads do not fit map value bounds.

Verdict authority stays userspace ([§9.3]): the engine decides, the shield
enforces. The kernel counts, drops and reads bans. It never learns who the
request belongs to.

## 7. The TR-40a reconciliation

The census class `jwt_authz` stays gate-locked
([TR-40a](socket-plane/4-compiler-census.md), section 2). The kernel-module
assessment locks the hash and encode primitives on the tracked kernels. This
record keeps the census verdict and adds the boundary reason:

1. The census governs compile feasibility. Its gate re-reads on the recorded
   upstream trigger, not on demand.
2. This record governs policy altitude. Claims identity stays engine-side even
   under an open gate.
3. A compiled `jwt_authz` artifact, with the gate open, carries only the
   source-keyed verdict classes the maps carry today. It never carries claims.
4. HS256 offload stays a compile question. The claims policy stays a userspace
   question. The 2 records compose with no conflict.

## 8. The surveys

### 8.1 Where the field puts verification

| Component | Verification site | Key cache pattern |
| --- | --- | --- |
| [Envoy jwt_authn](https://envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter) | a proxy HTTP filter; rejects pre-upstream | local JWKS or remote JWKS with `cache_duration` (default 600 s) and async fetch; caches valid tokens only |
| [Kong JWT plugin](https://developer.konghq.com/plugins/jwt/) | gateway data plane; discards failed tokens | shared-memory JWKS caches; `exp`/`nbf` checks stay optional |
| [Kubernetes API server](https://kubernetes.io/docs/reference/access-authn-authz/authentication/) | the authenticator chain | OIDC discovery keys, loaded locally; `TokenReview` is a per-request API-server round trip |
| [Vault JWT auth](https://developer.hashicorp.com/vault/docs/auth/jwt/oidc-providers/kubernetes) | consumer side | public-key checks; it deliberately skips `TokenReview` |

The survey gives 3 verdicts:

1. The field puts signature verification at the proxy or gateway, in userspace,
   pre-upstream. This record's precondition matches the field.
2. No component in the table verifies a JWT in kernel space. The tracked
   kernels lack the primitives ([§9.1]; the
   [TR-40a](socket-plane/4-compiler-census.md) part-1 assessment).
3. Trishula follows the field on verification. The engine's value-add is the
   claims policy at S3, plus the ban loop at S5 and S6.

### 8.2 The CEL extension surface

| Surface | State | Verdict |
| --- | --- | --- |
| membership (`in`) over a list | language core | use first |
| `exists` / `all` comprehensions | language core | use |
| `ext.lists`: `range`, `slice`, `sort` | upstream extension | stays out until a rule needs it |
| `ext.strings` | upstream extension | stays out until a rule needs it |
| a scope-glob member function | not upstream | the 1 candidate; rides the `matches(glob)` overload path |

### 8.3 The JWKS cache patterns

| Pattern | Shape | Verdict for the data plane |
| --- | --- | --- |
| local JWKS with background TTL refresh | fetch off the request path | the verifier's pattern; matches the Envoy `remote_jwks` cache shape |
| remote JWKS fetch per request | fetch on the data plane | reject: a network fetch owns request latency |
| `TokenReview` per request | an API-server round trip | reject: availability couples the API server to every request |

The engine never fetches JWKS inline with request evaluation. A future
engine-owned verifier, if one lands, refreshes its key set off-path with a TTL.
This record claims no such verifier.

## 9. The decision record

| Item | Decision | Record |
| --- | --- | --- |
| The precondition boundary: verification upstream or engine-precondition, never kernel | adopt | section 2 |
| S3 as the 1 claims-policy stage; no ladder renumbering | adopt | section 3 |
| The `request.auth.*` vocabulary: 7 names | adopt (design) | section 4 |
| The `request.auth.verified` fail-safe gate | adopt | section 4 |
| Scope matching: native operators first | adopt | section 4, section 8.2 |
| The `auth:<condition>` RuleID and reason tokens | adopt (design) | section 5 |
| The failure-to-action mapping | adopt | section 5 |
| Kernel participation: bans only, claims never | adopt | section 6 |
| The TR-40a gate-locked verdict | stays | section 7 |
| The wildcard scope extension | defer until a rule needs it | section 8.2 |
| JWKS fetch inline with request evaluation | reject | section 8.3 |
| `TokenReview` in the data plane | reject | section 8.3 |
| Self-asserted identity headers as a claim source | reject | section 4 |
| ML features over identity claims | reject | section 3 |
| The CEL rule-pack demo with fixture JWTs | out of this record | section 10 |

## 10. The closure record

What stays outside the engine:

1. An identity product: no user store, no credential store, no account state.
   [§6.3] records the vault boundary already: Trishula references JWT claims,
   it stores nothing and tokenizes nothing.
2. Token issuance, token refresh, revocation or introspection.
3. Cryptographic checks in kernel space: no signature work at XDP or TC.
4. JWKS fetch or refresh inline with request evaluation.
5. Identity headers as an unverified claim source.
6. ML features over identity claims ([§14.2]).
7. Logged claim values: records carry names only ([§15.4]).

Downstream notes:

1. The vocabulary feeds the TR-05 view-extension slice.
2. The precondition stage naming feeds the TR-47 stage-stamp record
   ([#194](https://github.com/trishula-dev/trishula/issues/194)).
3. The demo rule pack over fixture JWTs lands in its own slice, only if a
   verdict calls for it. This record closes TR-45 without it.

The record closes TR-45: the boundary, the ladder placement, the vocabulary,
the taxonomy, the kernel note, the reconciliation and the surveys. No
capability claim rides on the record. Every named artifact stays a proposal
until its own slice lands.
