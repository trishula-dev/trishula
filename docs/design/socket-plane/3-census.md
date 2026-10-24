# Socket-plane fast path — CRS/CEL enforceable-fraction census (TR-39c)

> **Trishula design note TR-39c** — part 3 of 3 of the socket-plane note. Parent record:
> [TR-39 #51](https://github.com/trishula-dev/trishula/issues/51). Mechanism record: part 1.
> Ladder record: part 2. This census feeds the borrow-vs-build question,
> spec [§20.3 Q7](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#203-open-questions)
> (TR-36).
>
> **Spec ref:** [§9.9 socket-plane fast path](https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#99-socket-plane-l7-fast-path-tracked-evaluation-not-a-v1-commitment)

## 1. Question and status

Beeline reports that 89% of observed L7 service-mesh policies enforce without kernel changes
(arXiv:2605.31084; 4,699 Envoy configs across 2,417 projects). That number counts routing,
bridging and authz policies, not WAF signatures. This census answers the same question for this
project's own corpora: the CRS rule families and the CEL predicate vocabulary. Status: ESTIMATE.
The numbers come from the stated method on the committed corpus. They are not measured runtimes
and they are not portability claims.

## 2. One method, stated once

### 2.1 Corpus (a): CRS

The repo pins a verbatim CRS 4.0.0-rc2 request-phase slice at
`test/crs-differential/testdata/seclang/@owasp_crs/` (differential-parity corpus). The slice
carries 7 files: 901, 913, 921, 930, 941, 942, 944 plus setup. Family labels beyond the slice
come from the CRS documentation family taxonomy (coreruleset.org, "What's In The Rules",
release v4). The census reads only what the corpus carries; it states the slice boundary every
time it generalizes.

Extraction rule for the slice:

1. Fold backslash line-continuations. One `SecRule` directive with an `id:` action opens a
   transaction. Following id-less chained members join it. The unique transaction is the census
   unit (chains read together).
2. Per transaction, record: rule id, `paranoia-level/N` tag, target variables, operator tokens.

Classification rule, applied uniformly:

- Socket-visible targets: `REQUEST_LINE`, `REQUEST_URI`, `REQUEST_FILENAME`, `REQUEST_METHOD`,
  `REQUEST_BASENAME`, `QUERY_STRING`, `REQUEST_HEADERS`, `REQUEST_COOKIES`, `ARGS_GET`,
  `SERVER_NAME`/`SERVER_PORT`, `IP`, `TX`, `MATCHED_VAR*`, `TIME_*`, `GLOBAL`, `RESOURCE`.
- Non-visible targets: `ARGS*` (body-inclusive union), `ARGS_POST*`, `ARGS_JSON`, `XML`,
  `MULTIPART`, `REQUEST_BODY`, `FILES*`, and every `RESPONSE_*` variable. The kernel plane sees
  reassembled, terminated message headers only; body and response bytes never reach it (§9.9).
- Transaction with `skipAfter`: a family-scope gate (control flow), outside the policy census.
- Family 901 (`INITIALIZATION`): setup bookkeeping, outside the policy census.
- Operator classes per transaction (one regex member makes the whole transaction regex-class):
  - P (primitive-expressible): `@eq @streq @gt @gte @lt @le @within` — map to the compare
    primitive of part 1.
  - S (bounded-scan, adapt): `@contains @pm @pmf @ipMatch* @validateByteRange @endsWith
    @startsWith @rsub @validatePattern` — need a bounded-scan primitive or a phrase map.
  - R (regex): `@rx` and bare operators (regex by default) — outside the v1 library.
  - X (semantic engines): `@detect* @geoLookup @rbl @verifyCC @validateHash` — outside the v1
    library.
- Verdict per transaction: `expressible` = all targets socket-visible and class P. `adapt` = all
  targets socket-visible and class S. `userspace` = otherwise.

### 2.2 Vocabulary (b): CEL

The CEL corpus is the surface the repo actually compiles today:

- `rules/cel/seed.yaml` and its wire copy `internal/operator/seed_pack.yaml` (rule TR02-001);
- the DX1 lab packs `deployment/dx1/manifests/dx1-rulepack-sqli.yaml` (DX-LAB-001) and the
  compile-gate fixture `dx1-broken-pack.yaml`;
- the checker fixture `internal/engine/cel/testdata/bad_expr_rules.yaml` (BAD-001).

The environment declaration sits in `internal/engine/cel/rule.go`: `request` carries `method`,
`path`, `query` and `rate_windows`; the top-level name `path` binds to `request.path`. The census
lists the atomic predicates of those rules and maps each onto the part-1 template library.

## 3. Census (a) results — the CRS slice

| Family | File | Policy rules | Expressible (P) | Adapt (S) | Userspace | PL bands (policy rules) |
| --- | --- | --- | --- | --- | --- | --- |
| 901 | REQUEST-901-INITIALIZATION.conf | init bookkeeping (excluded) | - | - | - | - |
| 901 gates | (per-family skipAfter controllers) | 48 gates (excluded) | - | - | - | - |
| 913 | REQUEST-913-SCANNER-DETECTION.conf | 1 | 0 | 1 | 0 | PL1=1 |
| 921 | REQUEST-921-PROTOCOL-ATTACK.conf | 17 | 2 | 0 | 15 | PL1=11 PL2=2 PL3=3 PL4=1 |
| 930 | REQUEST-930-APPLICATION-ATTACK-LFI.conf | 5 | 0 | 2 | 3 | PL1=4 PL2=1 |
| 941 | REQUEST-941-APPLICATION-ATTACK-XSS.conf | 34 | 0 | 1 | 33 | PL1=26 PL2=8 |
| 942 | REQUEST-942-APPLICATION-ATTACK-SQLI.conf | 61 | 0 | 0 | 61 | PL1=20 PL2=32 PL3=7 PL4=2 |
| 944 | REQUEST-944-APPLICATION-ATTACK-JAVA.conf | 14 | 0 | 0 | 14 | PL1=6 PL2=6 PL3=1 PL4=1 |

Totals on the policy basis (208 transactions: 48 gates + 28 init + 132 policy rules):

| Measure | Count | Fraction (ESTIMATE) |
| --- | --- | --- |
| Expressible (P) | 2 of 132 | 1.5% |
| Expressible + adapt (P∪S) | 6 of 132 | 4.5% |
| Userspace | 126 of 132 | 95.5% |

The expressible pair are header/count checks: 921230 (`Range` header presence, `@gt 0`) and
921180 (per-parameter counter over state, `@gt 1`). Their scores feed the anomaly model; the
scoring and blocking stay userspace. The adapt band is four phrase/byte rules: 913100 and the
930121/930130 pair (`@pmFromFile` over header or filename lists) and 941010
(`@validateByteRange` over the filename). The adapt band moves in only if the library grows a
phrase-map or byte-scan primitive; otherwise it stays userspace.

**Estimate statement.** On this method, the socket-plane-expressible fraction of the vendored CRS
policy rules sits at 1.5% to 4.5%. The point value 1.5% holds for the eight-primitive library;
4.5% holds under the extended bounded-scan primitive. The range reflects that library decision,
not corpus noise. Marked: ESTIMATE on a 132-rule committed slice of CRS 4.0.0-rc2.

### 3.1 Families outside the vendored slice (docs taxonomy, family-level verdicts)

These families are absent from the vendored slice. The verdict applies the 2.1 classification to
the family description in the CRS v4 documentation. No per-rule counts exist in-repo; these rows
carry no fraction numbers.

| Family | Inspection target | Verdict |
| --- | --- | --- |
| 920 Protocol enforcement | request line + headers; regex + numeric operators | mostly userspace; small header-presence band expressible |
| 911 Method enforcement | `REQUEST_METHOD` against a method list | expressible (method compare) |
| 912 DoS protection | request counting per source | adapt through the §13 rate/ban plane (§9.5 counters + ban table), not through message templates |
| 922 Multipart attack | multipart body structure | userspace (body target) |
| 932 RCE | command-injection regex over args and bodies | userspace |
| 933 PHP | PHP-injection regex over args and bodies | userspace |
| 934 Generic (Node.js, deserialization) | body payload signatures | userspace |
| 943 Session fixation | cookie values, regex | userspace (visible target, regex operator) |
| 950-959 response families | response bodies | out of socket scope; response evaluation has no socket-plane tier |
| 980 Correlation | counters across both phases | userspace |

## 4. Census (b) results — the CEL vocabulary

| # | Construct (source rule) | Predicate class | Template mapping | Verdict |
| --- | --- | --- | --- | --- |
| 1 | `request.method == "POST"` (TR02-001) | string equality on a header-set field | compare | expressible |
| 2 | `path.matches("/v1/chat/*")` (TR02-001, DX-LAB-001) | path glob | bounded-scan match (prefix/suffix segments at compile time) | adapt |
| 3 | `request.query.contains("UNION")` (DX-LAB-001) | substring over query | bounded-scan match | adapt |
| 4 | `request.rate_windows["5m"].requests > 40` (TR02-001) | map read + numeric threshold | get over the §9.3 `rate_windows` maps + compare | expressible |
| 5 | `size(request.body.messages) > 128` (dx1-broken-pack fixture) | body view | none; the compile gate rejects it today | out of scope (body inspection) |
| 6 | `undeclared_top_level == "x"` (BAD-001 fixture) | name outside the declared env | none; the CEL checker fails the compile | negative fixture (not a policy surface) |

**Estimate statement.** Of the 5 census constructs, 2 map to the eight-primitive library (40%)
and 4 map with the bounded-scan primitive (80%); the body construct stays out of scope at kernel
altitude, as the compile-gate fixture already proves. Excluding the body construct, the in-scope
fraction is 2 of 4 (50%) at the v1 library and 4 of 4 with the extension. Marked: ESTIMATE on the
declared environment of `internal/engine/cel/rule.go` at the tracked state of this repo.

## 5. Reading into the verdicts (feeds §20.3 Q7)

| Component | Verdict | Feeds Q7 because |
| --- | --- | --- |
| Template synthesis (parse-match-action) | adopt — the mechanism class | the offloadable set is the header-class policy classes, sized here and in part 3 of the parent brief |
| Kernel CRS evaluation | reject | 95.5% of CRS policy rules on this corpus are regex/semantic/body work; the kernel adds no enforcement there |
| Socket plane as CRS front-filter (phrase/byte band only) | adapt — optional later extension | the 4.5% band moves in only with a new primitive; treat as a follow-up, not a scope item |
| CEL as the fast-path policy source | adapt | 40-80% of the live vocabulary compiles to the library; the CEL env view (§11.3) already names the same fields the kernel parses |
| Borrow the Envoy-config 89% number | reject — never restate it for CRS or CEL | the 89% measures routing/authz policies of service meshes, a different corpus |

The two corpora give one consistent picture: the socket plane earns its altitude on header-class
policy classes (JWT HS256 once hash coverage lands, RBAC allowlists, route marking, telemetry,
header mutation) and on the CEL vocabulary that names the same fields. The CRS detection mainline
stays at the engine, exactly as §9.9 states: the fast path is an enforcement layer for
header-class policies, not a kernel WAF.
