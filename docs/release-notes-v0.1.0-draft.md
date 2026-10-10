# v0.1.0 release notes — DRAFT (TR-14, issue #14)

> **Status: draft for user approval — nothing here is tagged yet.** The lane
> does NOT tag or release; the tag + GitHub Release are the user's manual
> steps (checklist at the bottom) after the TR-14 PR merges.

**Trishula v0.1.0 — Phase 0 (PoC) exit.** eBPF-native, developer-first WAF /
API firewall for Kubernetes: kernel shield · userspace engine · control
plane. This is the honest exit: everything below is merged to `main`,
GPG-signed, delivered as watched-RED → GREEN leaf PRs, and evidenced by
recorded runs — the `lab/demo.sh` exit-gate transcript (README "Proof"
section), the issue evidence trail (#6, #7, #10, #11, #13, #76, #80), and the
CI gates. What is NOT delivered is in the README "What does not exist yet"
section — the <10 ms inline benchmark is **pending TR-24** (the harness does
not exist yet; the only timing recorded is the apply→effect control-plane
round trip, 2618 ms ≤ 5 s PRD §8 M9 budget).

## What ships (per component)

- **Kernel shield** (`bpf/` + `internal/shield/`, ed9b271…): CO-RE XDP
  shield (ACL, verdict cache, ban table, tier probe counters) + TC flow
  producer (`flow_tc.c`); Go loaders with XDP/TC attach, pinned-prog
  lifecycle, fail-closed `TierRefusal`; visibility tier measured at boot and
  emitted as `trishula.shield.visibility_tier` (#80); ban publish/reconcile
  (`bans_v4`) + JSONL evidence sink. In-VM E2E: ban `TC_ACT_SHOT` (shot 3→4),
  expiry auto-lift, reconciler lift (#10).
- **Userspace engine** (`cmd/engine/` + `internal/engine/`): transparent
  proxy host (NGF backend, `X-Trishula-Hop`), bundle consult + polled
  hot-reload; ingest (ringbuf drain → tx assembly, #81); detection ladder
  S0–S5 with the Verdict/Action/Phase vocabulary (#91); OTel verdict triad
  (trace + `verdicts_total` + log) correlated by request id (#101); botdef
  JA4 + header fingerprints v0 (#99); positive OpenAPI gate v0 (#102);
  rateban ScoredWindowBan v1 (#95) + BanEnforcer → kernel map (#105).
- **CRS evaluator + parity gate** (`internal/crs/` + `test/crs-differential/`,
  #93/#103): embedded-Coraza reference evaluator; CI-blocking differential at
  **19/19 corpus cases, 100% verdict parity** (1 skip documented) (#7).
- **Control plane** (`api/v1alpha1/` + `internal/operator/` + `cmd/operator/`,
  #94/#98/#104): `WAFPolicy` CRD → Bundle v1 compile (fail closed) → CRD
  watch → bundle publish; in-process compile→load round-trip test (0.239 s,
  #75); live apply→effect M9: 2618 ms ≤ 5 s (#76).
- **Lab surfaces** (`lab/`): `demo.sh` the one-command exit-gate demo (setup +
  apply-effect + verify); `dx1/` the NGF-steering lab (kind/OrbStack, hop
  evidence); `demo-attack.sh` (attack replay, Linux VM), `verify-xdp-chain.sh`
  (kernel env gate), `tier-gate.sh` (visibility-tier gate).
- **Test gates** (`test/`): `crs-differential` (parity gate), `ban-conformance`
  (ScoredWindowBan oracle), `banenforce` (in-VM kernel E2E), `tier` (shield
  tier E2E), `bench` (TR-24 placeholder — empty).

Evidence trail: #6 (steering hop + delivery) · #7 (parity 19/19) · #10
(in-VM ban E2E) · #76 (M9 timed) · #11 (OTel triad) · #13 (positive v0) ·
#80 (visibility tiers) — each cited from README; the exit-gate demo output is
pasted verbatim in README "Proof".

## Release assets (PRD §9.2 — byte-identical bpf2go objects per arch)

The bpf2go objects are committed per arch and are byte-identical between
arm64 and amd64 builds (same clang IR emitted for both target keys; sha256
differ only when the object carries arch-dependent constants — here all four
pairs hash equal). Attach as release assets **from the tagged tree** after
re-generating, per §9.2 ("objects generated in-CI via bpf2go so a tagged
release ships byte-identical objects"):

| Object | Role |
|---|---|
| `internal/shield/bpf_shield_arm64_bpfel.o` + `bpf_shield_x86_bpfel.o` | the shield (XDP ACL/verdict-cache/ban table + tier probes) |
| `internal/engine/ingest/ingest_flow_arm64_bpfel.o` + `ingest_flow_x86_bpfel.o` | the TC flow producer consumed by ingest |
| `test/banenforce/ban_enforce_{arm64,x86}_bpfel.o` | kernel ban E2E object |
| `test/tier/tier_{xdp,probe}_{arm64,x86}_bpfel.o` | visibility-tier probe objects |

Checksums (on the current tree at ed9b271; REGENERATE on the tagged commit
and compare — they must match unless the tagged tree moved):

```
466207b1faa91bd08ac71524b804fb4587e487aa27820a5ffb2bdcee082ff0ab  internal/engine/ingest/ingest_flow_{arm64,x86}_bpfel.o
a1984312500142ffc06a37774dfdafa356c26bd5f55006d65d60f10e86e3f8e1  internal/shield/bpf_shield_{arm64,x86}_bpfel.o
cad16bcff92ef2397e3884fb87db0ec86b0e27b720aa7019aa84e858e2078fb1  test/banenforce/ban_enforce_{arm64,x86}_bpfel.o
91f54630a99a764103b0c9b7c6541d4b4dab7e3430558c4bc40afbea1b35d3fe  test/tier/tier_probe_{arm64,x86}_bpfel.o
eb639c9f1ea540e8ca335f961435dd3b6eb4816087bd8127e403b7d86579db21  test/tier/tier_xdp_{arm64,x86}_bpfel.o
```

Verify before upload: `find . -name '*.o' -not -path './.git/*' -exec
shasum -a 256 {} \; | sort` on the TAGGED tree; paste the full checksum list
into the release's `checksums.txt` asset.

## The 4 manual release steps (user)

1. **Tag (signed):**
   `git tag -s v0.1.0 -u AAF8226F3F4C1712 -m 'Trishula v0.1.0 — Phase 0 exit (TR-14)' main`
   (run after the TR-14 PR merges; tag MAIN'S MERGE COMMIT, not the branch
   tip; `git config user.signingkey AAF8226F3F4C1712` if the clone doesn't
   carry the OWASP identity).
2. **Push the tag:** `git push origin v0.1.0` — never re-point a mistaken
   tag; delete + re-tag only before the release object exists.
3. **Create the release with these notes + assets:**
   `gh release create v0.1.0 --title 'v0.1.0 — Phase 0 exit' --notes-file
   <this file rendered for the release> <the 4 archive .o asset paths>
   checksums.txt` (assets per the table above, from the tagged tree).
4. **Verify:** `git tag -v v0.1.0` (signature
   `Shain.Singh@owasp.org / AAF8226F3F4C1712`), and
   `gh release view v0.1.0 --json assets` (4×2 objects + checksums.txt
   present).

## Honesty note (must stay in the release notes verbatim)

Unoptimized inline-processing numbers (<10 ms, PRD §20.2) are **not** in this
release: the benchmark harness is TR-24 and `test/bench/` is a placeholder.
The recorded timing is the apply→effect control-plane round trip (2618 ms,
M9 ≤ 5 s budget — #76). Shield kernel-leg evidence is Linux-VM-based (#10,
#80); on OrbStack-family clusters pod-veth fast paths limit shield visibility
to the first packet of a connection (measured `first_packet` tier — #80).
Nothing in these notes claims benchmark performance or a kind-node kernel
enforcement leg.
