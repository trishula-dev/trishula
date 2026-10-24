#!/usr/bin/env bash
# TR-27c (issue #171, spec sections 7.1 Module 4 + 2.3 + 13) — the
# module-4 lab: security modeling — the rate algorithms and the ban
# ladder.
#
# Scripted scenario:
#   leg 1  rate-algorithms  (any host, pure Go) — the rateban table tests
#                           for token bucket, sliding window, EWMA and
#                           key composition, verbosely: every named row
#                           is the lesson's fixture.
#   leg 2  ban-ladder       (any host, pure Go) — the ScoredWindowBan v1
#                           conformance oracle over
#                           test/ban-conformance/ban_conformance_fixtures.yaml.
#   leg 3  fingerprints     (any host, pure Go) — the botdef header
#                           fingerprint and behavior window tests: the
#                           fingerprints-vs-behavior lesson, executed.
#   leg 4  verdict-records  (any host) — cmd/attackdemo drives the seed
#                           rate rule at sub-limit, boundary and over-limit
#                           rates (the interactive rate fixture) and prints
#                           the BOLA verdict.v1 record.
#   leg 5  kernel-ban       (Linux, root; optional) — go test -tags ban_e2e
#                           ./test/banenforce/: threshold-cross -> kernel
#                           drop -> expiry -> evidence JSONL (the L2 tier).
#
# The kernel leg needs Linux (root+BTF+BPFFS) or an OrbStack VM: set
# TRISHULA_LAB_VM (the legs then run via `orb run`). A missing kernel
# environment prints a loud SKIP line. PASS / SKIP / FAIL; the script
# exits nonzero on any FAIL and never reports a skip as a pass.
set -euo pipefail

M4_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${M4_DIR}/../.." && pwd)"
TRISHULA_ROOT="${TRISHULA_ROOT:-$REPO_ROOT}"
TRISHULA_LAB_VM="${TRISHULA_LAB_VM:-}"
VM_ROOT="${TRISHULA_VM_ROOT:-}"

WORK="$(mktemp -d /tmp/module4-lab.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

banner() { printf '\n============================================================\n== %s\n============================================================\n' "$*"; }
leg() { printf '\n---- leg %s: %s ----\n' "$1" "$2"; }
fail() { printf '== MODULE4-LAB-FAIL — %s ==\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP  %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1 (see lab/module-4/README.md)"
}

require go

banner "module-4 lab (TR-27c, issue #171) — security modeling"
printf 'repo:  %s\n' "$TRISHULA_ROOT"

# leg 1: the rate-algorithm tables -------------------------------------------
leg 1 "rate-algorithms — token bucket vs sliding window vs EWMA (rateban tables)"
(
  cd "$TRISHULA_ROOT" &&
    go test -count=1 -v \
      -run 'TestTokenBucketRows|TestSlidingWindowRows|TestEWMARateRows|TestKeyCompositionRows' \
      ./internal/engine/rateban/
) >"$WORK/rate.txt" 2>&1 || { cat "$WORK/rate.txt"; fail "the rate-algorithm tables failed"; }
PASS_ROWS="$(grep -c '^    --- PASS' "$WORK/rate.txt" || true)"
grep -E '^    --- PASS: Test(TokenBucket|SlidingWindow|EWMA)Rows' "$WORK/rate.txt" | head -9
pass "the three algorithm families hold ($PASS_ROWS pinned rows green)"

# leg 2: the ban-ladder oracle ------------------------------------------------
leg 2 "ban-ladder — the ScoredWindowBan v1 conformance oracle"
(
  cd "$TRISHULA_ROOT" && go test -count=1 -v ./test/ban-conformance/
) >"$WORK/banconf.txt" 2>&1 || { cat "$WORK/banconf.txt"; fail "the ban conformance oracle failed"; }
tail -1 "$WORK/banconf.txt"
pass "the spec ban algorithm reproduces from the fixture set alone"

# leg 3: fingerprints vs behavior ---------------------------------------------
leg 3 "fingerprints — the botdef detector tests (headers, behavior, merge)"
(
  cd "$TRISHULA_ROOT" &&
    go test -count=1 -v \
      -run 'TestHeaderFingerprintBrowserShape|TestHeaderFingerprintToolShape|TestBehaviorWindowsVectors|TestMergePolicyConsensus' \
      ./internal/engine/botdef/
) >"$WORK/fp.txt" 2>&1 || { cat "$WORK/fp.txt"; fail "the botdef detector tests failed"; }
tail -1 "$WORK/fp.txt"
pass "browser vs tool shapes classify apart; the merge policy holds"

# leg 4: the interactive rate fixture + the verdict record --------------------
leg 4 "verdict-records — the seed rate rule at sub-limit, boundary, over-limit; the BOLA record"
(
  cd "$TRISHULA_ROOT" && go build -o "$WORK/attackdemo" ./cmd/attackdemo
) || fail "attackdemo build failed"
r39="$("$WORK/attackdemo" cel POST /v1/chat/completions 39)"
r40="$("$WORK/attackdemo" cel POST /v1/chat/completions 40)"
r41="$("$WORK/attackdemo" cel POST /v1/chat/completions 41)"
printf '%s\n%s\n%s\n' "$r39" "$r40" "$r41"
check_flip() { # check_flip <rate> <output>
  want=false
  [ "$1" = "41" ] && want=true
  printf '%s\n' "$2" | grep -q "match=$want" \
    || fail "the seed rate rule verdict at rate=$1 is not match=$want"
}
check_flip 39 "$r39"
check_flip 40 "$r40"
check_flip 41 "$r41"
bola_ok="$("$WORK/attackdemo" bola order-7 owner-9 owner-9)"
bola_bad="$("$WORK/attackdemo" bola order-7 owner-9 subject-12)"
printf '%s\n%s\n' "$bola_ok" "$bola_bad"
printf '%s\n' "$bola_ok" | grep -q "→ AUTHORIZED" \
  || fail "the BOLA match case did not print AUTHORIZED"
printf '%s\n' "$bola_bad" | grep -q "→ BLOCK (API1:2023 BOLA)" \
  || fail "the BOLA mismatch case did not print BLOCK"
pass "the rate rule flips exactly at the >40 boundary; the verdict.v1 record prints both ways"

# leg 5: the kernel ban enforcement (optional, L2 tier) -----------------------
leg 5 "kernel-ban — threshold-cross -> kernel drop -> expiry (test/banenforce, tag ban_e2e)"
vm_root_of() {
  if [ -n "$VM_ROOT" ]; then
    printf '%s\n' "$VM_ROOT"
  else
    printf '%s\n' "$TRISHULA_ROOT" | sed 's|^/Users/|/mnt/mac/Users/|'
  fi
}
kernel_ctx() {
  if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" -eq 0 ] && [ -f /sys/kernel/btf/vmlinux ]; then
    printf 'host\n'
  elif [ -n "$TRISHULA_LAB_VM" ]; then
    printf 'vm\n'
  else
    printf 'none\n'
  fi
}
KCTX="$(kernel_ctx)"
case "$KCTX" in
host)
  (cd "$TRISHULA_ROOT" && go test -tags ban_e2e -count=1 -v ./test/banenforce/) \
    >"$WORK/e2e.txt" 2>&1 || { cat "$WORK/e2e.txt"; fail "ban e2e failed on the Linux host"; }
  tail -1 "$WORK/e2e.txt"
  pass "L2 enforcement holds in kernel (publish, drop, expiry, evidence JSONL)"
  ;;
vm)
  VMROOT="$(vm_root_of)"
  printf 'vm %s: go test -tags ban_e2e -count=1 ./test/banenforce/ (at %s)\n' "$TRISHULA_LAB_VM" "$VMROOT"
  orb run -m "$TRISHULA_LAB_VM" -u root bash -cl \
    "cd '$VMROOT' && PATH=/usr/local/go/bin:\$PATH go test -tags ban_e2e -count=1 -v ./test/banenforce/" \
    >"$WORK/e2e.txt" 2>&1 || { cat "$WORK/e2e.txt"; fail "ban e2e failed inside $TRISHULA_LAB_VM"; }
  tail -1 "$WORK/e2e.txt"
  pass "L2 enforcement holds in kernel inside $TRISHULA_LAB_VM (publish, drop, expiry, evidence JSONL)"
  ;;
none)
  skip "kernel environment unavailable (need Linux with root+BTF+BPFFS, or TRISHULA_LAB_VM set; see lab/module-3/README.md)"
  ;;
esac

banner "MODULE4-LAB-OK — rate, ban-ladder, fingerprints, records and kernel legs green"
