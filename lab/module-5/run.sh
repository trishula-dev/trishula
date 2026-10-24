#!/usr/bin/env bash
# TR-28 (issue #28, spec sections 7.1 Module 5 + 7.2 + 14) — the module-5
# lab: the frontier lessons.
#
# Scripted scenario:
#   leg 1  verdicts     (any host, pure Go) — the ladder's action vocabulary
#                         and resolution semantics (the DX5 verdict
#                         record's vocabulary).
#   leg 2  fail-closed  (any host, pure Go) — the operator compile gate:
#                         the uncompilable-rule oracle plus the route-class
#                         fail-closed compile test.
#   leg 3  dx1          (opt-in, KIND_LAB=1) — lab/dx1/apply-effect.sh runs
#                         the shipped apply→effect scenario; its fail-closed
#                         leg applies the uncompilable body-view policy.
#                         The leg asserts the operator log line and the
#                         preserved traffic shape: COMPILE FAILED, and the
#                         benign pass and the DX-LAB-001 block both survive.
#
# The HTTP/3 and PQ legs are PENDING — the owning evaluations are named in
# docs/academy/module-5.md. No leg reports a pending item as a pass.
# A missing cluster prints a loud SKIP line. PASS / SKIP / FAIL; the
# script exits nonzero on any FAIL and never reports a skip as a pass.
set -euo pipefail

M5_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${M5_DIR}/../.." && pwd)"
TRISHULA_ROOT="${TRISHULA_ROOT:-$REPO_ROOT}"
KIND_LAB="${KIND_LAB:-0}"
NODE_HTTP_PORT="${NODE_HTTP_PORT:-31437}"
DX1_HOST="${DX1_HOST:-engine.dx1.example.com}"

WORK="$(mktemp -d /tmp/module5-lab.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

banner() { printf '\n============================================================\n== %s\n============================================================\n' "$*"; }
leg() { printf '\n---- leg %s: %s ----\n' "$1" "$2"; }
fail() { printf '== MODULE5-LAB-FAIL — %s ==\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP  %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1 (see lab/module-5/README.md)"
}

require go

banner "module-5 lab (TR-28, issue #28) — the frontier lessons"
printf 'repo:  %s\n' "$TRISHULA_ROOT"

# --- leg 1: the verdict vocabulary --------------------------------------------
leg 1 "verdicts — the ladder's action vocabulary and resolution semantics"
(
  cd "$TRISHULA_ROOT" && go test -count=1 ./internal/engine/ladder/
) >"$WORK/ladder.txt" 2>&1 || { cat "$WORK/ladder.txt"; fail "the ladder tests failed"; }
tail -1 "$WORK/ladder.txt"
grep -q "^ok  " "$WORK/ladder.txt" || fail "the ladder leg ended without a green package line"
pass "the action vocabulary and resolution semantics hold (the DX5 vocabulary)"

# --- leg 2: the operator compile gate -------------------------------------------
leg 2 "fail-closed — the uncompilable-rule oracle + the route-class fail-closed compile"
(
  cd "$TRISHULA_ROOT" &&
    go test -count=1 -v \
      -run 'TestReconcileFailClosedOnUncompilableRule|TestCompileRouteClassFailClosed' \
      ./internal/operator/
) >"$WORK/operator.txt" 2>&1 || { cat "$WORK/operator.txt"; fail "the compile-gate tests failed"; }
FC_ROWS="$(grep -cE '^[[:space:]]*--- PASS' "$WORK/operator.txt" || true)"
tail -1 "$WORK/operator.txt"
pass "uncompilable policies return their error and stamp nothing ($FC_ROWS oracle rows green)"

# --- leg 3 (opt-in): the DX1 fail-closed scenario --------------------------------
leg 3 "dx1 — apply→effect, the broken-policy failure path, and the traffic read (opt-in)"
if [ "$KIND_LAB" != "1" ]; then
  skip "KIND_LAB=1 not set — bring the DX1 lab up first (lab/dx1/setup.sh)"
else
  require kubectl
  require curl
  kubectl get nodes >/dev/null 2>&1 || fail "KIND_LAB=1 but no reachable cluster (run lab/dx1/setup.sh first)"
  printf 'running lab/dx1/apply-effect.sh (the shipped M9 scenario + its fail-closed leg)\n'
  bash "$TRISHULA_ROOT/lab/dx1/apply-effect.sh" >"$WORK/effect.txt" 2>&1 \
    || { tail -20 "$WORK/effect.txt"; fail "apply-effect failed (see its output above)"; }
  grep -q "M9 apply" "$WORK/effect.txt" || fail "apply-effect ended without its M9 timing line"
  OPLOG="$(kubectl -n dx1 logs deploy/dx1-operator --tail=50 2>/dev/null || true)"
  printf 'operator log   COMPILE FAILED dx1/broken-rule-gate -> %s\n' \
    "$(printf '%s' "$OPLOG" | grep -c 'COMPILE FAILED dx1/broken-rule-gate' || true) line(s)"
  printf '%s\n' "$OPLOG" | grep -m1 'COMPILE FAILED dx1/broken-rule-gate' \
    || fail "the operator never logged COMPILE FAILED for the broken policy"
  BASE_URL="http://127.0.0.1:${NODE_HTTP_PORT}"
  benign_code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Host: ${DX1_HOST}" "${BASE_URL}/v1/chat/completions")"
  probe_code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Host: ${DX1_HOST}" "${BASE_URL}/v1/chat/completions?q=1%20UNION%20SELECT")"
  probe_rule="$(curl -sS -D - -o /dev/null -X POST -H "Host: ${DX1_HOST}" "${BASE_URL}/v1/chat/completions?q=1%20UNION%20SELECT" | grep -i "x-trishula-rule" | tr -d '\r' || true)"
  printf 'benign shape   POST /v1/chat/completions               -> %s (passes)\n' "$benign_code"
  printf 'probe shape    POST /v1/chat/completions?q=1 UNION SELECT -> %s (%s)\n' "$probe_code" "${probe_rule:-no rule header}"
  [ "$benign_code" = "200" ] || fail "benign shape returned $benign_code — the broken policy widened enforcement"
  [ "$probe_code" = "403" ] || fail "probe shape returned $probe_code — the prior enforcement did not survive"
  pass "fail closed holds: no bundle published, the prior enforcement and the pass both survive"
fi

banner "MODULE5-LAB-OK — verdicts and fail-closed legs green"
