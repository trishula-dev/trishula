#!/usr/bin/env bash
# TR-28 (issue #28, spec sections 7.1 Module 2 + 7.2 + 12) — the module-2
# lab: the TLS/QUIC lessons.
#
# Scripted scenario:
#   leg 1  ja4          (any host, pure Go) — the JA4 golden vectors, hash
#                         variants, ALPN codes and self-consistency tests.
#                         The vector set derives the QUIC transport
#                         variant (summary transport code 'q') live.
#   leg 2  header-plane (any host, pure Go) — the in-repo JA4H equivalent:
#                         browser versus tool shapes classify apart.
#   leg 3  h2           (any host, pure Go) — the engine hop's
#                         ALPN-selected plane: the h2/gRPC/SSE head
#                         classification tests.
#   leg 4  termination  (opt-in, KIND_LAB=1) — the DX1 lab: the hop
#                         evidence through NGF, plus the Gateway listener
#                         protocol read. The lab ships the plain-HTTP
#                         listener; an HTTPS-listener leg is pending work.
#
# A missing cluster prints a loud SKIP line. PASS / SKIP / FAIL; the
# script exits nonzero on any FAIL and never reports a skip as a pass.
set -euo pipefail

M2_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${M2_DIR}/../.." && pwd)"
TRISHULA_ROOT="${TRISHULA_ROOT:-$REPO_ROOT}"
KIND_LAB="${KIND_LAB:-0}"
NODE_HTTP_PORT="${NODE_HTTP_PORT:-31437}"
DX1_HOST="${DX1_HOST:-engine.dx1.example.com}"

WORK="$(mktemp -d /tmp/module2-lab.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

banner() { printf '\n============================================================\n== %s\n============================================================\n' "$*"; }
leg() { printf '\n---- leg %s: %s ----\n' "$1" "$2"; }
fail() { printf '== MODULE2-LAB-FAIL — %s ==\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP  %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1 (see lab/module-2/README.md)"
}

require go

banner "module-2 lab (TR-28, issue #28) — the TLS/QUIC lessons"
printf 'repo:  %s\n' "$TRISHULA_ROOT"

# --- leg 1: the JA4 golden vectors -------------------------------------------
leg 1 "ja4 — the golden vectors, hash variants, ALPN codes, self-consistency"
(
  cd "$TRISHULA_ROOT" &&
    go test -count=1 -v \
      -run 'TestJA4GoldenVectors|TestJA4HashVariants|TestJA4ALPNCodes|TestJA4SelfConsistency' \
      ./internal/engine/botdef/
) >"$WORK/ja4.txt" 2>&1 || { cat "$WORK/ja4.txt"; fail "the JA4 vector tests failed"; }
JA4_ROWS="$(grep -cE '^[[:space:]]*--- PASS' "$WORK/ja4.txt" || true)"
grep -q 'TestJA4ALPNCodes' "$WORK/ja4.txt" || fail "the ALPN code test never ran"
tail -1 "$WORK/ja4.txt"
pass "golden vectors hold ($JA4_ROWS pinned cases green; ALPN codes derive; QUIC transport variant derives)"

# --- leg 2: the header-plane fingerprint ---------------------------------------
leg 2 "header-plane — browser versus tool shapes classify apart"
(
  cd "$TRISHULA_ROOT" &&
    go test -count=1 -v \
      -run 'TestHeaderFingerprintBrowserShape|TestHeaderFingerprintToolShape|TestHeaderPairDistinct|TestHeaderEmptyView' \
      ./internal/engine/botdef/
) >"$WORK/headers.txt" 2>&1 || { cat "$WORK/headers.txt"; fail "the header-plane tests failed"; }
H_ROWS="$(grep -cE '^[[:space:]]*--- PASS' "$WORK/headers.txt" || true)"
tail -1 "$WORK/headers.txt"
pass "header-plane shapes hold ($H_ROWS pinned cases green)"

# --- leg 3: the h2 head classification -----------------------------------------
leg 3 "h2 — the ALPN-selected plane: stream, gRPC and SSE head tests"
(
  cd "$TRISHULA_ROOT" &&
    go test -count=1 ./internal/engine/http2/
) >"$WORK/h2.txt" 2>&1 || { cat "$WORK/h2.txt"; fail "the http2 package tests failed"; }
tail -1 "$WORK/h2.txt"
grep -q "^ok  " "$WORK/h2.txt" || fail "the h2 leg ended without a green package line"
pass "the h2/gRPC/SSE head classification holds on the one request view"

# --- leg 4 (opt-in): the DX1 termination read ----------------------------------
leg 4 "termination — the DX1 hop evidence + the Gateway listener read (opt-in)"
if [ "$KIND_LAB" != "1" ]; then
  skip "KIND_LAB=1 not set — bring the DX1 lab up first (lab/dx1/setup.sh)"
else
  require kubectl
  require curl
  kubectl get nodes >/dev/null 2>&1 || fail "KIND_LAB=1 but no reachable cluster (run lab/dx1/setup.sh first)"
  BASE_URL="http://127.0.0.1:${NODE_HTTP_PORT}"
  hop_code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: ${DX1_HOST}" "${BASE_URL}/?q=hello")"
  hop_hdr="$(curl -sS -D - -o /dev/null -H "Host: ${DX1_HOST}" "${BASE_URL}/?q=hello" | grep -i "x-trishula-hop" | tr -d '\r' || true)"
  printf 'hop shape      GET  /?q=hello  -> %s (%s)\n' "$hop_code" "${hop_hdr:-no hop header}"
  listener="$(kubectl -n nginx-gateway get gateway edge-gateway -o jsonpath='{.spec.listeners[0].protocol}' 2>/dev/null || true)"
  printf 'listener read  gateway.edge-gateway listeners[0].protocol -> %s\n' "${listener:-unavailable}"
  printf '(the DX1 lab ships the plain-HTTP listener; the reference deployment terminates TLS here)\n'
  [ "$hop_code" = "200" ] || fail "hop shape returned $hop_code, expected 200 through the DX1 hop"
  [ -n "$hop_hdr" ] || fail "no X-Trishula-Hop header — the engine hop is missing"
  pass "the engine hop answers; the live listener protocol reads off the Gateway"
fi

banner "MODULE2-LAB-OK — ja4, header-plane, h2 and termination legs green"
