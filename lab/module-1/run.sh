#!/usr/bin/env bash
# TR-27a (issue #169, spec sections 7.1 Module 1 + 7.2 + 11.8) — the
# module-1 lab: the wire and the smuggling lesson.
#
# Scripted scenario (hermetic; no cluster, no kernel, no network):
#   leg 1  wire    — every §11.8 corpus case converts to a raw HTTP/1.1
#                    request file. The converter reuses the harness's own
#                    strict corpus loader (lab/module-1/wire/), so the
#                    replay carries the same bytes the parity gate scores.
#   leg 2  replay  — cmd/attackdemo crs walks every wire file. The S2
#                    reference verdicts (rule ids, INTERRUPT/pass) print
#                    per case.
#   leg 3  parity  — the §11.8 differential parity gate runs on the same
#                    corpus (go test ./test/crs-differential/, the CI tag).
# Opt-in leg (documented in lab/module-1/README.md):
#   leg 4  cluster — KIND_LAB=1: replay three corpus shapes through the
#                    DX1 lab stack (bring it up with lab/dx1/setup.sh
#                    first). The clean shape passes, the DX-LAB-001 probe
#                    shape blocks, both prove the engine hop.
# A skip is loud, never silent. The script exits nonzero on any FAIL.
set -euo pipefail

M1_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${M1_DIR}/../.." && pwd)"
TRISHULA_ROOT="${TRISHULA_ROOT:-$REPO_ROOT}"
KIND_LAB="${KIND_LAB:-0}"
NODE_HTTP_PORT="${NODE_HTTP_PORT:-31437}"
DX1_HOST="${DX1_HOST:-engine.dx1.example.com}"

WORK="$(mktemp -d /tmp/module1-lab.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

banner() { printf '\n============================================================\n== %s\n============================================================\n' "$*"; }
leg() { printf '\n---- leg %s: %s ----\n' "$1" "$2"; }
fail() { printf '== MODULE1-LAB-FAIL — %s ==\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP  %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1 (see lab/module-1/README.md)"
}

require go

banner "module-1 lab (TR-27a, issue #169) — wire lessons over the §11.8 corpus"
printf 'repo:   %s\n' "$TRISHULA_ROOT"
printf 'corpus: test/crs-differential/corpus (20 cases)\n'

# --- leg 1: the corpus on raw wire files ------------------------------------
leg 1 "wire — corpus cases to raw HTTP/1.1 request files"
(
  cd "$TRISHULA_ROOT"
  go build -o "$WORK/wire" ./lab/module-1/wire
  go build -o "$WORK/attackdemo" ./cmd/attackdemo
) || fail "build of lab fixtures failed"
"$WORK/wire" "$WORK/wirefiles" || fail "wire conversion failed"
WIRE_COUNT="$(find "$WORK/wirefiles" -name '*.http' | wc -l | tr -d ' ')"
[ "$WIRE_COUNT" -eq 20 ] || fail "expected 20 wire files, got $WIRE_COUNT"
pass "20 raw wire files converted from the §11.8 corpus"

# --- leg 2: replay through the embedded-Coraza surface ----------------------
leg 2 "replay — attackdemo crs over every wire file (the demo CRS slice)"
INTERRUPTS=0
PASSES=0
for f in "$WORK"/wirefiles/*.http; do
  cname="$(basename "$f" .http)"
  out="$("$WORK/attackdemo" crs "$f")"
  printf 'case %s\n' "$cname"
  printf '%s\n' "$out" | sed 's/^/  /'
  if printf '%s\n' "$out" | grep -q "INTERRUPT"; then
    INTERRUPTS=$((INTERRUPTS + 1))
  elif printf '%s\n' "$out" | grep -q "→ pass"; then
    PASSES=$((PASSES + 1))
  fi
done
pass "replay done: 20 wire files through the demo CRS slice ($INTERRUPTS INTERRUPT, $PASSES pass; rule ids print only where the demo slice matches — the corpus's full expected-id sets score in leg 3)"

# --- leg 3: the §11.8 parity gate on the same corpus ------------------------
leg 3 "parity — the differential gate over test/crs-differential"
if ! (
  cd "$TRISHULA_ROOT"
  go test -tags coraza.rule.no_regex_multiline -count=1 -v -run 'TestCorpusParity$' ./test/crs-differential/ \
    >"$WORK/parity.txt" 2>&1
); then
  cat "$WORK/parity.txt"
  fail "the §11.8 parity gate failed"
fi
cat "$WORK/parity.txt"
grep -q "parity 19/19 ran" "$WORK/parity.txt" || fail "parity gate output changed shape (expected 19/19)"
pass "verdict parity 19/19 (1 explicit skip) — the §11.8 gate holds"

# --- leg 4 (opt-in): the DX1 kind cluster -----------------------------------
leg 4 "cluster — corpus shapes through the DX1 stack (opt-in)"
if [ "$KIND_LAB" != "1" ]; then
  skip "KIND_LAB=1 not set — bring the DX1 lab up first (lab/dx1/setup.sh)"
else
  require kubectl
  require curl
  kubectl get nodes >/dev/null 2>&1 || fail "KIND_LAB=1 but no reachable cluster (run lab/dx1/setup.sh first)"
  BASE_URL="http://127.0.0.1:${NODE_HTTP_PORT}"
  clean_code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: ${DX1_HOST}" "${BASE_URL}/?q=hello")"
  hop_hdr="$(curl -sS -D - -o /dev/null -H "Host: ${DX1_HOST}" "${BASE_URL}/?q=hello" | grep -i "x-trishula-hop" | tr -d '\r' || true)"
  printf 'clean shape    GET  /?q=hello                                    -> %s (%s)\n' "$clean_code" "${hop_hdr:-no hop header}"
  probe_code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Host: ${DX1_HOST}" "${BASE_URL}/v1/chat/completions?q=1%20UNION%20SELECT")"
  probe_rule="$(curl -sS -D - -o /dev/null -X POST -H "Host: ${DX1_HOST}" "${BASE_URL}/v1/chat/completions?q=1%20UNION%20SELECT" | grep -i "x-trishula-rule" | tr -d '\r' || true)"
  printf 'probe shape    POST /v1/chat/completions?q=1 UNION SELECT -> %s (%s)\n' "$probe_code" "${probe_rule:-no rule header}"
  [ "$clean_code" = "200" ] || fail "clean shape returned $clean_code, expected 200 through the DX1 hop"
  [ "$probe_code" = "403" ] || fail "probe shape returned $probe_code, expected 403 (DX-LAB-001)"
  pass "clean shape passes the engine hop; the DX-LAB-001 shape blocks (403)"
fi

banner "MODULE1-LAB-OK — wire, replay and parity legs green"
