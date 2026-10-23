#!/usr/bin/env bash
# TR-23 (issue #23, the DX1 lab gate per spec sections 5 and 21) — the DX1 timed gate.
#
# Asserts the M3 timing, one command from a checkout:
#
#   clone → first enforced rule ≤ 15 min
#
# Timed legs (the clock runs from the anchor to the first 403):
#   1. lab/dx1/setup.sh        — lab up (idempotent) + linux binaries
#                                built from THIS tree when missing
#   2. lab/dx1/apply-effect.sh — WAFPolicy apply → first 403; the leg
#                                pins t0 + the effect latency to a
#                                timing file, and the gate reads the
#                                first-enforced-rule moment from it
# Untimed evidence leg (runs after the M3 moment):
#   3. lab/dx1/verify.sh       — hop-by-hop steering evidence
#
# Anchor: DX1_START (epoch seconds). The nightly job sets it right after
# checkout, so the measured window covers the full clone → rule path. A
# plain run anchors at script start. Budget: DX1_TARGET seconds, default
# 900 (15 min, the M3 timed gate per spec section 21). The gate FAILs above the budget; a red run is
# the gate working — the lab exceeded the budget, read the table below.
#
# Timing files (overridable so concurrent gates on one host stay apart):
#   DX1_TIMING_FILE  — written by apply-effect.sh (t0 epoch ns + effect ms)
#   DX1_SUMMARY_FILE — written here (the CI job summary reads it)
set -euo pipefail

DX1_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DX1_START="${DX1_START:-$(date +%s)}"
DX1_TARGET="${DX1_TARGET:-900}"
DX1_TIMING_FILE="${DX1_TIMING_FILE:-/tmp/dx1-apply-effect-timing.txt}"
DX1_SUMMARY_FILE="${DX1_SUMMARY_FILE:-/tmp/dx1-gate-timing.md}"

LOCALARCH="$(go env GOARCH 2>/dev/null || echo arm64)"
ENGINE_BIN="${ENGINE_BIN:-/tmp/engine-linux-${LOCALARCH}}"
OPERATOR_BIN="${OPERATOR_BIN:-/tmp/tr08c-operator-linux}"
export ENGINE_BIN OPERATOR_BIN BIN="${ENGINE_BIN}"

banner() { printf '\n============================================================\n== %s\n============================================================\n' "$*"; }
leg_banner() { printf '\n------------------------------------------------------------\n| DX1 gate leg %d — %s\n------------------------------------------------------------\n' "$1" "$2"; }
table() { # table <setup_s> <apply_s> <verify_s> <total_s> <first_rule_s> <budget_s>
  printf '\n== DX1 gate timing (M3: clone → first enforced rule)\n'
  printf '\n| leg | seconds |\n|---|---|\n'
  printf '| 1 — setup (binaries + lab up) | %s |\n' "$1"
  printf '| 2 — apply→effect leg (t0 → 403) | %s |\n' "$2"
  printf '| 3 — verify (untimed evidence) | %s |\n' "$3"
  printf '| full gate run (anchor → end) | %s |\n' "$4"
  printf '\nfirst enforced rule at %s s — budget ≤ %s s (M3 target: ≤ 15 min)\n' "$5" "$6"
}

CURRENT=0
LEG_NAMES=("binaries" "setup (lab up, idempotent)" "apply→effect (the M9 leg, timed)" "verify (hop evidence)")
trap 'printf "\n== DX1-FAIL — leg %s (%s) failed; full output above ==\n" "${CURRENT:-?}" "${LEG_NAMES[${CURRENT}]:-?}" >&2; exit 1' ERR

banner "DX1 timed gate (TR-23, spec section 21 M3) — anchor ${DX1_START} (epoch s), budget ${DX1_TARGET} s"

# --- leg 0: linux binaries from this tree (the clone, never a stale one) ----
CURRENT=1
leg_banner 0 "binaries from this tree when missing"
if ! command -v go >/dev/null 2>&1; then
  echo "missing dependency: go (see lab/dx1/README.md)" >&2
  exit 2
fi
for pair in "engine:${ENGINE_BIN}:./cmd/engine" "operator:${OPERATOR_BIN}:./cmd/operator"; do
  IFS=: read -r what bin pkg <<<"$pair"
  if [ ! -f "$bin" ]; then
    echo "building linux/${LOCALARCH} $what -> ${bin}"
    (cd "${DX1_DIR}/../.." && CGO_ENABLED=0 GOOS=linux GOARCH="${LOCALARCH}" go build -o "${bin}" "${pkg}")
  fi
done

# --- leg 1: the lab up (timed, idempotent) ----------------------------------
CURRENT=2
leg_banner 1 "${LEG_NAMES[1]}"
T0="$(date +%s)"
"$DX1_DIR/setup.sh"
SETUP_S=$(( "$(date +%s)" - T0 ))

# --- leg 2: apply→effect (the M9 leg; its timing file pins the M3 moment) ---
CURRENT=3
leg_banner 2 "${LEG_NAMES[2]}"
rm -f "${DX1_TIMING_FILE}"
T0="$(date +%s)"
"$DX1_DIR/apply-effect.sh"
APPLY_S=$(( "$(date +%s)" - T0 ))

# --- the M3 moment: t0 + measured effect, against the anchor -----------------
[ -s "${DX1_TIMING_FILE}" ] || {
  echo "FAIL: the timing file is absent — apply-effect.sh left none at ${DX1_TIMING_FILE}" >&2
  exit 1
}
read -r T0_NS EFFECT_MS < "${DX1_TIMING_FILE}"
FIRST_RULE_MS=$(( (T0_NS + EFFECT_MS * 1000000 - DX1_START * 1000000000) / 1000000 ))
[ "${FIRST_RULE_MS}" -ge 0 ] || FIRST_RULE_MS=0
FIRST_RULE_S=$(( (FIRST_RULE_MS + 999) / 1000 ))

# --- leg 3: hop evidence (after the M3 moment; it fails, never inflates) -----
CURRENT=4
leg_banner 3 "${LEG_NAMES[3]}"
T0="$(date +%s)"
"$DX1_DIR/verify.sh"
VERIFY_S=$(( "$(date +%s)" - T0 ))

TOTAL_S=$(( "$(date +%s)" - DX1_START ))
trap - ERR

table "${SETUP_S}" "${APPLY_S}" "${VERIFY_S}" "${TOTAL_S}" "${FIRST_RULE_S}" "${DX1_TARGET}" | tee "${DX1_SUMMARY_FILE}"

# --- verdict -----------------------------------------------------------------
if [ "${FIRST_RULE_S}" -gt "${DX1_TARGET}" ]; then
  echo "FAIL: first enforced rule at ${FIRST_RULE_S} s — M3 budget ${DX1_TARGET} s (≤ 15 min) exceeded" | tee -a "${DX1_SUMMARY_FILE}" >&2
  exit 1
fi
printf '\nDX1 GATE PASS — first enforced rule at %s s ≤ %s s (M3: clone → first enforced rule ≤ 15 min)\n' "${FIRST_RULE_S}" "${DX1_TARGET}" | tee -a "${DX1_SUMMARY_FILE}"
