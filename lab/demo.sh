#!/usr/bin/env bash
# TR-14 (issue #14, PRD §20.2 Phase 0) — lab/demo.sh: the exit-gate demo.
#
# One command from a fresh clone to the full v0.1 demo. Composes the DX1
# lab gates in evidence order and prints the hop evidence LAST:
#
#   stage 1 — lab/dx1/setup.sh        (idempotent: cluster + NGF + engine
#                                      + echo from the repo + a linux build
#                                      of cmd/engine)
#   stage 2 — lab/dx1/apply-effect.sh (the M9 timed scenario: kubectl apply
#                                      of a WAFPolicy CR → operator compile
#                                      → engine hot-reload → 403 on-traffic;
#                                      ≤ 5 s budget, plus the fail-closed
#                                      broken-policy path)
#   stage 3 — lab/dx1/verify.sh       (hop-by-hop: NGF → engine → echo pod;
#                                      printed last, its header evidence is
#                                      the demo's closing block)
#
# Every stage passes/fails LOUDLY (per-stage PASS markers, a DEMO-OK /
# DEMO-FAIL banner, `set -euo pipefail` — the first failing stage aborts
# the run with its full output above the banner). A plain run needs only
# `go` + `kubectl` + `helm` + `docker` + `curl`; stage 3's output is the
# transcript pasted into README.md (Proof) and the release notes.
#
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${LAB_DIR}/.." && pwd)"
cd "$REPO_DIR"

LOCALARCH="$(go env GOARCH 2>/dev/null || echo arm64)"
# Linux binaries for the lab images: one engine build feeds both setup.sh
# ( BIN) and apply-effect.sh (ENGINE_BIN); the operator build feeds
# apply-effect.sh (OPERATOR_BIN). Built here when missing, from THIS tree.
ENGINE_BIN="${ENGINE_BIN:-/tmp/engine-linux-${LOCALARCH}}"
OPERATOR_BIN="${OPERATOR_BIN:-/tmp/tr08c-operator-linux}"
export M9_TARGET="${M9_TARGET:-5}"

banner() { printf '\n============================================================\n== %s\n============================================================\n' "$*"; }
stage_banner() { printf '\n------------------------------------------------------------\n| STAGE %d/3 — %s\n------------------------------------------------------------\n' "$1" "$2"; }
pass_marker() { printf '| stage %d PASS — %s\n' "$1" "$2"; }

banner "Trishula v0.1 exit-gate demo (lab/demo.sh) — repo $(git rev-parse --short HEAD 2>/dev/null || echo unknown), host arch ${LOCALARCH}"

# --- stage 0: linux binaries (built from this tree when missing) -------------
for pair in "engine:${ENGINE_BIN}:./cmd/engine" "operator:${OPERATOR_BIN}:./cmd/operator"; do
  IFS=: read -r what bin pkg <<<"$pair"
  if [ ! -f "$bin" ]; then
    echo "building linux/${LOCALARCH} $what -> ${bin}"
    CGO_ENABLED=0 GOOS=linux GOARCH="$LOCALARCH" go build -o "$bin" "$pkg"
  fi
done

CURRENT=0
trap 'printf "\n== DEMO-FAIL — stage %s (%s) failed; full output above ==\n" "${CURRENT:-?}" "${STAGE_NAMES[${CURRENT}]:-?}" >&2; exit 1' ERR

STAGE_NAMES=("binaries" "setup (lab up, idempotent)" "apply-effect (M9 timed)" "verify (hop evidence)")

CURRENT=1
stage_banner 1 "DX1 lab setup (lab/dx1/setup.sh, idempotent)"
bash "$LAB_DIR/dx1/setup.sh" 2>&1 | tee /tmp/trishula-demo-stage1.log
pass_marker 1 "cluster + NGF + engine + echo up (lab left installed)"

CURRENT=2
stage_banner 2 "apply→effect, M9 timed (lab/dx1/apply-effect.sh)"
# Rerun determinism: if the engine already hot-loads this very bundle from a
# previous demo run, the operator's bundle is byte-identical and NO new
# "consult active" line appears for apply-effect's assert to find. Restart
# the engine deployment so stage 2's reload evidence is cold (file absent →
# received → hot-reloaded → logged) on every run.
ENGINE_NS="${ENGINE_NS:-dx1}"
kubectl -n "$ENGINE_NS" rollout restart deployment/dx1-engine >/dev/null
kubectl -n "$ENGINE_NS" rollout status --timeout=3m deployment/dx1-engine >/dev/null
bash "$LAB_DIR/dx1/apply-effect.sh" 2>&1 | tee /tmp/trishula-demo-stage2.log
pass_marker 2 "CRD apply → operator compile → engine hot-reload → 403, within budget"

CURRENT=3
stage_banner 3 "hop evidence (lab/dx1/verify.sh) — the demo's closing transcript"
bash "$LAB_DIR/dx1/verify.sh" 2>&1 | tee /tmp/trishula-demo-stage3.log
pass_marker 3 "NGF → engine → echo pod hop-by-hop evidenced"

banner "DEMO-OK — lab/demo.sh complete: setup + M9 apply→effect + hop evidence all PASS (lab left running, no teardown)"
