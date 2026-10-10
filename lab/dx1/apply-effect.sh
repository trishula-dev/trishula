#!/usr/bin/env bash
# TR-08c (issue #76, M9) — DX1 lab apply→effect timed scenario.
#
# The cluster round trip (PRD §8, §10.3; TR-08 acceptance M9): kubectl apply
# of a WAFPolicy CR → the operator pod compiles it (internal/operator.
# Reconcile: rule-pack resolution + compile, fail closed) → the engine pod
# picks the bundle up (the operator publishes bundle.json to a configmap,
# the script feeds it to the running engine's polled path via kubectl exec,
# the engine hot-reloads) → the effect is visible on traffic through NGF:
#
#   t0 = kubectl apply -f dx1-wafpolicy.yaml
#   t1 = the first request through NGF blocked by the policy (403,
#        X-Trishula-Decision: block, the rule id named) while a benign
#        request still passes (defaultAction: pass + forward)
#   print apply→effect duration; FAIL when it exceeds M9_TARGET (5s).
#
# Failure path (fail closed, timed): after deleting the good policy, apply
# dx1-wafpolicy-broken.yaml (an uncompilable CEL rule) → the operator logs
# COMPILE FAILED, publishes NO bundle, the engine keeps the previously
# loaded bundle (the request surface is UNCHANGED: the SQLi probe stays
# blocked, the benign request still passes), and the operator process stays
# alive (no crash). The broken policy is deleted afterwards.
#
# Idempotent: reuses the setup.sh lab (cluster + NGF + engine + echo) and
# (re-)applies the operator deployment; leaves everything running.

set -euo pipefail

DX1_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${DX1_DIR}/../.." && pwd)"

NGF_NS="${NGF_NS:-nginx-gateway}"
ENGINE_NS="${ENGINE_NS:-dx1}"
HOST_HDR="${HOST_HDR:-dx1-routed.dx1.example.com}"
M9_TARGET="${M9_TARGET:-5}"           # seconds, the M9 budget
OUT_IMG="${OUT_IMG:-trishula-engine:dx1}"
OPERATOR_IMG="${OPERATOR_IMG:-trishula-operator:dx1}"
ENGINE_BIN="${ENGINE_BIN:-/tmp/tr08c-engine-linux}"
OPERATOR_BIN="${OPERATOR_BIN:-/tmp/tr08c-operator-linux}"
LOCALARCH="$(go env GOARCH 2>/dev/null || echo arm64)"
NODE_HTTP_PORT="${NODE_HTTP_PORT:-31437}"

log() { printf '\n== %s\n' "$*"; }

# fail_with keeps the operator/engine logs on a failed assert before exit.
fail_with() {
  echo "FAIL: $*" >&2
  kubectl -n "${ENGINE_NS}" logs deploy/dx1-operator --tail=20 2>/dev/null || true
  kubectl -n "${ENGINE_NS}" logs deploy/dx1-engine --tail=20 2>/dev/null || true
  exit 1
}

command -v go      >/dev/null 2>&1 || { echo "missing dependency: go" >&2; exit 2; }
command -v kubectl >/dev/null 2>&1 || { echo "missing dependency: kubectl" >&2; exit 2; }
command -v curl    >/dev/null 2>&1 || { echo "missing dependency: curl" >&2; exit 2; }
kubectl get nodes >/dev/null 2>&1 || { echo "no cluster reachable (run lab/dx1/setup.sh)" >&2; exit 2; }

# --- (a) ensure the lab is up (setup.sh idempotency) ------------------------
log "(a) lab up (lab/dx1/setup.sh, idempotent)"
"${DX1_DIR}/setup.sh" >/tmp/dx1-setup-tr08c.log 2>&1 || {
  echo "setup.sh failed; last lines:" >&2; tail -20 /tmp/dx1-setup-tr08c.log >&2; exit 3;
}
kubectl rollout status --timeout=3m -n "${ENGINE_NS}" deployment/dx1-engine >/dev/null

# --- the operator + the WAFPolicy CRD ---------------------------------------
log "(pre) CRD + operator image + operator deployment"
kubectl apply -f "${REPO_DIR}/manifests/crd/wafpolicy-crd.yaml" >/dev/null
test -f "${OPERATOR_BIN}" || {
  echo "operator binary not found at ${OPERATOR_BIN}; build it first:" >&2
  echo "  CGO_ENABLED=0 GOOS=linux GOARCH=${LOCALARCH} go build -o ${OPERATOR_BIN} ./cmd/operator" >&2
  exit 2
}
cat > "${DX1_DIR}/Dockerfile.operator" <<'YAML'
# TR-08c DX1 lab — operator image from the cmd/operator watch-loop leaf,
# reproducible from the repo alone (scratch + the Go binary; the ko build
# is the registry-direct alternative).
FROM scratch
COPY operator /operator
EXPOSE 1936
ENTRYPOINT ["/operator"]
YAML
cp "${OPERATOR_BIN}" "${DX1_DIR}/operator"
docker build -q -f "${DX1_DIR}/Dockerfile.operator" -t "${OPERATOR_IMG}" "${DX1_DIR}" >/dev/null
rm -f "${DX1_DIR}/operator"
if kind get clusters 2>/dev/null | grep -q .; then
  kind load docker-image "${OPERATOR_IMG}" --name "$(kind get clusters | head -1)" >/dev/null
else
  echo "provider kubernetes (OrbStack): ${OPERATOR_IMG} visible to the node via the shared docker daemon"
fi
kubectl apply -f "${DX1_DIR}/manifests/dx1-operator-rbac.yaml" >/dev/null
kubectl apply -f "${DX1_DIR}/manifests/dx1-operator-svc.yaml" >/dev/null
kubectl apply -f "${DX1_DIR}/manifests/dx1-operator.yaml" >/dev/null
kubectl rollout status --timeout=3m -n "${ENGINE_NS}" deployment/dx1-operator >/dev/null

# The rule pack (the enforced DX-LAB-001) + ensure a clean policy slate.
kubectl apply -f "${DX1_DIR}/manifests/dx1-rulepack-sqli.yaml" >/dev/null
kubectl -n "${ENGINE_NS}" delete wafpolicy --all >/dev/null 2>&1 || true
kubectl -n "${ENGINE_NS}" delete configmap dx1-wafpolicy-bundle --ignore-not-found >/dev/null

# Engine probes (through NGF) before the policy: both shapes pass with no
# decision surface (the TR-06 transparent contract is the baseline).
NODE_IP="$(kubectl get nodes -o go-template --template '{{range .items}}{{range .status.addresses}}{{if eq .type "InternalIP"}}{{.address}} {{end}}{{end}}{{end}}' | awk '{print $1}')"
probe() { # probe - -> the benign probe's HTTP status
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${NODE_IP}:${NODE_HTTP_PORT}/v1/chat/completions?q=greeting" -H "Host: ${HOST_HDR}"
}
BASELINE="$(probe -)"
[ "${BASELINE}" = "200" ] || { echo "baseline probe failed (${BASELINE}); fix the lab before the timed scenario" >&2; exit 4; }
log "pre-policy baseline: the benign probe passes transparently (200)"

# --- (b) t0: kubectl apply the WAFPolicy CR ---------------------------------
log "(b) t0 — kubectl apply dx1-wafpolicy.yaml"
T0_NS="$(date +%s%N)"

# --- (c) wait for compile + pickup: the operator's bundle configmap, fed
#         to the engine, the consult ACTIVE in the engine logs --------------
BUNDLE_NS="${ENGINE_NS}"
FOUND=""
for _ in $(seq 1 100); do # 100 x 0.1s = 10s hard ceiling for the wait itself
  if kubectl -n "${BUNDLE_NS}" get configmap dx1-wafpolicy-bundle >/dev/null 2>&1; then FOUND=1; break; fi
  sleep 0.1
done
[ -n "${FOUND}" ] || fail_with "the operator did not publish the bundle configmap in 10s"
kubectl -n "${BUNDLE_NS}" get configmap dx1-wafpolicy-bundle -o jsonpath='{.data.bundle\.json}' > /tmp/tr08c-bundle.json
[ -s /tmp/tr08c-bundle.json ] || fail_with "the published bundle is empty"
# Engine pickup: feed the bundle into the running engine's polled path
# (kubectl exec, single process, no TTY discipline games).
kubectl -n "${ENGINE_NS}" exec deploy/dx1-engine -c engine -i -- /engine -receive-bundle /tmp/bundle.json < /tmp/tr08c-bundle.json >/tmp/tr08c-receive.log 2>&1 \
  || fail_with "engine -receive-bundle delivery failed: $(cat /tmp/tr08c-receive.log | tail -2)"
CONSULT=""
for _ in $(seq 1 100); do # wait for the hot reload (200ms poll)
  kubectl -n "${ENGINE_NS}" logs deploy/dx1-engine --tail=30 2>/dev/null | grep -q "consult active" && { CONSULT=1; break; }
  sleep 0.1
done
[ -n "${CONSULT}" ] || fail_with "the engine never activated the consult (no 'consult active' log)"
log "(c) operator compiled + engine consult active"

# --- (d) t1: the first request through NGF showing the effect ---------------
SQLI_MARK="UNION%20SELECT%2F%2A"
T1_NS=""
EFFECT_MS=""
for _ in $(seq 1 100); do
  ST="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${NODE_IP}:${NODE_HTTP_PORT}/v1/chat/completions?q=${SQLI_MARK}" -H "Host: ${HOST_HDR}")"
  if [ "${ST}" = "403" ]; then
    T1_NS="$(date +%s%N)"
    EFFECT_MS=$(( (T1_NS - T0_NS) / 1000000 ))
    break
  fi
  sleep 0.05
done
[ -n "${T1_NS}" ] || fail_with "no 403 on the SQLi probe within the effect window"

log "(d) effect: SQLi probe → 403"
# The evidence headers + the benign probe still passes (defaultAction pass).
EV="$(curl -s -i --max-time 10 "http://${NODE_IP}:${NODE_HTTP_PORT}/v1/chat/completions?q=${SQLI_MARK}" -H "Host: ${HOST_HDR}")"
printf '%s\n' "${EV}" | head -3
printf '%s' "${EV}" | grep -qi '^x-trishula-decision: block' || fail_with "X-Trishula-Decision: block absent"
printf '%s' "${EV}" | grep -qi '^x-trishula-rule: DX-LAB-001' || fail_with "X-Trishula-Rule: DX-LAB-001 absent"
BENIGN="$(probe -)"
[ "${BENIGN}" = "200" ] || fail_with "the benign request must still pass (defaultAction: pass), got ${BENIGN}"

# --- the M9 verdict ----------------------------------------------------------
DUR_S=$(( EFFECT_MS / 1000 ))
if [ "${DUR_S}" -gt "${M9_TARGET}" ]; then
  fail_with "apply→effect took ${EFFECT_MS}ms — M9 budget ${M9_TARGET}s exceeded"
fi
log "M9 apply→effect: ${EFFECT_MS}ms (target ≤ ${M9_TARGET}s) — PASS"

# --- failure path: uncompilable rule → logged, no effect, fail closed -------
log "failure path — apply dx1-wafpolicy-broken.yaml (uncompilable CEL rule)"
kubectl delete wafpolicy chat-completions-gate -n "${ENGINE_NS}" >/dev/null
BT0="$(date +%s%N)"
kubectl apply -f "${DX1_DIR}/manifests/dx1-wafpolicy-broken.yaml" >/dev/null
COMPILE_FAILED=""
for _ in $(seq 1 100); do
  kubectl -n "${ENGINE_NS}" logs deploy/dx1-operator --tail=20 2>/dev/null | grep -q "COMPILE FAILED dx1/broken-rule-gate" && { COMPILE_FAILED=1; break; }
  sleep 0.1
done
[ -n "${COMPILE_FAILED}" ] || fail_with "the operator never logged COMPILE FAILED for the broken policy"
log "operator logged the compile error"

# No effect: the previously loaded bundle still decides the traffic shape
# (the good policy was deleted, the broken one ships NOTHING).
ST_BENIGN="$(probe -)"
ST_SQLI="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${NODE_IP}:${NODE_HTTP_PORT}/v1/chat/completions?q=${SQLI_MARK}" -H "Host: ${HOST_HDR}")"
[ "${ST_BENIGN}" = "200" ] || fail_with "fail-closed broken: the benign request changed shape (${ST_BENIGN})"
[ "${ST_SQLI}" = "403" ] || fail_with "fail-closed broken: the SQLi probe changed shape (${ST_SQLI})"
# The engine (and operator) processes are still alive (no crash).
kubectl -n "${ENGINE_NS}" get pods -l app.kubernetes.io/name=trishula-operator -o jsonpath='{.items[0].status.containerStatuses[0].ready}' | grep -q true || fail_with "the operator pod is not Ready after the broken policy"
kubectl -n "${ENGINE_NS}" get pods -l app.kubernetes.io/name=trishula-engine -o jsonpath='{.items[0].status.containerStatuses[0].ready}' | grep -q true || fail_with "the engine pod is not Ready after the broken policy"
BT1="$(date +%s%N)"
log "fail-closed scenario: $(( (BT1 - BT0) / 1000000 ))ms from apply(broken) to the logged compile error; traffic unchanged; pods Ready"

kubectl delete wafpolicy broken-rule-gate -n "${ENGINE_NS}" >/dev/null
log "TR-08c apply→effect complete — lab left running (no teardown)"
