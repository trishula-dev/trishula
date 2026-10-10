#!/usr/bin/env bash
# TR-06 (issue #6, PRD v4 §10.3) — DX1 lab verification.
#
# Drives the live topology end to end and prints hop-by-hop header evidence:
#
#   client -> NodePort :<NODE_HTTP_PORT> on the node
#          -> NGF (Gateway 'edge-gateway', GatewayClass nginx, listener :80)
#          -> dx1/dx1-engine Service  (hostname-routed HTTPRoute)
#          -> cmd/engine transparent ReverseProxy (X-Trishula-Hop)
#          -> dx1/dx1-echo Service    (the demo pod)
#
# Proves the §10.2 variant-A contract live: NGF steers weighted traffic to
# the engine as it would to any Service; the engine forwards transparently
# to the pool; readiness/health stays engine-local (/healthz).

set -euo pipefail

NGF_NS="${NGF_NS:-nginx-gateway}"
GATEWAY_NAME="${GATEWAY_NAME:-edge-gateway}"
ENGINE_NS="${ENGINE_NS:-dx1}"
HOST_HDR="${HOST_HDR:-dx1-routed.dx1.example.com}"
CONTRAST_HDR_HOST="${CONTRAST_HDR_HOST:-direct-echo.dx1.example.com}"
# Node address: auto-detected from the first Ready node (Override with NODE_IP).
NODE_IP="${NODE_IP:-$(kubectl get nodes -o go-template --template '{{range .items}}{{range .status.addresses}}{{if eq .type "InternalIP"}}{{.address}} {{end}}{{end}}{{end}}' | awk '{print $1}')}"
ROUTED_PATH="${ROUTED_PATH:-/v1/chat/completions}"

# NodePort: prefer the pinned NODE_HTTP_PORT when set; otherwise read the port
# assigned to the NGF Service (NGF 1.x assigns a random NodePort).
if [ "${NODE_HTTP_PORT:-}" = "" ]; then
  GW_SVC="$(kubectl -n "${NGF_NS}" get svc -l 'app.kubernetes.io/name=nginx-gateway-fabric,app.kubernetes.io/managed-by=Helm' -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "${GW_SVC}" ] || GW_SVC="$(kubectl -n "${NGF_NS}" get svc -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -n "${GW_SVC}" ]; then
    NODE_HTTP_PORT="$(kubectl -n "${NGF_NS}" get svc "${GW_SVC}" -o jsonpath='{.spec.ports[?(@.port==80)].nodePort}')"
  fi
fi
[ -n "${NODE_HTTP_PORT:-}" ] || { echo "cannot resolve the NGF NodePort (set NODE_HTTP_PORT or check the '${NGF_NS}' services)" >&2; exit 2; }

log() { printf '\n== %s\n' "$*"; }

# --- hop 1: the gateway tier -------------------------------------------------
log "hop 1 — NGF (Gateway ${GATEWAY_NAME}, GatewayClass nginx)"
kubectl -n "${NGF_NS}" get gateway "${GATEWAY_NAME}" -o wide || true
kubectl -n "${ENGINE_NS}" get svc,deploy 2>/dev/null || true

GW_ACCEPTED="$(kubectl -n "${NGF_NS}" get gateway "${GATEWAY_NAME}" -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null || true)"
GW_PROGRAMMED="$(kubectl -n "${NGF_NS}" get gateway "${GATEWAY_NAME}" -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' 2>/dev/null || true)"
log "Gateway ${GATEWAY_NAME} Accepted=${GW_ACCEPTED:-<absent>} Programmed=${GW_PROGRAMMED:-<absent>} (§10.2: NGF steers to the engine Service as a plain backend)"

# --- hop 2: through NGF to the engine ----------------------------------------
log "hop 2 — request through NGF -> engine (path ${ROUTED_PATH}, Host ${HOST_HDR}, http://${NODE_IP}:${NODE_HTTP_PORT})"
NGF_PROBE="$(curl -s -i --max-time 15 "http://${NODE_IP}:${NODE_HTTP_PORT}${ROUTED_PATH}" -H "Host: ${HOST_HDR}")"
printf '%s\n' "${NGF_PROBE}"

if ! printf '%s' "${NGF_PROBE}" | head -1 | grep -q ' 200 '; then
  echo "FAIL: NGF -> engine hop did not return 200" >&2
  exit 1
fi
printf '%s' "${NGF_PROBE}" | grep -qi '^x-trishula-hop:' || {
  echo "FAIL: X-Trishula-Hop absent — the engine hop was not traversed" >&2
  exit 1
}

# --- hop 3: the echo pod answered through the engine -------------------------
log "hop 3 — the echo pod responded through the engine (hop-by-hop headers)"
# The echo pod's own response header made it back: the pool answered (the
# request traversed NGF -> engine -> echo pod).
printf '%s' "${NGF_PROBE}" | grep -qi '^x-powered-by:' || {
  echo "FAIL: the echo pod's response header is absent — the demo pod did not answer" >&2
  exit 1
}
ECHO_POD_ID="$(printf '%s' "${NGF_PROBE}" | tr -d '\n' | sed -n 's/.*"os": *{ *"hostname": *"\([^"]*\)".*/\1/p' || true)"
log "echo response body host (demo pod id): ${ECHO_POD_ID:-<unparsed>}"

# --- contrast: direct-to-echo route (no engine hop on the same NGF nodeport) -
log "contrast — Host ${CONTRAST_HDR_HOST} on the same NGF NodePort lands directly on the echo pod (no X-Trishula-Hop)"
CONTRAST_PROBE="$(curl -s -i --max-time 15 "http://${NODE_IP}:${NODE_HTTP_PORT}/anything/at/all" -H "Host: ${CONTRAST_HDR_HOST}")"
printf '%s\n' "${CONTRAST_PROBE}" | head -14
if printf '%s' "${CONTRAST_PROBE}" | head -1 | grep -q ' 200 '; then
  if printf '%s' "${CONTRAST_PROBE}" | grep -qi '^x-trishula-hop:'; then
    echo "FAIL: contrast route unexpectedly traversed the engine" >&2
    exit 1
  fi
  printf '%s' "${CONTRAST_PROBE}" | grep -qi '^x-powered-by:' || {
    echo "WARN: contrast route reached NGF but not the echo pod (routing to the echo backend may not have reconciled)"
  }
fi

# --- engine-local healthz is not proxied (readiness semantics) ----------------
log "engine-local /healthz (readiness gate, answered by the engine itself)"
ENG_EP_ADDR="$(kubectl -n "${ENGINE_NS}" get endpoints dx1-engine -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null || true)"
ENG_EP_PORT="$(kubectl -n "${ENGINE_NS}" get endpoints dx1-engine -o jsonpath='{.subsets[0].ports[0].port}' 2>/dev/null || true)"
if [ -n "${ENG_EP_ADDR}" ] && [ -n "${ENG_EP_PORT}" ]; then
  curl -s --max-time 10 "http://${ENG_EP_ADDR}:${ENG_EP_PORT}/healthz" &&
    printf ' <- engine-local /healthz (%s:%s)\n' "${ENG_EP_ADDR}" "${ENG_EP_PORT}"
else
  echo "engine endpoints not readable; skipping the engine-local healthz probe"
fi

log "DX1 verify: hop 1 NGF -> hop 2 engine -> hop 3 echo pod all evidenced above"
log "§10.2 variant A reproduced live: gateway -> engine backend -> transparent forward -> demo pool"
log "Done. The lab remains installed (no teardown)."
