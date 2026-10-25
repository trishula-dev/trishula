#!/usr/bin/env bash
# TR-198 (issue #240) — the DX1 auth lane: the S3 vocabulary example runs
# end to end through the lab (the record's example set: the verified gate
# over /orders/*, the membership read "read:orders" in request.auth.scopes,
# the HS256 verifier bundle the pack carries).
#
# Scenario (the design record's claims sources, both halves on one route):
#   - no bearer token            -> verified=false gates the allow path (403,
#                                   X-Trishula-Decision: block, rule id named)
#   - a verified identity with   -> the membership read denies (403, same
#     scope "read:chat"             gate)
#   - a verified identity with   -> admitted (200, defaultAction pass; the
#     scope "read:orders"          allow path opens behind the gate)
#
# Mechanics follow lab/dx1/apply-effect.sh: the setup is idempotent; the
# lane rebuilds the engine + operator images from THIS checkout, applies
# the auth rule-set + policy, feeds the compiled bundle to the running
# engine (-receive-bundle), and probes through NGF. The lane REPLACES the
# consult bundle: afterwards re-running `just apply-effect` restores the
# SQLi gate shape. The lane leaves the lab running (no teardown).
#
# The lanes' prereq layers = just then docker-or-kubernetes (the justfile's
# header); lab/dx1/setup.sh owns the cluster + NGF setup and stays the
# prereq's owner.

set -euo pipefail

DX1_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${DX1_DIR}/../.." && pwd)"

NGF_NS="${NGF_NS:-nginx-gateway}"
ENGINE_NS="${ENGINE_NS:-dx1}"
HOST_HDR="${HOST_HDR:-dx1-routed.dx1.example.com}"
OUT_IMG="${OUT_IMG:-trishula-engine:dx1}"
OPERATOR_IMG="${OPERATOR_IMG:-trishula-operator:dx1}"
ENGINE_BIN="${ENGINE_BIN:-/tmp/tr198-engine-linux}"
OPERATOR_BIN="${OPERATOR_BIN:-/tmp/tr198-operator-linux}"
LOCALARCH="$(go env GOARCH 2>/dev/null || echo arm64)"
NODE_HTTP_PORT="${NODE_HTTP_PORT:-31437}"
HS_KEY_HEX="3c6fa2e5b19d4c718fa2d5e9b0c874a1"   # the dx1-auth pack's fixture key

log() { printf '\n== %s\n' "$*"; }
fail_with() {
  echo "FAIL: $*" >&2
  kubectl -n "${ENGINE_NS}" logs deploy/dx1-operator --tail=20 2>/dev/null || true
  kubectl -n "${ENGINE_NS}" logs deploy/dx1-engine --tail=30 2>/dev/null || true
  exit 1
}

command -v go      >/dev/null 2>&1 || { echo "missing dependency: go" >&2; exit 2; }
command -v kubectl >/dev/null 2>&1 || { echo "missing dependency: kubectl" >&2; exit 2; }
command -v curl    >/dev/null 2>&1 || { echo "missing dependency: curl" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "missing dependency: python3 (the token fixture builder)" >&2; exit 2; }
kubectl get nodes >/dev/null 2>&1 || { echo "no cluster reachable (run lab/dx1/setup.sh)"; exit 2; }

# --- token fixtures (python3 stdlib; the engine never issues tokens) --------
mk_jwt() { # mk_jwt <payload-json> -> the compact HS256 token (stdout)
  python3 - "$HS_KEY_HEX" "$1" <<'PY'
import sys, hmac, hashlib, base64
key = bytes.fromhex(sys.argv[1])
head = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b'=')
payload = base64.urlsafe_b64encode(sys.argv[2].encode()).rstrip(b'=')
signing = head.decode() + '.' + payload.decode()
sig = base64.urlsafe_b64encode(hmac.new(key, signing.encode(), hashlib.sha256).digest()).rstrip(b'=')
print(signing + '.' + sig.decode())
PY
}

# --- (a) lab up (idempotent) ------------------------------------------------
log "(a) lab up (lab/dx1/setup.sh, idempotent)"
"${DX1_DIR}/setup.sh" >/tmp/dx1-setup-tr198.log 2>&1 || {
  echo "setup.sh failed; last lines:" >&2; tail -20 /tmp/dx1-setup-tr198.log >&2; exit 3;
}
kubectl rollout status --timeout=3m -n "${ENGINE_NS}" deployment/dx1-engine >/dev/null

# --- (b) rebuild the engine + the operator with THIS checkout ---------------
log "(b) TR-198 engine + operator images (linux/${LOCALARCH} from this checkout)"
CGO_ENABLED=0 GOOS=linux GOARCH="${LOCALARCH}" go build -o "${ENGINE_BIN}" ./cmd/engine
CGO_ENABLED=0 GOOS=linux GOARCH="${LOCALARCH}" go build -o "${OPERATOR_BIN}" ./cmd/operator

cat > "${DX1_DIR}/Dockerfile.engine" <<'YAML'
FROM scratch
COPY engine /engine
EXPOSE 8080
ENTRYPOINT ["/engine"]
YAML
cat > "${DX1_DIR}/Dockerfile.operator" <<'YAML'
FROM scratch
COPY operator /operator
EXPOSE 1936
ENTRYPOINT ["/operator"]
YAML
cp "${ENGINE_BIN}" "${DX1_DIR}/engine"
docker build -q -f "${DX1_DIR}/Dockerfile.engine" -t "${OUT_IMG}" "${DX1_DIR}" >/dev/null
rm -f "${DX1_DIR}/engine"
cp "${OPERATOR_BIN}" "${DX1_DIR}/operator"
docker build -q -f "${DX1_DIR}/Dockerfile.operator" -t "${OPERATOR_IMG}" "${DX1_DIR}" >/dev/null
rm -f "${DX1_DIR}/operator"
if kind get clusters 2>/dev/null | grep -q .; then
  kind load docker-image "${OUT_IMG}" --name "$(kind get clusters | head -1)" >/dev/null
  kind load docker-image "${OPERATOR_IMG}" --name "$(kind get clusters | head -1)" >/dev/null
else
  echo "provider kubernetes (OrbStack): both images visible to the node via the shared docker daemon"
fi

kubectl rollout restart deployment/dx1-engine -n "${ENGINE_NS}"
kubectl rollout restart deployment/dx1-operator -n "${ENGINE_NS}"
kubectl rollout status --timeout=3m -n "${ENGINE_NS}" deployment/dx1-engine >/dev/null
kubectl rollout status --timeout=3m -n "${ENGINE_NS}" deployment/dx1-operator >/dev/null

# --- (c) the claims gate: rule set + policy, compile, pickup ----------------
log "(c) apply the auth rule set + the policy (the compiled bundle feeds the running engine)"
kubectl apply -f "${REPO_DIR}/deployment/dx1/manifests/dx1-rulepack-auth.yaml" >/dev/null
kubectl -n "${ENGINE_NS}" delete wafpolicy orders-read-gate --ignore-not-found >/dev/null 2>&1 || true
kubectl -n "${ENGINE_NS}" delete configmap dx1-wafpolicy-bundle --ignore-not-found >/dev/null
kubectl apply -f "${REPO_DIR}/deployment/dx1/manifests/dx1-wafpolicy-auth.yaml" >/dev/null

FOUND=""
for _ in $(seq 1 100); do
  if kubectl -n "${ENGINE_NS}" get configmap dx1-wafpolicy-bundle >/dev/null 2>&1; then FOUND=1; break; fi
  sleep 0.1
done
[ -n "${FOUND}" ] || fail_with "the operator did not publish the bundle configmap in 10s (compile failed?)"
kubectl -n "${ENGINE_NS}" get configmap dx1-wafpolicy-bundle -o jsonpath='{.data.bundle\.json}' > /tmp/tr198-bundle.json
[ -s /tmp/tr198-bundle.json ] || fail_with "the published bundle is empty"
python3 -c '
import json,sys
b=json.load(open("/tmp/tr198-bundle.json"))
assert any(r.get("id")=="auth:scope_insufficient" for p in b["rulePacks"] for r in p["rules"]), "the bundle lost the vocabulary rule"
assert any(p.get("verifier") for p in b["rulePacks"]), "the bundle lost the verifier bundle"
print("bundle shape ok: the vocabulary rule + the verifier bundle ride it")
'
kubectl -n "${ENGINE_NS}" exec deploy/dx1-engine -c engine -i -- /engine -receive-bundle /bundle.json < /tmp/tr198-bundle.json >/tmp/tr198-receive.log 2>&1 \
  || fail_with "engine -receive-bundle delivery failed: $(tail -2 /tmp/tr198-receive.log)"
CONSULT=""
for _ in $(seq 1 100); do
  kubectl -n "${ENGINE_NS}" logs deploy/dx1-engine --tail=30 2>/dev/null | grep -q "consult active" && { CONSULT=1; break; }
  sleep 0.1
done
[ -n "${CONSULT}" ] || fail_with "the engine never activated the consult (no 'consult active' log)"
log "(c) operator compiled the claims gate + the engine consult is active"

# --- (d) the vocabulary example's three cases through NGF -------------------
NODE_IP="$(kubectl get nodes -o go-template --template '{{range .items}}{{range .status.addresses}}{{if eq .type "InternalIP"}}{{.address}} {{end}}{{end}}{{end}}' | awk '{print $1}')"
SCOPED="$(mk_jwt '{"sub":"u1","iss":"https://issuer.example","aud":"api","scope":"read:orders","exp":1900000000}')"
UNSCOPED="$(mk_jwt '{"sub":"u2","iss":"https://issuer.example","aud":"api","scope":"read:chat","exp":1900000000}')"
PROBE="http://${NODE_IP}:${NODE_HTTP_PORT}/orders/7"

probe_status() {  # probe_status [bearer-token]
  if [ -n "${1:-}" ]; then
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Authorization: Bearer ${1}" -H "Host: ${HOST_HDR}" "${PROBE}"
  else
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: ${HOST_HDR}" "${PROBE}"
  fi
}
probe_proof() {  # probe_proof [bearer-token] -> the decision + rule headers, one line
  if [ -n "${1:-}" ]; then
    curl -s -i --max-time 10 -H "Authorization: Bearer ${1}" -H "Host: ${HOST_HDR}" "${PROBE}" |
      grep -E -i '^x-trishula-(decision|rule):' | paste -sd ';' -
  else
    curl -s -i --max-time 10 -H "Host: ${HOST_HDR}" "${PROBE}" |
      grep -E -i '^x-trishula-(decision|rule):' | paste -sd ';' -
  fi
}

log "(d) the record's example set over the wire"
rc=0
S1="$(probe_status "")"; P1="$(probe_proof "")"
if [ "${S1}" = "403" ]; then
  echo "PASS  no-bearer -> 403 (verified=false gates the allow path)   receipts: ${P1}"
else
  echo "FAIL  no-bearer -> ${S1}, want 403"; rc=1
fi
S2="$(probe_status "${UNSCOPED}")"; P2="$(probe_proof "${UNSCOPED}")"
if [ "${S2}" = "403" ]; then
  echo "PASS  unscoped-bearer -> 403 (the membership read denies)      receipts: ${P2}"
else
  echo "FAIL  unscoped-bearer -> ${S2}, want 403"; rc=1
fi
S3="$(probe_status "${SCOPED}")"
if [ "${S3}" = "200" ]; then
  echo "PASS  scoped-bearer -> 200 (verified identity + read:orders admits)"
else
  echo "FAIL  scoped-bearer -> ${S3}, want 200"; rc=1
fi

log "TR-198 auth lane complete — lab left running"
exit ${rc}
