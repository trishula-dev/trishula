#!/usr/bin/env bash
# TR-06 (issue #6, PRD v4 §10.3) — DX1 lab setup.
#
# Provisions, idempotently, on the local Docker provider (kind or
# OrbStack-provided Kubernetes):
#   1. a kind cluster (skipped when a cluster is already reachable;
#      OrbStack-provided Kubernetes is used as the provider when present)
#   2. the engine image, built from cmd/engine (TR-06a) and loaded into the
#      node's image store
#   3. the Gateway API CRDs NGF requires
#   4. NGF (NGINX Gateway Fabric) via helm, service.type=NodePort
#   5. the lab workloads: engine + demo echo pod + Gateway/HTTPRoute
#
# Chart source verified live (helm search repo / docs.nginx.com
# nginx-gateway-fabric): the current chart ships from the NGINX OCI
# registry, NOT the legacy helm.nginx.org index (which carries no
# gateway-fabric chart):
#
#   helm install ngf oci://ghcr.io/nginx/charts/nginx-gateway-fabric \
#     --create-namespace -n nginx-gateway \
#     --set service.type=NodePort
#
# The chart ships NO Gateway API CRDs (the v2.7.2 chart carries no
# CustomResourceDefinition); the CRDs come from the pinned upstream sources
# applied below (the same Gateway API v1.5.1 set NGF v2.7.2's own
# install refs pin, applied file-by-file as pure kubectl).
#
# Container images are pulled anonymously from ghcr.io / registry.k8s.io via
# crane with an isolated DOCKER_CONFIG and loaded into the node's image
# store (keychain-flaky hosts — e.g. headless macOS sessions hitting
# "Keychain Error -25320" in docker/helm/oras credential lookups — stay on
# the anonymous path; the docker CLI never contacts a registry here).

set -euo pipefail

DX1_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NGF_CHART_VERSION="${NGF_CHART_VERSION:-2.7.2}"
NGF_RELEASE="${NGF_RELEASE:-dx1}"
NGF_NS="${NGF_NS:-nginx-gateway}"
GATEWAY_NAME="${GATEWAY_NAME:-edge-gateway}"
NODE_HTTP_PORT="${NODE_HTTP_PORT:-31437}"
NGF_INSTALLED_NEW="0"   # 1 once this run helm-installs NGF (the rollout-status gates)
MANIFESTS_DIR="${DX1_DIR}/manifests"
OUT_IMG="${OUT_IMG:-trishula-engine:dx1}"   # local tag for the engine image
BIN="${BIN:-/tmp/engine-linux-arm64}"       # linux/$LOCALARCH build of cmd/engine (TR-06a)
LOCALARCH="$(go env GOARCH 2>/dev/null || echo arm64)"

log() { printf '\n== %s\n' "$*"; }

# crane_anon: anonymous registry reads with an isolated, empty DOCKER_CONFIG
# so the docker credential helper (osxkeychain) is never consulted.
crane_anon() {
  local dc
  dc="$(mktemp -d)"
  printf '{}\n' > "${dc}/config.json"
  DOCKER_CONFIG="${dc}" crane "$@"
  rm -rf "${dc}"
}

# docker_pull: crane pull to a tarball + docker load; the docker CLI itself
# never talks to a registry (anonymous pulls are done by crane).
docker_pull() {
  local img="$1" tarball
  tarball="$(mktemp -t dx1img.XXXXXX).tar"
  log "pulling ${img} (crane anonymous -> docker load)"
  crane_anon pull --platform all "${img}" "${tarball}"
  docker load -i "${tarball}" >/dev/null
  rm -f "${tarball}"
}

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing dependency: $1 (see lab/dx1/README.md)" >&2
    exit 2
  }
}

require docker
require crane
require helm
require kubectl
require go

# --- kind vs provider kubernetes (OrbStack) ---------------------------------
provider_kind() {
  command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -q .
}
load_into_node() {
  if provider_kind; then
    kind load docker-image "$1" --name "$(kind get clusters | head -1)" >/dev/null
  else
    echo "provider kubernetes (OrbStack): $1 visible to the node via the shared docker daemon"
  fi
}

# --- 1. cluster: skipped when one is already reachable (idempotent) ---------
log "cluster (idempotent — skipped if reachable)"
if kubectl get nodes >/dev/null 2>&1; then
  echo "cluster already exists (context: $(kubectl config current-context)) — kind create cluster skipped"
else
  echo "no cluster reachable; creating a kind cluster"
  command -v kind >/dev/null 2>&1 || {
    echo "install kind (brew install kind or go install sigs.k8s.io/kind)" >&2
    exit 2
  }
  # Pre-stage the pinned node image so cluster creation never needs a
  # registry (keychain-flaky hosts pull anonymously via crane).
  KINDEST_NODE_REF="kindest/node:v1.35.8"
  KINDEST_NODE_DIGEST="07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"
  if ! docker image inspect "${KINDEST_NODE_REF}" >/dev/null 2>&1; then
    docker_pull "${KINDEST_NODE_REF}"
  fi
  cat > "${DX1_DIR}/kind-config.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 31437
    hostPort: 31437
    protocol: tcp
YAML
  kind create cluster \
    --image "${KINDEST_NODE_REF}@sha256:${KINDEST_NODE_DIGEST}" \
    --config "${DX1_DIR}/kind-config.yaml"
fi

# --- 2. engine image: build from cmd/engine (TR-06a), load into the node ----
log "engine image (build ${OUT_IMG} from cmd/engine, load into the node's image store)"
test -f "${BIN}" || {
  echo "engine binary not found at ${BIN}; build it from the repo first:" >&2
  echo "  git checkout feat/tr06-engine-proxy && \\" >&2
  echo "  CGO_ENABLED=0 GOOS=linux GOARCH=${LOCALARCH} go build -o ${BIN} ./cmd/engine" >&2
  exit 2
}
cat > "${DX1_DIR}/Dockerfile.engine" <<'YAML'
# TR-06 DX1 lab — engine image from the cmd/engine proxy leaf (TR-06a),
# reproducible from the repo alone: Go build of cmd/engine into a scratch
# image (GOARCH must match the node; a ko build is the registry-direct
# alternative).
FROM scratch
COPY engine /engine
EXPOSE 8080
ENTRYPOINT ["/engine"]
YAML
cp "${BIN}" "${DX1_DIR}/engine"
docker build -q -f "${DX1_DIR}/Dockerfile.engine" -t "${OUT_IMG}" "${DX1_DIR}" >/dev/null
rm -f "${DX1_DIR}/engine"
load_into_node "${OUT_IMG}"

# --- 3. Gateway API CRDs (pinned upstream; the chart ships none) ------------
log "Gateway API CRDs (Gateway API v1.5.1 standard channel, the set NGF v${NGF_CHART_VERSION} installs)"
if ! kubectl get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
  for f in \
    gateway.networking.k8s.io_gatewayclasses.yaml \
    gateway.networking.k8s.io_gateways.yaml \
    gateway.networking.k8s.io_httproutes.yaml \
    gateway.networking.k8s.io_referencegrants.yaml; do
    kubectl apply -f \
      "https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.5.1/config/crd/standard/${f}"
  done
else
  echo "Gateway API CRDs already present"
fi

# --- 4. NGF (NGINX Gateway Fabric) via helm ---------------------------------
log "NGF release ${NGF_RELEASE} (helm, service.type=NodePort)"

# helm_sets: the shared helm values for the 2.x chart (NodePort + provisioned
# Gateway listener).
helm_sets() {
  printf '%s\n' \
    --set "service.type=NodePort" \
    --set "gateways[0].name=${GATEWAY_NAME}" \
    --set "gateways[0].spec.listeners[0].name=http" \
    --set "gateways[0].spec.listeners[0].port=80" \
    --set "gateways[0].spec.listeners[0].protocol=HTTP" \
    --set "gateways[0].spec.listeners[0].hostname=*.dx1.example.com" \
    --set 'nginx.service.type=NodePort' \
    --set-json "nginx.service.nodePorts=[{\"port\":${NODE_HTTP_PORT},\"listenerPort\":80}]"
}

# fetch_chart_dir <image-ref> <dest> — official chart package via anonymous
# crane (keychain-flaky environments); installs from the chart directory.
fetch_chart_dir() {
  local img="$1" dest="$2" work layer f
  work="$(mktemp -d)"
  crane_anon pull "${img}" "${work}/chart.tar"
  tar -xf "${work}/chart.tar" -C "${work}"
  layer=""
  for f in "${work}"/*.tar.gz "${work}"/*.tgz; do
    [ -f "${f}" ] || continue
    if tar -tzf "${f}" 2>/dev/null | grep -q 'nginx-gateway-fabric/Chart.yaml'; then
      layer="${f}"
      break
    fi
  done
  test -n "${layer}" && test -s "${layer}" || return 1
  mkdir -p "${dest}"
  tar -xzf "${layer}" -C "${dest}"
  rm -rf "${work}"
}

if ! helm status "${NGF_RELEASE}" -n "${NGF_NS}" >/dev/null 2>&1; then
  NGF_INSTALLED_NEW="1"
  readarray -t HELM_SETS < <(helm_sets)
  if ! helm install "${NGF_RELEASE}" "oci://ghcr.io/nginx/charts/nginx-gateway-fabric" \
        --version "${NGF_CHART_VERSION}" -n "${NGF_NS}" --create-namespace \
        --wait --timeout 5m "${HELM_SETS[@]}" 2>/tmp/dx1-helm-err.log; then
    cat /tmp/dx1-helm-err.log >&2
    echo "helm install oci failed; retrying with the official chart package" >&2
    CHART_DIR="$(mktemp -d)/chart"
    fetch_chart_dir "ghcr.io/nginx/charts/nginx-gateway-fabric:${NGF_CHART_VERSION}" "${CHART_DIR}" || {
      echo "chart package unavailable; install with: helm install ${NGF_RELEASE} oci://ghcr.io/nginx/charts/nginx-gateway-fabric --version ${NGF_CHART_VERSION} ..." >&2
      exit 3
    }
    if ! helm install "${NGF_RELEASE}" "${CHART_DIR}/nginx-gateway-fabric" \
          -n "${NGF_NS}" --create-namespace --wait --timeout 5m "${HELM_SETS[@]}"; then
      # NGF 2.x dataplane registration is agent-based: the control plane waits
      # for the dataplane agent to report an nginx INSTANCE built from
      # /proc/<pid>/cmdline. On k8s-under-OrbStack the setproctitle rewrite
      # never lands in /proc for containerd pods, the agent reports zero
      # instances and every dataplane pod stays 0/1 ("timed out waiting for
      # agent to register nginx"). Verified 2026-10-10 (2.7.2 + 2.6.8, kind
      # v1.35.8 + OrbStack k8s v1.35.6). OrbStack-only labs: fall back to the
      # 1.x single-pod architecture (control + data plane in one pod, no
      # agent handshake) — the lab's steering evidence is identical.
      echo "NGF ${NGF_CHART_VERSION} dataplane did not become ready; retrying with the 1.x single-pod architecture (NGF_FALLBACK_CHART)" >&2
      helm uninstall "${NGF_RELEASE}" -n "${NGF_NS}" --wait --timeout 3m 2>/dev/null || true
      FALLBACK_CHART_VERSION="${NGF_FALLBACK_CHART_VERSION:-1.6.2}"
      FALLBACK_IMAGE="ghcr.io/nginx/nginx-gateway-fabric:${FALLBACK_CHART_VERSION}"
      if ! docker image inspect "${FALLBACK_IMAGE}" >/dev/null 2>&1; then
        docker_pull "${FALLBACK_IMAGE}"
      fi
      load_into_node "${FALLBACK_IMAGE}"
      CHART_DIR="$(mktemp -d)/chart"
      fetch_chart_dir "ghcr.io/nginx/charts/nginx-gateway-fabric:${FALLBACK_CHART_VERSION}" "${CHART_DIR}"
      test -d "${CHART_DIR}/nginx-gateway-fabric" || {
        # direct extraction fallback: crane pull -> untar OCI layer
        FALLWORK="$(mktemp -d)"
        crane_anon pull "ghcr.io/nginx/charts/nginx-gateway-fabric:${FALLBACK_CHART_VERSION}" "${FALLWORK}/chart.tar"
        tar -xf "${FALLWORK}/chart.tar" -C "${FALLWORK}"
        FALL_LAYER="$(for f in "${FALLWORK}"/*.tar.gz; do tar -tzf "${f}" 2>/dev/null | grep -q 'Chart.yaml' && echo "${f}" && break; done)"
        mkdir -p "${CHART_DIR}" && tar -xzf "${FALL_LAYER}" -C "${CHART_DIR}"
      }
      FALLBACK_SETS=(
        --set 'service.type=NodePort'
        --set 'nginxGateway.replicaCount=1'
      )
      kubectl delete crd -l 'app.kubernetes.io/instance=nginx-gateway-fabric' --ignore-not-found 2>/dev/null || true
      for c in $(kubectl get crd -o name 2>/dev/null | grep 'gateway.nginx.org'); do
        kubectl delete "${c}" --ignore-not-found
      done
      helm install "${NGF_RELEASE}" "${CHART_DIR}/nginx-gateway-fabric" \
        -n "${NGF_NS}" --create-namespace --wait --timeout 6m "${FALLBACK_SETS[@]}"
      # Pin the NodePort (the 1.x chart assigns a random one).
      kubectl -n "${NGF_NS}" patch svc "${NGF_RELEASE}-nginx-gateway-fabric" \
        --type=merge -p "{\"spec\":{\"ports\":[{\"name\":\"http\",\"port\":80,\"nodePort\":${NODE_HTTP_PORT}}]}}"
      NGF_CHART_VERSION="${FALLBACK_CHART_VERSION}"
    fi
  fi
else
  echo "helm release ${NGF_RELEASE} already installed (lab pins ${NGF_CHART_VERSION})"
fi

# --- 5. NGF images pulled anonymously, loaded into the node -----------------
log "NGF images pulled anonymously and loaded (control plane + nginx data plane)"
if ! docker image inspect "ghcr.io/nginx/nginx-gateway-fabric:${NGF_CHART_VERSION}" >/dev/null 2>&1; then
  docker_pull "ghcr.io/nginx/nginx-gateway-fabric:${NGF_CHART_VERSION}"
fi
if ! docker image inspect "ghcr.io/nginx/nginx-gateway-fabric/nginx:${NGF_CHART_VERSION}" >/dev/null 2>&1; then
  docker_pull "ghcr.io/nginx/nginx-gateway-fabric/nginx:${NGF_CHART_VERSION}"
fi
load_into_node "ghcr.io/nginx/nginx-gateway-fabric:${NGF_CHART_VERSION}"
load_into_node "ghcr.io/nginx/nginx-gateway-fabric/nginx:${NGF_CHART_VERSION}"
if ! docker image inspect "ghcr.io/mendhak/http-https-echo:42" >/dev/null 2>&1; then
  docker_pull "ghcr.io/mendhak/http-https-echo:42"
fi
load_into_node "ghcr.io/mendhak/http-https-echo:42"

if [ "${NGF_INSTALLED_NEW}" = "1" ]; then
  kubectl rollout status --timeout=5m -n "${NGF_NS}" "deployment/${NGF_RELEASE}-nginx-gateway-fabric"
  kubectl rollout status --timeout=5m -n "${NGF_NS}" "deployment/${NGF_RELEASE}-nginx"
fi

# --- 6. lab manifests: engine + echo + Gateway/HTTPRoute --------------------
log "applying lab manifests (${MANIFESTS_DIR})"
kubectl apply -f "${MANIFESTS_DIR}/dx1-namespace.yaml"
kubectl apply -f "${MANIFESTS_DIR}/dx1-backend.yaml"
kubectl apply -f "${MANIFESTS_DIR}/dx1-engine.yaml"
kubectl apply -f "${MANIFESTS_DIR}/dx1-gateway.yaml"
kubectl apply -f "${MANIFESTS_DIR}/dx1-httproute.yaml"

kubectl rollout status --timeout=3m -n dx1 deployment/dx1-engine
kubectl rollout status --timeout=3m -n dx1 deployment/dx1-echo

log "DX1 lab setup complete"
kubectl -n "${NGF_NS}" get gateway,svc 2>/dev/null || true
kubectl -n dx1 get all 2>/dev/null || true
