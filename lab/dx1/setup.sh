#!/usr/bin/env bash
# TR-06 (issue #6, spec v4 section 10.3) — DX1 lab setup.
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

# the target gate (issue #261): the prereq = docker OR a reachable cluster.
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/prereq.sh"

DX1_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${DX1_DIR}/../.." && pwd)"

NGF_CHART_VERSION="${NGF_CHART_VERSION:-2.7.2}"
NGF_RELEASE="${NGF_RELEASE:-dx1}"
NGF_NS="${NGF_NS:-nginx-gateway}"
GATEWAY_NAME="${GATEWAY_NAME:-edge-gateway}"
NODE_HTTP_PORT="${NODE_HTTP_PORT:-31437}"
NODE_HTTPS_PORT="${NODE_HTTPS_PORT:-31438}"   # the TLS-leg NodePort (TR-203 L4)
DX1_TLS_LEG="${DX1_TLS_LEG:-1}"               # 0 = the pre-L4 shape (no https listener leg)
NGF_INSTALLED_NEW="0"   # 1 once this run helm-installs NGF (the rollout-status gates)
# The derived manifests: internal/cuegen generates them into the deployment
# tree from the CUE sources (cue/lab/dx1; TR-46, issue #192). Hand edits
# fail the golden-diff gate.
MANIFESTS_DIR="${REPO_DIR}/deployment/dx1/manifests"
OUT_IMG="${OUT_IMG:-trishula-engine:dx1}"   # local tag for the engine image
BIN="${BIN:-/tmp/engine-linux-arm64}"       # linux/$LOCALARCH build of cmd/engine (TR-06a)
LOCALARCH="$(go env GOARCH 2>/dev/null || echo arm64)"

log() { printf '\n== %s\n' "$*"; }

# crane_anon: anonymous registry reads with an isolated, empty DOCKER_CONFIG
# so the docker credential helper (osxkeychain) is never consulted. The
# crane exit code rides out (rm -rf alone would swallow it and every caller
# would read a failed pull as success — issue #198).
crane_anon() {
  local dc rc
  dc="$(mktemp -d)"
  printf '{}\n' > "${dc}/config.json"
  DOCKER_CONFIG="${dc}" crane "$@" || rc=$?
  rm -rf "${dc}"
  return "${rc:-0}"
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
    # Pick the kind cluster the current kubecontext points at; the legacy
    # head -1 read mis-loads on multi-cluster hosts (a second kind cluster
    # on the same host got the image instead of the lab's cluster).
    local cluster kind_cluster
    cluster="$(kubectl config current-context 2>/dev/null | sed -E 's/^kind-//')" || cluster=""
    if [ -n "$cluster" ] && kind get clusters 2>/dev/null | grep -qx "$cluster"; then
      kind_cluster="$cluster"
    else
      kind_cluster="$(kind get clusters 2>/dev/null | head -1)"
    fi
    kind load docker-image "$1" --name "${kind_cluster}" >/dev/null
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
  - containerPort: 31438
    hostPort: 31438
    protocol: tcp
  - containerPort: 31441
    hostPort: 31441
    protocol: tcp
  - containerPort: 31440
    hostPort: 31440
    protocol: udp
YAML
  kind create cluster \
    --image "${KINDEST_NODE_REF}@sha256:${KINDEST_NODE_DIGEST}" \
    --config "${DX1_DIR}/kind-config.yaml"
fi

# --- 2. engine image: build from cmd/engine (TR-06a), load into the node ----
log "engine image (build ${OUT_IMG} from cmd/engine, load into the node's image store)"
test -f "${BIN}" || {
  echo "engine binary not found at ${BIN}; build it from the repo checkout first:" >&2
  echo "  CGO_ENABLED=0 GOOS=linux GOARCH=${LOCALARCH} go build -o ${BIN} ./cmd/engine" >&2
  echo "  (run the build from the repo checkout; the DX1 gate, lab/dx1/dx1-gate.sh, builds both binaries when missing)" >&2
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
# GRPCRoute sits in the same standard-channel set: NGF 1.x watches it at v1
# and the control loop dies without the CRD (the informers never sync —
# nginx-gateway CrashLoopBackOff; run 40082782812). Per-CRD guard: the outer
# guard above skips everything once the four early CRDs exist.
if ! kubectl get crd grpcroutes.gateway.networking.k8s.io >/dev/null 2>&1; then
  kubectl apply -f \
    "https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.5.1/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml"
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
    --set 'nginx.service.type=NodePort'
  # The TLS leg (TR-203 L4): the https NodePort row joins the same list; the
  # https LISTENER itself comes from the committed dx1-gateway manifest.
  if [ "$DX1_TLS_LEG" = "1" ]; then
    printf '%s\n' --set-json "nginx.service.nodePorts=[{\"port\":${NODE_HTTP_PORT},\"listenerPort\":80},{\"port\":${NODE_HTTPS_PORT},\"listenerPort\":443}]"
  else
    printf '%s\n' --set-json "nginx.service.nodePorts=[{\"port\":${NODE_HTTP_PORT},\"listenerPort\":80}]"
  fi
}

# crane_manifest_evidence <image-ref> — one line of live store evidence: the
# artifact's config + layer mediaTypes. Optional jq; a failed read prints its
# own line (never a silent gap).
crane_manifest_evidence() {
  local ev
  ev="$(crane_anon manifest "$1" 2>/dev/null | jq -c '{config: .config.mediaType, layers: [.layers[] | {mediaType: .mediaType, size: .size}]}' 2>/dev/null)" &&
    [ -n "${ev}" ] &&
    echo "store evidence: ${ev}" >&2 ||
    echo "store evidence: manifest read failed (the tag may not publish)" >&2
}

# fetch_chart_dir <image-ref> <dest> — official chart package via anonymous
# crane (keychain-flaky environments); installs from the chart directory.
# crane export reads the artifact's layer contents directly (the chart
# tree): crane pull's legacy tarball names its blobs unpredictably across
# hosts, and the runner-side search for a chart-package blob at the
# extraction root found nothing where this host found the package
# (issue #198, run 40082586664 — the gap branch, with the store evidence
# line proving the layer publishes). A failure names its stage with
# evidence: the export error, an empty stream, or the live manifest when
# the artifact publishes no chart tree.
fetch_chart_dir() {
  local img="$1" dest="$2" flat
  flat="$(mktemp)"
  if ! crane_anon export "${img}" "${flat}"; then
    echo "chart package fetch failed at the crane export stage (its error prints above)" >&2
    crane_manifest_evidence "${img}"
    rm -f "${flat}"
    return 1
  fi
  if ! test -s "${flat}"; then
    echo "chart package gap: the export of ${img} produced an empty stream" >&2
    crane_manifest_evidence "${img}"
    rm -f "${flat}"
    return 1
  fi
  mkdir -p "${dest}"
  if ! tar -xf "${flat}" -C "${dest}"; then
    echo "chart package gap: the export stream of ${img} is not a chart tarball" >&2
    crane_manifest_evidence "${img}"
    rm -f "${flat}"
    return 1
  fi
  rm -f "${flat}"
  if ! test -f "${dest}/nginx-gateway-fabric/Chart.yaml"; then
    echo "chart package gap: the export of ${img} carries no nginx-gateway-fabric/Chart.yaml" >&2
    crane_manifest_evidence "${img}"
    return 1
  fi
  return 0
}

# install_ngf_1x <version> — the proven 1.x single-pod lane (control + data
# plane in one pod; no dataplane-agent handshake). It serves both callers:
# a direct NGF_CHART_VERSION=1.x pin (the CI gate; the 2.x set shape does
# not exist in the 1.x chart) and the 2.x fallback below. Both chart images
# pre-stage into the node before the helm wait — the pod runs two containers
# (nginx-gateway + nginx); a kubelet pull would ride the install budget
# (issue #198, run 40077270222).
install_ngf_1x() {
  local version="$1" chart_dir work layer f
  helm uninstall "${NGF_RELEASE}" -n "${NGF_NS}" --wait --timeout 3m 2>/dev/null || true
  for img in \
    "ghcr.io/nginx/nginx-gateway-fabric:${version}" \
    "ghcr.io/nginx/nginx-gateway-fabric/nginx:${version}"; do
    if ! docker image inspect "${img}" >/dev/null 2>&1; then
      docker_pull "${img}"
    fi
    load_into_node "${img}"
  done
  chart_dir="$(mktemp -d)/chart"
  fetch_chart_dir "ghcr.io/nginx/charts/nginx-gateway-fabric:${version}" "${chart_dir}" || true
  test -d "${chart_dir}/nginx-gateway-fabric" || {
    # direct extraction fallback: crane pull -> untar OCI layer (kept for
    # hosts where export misbehaves; a failed pull prints its evidence)
    work="$(mktemp -d)"
    crane_anon pull "ghcr.io/nginx/charts/nginx-gateway-fabric:${version}" "${work}/chart.tar" || {
      echo "the direct extraction fallback also failed (the crane error prints above)" >&2
      return 1
    }
    tar -xf "${work}/chart.tar" -C "${work}"
    layer="$(for f in "${work}"/*.tar.gz; do tar -tzf "${f}" 2>/dev/null | grep -q 'Chart.yaml' && echo "${f}" && break; done)"
    mkdir -p "${chart_dir}" && tar -xzf "${layer}" -C "${chart_dir}"
  }
  # Leftovers of a failed 2.x attempt go first (--ignore-not-found); a
  # direct 1.x pin finds none.
  kubectl delete crd -l 'app.kubernetes.io/instance=nginx-gateway-fabric' --ignore-not-found 2>/dev/null || true
  for c in $(kubectl get crd -o name 2>/dev/null | grep 'gateway.nginx.org'); do
    kubectl delete "${c}" --ignore-not-found
  done
  helm install "${NGF_RELEASE}" "${chart_dir}/nginx-gateway-fabric" \
    -n "${NGF_NS}" --create-namespace --wait --timeout 6m \
    --set 'service.type=NodePort' \
    --set 'nginxGateway.replicaCount=1' || {
    echo "the NGF 1.x install did not go ready (the pod state is the evidence)" >&2
    kubectl get pods -n "${NGF_NS}" -o wide 1>&2 || true
    kubectl get events -n "${NGF_NS}" --sort-by=.lastTimestamp 2>/dev/null | tail -15 1>&2 || true
    for p in $(kubectl get pods -n "${NGF_NS}" -o name 2>/dev/null); do
      kubectl logs -n "${NGF_NS}" "${p}" --all-containers --tail=30 1>&2 || true
    done
    return 1
  }
  # The 1.x chart assigns a random NodePort: pin both rows here (TR-203 L4
  # adds the https row; the http row keeps 31437).
  pin_nodeports
  NGF_CHART_VERSION="${version}"
}

# pin_nodeports — the 1.x lane's Service carries one random NodePort; the
# merge patch replaces the ports list, so both rows ride the patch. Re-run
# safe (step 6 calls it on an existing 1.x lab too).
pin_nodeports() {
  kubectl -n "${NGF_NS}" patch svc "${NGF_RELEASE}-nginx-gateway-fabric" \
    --type=merge -p "{\"spec\":{\"ports\":[{\"name\":\"http\",\"port\":80,\"nodePort\":${NODE_HTTP_PORT}},{\"name\":\"https\",\"port\":443,\"nodePort\":${NODE_HTTPS_PORT}}]}}"
}

if ! helm status "${NGF_RELEASE}" -n "${NGF_NS}" >/dev/null 2>&1; then
  NGF_INSTALLED_NEW="1"
  case "${NGF_CHART_VERSION}" in
    1.*)
      # A 1.x pin rides the proven single-pod lane directly: the 2.x set
      # shape (provisioned gateways, nginx.service.*) does not exist in the
      # 1.x chart, and the 2.x OCI lane misses the install deadline
      # (issue #198, run 40077270222).
      echo "NGF pin ${NGF_CHART_VERSION}: the 1.x single-pod lane installs directly" >&2
      install_ngf_1x "${NGF_CHART_VERSION}"
      ;;
    *)
      readarray -t HELM_SETS < <(helm_sets)
      if ! helm install "${NGF_RELEASE}" "oci://ghcr.io/nginx/charts/nginx-gateway-fabric" \
            --version "${NGF_CHART_VERSION}" -n "${NGF_NS}" --create-namespace \
            --wait --timeout 5m "${HELM_SETS[@]}" 2>/tmp/dx1-helm-err.log; then
        cat /tmp/dx1-helm-err.log >&2
        echo "helm install oci failed; retrying with the official chart package" >&2
        CHART_DIR="$(mktemp -d)/chart"
        fetch_chart_dir "ghcr.io/nginx/charts/nginx-gateway-fabric:${NGF_CHART_VERSION}" "${CHART_DIR}" || {
          echo "2.x retry ends here: no installable chart package came out of the pull (evidence above)" >&2
          echo "the OCI store publishes chart ${NGF_CHART_VERSION} in the oci:// chart form; the CI gate pins NGF_CHART_VERSION=1.6.2 (the proven single-pod lane) instead" >&2
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
          echo "NGF ${NGF_CHART_VERSION} dataplane did not become ready; retrying with the 1.x single-pod architecture (NGF_FALLBACK_CHART_VERSION)" >&2
          install_ngf_1x "${NGF_FALLBACK_CHART_VERSION:-1.6.2}"
        fi
      fi
      ;;
  esac
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
# TR-203 L2: the terminator leg's image = the 2.7.2 dataplane build (its
# nginx carries --with-http_v3_module; measure with `nginx -V` on the
# image). The ref pins the same string the derived manifest carries.
TERM_IMAGE="${TERM_IMAGE:-ghcr.io/nginx/nginx-gateway-fabric/nginx:2.7.2}"
if ! docker image inspect "${TERM_IMAGE}" >/dev/null 2>&1; then
  docker_pull "${TERM_IMAGE}"
fi
load_into_node "${TERM_IMAGE}"

if [ "${NGF_INSTALLED_NEW}" = "1" ]; then
  kubectl rollout status --timeout=5m -n "${NGF_NS}" "deployment/${NGF_RELEASE}-nginx-gateway-fabric"
  case "${NGF_CHART_VERSION}" in
    1.*)
      ;; # the 1.x chart ships one deployment; a ${NGF_RELEASE}-nginx read fails on a missing deployment
    *)
      # The 2.x dataplane runs as its own deployment. The 2.7.x chart names
      # the dataplane after the GATEWAY (edge-gateway-nginx); older 2.x
      # names read ${NGF_RELEASE}-nginx. Read both, one must roll.
      if ! kubectl rollout status --timeout=5m -n "${NGF_NS}" \
            "deployment/${GATEWAY_NAME}-nginx" 2>/tmp/dx1-dp-roll.log; then
        cat /tmp/dx1-dp-roll.log >&2
        kubectl rollout status --timeout=5m -n "${NGF_NS}" "deployment/${NGF_RELEASE}-nginx"
      fi
      ;;
  esac
fi

# --- 5a. the TLS leg (TR-203 L4): the listener cert fixture + the Secret -----
# The lab terminator surface needs a TLS leg before any key exchange reads
# off it. The fixture pair is a self-signed LAB cert (openssl, local temp
# dir), created into the dx1-lab-tls Secret in the Gateway ns — never a
# product cert, never committed. The PQ signature migration (the CA/cert
# chain) stays on the 2026.02/03 calendar lanes (issue #264, decision 4):
# this fixture exists only to open the key-exchange leg. DX1_TLS_LEG=0 skips
# the leg (the pre-L4 lab shape; the http steering leg carries the evidence
# unchanged).
log "TLS leg (TR-203 L4): the dx1-lab-tls fixture Secret"
if [ "$DX1_TLS_LEG" != "1" ]; then
  echo "DX1_TLS_LEG=0 — the https leg runs without its Secret: NGF marks the https listener Reconciled=false, the read reports the leg down"
else
  FIXTURE_DIR="$(mktemp -d /tmp/dx1-lab-tls.XXXXXX)"
  # RSA-2048: the pair every openssl build (LibreSSL on macOS included) and
  # Go's x509 reader agree on. The key exchange never reads this key.
  # SANs (TR-203 L2): the *.dx1.example.com DNS rows + the 127.0.0.1 IP
  # SAN the host-side dials read (the h3spec leg dials by IP; the tls
  # library then checks the IP SAN against the dialed address).
  openssl req -x509 -newkey rsa:2048 \
    -keyout "${FIXTURE_DIR}/tls.key" -out "${FIXTURE_DIR}/tls.crt" \
    -days 30 -nodes -subj '/CN=*.dx1.example.com' \
    -addext 'subjectAltName=DNS:*.dx1.example.com,DNS:engine.dx1.example.com,IP:127.0.0.1' \
    >/dev/null 2>&1 || {
    echo "the fixture pair generation failed (openssl $?) — the lab TLS leg stays down" >&2
    FIXTURE_DIR=""
  }
  if [ -n "${FIXTURE_DIR:-}" ]; then
    kubectl -n "${NGF_NS}" delete secret dx1-lab-tls --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "${NGF_NS}" create secret tls dx1-lab-tls \
      --cert="${FIXTURE_DIR}/tls.crt" --key="${FIXTURE_DIR}/tls.key" \
      >/dev/null 2>&1 || {
      echo "the dx1-lab-tls Secret create failed (cluster reachable?)" >&2
      exit 2
    }
    echo "dx1-lab-tls fixture in place (CN=*.dx1.example.com; DNS + 127.0.0.1 IP SAN; 30-day lab fixture)"
    DX1_TLS_FIXTURE=1   # the dx1-ns copy waits for the manifest stage (the ns applies first)
  else
    DX1_TLS_FIXTURE=0
  fi
fi

# --- 6. lab manifests: engine + echo + Gateway/HTTPRoute (+ the L2
# terminator leg) -------------------------------------------------------------
log "applying lab manifests (${MANIFESTS_DIR})"
kubectl apply -f "${MANIFESTS_DIR}/dx1-namespace.yaml"
kubectl apply -f "${MANIFESTS_DIR}/dx1-backend.yaml"
kubectl apply -f "${MANIFESTS_DIR}/dx1-engine.yaml"
kubectl apply -f "${MANIFESTS_DIR}/dx1-gateway.yaml"
kubectl apply -f "${MANIFESTS_DIR}/dx1-httproute.yaml"

# TR-203 L2 (issue #264, leaf L2): the QUIC-ingress terminator leg. The
# Secret mounts first (the fixture's dx1-ns copy), then the
# terminator Service + Deployment. DX1_TLS_LEG=0 leaves the leg
# unapplied (the fixture stays down — the leg's named absence).
if [ "${DX1_TLS_LEG:-1}" = "1" ] && [ "${DX1_TLS_FIXTURE:-0}" = "1" ]; then
  kubectl -n dx1 delete secret dx1-lab-tls --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n dx1 create secret tls dx1-lab-tls \
    --cert="${FIXTURE_DIR}/tls.crt" --key="${FIXTURE_DIR}/tls.key" \
    >/dev/null 2>&1 || {
    echo "the dx1-ns dx1-lab-tls Secret create failed (the manifest stage needs it; the fixture stage produced it)" >&2
    exit 2
  }
  echo "dx1-lab-tls fixture in the dx1 ns (the terminator mount)"
  kubectl apply -f "${MANIFESTS_DIR}/dx1-terminator.yaml"
fi

kubectl rollout status --timeout=3m -n dx1 deployment/dx1-engine
kubectl rollout status --timeout=3m -n dx1 deployment/dx1-echo
if [ "${DX1_TLS_LEG:-1}" = "1" ]; then
  kubectl rollout status --timeout=3m -n dx1 deployment/dx1-terminator
fi

# An existing 1.x lab (idempotent re-run): pin the https NodePort row too.
case "${NGF_CHART_VERSION}" in
  1.*) [ "$DX1_TLS_LEG" = "1" ] && pin_nodeports ;;
esac

log "DX1 lab setup complete"
kubectl -n "${NGF_NS}" get gateway,svc 2>/dev/null || true
kubectl -n dx1 get all 2>/dev/null || true
