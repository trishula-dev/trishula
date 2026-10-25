#!/usr/bin/env bash
# lab/prereq.sh — the target gate for every lab script (issue #261).
#
# Source it at the top of a lab script:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/prereq.sh"
#
# It refuses unless the host carries DOCKER or a reachable KUBERNETES, in
# that order, and exports what the scripts branch on:
#
#   LAB_TARGET  = k8s | docker
#   LAB_CONTEXT = the kubectl context name (k8s) | the docker server (docker)
#   LAB_LOCAL   = 1 when the context talks to THIS machine (a local kind,
#                 OrbStack, Docker Desktop), else 0 (cloud: EKS, DOKS, ...)
#
# Everything after the source works from there — no kind assumption, no
# OrbStack assumption. A hypervisor-VM lane sources this INSIDE the VM.

# shellcheck shell=bash
# the LAB_* exports = the sourcing scripts' contract (unused locally)
# shellcheck disable=SC2034

lab_prereq() {
  local have_docker=0 have_k8s=0
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && have_docker=1
  if command -v kubectl >/dev/null 2>&1 && \
     kubectl cluster-info --request-timeout=5s >/dev/null 2>&1; then
    have_k8s=1
  fi

  if [ "$have_k8s" = 1 ]; then
    export LAB_TARGET=k8s
    LAB_CONTEXT="$(kubectl config current-context)"
    export LAB_CONTEXT
    export LAB_LOCAL=0
    case "$LAB_CONTEXT" in
      kind-*|orbstack*|docker-*) export LAB_LOCAL=1 ;;
    esac
  elif [ "$have_docker" = 1 ]; then
    export LAB_TARGET=docker
    LAB_CONTEXT="$(docker context show 2>/dev/null || docker info --format "{{.Name}}" 2>/dev/null || echo docker)"
    export LAB_CONTEXT
    export LAB_LOCAL=1
  else
    cat >&2 <<'EOF'
lab prereq: install one of the two surfaces and run again.
  either: docker          (brew install docker / colima start / any docker provider)
      or: kubectl + a reachable cluster (a local kind or OrbStack, or a
          cloud Kubernetes such as EKS/DOKS — point kubeconfig at it)
EOF
    return 1
  fi
  echo "lab target: $LAB_TARGET (context: $LAB_CONTEXT, local=$LAB_LOCAL)" >&2
  return 0
}

lab_prereq "$@"
