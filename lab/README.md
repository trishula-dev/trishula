# lab/

Demo + DX1 scenarios with NGF (TR-06, TR-23).

## Prerequisites

- `just` — the entry runner: `just` alone lists every lane; `just demo` runs it. (brew install just)
- The direct form stays: `bash lab/demo.sh` = `just demo`.

## The target gate (issue #261)

Every lab entry (`demo.sh`, `lab/dx1/setup.sh`) sources
[`prereq.sh`](prereq.sh). The prereq = **docker OR kubernetes**:

- docker without a cluster = the docker target (the standalone image path).
- kubectl with a reachable cluster = the k8s target. Any context works:
  a local kind or OrbStack, a hypervisor-hosted VM's node, or a cloud
  Kubernetes (EKS, DOKS) — point `kubeconfig` at it and run.
- Neither = the script refuses and names exactly what to install.

`prereq.sh` exports `LAB_TARGET` / `LAB_CONTEXT` / `LAB_LOCAL`; the lab
branches on them (the image load stays a local-cluster leg; a remote
context needs its registry — the follow-up leaf).

## Environment gates

- `verify-xdp-chain.sh` — proves the Linux host can compile CO-RE eBPF,
  verify-load, pin, attach XDP and detach cleanly (TR-03). Run with sudo
  on a Linux host; output is pasted into kernel-side PR bodies.
