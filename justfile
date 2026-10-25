# justfile — the entry surface (issue #261). The targets = one delegation
# each; the procedures stay in the scripts they point at. `just` alone
# lists every recipe. Nothing here carries logic: a failing script is the
# recipe's failure; the labs' loud banners + `set -euo pipefail` remain
# the contract.
#
# Prereqs, in layers:
#   1. just — this runner (brew install just / nix-shell -p just)
#   2. docker OR kubernetes — the target gate the scripts run
#      (lab/prereq.sh; a local kind/OrbStack, a hypervisor VM's node, or
#      a cloud Kubernetes — EKS, DOKS — via the current kubeconfig)
#   3. go — the builds and the tests build from this tree

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

_default:
    @just --list

# the entry list (jot the procedures in the scripts, not here)
alias l := _default

demo:               # the full DX1 demo (the 3-stage exit gate; the prereq gate runs inside)
    bash lab/demo.sh

demo-attack:        # the attack demo (the wire legs + the kernel answer)
    bash lab/demo-attack.sh

gate:               # the DX1 gate (the apply→effect timed leg)
    bash lab/dx1/dx1-gate.sh

setup:              # the lab cluster up (the current context; kind only when local)
    bash lab/dx1/setup.sh

verify:             # the hop-by-hop verification (NGF → engine → echo)
    bash lab/dx1/verify.sh

apply-effect:       # the M9 timed apply→effect scenario only
    bash lab/dx1/apply-effect.sh

auth:               # the S3 vocabulary example (the claims gate; TR-198)
    bash lab/dx1/dx1-auth.sh

h3-ingress:         # the QUIC-ingress topology read (TR-203 L2: P4 advisory + the P8 h3 hop)
    bash lab/dx1/h3-ingress-read.sh

bench:              # the bench rig (run inside a Linux VM; the A/B surface)
    bash lab/bench-vm.sh

tier-gate:          # the shield's visibility tier on this host
    bash lab/tier-gate.sh

verify-xdp:         # the CO-RE/XDP chain proof (root; a Linux host)
    bash lab/verify-xdp-chain.sh

build:              # go build ./...
    go build ./...

vet:                # go vet ./...
    go vet ./...

test:               # the full suite (the CI shape: serialized + the CRS rx profile)
    go test -tags coraza.rule.no_regex_multiline -p 1 ./... -count=1

clean:              # the lab's ephemeral state (the pins + the tmp dirs the demos own)
    rm -rf /sys/fs/bpf/tr195 /sys/fs/bpf/tr10ban /tmp/tr195 /tmp/tr10ban
