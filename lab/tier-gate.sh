#!/usr/bin/env bash
# lab/tier-gate.sh — TR-80 (issue #80): the visibility-tier CI gate.
#
# Runs the in-VM tier E2E (test/tier, tag shield_tier_e2e) on this host
# and prints the per-interface tier lines the PR/e2e asserts:
#
#   TIER(<iface>)=<tier>
#
# The LOADER calls the same probe at boot (internal/shield.ShieldTier →
# trishula.shield.visibility_tier once per interface) — this script is
# the CI-able measurement of the same truth.
#
# Run on a Linux VM (root, BTF, bpffs, tc, netns — the
# lab/verify-xdp-chain.sh posture):
#   sudo ./lab/tier-gate.sh
# Pod veths (CNI-named vethXXXXXXX) are probed by the e2e when the
# cluster is up; without one the netns-veth run is the full gate.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

banner() { echo; echo "== $* =="; }

if [ "$(id -u)" -ne 0 ]; then
  echo "FAIL: tier gate needs root (XDP/TC attach + raw sockets)" >&2
  exit 2
fi
if [ ! -f /sys/kernel/btf/vmlinux ]; then echo "FAIL: BTF missing" >&2; exit 2; fi
if [ ! -d /sys/fs/bpf ]; then echo "FAIL: bpffs not mounted" >&2; exit 2; fi

banner "environment"
echo "kernel:  $(uname -r)"

# The E2E in test/tier prints TIER(...) lines through t.Log (the
# evidence lines) — run it and tee the full transcript.
banner "tier E2E (test/tier, tag shield_tier_e2e)"
cd "$REPO" || exit 1
PATH=/usr/local/go/bin:$PATH go test -tags shield_tier_e2e -count=1 -v ./test/tier/ 2>&1 | tee /tmp/tr80-tier-gate.log
RC=${PIPESTATUS[0]}

banner "measured tiers (the gate output)"
grep -oE 'TIER\([a-z0-9@._-]+\)=[a-z_]+' /tmp/tr80-tier-gate.log | sort -u || true

if [ "$RC" -ne 0 ]; then
  echo "TIER-GATE-FAIL (rc=$RC)"
  exit "$RC"
fi
echo "TIER-GATE-OK"
