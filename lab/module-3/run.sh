#!/usr/bin/env bash
# TR-27b (issue #170, spec sections 7.1 Module 3 + 9) — the module-3 lab:
# packets meet programs — attach, map state, and the verdict path.
#
# Scripted scenario:
#   leg 1  wire     (any host, pure Go) — the kernel wire contracts and
#                     tier tests: ban entry layout, v4 wire contract,
#                     reason codes, verdict semantics, kernel contract,
#                     tier classification. These tests pin the map values
#                     and the event layouts the maps carry.
#   leg 2  attach   (Linux, root) — lab/verify-xdp-chain.sh <iface>: CO-RE
#                     compile, verifier load, pin, XDP attach, detach clean
#                     (XDP-CHAIN-OK).
#   leg 3  ban-e2e  (Linux, root) — go test -tags ban_e2e ./test/banenforce/:
#                     ban published to the kernel ban_table, replay dies in
#                     kernel, expiry lifts the ban, evidence JSONL lands.
#
# On a macOS host the kernel legs need an OrbStack Linux VM: set
# TRISHULA_LAB_VM (<vm name>; the legs then run via `orb run`) and,
# optionally, TRISHULA_VM_ROOT (the repo path inside the VM; the default
# maps the macOS $HOME mount /Users to /mnt/mac/Users — the OrbStack
# mount shape). The VM's default bpftool sits version-mismatched against
# the OrbStack kernel (the repo AGENTS.md note); override it with
# TRISHULA_VM_BPFTOOL (the default carries the linux-tools discovery
# fallback lab/verify-xdp-chain.sh documents).
#
# A missing kernel environment prints a loud SKIP line. PASS / SKIP /
# FAIL; the script exits nonzero on any FAIL and never reports a skip
# as a pass.
set -euo pipefail

M3_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${M3_DIR}/../.." && pwd)"
TRISHULA_ROOT="${TRISHULA_ROOT:-$REPO_ROOT}"
TRISHULA_LAB_VM="${TRISHULA_LAB_VM:-}"
VM_ROOT="${TRISHULA_VM_ROOT:-}"
VM_IFACE="${VM_IFACE:-eth0}"
VM_BPFTOOL="${TRISHULA_VM_BPFTOOL:-/usr/lib/linux-tools/6.8.0-146-generic/bpftool}"

WORK="$(mktemp -d /tmp/module3-lab.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

banner() { printf '\n============================================================\n== %s\n============================================================\n' "$*"; }
leg() { printf '\n---- leg %s: %s ----\n' "$1" "$2"; }
fail() { printf '== MODULE3-LAB-FAIL — %s ==\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP  %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1 (see lab/module-3/README.md)"
}

# vm_root_of: the OrbStack /mnt/mac path for this host checkout.
vm_root_of() {
  if [ -n "$VM_ROOT" ]; then
    printf '%s\n' "$VM_ROOT"
  else
    printf '%s\n' "$TRISHULA_ROOT" | sed 's|^/Users/|/mnt/mac/Users/|'
  fi
}

banner "module-3 lab (TR-27b, issue #170) — packets meet programs"
printf 'repo:  %s\n' "$TRISHULA_ROOT"
printf 'vm:    %s (the kernel legs run here when set)\n' "${TRISHULA_LAB_VM:-none}"

require go

# leg 1: the kernel wire contracts (pure Go, runs everywhere) ----------------
leg 1 "wire — the ban/verdict/tier contract tests of internal/shield"
(
  cd "$TRISHULA_ROOT" &&
    go test -count=1 -v \
      -run 'TestBanEntryWireContract|TestBanKeyParsing|TestBansV4WireContract|TestReasonCodesWire|TestVerdictSemantics|TestKernelContract|TestClassifyTier|TestTierStringContract' \
      ./internal/shield/
) >"$WORK/wire.txt" 2>&1 || { cat "$WORK/wire.txt"; fail "the wire contract tests failed"; }
PASS_ROWS="$(grep -c '^    --- PASS' "$WORK/wire.txt" || true)"
tail -1 "$WORK/wire.txt"
pass "wire contracts hold ($PASS_ROWS pinned cases green)"

# kernel dispatch: "host" (this box is Linux with root+BTF), "vm", or "none".
kernel_ctx() {
  if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" -eq 0 ] && [ -f /sys/kernel/btf/vmlinux ]; then
    printf 'host\n'
  elif [ -n "$TRISHULA_LAB_VM" ]; then
    printf 'vm\n'
  else
    printf 'none\n'
  fi
}
KCTX="$(kernel_ctx)"
SKIPLINE="kernel environment unavailable (need Linux with root+BTF+BPFFS, or TRISHULA_LAB_VM set)"

# leg 2: attach — CO-RE compile, verify, pin, attach, detach -----------------
leg 2 "attach — lab/verify-xdp-chain.sh $VM_IFACE (the XDP attach lifecycle)"
case "$KCTX" in
host)
  cd "$TRISHULA_ROOT"
  if [ -n "${BPFTOOL:-}" ] || command -v bpftool >/dev/null 2>&1 || find /usr/lib/linux-tools -maxdepth 3 -name bpftool 2>/dev/null | grep -q .; then
    bash lab/verify-xdp-chain.sh "$VM_IFACE" || fail "the attach leg failed"
    pass "XDP attach lifecycle green (compile, verify-load, pin, attach, detach)"
  else
    fail "bpftool missing (set BPFTOOL=<path>, see lab/verify-xdp-chain.sh)"
  fi
  ;;
vm)
  VMROOT="$(vm_root_of)"
  printf 'vm %s: bash lab/verify-xdp-chain.sh %s (BPFTOOL=%s, at %s)\n' "$TRISHULA_LAB_VM" "$VM_IFACE" "$VM_BPFTOOL" "$VMROOT"
  orb run -m "$TRISHULA_LAB_VM" -u root bash -cl \
    "cd '$VMROOT' && BPFTOOL='$VM_BPFTOOL' bash lab/verify-xdp-chain.sh '$VM_IFACE'" \
    || fail "the attach leg failed inside $TRISHULA_LAB_VM"
  pass "XDP attach lifecycle green inside $TRISHULA_LAB_VM (compile, verify-load, pin, attach, detach)"
  ;;
none)
  skip "$SKIPLINE"
  ;;
esac

# leg 3: the ban verdict path — publish, drop, expiry, evidence --------------
leg 3 "ban-e2e — the full verdict path in kernel (test/banenforce, tag ban_e2e)"
case "$KCTX" in
host)
  (cd "$TRISHULA_ROOT" && go test -tags ban_e2e -count=1 -v ./test/banenforce/) \
    >"$WORK/bane2e.txt" 2>&1 || { cat "$WORK/bane2e.txt"; fail "ban e2e failed on the Linux host"; }
  tail -1 "$WORK/bane2e.txt"
  ;;
vm)
  VMROOT="$(vm_root_of)"
  printf 'vm %s: go test -tags ban_e2e -count=1 ./test/banenforce/ (at %s)\n' "$TRISHULA_LAB_VM" "$VMROOT"
  orb run -m "$TRISHULA_LAB_VM" -u root bash -cl \
    "cd '$VMROOT' && PATH=/usr/local/go/bin:\$PATH go test -tags ban_e2e -count=1 -v ./test/banenforce/" \
    >"$WORK/bane2e.txt" 2>&1 || { cat "$WORK/bane2e.txt"; fail "ban e2e failed inside $TRISHULA_LAB_VM"; }
  tail -1 "$WORK/bane2e.txt"
  ;;
none)
  skip "$SKIPLINE"
  ;;
esac
if [ "$KCTX" != "none" ]; then
  grep -q "^ok  \tgithub.com/trishula-dev/trishula/test/banenforce" "$WORK/bane2e.txt" \
    || fail "the ban-e2e leg ended without a green package line"
  pass "ban publish -> kernel drop -> expiry -> evidence JSONL all hold (tagged e2e green)"
fi

banner "MODULE3-LAB-OK — wire, attach and ban-e2e legs green"
