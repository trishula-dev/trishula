#!/usr/bin/env bash
# lab/verify-xdp-chain.sh — TR-03 environment gate (PRD §19.1, issue #3).
#
# Proves the Linux test host can compile CO-RE eBPF, load it under the
# verifier, pin it, attach it to an interface as XDP, and detach cleanly.
# This is the environment gate for every kernel-side PR; paste its output
# into the PR body (issue #42 standard). Run on a Linux host with:
#   sudo ./lab/verify-xdp-chain.sh [iface]   # default: eth0
set -euo pipefail

IFACE="${1:-eth0}"
BPFTOOL="${BPFTOOL:-$(command -v bpftool || find /usr/lib/linux-tools -maxdepth 3 -name bpftool 2>/dev/null | head -1)}"
WORK="$(mktemp -d)"
trap 'ip link set dev "$IFACE" xdp off 2>/dev/null || true; rm -rf "$WORK" 2>/dev/null || true' EXIT

"$BPFTOOL" version >/dev/null 2>&1 || { echo "FAIL: bpftool unusable (\$BPFTOOL=$BPFTOOL); set BPFTOOL=<path>" >&2; exit 2; }
[ -f /sys/kernel/btf/vmlinux ] || { echo "FAIL: BTF missing at /sys/kernel/btf/vmlinux" >&2; exit 1; }
[ -d /sys/fs/bpf ] || { echo "FAIL: bpffs not mounted at /sys/fs/bpf" >&2; exit 1; }
ip link show "$IFACE" > /dev/null || { echo "FAIL: interface $IFACE not found" >&2; exit 1; }

echo "== host =="
uname -r
"$BPFTOOL" version | head -1

echo "== BTF dump (vmlinux.h) =="
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$WORK/vmlinux.h"
wc -l < "$WORK/vmlinux.h"

echo "== compile CO-RE XDP probe =="
cat > "$WORK/xdp_ping.c" <<'EOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
SEC("xdp")
int test_xdp(struct xdp_md *ctx) { return XDP_PASS; }
char _license[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -D__TARGET_ARCH_"$(uname -m | sed 's/aarch64/arm64/;s/x86_64/x86/')" \
  -I"$WORK" -c "$WORK/xdp_ping.c" -o "$WORK/xdp_ping.o"

echo "== verifier load + pin =="
"$BPFTOOL" prog loadall "$WORK/xdp_ping.o" "$WORK/pin" type xdp
"$BPFTOOL" prog show pinned "$WORK/pin/test_xdp" | head -3

echo "== attach $IFACE =="
ip link set dev "$IFACE" xdp pinned "$WORK/pin/test_xdp"
ip link show "$IFACE" | grep -oE "prog/xdp[a-z_]*" | head -1

echo "== detach + cleanup =="
# Detach first, delete the pinned prog, THEN the pin dir (it mounts the
# bpffs, so it is busy while anything is pinned under it).
ip link set dev "$IFACE" xdp off || true
"$BPFTOOL" prog delete pinned "$WORK/pin/test_xdp" 2>/dev/null || true
umount "$WORK/pin" 2>/dev/null || true

echo "XDP-CHAIN-OK ($IFACE)"
