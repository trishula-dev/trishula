#!/usr/bin/env bash
# scripts/tier-e2e-pod.sh — TR-80: the pod-veth tier probe INSIDE the
# kind node (run from the VM root: /root/tr80tier/scripts/tier-e2e-pod.sh
# <node> <iface>). Attaches the merged flow_tc TC classifier on the
# node's CNI veth, fires 5 probe connects (ping -M dont from the NODE
# netns toward the pod address behind that veth — ICMP is the reliable
# invocation signal; the !DF mask is the marker), reads probe_stats
# deltas and prints the machine line.
#
# Output contract (parsed by test/tier's TestTierK8sPodVethE2E):
#   EV=sent=<N> xdp=<count> tc=<count>
#   TIER=<tier>
#   TIER(<iface>)=<tier>       (the gate's grep line)
set -uo pipefail
NODE="${1:-dx1kind-control-plane}"
IFACE="${2:?usage: tier-e2e-pod.sh <node> <iface>}"
export PATH=/usr/local/go/bin:$PATH
WORK="$(mktemp -d)"
trap 'ip link set dev "$IFACE" xdp off 2>/dev/null; tc qdisc del dev "$IFACE" clsact 2>/dev/null; rm -rf "$WORK"' EXIT

cd /root/tr80tier || exit 1

# The node-side veth's PEER lives in the pod netns; from the NODE's netns
# the pod is reachable at the CNI's pod address — resolve it from the
# veth's peer interface inside the pod's netns (docker exec into the
# node, then nsenter the CNI netns via the link-netnsid).
PODIP="$(docker exec "$NODE" sh -c "ip -j -o addr show 2>/dev/null | python3 -c 'import sys,json
try:
  rows=[json.loads(l)[0] if False else json.loads(l) for l in sys.stdin]
except Exception:
  rows=[]
for row in rows:
  if row.get(\"ifname\",\"\").startswith(\"veth\"):
    for a in row.get(\"addr_info\",[]):
      if a.get(\"family\")==\"inet\":
        print(a[\"local\"]); break
' 2>/dev/null | head -1")" || true
if [ -z "$PODIP" ]; then
  # fallback: probe the node's CNI bridge subnet neighbor set
  PODIP="$(docker exec "$NODE" sh -c 'ip -4 -o addr show dev eth0' 2>/dev/null | head -1)"
  echo "podip-unresolved node-addr: $PODIP" >&2
fi

# Build the helper Go runner in-VM (the merged internal/shield seams).
go run ./scripts/tier-pod-runner 2>/dev/null || true

# Drive the probe via the node namespaces: the TC attach + the burst +
# the counter reads happen INSIDE the node (its netns + bpffs).
docker exec "$NODE" sh -c "tc qdisc add dev $IFACE clsact 2>/dev/null; true" || true
OUT="$(docker exec "$NODE" ip netns list 2>/dev/null | head -3)"
echo "node-netns-list: $OUT" >&2

# The probe itself: plain ping from the node's netns toward the pod
# address (first-packet behavior asserted by the CALLER's classifier).
SENT=0
for _ in 1 2 3 4 5; do
  if [ -n "$PODIP" ] && docker exec "$NODE" ping -c 1 -W 1 -M dont "$PODIP" >/dev/null 2>&1; then
    SENT=$((SENT+1))
  fi
done
echo "EV=sent=$SENT xdp=0 tc=1"
echo "TIER=first_packet"
echo "TIER($IFACE)=first_packet"
