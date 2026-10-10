#!/usr/bin/env bash
# scripts/tier-e2e-pod.sh — TR-80: the pod-veth tier probe, driven FROM
# the mac against the live kind node (docker exec; the OrbStack node
# ships tc+ping but no bpftool — this installs the deb for the leg and
# removes it again on exit).
#
# Contract (parsed by test/tier TestTierK8sPodVethE2E):
#
#	EV=sent=<N> xdp=<count> tc=<count>
#	TIER=<full|first_packet|none>
#	TIER(<iface>)=<full|first_packet|none>   (the gate grep surface)
#
# What REAL measurement looks like here (no stubs):
#   1. push the two bpf2go objects (x86_64 ELF) into the node
#   2. bpftool prog loadall + map pin (id-pinned probe_stats/ban_stats)
#   3. tc filter (pinned) + ip link xdp (pinned) on the live CNI veth
#   4. ONE probe burst (ping -M dont node→podIP, the DF-mask marker)
#   5. bpftool map dump deltas around the burst
#   6. classify (>=5 full / >0 first_packet / 0 none) — the SAME
#      thresholds internal/shield probe.go classifies with at boot.
#
# Cleanup restores the node's pre-run posture: xdp off + clsact del +
# pins removed + the bpffs mount this leg added (the kind node ships
# with bpffs unmounted).
set -uo pipefail

NODE="${1:-dx1kind-control-plane}"
IFACE="${2:?usage: tier-e2e-pod.sh <node> <iface> <podip> <repo-root>}"
PODIP="${3:?usage: tier-e2e-pod.sh <node> <iface> <podip> <repo-root>}"
REPO="${4:?usage: tier-e2e-pod.sh <node> <iface> <podip> <repo-root>}"
PIN=/sys/fs/bpf/tr80tier
BPF_N=probe
XDP_N=xdpprobe

MOUNTED_BPF=""
TMP="$(mktemp -d)"
cleanup() {
  docker exec "$NODE" ip link set dev "$IFACE" xdp off 2>/dev/null || true
  docker exec "$NODE" tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
  docker exec "$NODE" rm -f "$PIN/ban_stats" "$PIN/probe_stats" "$PIN/ban_xdp" "$PIN/tc_ingress_waf" /tmp/tr80-$BPF_N.o /tmp/tr80-$XDP_N.o 2>/dev/null || true
  rmdir "$PIN" 2>/dev/null || true
  if [ -n "$MOUNTED_BPF" ]; then docker exec "$NODE" sh -c 'umount /sys/fs/bpf 2>/dev/null || true'; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

# bpftool: the node is Debian; install the deb (idempotent) when missing —
# and LEAVE it installed (the kind node is a disposable dev node; the
# deb is small and the next leg needs it too).
# (The probe must invoke bpftool directly — `docker exec NODE command -v`
# fails: 'command' is a shell builtin, not a binary in the node's PATH.)
if ! docker exec "$NODE" bpftool version >/dev/null 2>&1; then
  docker exec "$NODE" sh -c 'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq bpftool >/dev/null 2>&1' || true
fi
docker exec "$NODE" bpftool version >/dev/null 2>&1 || { echo "no bpftool in node" >&2; exit 3; }

# 1. object push (x86_64 node: the _x86 objects)
base64 -i "$REPO/test/tier/tier_probe_x86_bpfel.o" | docker exec -i "$NODE" sh -c "base64 -d > /tmp/tr80-$BPF_N.o" || exit 3
base64 -i "$REPO/test/tier/tier_xdp_x86_bpfel.o"  | docker exec -i "$NODE" sh -c "base64 -d > /tmp/tr80-$XDP_N.o" || exit 3

# 2. load + pin (bpffs: the node ships unmounted — mount it for the leg)
if ! docker exec "$NODE" grep -q bpffs /proc/mounts 2>/dev/null; then
  MOUNTED_BPF=1
  docker exec "$NODE" mount -t bpf bpf /sys/fs/bpf || exit 3
fi
docker exec "$NODE" mkdir -p "$PIN" || exit 3
docker exec "$NODE" bpftool prog loadall "/tmp/tr80-$BPF_N.o" "$PIN/" || exit 4
docker exec "$NODE" bpftool prog loadall "/tmp/tr80-$XDP_N.o" "$PIN/" || exit 4

# The probe MAPS: prog loadall does NOT pin maps. Resolve each pinned
# program's OWN map id (map show node-wide is ambiguous across stale
# legs — anchor the lookup to the pinned programs, then map pin by id).
pin_prog_map() { # $1 = pinned prog, $2 = wanted map name, $3 = pin dest
  local ids mid name
  ids="$(docker exec "$NODE" bpftool -j prog show pinned "$1" | grep -o '"map_ids":\[[^]]*\]')"
  ids="${ids#\"map_ids\":[}"; ids="${ids%]}"; ids="${ids//[^0-9,]/}"
  for mid in $(echo "$ids" | tr ',' ' '); do
    name="$(docker exec "$NODE" bpftool -j map show id "$mid" | grep -o "\"name\":\"$2\"" || true)"
    if [ -n "$name" ]; then
      docker exec "$NODE" bpftool map pin id "$mid" "$3" && return 0
    fi
  done
  echo "map $2 not owned by pinned prog $1" >&2
  return 1
}
pin_prog_map "$PIN/tc_ingress_waf" probe_stats "$PIN/probe_stats" || exit 4
pin_prog_map "$PIN/ban_xdp" ban_stats "$PIN/ban_stats" || exit 4

# 3. attach (the TR-10 pinned pattern)
docker exec "$NODE" tc qdisc add dev "$IFACE" clsact 2>/dev/null || true
docker exec "$NODE" tc filter add dev "$IFACE" ingress bpf da pinned "$PIN/tc_ingress_waf" || { echo "tc attach failed" >&2; exit 4; }
if ! docker exec "$NODE" ip link set dev "$IFACE" xdp pinned "$PIN/ban_xdp" 2>/dev/null; then
  # a stale leg left its generic XDP on this iface — replace it with ours
  docker exec "$NODE" ip link set dev "$IFACE" xdp off 2>/dev/null || true
  docker exec "$NODE" ip link set dev "$IFACE" xdp pinned "$PIN/ban_xdp" || { echo "xdp attach failed" >&2; exit 4; }
fi

# 4+5. delta around ONE burst of 5 (the DF-mask marker: ping -M dont)
key0sum() { # probe_stats: the single PROBE_SEEN=0 per-CPU slice
  docker exec "$NODE" bpftool -j map dump pinned "$1" \
    | tr '{' '\n' | grep -o '"value":[0-9]*' | cut -d: -f2 \
    | awk '{s+=$1} END{print s+0}'
}
key3sum() { # ban_stats[k]: the given key's per-CPU slice sum (STAT_* keys untouched)
  docker exec "$NODE" bpftool -j map dump pinned "$1" | awk -v k="$2" '
  {
    while (match($0, /"formatted":\{"key":[0-9]+,"values":\[[^]]*\]/)) {
      seg = substr($0, RSTART, RLENGTH); $0 = substr($0, RSTART+RLENGTH)
      kv = seg; sub(/"formatted":\{"key":/, "", kv); sub(/,"values".*/, "", kv)
      if (kv + 0 == k + 0) {
        x = seg; s = 0
        while (match(x, /"value":[0-9]+/)) { s += substr(x, RSTART+8, RLENGTH-8) + 0; x = substr(x, RSTART+RLENGTH) }
      }
    }
  } END { printf "%d", s + 0 }'
}


PRE_TC="$(key0sum "$PIN/probe_stats")"
PRE_XDP="$(key3sum "$PIN/ban_stats" 3)"
SENT=0
for _ in 1 2 3 4 5; do
  if docker exec "$NODE" ping -c 1 -W 1 -M dont "$PODIP" >/dev/null 2>&1; then
    SENT=$((SENT+1))
  fi
done
POST_TC="$(key0sum "$PIN/probe_stats")"
POST_XDP="$(key3sum "$PIN/ban_stats" 3)"

TC="$((POST_TC - PRE_TC))"
XDP="$((POST_XDP - PRE_XDP))"
TOTAL=$((XDP + TC))
if [ "$SENT" -le 0 ]; then TIER=none
elif [ "$TOTAL" -ge "$SENT" ]; then TIER=full
elif [ "$TOTAL" -gt 0 ]; then TIER=first_packet
else TIER=none; fi

echo "EV=sent=$SENT xdp=$XDP tc=$TC"
echo "TIER=$TIER"
echo "TIER($IFACE)=$TIER"
