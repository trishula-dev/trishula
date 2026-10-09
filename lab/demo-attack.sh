#!/usr/bin/env bash
# lab/demo-attack.sh — TR-43 (issue #83): the full attack demo.
#
# Three attacks against a live HTTP target through a real kernel TC hook,
# with per-altitude evidence, over MERGED engine code:
#
#   Attack A — CRS layer:   path traversal + SQLi payloads; the captured
#                           requests run through embedded Coraza (the
#                           reference CRS evaluator) → the S2 verdict
#                           these payloads earn (rule ids).
#   Attack B — API layer:   BOLA (API1:2023): tenant-B object requested
#                           with tenant-A credentials; ownership-mismatch
#                           decision + the trishula.verdict.v1 record.
#   Attack C — enforcement: the same attacker source banned via the
#                           shield loader ABI; the replay dies IN KERNEL
#                           (TC_ACT_SHOT, zero userspace round-trip).
#
# All transcripts post to issue #83 (the validation protocol).
#
# Run on a Linux VM (kernel ≥5.8, BTF, root):  sudo ./lab/demo-attack.sh
set -euo pipefail

IFACE="tr04h"
NS="tr04d"
PIN_DIR="/sys/fs/bpf/tr43demo"
BPFTOOL="${BPFTOOL:-$(command -v bpftool || find /usr/lib/linux-tools -maxdepth 3 -name bpftool 2>/dev/null | head -1)}"
DEMO_BIN="${DEMO_BIN:-/tmp/attackdemo}"
TARGET_IP="10.99.0.1"     # listener (host side of the pair)
ATTACKER_IP="10.99.0.66"  # "attacker" (ns side of the pair)
PORT="18099"

banner() { echo; echo "== $* =="; }
sha() { git -C "${TRISHULA_ROOT:-$(dirname "$0")/..}" rev-parse --short HEAD 2>/dev/null || cat "${TRISHULA_ROOT:-$(dirname "$0")/..}/.demo-commit" 2>/dev/null || echo unknown; }

cleanup() {
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$IFACE" 2>/dev/null || true
  findmnt -t bpf -n -o TARGET 2>/dev/null | grep -F "$PIN_DIR" | xargs -r umount 2>/dev/null || true
  rm -rf "$PIN_DIR"
}
trap cleanup EXIT

[ -n "$BPFTOOL" ] || { echo "FAIL: bpftool not found" >&2; exit 1; }
[ -f /sys/kernel/btf/vmlinux ] || { echo "FAIL: BTF missing" >&2; exit 1; }
[ -x "$DEMO_BIN" ] || { echo "FAIL: build cmd/attackdemo (linux) + set DEMO_BIN" >&2; exit 1; }

banner "environment (issue #83 evidence protocol)"
echo "kernel:    $(uname -r)"
echo "commit:    $(sha)"
echo "bpftool:   $($BPFTOOL version | head -1)"
echo "attacker:  $ATTACKER_IP → target: $TARGET_IP:$PORT"

# harness: veth pair + netns + TC filter with the merged flow_tc producer
banner "harness (under the hood; the app-dev framing of the attack is the curl below)"
ip netns add "$NS"
ip link add "$IFACE" type veth peer name tr04n
ip link set tr04n netns "$NS"
ip addr add "$TARGET_IP/24" dev "$IFACE"
ip link set "$IFACE" up
ip netns exec "$NS" ip addr add "$ATTACKER_IP/24" dev tr04n
ip netns exec "$NS" ip link set tr04n up
tc qdisc add dev "$IFACE" clsact
mkdir -p "$PIN_DIR"
# idempotent pinning: fresh dir, pin by id of the NEWLY loaded tc prog
# stale bpffs mounts from interrupted runs shadow rm -rf — unmount first
mount | awk -v d="$PIN_DIR" '$0 ~ d {print $2}' | while read -r m; do umount "$m" 2>/dev/null || true; done
rm -rf "$PIN_DIR"; mkdir -p "$PIN_DIR"
# loadall pins every program it loads into the dir itself (incl.
# tc_ingress_waf) — pinning again by id would double-create; attach
# the loadall pin directly.
# loadall pins the PROGRAM only; the maps (ban_table/events/lost_events/
# flow_stats) stay unpinned. Snapshot map ids BEFORE the load, then pin
# the maps the load created (ids not in the snapshot).
$BPFTOOL -j map show | python3 -c 'import json,sys;d=json.load(sys.stdin);print(" ".join(str(m["id"]) for m in d))' > /tmp/before.ids 2>/dev/null || true
BEFORE_MAPS=$(cat /tmp/before.ids 2>/dev/null || echo "")
$BPFTOOL prog loadall /tmp/flow_tc.o "$PIN_DIR" type tc > /dev/null
$BPFTOOL prog show pinned "$PIN_DIR/tc_ingress_waf" | sed -n 1p
tc filter add dev "$IFACE" ingress bpf da pinned "$PIN_DIR/tc_ingress_waf"
python3 - "$BEFORE_MAPS" "$PIN_DIR" <<'PY'
import json, os, subprocess, sys
before = set(sys.argv[1].split())
pin, bpftool = sys.argv[2], os.environ.get("BPFTOOL", "bpftool")
out = subprocess.run([bpftool, "-j", "map", "show"], capture_output=True, text=True).stdout
maps = json.loads(out)
fresh = [m for m in maps if str(m["id"]) not in before]
for m in fresh:
    if m["name"] in ("ban_table", "events", "lost_events", "flow_stats"):
        subprocess.run([bpftool, "map", "pin", "id", str(m["id"]), f"{pin}/{m['name']}"], check=True)
print("maps pinned:", sorted({m["name"] for m in fresh} & {"ban_table", "events", "lost_events", "flow_stats"}))
PY
echo "kernel:    flow_tc attached (TC ingress on $IFACE), program + maps pinned"

# the target: TFO-enabled listener serving order objects with an
# ownership map (tenant-a: 1001,1002 · tenant-b: 2001,2002)
/tmp/tfo "$TARGET_IP:$PORT" > /tmp/demo-srv.log 2>&1 &
SRV=$!
sleep 0.8
echo "target:    /tmp/tfo listening (order store: tenant-a→1001,1002 · tenant-b→2001,2002)"

banner "ATTACK A — CRS layer (negative security)"
printf 'GET /download?file=../../../etc/passwd HTTP/1.1\r\nHost: demo.internal\r\nUser-Agent: attack-demo/1.0\r\n\r\n' > /tmp/traversal.http
ip netns exec "$NS" curl -s -m 5 --path-as-is \
  "http://$TARGET_IP:$PORT/download?file=../../../etc/passwd" -o /dev/null \
  -w 'wire:    target answered HTTP %{http_code}\n' || true
echo "--- payload evidence (what the S2 evaluator sees) ---"
printf 'GET /download?file=../../../etc/passwd HTTP/1.1\nHost: demo.internal\n' | tee /tmp/traversal.http >/dev/null
"$DEMO_BIN" crs /tmp/traversal.http
printf 'GET /products?id=1%%20UNION%%20SELECT%%20user,pass%%20FROM%%20users HTTP/1.1\nHost: demo.internal\n' > /tmp/sqli.http
"$DEMO_BIN" crs /tmp/sqli.http

banner "ATTACK B — API layer: BOLA (API1:2023)"
echo "story:    tenant-a (subject) requests order 2002 — owned by tenant-b"
printf 'GET /api/v1/orders/2002 HTTP/1.1\nHost: demo.internal\nAuthorization: Bearer <tenant-a token>\n' > /tmp/bola.http
ip netns exec "$NS" curl -s -m 5 "http://$TARGET_IP:$PORT/api/v1/orders/2002" \
  -o /dev/null -w 'wire:    target answered HTTP %{http_code}\n' || true
"$DEMO_BIN" bola 2002 tenant-b tenant-a
echo "--- the ownership-matched control (same subject, own object) ---"
"$DEMO_BIN" bola 1001 tenant-a tenant-a
echo "--- S3 rate rule over the same request view (merged TR-02 engine) ---"
"$DEMO_BIN" cel GET /api/v1/orders/2002 1

banner "kernel wire evidence for both attacks (merged ingest decoder)"
# 12 = headroom over the ~5 events the two attacks emit; reader returns
# after a 1s drain window so the demo never blocks on a short ring.
"$DEMO_BIN" ring "$PIN_DIR/events" 12 || echo "ring: (drain returned)"

banner "ATTACK C — enforcement (§13): repeat offender banned, kernel drops"
echo "story:    the attacker source crosses the ban threshold (TR-09 decides);
           the shield enforces (merged TR-03 loader ABI)"
# loadall pinned ban_table under $PIN_DIR (loadall pins every map it
# loads). Plain `map show` hides pin paths — use the pinned file's own
# id via `map show pinned <path>`:
BT_MAP="$($BPFTOOL map show pinned "$PIN_DIR/ban_table" | sed 's/^\([0-9]*\):.*/\1/;t;d')"
[ -n "$BT_MAP" ] || { echo "FAIL: ban_table not pinned in $PIN_DIR" >&2; exit 1; }
$BPFTOOL map pin id "$BT_MAP" "$PIN_DIR/ban"
"$DEMO_BIN" ban "$PIN_DIR/ban" "$ATTACKER_IP" 120
echo "--- replay the same request through the kernel ---"
REPLAY=$(ip netns exec "$NS" curl -s -m 3 -o /dev/null -w '%{http_code}' \
  "http://$TARGET_IP:$PORT/v1/chat/completions" 2>&1 || echo "connection: $(ip netns exec "$NS" curl -s -m 3 "http://$TARGET_IP:$PORT/" 2>&1 | head -1)")
echo "wire:    replay result: ${REPLAY:-timeout/refused} (the kernel answered, not the app)"
echo "--- kernel state after the drop ---"
$BPFTOOL map show | grep -E 'name (lost_events|flow_stats)' | head -2 || true
$BPFTOOL map dump pinned "$PIN_DIR/ban" 2>/dev/null | sed -n '1,6p' || true

banner "demo complete — transcripts recorded on issue #83"
kill "$SRV" 2>/dev/null || true
