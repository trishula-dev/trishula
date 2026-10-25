//go:build linux

package dosrunner

// TR-203 L1 (issue #264, pulled from #242): the ban-push leg on the UDP
// flow rows. The push = a live ban_table row for the source (the loader
// producer ABI's row shape: internal/shield/bans.go + banwire_test.go
// pin the layout). The TC UDP walk SHOTs the datagrams while the ban
// holds (until_ts > now); after the expiry (now >= until_ts) the walk
// passes them again — the row goes stale, it never re-shots, the LRU
// evicts lazily. The drive = raw AF_PACKET datagrams from the offender
// netns (the same posture as the flow-row contract test).
//
// Watched RED first (the RED half of the pair): the pre-L1 collection
// carries no UDP ban probe — the during-ban datagrams get counted and
// the first assert fires.

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type shotBanKey struct {
	Addr struct {
		V4 uint32
		_  [12]byte
	}
	Family   uint8
	KeyClass uint8
	_        [2]byte
}

type shotBanVal struct {
	UntilTS    uint64
	Tier       uint8
	Pad        uint8
	ReasonCode uint16
	_          uint32
}

// udpShotInject = one burst leg: N datagrams from the offender source,
// 0.4 s apart, on the same wire the flow-row drive uses.
const udpShotInject = `import socket,struct,sys,time
n=int(sys.argv[1])
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
s.bind(("tr195n0",0x0800))
dmac=b"\x02\x00\xde\xad\xbe\xef"
smac=b"\x02\x00\xaa\xbb\xcc\xdd"
def frame():
    pay=b"quicprobe"
    eth=struct.pack("!6s6sH",dmac,smac,0x0800)
    iph=struct.pack("!BBHHHBBH4s4s",0x45,0,20+8+len(pay),1,0,64,17,0,socket.inet_aton("10.77.0.66"),socket.inet_aton("10.77.0.1"))
    udph=struct.pack("!HHHH",6666,9440,8+len(pay),0)
    return eth+iph+udph+pay
for i in range(n):
    s.send(frame()); time.sleep(0.4)
print("udp-shot-ok")`

// kernelNowNS195 reads CLOCK_MONOTONIC in ns — the clock of the
// ban_value's until_ts (bpf_ktime_get_ns parity).
func kernelNowNS195(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("clock_gettime: %v", err)
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// TestUDPBanExpiryRows = the ban-push contract: a live ban SHOTs the
// offender's datagrams (the flow row stays absent); the expiry re-opens
// the walk (the rows count again; the stale row reads expired).
func TestUDPBanExpiryRows(t *testing.T) {
	mustRoot195(t)
	cleanup195(t)

	run195(t, "ip", "netns", "add", ns195)
	defer cleanup195(t)
	run195(t, "ip", "link", "add", veth195, "type", "veth", "peer", "name", nsDev)
	run195(t, "ip", "link", "set", nsDev, "netns", ns195)
	run195(t, "ip", "addr", "add", v4195, "dev", veth195)
	run195(t, "ip", "link", "set", veth195, "up")
	run195(t, "ip", "netns", "exec", ns195, "ip", "addr", "add", nsV4195, "dev", nsDev)
	run195(t, "ip", "netns", "exec", ns195, "ip", "link", "set", nsDev, "up")

	flowspec, err := loadFlow_dos()
	if err != nil {
		t.Fatalf("bpf2go flow load: %v", err)
	}
	flowColl, err := ebpf.NewCollection(flowspec)
	if err != nil {
		t.Fatalf("flow collection (verifier): %v", err)
	}
	defer flowColl.Close()
	if mk := os.MkdirAll(pin195, 0o700); mk != nil {
		t.Skipf("pin dir: %v", mk)
	}
	if perr := flowColl.Programs["tc_ingress_waf"].Pin(pinFlow); perr != nil {
		t.Fatalf("flow prog pin: %v", perr)
	}
	if perr := flowColl.Maps["flow_stats"].Pin(pinStat); perr != nil {
		t.Fatalf("flow_stats pin: %v", perr)
	}
	run195(t, "tc", "qdisc", "replace", "dev", veth195, "clsact")
	run195(t, "tc", "filter", "replace", "dev", veth195, "ingress", "bpf", "da", "pinned", pinFlow)

	// Phase 0, the pre-ban sanity: one datagram passes and the walk
	// counts it. This row is the baseline the ban leg reads against.
	cout, cerr := run195outNS("ip", "netns", "exec", ns195, "python3", "-c", udpShotInject, "1")
	if cerr != nil {
		t.Skipf("the UDP drive:\n%s", cout)
	}
	if !strings.Contains(cout, "udp-shot-ok") {
		t.Fatalf("the pre-ban drive did not complete:\n%s", cout)
	}
	time.Sleep(300 * time.Millisecond)

	stats := flowColl.Maps["flow_stats"]
	baseline := udpRowSegCount(t, stats)
	if baseline == 0 {
		t.Fatalf("TR-203 L1 RED: no flow row for the UDP flow (the TC walk carries TCP only; the ban leg has no basis)")
	}
	t.Logf("pre-ban: the walk counts the offender row (base segs=%d)", baseline)

	// The ban push: one live row for the offender source (family 4,
	// key_class 0 = the table's IP class).
	var bk shotBanKey
	bk.Addr.V4 = udpSaddrLE
	bk.Family = kafInet
	bk.KeyClass = 0
	var bv shotBanVal
	bv.UntilTS = kernelNowNS195(t) + uint64(2*time.Second)
	bv.Tier = 1
	bv.ReasonCode = 42
	banTable := flowColl.Maps["ban_table"]
	if put := banTable.Put(&bk, &bv); put != nil {
		t.Fatalf("ban push: %v (the row shape is the Go mirror's: 20B key, 16B val)", put)
	}
	t.Logf("ban pushed: until_ns=%d (now=%d)", bv.UntilTS, kernelNowNS195(t))

	// The during phase: the ban holds; the SHOT keeps the baseline row
	// frozen (no counted datagram passes a live ban).
	cout, cerr = run195outNS("ip", "netns", "exec", ns195, "python3", "-c", udpShotInject, "3")
	if cerr != nil {
		t.Skipf("the during-ban drive:\n%s", cout)
	}
	if !strings.Contains(cout, "udp-shot-ok") {
		t.Fatalf("the during-ban drive did not complete:\n%s", cout)
	}
	time.Sleep(300 * time.Millisecond)
	if segs := udpRowSegCount(t, stats); segs != baseline {
		t.Fatalf("TR-203 L1 RED: the live ban left %d of %d counted datagrams (the UDP walk has no ban probe)", segs-baseline, 3)
	}
	t.Log("during phase: the live ban SHOTs the datagrams (the row stays frozen)")

	// The expiry: now >= until_ts. The rows count again; the stale ban
	// row never re-shots (the LRU evicts lazily).
	time.Sleep(2_600 * time.Millisecond)
	cout, cerr = run195outNS("ip", "netns", "exec", ns195, "python3", "-c", udpShotInject, "3")
	if cerr != nil {
		t.Skipf("the UDP drive (post-expiry):\n%s", cout)
	}
	if !strings.Contains(cout, "udp-shot-ok") {
		t.Fatalf("the post-expiry drive did not complete:\n%s", cout)
	}
	time.Sleep(300 * time.Millisecond)

	segs, bytes := udpRowSegCount(t, stats), udpRowReqBytes(t, stats)
	if segs == baseline {
		t.Fatal("post-expiry drive counted nothing — the walk still SHOTs past until_ts")
	}
	if segs < baseline+2 {
		t.Errorf("post-expiry row seg_count = %d, want >= %d (base + 2 of the 3 driven)", segs, baseline+2)
	}
	if bytes < baseline*9+18 {
		t.Errorf("post-expiry row req_bytes = %d, want >= %d (base + 2 datagrams at 9 bytes)", bytes, baseline*9+18)
	}

	// The expiry readback: the stale row sits in the table, until_ts
	// reads in the past, and the datagrams pass anyway.
	var stale shotBanVal
	if lk := banTable.Lookup(&bk, &stale); lk != nil {
		t.Fatalf("the pushed ban row vanished before the LRU pressure (lookup: %v)", lk)
	}
	if stale.UntilTS > kernelNowNS195(t) {
		t.Fatalf("the ban reads unexpired at now=%d: until_ts=%d", kernelNowNS195(t), stale.UntilTS)
	}
	t.Log("TR-203 L1 ban leg GREEN: live ban SHOTs the rows; expiry re-opens the walk; the stale row reads expired")
}

// udpRowSegCount reads the offender flow row's seg_count (0 = absent).
func udpRowSegCount(t *testing.T, m *ebpf.Map) uint32 {
	t.Helper()
	return readUDPRow(t, m, func(v *udpFlowStat) uint32 { return v.SegCount })
}

// udpRowReqBytes reads the offender flow row's req_bytes (0 = absent).
func udpRowReqBytes(t *testing.T, m *ebpf.Map) uint32 {
	t.Helper()
	return readUDPRow(t, m, func(v *udpFlowStat) uint32 { return v.ReqBytes })
}

func readUDPRow(t *testing.T, m *ebpf.Map, pick func(*udpFlowStat) uint32) uint32 {
	t.Helper()
	it := m.Iterate()
	var k udpFlowKey
	var v udpFlowStat
	for it.Next(&k, &v) {
		if k.Family == kafInet && k.Saddr.A4 == udpSaddrLE {
			return pick(&v)
		}
	}
	if err := it.Err(); err != nil {
		t.Fatalf("flow_stats walk: %v", err)
	}
	return 0
}
