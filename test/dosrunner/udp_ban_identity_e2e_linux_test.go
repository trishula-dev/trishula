//go:build linux

package dosrunner

// TR-203 L2 (issue #264, leaf L2; the record = TR-29): probe P7, the ban
// identity for the QUIC/H3 hop. The record's fact F3 names the kernel's
// reading: QUIC traffic meets these classes as UDP. The ban table keys
// the source address alone (bpf/shield_xdp.c, struct ban_key: addr +
// family, no port, no connection id). The probe measures exactly that
// identity, on the L1 UDP leg (issues #242/#264):
//
//   leg A  the identity read: the h3 hop's flow classed as its UDP class
//          — a live ban row SHOTs the keyed source's datagrams (the row
//          reads the kernel ban_table; the L1 leg carried the shape).
//   leg B  the migration leg: the same QUIC-class datagram flow
//          re-addresses (a second source on the same probe net) and the
//          datagrams PASS while the row stays live. The row never covers
//          the re-addressed stream: the kernel reads no QUIC connection
//          id — the record's N7 boundary, now measured (the gap rows
//          file by PR with the recorded run).
//
// Watched RED note: this test pins the live L1 contract; its first run
// reads GREEN by design (the identity semantics already ship on main).
// The RED state of the leaf = the record's PENDING rows for P7 (the
// absent leg), recorded on issue #264. The pin exists so the identity
// boundary drifts only through a deliberate, spec-cited change.

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// saddr77LE = the LE readback of the migration source 10.77.0.77 (the
// same probe net; the second address the re-addressed stream uses).
const saddr77LE = uint32(77<<24 | 77<<8 | 10)

// udpIdentityInject = one QUIC-class datagram burst from a picked source.
// The frame shape = the flow-row drive's (the L1 leg): one IP/UDP frame,
// 9-byte payload, the source and the count on the argv. The source port
// holds the same fixed value for both drives: the identity under test =
// the address (the migration changes the address, not the class).
const udpIdentityInject = `import socket,struct,sys,time
src=sys.argv[1]
n=int(sys.argv[2])
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
s.bind(("tr195n0",0x0800))
dmac=b"\x02\x00\xde\xad\xbe\xef"
smac=b"\x02\x00\xaa\xbb\xcc\xdd"
def frame():
    pay=b"quicprobe"
    eth=struct.pack("!6s6sH",dmac,smac,0x0800)
    iph=struct.pack("!BBHHHBBH4s4s",0x45,0,20+8+len(pay),1,0,64,17,0,socket.inet_aton(src),socket.inet_aton("10.77.0.1"))
    udph=struct.pack("!HHHH",7777,9440,8+len(pay),0)
    return eth+iph+udph+pay
for i in range(n):
    s.send(frame()); time.sleep(0.4)
print("udp-identity-ok", src, n)`

// udpRowSegCountFor reads the flow row's seg_count for one source (0 =
// the row stays absent). The readUDPRow helper pins this file's sibling
// to the one offender source; the migration leg reads two.
func udpRowSegCountFor(t *testing.T, m *ebpf.Map, saddrLE uint32) uint32 {
	t.Helper()
	it := m.Iterate()
	var k udpFlowKey
	var v udpFlowStat
	for it.Next(&k, &v) {
		if k.Family == kafInet && k.Saddr.A4 == saddrLE {
			return v.SegCount
		}
	}
	if err := it.Err(); err != nil {
		t.Fatalf("flow_stats walk: %v", err)
	}
	return 0
}

// identityDrive = one paced burst from one source inside the netns.
func identityDrive(t *testing.T, src string, n int) {
	t.Helper()
	cout, cerr := run195outNS("ip", "netns", "exec", ns195, "python3", "-c", udpIdentityInject, src, fmt.Sprintf("%d", n))
	if cerr != nil {
		t.Skipf("the identity drive (src=%s):\n%s", src, cout)
	}
	if !strings.Contains(cout, "udp-identity-ok") {
		t.Fatalf("the identity drive (src=%s) did not complete:\n%s", src, cout)
	}
}

// TestUDPBanIdentityRows = probe P7 on the L1 UDP leg: the live ban row
// reads the keyed source's QUIC-class flow (leg A) and never covers the
// re-addressed stream (leg B) — the source-key identity the record's
// §13.3 ban path pins for v0.
func TestUDPBanIdentityRows(t *testing.T) {
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
	// The migration source: the second address the re-addressed stream uses.
	run195(t, "ip", "netns", "exec", ns195, "ip", "addr", "add", "10.77.0.77/24", "dev", nsDev)

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

	// Phase 0, the baseline: the keyed source's row counts one datagram.
	identityDrive(t, "10.77.0.66", 1)
	time.Sleep(300 * time.Millisecond)
	stats := flowColl.Maps["flow_stats"]
	baseline := udpRowSegCountFor(t, stats, udpSaddrLE)
	if baseline != 1 {
		t.Fatalf("baseline row seg_count = %d, want 1 (the drive's one datagram)", baseline)
	}
	t.Logf("baseline: the keyed source's row counts the datagram (segs=%d)", baseline)

	// The ban push: one live row for the keyed source — the h3 hop's ban
	// identity row (family 4, key_class 0 = the table's IP class). The
	// TTL stays past both drives so the leg B pass reads the LIVE row,
	// never an expired one.
	var bk shotBanKey
	bk.Addr.V4 = udpSaddrLE
	bk.Family = kafInet
	bk.KeyClass = 0
	var bv shotBanVal
	bv.UntilTS = kernelNowNS195(t) + uint64(15*time.Second)
	bv.Tier = 1
	bv.ReasonCode = 42
	banTable := flowColl.Maps["ban_table"]
	if put := banTable.Put(&bk, &bv); put != nil {
		t.Fatalf("ban push: %v", put)
	}
	t.Logf("ban pushed: until_ns=%d (now=%d)", bv.UntilTS, kernelNowNS195(t))

	// Leg A: the h3 hop's datagrams meet the live row. The keyed
	// source's datagrams drop; the row never grows again.
	identityDrive(t, "10.77.0.66", 2)
	time.Sleep(300 * time.Millisecond)
	if segs := udpRowSegCountFor(t, stats, udpSaddrLE); segs != baseline {
		t.Fatalf("leg A RED: the live ban left %d of %d datagrams pass for the keyed source (the ban read has no identity probe)", segs-baseline, 2)
	}
	t.Log("leg A: the live ban row SHOTs the keyed source's QUIC-class flow (the h3 hop's ban read)")

	// Leg B: the migration shape. The same QUIC-class flow re-addresses
	// (source 10.77.0.77). The row keys one source: the re-addressed
	// stream passes while the row stays live, and the keyed source's
	// row never moves.
	identityDrive(t, "10.77.0.77", 2)
	time.Sleep(300 * time.Millisecond)
	migrated := udpRowSegCountFor(t, stats, saddr77LE)
	if migrated < 1 {
		t.Fatalf("leg B: the re-addressed stream counted nothing (want the pass; the row keys one source per key)")
	}
	if segs := udpRowSegCountFor(t, stats, udpSaddrLE); segs != baseline {
		t.Fatalf("leg B: the keyed source's row moved to %d while the migration read ran", segs)
	}
	var live shotBanVal
	if lk := banTable.Lookup(&bk, &live); lk != nil {
		t.Fatalf("the pushed ban row vanished mid-leg (lookup: %v)", lk)
	}
	if live.UntilTS <= kernelNowNS195(t) {
		t.Fatalf("the ban row expired inside the probe (until_ts=%d now=%d) — leg B would read the expiry, not the identity gap", live.UntilTS, kernelNowNS195(t))
	}
	t.Log("TR-203 L2 ban identity GREEN: the row SHOTs its keyed source at the h3 hop; the re-addressed stream passes while the row stays live — one source per key, no connection-id bind (the record's N7 gap, measured)")
}
