//go:build linux

package dosrunner

// TR-203 L1 (issue #264, pulled from #242): the UDP leg of the TC flow
// accounting. The contract test FIRST: a paced UDP stream from an offender
// netns leaves flow_stats rows (the datagram count, the byte count, the
// window stamps). The TC hook never enforces on them at this leaf (the
// enforcement = the XDP class's next leaf; probe P1's seed).

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// udpSaddrLE = the LE readback of the offender source 10.77.0.66: the
// union bytes land [0a 4d 00 42], the LE u32 = 0x42004d0a; the TR-31
// e2e pins the direction. kafInet = the wire family value the C writes
// for IPv4 rows (the flow_key KEY_AF_INET constant).
const (
	udpSaddrLE = uint32(66<<24 | 77<<8 | 10)
	kafInet    = uint8(4)
)

type udpFlowKey struct {
	Saddr struct {
		A4 uint32
		_  [12]byte
	}
	Daddr struct {
		V4 uint32
		_  [12]byte
	}
	Sport  uint16
	Dport  uint16
	Family uint8
	_      [3]byte
}

type udpFlowStat struct {
	SynTs      uint64
	FirstSegTs uint64
	LastSegTs  uint64
	ReqBytes   uint32
	SegCount   uint32
}

// pacedUDPInject = 30 UDP datagrams, 1.1 s apart, one flow (33 s total).
// The bind matches nsDev = "tr195n0".
const pacedUDPInject = `import socket,struct,time
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
for i in range(30):
    s.send(frame()); time.sleep(1.1)
print("udp-30-ok")`

func TestUDPFlowStatsRows(t *testing.T) {
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

	inject := pacedUDPInject
	cout, cerr := run195outNS("ip", "netns", "exec", ns195, "python3", "-c", inject)
	if cerr != nil {
		t.Skipf("the paced UDP drive:\n%s", cout)
	}
	if !strings.Contains(string(cout), "udp-30-ok") {
		t.Fatalf("the UDP drive did not complete:\n%s", cout)
	}
	time.Sleep(300 * time.Millisecond)

	// the readback: the offender row = seg_count >= 24 (of the 30
	// driven), req_bytes >= 216, the span >= 30 s. The row exists ONLY
	// when the UDP slice walks the TC hook (the RED step asserts this).
	stats := flowColl.Maps["flow_stats"]
	it := stats.Iterate()
	var k udpFlowKey
	var v udpFlowStat
	rows, gotSegs := 0, 0
	for it.Next(&k, &v) {
		rows++
		if testing.Verbose() {
			t.Logf("row: fam=%d saddr=%#08x sp=%d dp=%d bytes=%d segs=%d",
				k.Family, k.Saddr.A4, k.Sport, k.Dport, v.ReqBytes, v.SegCount)
		}
		if k.Family == kafInet && k.Saddr.A4 == udpSaddrLE {
			gotSegs = int(v.SegCount)
			if v.ReqBytes < 24*9 {
				t.Errorf("UDP row req_bytes = %d, want >= 216", v.ReqBytes)
			}
			if span := int64(v.LastSegTs-v.FirstSegTs) / 1e9; span < 30 {
				t.Errorf("UDP row span = %d s, want >= 30", span)
			}
		}
	}
	if it.Err() != nil {
		t.Fatalf("flow_stats walk: %v", it.Err())
	}
	if gotSegs == 0 {
		t.Fatalf("TR-203 L1 RED: %d flow_stats rows exist, none for the UDP flow (the TC walk carries TCP only)", rows)
	}
	if gotSegs < 24 {
		t.Errorf("UDP row seg_count = %d, want >= 24 of the 30 driven", gotSegs)
	}
}

// run195outNS = the netns command wrapper returning the combined output.
func run195outNS(args ...string) (string, error) {
	c := exec.Command(args[0], args[1:]...)
	out, err := c.CombinedOutput()
	return string(out), err
}
