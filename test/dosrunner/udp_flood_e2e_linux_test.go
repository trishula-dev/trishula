//go:build linux

package dosrunner

// TR-203 L1 (issue #264, pulled from #242 leaf 1): the UDP flood leg on
// the XDP side. The chain: the knob row (shield_knobs[0]) arms the leg;
// the rate_windows rows count the per-source datagrams over the knob's
// window; the count past the knob = XDP_DROP (the tarpit action at
// this altitude). The payload = the QUIC posture: encrypted-looking
// bytes, no request view (fact F3; probe P1: the QUIC-load leg).
//
// Phases: A the armed flood drops (recv <= 60 of 500; the tarpit drop
// ticks >= 150), B the disarm re-opens (the knob row deleted; recv
// >= 200 — the fail-open default proven from the knob side), C the ban
// kill (a live ban_table row drops the burst outright; the ban-table
// reuse).
//
// Watched RED first (the RED half of the pair): the pre-L1 shield
// object carries no knob map, the knob write fails and the leg cannot
// arm.

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type shieldKnobKey struct {
	Zeros uint32
}

type shieldKnobVal struct {
	UDPFloodPPS uint32
	_           uint32
	WindowNS    uint64
}

// udpFloodInject = one burst: N datagrams as fast as the raw socket
// takes them (the flood's shape), then one trailing report line.
const udpFloodInject = `import socket,struct,sys
n=int(sys.argv[1])
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
s.bind(("tr195n0",0x0800))
dmac=b"\x02\x00\xde\xad\xbe\xef"
smac=b"\x02\x00\xaa\xbb\xcc\xdd"
def frame():
    pay=b"\x00\x03\x00\xfe\x10\xca\xde\xad" + b"\x77"*16
    eth=struct.pack("!6s6sH",dmac,smac,0x0800)
    iph=struct.pack("!BBHHHBBH4s4s",0x45,0,20+8+len(pay),1,0,64,17,0,socket.inet_aton("10.77.0.66"),socket.inet_aton("10.77.0.1"))
    udph=struct.pack("!HHHH",6666,9440,8+len(pay),0)
    return eth+iph+udph+pay
sent=0
for i in range(n):
    s.send(frame()); sent+=1
print("udp-flood-%d-ok"%sent)`

// udpRecvProbe listens on the host veth's UDP 9440 for w seconds and
// prints "recv-count N". The receiver runs in the HOST ns: the
// datagrams that passed XDP land here (the kernel-drop readback).
const udpRecvProbe = `import socket,time,sys
w=int(sys.argv[1])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("10.77.0.1",9440))
s.settimeout(0.3)
end=time.time()+w
n=0
while time.time()<end:
    try:
        s.recvfrom(2048)
        n+=1
    except socket.timeout:
        pass
print("recv-count %d"%n)`

// statsSum195 reads one per-CPU counter key and sums the CPUs (the
// banenforce harness's percpuStat shape, local to this package).
func statsSum195(t *testing.T, m *ebpf.Map, key uint32) uint64 {
	t.Helper()
	var vals []uint64
	if err := m.Lookup(&key, &vals); err != nil {
		return 0 // untouched per-CPU key = zero
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total
}

// driveFlood195 runs the receiver (the host ns) and the flood burst
// (the offender netns) together; the datagrams that passed XDP land in
// the receiver. Returns the receiver's count.
func driveFlood195(t *testing.T, burst int) (recv int) {
	t.Helper()
	rcv := exec.Command("python3", "-c", udpRecvProbe, "3")
	if serr := rcv.Start(); serr != nil {
		t.Skipf("the receiver: %v", serr)
	}
	time.Sleep(600 * time.Millisecond)
	cout, cerr := run195outNS("ip", "netns", "exec", ns195, "python3", "-c", udpFloodInject, strconv.Itoa(burst))
	if cerr != nil {
		t.Skipf("the flood drive:\n%s", cout)
	}
	if !strings.Contains(cout, "ok") {
		t.Fatalf("the flood drive did not complete:\n%s", cout)
	}
	_ = rcv.Wait() // the receiver self-times out at 3 s
	out, rerr := rcv.CombinedOutput()
	_ = rerr
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "recv-count") {
			line = l
		}
	}
	n, perr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "recv-count ")))
	if perr != nil {
		t.Fatalf("the receiver printed no count (%q): %v", line, out)
	}
	return n
}

// TestUDPFloodTarpitE2E = #242 leaf 1's XDP acceptance: the armed knob
// holds the flood at the tarpit; the disarm re-opens; the ban row
// kills the burst outright.
func TestUDPFloodTarpitE2E(t *testing.T) {
	mustRoot195(t)
	cleanup195(t)

	run195(t, "ip", "netns", "add", ns195)
	defer cleanup195(t)
	run195(t, "ip", "link", "add", veth195, "type", "veth", "peer", "name", nsDev)
	// The host veth's MAC: the drive's frames carry the pinned dmac
	// (02:00:de:ad:be:ef in the inject script); the receiver's socket
	// sees only frames the IP stack accepts.
	run195(t, "ip", "link", "set", "dev", veth195, "address", "02:00:de:ad:be:ef")
	run195(t, "ip", "link", "set", nsDev, "netns", ns195)
	run195(t, "ip", "addr", "add", v4195, "dev", veth195)
	run195(t, "ip", "link", "set", veth195, "up")
	run195(t, "ip", "netns", "exec", ns195, "ip", "addr", "add", nsV4195, "dev", nsDev)
	run195(t, "ip", "netns", "exec", ns195, "ip", "link", "set", nsDev, "up")

	shieldspec, err := loadUdp_shield()
	if err != nil {
		t.Fatalf("bpf2go shield load: %v", err)
	}
	shieldColl, err := ebpf.NewCollection(shieldspec)
	if err != nil {
		t.Fatalf("shield collection (verifier): %v", err)
	}
	defer shieldColl.Close()
	if mk := os.MkdirAll(pin195, 0o700); mk != nil {
		t.Skipf("pin dir: %v", mk)
	}
	if perr := shieldColl.Programs["shield_xdp"].Pin(pinShield); perr != nil {
		t.Fatalf("shield prog pin: %v", perr)
	}
	run195(t, "ip", "link", "set", "dev", veth195, "xdp", "pinned", pinShield)

	// The knob push: the leg's switch row (the map row carries the
	// threshold and the window; the kernel owns the count and the
	// drop — the engine-published shape the ban and the ACL rows use).
	knobs := shieldColl.Maps["shield_knobs"]
	if knobs == nil {
		t.Fatalf("TR-203 L1 RED: the shield object carries no knob map — the flood leg cannot arm")
	}
	var knobVal shieldKnobVal
	knobVal.UDPFloodPPS = 20
	knobVal.WindowNS = 1_000_000_000
	if perr := knobs.Put(&shieldKnobKey{}, &knobVal); perr != nil {
		t.Fatalf("TR-203 L1 RED: the knob push failed (%v)", perr)
	}
	t.Logf("knob pushed: udp_flood_pps=%d window_ns=%d", knobVal.UDPFloodPPS, knobVal.WindowNS)
	statsMap := shieldColl.Maps["shield_stats"]
	if statsMap == nil {
		t.Fatalf("TR-203 L1 RED: the shield object carries no verdict counter map — the drop readback cannot arm")
	}

	// --- phase A: the armed tarpit holds the flood -------------------
	baseDrops := statsSum195(t, statsMap, 0)
	recv := driveFlood195(t, 500)
	if recv > 60 {
		t.Fatalf("TR-203 L1 RED: the flood passed %d of 500 (no tarpit: recv must fit the knob ceiling)", recv)
	}
	drops := statsSum195(t, statsMap, 0)
	if drops < baseDrops+150 {
		t.Errorf("tarpit drop ticks %d -> %d, want >= 150 ticks", baseDrops, drops)
	}
	t.Logf("phase A: the armed tarpit held the flood (recv=%d of 500; drop ticks %d -> %d)", recv, baseDrops, drops)

	// --- phase B: the disarm re-opens (the fail-open default) -------
	if derr := knobs.Delete(&shieldKnobKey{}); derr != nil {
		t.Fatalf("disarm delete: %v", derr)
	}
	recv = driveFlood195(t, 300)
	if recv < 200 {
		t.Errorf("phase B: the disarmed leg dropped %d of 300 — the knob's absence must open the path", 300-recv)
	}
	t.Logf("phase B: the disarmed leg passed the flood (recv=%d of 300)", recv)

	// --- phase C: the ban kill (the ban-table reuse) -----------------
	offender := shotBanKey{Family: kafInet, KeyClass: 0}
	offender.Addr.V4 = udpSaddrLE
	var banVal shotBanVal
	banVal.UntilTS = kernelNowNS195(t) + uint64(10*time.Second)
	banVal.Tier = 1
	banVal.ReasonCode = 42
	if perr := shieldColl.Maps["ban_table"].Put(&offender, &banVal); perr != nil {
		t.Fatalf("ban push: %v", perr)
	}
	recv = driveFlood195(t, 50)
	if recv != 0 {
		t.Errorf("phase C: the banned burst passed %d of 50 — the ban row did not kill the UDP flow", recv)
	}
	t.Log("TR-203 L1 XDP leg GREEN: the armed tarpit holds; the disarm opens; the ban row kills")
}
