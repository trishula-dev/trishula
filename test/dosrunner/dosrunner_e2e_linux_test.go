//go:build linux

package dosrunner

// TR-195 (issue #237) in-VM runner acceptance — issue #253. The kernel
// path of the shield DoS runner on a live Linux VM (OrbStack
// trishula-build-dev, arm64):
//
//	sudo go test -run TestDoSRunnerE2E ./test/dosrunner/ -v
//
// The chain under test: the paced slowloris flow (30 frames, 8 bytes per
// segment, a 34+ s span) lands in the pinned flow_stats map through the
// real tc_ingress_waf program → DosRunner.Sweep() forms the cue from the
// map row → 4 sweeps cross the scored threshold (kernelBurstFlag, 3
// points per cue) → the enforcer publishes the bans_v4 row → the
// offender's traffic dies at XDP → the evidence JSONL carries the
// would-ban with the dynamic signature matching the map facts.
//
// Attach pattern: the programs pin with the ebpf API and attach with
// `ip link set dev X xdp pinned` and `tc filter replace ... bpf da
// pinned` (the TR-04d/TR-10 pinned pattern; a bpf_link attach misses
// post-ban traffic on this stack).

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/trishula-dev/trishula/internal/shield"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native flow_dos ../../bpf/flow_tc.c -- -I../../bpf -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native ban_dos ../../bpf/ban_xdp.c -- -I../../bpf -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native udp_shield ../../bpf/shield_xdp.c -- -I../../bpf -O2 -g

const (
	ns195     = "tr195dos"
	veth195   = "tr195h0"
	nsDev     = "tr195n0"
	nsV4195   = "10.77.0.66/24"
	v4195     = "10.77.0.1/24"
	off195    = "10.77.0.66"
	host195   = "10.77.0.1"
	pin195    = "/sys/fs/bpf/tr195"
	pinFlow   = "/sys/fs/bpf/tr195/flow_tc"
	pinStat   = "/sys/fs/bpf/tr195/flow_stats"
	pinBan    = "/sys/fs/bpf/tr195/ban_xdp"
	pinBans   = "/sys/fs/bpf/tr195/bans_v4"
	pinShield = "/sys/fs/bpf/tr195/shield_xdp"
	ev195     = "/tmp/tr195/dos_runner_evidence.jsonl"
)

func mustRoot195(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("runner e2e needs root (XDP + netns + map access)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("no BTF at /sys/kernel/btf/vmlinux")
	}
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skip("no bpffs mounted")
	}
}

func run195(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Skipf("%v: %v (host lacks the facility?)\n%s", args[:3], err, out)
	}
	return string(out)
}

func cleanup195(t *testing.T) {
	t.Helper()
	_ = os.Remove(pinFlow)
	_ = os.Remove(pinStat)
	_ = os.Remove(pinBan)
	_ = os.Remove(pinBans)
	_ = os.Remove(pinShield)
	_ = exec.Command("ip", "netns", "del", ns195).Run()
	_ = exec.Command("ip", "link", "del", veth195).Run()
}

// ping195 sends one ICMP echo from the offender netns; true = answered =
// the packet passed the XDP program.
func ping195(t *testing.T) bool {
	t.Helper()
	return exec.Command("ip", "netns", "exec", ns195, "ping", "-c", "1", "-W", "1", host195).Run() == nil
}

func kernelNowMS195(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("clock_gettime: %v", err)
	}
	return uint64(ts.Sec)*1_000 + uint64(ts.Nsec)/1_000_000
}

// pacedInject95 = the slowloris trickle: 30 frames, 9 bytes of payload
// per segment, 1.15 s apart (the span crosses the detector's 30 s window
// leg, 8 bytes/seg after the header accounting).
const pacedInject95 = `import socket,struct,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
s.bind(("tr195n0",0x0800))
dmac=b"\x02\x00\xde\xad\xbe\xef"
smac=b"\x02\x00\xaa\xbb\xcc\xdd"
def frame(seq):
    pay=b"slowloris"
    eth=struct.pack("!6s6sH",dmac,smac,0x0800)
    iph=struct.pack("!BBHHHBBH4s4s",0x45,0,20+20+len(pay),1,0,64,6,0,socket.inet_aton("10.77.0.66"),socket.inet_aton("10.77.0.1"))
    tcph=struct.pack("!HHIIBBHHH",6666,9440,seq,0,(5<<4),0x18,1024,0,0)
    return eth+iph+tcph+pay
seq=1000
for i in range(30):
    s.send(frame(seq)); seq+=len(b"slowloris"); time.sleep(1.15)
print("paced-30-ok")`

// TestDoSRunnerE2E is issue #253's acceptance: the map → the sweep → the
// kernel row → the replay dies.
func TestDoSRunnerE2E(t *testing.T) {
	mustRoot195(t)
	cleanup195(t)
	// --- setup: netns + veth ------------------------------------------
	run195(t, "ip", "netns", "add", ns195)
	defer cleanup195(t)
	run195(t, "ip", "link", "add", veth195, "type", "veth", "peer", "name", nsDev)
	run195(t, "ip", "link", "set", nsDev, "netns", ns195)
	run195(t, "ip", "addr", "add", v4195, "dev", veth195)
	run195(t, "ip", "link", "set", veth195, "up")
	run195(t, "ip", "netns", "exec", ns195, "ip", "addr", "add", nsV4195, "dev", nsDev)
	run195(t, "ip", "netns", "exec", ns195, "ip", "link", "set", nsDev, "up")

	// --- load both collections; pin programs + maps -------------------
	flowspec, err := loadFlow_dos()
	if err != nil {
		t.Fatalf("bpf2go flow load: %v", err)
	}
	flowColl, err := ebpf.NewCollection(flowspec)
	if err != nil {
		t.Fatalf("flow collection (verifier): %v", err)
	}
	defer flowColl.Close()
	banspec, err := loadBan_dos()
	if err != nil {
		t.Fatalf("bpf2go ban load: %v", err)
	}
	banColl, err := ebpf.NewCollection(banspec)
	if err != nil {
		t.Fatalf("ban collection (verifier): %v", err)
	}
	defer banColl.Close()
	if mkerr := os.MkdirAll(pin195, 0o700); mkerr != nil {
		t.Fatalf("pin dir: %v", mkerr)
	}
	if perr := flowColl.Programs["tc_ingress_waf"].Pin(pinFlow); perr != nil {
		t.Fatalf("flow prog pin: %v", perr)
	}
	if perr := flowColl.Maps["flow_stats"].Pin(pinStat); perr != nil {
		t.Fatalf("flow_stats pin: %v", perr)
	}
	if perr := banColl.Programs["ban_xdp"].Pin(pinBan); perr != nil {
		t.Fatalf("ban prog pin: %v", perr)
	}
	if perr := banColl.Maps["bans_v4"].Pin(pinBans); perr != nil {
		t.Fatalf("bans_v4 pin: %v", perr)
	}

	run195(t, "tc", "qdisc", "replace", "dev", veth195, "clsact")
	run195(t, "tc", "filter", "replace", "dev", veth195, "ingress", "bpf", "da", "pinned", pinFlow)
	run195(t, "ip", "link", "set", "dev", veth195, "xdp", "pinned", pinBan)

	if mkerr := os.MkdirAll("/tmp/tr195", 0o755); mkerr != nil {
		t.Fatalf("ev dir: %v", mkerr)
	}
	// --- the runner over the pinned maps -------------------------------
	runner, err := shield.NewDosRunnerFromPins(pinStat, pinBans)
	if err != nil {
		t.Fatalf("runner from pins: %v", err)
	}
	if aerr := runner.Enf.Sink().AppendFile(ev195); aerr != nil {
		t.Fatalf("evidence file: %v", aerr)
	}
	bansV4 := banColl.Maps["bans_v4"]

	// --- pass phase: pings traverse before the ban ---------------------
	for i := 0; i < 3; i++ {
		if !ping195(t) {
			t.Fatal("the warm-up ping died before any ban (harness broke)")
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Log("pass phase: pings answered before the ban")

	// --- drive the paced slowloris through the tc hook ----------------
	c95 := exec.Command("ip", "netns", "exec", ns195, "python3", "-c", pacedInject95)
	cout, cerr := c95.CombinedOutput()
	if cerr != nil {
		t.Skipf("paced frames need python3 in the netns: %v\n%s", cerr, cout)
	}
	if !strings.Contains(string(cout), "paced-30-ok") {
		t.Fatalf("paced inject did not complete cleanly:\n%s", cout)
	}
	time.Sleep(300 * time.Millisecond)

	// --- 4 sweeps: one cue per sweep; the 4x3 = 12 crosses T = 10 -----
	bansKey, err := shield.BansV4KeyFromIP(mustAddr195(t, off195))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	crossed := false
	var val shield.BansV4Val
	var recOne []byte
	for sweep := 1; sweep <= 4 && !crossed; sweep++ {
		time.Sleep(1_100 * time.Millisecond)
		recs, serr := runner.Sweep()
		if serr != nil {
			t.Fatalf("sweep %d: %v", sweep, serr)
		}
		if len(recs) > 0 {
			crossed = true
			for _, r := range recs {
				if r.OSig == nil {
					t.Fatal("the crossing record carries no signature")
				}
				if r.OSig.Segs < 24 || r.OSig.BytesPerSeg == 0 || r.OSig.BytesPerSeg > 64 || r.OSig.SpanSec < 30 {
					t.Fatalf("signature out of the driven shape: segs=%d bps=%d span=%ds",
						r.OSig.Segs, r.OSig.BytesPerSeg, r.OSig.SpanSec)
				}
				if r.OSig.Class != "slowloris_suspect" {
					t.Fatalf("sig class = %q, want slowloris_suspect", r.OSig.Class)
				}
			}
		}
		if berr := bansV4.Lookup(&bansKey, &val); berr == nil {
			crossed = true
			recOne = []byte(fmt.Sprintf("crossed at sweep %d", sweep))
		}
	}
	if !crossed {
		t.Fatal("4 sweeps produced no crossing (the detector or the scored path broke)")
	}
	if err := bansV4.Lookup(&bansKey, &val); err != nil {
		t.Fatalf("bans_v4 has no entry for %s after the crossing: %v", off195, err)
	}
	if val.BanUntilMs <= kernelNowMS195(t) {
		t.Fatalf("ban_until_ms %d is not in the future", val.BanUntilMs)
	}
	t.Logf("bans_v4[%s] = {until_ms=%d score=%d reason_code=%d} %s",
		off195, val.BanUntilMs, val.Score, val.ReasonCode, recOne)

	// --- the kernel dies the offender's traffic -----------------------
	time.Sleep(400 * time.Millisecond)
	if ping195(t) {
		t.Fatal("banned ping was ANSWERED — the XDP program shot nothing")
	}
	t.Log("the kernel banned the offender: the ping died at XDP")

	replay := exec.Command("ip", "netns", "exec", ns195, "timeout", "2", "sh", "-c",
		"echo x > /dev/tcp/"+host195+"/9440")
	if rerr := replay.Run(); rerr == nil {
		t.Fatal("the replay connect was ANSWERED — the ban row did not stop it")
	}
	t.Log("the replay connect died at the NIC (TC_ACT_SHOT at XDP)")

	// --- the evidence JSONL carries the sig ---------------------------
	raw, err := os.ReadFile(ev195)
	if err != nil {
		t.Fatalf("evidence file: %v", err)
	}
	if !strings.Contains(string(raw), "slowloris_suspect") {
		t.Fatalf("the evidence lines carry no dynamic signature:\n%s", raw)
	}
	t.Logf("evidence JSONL: %d bytes, the sig on the would-ban row", len(raw))
}

func mustAddr195(t *testing.T, s string) netip.Addr {
	t.Helper()
	ip, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return ip
}
