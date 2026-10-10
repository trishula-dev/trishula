//go:build linux

package tier

// TR-80 (issue #80) — the in-VM visibility-tier E2E: the CI-able tier
// output for the OrbStack veth fast path (lab/tier-gate.sh runs this and
// prints TIER(<iface>)=<tier> lines).
//
//	go test -tags shield_tier_e2e -run TestTierNetnsVethE2E ./test/tier/ -v
//
// Asserts (the deliverable):
//   - netns veth pair → tier FULL **or** ICMP-XDP-only, documented WHICH
//     (the e2e echoes the measured evidence per interface; TR-10's
//     ICMP-reliability evidence predicts FULL for the pair).
//   - a REAL kubernetes pod veth (the live kind node's CNI veths —
//     docker exec <node>): tier first_packet per the issue-80 kernel
//     evidence (TC first-packet-only; XDP none/ICMP-only). Skipped
//     cleanly when no node/pod veths are up — netns-only runs are
//     still a full gate.
//
// Attach/posture (TR-04d/TR-10 probe-verified on this OrbStack kernel):
// pinned attach via ip link (the bpf_link generic attach misses
// post-ban traffic); ICMP with the DF mask cleared is the reliable XDP
// invocation signal AND the marker both tickers key on.
//
// Root + BTF + bpffs + tc + netns required (lab/verify-xdp-chain.sh
// posture).

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	trishield "github.com/trishula-dev/trishula/internal/shield"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native tier_probe ../../bpf/flow_tc.c -- -I../../bpf -I../../bpf/include -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native tier_xdp ../../bpf/ban_xdp.c -- -I../../bpf -I../../bpf/include -O2 -g

const (
	nsName   = "tr80tier"
	hostVeth = "tr80h0"
	nsVeth   = "tr80n0"
	nsV4     = "10.90.0.66/24"
	hostV4   = "10.90.0.1/24"
	hostIP   = "10.90.0.1"
	nsIP     = "10.90.0.66"
	pinDir80 = "/sys/fs/bpf/tr80tier"
	pinTC    = pinDir80 + "/tc_ingress_waf"
	pinXDP   = pinDir80 + "/ban_xdp"
)

func mustRoot80(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("tier e2e needs root (attach + netns + raw socket)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("no BTF at /sys/kernel/btf/vmlinux")
	}
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skip("no bpffs mounted")
	}
}

func run80(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("run %v: %v\n%s", args[:3], err, out)
	}
	return string(out)
}

// cleanup80 tears the harness names down (BEFORE setup: stale netns/
// links/pins fail setup and leave stale TC filters masking the test).
func cleanup80(t *testing.T) {
	t.Helper()
	_ = exec.Command("ip", "netns", "del", nsName).Run()
	_ = exec.Command("ip", "link", "del", hostVeth).Run()
	_ = exec.Command("ip", "link", "set", "dev", hostVeth, "xdp", "off").Run()
	_ = exec.Command("tc", "qdisc", "del", "dev", hostVeth, "clsact").Run()
	_ = os.Remove(pinTC)
	_ = os.Remove(pinXDP)
}

// netnsHarness brings the tr80tier pair up.
func netnsHarness(t *testing.T) {
	t.Helper()
	cleanup80(t)
	run80(t, "ip", "netns", "add", nsName)
	run80(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	run80(t, "ip", "link", "set", nsVeth, "netns", nsName)
	run80(t, "ip", "addr", "add", hostV4, "dev", hostVeth)
	run80(t, "ip", "link", "set", hostVeth, "up")
	run80(t, "ip", "netns", "exec", nsName, "ip", "addr", "add", nsV4, "dev", nsVeth)
	run80(t, "ip", "netns", "exec", nsName, "ip", "link", "set", nsVeth, "up")
	run80(t, "ip", "netns", "exec", nsName, "ping", "-c", "1", "-W", "1", hostIP) // ARP warm
}

// attachBoth pins + attaches BOTH collections on the host side of the
// pair: the TC classifier from the flow_tc collection (pinned filter) +
// the XDP program from the tier_xdp collection (pinned ip-link attach —
// the TR-10 pattern; the bpf_link generic attach is the #80 quirk's
// blind face). Two bpf2go objects ⇒ two collections: the programs do
// NOT share maps (ban_stats lives only in the xdp collection,
// probe_stats only in the tc collection).
func attachBoth(t *testing.T, coll, xcoll *ebpf.Collection, iface string) {
	t.Helper()
	if mkerr := os.MkdirAll(pinDir80, 0o700); mkerr != nil {
		t.Fatalf("pin dir: %v", mkerr)
	}
	if p := coll.Programs["tc_ingress_waf"]; p != nil {
		if perr := p.Pin(pinTC); perr != nil {
			t.Fatalf("tc pin: %v", perr)
		}
		run80(t, "tc", "qdisc", "add", "dev", iface, "clsact")
		if out, err := exec.Command("tc", "filter", "add", "dev", iface, "ingress", "bpf",
			"da", "pinned", pinTC).CombinedOutput(); err != nil {
			t.Fatalf("tc attach: %v\n%s", err, out)
		}
	}
	if p := xcoll.Programs["ban_xdp"]; p != nil {
		if perr := p.Pin(pinXDP); perr != nil {
			t.Fatalf("xdp pin: %v", perr)
		}
		run80(t, "ip", "link", "set", "dev", iface, "xdp", "pinned", pinXDP)
	}
}

// burstSender80 is the kernel PacketSender: N probe echoes ns → host
// with the DF mask cleared (`ping -M dont`) — ICMP is the reliable XDP
// invocation signal on OrbStack veths (TR-10) and the !DF mask is the
// invocation marker BOTH tickers key on.
type burstSender80 struct{ t *testing.T }

func (b burstSender80) Send(_ trishield.TierAttachArgs, n int) error {
	for i := 0; i < n; i++ {
		if err := exec.Command("ip", "netns", "exec", nsName, "ping", "-c", "1",
			"-W", "1", "-M", "dont", hostIP).Run(); err != nil {
			return fmt.Errorf("probe burst[%d]: %w", i, err)
		}
	}
	return nil
}

// readPerCPU80 sums one per-CPU counter slot (untouched keys: clean zero —
// the TR-10 percpuStat shape).
func readPerCPU80(t *testing.T, m *ebpf.Map, key uint32, what string) uint64 {
	t.Helper()
	var vals []uint64
	if err := m.Lookup(&key, &vals); err != nil {
		t.Fatalf("probe_stats %s read: %v", what, err)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total
}

// TestTierNetnsVethE2E measures the netns veth pair's tier with BOTH
// altitudes attached (TC + generic XDP on the host side) and echoes
// WHICH posture the counters showed. On this OrbStack kernel the ICMP
// path is TR-10-verified visible at both altitudes on a plain pair.
func TestTierNetnsVethE2E(t *testing.T) {
	mustRoot80(t)
	netnsHarness(t)
	t.Cleanup(func() { cleanup80(t) })

	spec, err := loadTier_probe()
	if err != nil {
		t.Fatalf("bpf2go load (flow_tc): %v", err)
	}
	xspec, err := loadTier_xdp()
	if err != nil {
		t.Fatalf("bpf2go load (ban_xdp): %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("collection (verifier): %v", err)
	}
	t.Cleanup(coll.Close)
	xcoll, err := ebpf.NewCollection(xspec)
	if err != nil {
		t.Fatalf("collection xdp (verifier): %v", err)
	}
	t.Cleanup(xcoll.Close)
	attachBoth(t, coll, xcoll, hostVeth)
	banStats := xcoll.Maps["ban_stats"]    // ban_xdp's stats (probe tick = idx 3)
	probeStats := coll.Maps["probe_stats"] // flow_tc's stats (probe tick = idx 0)
	if banStats == nil || probeStats == nil {
		t.Fatalf("maps missing: ban_stats=%v probe_stats=%v", banStats != nil, probeStats != nil)
	}

	src := func() (trishield.ProbeStats, error) {
		return trishield.ProbeStats{
			XDP: readPerCPU80(t, banStats, trishield.ProbeIDXDPCounter, "xdp"),
			TC:  readPerCPU80(t, probeStats, trishield.ProbeITCCounter, "tc"),
		}, nil
	}
	pr := trishield.NewProbe(
		func(trishield.TierAttachArgs) (trishield.TierHandle, error) { return nil, nil },
		src,
	)
	res, err := pr.Detect(hostVeth, burstSender80{t: t})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	line := trishield.TierLine(hostVeth, res.Tier)
	t.Logf("netns-veth evidence: %s (%s)", res.Ev, res.Iface)

	switch res.Tier {
	case trishield.TierFull:
		t.Logf("%s — netns veth pair: FULL (XDP=%d TC=%d of %d packets; both altitudes invoked)",
			line, res.Ev.XDPInvoked, res.Ev.TCInvoked, res.Ev.Sent)
	case trishield.TierFirstPacket:
		if res.Ev.XDPInvoked == 0 && res.Ev.TCInvoked == 0 {
			t.Fatalf("FIRST_PACKET with NO invocations is the NONE posture: %+v", res)
		}
		t.Logf("%s — netns veth pair: ICMP-XDP-only (XDP=%d TC=%d of %d; the TC fast path ate the rest)",
			line, res.Ev.XDPInvoked, res.Ev.TCInvoked, res.Ev.Sent)
	default:
		t.Fatalf("netns veth pair measured %s (%s) — neither FULL nor ICMP-XDP-only; markers/wire wrong",
			res.Tier, line)
	}
	if err := trishield.RequireVisibleTier(res); err != nil {
		t.Fatalf("netns pair refused: %v", err)
	}
}

// TestTierK8sPodVethE2E measures a REAL kubernetes pod veth — the kind
// node's CNI veth (docker exec <node>). The issue-80 kernel evidence:
// tier first_packet (TC sees ONE tick per probe connection; the XDP
// side sees none). Skips cleanly when no node is running (netns-only
// runs are still a full gate).
func TestTierK8sPodVethE2E(t *testing.T) {
	mustRoot80(t)
	node := os.Getenv("TIER_KIND_NODE")
	if node == "" {
		node = "dx1kind-control-plane"
	}
	if out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}",
		node).CombinedOutput(); err != nil || !strings.Contains(string(out), "true") {
		t.Skipf("kind node %s not running: %v %s", node, err, strings.TrimSpace(string(out)))
	}
	iface := findPodVeth80(t, node)
	if iface == "" {
		t.Skip("no live CNI pod veths on the node")
	}
	t.Logf("pod veth (node-side half) under test: %s on %s", iface, node)

	spec, err := loadTier_probe()
	if err != nil {
		t.Fatalf("bpf2go load: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("collection (verifier): %v", err)
	}
	t.Cleanup(coll.Close)

	res, ok := probePodVeth(t, node, iface, coll)
	if !ok {
		t.Skip("pod-veth probe could not run on this node (no measurement)")
	}
	line := trishield.TierLine(iface, res.Tier)
	t.Logf("pod-veth evidence: %s (%s)", res.Ev, res.Iface)
	if res.Tier != trishield.TierFirstPacket {
		t.Fatalf("pod veth measured %s — the #80 signature is first_packet (counters: %s)",
			res.Tier, res.Ev)
	}
	t.Logf("%s — k8s pod veth: FIRST_PACKET (TC=%d of %d probe packets; XDP=%d — the OrbStack fast-path posture, measured)",
		line, res.Ev.TCInvoked, res.Ev.Sent, res.Ev.XDPInvoked)
}

// findPodVeth80 names one live CNI pod veth on the node (bridge-side
// half, vethXXXXXXXX@ifN — the CNI's naming; the peer half sits in the
// pod's netns).
func findPodVeth80(t *testing.T, node string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", node, "ip", "-o", "link", "show").CombinedOutput()
	if err != nil {
		t.Logf("docker exec ip: %v", err)
		return ""
	}
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(l, "veth") || !strings.Contains(l, "state UP") {
			continue
		}
		f := strings.SplitN(l, ": ", 3)
		if len(f) < 2 {
			continue
		}
		name := f[1]
		if i := strings.Index(name, "@"); i > 0 {
			name = name[:i]
		}
		if strings.HasPrefix(name, "veth") && len(name) >= 11 {
			return name
		}
	}
	return ""
}

// probePodVeth drives the pod-veth tier probe INSIDE the kind node
// (scripts/tier-e2e-pod.sh runs in the node's namespaces via docker
// exec): TC attach on the CNI veth + the burst from the node's own
// stack toward the pod behind that veth, counters read through the
// same wire contract. The helper script is generated in-VM by the
// runner (vm-tier-e2e.sh) — absence skips the pod leg cleanly.
func probePodVeth(t *testing.T, node, iface string, coll *ebpf.Collection) (trishield.DetectResult, bool) {
	t.Helper()
	_ = coll
	helper := "/root/tr80tier/scripts/tier-e2e-pod.sh"
	if _, err := os.Stat(helper); err != nil {
		t.Logf("in-vm pod runner missing: %v", err)
		return trishield.DetectResult{}, false
	}
	out, err := exec.Command(helper, node, iface).CombinedOutput()
	if err != nil {
		t.Logf("in-vm pod runner failed: %v\n%s", err, out)
		return trishield.DetectResult{}, false
	}
	var res trishield.DetectResult
	res.Iface = iface
	for _, l := range strings.Split(string(out), "\n") {
		if i := strings.Index(l, "EV="); i >= 0 {
			_, _ = fmt.Sscanf(l[i:], "EV=sent=%d xdp=%d tc=%d",
				&res.Ev.Sent, &res.Ev.XDPInvoked, &res.Ev.TCInvoked)
		}
		switch {
		case strings.Contains(l, "TIER="+trishield.TierFull.String()):
			res.Tier = trishield.TierFull
		case strings.Contains(l, "TIER="+trishield.TierFirstPacket.String()):
			res.Tier = trishield.TierFirstPacket
		case strings.Contains(l, "TIER="+trishield.TierNone.String()):
			res.Tier = trishield.TierNone
		}
	}
	return res, res.Tier != trishield.TierUnknown
}
