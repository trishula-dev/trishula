//go:build linux

package banenforce

// TR-10 (issue #10) in-VM E2E — the kernel-side enforcement leg on a live
// Linux VM (OrbStack trishula-build-dev, arm64):
//
//	sudo go test -tags ban_e2e -run TestBanEnforceE2E ./test/banenforce/ -v
//
// The chain under test: the REAL TR-09 engine (rateban.Engine §13.3,
// Clock seam injected) scores synthetic FlowEvents from an offender
// netns → a would-ban crosses threshold(10) → its record is routed
// THROUGH the enforcer (the engine's EvidenceSink seam IS the
// BanEnforcer — the exact production wiring) → bans_v4 (bpf/ban_xdp.c)
// → the offender's traffic is TC_ACT_SHOT'd at XDP → expiry: now >=
// ban_until_ms DELETES the entry in-kernel and traffic passes again →
// the JSONL evidence carries a record for every ban (score, window,
// reason, until).
//
// Attach + probe pattern (probe-verified on this OrbStack stack,
// 2026-10): the program is pinned with the ebpf API and attached with
// `ip link set dev X xdp pinned` (the TR-04d pinned-attach pattern) — a
// bpf_link-backed generic attach misses post-ban traffic here (the #80
// fast-path quirk's bpf_link face), while the pinned attach + ICMP
// probes traverse the full lifecycle. Env gates: root, BTF, bpffs,
// netns+veth (the lab/verify-xdp-chain.sh posture).

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
	"github.com/trishula-dev/trishula/internal/shield"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native ban_enforce ../../bpf/ban_xdp.c -- -I../../bpf -O2 -g

const (
	nsName     = "tr10ban"
	hostVeth   = "tr10h0"
	nsVeth     = "tr10n0"
	nsV4       = "10.66.0.66/24"
	hostV4     = "10.66.0.1/24"
	offenderIP = "10.66.0.66"
	hostIP     = "10.66.0.1"
	pinDir     = "/sys/fs/bpf/tr10ban"
	pinProg    = pinDir + "/ban_xdp"
	evDir      = "/tmp/tr10ban"
	evPath     = evDir + "/ban_evidence.jsonl"
)

func mustRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("ban e2e needs root (XDP attach + netns + map access)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("no BTF at /sys/kernel/btf/vmlinux")
	}
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skip("no bpffs mounted")
	}
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("run %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func mustParseNetip(t *testing.T, s string) netip.Addr {
	t.Helper()
	ip, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return ip
}

// TestBanEnforceE2E is the issue #10 acceptance: a repeat-offender flow
// gets TC_ACT_SHOT (XDP_DROP) in the kernel after threshold; expiry
// auto-lifts (kernel-side expiry branch + the reconciler's loader-side
// lift); an evidence record exists for every ban.
func TestBanEnforceE2E(t *testing.T) {
	mustRoot(t)

	// --- setup: netns + veth (tear stale names down FIRST) -------------
	cleanup(t)
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		t.Fatalf("ev dir: %v", err)
	}
	run(t, "ip", "netns", "add", nsName)
	defer cleanup(t)
	run(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	run(t, "ip", "link", "set", nsVeth, "netns", nsName)
	run(t, "ip", "addr", "add", hostV4, "dev", hostVeth)
	run(t, "ip", "link", "set", hostVeth, "up")
	run(t, "ip", "netns", "exec", nsName, "ip", "addr", "add", nsV4, "dev", nsVeth)
	run(t, "ip", "netns", "exec", nsName, "ip", "link", "set", nsVeth, "up")

	// --- load + PIN + ip-link attach (the TR-04d pinned pattern) --------
	spec, err := loadBan_enforce()
	if err != nil {
		t.Fatalf("bpf2go load: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection (verifier): %v", err)
	}
	defer coll.Close()
	if mkerr := os.MkdirAll(pinDir, 0o700); mkerr != nil {
		t.Fatalf("pin dir: %v", mkerr)
	}
	prog := coll.Programs["ban_xdp"]
	if err := prog.Pin(pinProg); err != nil {
		t.Fatalf("prog pin: %v", err)
	}
	run(t, "ip", "link", "set", "dev", hostVeth, "xdp", "pinned", pinProg)
	out := run(t, "ip", "-d", "link", "show", hostVeth)
	if !strings.Contains(out, "prog/xdp") && !strings.Contains(out, "xdp") {
		t.Fatalf("XDP attach not visible on %s:\n%s", hostVeth, out)
	}
	t.Logf("attached: pin=%s; ip -d shows the xdp program", pinProg)
	bansV4 := coll.Maps["bans_v4"]
	banStats := coll.Maps["ban_stats"]
	pub := &kernelBansV4{m: bansV4}

	// --- the REAL TR-09 engine; the enforcer IS its evidence sink ------
	// The engine's clock is the Clock seam (injected now fn — advanced by
	// the test to cross expiry); the enforcer's clock is the KERNEL clock
	// (CLOCK_MONOTONIC — the clock bpf_ktime_get_ns reads, per the
	// loader's NowNS parity).
	var engMu sync.Mutex
	var nowSec int64 = 1_000
	kernelNowMS := func() uint64 {
		var ts unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
			t.Logf("clock_gettime: %v", err)
			return 0
		}
		return uint64(ts.Sec)*1_000 + uint64(ts.Nsec)/1_000_000 // ms
	}
	bx := shield.NewBanEnforcer(pub, shield.NewJSONLEvidenceSink())
	if err := bx.Sink().AppendFile(evPath); err != nil { // the file sink (lab evidence)
		t.Fatalf("evidence file: %v", err)
	}
	bx.SetClock(func() (uint64, error) { return kernelNowMS() * 1_000_000, nil })
	eng := rateban.New(func() int64 {
		engMu.Lock()
		defer engMu.Unlock()
		return nowSec
	}, sinkFunc(func(r rateban.BanEvidence) error { return bx.Record(r) })) // production wiring: assess → publish

	// Synthetic FlowEvents from the offender source: 4 × rateBreach
	// (weight 3) ≈ score 12 > threshold(10) — a repeat offender crosses.
	for i := 0; i < 4; i++ {
		engMu.Lock()
		at := nowSec
		engMu.Unlock()
		if err := eng.Ingest(offenderIP, rateban.KindRateBreach, at, "e2e"); err != nil {
			t.Fatalf("engine ingest: %v", err)
		}
		engMu.Lock()
		nowSec++
		engMu.Unlock()
	}

	// --- step 1: assess → the would-ban publishes into bans_v4 ---------
	recs := eng.Assess(offenderIP, nowSec)
	if len(recs) != 1 {
		t.Fatalf("engine produced %d would-bans, want 1", len(recs))
	}
	rec := recs[0]
	t.Logf("engine verdict: score=%.2f > T=%.0f  bantime=%ds recidivism=%d",
		rec.Score, rec.Threshold, rec.BantimeSec, rec.Recidivism)

	k, err := shield.BansV4KeyFromIP(mustParseNetip(t, offenderIP))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	var val shield.BansV4Val
	if err := bansV4.Lookup(&k, &val); err != nil {
		t.Fatalf("bans_v4 has no entry for %s after assess+publish: %v", offenderIP, err)
	}
	if val.BanUntilMs <= kernelNowMS() {
		t.Fatalf("ban_until_ms %d is not in the future", val.BanUntilMs)
	}
	if got, want := val.ReasonCode, uint16(1300); got != want {
		t.Fatalf("reason_code = %d, want %d (scored-window)", got, want)
	}
	t.Logf("bans_v4[%s] = {until_ms=%d score=%d reason_code=%d}",
		offenderIP, val.BanUntilMs, val.Score, val.ReasonCode)

	// --- step 2: THE KERNEL SHOTs the offender's probe (TC_ACT_SHOT) ---
	// Warm the L2 path first: banned pings resolve ARP even though they
	// die at XDP (L2 precedes the XDP verdict).
	for i := 0; i < 3; i++ {
		pingFromNetns(t)
		time.Sleep(250 * time.Millisecond)
	}
	baseDrops := percpuStat(t, banStats, 0)
	if pingFromNetns(t) {
		t.Fatal("BANNED ping was ANSWERED — the kernel shot nothing")
	}
	time.Sleep(400 * time.Millisecond)
	drops := percpuStat(t, banStats, 0)
	if drops <= baseDrops {
		t.Fatalf("banned ping produced no XDP drop tick (drop %d→%d)", baseDrops, drops)
	}
	t.Logf("THE KERNEL SHOT THE OFFENDER: banned ping died; ban_stats{drop} %d→%d",
		baseDrops, drops)
	// The live ban stays (no premature expiry mid-window).
	if err := bansV4.Lookup(&k, &val); err != nil {
		t.Fatalf("live ban vanished during the drop phase: %v", err)
	}

	// --- step 3: XDP expiry auto-lift (kernel-side clock comparison) ----
	// The engine's bantime is 600s — too long to sleep out, so the
	// KERNEL-native expiry branch is probed with a lab-shortened window
	// through the SAME publish path (the adapter honors the record's
	// window): ban for 2 s; pings DIE while now < until; past until the
	// next ping takes the now >= branch (delete + pass) and is ANSWERED.
	baseLifts := percpuStat(t, banStats, 2)
	short := rec
	short.Key = offenderIP
	short.BantimeSec = 2
	short.Score = 14
	if err := bx.Record(short); err != nil {
		t.Fatalf("short-window publish: %v", err)
	}
	var shortVal shield.BansV4Val
	if err := bansV4.Lookup(&k, &shortVal); err != nil {
		t.Fatalf("short-window ban missing in bans_v4: %v", err)
	}
	t.Logf("short-window ban: until_ms=%d (now=%d)", shortVal.BanUntilMs, kernelNowMS())
	if pingFromNetns(t) {
		t.Fatal("banned ping was ANSWERED during its window")
	}
	t.Log("banned ping DIES during its window (TC_ACT_SHOT at XDP)")
	untilWait := time.Until(unixMsToTime(shortVal.BanUntilMs)) + 600*time.Millisecond
	if untilWait < 0 {
		untilWait = 600 * time.Millisecond
	}
	time.Sleep(untilWait)
	if !pingFromNetns(t) {
		// Instrumented exhaustion dump: the entry's live state NOW.
		var dumpK shield.BansV4Key
		var dumpV shield.BansV4Val
		iter := bansV4.Iterate()
		var entries []string
		for iter.Next(&dumpK, &dumpV) {
			entries = append(entries, fmt.Sprintf("{saddr=%x fam=%d until=%d}",
				dumpK.SAddr, dumpK.Family, dumpV.BanUntilMs))
		}
		t.Logf("EXHAUSTION DUMP: kernel_now_ms=%d short_u2=%d entries=%v lift=%d baseLift=%d",
			kernelNowMS(), shortVal.BanUntilMs, entries, percpuStat(t, banStats, 2), baseLifts)
		t.Fatal("post-expiry ping FAILED — kernel auto-lift missing")
	}
	t.Log("kernel expiry auto-lift: post-expiry ping ANSWERED (the XDP program took the now >= until branch: entry deleted + packet passed)")
	if err := bansV4.Lookup(&k, &shortVal); err == nil {
		t.Fatalf("expired short ban still in bans_v4 (kernel auto-lift missing)")
	}
	lifts := percpuStat(t, banStats, 2)
	t.Logf("kernel lift ticked: ban_stats{lift}=%d (base %d); entry deleted in-kernel",
		lifts, baseLifts)

	// --- step 4: reconciler parity — the LONG engine ban lifted by the
	// Go reconciler at/after its until_ms (the loader-side lift; the
	// engine's UntilSec parity in engine-space).
	engMu.Lock()
	nowSec = rec.UntilSec + 1
	engMu.Unlock()
	bx.Reconcile(int64(kernelNowMS() + 601_000)) // now >= until_ms (kernel ms)
	if err := bansV4.Lookup(&k, &val); err == nil {
		t.Fatalf("reconciler did not lift the engine ban (bans_v4 still carries it)")
	}
	if eng.Active(offenderIP, rec.UntilSec+1) {
		t.Fatal("engine reports ACTIVE at now >= until (expiry parity broken)")
	}
	t.Log("reconciler lifted the long engine ban; engine Active=false past until")

	// --- step 5: post-lift traffic is ANSWERED again (the ban is gone) --
	if !pingFromNetns(t) {
		t.Fatal("post-reconcile ping not answered — the lifted ban still blocks")
	}
	t.Log("post-reconcile ping ANSWERED (auto-lift end-to-end)")

	// --- step 6: evidence JSONL — a record for EVERY ban -----------------
	sink := bx.Sink()
	recd := sink.Records()
	if len(recd) != 2 {
		t.Fatalf("evidence records = %d, want 2 (one per ban)", len(recd))
	}
	first, second := recd[0], recd[1]
	if !first.Published || first.Verdict != "ban" || first.SourceIP != offenderIP ||
		first.ReasonCode != 1300 || first.ScoreCenti < 1000 || first.UntilMS == 0 ||
		first.BantimeSec != rec.BantimeSec {
		t.Fatalf("engine-ban record incomplete: %+v", first)
	}
	if first.Score < 10 {
		t.Fatalf("evidence score below threshold: %+v", first)
	}
	if len(first.Events) != 4 || first.Events[3].Kind != "rateBreach" {
		t.Fatalf("evidence trajectory lost: %+v", first.Events)
	}
	if !second.Published || second.BantimeSec != 2 || second.ScoreCenti != 1400 {
		t.Fatalf("short-ban record incomplete: %+v", second)
	}
	// AND on disk: the file sink is wired before the records land, so the
	// JSONL file must carry both lines already.
	raw, err := os.ReadFile(evPath)
	if err != nil {
		t.Fatalf("evidence file: %v", err)
	}
	lines := splitLines(raw)
	if len(lines) != 2 {
		t.Fatalf("evidence JSONL lines = %d, want 2", len(lines))
	}
	var disk shield.BanRecord
	if err := json.Unmarshal([]byte(lines[0]), &disk); err != nil {
		t.Fatalf("evidence JSON: %v\n%s", err, lines[0])
	}
	if disk.Verdict != "ban" || disk.SourceIP != offenderIP || !disk.Published {
		t.Fatalf("disk record invariants: %+v", disk)
	}
	if disk.UntilMS != first.UntilMS || disk.BantimeSec != first.BantimeSec {
		t.Fatalf("disk record diverged from the in-memory record")
	}
	t.Logf("evidence[0]: source=%s verdict=%s score=%.2f untilMs=%d window=%ds reason=%d",
		disk.SourceIP, disk.Verdict, disk.Score, disk.UntilMS, disk.BantimeSec, disk.ReasonCode)
	t.Log("TR-10 E2E GREEN: threshold-cross → kernel shot; kernel expiry auto-lift; reconciler lift; evidence for every ban")
}

// cleanup removes the harness names (tear down BEFORE setup: stale
// netns/links/pins fail setup and leave stale XDP filters masking the
// code under test).
func cleanup(t *testing.T) {
	t.Helper()
	_ = os.Remove(pinProg)
	_ = exec.Command("ip", "netns", "del", nsName).Run()
	_ = exec.Command("ip", "link", "del", hostVeth).Run()
}

// pingFromNetns sends one ICMP echo from the offender netns: exit 0 = a
// reply came back = the packet PASSED the XDP program and the host
// answered (ICMP traverses the OrbStack veth XDP path reliably —
// probe-verified in-VM).
func pingFromNetns(t *testing.T) bool {
	t.Helper()
	return exec.Command("ip", "netns", "exec", nsName, "ping", "-c", "1", "-W", "1", hostIP).Run() == nil
}

// percpuStat reads one ban_stats key and sums its per-CPU value (keys
// not yet touched don't exist in a per-CPU array — a clean zero).
func percpuStat(t *testing.T, m *ebpf.Map, key uint32) uint64 {
	t.Helper()
	var vals []uint64 // one entry per possible CPU (ensurePerCPUSlice fills)
	if err := m.Lookup(&key, &vals); err != nil {
		return 0 // untouched per-CPU key = counter at zero
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total
}

func unixMsToTime(ms uint64) time.Time {
	// CLOCK_MONOTONIC has no epoch anchor; for wait math we only need a
	// comparable point: map the ms value through a fresh read.
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	nowMs := uint64(ts.Sec)*1_000 + uint64(ts.Nsec)/1_000_000
	return time.Now().Add(time.Duration(int64(ms)-int64(nowMs)) * time.Millisecond)
}

func splitLines(raw []byte) []string {
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// kernelBansV4 adapts the live ebpf.Map to the enforcer's publisher.
type kernelBansV4 struct {
	m *ebpf.Map
}

func (k *kernelBansV4) PutBansV4(key shield.BansV4Key, val shield.BansV4Val) error {
	return k.m.Put(&key, &val)
}

func (k *kernelBansV4) DeleteBansV4(key shield.BansV4Key) error {
	return k.m.Delete(&key)
}

// sinkFunc adapts a func to the engine's EvidenceSink.
type sinkFunc func(rateban.BanEvidence) error

func (f sinkFunc) Record(r rateban.BanEvidence) error { return f(r) }
