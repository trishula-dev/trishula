package shield

// TR-80 (issue #80) — the probe's EVIDENCE types + the runner. The
// exported shapes Detect returns; internal to the shield's boot path,
// consumed by the loader's OTel emit + the lab gate's assertion.
//
// probe_stats (bpf/ban_xdp.c + bpf/flow_tc.c): the TR-80 probe
// invocation counters, per-CPU arrays —
//
//	ban_xdp.c:  ban_stats[PROBE_SEEN=3] (the STAT_DROP/PASS/LIFT
//	            verdict keys 0/1/2 stay untouched; max_entries
//	            widened 3 → 4 — the TR-10 e2e asserts only 0/1/2).
//	flow_tc.c:  probe_stats[PROBE_SEEN=0] (a dedicated per-CPU array —
//	            the TC classifier had no stats map).
//
// The marker BOTH tickers share: the DF-bit MASK in the IPv4 header
// (frag_off) — the probe sender clears DF on every burst packet; no
// ordinary stack emits a !DF TCP/ICMP frame (DF is effectively universal
// on modern wires). ICMP probes carry the mask and ICMP is the reliable
// XDP invocation signal on OrbStack veths (TR-10's E2E, probe-verified).
//
// The GREEN Go side: the kernel map reads live in probe_kernel.go
// (linux loader); tier_test.go drives these shapes kernel-free.

import "fmt"

// ProbesPerBurst is the probe's packet count (issue #80: N=5).
const ProbesPerBurst = 5

// ProbeStats is one probe-counter snapshot: the two programs' probe
// invocation totals summed over all CPUs (per-CPU reads arrive as a
// []uint64 slice — one slot per possible CPU — summed by probeCPU).
type ProbeStats struct {
	XDP uint64
	TC  uint64
}

// ProbeDelta carries one burst's invocation accounting (internal to the
// classifier; the exported evidence shape is DetectResult).
type ProbeDelta struct {
	sent int
	xdp  int
	tc   int
}

// probeCPU sums one per-CPU counter slice (untouched keys read as an
// all-zero slice — a clean zero).
func probeCPU(vals []uint64) uint64 {
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total
}

// deltaOf computes the deltas from the counter snapshots.
func deltaOf(before, after ProbeStats, sent int) ProbeDelta {
	return ProbeDelta{
		sent: sent,
		xdp:  int(after.XDP - before.XDP),
		tc:   int(after.TC - before.TC),
	}
}

// classify is the tier decision over the deltas (vocabulary pinned in
// tier_test.go; the same shapes the VM e2e measures through probe_stats).
//
// TOTAL invocations >= N ⇒ FULL (every packet observed); anything above
// zero but short of N ⇒ FIRST_PACKET (a subset of packets is visible —
// the OrbStack signature: 1 TC hit for the conn's first packet, or
// ICMP-only XDP hits); zero everywhere ⇒ NONE (refuse + fail loudly).
func classify(d ProbeDelta) Tier {
	if d.sent <= 0 {
		return TierNone
	}
	total := d.xdp + d.tc
	switch {
	case total >= d.sent:
		return TierFull
	case total > 0:
		return TierFirstPacket
	default:
		return TierNone
	}
}

// ProbeEvidence is the per-burst accounting Detect returns (the "typed
// Tier + the probe evidence (counts)" deliverable).
type ProbeEvidence struct {
	Sent       int    // packets the sender put on the wire
	XDPInvoked uint64 // XDP program probe invocations (summed per-CPU)
	TCInvoked  uint64 // TC classifier probe invocations (summed per-CPU)
}

// String renders one CI log line (the e2e's t.Logf form).
func (e ProbeEvidence) String() string {
	return fmt.Sprintf("sent=%d xdp=%d tc=%d", e.Sent, e.XDPInvoked, e.TCInvoked)
}

// StatsSource reads the two programs' probe counters (kernel maps in
// prod: ban_xdp's ban_stats[3] + tc_ingress_waf's probe_stats[0];
// synthetic snapshots in kernel-free tests).
type StatsSource func() (ProbeStats, error)

// AttachFunc performs (or fakes) the loader's attach on the interface.
type AttachFunc func(tierAttachArgs) (TierHandle, error)

// tierAttachArgs carries the attach hook's context (iface name).
type tierAttachArgs struct {
	iface string
}

// TierHandle is the attached stack (real loader in prod; test fakes).
type TierHandle interface {
	Stats() (ProbeStats, error) // probe_stats read (what classify sees)
	Close() error
}

// PacketSender sends the probe burst (netns raw socket or host ICMP).
type PacketSender interface {
	Send(tierAttachArgs, int) error
}

// Probe is the assembled runner (Detect is the boot-time entrypoint).
type Probe struct {
	attachFn AttachFunc
	source   StatsSource
}

// NewProbe assembles a probe over its two kernel-free seams.
func NewProbe(attach AttachFunc, source StatsSource) *Probe {
	return &Probe{attachFn: attach, source: source}
}

// DetectResult is the typed classification + its evidence (counts).
type DetectResult struct {
	Tier   Tier
	Iface  string
	Ev     ProbeEvidence
	Reason string
}

// Detect runs the visibility probe on iface: attach → snapshot → burst →
// delta → classify (the vocabulary's contract, tier_test.go).
func (p *Probe) Detect(iface string, sender PacketSender) (DetectResult, error) {
	if p == nil || p.attachFn == nil {
		return DetectResult{}, fmt.Errorf("shield: tier probe: nil attach hook")
	}
	if p.source == nil {
		return DetectResult{}, fmt.Errorf("shield: tier probe: nil counter source")
	}
	if iface == "" {
		return DetectResult{}, fmt.Errorf("shield: tier probe: empty iface")
	}
	if sender == nil {
		return DetectResult{}, fmt.Errorf("shield: tier probe: nil packet sender")
	}
	before, err := p.source()
	if err != nil {
		return DetectResult{}, fmt.Errorf("shield: tier probe: pre-burst stats: %w", err)
	}
	if err := sender.Send(tierAttachArgs{iface: iface}, ProbesPerBurst); err != nil {
		return DetectResult{}, fmt.Errorf("shield: tier probe: burst: %w", err)
	}
	after, err := p.source()
	if err != nil {
		return DetectResult{}, fmt.Errorf("shield: tier probe: post-burst stats: %w", err)
	}
	d := deltaOf(before, after, ProbesPerBurst)
	res := DetectResult{
		Tier:  classify(d),
		Iface: iface,
		Ev: ProbeEvidence{
			Sent:       d.sent,
			XDPInvoked: uint64(d.xdp),
			TCInvoked:  uint64(d.tc),
		},
	}
	switch res.Tier {
	case TierFull:
		res.Reason = "every probe packet observed at both altitudes"
	case TierFirstPacket:
		res.Reason = "only a subset of probe packets observed (first-packet/ICMP-only fast path)"
	case TierNone:
		res.Reason = "no probe packets observed at any altitude"
	}
	return res, nil
}
