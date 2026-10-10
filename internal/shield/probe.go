package shield

// TR-80 (issue #80) — the probe's EVIDENCE types (the exported shapes
// Detect returns; internal to the shield's boot path, consumed by the
// loader's OTel emit + the lab gate's assertion).
//
// probe_stats (bpf/ban_xdp.c + bpf/flow_tc.c): one per-CPU array per
// program, two counters each —
//
//	PROBE_XDP_SEEN (0) — ban_xdp invocations on probe packets
//	PROBE_TC_SEEN  (0) — tc_ingress_waf invocations on probe packets
//
// (index 1 in each program's array is reserved for the verdict stat the
// program already ticked — ban_stats keys stay untouched).

import "fmt"

// ProbesPerBurst is the probe's packet count (issue #80: N=5).
const ProbesPerBurst = 5

// Probe evidence keys (the exported counter names; the C pins the same
// values as its PROBE_* indices — wire contract, contract-style).
const (
	// ProbeIDXDPSeen = ban_xdp's probe_stats[0] tick per probe packet
	// the XDP program invoked (any L4: ICMP included).
	ProbeIDXDPSeen uint32 = 0
	// ProbeITCSeen = tc_ingress_waf's probe_stats[0] tick per probe
	// packet that RE-INGRESSED clsact (per-CPU, summed over CPUs).
	ProbeITCSeen uint32 = 0
)

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
// prod: ban_xdp's + tc_ingress_waf's probe_stats; synthetic snapshots in
// kernel-free tests).
type StatsSource func() (ProbeStats, error)

// NewProbe assembles a probe over an attach hook + a counter reader
// (all seams injectable — the tier unit test runs with NO root and NO
// daemon: synthetic StatsSource + fake PacketSender).
func NewProbe(attach AttachFunc, source StatsSource) *Probe {
	return &Probe{attachFn: attach, source: source}
}

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
	if err := sender.Send(tierAttachArgs{iface: iface}, ProbesPerBurst); err != nil {
		return DetectResult{}, fmt.Errorf("shield: tier probe: %w", err)
	}
	after, err := p.source()
	if err != nil {
		return DetectResult{}, fmt.Errorf("shield: tier probe: stats: %w", err)
	}
	d := deltaOf(ProbeStats{}, after, ProbesPerBurst)
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
