package shield

import "fmt"

// TR-80 (issue #80) — the visibility-tier vocabulary.
//
// OrbStack veth fast paths make ATTACH altitude ≠ EFFECTIVE altitude: on
// Kubernetes pod veths, established-flow segments never re-ingress clsact
// (TC sees only each connection's first packet, TR-04d), and generic XDP
// is never invoked for netns-sourced UDP at all — ICMP, by contrast,
// reliably invokes XDP (TR-04d/TR-10 probe evidence, 2026-10). A loader
// that assumes full visibility silently degrades. The tier makes the
// degradation EXPLICIT: measured at boot by Probe.Detect (probe.go) from
// the programs' per-CPU probe counters (bpf/ban_xdp.c + bpf/flow_tc.c
// probe_stats), classified here, emitted once as an attribute on the
// shield's startup evidence (tier_otel.go).
//
// Classify (invocation deltas over the probe burst, N=ProbesPerBurst):
//
//	TIER_FULL         every probe packet observed at both altitudes
//	                  (xdp+tc invocations >= N).
//	TIER_FIRST_PACKET only a SUBSET of the burst is visible — the
//	                  OrbStack signature: exactly 1 TC hit (the
//	                  connection's first packet reached clsact; the
//	                  established-flow segments bypassed it), or
//	                  ICMP-only XDP hits (netns UDP never invokes the
//	                  generic XDP path).
//	TIER_NONE         nothing observed at any altitude — the loader must
//	                  refuse to run silently and fail loudly.
type Tier int

// The tiers (String() returns the attribute literal — tier_otel.go).
const (
	// TierUnknown = not yet probed (zero value; never emitted).
	TierUnknown Tier = iota
	// TierFull: every packet seen at both altitudes.
	TierFull
	// TierFirstPacket: first-packet-only at TC; XDP none/ICMP-only.
	TierFirstPacket
	// TierNone: no invocations at all — refuse loudly.
	TierNone
)

// String returns the tier's metric/attribute literal
// (AttrShieldVisibilityTier value form; tier_otel.go).
func (t Tier) String() string {
	switch t {
	case TierFull:
		return "full"
	case TierFirstPacket:
		return "first_packet"
	case TierNone:
		return "none"
	default:
		return "unknown"
	}
}

// Enforcement states what enforcement MEANS at each tier (the README/PR
// vocabulary; unknown is not a state the loader may run in).
func (t Tier) Enforcement() string {
	switch t {
	case TierFull:
		return "full payload visibility at TC"
	case TierFirstPacket:
		return "ban/ACL on first packet ONLY (correct for NEW connections); payload deep-inspection degraded to sampled flows"
	case TierNone:
		return "loader must refuse: no packets visible at any altitude"
	default:
		return "unprobed"
	}
}

// ProbeStats is one probe-counter snapshot: the two programs' probe_stats
// totals summed over all CPUs. (The exported evidence types + StatsSource
// live in probe.go/evidence.go — this is the classify-side wire value.)
type ProbeStats struct {
	XDP uint64
	TC  uint64
}

// ProbeDelta carries one burst's invocation accounting (internal to the
// classifier; the exported evidence shape is DetectResult in probe.go).
type ProbeDelta struct {
	sent int
	xdp  int
	tc   int
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
	// GREEN pending (the RED commit's watched work): classification
	// lands with the loader C (probe_stats tick + read path).
	panic("shield: classify — GREEN pending (TR-80)")
}

// TierRefusal is the error a NONE classification must surface (the
// loader fails the boot loudly rather than run an invisible shield).
type TierRefusal struct {
	Iface string
}

func (e *TierRefusal) Error() string {
	return fmt.Sprintf("shield: visibility tier NONE on %s (no probe packets observed at any altitude) — refusing silent attach", e.Iface)
}
