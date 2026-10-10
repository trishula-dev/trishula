//go:build linux

package shield

// TR-80 (issue #80) — the KERNEL probe plane (the loader's leg). This
// commit carries ONLY the per-CPU readers (probeStatsXDP/probeStatsTC —
// the same helpers the loader's Tier() wiring and the in-VM E2E call);
// the attach + burst-sender + classify wiring lands with the loader
// commit (the deliverable's step order: RED contract → wire contract →
// kernel readers → loader Tier() + gate).
//
// Mechanism notes (TR-10 E2E, probe-verified on OrbStack trishula-build-dev):
//   - PIN with the ebpf API + attach via `ip link set dev X xdp pinned`:
//     a bpf_link-backed generic attach misses post-ban traffic on
//     OrbStack veths (#80's bpf_link face); the pinned attach does not.
//   - ICMP is the reliable XDP invocation signal on OrbStack veths; the
//     probe burst sender will be raw-ICMP with the DF-mask marker (both
//     tickers key on the frag_off mask — bpf/ban_xdp.c + bpf/flow_tc.c).
//   - Env gates: root, BTF, bpffs, netns+veth (the lab gate's posture).

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// ProbeIDXDPCounter is ban_stats' probe index (bpf/ban_xdp.c
// PROBE_SEEN — 3, above the STAT_DROP/PASS/LIFT verdict keys).
const ProbeIDXDPCounter uint32 = 3

// ProbeITCCounter is probe_stats' probe index (bpf/flow_tc.c
// PROBE_SEEN — 0, the array's single entry).
const ProbeITCCounter uint32 = 0

// probeStatsXDP reads ban_stats[3] (per-CPU) — the XDP probe tick count.
func probeStatsXDP(m *ebpf.Map) (uint64, error) {
	return readPerCPUCounter(m, ProbeIDXDPCounter, "xdp")
}

// probeStatsTC reads probe_stats[0] (per-CPU) — the TC probe tick count.
func probeStatsTC(m *ebpf.Map) (uint64, error) {
	return readPerCPUCounter(m, ProbeITCCounter, "tc")
}

// readPerCPUCounter sums one per-CPU array slot (untouched keys read as
// an all-zero slice — a clean zero; this is the TR-10 e2e's percpuStat
// shape, promoted to the loader's plane).
func readPerCPUCounter(m *ebpf.Map, key uint32, what string) (uint64, error) {
	if m == nil {
		return 0, fmt.Errorf("probe_stats %s: nil map", what)
	}
	var vals []uint64
	if err := m.Lookup(&key, &vals); err != nil {
		return 0, fmt.Errorf("probe_stats %s: %w", what, err)
	}
	return probeCPU(vals), nil
}
