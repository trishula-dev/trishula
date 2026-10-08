package ingest

import (
	"testing"
)

// TR-04c (issue #68, child of TR-04): the ring-loss path — PRD §9.4
// (R1b): "loss is a telemetry-quality issue, surfaced as
// trishula_shield_ring_dropped_total". The OTel metric binding lands
// with TR-11; THIS leaf pins the drain-loop counter contract.

func TestDrainCountsLossOnOverrun(t *testing.T) {
	m := NewTxManager()
	rd := newLossyRing(
		// 3 clean records interleave 2 losses (writer overran the reader):
		lossMarker{},
		syntheticEvent(synEvent{TS: 1, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 0, 0, 1}, DstIP4: [4]byte{10, 0, 0, 2}}),
		lossMarker{},
		syntheticEvent(synEvent{TS: 2, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 0, 0, 3}, DstIP4: [4]byte{10, 0, 0, 2}}),
		syntheticEvent(synEvent{TS: 3, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 0, 0, 5}, DstIP4: [4]byte{10, 0, 0, 2}}),
	)
	res := Drain(m, rd)
	if res.Decoded != 3 {
		t.Fatalf("decoded=%d, want 3", res.Decoded)
	}
	if res.RingLoss != 2 {
		t.Fatalf("ring losses=%d, want 2 (exactly the loss markers)", res.RingLoss)
	}
	if m.Len() != 3 {
		t.Fatalf("tx table=%d, want 3", m.Len())
	}
}

func TestDrainLossIsNotError(t *testing.T) {
	// §9.4 contract: loss is telemetry-quality — the drain MUST NOT fail
	// or unwind on loss markers; stats surface it.
	rd := newLossyRing(lossMarker{}, lossMarker{}, lossMarker{})
	res := Drain(NewTxManager(), rd)
	if res.Decoded != 0 || res.RingLoss != 3 {
		t.Fatalf("loss-only ring: %+v, want decoded=0 loss=3", res)
	}
}

func TestLossCounterStickyAcrossDrains(t *testing.T) {
	// The counter is engine-scoped (not per-drain): two drain passes
	// accumulate into one counter (the OTel binding reads it later).
	m := NewTxManager()
	var st Stats
	_ = Drain(m, newLossyRing(lossMarker{}), DrainStats(&st))
	_ = Drain(m, newLossyRing(lossMarker{}), DrainStats(&st))
	if st.RingLossTotal != 2 {
		t.Fatalf("sticky loss total=%d, want 2", st.RingLossTotal)
	}
}
