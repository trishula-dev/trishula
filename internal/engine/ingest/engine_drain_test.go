package ingest

import (
	"testing"
)

// TR-04d RED (issue #69): the Engine drain semantics, fake-ring driven —
// the kernel contract (C producer) is build-verified against the SAME
// wire in the VM gate; these tests freeze the Go behavior first.
// DrainShieldCtx adds the shutdown contract (ctx bounds the drain).

func TestEngineDrainShieldDecodes(t *testing.T) {
	e := NewEngine()
	rd := newLossyRing(
		syntheticEvent(synEvent{TS: 1, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 0, 0, 1}, DstIP4: [4]byte{10, 0, 0, 2},
			HTTPSeen: 1, Path: "/v1/chat"}),
		syntheticEvent(synEvent{TS: 2, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 0, 0, 3}, DstIP4: [4]byte{10, 0, 0, 2}}),
	)
	if err := e.DrainShield(rd); err != nil {
		t.Fatalf("DrainShield: %v", err)
	}
	snap := e.Snapshot()
	if snap.DecodedTotal != 2 {
		t.Fatalf("decoded=%d, want 2", snap.DecodedTotal)
	}
	if e.tx.Len() != 2 {
		t.Fatalf("tx=%d, want 2", e.tx.Len())
	}
}

func TestEngineDrainSurvivesLossAndMalformed(t *testing.T) {
	e := NewEngine()
	rd := newLossyRing(
		[]byte("bad"),
		lossMarker{},
		syntheticEvent(synEvent{TS: 9, DstPort: 80, Family: 4,
			SrcIP4: [4]byte{10, 0, 0, 9}, DstIP4: [4]byte{10, 0, 0, 2}}),
		lossMarker{},
	)
	if err := e.DrainShield(rd); err != nil {
		t.Fatalf("drain must survive loss+malformed: %v", err)
	}
	snap := e.Snapshot()
	if snap.DecodedTotal != 1 || snap.SkippedTotal != 1 || snap.RingLossTotal != 2 {
		t.Fatalf("stats=%+v, want decoded=1 skipped=1 loss=2", snap)
	}
}

func TestEngineDrainStopsOnClosedRing(t *testing.T) {
	e := NewEngine()
	rd := newLossyRing() // empty ring = immediate close
	if err := e.DrainShield(rd); err != nil {
		t.Fatalf("closed ring: %v", err)
	}
	if snap := e.Snapshot(); snap.DecodedTotal != 0 {
		t.Fatalf("decoded=%d on empty ring", snap.DecodedTotal)
	}
}
