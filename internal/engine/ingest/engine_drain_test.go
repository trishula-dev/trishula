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

// TR-194 (issue #236): the size gate counts the stages field. The landed
// 200-byte class and the extended 208-byte class both decode; anything
// over StagesWireSize is over-budget and fills the SkippedTotal row (the
// skipped-count contract). The drain carries the decoded records onto the
// tx (the span-link + shield.stages correlation source; bounded by
// ShieldEventsCap).
func TestSizeGateExtendedRecords(t *testing.T) {
	e := NewEngine()
	rd := newLossyRing(
		// (a) the landed 200-byte class: decodes; the bitmap reads
		// all-absent (a zero value, never an invented read).
		syntheticEvent(synEvent{TS: 1, DstPort: 443, Family: 4, SrcIP4: [4]byte{10, 9, 9, 1}, DstIP4: [4]byte{10, 9, 9, 2}}),
		// (b) the extended 208-byte class: decodes; the bits ride.
		stagedEvent(syntheticEvent(synEvent{TS: 2, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 9, 9, 1}, DstIP4: [4]byte{10, 9, 9, 2}}), 0x70),
		// (c) the over-budget 209-byte frame: the size gate fills the
		// SkippedTotal row.
		appendStages(syntheticEvent(synEvent{TS: 3, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 9, 9, 1}, DstIP4: [4]byte{10, 9, 9, 2}}), 0x70, 9),
	)
	if err := e.DrainShield(rd); err != nil {
		t.Fatalf("DrainShield: %v", err)
	}
	snap := e.Snapshot()
	if snap.DecodedTotal != 2 || snap.SkippedTotal != 1 {
		t.Fatalf("stats = %+v, want decoded=2 skipped=1 (the over-budget frame fills the skipped row)", snap)
	}
	tx := e.tx.LookupFlow(FlowKey{SrcIP: [4]byte{10, 9, 9, 1}, DstIP: [4]byte{10, 9, 9, 2},
		DstPort: 443, Family: 4})
	if tx == nil {
		t.Fatal("drain: no tx for the shared flow key")
	}
	// The tx carries BOTH records: the landed record reads 0; the
	// extended record reads the bits. Zero stays a VALUE (the wire's own read); only
	// record absence reads absent.
	if len(tx.ShieldEvents) != 2 {
		t.Fatalf("tx shield events = %d, want 2 (the records ride the correlation carrier)", len(tx.ShieldEvents))
	}
	if got := tx.ShieldEvents[0].Stages; got != 0 {
		t.Fatalf("landed record stages = %#x, want 0 (all-absent on the landed wire)", got)
	}
	if got := tx.ShieldEvents[1].Stages; got != 0x70 {
		t.Fatalf("extended record stages = %#x, want 0x70 (the TC consult bits ride)", got)
	}
	// The bounded carrier: a burst flow cannot grow the tx unbounded
	// (the drain keeps the newest ShieldEventsCap records).
	for i := uint64(4); i < uint64(32); i++ {
		e.DrainShield(newLossyRing(stagedEvent(syntheticEvent(synEvent{TS: i, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 9, 9, 1}, DstIP4: [4]byte{10, 9, 9, 2}}), 0x10)))
	}
	if len(tx.ShieldEvents) > ShieldEventsCap {
		t.Fatalf("tx shield events = %d, want <= %d (the carrier stays bounded)", len(tx.ShieldEvents), ShieldEventsCap)
	}
}
