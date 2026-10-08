package ingest

import (
	"testing"
	"time"
)

// TR-04a (issue #66, child of TR-04/#4): the transaction-assembly core.
// Kernel-free — synthetic flows only; the ringbuf reader is TR-04b's
// dependency, not this one's (§19.1 ingest sketch: NoteFlow attaches flow
// metadata to a TX context keyed by flow identity).

func TestNoteFlowKeysAndRetrieves(t *testing.T) {
	m := NewTxManager()
	k := FlowKey{
		SrcIP:   [4]byte{10, 66, 0, 7},
		DstIP:   [4]byte{10, 66, 0, 1},
		SrcPort: 53000,
		DstPort: 443,
		Family:  4,
	}
	tx := m.NoteFlow(k)
	if tx == nil {
		t.Fatal("NoteFlow returned nil tx")
	}
	got := m.LookupFlow(k)
	if got != tx {
		t.Fatalf("LookupFlow=%v, want the same tx instance", got)
	}
	if got.Key != k {
		t.Fatalf("tx key = %+v, want %+v", got.Key, k)
	}
}

func TestNoteFlowIsIdempotentPerKey(t *testing.T) {
	m := NewTxManager()
	k := FlowKey{DstPort: 80, Family: 4}
	a := m.NoteFlow(k)
	b := m.NoteFlow(k)
	if a != b {
		t.Fatalf("re-Note on the same key produced a new tx: %p vs %p", a, b)
	}
}

func TestFlowFamilyDistinctness(t *testing.T) {
	// Defect #62 regression at the tx layer: a v4 key must never alias a
	// v6 key with the same numeric tail (family is part of the key).
	m := NewTxManager()
	v4 := FlowKey{
		SrcIP:   [4]byte{1, 2, 3, 4},
		Family:  4,
		DstPort: 443,
	}
	v6 := FlowKey{
		SrcIP6:  [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
		Family:  6,
		DstPort: 443,
	}
	t4 := m.NoteFlow(v4)
	t6 := m.NoteFlow(v6)
	if t4 == t6 {
		t.Fatal("v4 and v6 flows collapsed to one tx (family not keyed)")
	}
}

func TestExpireSweep(t *testing.T) {
	m := NewTxManager()
	k := FlowKey{DstPort: 80, Family: 4}
	_ = m.NoteFlow(k)
	if m.ExpireOlderThan(0) != 0 {
		t.Fatal("cutoff=0 must evict nothing (timestamps are positive)")
	}
	now := uint64(time.Now().UnixNano())
	if n := m.ExpireOlderThan(now + 1); n != 1 {
		t.Fatalf("ExpireOlderThan(now+1) evicted %d, want 1", n)
	}
	if got := m.LookupFlow(k); got != nil {
		t.Fatalf("tx survived a full-expiry sweep: %+v", got)
	}
}
