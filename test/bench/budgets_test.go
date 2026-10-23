package bench

// Guard: the budget table encodes every §17.1 row 1:1, including the
// two kernel-cache regimes the seventh line states and the §21 M2 flag
// on the end-to-end hop row. One concern: the §17.1 budget record.
import "testing"

func TestBudgetsEncode17_1(t *testing.T) {
	cat, err := LoadBudgets()
	if err != nil {
		t.Fatalf("load budgets: %v", err)
	}

	// The §17.1 row set, read off the PRD (line 7 splits into its two
	// stated regimes: direct short-circuit vs context-fetch).
	want := []Budget{
		{ID: "xdp-hot-path", PRDRow: "XDP shield (ACL/flood/cache/ban-hit path)", Kind: CeilingP99, Value: 10, EnforcedBy: "shield DaemonSet, node NIC"},
		{ID: "tc-classifier-emit", PRDRow: "TC classifier + ringbuf emit", Kind: CeilingP99, Value: 20, EnforcedBy: "shield DaemonSet"},
		{ID: "engine-inspect-8k", PRDRow: "Engine parse + deep inspect (CRS+CEL+schema, 8KB body)", Kind: CeilingP99, Value: 600, EnforcedBy: "engine"},
		{ID: "engine-inspect-64k", PRDRow: "Engine parse + deep inspect (64KB JSON body)", Kind: CeilingP99, Value: 1200, EnforcedBy: "engine"},
		{ID: "ml-scorer-local", PRDRow: "ML local scorer (in-band, parallel with rules)", Kind: CeilingP99, Value: 1000, EnforcedBy: "engine ML tier"},
		{ID: "e2e-inline-hop-8k", PRDRow: "Total inline hop added vs direct (8KB, full CRS)", Kind: CeilingP99, Value: 1500, P50us: 300, EnforcedBy: "end-to-end gate", M2: true},
		{ID: "kernel-cache-direct", PRDRow: "Kernel-cached verdict/ban short-circuit (direct)", Kind: CeilingP99, Value: 1, EnforcedBy: "shield"},
		{ID: "kernel-cache-context", PRDRow: "Kernel-cached verdict/ban short-circuit (context fetch)", Kind: CeilingP99, Value: 100, EnforcedBy: "shield"},
		{ID: "engine-throughput-replica", PRDRow: "Throughput per engine replica (4 vCPU, CRS+schema)", Kind: FloorReqPS, Value: 10000, EnforcedBy: "load gate"},
	}
	if len(cat.ByID) != len(want) {
		t.Errorf("budget rows = %d, want %d (one per §17.1 line; line 7 splits into two regimes)", len(cat.ByID), len(want))
	}
	for _, w := range want {
		got, ok := cat.ByID[w.ID]
		if !ok {
			t.Errorf("budget %q missing from the catalog", w.ID)
			continue
		}
		if got != w {
			t.Errorf("budget %q = %+v, want %+v", w.ID, got, w)
		}
	}

	m2, ok := cat.ByID["e2e-inline-hop-8k"]
	if !ok || !m2.M2 {
		t.Errorf("budget e2e-inline-hop-8k must carry M2: got %+v (ok=%v)", m2, ok)
	}
}
