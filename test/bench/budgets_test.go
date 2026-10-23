package bench

// Guard: the budget table encodes every spec budget-table row 1:1, including the
// two kernel-cache regimes the seventh line states and the spec's M2 flag
// on the end-to-end hop row. One concern: the spec's budget-record set.
import "testing"

func TestBudgetsEncode17_1(t *testing.T) {
	cat, err := LoadBudgets()
	if err != nil {
		t.Fatalf("load budgets: %v", err)
	}

	// The spec's budget-table row set, read off the spec (line 7 splits into its two
	// stated regimes: direct short-circuit vs context-fetch).
	want := []Budget{
		{ID: "xdp-hot-path", SpecRow: "XDP shield (ACL/flood/cache/ban-hit path)", Kind: CeilingP99, Value: 10, EnforcedBy: "shield DaemonSet, node NIC"},
		{ID: "tc-classifier-emit", SpecRow: "TC classifier + ringbuf emit", Kind: CeilingP99, Value: 20, EnforcedBy: "shield DaemonSet"},
		{ID: "engine-inspect-8k", SpecRow: "Engine parse + deep inspect (CRS+CEL+schema, 8KB body)", Kind: CeilingP99, Value: 600, EnforcedBy: "engine"},
		{ID: "engine-inspect-64k", SpecRow: "Engine parse + deep inspect (64KB JSON body)", Kind: CeilingP99, Value: 1200, EnforcedBy: "engine"},
		{ID: "ml-scorer-local", SpecRow: "ML local scorer (in-band, parallel with rules)", Kind: CeilingP99, Value: 1000, EnforcedBy: "engine ML tier"},
		{ID: "e2e-inline-hop-8k", SpecRow: "Total inline hop added vs direct (8KB, full CRS)", Kind: CeilingP99, Value: 1500, P50us: 300, EnforcedBy: "end-to-end gate", M2: true},
		{ID: "kernel-cache-direct", SpecRow: "Kernel-cached verdict/ban short-circuit (direct)", Kind: CeilingP99, Value: 1, EnforcedBy: "shield"},
		{ID: "kernel-cache-context", SpecRow: "Kernel-cached verdict/ban short-circuit (context fetch)", Kind: CeilingP99, Value: 100, EnforcedBy: "shield"},
		{ID: "engine-throughput-replica", SpecRow: "Throughput per engine replica (4 vCPU, CRS+schema)", Kind: FloorReqPS, Value: 10000, EnforcedBy: "load gate"},
	}
	if len(cat.ByID) != len(want) {
		t.Errorf("budget rows = %d, want %d (one per §17.1 line; line 7 splits into two regimes)", len(cat.ByID), len(want)) // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
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
