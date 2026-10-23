package bench

// Guard: the gate's verdict logic, pure — budget bounds (p99 + the
// optional p50 row bound), the floor kind, the 10-pct regression rule
// over a recorded baseline, and the machine-factor normalization. One
// concern: the spec's benchmark-plan gate semantics.
import (
	"strings"
	"testing"
)

func gateCat() Catalog {
	return Catalog{ByID: map[string]Budget{
		"e2e-inline-hop-8k":         {ID: "e2e-inline-hop-8k", Kind: CeilingP99, Value: 1500, P50us: 300, M2: true},
		"engine-inspect-8k":         {ID: "engine-inspect-8k", Kind: CeilingP99, Value: 600},
		"engine-throughput-replica": {ID: "engine-throughput-replica", Kind: FloorReqPS, Value: 10000},
	}}
}

func TestGateVerdicts(t *testing.T) {
	cat := gateCat()
	cases := []struct {
		name      string
		in        GateInput
		wantKinds []ViolationKind
		wantSubs  []string // substrings each violation detail must carry, in order
		wantErr   bool
	}{
		{
			name:      "within budget",
			in:        GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 900, P50us: 250}, MachineFactor: 1},
			wantKinds: nil,
		},
		{
			name:      "budget exceeded (M2 row)",
			in:        GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1700}, MachineFactor: 1},
			wantKinds: []ViolationKind{VioBudget},
			wantSubs:  []string{"e2e-inline-hop-8k"},
		},
		{
			name:      "p50 bound exceeded",
			in:        GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 900, P50us: 400}, MachineFactor: 1},
			wantKinds: []ViolationKind{VioBudgetP50},
			wantSubs:  []string{"p50"},
		},
		{
			name:      "regression over the baseline above 10%",
			in:        GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1150}, Base: &Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1000}, MachineFactor: 1},
			wantKinds: []ViolationKind{VioRegression},
			wantSubs:  []string{"regression"},
		},
		{
			name:      "regression at the 10% limit is clean",
			in:        GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1100}, Base: &Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1000}, MachineFactor: 1},
			wantKinds: nil,
		},
		{
			name:      "machine factor normalizes the budget + regression checks",
			in:        GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1400}, Base: &Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1000}, MachineFactor: 1.3},
			wantKinds: nil,
		},
		{
			name:      "combined budget + regression findings coexist",
			in:        GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1700}, Base: &Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1000}, MachineFactor: 1},
			wantKinds: []ViolationKind{VioBudget, VioRegression},
			wantSubs:  []string{"e2e-inline-hop-8k", "regression"},
		},
		{
			name:      "floor budget not met",
			in:        GateInput{Report: Report{RecipeID: "load-replica", BudgetID: "engine-throughput-replica", ReqPS: 9000}, MachineFactor: 1},
			wantKinds: []ViolationKind{VioBudget},
			wantSubs:  []string{"10000"},
		},
		{
			name:      "floor budget met",
			in:        GateInput{Report: Report{RecipeID: "load-replica", BudgetID: "engine-throughput-replica", ReqPS: 10000}, MachineFactor: 1},
			wantKinds: nil,
		},
		{
			name:    "machine factor zero is gate misuse",
			in:      GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 900}, MachineFactor: 0},
			wantErr: true,
		},
		{
			name:    "machine factor over the clamp is gate misuse",
			in:      GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 900}, MachineFactor: 11},
			wantErr: true,
		},
		{
			name:    "unknown budget id is gate misuse",
			in:      GateInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "nope", P99us: 900}, MachineFactor: 1},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		vs, err := Evaluate(tc.in, cat)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: Evaluate err = nil, want error", tc.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Evaluate err = %v, want nil", tc.name, err)
			continue
		}
		if len(vs) != len(tc.wantKinds) {
			t.Errorf("%s: violations = %d (%v), want %d", tc.name, len(vs), vs, len(tc.wantKinds))
			continue
		}
		for i, want := range tc.wantKinds {
			if vs[i].Kind != want {
				t.Errorf("%s: violation %d kind = %q, want %q", tc.name, i, vs[i].Kind, want)
			}
			if i < len(tc.wantSubs) && !strings.Contains(vs[i].Detail, tc.wantSubs[i]) {
				t.Errorf("%s: violation %d detail = %q, want it to name %q", tc.name, i, vs[i].Detail, tc.wantSubs[i])
			}
			if vs[i].RecipeID != tc.in.Report.RecipeID {
				t.Errorf("%s: violation names recipe %q, want %q", tc.name, vs[i].RecipeID, tc.in.Report.RecipeID)
			}
		}
	}
}
