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

// The TR-92a watch, carried from the RED commit. The RED state ran this
// named test against the once-per-run calibrator: the row read unmet on
// a mid-run inflation episode. The GREEN state pairs the machine factor
// around the budget-row pair: one sample settles quiet (1.00), the
// other settles inside the episode (3.00), and the row records
// retained-with-variance while the run continues.
func TestBudgetRowVerdictUnderMidRunInflation(t *testing.T) {
	cat := gateCat()
	// The load episode arrives after the sample point. The raw p99
	// rides the episode: 4500 us at 3x the 1500 us row.
	rep := Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 4500}
	row, err := EvaluateRow(RowInput{Report: rep, PreFactor: 1.0, PostFactor: 3.0}, cat)
	if err != nil {
		t.Fatalf("EvaluateRow: %v", err)
	}
	if row.Verdict != RowRetainedWithVariance {
		t.Fatalf("recipe %s: verdict = %q, want %q: one sample of the pair carries the inflation, so the raw miss cannot settle as code evidence",
			rep.RecipeID, row.Verdict, RowRetainedWithVariance)
	}
}

// Guard: the paired-sample verdict classes the live run records. The
// pair rides the runner on the fixed calibration probe; the classes
// separate code evidence from runner variance. One concern: the
// TR-92a classification rule over the machine-factor pair.
func TestBudgetRowVerdictClassesPairedSamples(t *testing.T) {
	cat := gateCat()
	cases := []struct {
		name       string
		in         RowInput
		want       RowVerdict
		wantFactor float64
		wantSub    string // substring the record's detail carries, or empty
		wantErr    bool
	}{
		{
			name: "one sample carries the inflation before the row, raw miss — retained-with-variance",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 4500}, PreFactor: 3.0, PostFactor: 1.0},
			want: RowRetainedWithVariance,
		},
		{
			name: "one sample carries the inflation after the row, raw miss — retained-with-variance",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 4500}, PreFactor: 1.0, PostFactor: 3.0},
			want: RowRetainedWithVariance,
		},
		{
			name: "one sample carries the inflation, raw walls hold — holds",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 900}, PreFactor: 2.0, PostFactor: 1.0},
			want: RowHolds,
		},
		{
			name: "both samples agree on inflation, normalized p99 still misses — unmet",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 9000}, PreFactor: 2.5, PostFactor: 3.5},
			want: RowUnmet, wantFactor: 3.0,
			wantSub: "machine factor 3.00",
		},
		{
			name: "both samples agree on inflation, normalized p99 holds — retained-with-variance",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 4200}, PreFactor: 3.0, PostFactor: 3.0},
			want: RowRetainedWithVariance, wantFactor: 3.0,
		},
		{
			name: "both samples quiet, shallow raw miss under the blowup bound — retained-with-variance",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 1700}, PreFactor: 1.0, PostFactor: 1.0},
			want: RowRetainedWithVariance, wantFactor: 1.0,
			wantSub: "1700.0 us above the budget",
		},
		{
			name: "both samples quiet, raw miss under the blowup bound on a pinned row — unmet, the margin rule judges it",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 3000}, PreFactor: 1.0, PostFactor: 1.0, Pinned: true},
			want: RowUnmet, wantFactor: 1.0,
			wantSub: "3000.0 us above the budget",
		},
		{
			name: "both samples quiet, raw miss over the blowup bound — unmet, the miss settles as code evidence",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 6400}, PreFactor: 1.0, PostFactor: 1.0},
			want: RowUnmet, wantFactor: 1.0,
			wantSub: "6400.0 us above the budget",
		},
		{
			name: "both samples quiet, budget holds — holds",
			in:   RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 900}, PreFactor: 1.0, PostFactor: 1.0},
			want: RowHolds, wantFactor: 1.0,
		},
		{
			name:    "floor budget not met on raw walls — unmet",
			in:      RowInput{Report: Report{RecipeID: "load-replica", BudgetID: "engine-throughput-replica", ReqPS: 9000}, PreFactor: 1.0, PostFactor: 1.0},
			want:    RowUnmet,
			wantSub: "under the floor budget",
		},
		{
			name:    "zero sample factor is gate misuse",
			in:      RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 900}, PreFactor: 0, PostFactor: 1.0},
			wantErr: true,
		},
		{
			name:    "sample factor over the clamp is gate misuse",
			in:      RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 900}, PreFactor: 11, PostFactor: 1.0},
			wantErr: true,
		},
		{
			name:    "unknown budget id is gate misuse",
			in:      RowInput{Report: Report{RecipeID: "steady-json-8k", BudgetID: "nope", P99us: 900}, PreFactor: 1.0, PostFactor: 1.0},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		row, err := EvaluateRow(tc.in, cat)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: EvaluateRow err = nil, want error", tc.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: EvaluateRow err = %v, want nil", tc.name, err)
			continue
		}
		if row.Verdict != tc.want {
			t.Errorf("%s: verdict = %q, want %q", tc.name, row.Verdict, tc.want)
		}
		if tc.wantFactor != 0 && row.Factor != tc.wantFactor {
			t.Errorf("%s: factor = %g, want %g", tc.name, row.Factor, tc.wantFactor)
		}
		if tc.wantSub != "" && !strings.Contains(row.Detail, tc.wantSub) {
			t.Errorf("%s: detail = %q, want it to carry %q", tc.name, row.Detail, tc.wantSub)
		}
	}
}

// The TR-199 watch, carried from the RED commit. The RED state ran this
// named test against the TR-92a classes: a quiet-pair raw miss read
// unmet, and the unmet-count gate turned the sub-blowup miss into a
// row-count coin toss under runner contention (issue #199: three CI runs
// in one hour read 4, 4, then 5 unmet rows while the paired samples read
// 1.00-1.01). The pair samples before and after the row: the probes read
// instants, the row measures an interval, so a row inside a contention
// window reads factor 1.00 on both sides while its walls inflate. The
// GREEN state classifies a quiet-pair ceiling miss below the blowup
// bound as retained-with-variance: the pair cannot witness the row
// window's load, so the miss cannot settle as code evidence.
func TestBudgetRowVerdictUnderQuietPairShallowMiss(t *testing.T) {
	cat := gateCat()
	// The pair reads quiet on both sides; the raw p99 rides load the
	// row window carried and the pair never sampled: 3000 us at 2x
	// the 1500 us row, under the blowup bound (6000 us at 4x).
	rep := Report{RecipeID: "steady-json-8k", BudgetID: "e2e-inline-hop-8k", P99us: 3000}
	row, err := EvaluateRow(RowInput{Report: rep, PreFactor: 1.0, PostFactor: 1.0}, cat)
	if err != nil {
		t.Fatalf("EvaluateRow: %v", err)
	}
	if row.Verdict != RowRetainedWithVariance {
		t.Fatalf("recipe %s: verdict = %q, want %q: the pair cannot witness the row window's load, so the sub-blowup miss cannot settle as code evidence",
			rep.RecipeID, row.Verdict, RowRetainedWithVariance)
	}
}
