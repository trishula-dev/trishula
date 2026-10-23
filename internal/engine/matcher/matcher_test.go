// matcher_test.go (TR-16): in-package table tests for the hot-subset
// selection, the block-mode compile/scan, and the divergence demotion.
// Every dependency is injected: the frequency function, the pattern set
// and the view payloads arrive as call arguments — no globals, no
// evaluator dependency (the differential gate lives in test/crs-differential).
package matcher

import (
	"reflect"
	"strings"
	"testing"
)

// TestSelectHot pins the R2b selection: ranking by frequency, descending;
// ties break by rule id, ascending; the budget caps the hot subset and
// every pattern outside the budget moves to PathReference. Configuration
// errors: nil freq, non-positive budget.
func TestSelectHot(t *testing.T) {
	base := []Pattern{
		{Rule: 942480, Phase: PhaseRequestBody, Surfaces: []string{"query"}, Expr: "union"},
		{Rule: 913100, Phase: PhaseRequestHeaders, Surfaces: []string{"headers"}, Expr: "sqlmap"},
		{Rule: 941100, Phase: PhaseRequestBody, Surfaces: []string{"query"}, Expr: "script"},
	}
	freq := func() func(int) uint64 {
		counts := map[int]uint64{942480: 50, 913100: 50, 941100: 1}
		return func(rule int) uint64 { return counts[rule] }
	}

	cases := []struct {
		name      string
		budget    int
		wantHot   []int
		wantCold  []int
		wantError string
	}{
		{name: "budget above set size", budget: 2, wantHot: []int{913100, 942480}, wantCold: []int{941100}},
		// Ranked order (frequency desc, ties by rule id) is the
		// selection's output contract: the hot list reads hot-first.
		{name: "budget equals set size", budget: 3, wantHot: []int{913100, 942480, 941100}, wantCold: []int{}},
		{name: "zero budget is an error", budget: 0, wantError: "budget"},
		{name: "negative budget is an error", budget: -1, wantError: "budget"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			set, err := NewSet(base)
			if err != nil {
				t.Fatalf("NewSet: %v", err)
			}
			active, cold, err := set.SelectHot(freq(), tc.budget)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("SelectHot error = %v, want contains %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectHot: %v", err)
			}
			gotHot := rules(active)
			gotCold := rules(cold)
			if !reflect.DeepEqual(gotHot, tc.wantHot) {
				t.Errorf("hot = %v, want %v", gotHot, tc.wantHot)
			}
			if !reflect.DeepEqual(gotCold, tc.wantCold) {
				t.Errorf("cold = %v, want %v", gotCold, tc.wantCold)
			}
		})
	}

	// Nil frequency is a configuration error (deps injected — never a
	// silent default).
	set, err := NewSet(base)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if _, _, err := set.SelectHot(nil, 2); err == nil {
		t.Errorf("SelectHot(nil freq): nil error, want config error")
	}
}

// TestCompileAndScan pins the block-mode DB: compile validates every
// expression at load; Scan returns the matched rule ids sorted and
// deduplicated; patterns of another phase, with an absent surface, or
// demoted out of the compiled list do not fire.
func TestCompileAndScan(t *testing.T) {
	seeds := []Pattern{
		{Rule: 942480, Phase: PhaseRequestBody, Surfaces: []string{"query", "body"}, Expr: `(?i)union[\s]{1,3}select`},
		{Rule: 913100, Phase: PhaseRequestHeaders, Surfaces: []string{"headers"}, Expr: `(?i)sqlmap`},
		{Rule: 941100, Phase: PhaseRequestBody, Surfaces: []string{"query", "body", "headers"}, Expr: `(?i)<script`},
	}
	db, err := Compile(seeds)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	cases := []struct {
		name    string
		phase   int
		view    map[string]string
		wantIDs []int
	}{
		{
			name:    "phase 2 union in query and body fires 942480 twice, dedup",
			phase:   PhaseRequestBody,
			view:    map[string]string{"query": "q=1 UNION SELECT a", "body": "q=1 UNION SELECT a"},
			wantIDs: []int{942480},
		},
		{
			name:    "phase 2 xss in body fires 941100 with 942480",
			phase:   PhaseRequestBody,
			view:    map[string]string{"body": "<script>alert(1)</script>"},
			wantIDs: []int{941100},
		},
		{
			name:    "phase 1 scanner UA fires only the phase 1 pattern",
			phase:   PhaseRequestHeaders,
			view:    map[string]string{"headers": "User-Agent: sqlmap/1.5"},
			wantIDs: []int{913100},
		},
		{
			name:    "missing surface never fires",
			phase:   PhaseRequestBody,
			view:    map[string]string{"uri": "/union select"},
			wantIDs: []int{},
		},
		{
			name:    "clean view stays silent",
			phase:   PhaseRequestBody,
			view:    map[string]string{"query": "q=hello", "body": "user=ok"},
			wantIDs: []int{},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := db.Scan(tc.phase, tc.view)
			if !reflect.DeepEqual(got, tc.wantIDs) {
				t.Errorf("Scan(%d, %v) = %v, want %v", tc.phase, tc.view, got, tc.wantIDs)
			}
		})
	}

	// A malformed expression fails the compile (load-time discipline).
	if _, err := Compile([]Pattern{{Rule: 1, Phase: PhaseRequestBody, Surfaces: []string{"query"}, Expr: "("}}); err == nil {
		t.Errorf("Compile bad expr: nil error, want load error")
	}

	// A reference-path pattern in the compile input is a configuration
	// error, never silent demotion-by-default.
	cold := append([]Pattern{}, seeds...)
	cold[0].Path = PathReference
	if _, err := Compile(cold); err == nil {
		t.Errorf("Compile reference-path pattern: nil error, want config error")
	}
}

// TestDemote pins the self-healing parity action: demotion moves exactly
// the named rules to PathReference, an unknown rule id is an error (no
// phantom demotion), re-demotion is a no-op, and the demoted rule stops
// scanning after a recompile.
func TestDemote(t *testing.T) {
	seeds := []Pattern{
		{Rule: 942480, Phase: PhaseRequestBody, Surfaces: []string{"query"}, Expr: "union"},
		{Rule: 913100, Phase: PhaseRequestHeaders, Surfaces: []string{"headers"}, Expr: "sqlmap"},
	}
	set, err := NewSet(seeds)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if err := set.Demote(942480); err != nil {
		t.Fatalf("Demote(942480): %v", err)
	}
	gotHot := rules(set.Active())
	if !reflect.DeepEqual(gotHot, []int{913100}) {
		t.Errorf("Active = %v, want [913100]", gotHot)
	}
	gotCold := rules(set.ReferenceOnly())
	if !reflect.DeepEqual(gotCold, []int{942480}) {
		t.Errorf("ReferenceOnly = %v, want [942480]", gotCold)
	}
	if err := set.Demote(942480); err != nil {
		t.Errorf("re-Demote(942480): %v, want no-op", err)
	}
	if err := set.Demote(12345); err == nil {
		t.Errorf("Demote(unknown): nil error, want error")
	}

	active := append([]Pattern{}, set.Active()...)
	db, err := Compile(active)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := db.Scan(PhaseRequestBody, map[string]string{"query": "1 UNION SELECT a"}); len(got) != 0 {
		t.Errorf("Scan after demotion = %v, want silent", got)
	}
}

// rules extracts the rule ids of a pattern list.
func rules(ps []Pattern) []int {
	out := make([]int, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Rule)
	}
	return out
}
