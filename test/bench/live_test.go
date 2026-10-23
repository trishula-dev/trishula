package bench

// Guard: the driveable §17.2 scenarios measure on the REAL committed CRS
// reference path, deterministically bounded (Iterations + Warmup), with
// behavior-consistency checks per recipe family (idle passing traffic
// carries no CRS matches; attack recipes land phase-2 matches; the body
// ladder delivers all its sizes). One concern: the measurement runner.
//
// The budget verdict assert lives in TestBudgetVerdictsOnLivePath — one
// concern per guard.
import (
	"sort"
	"testing"
)

// The idle recipe: clean passing traffic through the CRS walk.
const idleRecipeID = "idle-get"

// The §21 M2 metric shape: the inline 8KB full-CRS cell the end-to-end
// hop budget binds (recipe set = the steady scenario's 8KB member).
const steadyM2RecipeID = "steady-json-8k"

// The recipe ids whose §17.1 budget verdicts the harness RECORDS as
// unmet today: the arg-dense urlencoded deep-inspect surface. The pin
// flips with engine evidence only (the §17.1 budget holds or the shape
// changes) — a live green here means the surface got fixed or the
// binding drifted; both force a conscious re-pin with fresh numbers.
var wantUnmet = []string{"ladder-form-dense-1k", "ladder-form-dense-8k"}

func TestDriveableScenariosMeasureOnRealPath(t *testing.T) {
	byScen := recipesByScenario(t)

	// Exactly the §17.2 driveable set carries recipes.
	if len(byScen) != 3 {
		t.Errorf("recipe scenarios = %d, want 3 (inline-idle, inline-steady, body-ladder)", len(byScen))
	}
	for scen := range byScen {
		switch scen {
		case "s17-2-2-inline-idle", "s17-2-3-inline-steady", "s17-2-7-body-ladder":
		default:
			t.Errorf("recipes ride non-driveable scenario %q", scen)
		}
	}

	eval := reference(t)
	attackSeen := false
	idleSeen := false
	for scen, rs := range byScen {
		for _, rec := range rs {
			res, err := RunScenario(rec, eval)
			if err != nil {
				t.Errorf("recipe %s: run: %v", rec.ID, err)
				continue
			}
			rep := res.Report
			if rep.RecipeID != rec.ID || rep.ScenarioID != scen || rep.BudgetID != rec.BudgetID {
				t.Errorf("recipe %s: report identity = %+v (scenario=%s budget=%s)", rec.ID, rep, scen, rec.BudgetID)
			}
			if rep.Iters != rec.Iterations || rep.SizeBytes != len(rec.Body) {
				t.Errorf("recipe %s: iters/size = %d/%d B, want %d/%d B", rec.ID, rep.Iters, rep.SizeBytes, rec.Iterations, len(rec.Body))
			}
			if rep.P50us <= 0 || rep.P99us < rep.P50us {
				t.Errorf("recipe %s: percentiles collapsed (p50=%.1f p99=%.1f)", rec.ID, rep.P50us, rep.P99us)
			}
			switch {
			case rec.ID == idleRecipeID:
				idleSeen = true
				if res.Interrupted || res.MaxPhase2Matches != 0 {
					t.Errorf("recipe %s: passing-traffic run carries CRS verdicts (interrupted=%v ph2=%d)", rec.ID, res.Interrupted, res.MaxPhase2Matches)
				}
			case rec.Attack:
				attackSeen = true
				if res.MaxPhase2Matches < 1 {
					t.Errorf("recipe %s: attack payload landed no phase-2 CRS match", rec.ID)
				}
			}
		}
	}
	if !idleSeen {
		t.Errorf("idle-passing recipe %q missing from the measured set", idleRecipeID)
	}
	if !attackSeen {
		t.Errorf("no attack recipe measured (the CRS-detection leg of the harness never fired)")
	}
}

func TestBudgetVerdictsOnLivePath(t *testing.T) {
	cat, err := LoadBudgets()
	if err != nil {
		t.Fatalf("load budgets: %v", err)
	}
	eval := reference(t)
	byScen := recipesByScenario(t)

	var unmet []string
	m2, ok := cat.ByID["e2e-inline-hop-8k"]
	if !ok {
		t.Fatalf("M2 budget row missing")
	}
	m2Seen := false
	for _, rs := range byScen {
		for _, rec := range rs {
			res, err := RunScenario(rec, eval)
			if err != nil {
				t.Errorf("recipe %s: run: %v", rec.ID, err)
				continue
			}
			// The M2 envelope is the one §21-mandated CI-blocking bound:
			// the inline 8KB full-CRS cell sits inside 1.5 ms p99
			// (the engine-side share cannot exceed the hop budget).
			if rec.BudgetID == m2.ID && res.Report.P99us > m2.Value {
				t.Errorf("recipe %s: p99 = %.1f us exceeds the M2 bound (%.0f us)", rec.ID, res.Report.P99us, m2.Value)
			}
			m2Seen = m2Seen || rec.ID == steadyM2RecipeID
			vs, err := Evaluate(GateInput{Report: res.Report, MachineFactor: 1}, cat)
			if err != nil {
				t.Errorf("recipe %s: gate: %v", rec.ID, err)
				continue
			}
			for _, v := range vs {
				if v.Kind != VioBudget {
					t.Errorf("recipe %s: non-budget finding on live path: %+v", rec.ID, v)
				}
				unmet = append(unmet, rec.ID)
			}
		}
	}
	sort.Strings(unmet)
	if !m2Seen {
		t.Errorf("M2 recipe %q missing from the gate run", steadyM2RecipeID)
	}

	// The open §17.1 finding, pinned: the arg-dense urlencoded
	// deep-inspect surface exceeds its budget (exact set = the two
	// dense-form ladder cells). Any other unmet row is either a
	// machine-noise flip (compare the log table, then re-pin with the
	// recorded run) or a new §17 drift.
	if len(unmet) != len(wantUnmet) {
		t.Errorf("unmet budget set = %v, want exactly %v", unmet, wantUnmet)
	}
	for i, id := range wantUnmet {
		if i >= len(unmet) || unmet[i] != id {
			t.Errorf("unmet budget set[%d] = %q, want %q (full set %v)", i, safeAt(unmet, i), id, unmet)
		}
	}
}

func safeAt(xs []string, i int) string {
	if i < len(xs) {
		return xs[i]
	}
	return "(absent)"
}
