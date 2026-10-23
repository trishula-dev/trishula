package bench

// Guard: the scenario inventory encodes the nine spec benchmark-plan rows with their
// plane + gate classification; the recipe catalog validates against it.
// One concern: the spec's benchmark-plan inventory record + recipe-catalog integrity.
import (
	"strings"
	"testing"
)

func TestScenariosEncode17_2(t *testing.T) {
	scens, err := LoadScenarios()
	if err != nil {
		t.Fatalf("load scenarios: %v", err)
	}
	byID := map[string]Scenario{}
	for _, s := range scens {
		byID[s.ID] = s
	}
	if len(scens) != 9 {
		t.Errorf("scenario inventory = %d rows, want 9 (§17.2 lists nine)", len(scens)) // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
	}

	// Benchmark-plan rows 2, 3 and 7 are the engine-side scenarios hosted CI can
	// measure on the committed CRS reference path; the rest name their
	// absent runtime.
	driveableWant := map[string]bool{
		"s17-2-2-inline-idle":   true,
		"s17-2-3-inline-steady": true,
		"s17-2-7-body-ladder":   true,
	}
	for _, s := range scens {
		if s.Driveable != driveableWant[s.ID] {
			t.Errorf("scenario %q driveable = %v, want %v", s.ID, s.Driveable, driveableWant[s.ID])
		}
		if s.Plane == "" {
			t.Errorf("scenario %q: empty plane", s.ID)
		}
		if !s.Driveable && s.Gate == "" {
			t.Errorf("scenario %q: non-driveable rows must name their gate", s.ID)
		}
	}

	// Recipe-catalog integrity: every recipe resolves, and a floor
	// budget (lab-side load gate) never binds a CI recipe.
	rs, err := Recipes()
	if err != nil {
		t.Fatalf("load recipes: %v", err)
	}
	cat, err := LoadBudgets()
	if err != nil {
		t.Fatalf("load budgets: %v", err)
	}
	if err := ValidateRecipes(cat, scens, rs); err != nil {
		t.Fatalf("validate recipes: %v", err)
	}
	seen := map[string]string{}
	for _, r := range rs {
		if prev, dup := seen[r.ID]; dup {
			t.Errorf("recipe %q doubles recipe %q", r.ID, prev)
			continue
		}
		seen[r.ID] = "seen"
		if !strings.HasPrefix(r.Scenario, "s17-2-") {
			t.Errorf("recipe %q: scenario id %q outside the §17.2 scheme", r.ID, r.Scenario) // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
		}
		if r.Iterations <= 0 || r.Warmup < 0 {
			t.Errorf("recipe %q: measured loop unbounded or negative (iters=%d warmup=%d)", r.ID, r.Iterations, r.Warmup)
		}
	}

	// Validation rejects broken catalogs and recipes. The real catalog
	// backs the known-id cases; the floor case carries the load-gate row.
	realCat, err := LoadBudgets()
	if err != nil {
		t.Fatalf("load budgets: %v", err)
	}
	floorCat := Catalog{ByID: map[string]Budget{"engine-throughput-replica": {ID: "engine-throughput-replica", Kind: FloorReqPS, Value: 10000}}}
	errCases := []struct {
		name    string
		cat     Catalog
		scens   []Scenario
		rs      []Recipe
		wantSub string
	}{
		{
			name:    "unknown budget id",
			cat:     realCat,
			scens:   []Scenario{{ID: "s17-2-2-inline-idle", Driveable: true, Plane: "ci"}},
			rs:      []Recipe{{ID: "r", Scenario: "s17-2-2-inline-idle", BudgetID: "nope", Iterations: 1, Warmup: 1}},
			wantSub: "budget",
		},
		{
			name:    "unknown scenario id",
			cat:     realCat,
			rs:      []Recipe{{ID: "r", Scenario: "s17-2-99-nope", Iterations: 1, Warmup: 1}},
			wantSub: "scenario",
		},
		{
			name:    "non-driveable scenario",
			cat:     realCat,
			scens:   []Scenario{{ID: "s17-2-5-ban-ladder", Plane: "kernel", Gate: "XDP ban-hit path"}},
			rs:      []Recipe{{ID: "r", Scenario: "s17-2-5-ban-ladder", Iterations: 1, Warmup: 1}},
			wantSub: "not driveable",
		},
		{
			name:    "floor budget bound to a CI recipe",
			cat:     floorCat,
			scens:   []Scenario{{ID: "s17-2-2-inline-idle", Driveable: true, Plane: "ci"}},
			rs:      []Recipe{{ID: "r", Scenario: "s17-2-2-inline-idle", BudgetID: "engine-throughput-replica", Iterations: 1, Warmup: 1}},
			wantSub: "floor",
		},
		{
			name:  "dup recipe id",
			cat:   realCat,
			scens: []Scenario{{ID: "s17-2-2-inline-idle", Driveable: true, Plane: "ci"}},
			rs: []Recipe{
				{ID: "dup", Scenario: "s17-2-2-inline-idle", BudgetID: "engine-inspect-8k", Iterations: 1, Warmup: 1},
				{ID: "dup", Scenario: "s17-2-2-inline-idle", BudgetID: "engine-inspect-8k", Iterations: 1, Warmup: 1},
			},
			wantSub: "double",
		},
	}
	for _, tc := range errCases {
		err := ValidateRecipes(tc.cat, tc.scens, tc.rs)
		if err == nil {
			t.Errorf("%s: ValidateRecipes = nil, want error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: error = %q, want it to name %q", tc.name, err.Error(), tc.wantSub)
		}
	}
}
