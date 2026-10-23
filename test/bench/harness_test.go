package bench

// Shared live-path harness: the committed CRS reference evaluator loaded
// once per test binary (test-only; invisible to non-test builds).
import (
	"sync"
	"testing"

	"github.com/trishula-dev/trishula/internal/crs"
	"github.com/trishula-dev/trishula/test/crs-differential"
)

var (
	refOnce sync.Once
	refEval crs.Evaluator
	refErr  error
)

// reference loads the committed CRS slice (the differential harness's
// engine.conf home) once; tests and benchmarks share the instance.
func reference(tb testing.TB) crs.Evaluator {
	tb.Helper()
	refOnce.Do(func() {
		refEval, refErr = crsdifferential.LoadReference()
	})
	if refErr != nil {
		tb.Fatalf("load committed CRS reference: %v", refErr)
	}
	return refEval
}

// recipesByScenario loads the validated recipe set and buckets it.
func recipesByScenario(tb testing.TB) map[string][]Recipe {
	tb.Helper()
	cat, err := LoadBudgets()
	if err != nil {
		tb.Fatalf("load budgets: %v", err)
	}
	scens, err := LoadScenarios()
	if err != nil {
		tb.Fatalf("load scenarios: %v", err)
	}
	rs, err := Recipes()
	if err != nil {
		tb.Fatalf("load recipes: %v", err)
	}
	if err := ValidateRecipes(cat, scens, rs); err != nil {
		tb.Fatalf("validate recipes: %v", err)
	}
	byScen := map[string][]Recipe{}
	for _, r := range rs {
		byScen[r.Scenario] = append(byScen[r.Scenario], r)
	}
	return byScen
}
