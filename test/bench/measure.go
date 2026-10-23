package bench

import (
	"github.com/trishula-dev/trishula/internal/crs"
)

// Report is one measured cell: the recipe, its budget binding, the
// served size, and the latency percentiles over the recorded iteration
// count. Verdicts come from the gate, never from the runner. ReqPS
// carries the throughput measure for floor-kind budgets; the
// latency-runner cells leave it 0.
type Report struct {
	RecipeID   string
	ScenarioID string
	BudgetID   string
	SizeBytes  int
	Iters      int
	P50us      float64
	P99us      float64
	ReqPS      float64
}

// RunResult couples a cell's report with the verdict evidence the
// consistency guards check: whether any iteration interrupted
// (disruptive CRS verdict), the largest phase-2 matched-rule count, and
// the largest phase-1 matched-rule count seen across the run.
type RunResult struct {
	Report           Report
	Interrupted      bool
	MaxPhase2Matches int
	MaxPhase1Matches int
}

// Percentile returns the nearest-rank percentile of xs: rank
// ceil(p*n) with 1-indexing, matching the p50/p99 reporting the §17.1
// rows state. Empty input returns 0.
func Percentile(xs []float64, p float64) float64 {
	return 0
}

// BuildRequest materializes the recipe into the CRS request scope.
func BuildRequest(rec Recipe) crs.Options {
	return crs.Options{}
}

// RunScenario measures one recipe on the committed CRS reference path:
// Warmup unrecorded iterations, then Iterations recorded per-iteration
// evaluations with verdict capture.
func RunScenario(rec Recipe, eval crs.Evaluator) (RunResult, error) {
	return RunResult{}, errNotImplemented
}
