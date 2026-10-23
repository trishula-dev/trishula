package bench

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"time"

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

// benchClient and benchPort are the fixed peer scope the CRS evaluator
// keys transactions on (§17.2 cells share one stable peer).
var benchClient = netip.MustParseAddr("10.0.0.7")

const benchPort = 8080

// Percentile returns the nearest-rank percentile of xs: rank
// ceil(p*n) with 1-indexing, matching the p50/p99 reporting the §17.1
// rows state. Input stays unsorted for the caller; empty input
// returns 0.
func Percentile(xs []float64, p float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	rank := int(math.Ceil(p * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	return sorted[rank-1]
}

// BuildRequest materializes the recipe into the CRS request scope: the
// request line, the peer scope and, for bodies, the content type with
// its true length.
func BuildRequest(rec Recipe) crs.Options {
	hdr := map[string]string{}
	if rec.Body != "" {
		hdr["Content-Type"] = rec.ContentType
		hdr["Content-Length"] = strconv.Itoa(len(rec.Body))
	}
	return crs.Options{
		Method:  rec.Method,
		URI:     rec.URI,
		Version: "1.1",
		Headers: hdr,
		Body:    []byte(rec.Body),
		Client:  benchClient,
		Port:    benchPort,
		Now:     time.Now(),
	}
}

// RunScenario measures one recipe on the committed CRS reference path:
// Warmup unrecorded iterations, then Iterations recorded per-iteration
// evaluations with verdict capture. An evaluation error fails the run
// (no silent sample dropping).
func RunScenario(rec Recipe, eval crs.Evaluator) (RunResult, error) {
	if eval == nil {
		return RunResult{}, fmt.Errorf("bench: recipe %s: nil evaluator", rec.ID)
	}
	if rec.Iterations <= 0 {
		return RunResult{}, fmt.Errorf("bench: recipe %s: iterations %d out of range", rec.ID, rec.Iterations)
	}
	req := BuildRequest(rec)
	for i := 0; i < rec.Warmup; i++ {
		if _, err := eval.Evaluate(req); err != nil {
			return RunResult{}, fmt.Errorf("bench: recipe %s: warmup iteration %d: %w", rec.ID, i, err)
		}
	}
	lat := make([]float64, 0, rec.Iterations)
	res := RunResult{Report: Report{
		RecipeID:   rec.ID,
		ScenarioID: rec.Scenario,
		BudgetID:   rec.BudgetID,
		SizeBytes:  len(rec.Body),
		Iters:      rec.Iterations,
	}}
	for i := 0; i < rec.Iterations; i++ {
		t0 := time.Now()
		v, err := eval.Evaluate(req)
		lat = append(lat, float64(time.Since(t0).Nanoseconds())/1000.0)
		if err != nil {
			return RunResult{}, fmt.Errorf("bench: recipe %s: iteration %d: %w", rec.ID, i, err)
		}
		if v.Interrupted {
			res.Interrupted = true
		}
		if len(v.Phase2Matches) > res.MaxPhase2Matches {
			res.MaxPhase2Matches = len(v.Phase2Matches)
		}
		if len(v.Phase1Matches) > res.MaxPhase1Matches {
			res.MaxPhase1Matches = len(v.Phase1Matches)
		}
	}
	res.Report.P50us = Percentile(lat, 0.50)
	res.Report.P99us = Percentile(lat, 0.99)
	return res, nil
}
