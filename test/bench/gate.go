package bench

import (
	"fmt"
)

// ViolationKind is the gate's violation taxonomy.
type ViolationKind string

const (
	// VioBudget: a ceiling budget exceeded (or floor not met).
	VioBudget ViolationKind = "budget_exceeded"
	// VioBudgetP50: a cell's p50 bound exceeded.
	VioBudgetP50 ViolationKind = "budget_p50_exceeded"
	// VioRegression: a cell regressed more than RegressionLimit over its
	// recorded baseline cell (the spec's benchmark plan: a p99 regression over 10% fails CI).
	VioRegression ViolationKind = "regression"
)

// RegressionLimit is the spec's benchmark-plan CI gate: 10% over the recorded baseline.
const RegressionLimit = 0.10

// Violation is one gate finding on one recipe.
type Violation struct {
	RecipeID string
	Kind     ViolationKind
	Detail   string
}

// GateInput couples one measured cell with its recorded baseline cell
// and the machine factor between the measuring host and the baseline
// host. MachineFactor > 1 means the measuring host is slower than the
// baseline host; 1.0 means same speed.
type GateInput struct {
	Report        Report
	Base          *Report // recorded prior measurement; nil = none yet
	MachineFactor float64
}

// Evaluate computes the cell's verdicts: budget bounds (p99 then the
// optional p50 row bound) versus the machine-normalized measurement,
// then the regression check over the baseline. Multiple findings
// coexist; the error return covers gate misuse only (a machine factor
// outside (0, 10] or an unknown budget id).
//
// Normalization: the measurement divides by MachineFactor, so a slower
// measuring host reads in baseline-host speed units. The baseline cell
// itself stays as recorded. A finding's detail carries the recipe, the
// measured numbers, the budget row and the factor — a red CI log names
// its case without re-running anything.
func Evaluate(in GateInput, cat Catalog) ([]Violation, error) {
	if in.MachineFactor <= 0 || in.MachineFactor > 10 {
		return nil, fmt.Errorf("bench: machine factor %g outside (0, 10]", in.MachineFactor)
	}
	b, ok := cat.ByID[in.Report.BudgetID]
	if !ok {
		return nil, fmt.Errorf("bench: unknown budget %q", in.Report.BudgetID)
	}
	var vs []Violation
	if b.Kind == FloorReqPS {
		if in.Report.ReqPS < b.Value {
			vs = append(vs, Violation{RecipeID: in.Report.RecipeID, Kind: VioBudget,
				Detail: fmt.Sprintf("throughput %.0f req/s under the floor budget %s (%.0f req/s)",
					in.Report.ReqPS, b.ID, b.Value)})
		}
		return vs, nil
	}
	p99n := in.Report.P99us / in.MachineFactor
	if p99n > b.Value {
		vs = append(vs, Violation{RecipeID: in.Report.RecipeID, Kind: VioBudget,
			Detail: fmt.Sprintf("p99 %.1f us above the budget %s (%.0f us) at machine factor %.2f",
				p99n, b.ID, b.Value, in.MachineFactor)})
	}
	if b.P50us > 0 && in.Report.P50us/in.MachineFactor > b.P50us {
		vs = append(vs, Violation{RecipeID: in.Report.RecipeID, Kind: VioBudgetP50,
			Detail: fmt.Sprintf("p50 %.1f us above the %s p50 bound (%.0f us) at machine factor %.2f",
				in.Report.P50us/in.MachineFactor, b.ID, b.P50us, in.MachineFactor)})
	}
	if in.Base != nil {
		limit := in.Base.P99us * (1 + RegressionLimit)
		if p99n > limit {
			vs = append(vs, Violation{RecipeID: in.Report.RecipeID, Kind: VioRegression,
				Detail: fmt.Sprintf("regression: p99 %.1f us reads %.1f%% over the recorded baseline %.1f us, beyond the %d%% limit",
					p99n, 100*(p99n/in.Base.P99us-1), in.Base.P99us, int(RegressionLimit*100))})
		}
	}
	return vs, nil
}
