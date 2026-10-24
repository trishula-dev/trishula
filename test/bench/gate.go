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

// InflationBand is the machine-factor level a paired sample reads when
// runner inflation rides the measurement window: a sample at or above
// it carries the load episode. Quiet-host samples read 1.00 within
// noise. Hosted-CI storm windows read 2x to 7x. 1.5 splits the two
// states with margin on each side.
const InflationBand = 1.5

// RowVerdict is the variance-consistent verdict class one budget-row
// pair reads on the live path (TR-92a). The class records why the row
// settled: a genuine budget miss, a bracket the samples could not
// settle, or a row that holds.
type RowVerdict string

const (
	// RowUnmet: the row misses its budget on the walls the verdict
	// settles. It reads the raw walls when the paired samples agree on
	// the runner state, the normalized walls when they agree on
	// inflation.
	RowUnmet RowVerdict = "unmet"
	// RowRetainedWithVariance: the walls miss or hold while one side of
	// the machine-factor pair carries inflation, or both sides carry
	// inflation and the normalized walls hold. The pair cannot settle
	// code evidence. The row stays recorded and the run continues.
	RowRetainedWithVariance RowVerdict = "retained-with-variance"
	// RowHolds: the row's budget holds on the compared walls.
	RowHolds RowVerdict = "holds"
)

// RowInput couples one measured cell with its paired machine factors:
// one sample before the row's measurement, one after. The pair rides
// the runner, never the recipe: the calibration probe is fixed work
// outside the CRS path, so an engine-side regression cannot inflate it.
type RowInput struct {
	Report     Report
	PreFactor  float64
	PostFactor float64
}

// RowVerdictRecord is the row's verdict class with the evidence the run
// record prints: the factor the budget comparison used, the budget
// findings on the compared walls, and their joined detail line.
type RowVerdictRecord struct {
	Verdict    RowVerdict
	Factor     float64 // the factor the walls normalize by; 1.0 when the row settles on raw walls
	Violations []Violation
	Detail     string
}

// EvaluateRow classifies one budget-row pair (recipe + budget row) from
// its paired machine factors. The TR-92a defect class: a once-per-run
// calibration prints 1.00, then sustained concurrent CI load inflates
// the walls the runner records, and rows misclassify unmet. The pair
// separates the two states:
//
//   - Both samples carry inflation: the bracket covers the row's
//     window on both sides, so the agreed level (the pair mean)
//     normalizes the walls as the gate specifies. The row reads unmet
//     when the normalized p99 still misses; else it reads
//     retained-with-variance.
//   - One sample carries inflation: the row's window may or may not
//     sit inside the episode. A raw miss cannot settle as code
//     evidence; the row reads retained-with-variance. Raw walls that
//     hold read holds.
//   - Neither sample carries inflation: the raw verdict stands, and
//     the row reads unmet only when the raw budget row genuinely
//     misses.
//
// Floor-kind budgets normalize nowhere (the live recipes cannot bind
// them; validation forbids the pairing) and compare their raw walls in
// every class. The recorded-baseline regression leg stays on Evaluate;
// this path carries the live budget-row verdicts.
func EvaluateRow(in RowInput, cat Catalog) (RowVerdictRecord, error) {
	if err := checkMachineFactors(in.PreFactor, in.PostFactor); err != nil {
		return RowVerdictRecord{}, err
	}
	if _, ok := cat.ByID[in.Report.BudgetID]; !ok {
		return RowVerdictRecord{}, fmt.Errorf("bench: unknown budget %q", in.Report.BudgetID)
	}
	preInf, postInf := in.PreFactor >= InflationBand, in.PostFactor >= InflationBand
	factor := 1.0
	if preInf && postInf {
		factor = (in.PreFactor + in.PostFactor) / 2
	}
	vs, err := Evaluate(GateInput{Report: in.Report, MachineFactor: factor}, cat)
	if err != nil {
		return RowVerdictRecord{}, err
	}
	rec := RowVerdictRecord{Factor: factor}
	miss := false
	for _, v := range vs {
		rec.Violations = append(rec.Violations, v)
		if rec.Detail != "" {
			rec.Detail += "; "
		}
		rec.Detail += v.Detail
		if v.Kind == VioBudget {
			miss = true
		}
	}
	switch {
	case preInf && postInf:
		if miss {
			rec.Verdict = RowUnmet
		} else {
			// The agreed inflation normalizes the walls to a hold: the
			// raw miss the record carries is runner variance, not code
			// evidence.
			rec.Verdict = RowRetainedWithVariance
		}
	case preInf != postInf:
		if miss {
			rec.Verdict = RowRetainedWithVariance
		} else {
			rec.Verdict = RowHolds
		}
	default:
		if miss {
			rec.Verdict = RowUnmet
		} else {
			rec.Verdict = RowHolds
		}
	}
	return rec, nil
}

// checkMachineFactors guards the same range the gate applies to one
// factor: both sides of a live pair stay in (0, 10].
func checkMachineFactors(fs ...float64) error {
	for _, f := range fs {
		if f <= 0 || f > 10 {
			return fmt.Errorf("bench: machine factor %g outside (0, 10]", f)
		}
	}
	return nil
}
