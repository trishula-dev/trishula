package bench

import "errors"

var errGate = errors.New("bench: not implemented (TR-24 RED state)")

// ViolationKind is the gate's violation taxonomy.
type ViolationKind string

const (
	// VioBudget: a ceiling budget exceeded (or floor not met).
	VioBudget ViolationKind = "budget_exceeded"
	// VioBudgetP50: a cell's p50 bound exceeded.
	VioBudgetP50 ViolationKind = "budget_p50_exceeded"
	// VioRegression: a cell regressed more than RegressionLimit over its
	// recorded baseline cell (§17.2: a p99 regression over 10% fails CI).
	VioRegression ViolationKind = "regression"
)

// RegressionLimit is the §17.2 CI gate: 10% over the recorded baseline.
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
func Evaluate(in GateInput, cat Catalog) ([]Violation, error) {
	return nil, errGate
}
