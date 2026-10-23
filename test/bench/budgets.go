// Package bench (TR-24) implements the PRD §17 benchmark harness in-repo:
// the §17.1 budget table and the §17.2 scenario inventory as typed data,
// the driveable engine-side scenarios measured over the committed CRS
// reference path (test/crs-differential), the nearest-rank p50/p99
// estimator, and the CI gate that turns measurements into budget and
// regression verdicts.
//
// Kernel-plane scenarios (XDP ban-hit path, shield flood, NGF baseline)
// need the lab and VM runtimes. They stay inventoried as data with their
// plane, and the guard pins that inventory, so a scenario never gets
// faked by a CI-mode stub. Kernel-dependent scenarios stay behind lab
// gates per AGENTS.md; this package is CI-buildable (`go test ./...`).
package bench

import "errors"

// BudgetKind pins the comparison direction §17.1 states per row: a
// latency ceiling (µs) or a throughput floor (req/s).
type BudgetKind string

const (
	// CeilingP99 is a latency ceiling row; Value is the p99 bound in µs
	// unless the row carries its own p50 bound.
	CeilingP99 BudgetKind = "ceiling_p99"
	// FloorReqPS is a throughput floor row; Value is req/s.
	FloorReqPS BudgetKind = "floor_reqps"
)

// Budget encodes one §17.1 stage row. P50us carries the row's secondary
// p50 bound when the PRD states one (the end-to-end hop row states p99
// and p50); M2 marks the row §21 lists as the M2 adoption gate.
type Budget struct {
	ID         string
	PRDRow     string // the §17.1 stage label this row encodes
	Kind       BudgetKind
	Value      float64 // µs for ceilings; req/s for floors
	P50us      float64 // optional p50 ceiling; 0 = the row states none
	EnforcedBy string
	M2         bool // the §21 M2 adoption gate row
}

// Catalog is the loaded budget table keyed by budget id.
type Catalog struct {
	ByID map[string]Budget
}

var errNotImplemented = errors.New("bench: not implemented (TR-24 RED state)")

// LoadBudgets returns the §17.1 budget table.
func LoadBudgets() (Catalog, error) {
	return Catalog{}, errNotImplemented
}

// ValidateRecipes checks every recipe resolves against the budget
// catalog and the scenario inventory: known ids, a latency budget the
// CI runner can bind, and a driveable scenario.
func ValidateRecipes(cat Catalog, scens []Scenario, rs []Recipe) error {
	return errNotImplemented
}
