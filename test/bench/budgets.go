// Package bench (TR-24) implements the spec's benchmark harness in-repo:
// the budget table and the scenario inventory it states as typed data,
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

import (
	"fmt"
)

// BudgetKind pins the comparison direction the spec's budget table states per row: a
// latency ceiling (µs) or a throughput floor (req/s).
type BudgetKind string

const (
	// CeilingP99 is a latency ceiling row; Value is the p99 bound in µs
	// unless the row carries its own p50 bound.
	CeilingP99 BudgetKind = "ceiling_p99"
	// FloorReqPS is a throughput floor row; Value is req/s.
	FloorReqPS BudgetKind = "floor_reqps"
)

// Budget encodes one budget-table stage row from the spec. P50us carries the row's secondary
// p50 bound when the spec states one (the end-to-end hop row states p99
// and p50); M2 marks the row the spec's adoption gates list as M2.
type Budget struct {
	ID         string
	SpecRow    string // the budget-table stage label this row encodes
	Kind       BudgetKind
	Value      float64 // µs for ceilings; req/s for floors
	P50us      float64 // optional p50 ceiling; 0 = the row states none
	EnforcedBy string
	M2         bool // the spec's M2 adoption-gate row
}

// Catalog is the loaded budget table keyed by budget id.
type Catalog struct {
	ByID map[string]Budget
}

// LoadBudgets returns the spec's budget table. Rows read 1:1 off the spec
// (the budget table's kernel-cache line encodes as its two stated regimes: the
// direct short-circuit and the context fetch). A violated budget is a
// recorded finding, never a silently-fudged row: the spec marks the
// userspace budgets targets pending PoC validation.
func LoadBudgets() (Catalog, error) {
	rows := []Budget{
		{ID: "xdp-hot-path", SpecRow: "XDP shield (ACL/flood/cache/ban-hit path)", Kind: CeilingP99, Value: 10, EnforcedBy: "shield DaemonSet, node NIC"},
		{ID: "tc-classifier-emit", SpecRow: "TC classifier + ringbuf emit", Kind: CeilingP99, Value: 20, EnforcedBy: "shield DaemonSet"},
		{ID: "engine-inspect-8k", SpecRow: "Engine parse + deep inspect (CRS+CEL+schema, 8KB body)", Kind: CeilingP99, Value: 600, EnforcedBy: "engine"},
		{ID: "engine-inspect-64k", SpecRow: "Engine parse + deep inspect (64KB JSON body)", Kind: CeilingP99, Value: 1200, EnforcedBy: "engine"},
		{ID: "ml-scorer-local", SpecRow: "ML local scorer (in-band, parallel with rules)", Kind: CeilingP99, Value: 1000, EnforcedBy: "engine ML tier"},
		{ID: "e2e-inline-hop-8k", SpecRow: "Total inline hop added vs direct (8KB, full CRS)", Kind: CeilingP99, Value: 1500, P50us: 300, EnforcedBy: "end-to-end gate", M2: true},
		{ID: "kernel-cache-direct", SpecRow: "Kernel-cached verdict/ban short-circuit (direct)", Kind: CeilingP99, Value: 1, EnforcedBy: "shield"},
		{ID: "kernel-cache-context", SpecRow: "Kernel-cached verdict/ban short-circuit (context fetch)", Kind: CeilingP99, Value: 100, EnforcedBy: "shield"},
		{ID: "engine-throughput-replica", SpecRow: "Throughput per engine replica (4 vCPU, CRS+schema)", Kind: FloorReqPS, Value: 10000, EnforcedBy: "load gate"},
	}
	c := Catalog{ByID: make(map[string]Budget, len(rows))}
	for _, b := range rows {
		if b.ID == "" || b.SpecRow == "" || b.EnforcedBy == "" {
			return Catalog{}, fmt.Errorf("bench: budget row %+v: empty id, spec row or enforcer", b)
		}
		if b.Value <= 0 {
			return Catalog{}, fmt.Errorf("bench: budget %q: non-positive value %g", b.ID, b.Value)
		}
		if b.Kind != CeilingP99 && b.Kind != FloorReqPS {
			return Catalog{}, fmt.Errorf("bench: budget %q: unknown kind %q", b.ID, b.Kind)
		}
		if b.P50us < 0 || (b.P50us > 0 && b.P50us >= b.Value) {
			return Catalog{}, fmt.Errorf("bench: budget %q: p50 bound %g not under p99 %g", b.ID, b.P50us, b.Value)
		}
		if _, dup := c.ByID[b.ID]; dup {
			return Catalog{}, fmt.Errorf("bench: budget %q doubles an earlier row", b.ID)
		}
		c.ByID[b.ID] = b
	}
	if len(c.ByID) == 0 {
		return Catalog{}, fmt.Errorf("bench: the budget table is empty")
	}
	return c, nil
}

// ValidateRecipes checks every recipe resolves against the budget
// catalog and the scenario inventory: known ids, a latency budget the
// CI runner can bind, and a driveable scenario.
func ValidateRecipes(cat Catalog, scens []Scenario, rs []Recipe) error {
	scenByID := map[string]Scenario{}
	for _, s := range scens {
		if s.ID == "" {
			return fmt.Errorf("bench: scenario with empty id")
		}
		if _, dup := scenByID[s.ID]; dup {
			return fmt.Errorf("bench: scenario %q doubles an earlier row", s.ID)
		}
		scenByID[s.ID] = s
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if r.ID == "" {
			return fmt.Errorf("bench: recipe with empty id")
		}
		if seen[r.ID] {
			return fmt.Errorf("bench: recipe %q doubles an earlier recipe", r.ID)
		}
		seen[r.ID] = true
		s, ok := scenByID[r.Scenario]
		if !ok {
			return fmt.Errorf("bench: recipe %q cites unknown scenario %q", r.ID, r.Scenario)
		}
		if !s.Driveable {
			return fmt.Errorf("bench: recipe %q binds scenario %q, not driveable (%s)", r.ID, r.Scenario, s.Gate)
		}
		b, ok := cat.ByID[r.BudgetID]
		if !ok {
			return fmt.Errorf("bench: recipe %q cites unknown budget %q", r.ID, r.BudgetID)
		}
		if b.Kind == FloorReqPS {
			return fmt.Errorf("bench: recipe %q binds floor budget %q; throughput cells belong to the lab load gate", r.ID, b.ID)
		}
		if r.Iterations <= 0 || r.Warmup < 0 {
			return fmt.Errorf("bench: recipe %q: bounds out of range (iters=%d warmup=%d)", r.ID, r.Iterations, r.Warmup)
		}
	}
	return nil
}
