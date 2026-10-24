package fastpathdifferential

// budgets.go carries the mismatch budget (the shadow report's budget
// table, the census record section 10): the mismatch classes the shadow
// differential names, the recorded census counts, and the accepted
// ceilings.
//
// Rules with teeth:
//
//   - A budget row the gate has not recorded yet fails the budget gate:
//     a run carries no verdict until a run records the census.
//   - The live census over a recorded ceiling reads as a regression. A
//     ceiling never re-pins to pass a comparison; only a maintainer
//     re-pins with a fresh recorded run (the bench precedent, TR-24).
//   - Zero-tolerance classes are recorded by design. They hold the gate
//     at zero: a new member of a zero-tolerance class is a finding, not
//     a budget spend.

// MismatchBudget is one budget row: the class, its definition, the record
// state and the accepted ceiling.
type MismatchBudget struct {
	// Class names the mismatch class (the projection's vocabulary).
	Class string
	// Definition states the class boundary one sentence long.
	Definition string
	// Recorded states whether a gate run recorded the census count.
	// Unrecorded rows fail the gate (no recorded census, no verdict).
	Recorded bool
	// Count is the recorded census at the recorded sha (informational).
	Count int
	// Budget is the accepted ceiling; the gate reads live over budget as
	// a regression.
	Budget int
}

// MismatchBudgets returns the mismatch budget table.
func MismatchBudgets() []MismatchBudget {
	return []MismatchBudget{
		{
			Class:      "unexplained",
			Definition: "a fast-path/engine pair outside every named class",
			Recorded:   true,
			Budget:     0,
		},
		{
			Class:      "failopen-drop",
			Definition: "a drop without compiled drop-row backing (row truth over the staged rows)",
			Recorded:   true,
			Budget:     0,
		},
		{
			Class:      "unresolved-engine",
			Definition: "the engine stream fails to resolve a corpus case (error verdict)",
			Recorded:   true,
			Budget:     0,
		},
		{
			Class:      "kernel-fidelity",
			Definition: "the kernel program's return value disagrees with the userspace decision (kernel leg)",
			Recorded:   true,
			Budget:     0,
		},
		{
			Class:      "plane-split",
			Definition: "a compiled drop beside a non-decisive engine verdict, or a forward beside a decisive one (the class split; the census reports it, the engine stays the detection authority)",
			// Recorded from the gate census over the tracked corpus:
			// 4 drop-vs-nondecisive cases and 1 forward-vs-decisive
			// case. The ceiling holds until a maintainer re-pins with a
			// fresh recorded run.
			Recorded: true,
			Count:    5,
			Budget:   5,
		},
	}
}

// BudgetVerdict is one row's gate read: holds or names the regression.
type BudgetVerdict struct {
	// Class is the budget row's class.
	Class string
	// Live is the run's live count for the class.
	Live int
	// Holds names the gate read.
	Holds bool
	// Detail carries the finding verdict verbatim.
	Detail string
}

// VerifyBudgets reads the live census against the budget table. The read
// fails closed: an unrecorded row fails the gate, a live count over the
// ceiling names the regression, everything else holds.
func VerifyBudgets(live map[string]int) []BudgetVerdict {
	rows := MismatchBudgets()
	verdicts := make([]BudgetVerdict, 0, len(rows))
	for _, row := range rows {
		liveCount := live[row.Class]
		v := BudgetVerdict{Class: row.Class, Live: liveCount}
		switch {
		case !row.Recorded:
			v.Holds = false
			v.Detail = "unrecorded: the census is not recorded; record it from a fresh gate run before any verdict"
		case liveCount > row.Budget:
			v.Holds = false
			v.Detail = "regression: live count over the recorded budget; re-pin needs a fresh recorded run (maintainer only)"
		default:
			v.Holds = true
			v.Detail = "holds"
		}
		verdicts = append(verdicts, v)
	}
	return verdicts
}
