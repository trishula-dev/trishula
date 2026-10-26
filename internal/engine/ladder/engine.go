package ladder

import (
	"fmt"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// Evaluator is one ladder stage's evaluation handle. Stage() pins the
// evaluator to its fixed ladder position; Evaluate returns a fragment
// (nil = no opinion). Injection keeps the host CI suite kernel-free —
// the S0 evaluator wraps the shield maps on Linux only (TR-05c).
type Evaluator interface {
	Stage() Stage
	Evaluate(tx *ingest.TxContext) *Verdict
}

// Engine walks the fixed S0–S7 ladder over a transaction (the reference-implementation
// Engine.EvaluateTx). Slots hold injected evaluators; unwired slots are
// skipped, so a slice wires exactly the stages it carries.
type Engine struct {
	slots [stageCount]Evaluator
}

// NewEngine returns an empty ladder (no stages wired).
func NewEngine() *Engine { return &Engine{} }

// Use wires ev into its declared slot, replacing any prior occupant.
// The ladder is fixed-size by design: an out-of-range stage, a nil
// evaluator or a stage/evaluator mismatch is a wiring error, not a
// silent skip.
func (e *Engine) Use(st Stage, ev Evaluator) error {
	if !st.Valid() {
		return fmt.Errorf("stage %d outside ladder range 0–%d", int(st), int(stageCount-1))
	}
	if ev == nil {
		return fmt.Errorf("stage %d: nil evaluator", int(st))
	}
	if ev.Stage() != st {
		return fmt.Errorf("stage %d: evaluator declares stage %d", int(st), int(ev.Stage()))
	}
	e.slots[st] = ev
	return nil
}

// EvaluateTx walks S0→S7 in fixed order, folding every stage fragment
// through Resolve; the first decisive fragment stops the walk. Each run
// stage records one verdict-record row (TR-194: walk order, the §3.4
// token, matched rules, the stage's µs wall — unwired or short-circuited
// stages leave no row).
func (e *Engine) EvaluateTx(tx *ingest.TxContext) *Verdict {
	acc := &Verdict{Action: ActionAllow, Phase: PhaseRequestHeaders}
	for st, ev := range e.slots {
		if ev == nil {
			continue
		}
		// TR-194 (issue #236): the stage's row — measured over this
		// stage's own Evaluate leg; 0 µs = the sub-µs floor.
		start := time.Now()
		frag := ev.Evaluate(tx)
		wall := time.Since(start).Microseconds()
		acc.Rows = append(acc.Rows, Row{
			Stage:   Stage(st),
			Matched: fragmentRules(frag),
			US:      wall,
		})
		if Resolve(acc, frag) {
			break
		}
	}
	return acc
}

// fragmentRules returns the fragment's contributed rule ids (nil-safe;
// the row shares the walk's read-only view of the fragment).
func fragmentRules(frag *Verdict) []RuleID {
	if frag == nil {
		return nil
	}
	return frag.Rules
}

// Resolve folds one stage fragment into the walk accumulator per the
// ladder discipline and reports whether the walk must stop. Decisive
// fragments short-circuit (first decisive wins); log fragments accumulate
// into Rules/Score and the walk continues; allow fragments are no-ops
// (pass accumulates nothing — ban-score inputs must not absorb pass
// evidence). A nil fragment is a no-op and never stops the walk.
func Resolve(acc *Verdict, frag *Verdict) bool {
	if acc == nil || frag == nil {
		return false
	}
	if frag.Action.Decisive() {
		acc.Action = frag.Action
		acc.Rules = append(acc.Rules, frag.Rules...)
		acc.Score += frag.Score
		if frag.Phase != "" {
			acc.Phase = frag.Phase
		}
		return true
	}
	if frag.Action == ActionLog {
		acc.Action = ActionLog // log outranks pass; evidence accumulates below
		acc.Rules = append(acc.Rules, frag.Rules...)
		acc.Score += frag.Score
		if frag.Phase != "" {
			acc.Phase = frag.Phase
		}
	}
	return false // allow fragments (and unwired opinions) pass through
}
