package ladder

import (
	"fmt"

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

// Engine walks the fixed S0–S7 ladder over a transaction (§19.1
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
// through Resolve; the first decisive fragment stops the walk.
func (e *Engine) EvaluateTx(tx *ingest.TxContext) *Verdict {
	acc := &Verdict{Action: ActionAllow, Phase: PhaseRequestHeaders}
	for _, ev := range e.slots {
		if ev == nil {
			continue
		}
		if Resolve(acc, ev.Evaluate(tx)) {
			break
		}
	}
	return acc
}

// Resolve folds one stage fragment into the walk accumulator per the
// ladder discipline and reports whether the walk must stop. Decisive
// fragments short-circuit (first decisive wins); log fragments accumulate
// into Rules/Score and the walk continues; allow fragments are no-ops
// (pass accumulates nothing — ban-score inputs must not absorb pass
// evidence). A nil fragment is a no-op and never stops the walk.
func Resolve(acc *Verdict, frag *Verdict) bool {
	return false // TR-05a GREEN: decisive short-circuit + log accumulation pending (watched RED below)
}
