// stage.go carries the S7 ladder stage (§19.1, TR-21): the in-band ML
// scorer. FeatureView extraction, the normalized signature, the
// cache-gated judge annotation and the budget-gated in-band score fold
// into ONE log-only fragment; the §20.1 R6 contract is structural here —
// the hard budget gate never waits past the deadline, and the fragment is
// never decisive (verdicts are never LLM-only, §14.2 item 4).
package ml

import (
	"sync/atomic"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// ScorerConfig wires the S7 scorer (deps injected; judge and cache are
// optional seams — nil = not consulted).
type ScorerConfig struct {
	// Model is the required in-band scorer.
	Model Model
	// Budget is the hard in-band budget (§20.1 R6: ONNX hard budget;
	// §17.1: the ML local scorer budget is 1 ms p99).
	Budget time.Duration
	// EscalateTau is the escalation threshold: a score at or above it
	// submits to the judge (§14.2: score >= escalation tau).
	EscalateTau float64
	// Judge is the optional async judge (nil = no escalation).
	Judge *AsyncJudge
	// Cache is the optional judge-verdict cache (nil = no annotation).
	Cache *VerdictCache
}

// Scorer is the §14 ML scorer on ladder stage S7 (TR-21): budget-gated
// in-band scoring + the suspicious-band escalation to the async judge.
// The counters are plain counts (the TR-11 exporter owns rates); Safe for
// concurrent use through the atomics.
type Scorer struct {
	model  Model
	budget time.Duration
	tau    float64
	judge  *AsyncJudge
	cache  *VerdictCache

	// Scored counts completed in-band scorings (any band).
	Scored atomic.Int64
	// Suspicious counts scorings at or above the escalation threshold.
	Suspicious atomic.Int64
	// Breaches counts in-band budget breaches (§20.1 R6: hard budget).
	Breaches atomic.Int64
}

// NewScorer builds the S7 scorer. A nil model, a non-positive budget or a
// tau outside [0, 1] is a wiring error.
func NewScorer(cfg ScorerConfig) (*Scorer, error) {
	return nil, nil // TR-21 RED stub
}

// Stage pins the fixed §19.1 ladder position: S7.
func (s *Scorer) Stage() ladder.Stage { return ladder.StageML }

// Evaluate folds the tx's ML tier into one fragment (always log-only at
// this slice):
//
//   - no parsed §11.3 view: no opinion (the parse stages own the tx);
//   - cached judge verdict for the signature: the fragment annotates with
//     the judged label (a recorded artifact, never fabricated);
//   - an in-band score at or above tau: the fragment logs the model rule
//     and the submission goes to the async judge;
//   - a budget breach (the model's context error): no fragment, no
//     fabricated verdict — the counter carries the event (§20.1 R6).
func (s *Scorer) Evaluate(tx *ingest.TxContext) *ladder.Verdict {
	return nil // TR-21 RED stub
}
