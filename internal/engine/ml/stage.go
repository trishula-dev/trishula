// stage.go carries the S7 ladder stage (the reference-implementation sketch, TR-21): the in-band ML
// scorer. FeatureView extraction, the normalized signature, the
// cache-gated judge annotation and the budget-gated in-band score fold
// into ONE log-only fragment; the spec's R6 risk-row contract is structural here —
// the hard budget gate never waits past the deadline, and the fragment is
// never decisive (verdicts are never LLM-only, the spec's hand-off item 4).
package ml

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// Band is the v0 score-band vocabulary (the spec's hand-off rule: the escalation tau cuts
// the in-band score).
type Band string

const (
	// BandClean is the below-tau band (log-silent; the counters carry the
	// telemetry).
	BandClean Band = "clean"
	// BandSuspicious is the at-or-above-tau band (escalates when a judge
	// is wired).
	BandSuspicious Band = "suspicious"
)

// modelRuleID renders the in-band rule id (ml:<model-id>:<band>).
func modelRuleID(modelID string, b Band) ladder.RuleID {
	return ladder.RuleID("ml:" + modelID + ":" + string(b))
}

// judgeRuleID renders the judge annotation rule id
// (ml:judge:<judge-model-id>:<label>).
func judgeRuleID(jv JudgeVerdict) ladder.RuleID {
	return ladder.RuleID("ml:judge:" + jv.ModelID + ":" + jv.Label)
}

// ScorerConfig wires the S7 scorer (deps injected; judge and cache are
// optional seams — nil = not consulted).
type ScorerConfig struct {
	// Model is the required in-band scorer.
	Model Model
	// Budget is the hard in-band budget (the spec's R6 risk row: ONNX hard budget;
	// the spec's performance budgets: the ML local scorer budget is 1 ms p99).
	Budget time.Duration
	// EscalateTau is the escalation threshold: a score at or above it
	// submits to the judge (the spec's hand-off rule: score >= escalation tau).
	EscalateTau float64
	// Judge is the optional async judge (nil = no escalation).
	Judge *AsyncJudge
	// Cache is the optional judge-verdict cache (nil = no annotation).
	Cache *VerdictCache
}

// Scorer is the spec's ML scorer on ladder stage S7 (TR-21): budget-gated
// in-band scoring + the suspicious-band escalation to the async judge.
// The counters are plain counts (the TR-11 exporter owns rates); the
// scorer is safe for concurrent use through the atomics.
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
	// Breaches counts in-band budget breaches (the spec's R6 risk row: hard budget).
	Breaches atomic.Int64
}

// NewScorer builds the S7 scorer. A nil model, a non-positive budget or a
// tau outside [0, 1] is a wiring error.
func NewScorer(cfg ScorerConfig) (*Scorer, error) {
	if cfg.Model == nil {
		return nil, fmt.Errorf("ml scorer: nil model")
	}
	if cfg.Budget <= 0 {
		return nil, fmt.Errorf("ml scorer: budget %s must be positive", cfg.Budget)
	}
	if cfg.EscalateTau < 0 || cfg.EscalateTau > 1 {
		return nil, fmt.Errorf("ml scorer: escalate tau %g outside [0, 1]", cfg.EscalateTau)
	}
	return &Scorer{
		model:  cfg.Model,
		budget: cfg.Budget,
		tau:    cfg.EscalateTau,
		judge:  cfg.Judge,
		cache:  cfg.Cache,
	}, nil
}

// Stage pins the fixed reference-implementation ladder position: S7.
func (s *Scorer) Stage() ladder.Stage { return ladder.StageML }

// Evaluate folds the tx's ML tier into one fragment (always log-only at
// this slice):
//
//   - no parsed CEL view (the spec's request view): no opinion (the parse stages own the tx);
//   - an in-band score at or above tau: the fragment logs the model rule
//     and the submission goes to the async judge;
//   - a below-tau score with no cached verdict: NO fragment (the
//     silent-clean posture; the counters carry the telemetry);
//   - the cached judge verdict for the signature: the fragment annotates
//     with the judged label (a recorded artifact, never fabricated);
//   - a budget breach (the model's context error): no in-band rule, no
//     fabricated verdict — the counter carries the event (the spec's R6 risk row).
//
// The in-band deadline rides the context (the Model contract); the
// evaluation goroutine never waits past it for a conforming model.
func (s *Scorer) Evaluate(tx *ingest.TxContext) *ladder.Verdict {
	view := ladder.TxView(tx)
	if view == nil {
		return nil // parse stages own the tx
	}
	fv, _ := Extract(view, tx)
	sig := Signature(view)
	frag := s.baseFragment()

	// In-band scoring under the hard budget (the spec's R6 risk row).
	ctx, cancel := context.WithTimeout(context.Background(), s.budget)
	defer cancel()
	val, err := s.model.Score(ctx, fv)
	if err != nil {
		// The model's context errored (budget breach on a conforming
		// model): skip — no in-band rule, no fabricated verdict; the
		// counter carries the event. The annotation (below) still stands.
		s.Breaches.Add(1)
	} else {
		s.Scored.Add(1)
		if val >= s.tau { // the spec's hand-off rule: score >= escalation tau
			s.Suspicious.Add(1)
			frag.Rules = append(frag.Rules, modelRuleID(s.model.ID(), BandSuspicious))
			frag.Score += int64(val * 100) // hundredths: the ladder's score vocabulary
			if s.judge != nil {
				s.judge.Submit(fv, sig)
			}
		}
		// A below-tau score fires no rule: the Scored/Suspicious counters
		// carry the telemetry (the spec's hand-off: the drift watch reads rates, not
		// per-tx fragments).
	}

	// The cached judge verdict annotates the fragment (a recorded
	// artifact, never fabricated; consulted under the wired judge's model
	// tag — the tag that produced every entry).
	if s.judge != nil && s.cache != nil {
		if jv, ok := s.cache.Get(sig, s.judge.ID()); ok {
			frag.Rules = append(frag.Rules, judgeRuleID(jv))
		}
	}
	if len(frag.Rules) == 0 {
		return nil // nothing to report: the silent-clean posture
	}
	return frag
}

// baseFragment is the log-only S7 fragment shell (the spec's hand-off item 4: verdicts
// are never LLM-only — this slice's fragment never carries a decisive
// action; pinned by the fragment tests).
func (s *Scorer) baseFragment() *ladder.Verdict {
	return &ladder.Verdict{
		Action: ladder.ActionLog,
		Phase:  ladder.PhaseRequestHeaders,
	}
}
