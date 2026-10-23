package ml

import (
	"context"
	"testing"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// --- fixtures -------------------------------------------------------------

// fixedModel answers instantly with a fixed score (the deterministic
// model seam; it honors a dead context per the budget contract).
type fixedModel struct {
	id string
	v  float64
}

func (m fixedModel) ID() string { return m.id }

func (m fixedModel) Score(ctx context.Context, _ FeatureView) (float64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return m.v, nil
}

// slowModel parks until the deadline or the release channel, then reports
// the context cause — the budget-breach fixture (timer-free).
type slowModel struct {
	release chan struct{}
}

func (m slowModel) ID() string { return "slow" }

func (m slowModel) Score(ctx context.Context, _ FeatureView) (float64, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-m.release:
		return 0, nil
	}
}

// scorerFixture builds a validated S7 scorer around a model (+ optional
// judge wiring done per test).
func scorerFixture(t *testing.T, model Model, mutate func(*ScorerConfig)) *Scorer {
	t.Helper()
	cfg := ScorerConfig{Model: model, Budget: time.Second, EscalateTau: 0.5}
	if mutate != nil {
		mutate(&cfg)
	}
	sc, err := NewScorer(cfg)
	if err != nil {
		t.Fatalf("NewScorer: %v", err)
	}
	if sc == nil {
		t.Fatal("NewScorer: nil scorer with nil error")
	}
	return sc
}

// suspiciousFixture is a tx whose fixed model scores decisively above the
// fixture tau (0.5).
func suspiciousFixture(t *testing.T) *ingest.TxContext {
	return txWithView(t, "POST", "/v1/chat/completions", "q=1", map[string]int64{"5m": 41}, 7)
}

// sigOf computes the signature of the standard fixture's view.
func sigOf(t *testing.T, method, path, query string) string {
	t.Helper()
	return Signature(&cel.Request{Method: method, Path: path, Query: query})
}

// --- S7 stage tests ---------------------------------------------------------

// TestScorerSuspiciousFragmentLogOnly pins the score path of the §20.1 R6
// contract: the S7 fragment is LOG-only (never decisive), names the model
// + band, carries the score in hundredths, and stamps the phase.
func TestScorerSuspiciousFragmentLogOnly(t *testing.T) {
	sc := scorerFixture(t, fixedModel{id: "ref-line-v0", v: 0.9}, nil)
	tx := suspiciousFixture(t)
	frag := sc.Evaluate(tx)
	if frag == nil {
		t.Fatal("suspicious score produced no fragment")
	}
	if frag.Action != ladder.ActionLog {
		t.Errorf("action: got %q, want log (log-only slice; a judge never decides either)", frag.Action)
	}
	want := ladder.RuleID("ml:ref-line-v0:suspicious")
	if len(frag.Rules) != 1 || frag.Rules[0] != want {
		t.Errorf("rules: got %v, want [%v]", frag.Rules, want)
	}
	if frag.Score != 90 {
		t.Errorf("score: got %d, want 90 (hundredths of 0.9)", frag.Score)
	}
	if frag.Phase != ladder.PhaseRequestHeaders {
		t.Errorf("phase: got %q, want request_headers", frag.Phase)
	}
	if sc.Scored.Load() != 1 || sc.Suspicious.Load() != 1 || sc.Breaches.Load() != 0 {
		t.Errorf("counters: scored=%d suspicious=%d breaches=%d, want 1/1/0",
			sc.Scored.Load(), sc.Suspicious.Load(), sc.Breaches.Load())
	}
}

// TestScorerCleanNoFragment pins the silent-clean posture: a below-tau
// score carries no fragment (the counters carry the telemetry), never a
// fabricated log line.
func TestScorerCleanNoFragment(t *testing.T) {
	sc := scorerFixture(t, fixedModel{id: "ref-line-v0", v: 0.2}, nil)
	tx := suspiciousFixture(t)
	if frag := sc.Evaluate(tx); frag != nil {
		t.Errorf("clean score produced a fragment %+v, want none", frag)
	}
	if sc.Scored.Load() != 1 || sc.Suspicious.Load() != 0 {
		t.Errorf("counters: scored=%d suspicious=%d, want 1/0", sc.Scored.Load(), sc.Suspicious.Load())
	}
}

// TestScorerNoViewNil pins the no-fabrication rule: a tx with no parsed
// §11.3 view gets no S7 opinion.
func TestScorerNoViewNil(t *testing.T) {
	sc := scorerFixture(t, fixedModel{id: "m", v: 0.99}, nil)
	tx := &ingest.TxContext{}
	if frag := sc.Evaluate(tx); frag != nil {
		t.Errorf("view-less tx produced a fragment %+v, want none", frag)
	}
}

// TestScorerBudgetBreach is the §20.1 R6 hard-budget pin: a model parked
// past the deadline reports through its context; the stage skips (no
// fragment, no fabricated verdict), counts the breach, and never waits
// beyond the budget.
func TestScorerBudgetBreach(t *testing.T) {
	sm := slowModel{release: make(chan struct{})}
	sc := scorerFixture(t, sm, func(c *ScorerConfig) { c.Budget = 10 * time.Millisecond })
	tx := suspiciousFixture(t)
	frag := sc.Evaluate(tx)
	if frag != nil {
		t.Errorf("breached scoring produced a fragment %+v, want none (skip, never block)", frag)
	}
	if sc.Breaches.Load() != 1 || sc.Scored.Load() != 0 {
		t.Errorf("counters: breaches=%d scored=%d, want 1/0", sc.Breaches.Load(), sc.Scored.Load())
	}
}

// TestScorerCachedJudgeAnnotation pins the T2 consult: the cached judge
// verdict annotates the fragment under the judge rule id, beside (or
// without) this request's in-band model rule.
func TestScorerCachedJudgeAnnotation(t *testing.T) {
	now := baseNow
	cache := mustCache(t, fixtureClock(&now))
	sig := sigOf(t, "POST", "/v1/chat/completions", "q=1")
	cache.Put(sig, "j1", JudgeVerdict{Label: "prompt-injection", ModelID: "j1", Confidence: 0.7, Reason: "r"})
	t.Run("suspicious: beside the model rule", func(t *testing.T) {
		sc := scorerFixture(t, fixedModel{id: "ref", v: 0.9}, func(c *ScorerConfig) { c.Cache = cache })
		frag := sc.Evaluate(suspiciousFixture(t))
		if frag == nil {
			t.Fatal("no fragment")
		}
		if frag.Action != ladder.ActionLog {
			t.Errorf("action: got %q, want log", frag.Action)
		}
		wantModel := ladder.RuleID("ml:ref:suspicious")
		wantJudge := ladder.RuleID("ml:judge:j1:prompt-injection")
		if len(frag.Rules) != 2 || frag.Rules[0] != wantModel || frag.Rules[1] != wantJudge {
			t.Errorf("rules: got %v, want [%v %v]", frag.Rules, wantModel, wantJudge)
		}
	})
	t.Run("clean: the judge rule alone", func(t *testing.T) {
		sc := scorerFixture(t, fixedModel{id: "ref", v: 0.1}, func(c *ScorerConfig) { c.Cache = cache })
		frag := sc.Evaluate(suspiciousFixture(t))
		if frag == nil {
			t.Fatal("no fragment")
		}
		wantJudge := ladder.RuleID("ml:judge:j1:prompt-injection")
		if len(frag.Rules) != 1 || frag.Rules[0] != wantJudge {
			t.Errorf("rules: got %v, want [%v]", frag.Rules, wantJudge)
		}
		if frag.Score != 0 {
			t.Errorf("score: got %d, want 0 (no in-band rule fired)", frag.Score)
		}
	})
}

// TestScorerEscalationSubmitsJudge pins the §14.2 mini-loop: a suspicious
// in-band score submits to the wired judge exactly once (cache-deduped on
// repeats), the judged verdict lands in the cache + sink, and a repeat
// evaluation annotates from the cache.
func TestScorerEscalationSubmitsJudge(t *testing.T) {
	j := &fakeJudge{id: "j1", label: "prompt-injection"}
	now := baseNow
	aj, cache, sink := judgeFixture(t, j, fixtureClock(&now), 8)
	sc := scorerFixture(t, fixedModel{id: "ref", v: 0.9}, func(c *ScorerConfig) { c.Judge = aj; c.Cache = cache })
	tx := suspiciousFixture(t)

	frag := sc.Evaluate(tx)
	if frag == nil || len(frag.Rules) != 1 || frag.Rules[0] != ladder.RuleID("ml:ref:suspicious") {
		t.Fatalf("fragment: got %+v, want the single pre-judgement model rule", frag)
	}
	if err := aj.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := j.calls.Load(); got != 1 {
		t.Errorf("judge calls: got %d, want 1 (the suspicious band escalates once)", got)
	}
	if got := sink.sigs.Load(); got != 1 {
		t.Errorf("sink records: got %d, want 1", got)
	}
	repeat := sc.Evaluate(tx)
	if repeat == nil || len(repeat.Rules) != 2 {
		t.Fatalf("repeat fragment: got %+v, want the annotated rules", repeat)
	}
	if repeat.Rules[1] != ladder.RuleID("ml:judge:j1:prompt-injection") {
		t.Errorf("repeat rules: got %v, want the judged annotation attached", repeat.Rules)
	}
	if repeat.Action != ladder.ActionLog {
		t.Errorf("repeat action: got %q, want log (never decisive)", repeat.Action)
	}
}

// TestScorerSuspiciousWithoutJudge pins the optional-judge rows: a
// suspicious score with NO judge wired still logs its fragment (the
// counters carry it) and submissions stay unwired-by-design (nil judge is
// never a panic).
func TestScorerSuspiciousWithoutJudge(t *testing.T) {
	sc := scorerFixture(t, fixedModel{id: "ref", v: 0.9}, nil)
	frag := sc.Evaluate(suspiciousFixture(t))
	if frag == nil || frag.Action != ladder.ActionLog {
		t.Fatalf("fragment: got %+v, want a log fragment", frag)
	}
}

// TestScorerValidates pins the wiring-error rows on the constructor.
func TestScorerValidates(t *testing.T) {
	rows := []struct {
		name   string
		mutate func(*ScorerConfig)
		wantOk bool
	}{
		{"nil model", func(c *ScorerConfig) { c.Model = nil }, false},
		{"zero budget", func(c *ScorerConfig) { c.Budget = 0 }, false},
		{"tau below zero", func(c *ScorerConfig) { c.EscalateTau = -0.1 }, false},
		{"tau above one", func(c *ScorerConfig) { c.EscalateTau = 1.1 }, false},
		{"valid", func(c *ScorerConfig) {}, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			cfg := ScorerConfig{Model: fixedModel{id: "m", v: 0.5}, Budget: time.Second, EscalateTau: 0.5}
			r.mutate(&cfg)
			if _, err := NewScorer(cfg); (err == nil) != r.wantOk {
				t.Errorf("NewScorer: err=%v, wantOk=%v", err, r.wantOk)
			}
		})
	}
}
