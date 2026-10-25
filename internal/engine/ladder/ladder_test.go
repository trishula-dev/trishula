package ladder

import (
	"fmt"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/http1"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// stubStage is a recording test double: counts calls, returns a fixed
// fragment. Stands in for the not-yet-wired detectors (the reference-implementation slots).
type stubStage struct {
	st    Stage
	calls int
	frag  *Verdict
}

func (s *stubStage) Stage() Stage { return s.st }

func (s *stubStage) Evaluate(_ *ingest.TxContext) *Verdict {
	s.calls++
	return s.frag
}

func fixtureTx() *ingest.TxContext {
	return &ingest.TxContext{Key: ingest.FlowKey{Family: ingest.FamilyV4}}
}

// TestActionVocabulary locks the reference-implementation Action values and the decisive
// classification (the spec's precedence rule: only block/challenge/ban stop the walk).
func TestActionVocabulary(t *testing.T) {
	for _, tc := range []struct {
		a        Action
		want     string
		decisive bool
	}{
		{ActionAllow, "allow", false},
		{ActionLog, "log", false},
		{ActionBlock, "block", true},
		{ActionChallenge, "challenge", true},
		{ActionBan, "ban", true},
	} {
		if string(tc.a) != tc.want {
			t.Errorf("action value: got %q, want %q", string(tc.a), tc.want)
		}
		if got := tc.a.Decisive(); got != tc.decisive {
			t.Errorf("action %q: Decisive()=%v, want %v", string(tc.a), got, tc.decisive)
		}
	}
}

// TestStageSlots locks the reference-implementation S0–S7 numbering (a renumbered ladder is
// a wire-level contract break: board issues, the spec sketch and kernel maps
// all name these positions).
func TestStageSlots(t *testing.T) {
	if StageKernel != 0 || StageMatcher != 1 || StageCRS != 2 || StageCEL != 3 ||
		StageSchema != 4 || StageBots != 5 || StageRateBan != 6 || StageML != 7 {
		t.Fatal("ladder slot numbering moved — S0–S7 positions are fixed by §19.1") // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
	}
	if Stage(8).Valid() || Stage(-1).Valid() {
		t.Error("stage range check: only S0–S7 are valid slots")
	}
}

func TestResolveNilFragmentNoop(t *testing.T) {
	acc := &Verdict{Action: ActionAllow, Phase: PhaseRequestHeaders}
	if Resolve(acc, nil) {
		t.Fatal("nil fragment stopped the walk")
	}
	if acc.Action != ActionAllow || acc.Rules != nil || acc.Score != 0 {
		t.Errorf("nil fragment mutated the accumulator: %+v", acc)
	}
}

// TestResolveDecisiveStops pins the decisive fragment contract: stop=true,
// action adopted, evidence contributed, phase stamped.
func TestResolveDecisiveStops(t *testing.T) {
	acc := &Verdict{Action: ActionAllow, Phase: PhaseRequestHeaders}
	stop := Resolve(acc, &Verdict{
		Action: ActionBlock,
		Rules:  []RuleID{"crs:942100"},
		Score:  5,
		Phase:  PhaseRequestBody,
	})
	if !stop {
		t.Error("decisive fragment did not stop the walk")
	}
	if acc.Action != ActionBlock {
		t.Errorf("resolved action: got %q, want block", acc.Action)
	}
	if len(acc.Rules) != 1 || acc.Rules[0] != "crs:942100" {
		t.Errorf("decisive fragment evidence lost: Rules=%v", acc.Rules)
	}
	if acc.Score != 5 {
		t.Errorf("decisive fragment score lost: Score=%d, want 5", acc.Score)
	}
	if acc.Phase != PhaseRequestBody {
		t.Errorf("decisive fragment phase not stamped: Phase=%q", acc.Phase)
	}
}

// TestResolveLogAccumulates pins the log semantics: never stops, rules and
// score accumulate in walk order, action upgrades allow→log (the spec's precedence rule: log
// outranks pass).
func TestResolveLogAccumulates(t *testing.T) {
	acc := &Verdict{Action: ActionAllow, Phase: PhaseRequestHeaders}
	if Resolve(acc, &Verdict{Action: ActionLog, Rules: []RuleID{"cel:seed"}, Score: 2}) {
		t.Fatal("log fragment stopped the walk")
	}
	if Resolve(acc, &Verdict{Action: ActionLog, Rules: []RuleID{"rate:breach"}, Score: 3}) {
		t.Fatal("second log fragment stopped the walk")
	}
	if acc.Action != ActionLog {
		t.Errorf("resolved action: got %q, want log", acc.Action)
	}
	if acc.Score != 5 {
		t.Errorf("log score accumulation: got %d, want 5", acc.Score)
	}
	if len(acc.Rules) != 2 || acc.Rules[0] != "cel:seed" || acc.Rules[1] != "rate:breach" {
		t.Errorf("log rules: got %v, want [cel:seed rate:breach] in walk order", acc.Rules)
	}
}

// TestResolveAllowAccumulatesNothing pins the pass contract: an allow
// fragment is a full no-op — its (empty) evidence must not leak Rules or
// Score into the ban inputs.
func TestResolveAllowAccumulatesNothing(t *testing.T) {
	acc := &Verdict{Action: ActionAllow, Phase: PhaseRequestHeaders}
	if Resolve(acc, &Verdict{Action: ActionAllow, Rules: []RuleID{"x"}, Score: 7}) {
		t.Fatal("allow fragment stopped the walk")
	}
	if acc.Action != ActionAllow || acc.Rules != nil || acc.Score != 0 {
		t.Errorf("allow fragment mutated the accumulator: %+v", acc)
	}
}

func TestEvaluateTxEmptyEngine(t *testing.T) {
	v := NewEngine().EvaluateTx(fixtureTx())
	if v.Action != ActionAllow {
		t.Errorf("empty ladder action: got %q, want allow", v.Action)
	}
	if v.Phase != PhaseRequestHeaders {
		t.Errorf("empty ladder phase: got %q, want request_headers", v.Phase)
	}
	if v.Rules != nil || v.Score != 0 {
		t.Errorf("empty ladder residue: Rules=%v Score=%d", v.Rules, v.Score)
	}
}

func TestEvaluateTxWalksEveryWiredStage(t *testing.T) {
	s0 := &stubStage{st: StageKernel}
	s3 := &stubStage{st: StageCEL}
	s7 := &stubStage{st: StageML}
	e := NewEngine()
	for _, st := range []struct {
		slot Stage
		ev   *stubStage
	}{{StageKernel, s0}, {StageCEL, s3}, {StageML, s7}} {
		if err := e.Use(st.slot, st.ev); err != nil {
			t.Fatalf("Use(%d): %v", int(st.slot), err)
		}
	}
	v := e.EvaluateTx(fixtureTx())
	if s0.calls != 1 || s3.calls != 1 || s7.calls != 1 {
		t.Errorf("walk completeness: S0=%d S3=%d S7=%d calls, want 1 each",
			s0.calls, s3.calls, s7.calls)
	}
	if v.Action != ActionAllow {
		t.Errorf("no-op walk action: got %q, want allow", v.Action)
	}
}

// TestS0DecisivePreventsS3Evaluation is the locked-order acceptance: a
// decisive kernel verdict short-circuits — later slots are not even
// evaluated.
func TestS0DecisivePreventsS3Evaluation(t *testing.T) {
	s0 := &stubStage{st: StageKernel, frag: &Verdict{
		Action: ActionBan,
		Rules:  []RuleID{"shield:ban"},
		Score:  10,
		Phase:  PhaseRequestHeaders,
	}}
	s3 := &stubStage{st: StageCEL}
	s6 := &stubStage{st: StageRateBan}
	e := NewEngine()
	if err := e.Use(StageKernel, s0); err != nil {
		t.Fatalf("Use(S0): %v", err)
	}
	if err := e.Use(StageCEL, s3); err != nil {
		t.Fatalf("Use(S3): %v", err)
	}
	if err := e.Use(StageRateBan, s6); err != nil {
		t.Fatalf("Use(S6): %v", err)
	}
	v := e.EvaluateTx(fixtureTx())
	if s0.calls != 1 {
		t.Errorf("S0 calls: got %d, want 1", s0.calls)
	}
	if s3.calls != 0 {
		t.Errorf("S3 evaluated after decisive S0 (calls=%d), want 0 — ladder order not enforced", s3.calls)
	}
	if s6.calls != 0 {
		t.Errorf("S6 evaluated after decisive S0 (calls=%d), want 0", s6.calls)
	}
	if v.Action != ActionBan {
		t.Errorf("resolved action: got %q, want ban", v.Action)
	}
	if len(v.Rules) != 1 || v.Rules[0] != "shield:ban" {
		t.Errorf("decisive evidence: Rules=%v", v.Rules)
	}
}

// TestDecisiveMidLadderStopsTail pins mid-ladder short-circuit: a decisive
// S3 stops S7 but the S0/S3 contributions before it are preserved.
func TestDecisiveMidLadderStopsTail(t *testing.T) {
	s3 := &stubStage{st: StageCEL, frag: &Verdict{
		Action: ActionBlock,
		Rules:  []RuleID{"cel:block"},
		Score:  1,
	}}
	s7 := &stubStage{st: StageML}
	e := NewEngine()
	if err := e.Use(StageCEL, s3); err != nil {
		t.Fatalf("Use(S3): %v", err)
	}
	if err := e.Use(StageML, s7); err != nil {
		t.Fatalf("Use(S7): %v", err)
	}
	v := e.EvaluateTx(fixtureTx())
	if s7.calls != 0 {
		t.Errorf("S7 evaluated after decisive S3 (calls=%d), want 0", s7.calls)
	}
	if v.Action != ActionBlock || len(v.Rules) != 1 || v.Rules[0] != "cel:block" {
		t.Errorf("mid-ladder decisive: got %+v", v)
	}
}

// TestLogAccumulationAcrossWalk pins the walk-level log discipline: log
// fragments flow through the whole ladder and the final verdict carries
// every rule + score in walk order, action=log.
func TestLogAccumulationAcrossWalk(t *testing.T) {
	s3 := &stubStage{st: StageCEL, frag: &Verdict{
		Action: ActionLog,
		Rules:  []RuleID{"cel:seed"},
		Score:  2,
	}}
	s6 := &stubStage{st: StageRateBan, frag: &Verdict{
		Action: ActionLog,
		Rules:  []RuleID{"rate:breach"},
		Score:  3,
	}}
	e := NewEngine()
	if err := e.Use(StageCEL, s3); err != nil {
		t.Fatalf("Use(S3): %v", err)
	}
	if err := e.Use(StageRateBan, s6); err != nil {
		t.Fatalf("Use(S6): %v", err)
	}
	v := e.EvaluateTx(fixtureTx())
	if v.Action != ActionLog {
		t.Errorf("log-only walk action: got %q, want log", v.Action)
	}
	if len(v.Rules) != 2 || v.Rules[0] != "cel:seed" || v.Rules[1] != "rate:breach" {
		t.Errorf("walk rules: got %v, want [cel:seed rate:breach] in walk order", v.Rules)
	}
	if v.Score != 5 {
		t.Errorf("walk score: got %d, want 5", v.Score)
	}
}

func TestUseValidatesWiring(t *testing.T) {
	e := NewEngine()
	if err := e.Use(Stage(9), &stubStage{st: Stage(9)}); err == nil {
		t.Error("out-of-range stage accepted")
	}
	if err := e.Use(StageKernel, nil); err == nil {
		t.Error("nil evaluator accepted")
	}
	if err := e.Use(StageCEL, &stubStage{st: StageKernel}); err == nil {
		t.Error("stage/evaluator mismatch accepted")
	}
}

// TestParseGateVerdict rows the TR-199 parse-gate mapping: the
// conformance record's section 4 reject table over the parse errors. New
// test home — the parse gate maps PARSE ERRORS, not request views, so no
// existing ladder table owns it (the TestEvaluateTx* tables walk
// evaluator fragments; an error classification is not one).
func TestParseGateVerdict(t *testing.T) {
	cases := []struct {
		name     string
		parseErr error
		want     *Verdict
	}{
		{"nil-parse", nil, nil},
		// A h1 grammar class is NOT a framing cell: the TR-05b taxonomy
		// stays the caller's surface (the mapping invents no cells).
		{"h1-grammar-remaining-class", fmt.Errorf("walk: %w: bad name", http1.ErrBadHeader), nil},
		{"h1-grammar-empty-input", http1.ErrEmpty, nil},
		{"framing-cl-te", fmt.Errorf("walk: %w: field pair", http1.ErrFramingCLTE),
			&Verdict{Action: ActionBlock, Rules: []RuleID{RuleIDFramingCLTE}, Phase: PhaseRequestHeaders}},
		{"framing-dup-cl", fmt.Errorf("walk: %w: second line", http1.ErrFramingDupCL),
			&Verdict{Action: ActionBlock, Rules: []RuleID{RuleIDFramingDupCL}, Phase: PhaseRequestHeaders}},
	}
	for _, tc := range cases {
		got := ParseGateVerdict(tc.parseErr)
		if (got == nil) != (tc.want == nil) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		if got == nil {
			continue
		}
		if got.Action != tc.want.Action {
			t.Errorf("%s: action got %q, want %q", tc.name, got.Action, tc.want.Action)
		}
		if got.Phase != tc.want.Phase {
			t.Errorf("%s: phase got %q, want %q", tc.name, got.Phase, tc.want.Phase)
		}
		if len(got.Rules) != len(tc.want.Rules) || len(got.Rules) == 0 || got.Rules[0] != tc.want.Rules[0] {
			t.Errorf("%s: rules got %v, want %v", tc.name, got.Rules, tc.want.Rules)
		}
		if !got.Action.Decisive() {
			t.Errorf("%s: the reject cell must stay decisive (the walk short-circuits pre-CRS)", tc.name)
		}
	}
}

// TR-194 (issue #236): the walk records one row per run stage (the
// stage-stamps record §4, tier T1): walk order, canonical tokens, the
// matched rules, and the stage's µs wall. Unwired slots read no row — a
// skipped stage stays absent (the record's §6 rule: absent, never passed).
func TestEvaluateTxRecordsStageRows(t *testing.T) {
	t.Run("rows in walk order with tokens + matched", func(t *testing.T) {
		s0 := &stubStage{st: StageKernel}
		s1 := &stubStage{st: StageMatcher,
			frag: &Verdict{Action: ActionLog, Rules: []RuleID{"crs:920480"}}}
		e := NewEngine()
		if err := e.Use(StageKernel, s0); err != nil {
			t.Fatalf("Use(S0): %v", err)
		}
		if err := e.Use(StageMatcher, s1); err != nil {
			t.Fatalf("Use(S1): %v", err)
		}
		v := e.EvaluateTx(fixtureTx())
		if len(v.Rows) != 2 {
			t.Fatalf("rows = %d, want 2 (one row per run stage)", len(v.Rows))
		}
		if v.Rows[0].Stage != StageKernel || v.Rows[0].Stage.Token() != "kernel" {
			t.Fatalf("row 0 = %v, want stage kernel", v.Rows[0])
		}
		if v.Rows[1].Stage != StageMatcher || v.Rows[1].Stage.Token() != "matcher" {
			t.Fatalf("row 1 = %v, want stage matcher", v.Rows[1])
		}
		if len(v.Rows[1].Matched) != 1 || v.Rows[1].Matched[0] != RuleID("crs:920480") {
			t.Fatalf("row 1 matched = %v, want [crs:920480]", v.Rows[1].Matched)
		}
		if v.Rows[0].Matched != nil {
			t.Fatalf("row 0 matched = %v, want nil (the stage matched nothing)", v.Rows[0].Matched)
		}
		if v.Rows[0].US < 0 {
			t.Fatalf("row 0 us = %d, want >= 0 (the stage's measured wall)", v.Rows[0].US)
		}
	})

	t.Run("short-circuit: the tail reads no row", func(t *testing.T) {
		s0 := &stubStage{st: StageKernel,
			frag: &Verdict{Action: ActionBlock, Rules: []RuleID{"shield:ban"}}}
		s7 := &stubStage{st: StageML}
		e := NewEngine()
		if err := e.Use(StageKernel, s0); err != nil {
			t.Fatalf("Use(S0): %v", err)
		}
		if err := e.Use(StageML, s7); err != nil {
			t.Fatalf("Use(S7): %v", err)
		}
		v := e.EvaluateTx(fixtureTx())
		if s7.calls != 0 {
			t.Fatalf("S7 calls = %d, want 0 (the decisive verdict stops the walk)", s7.calls)
		}
		if len(v.Rows) != 1 || v.Rows[0].Stage != StageKernel {
			t.Fatalf("rows = %+v, want the sole kernel row (absence, never a passed read)", v.Rows)
		}
	})

	t.Run("the token set is the record's vocabulary", func(t *testing.T) {
		want := []string{"kernel", "matcher", "crs", "cel", "schema", "bots", "rate_ban", "ml"}
		seen := map[string]bool{}
		for st := Stage(0); st < StageML; st++ {
			tok := st.Token()
			if seen[tok] {
				t.Fatalf("stage %d token %q repeats a name (one canonical name per stage)", int(st), tok)
			}
			seen[tok] = true
		}
		for i, w := range want {
			if got := Stage(i).Token(); got != w {
				t.Fatalf("stage %d token = %q, want %q (the wire order is walk order)", i, got, w)
			}
		}
	})
}
