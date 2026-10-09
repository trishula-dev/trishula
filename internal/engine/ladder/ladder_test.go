package ladder

import (
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// stubStage is a recording test double: counts calls, returns a fixed
// fragment. Stands in for the not-yet-wired detectors (§19.1 slots).
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

// TestActionVocabulary locks the §19.1 Action values and the decisive
// classification (§2.3: only block/challenge/ban stop the walk).
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

// TestStageSlots locks the §19.1 S0–S7 numbering (a renumbered ladder is
// a wire-level contract break: board issues, PRD sketch and kernel maps
// all name these positions).
func TestStageSlots(t *testing.T) {
	if StageKernel != 0 || StageMatcher != 1 || StageCRS != 2 || StageCEL != 3 ||
		StageSchema != 4 || StageBots != 5 || StageRateBan != 6 || StageML != 7 {
		t.Fatal("ladder slot numbering moved — S0–S7 positions are fixed by §19.1")
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
// score accumulate in walk order, action upgrades allow→log (§2.3: log
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
