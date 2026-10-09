package ladder

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// --- fixtures ---------------------------------------------------------

// seedRuleYaml is the TR-02 seed rule (verbatim §11.3 example, action=log).
const seedRuleYaml = `
rules:
  - id: seed-rate-shape
    name: chat rate shape
    description: the §11.3 seed example
    action: log
    expression: |
      request.method == "POST" && path.matches("/v1/chat/*") &&
      request.rate_windows["5m"].requests > 40
`

// celTx builds a tx carrying a parsed §11.3 view (the head TR-05b produces;
// direct attachment here — the engine plumbing is AttachView).
func celTx(t *testing.T, packYaml, method, path string, windows map[string]int64) (*ingest.TxContext, *CELEval) {
	t.Helper()
	pack, err := cel.ParseRulePack([]byte(packYaml))
	if err != nil {
		t.Fatalf("ParseRulePack: %v", err)
	}
	tx := &ingest.TxContext{
		Key:      ingest.FlowKey{Family: ingest.FamilyV4},
		Metadata: map[string]string{},
	}
	view := &cel.Request{Method: method, Path: path}
	if len(windows) > 0 {
		rw := map[string]cel.RateWindow{}
		for k, n := range windows {
			rw[k] = cel.RateWindow{Requests: n}
		}
		view.RateWindows = rw
	}
	if err := AttachView(tx, view); err != nil {
		t.Fatalf("AttachView: %v", err)
	}
	ev := NewCELEval(pack)
	return tx, ev
}

// --- S3 CEL tests ------------------------------------------------------

// TestCELEvalMatchLogsPinsLogOnly is the issue-#5-posture pin: a matching
// rule produces a LOG fragment and the fragment's action is log —
// block/challenge/ban are NOT emitted by this slot.
func TestCELEvalMatchLogsPinsLogOnly(t *testing.T) {
	tx, ev := celTx(t, seedRuleYaml, "POST", "/v1/chat/completions",
		map[string]int64{"5m": 41})
	frag := ev.Evaluate(tx)
	if frag == nil {
		t.Fatal("matching seed rule produced no fragment")
	}
	if frag.Action != ActionLog {
		t.Errorf("action: got %q, want log (log-only slice — enforcement is TR-10's lane)", frag.Action)
	}
	if len(frag.Rules) != 1 || frag.Rules[0] != "seed-rate-shape" {
		t.Errorf("rules: got %v, want [seed-rate-shape]", frag.Rules)
	}
	if frag.Score != 1 {
		t.Errorf("score: got %d, want 1", frag.Score)
	}
	if frag.Phase != PhaseRequestHeaders {
		t.Errorf("phase: got %q, want request_headers", frag.Phase)
	}
}

func TestCELEvalNoMatchNoFragment(t *testing.T) {
	tx, ev := celTx(t, seedRuleYaml, "GET", "/v1/chat/completions",
		map[string]int64{"5m": 41})
	if frag := ev.Evaluate(tx); frag != nil {
		t.Errorf("non-matching rule produced a fragment: %+v", frag)
	}
}

// TestCELEvalRuleErrorIsEvidenceNotMatch: an uncompilable rule fails safe —
// the fragment records <id>:error, contributes no match, and the slice
// never turns an eval failure into an enforcement-grade verdict.
func TestCELEvalRuleErrorIsEvidenceNotMatch(t *testing.T) {
	badPack := `
rules:
  - id: bad-rule
    action: log
    expression: |
      request.method == 42 && nonexistent_function()
`
	tx, ev := celTx(t, badPack, "POST", "/v1/chat/completions", nil)
	frag := ev.Evaluate(tx)
	if frag == nil {
		t.Fatal("error-verdict rule produced no fragment (evidence lost)")
	}
	if frag.Action != ActionLog {
		t.Errorf("error-verdict action: got %q, want log", frag.Action)
	}
	found := false
	for _, id := range frag.Rules {
		if strings.HasSuffix(string(id), ":error") {
			found = true
		}
		if id == "bad-rule" {
			t.Errorf("error verdict surfaced as a bare match id: %v", frag.Rules)
		}
	}
	if !found {
		t.Errorf("error rule id not recorded as :error evidence: %v", frag.Rules)
	}
}

func TestCELEvalEmptyPackWiringError(t *testing.T) {
	ev := NewCELEval(&cel.RulePack{})
	if err := ev.SetPack(nil); err == nil {
		t.Error("nil pack accepted")
	}
	if err := ev.SetPack(&cel.RulePack{}); err == nil {
		t.Error("empty pack accepted")
	}
}

// TestSetPackHotSwap pins the apply path: evaluate pack A, swap in pack B,
// the next fragment reflects B — the TR-17 hot-reload lane's floor.
func TestSetPackHotSwap(t *testing.T) {
	tx, ev := celTx(t, seedRuleYaml, "POST", "/v1/chat/completions",
		map[string]int64{"5m": 41})
	if frag := ev.Evaluate(tx); frag == nil || frag.Action != ActionLog {
		t.Fatalf("pre-swap baseline missing: %+v", frag)
	}
	packB, err := cel.ParseRulePack([]byte(`
rules:
  - id: never-fire
    action: log
    expression: request.method == "TEAPOT"
`))
	if err != nil {
		t.Fatalf("pack B: %v", err)
	}
	if err := ev.SetPack(packB); err != nil {
		t.Fatalf("SetPack: %v", err)
	}
	if frag := ev.Evaluate(tx); frag != nil {
		t.Errorf("post-swap fragment from pack B rule that cannot match: %+v", frag)
	}
}

// TestNoViewNoOpinion: a tx without an attached view is a no-op at S3
// (the parse stage owns it — no fabricated verdicts in either direction).
func TestNoViewNoOpinion(t *testing.T) {
	pack, err := cel.ParseRulePack([]byte(seedRuleYaml))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	ev := NewCELEval(pack)
	tx := &ingest.TxContext{Key: ingest.FlowKey{Family: ingest.FamilyV4}}
	if frag := ev.Evaluate(tx); frag != nil {
		t.Errorf("view-less tx produced a fragment: %+v", frag)
	}
}

// --- S0 kernel-hits tests ----------------------------------------------

func banTx(ip4 [4]byte) *ingest.TxContext {
	return &ingest.TxContext{
		Key:      ingest.FlowKey{Family: ingest.FamilyV4, SrcIP: ip4},
		LastNS:   uint64(time.Now().UnixNano()),
		Metadata: map[string]string{},
	}
}

// TestS0BannedTxReturnsDecisiveBan: banned source -> ActionBan fragment,
// evidence carries the shield rule id (tier+reason traceable), score seeds
// from the kernel tier.
func TestS0BannedTxReturnsDecisiveBan(t *testing.T) {
	st := newShieldAdapterState()
	srcIP := netip.MustParseAddr("192.0.2.7")
	st.setBan(srcIP, uint64(time.Now().UnixNano())+uint64(time.Minute), 3, 42)
	k := NewKernelHits(st.checker)
	frag := k.Evaluate(banTx(srcIP.As4()))
	if frag == nil {
		t.Fatal("banned source produced no fragment")
	}
	if frag.Action != ActionBan {
		t.Errorf("action: got %q, want ban", frag.Action)
	}
	if len(frag.Rules) != 1 || !strings.HasPrefix(string(frag.Rules[0]), "shield:ban:t3:r42") {
		t.Errorf("rule id: got %v, want shield:ban:t3:r42 prefix", frag.Rules)
	}
	if frag.Score != 3 {
		t.Errorf("score: got %d, want tier(3)", frag.Score)
	}
}

// TestS0ExpiredBanIsCleanMiss pins expiry-semantics parity with the loader
// (now >= until => miss).
func TestS0ExpiredBanIsCleanMiss(t *testing.T) {
	st := newShieldAdapterState()
	srcIP := netip.MustParseAddr("192.0.2.9")
	st.setBan(srcIP, 100, 2, 1) // expired long ago
	k := NewKernelHits(st.checker)
	if frag := k.Evaluate(banTx(srcIP.As4())); frag != nil {
		t.Errorf("expired ban produced a fragment: %+v", frag)
	}
}

func TestS0CleanSourceNoFragment(t *testing.T) {
	st := newShieldAdapterState()
	k := NewKernelHits(st.checker)
	if frag := k.Evaluate(banTx([4]byte{192, 0, 2, 77})); frag != nil {
		t.Errorf("clean source produced a fragment: %+v", frag)
	}
}

// TestS0NoSourceYieldsNoFragment: an unparseable tx source cannot invent
// a key — and must NOT silently pass as "clean" (no opinion at S0).
func TestS0NoSourceYieldsNoFragment(t *testing.T) {
	st := newShieldAdapterState()
	k := NewKernelHits(st.checker)
	tx := &ingest.TxContext{Key: ingest.FlowKey{Family: 0}, Metadata: map[string]string{}}
	if frag := k.Evaluate(tx); frag != nil {
		t.Errorf("family-less tx produced an S0 fragment: %+v", frag)
	}
}

// TestS0ProbeErrorYieldsNoFragment: a checker failure must not fabricate
// either direction (no fake ban, no fake clean verdict).
func TestS0ProbeErrorYieldsNoFragment(t *testing.T) {
	k := NewKernelHits(func(src netip.Addr, nowNS uint64) (khit, error) {
		return khit{}, errors.New("probe down")
	})
	if frag := k.Evaluate(banTx([4]byte{192, 0, 2, 5})); frag != nil {
		t.Errorf("probe failure fabricated a fragment: %+v", frag)
	}
}

// --- slice walk (RED targets the wiring assertions below) ---------------

// TestSliceWalkBannedTxIsDecisiveAtS0: on the assembled walk, a banned tx
// resolves ban WITHOUT reaching S3 (the TR-05c RED assertion).
func TestSliceWalkBannedTxIsDecisiveAtS0(t *testing.T) {
	st := newShieldAdapterState()
	srcIP := netip.MustParseAddr("192.0.2.23")
	st.setBan(srcIP, uint64(time.Now().UnixNano())+uint64(time.Minute), 2, 7)
	e := NewEngine()
	if err := e.Use(StageKernel, NewKernelHits(st.checker)); err != nil {
		t.Fatalf("wire S0: %v", err)
	}
	pack, err := cel.ParseRulePack([]byte(seedRuleYaml))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if err := e.Use(StageCEL, NewCELEval(pack)); err != nil {
		t.Fatalf("wire S3: %v", err)
	}
	v := e.EvaluateTx(banTx(srcIP.As4()))
	if v.Action != ActionBan {
		t.Errorf("banned walk action: got %q, want ban", v.Action)
	}
}

// TestSliceWalkCleanTxLogsCELMatch: on the assembled walk, a clean tx with
// a matching seed rule resolves log (never block) with the rule recorded —
// the TR-05c RED assertion pair.
func TestSliceWalkCleanTxLogsCELMatch(t *testing.T) {
	st := newShieldAdapterState()
	e := NewEngine()
	if err := e.Use(StageKernel, NewKernelHits(st.checker)); err != nil {
		t.Fatalf("wire S0: %v", err)
	}
	pack, err := cel.ParseRulePack([]byte(seedRuleYaml))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if err := e.Use(StageCEL, NewCELEval(pack)); err != nil {
		t.Fatalf("wire S3: %v", err)
	}
	tx, _ := celTx(t, seedRuleYaml, "POST", "/v1/chat/completions",
		map[string]int64{"5m": 41})
	v := e.EvaluateTx(tx)
	if v.Action != ActionLog {
		t.Errorf("clean walk action: got %q, want log (block must never emit at this slice)", v.Action)
	}
	if len(v.Rules) != 1 || v.Rules[0] != "seed-rate-shape" {
		t.Errorf("clean walk rules: got %v, want [seed-rate-shape]", v.Rules)
	}
}
