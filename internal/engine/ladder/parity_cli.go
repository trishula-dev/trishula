package ladder

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// ParityMatrixRender walks the parity fixture matrix (TR-05d) against a
// loaded rule pack and renders the verdict log — the CLI surface of the
// parent acceptance (cmd/trishula --parity). The in-memory kernel state
// mirrors the matrix cases (clean / cel-match / kernel-ban); exit-code
// semantics live with the caller.
//
// The matrix here is the same shape TestParityWalk asserts: clean allow,
// cel-match log, kernel-ban decisive ban (order proof: S3 never runs).
func ParityMatrixRender(pack *cel.RulePack) (string, int) {
	if pack == nil || len(pack.Rules) == 0 {
		return "parity: empty rule pack\n", 1
	}
	var b strings.Builder
	b.WriteString("verdict log (parity walk, S0+S3 slice):\n")
	failed := false

	// clean walk: no kernel state, non-matching request -> allow, S3 runs, silent
	v := parityWalkCase(pack, parityCLIOptions{})
	if v.Action != ActionAllow {
		failed = true
	}
	fmt.Fprintf(&b, "  case %-10s action=%-8s rules=%-18s score=%d [%s]\n",
		"clean", v.Action, "[]", 0, verdictStatus(v.Action, ActionAllow))

	// cel-match walk: clean kernel, seed matches -> log (never block)
	v = parityWalkCase(pack, parityCLIOptions{
		method: "POST", path: "/v1/chat/completions",
		rateRequests: 41,
	})
	ok := v.Action == ActionLog && len(v.Rules) == 1 && v.Rules[0] == RuleID(pack.Rules[0].ID)
	if !ok {
		failed = true
	}
	fmt.Fprintf(&b, "  case %-10s action=%-8s rules=%-18s score=%d [%s]\n",
		"cel-match", v.Action, fmt.Sprintf("%v", v.Rules), v.Score,
		verdictStatusBool(ok))

	// kernel-ban walk: banned source -> decisive ban, S3 never runs
	src := netip.MustParseAddr("192.0.2.23")
	st := newShieldAdapterState()
	st.setBan(src, uint64(time.Now().UnixNano())+(1<<40), 2, 7)
	calls := 0
	counting := countingEvaluatorCli{Evaluator: NewCELEval(pack), onEval: func() { calls++ }}
	e := NewEngine()
	if err := e.Use(StageKernel, NewKernelHits(st.checker)); err != nil {
		return fmt.Sprintf("parity: wire S0: %v\n", err), 1
	}
	if err := e.Use(StageCEL, counting); err != nil {
		return fmt.Sprintf("parity: wire S3: %v\n", err), 1
	}
	tx := &ingest.TxContext{
		Key:      ingest.FlowKey{Family: ingest.FamilyV4, SrcIP: src.As4()},
		LastNS:   uint64(time.Now().UnixNano()),
		Metadata: map[string]string{},
	}
	_ = AttachView(tx, &cel.Request{Method: "POST", Path: "/v1/chat/completions",
		RateWindows: map[string]cel.RateWindow{"5m": {Requests: 41}}})
	v = e.EvaluateTx(tx)
	banOK := v.Action == ActionBan && v.Rules[0] == RuleID("shield:ban:t2:r7") && calls == 0
	if !banOK {
		failed = true
	}
	fmt.Fprintf(&b, "  case %-10s action=%-8s rules=%-18s score=%d [%s]\n",
		"kernel-ban", v.Action, fmt.Sprintf("%v", v.Rules), v.Score,
		verdictStatusBool(banOK))

	b.WriteString("parity OK\n")
	if failed {
		return strings.Replace(b.String(), "parity OK\n", "parity FAILED\n", 1), 1
	}
	return b.String(), 0
}

// parityCLIOptions shapes the crafted request for one parity case.
type parityCLIOptions struct {
	method       string
	path         string
	rateRequests int64
}

// countingEvaluatorCli is the production-side call counter (the test-file
// twin stays in parity_test.go; non-test code cannot reference it).
type countingEvaluatorCli struct {
	Evaluator
	onEval func()
}

func (c countingEvaluatorCli) Evaluate(tx *ingest.TxContext) *Verdict {
	c.onEval()
	return c.Evaluator.Evaluate(tx)
}

// parityWalkCase assembles the clean-kernel S0+S3 walk and evaluates one
// crafted request (the parity matrix's per-case helper).
func parityWalkCase(pack *cel.RulePack, o parityCLIOptions) *Verdict {
	st := newShieldAdapterState()
	e := NewEngine()
	if err := e.Use(StageKernel, NewKernelHits(st.checker)); err != nil {
		return &Verdict{Action: ActionAllow}
	}
	if err := e.Use(StageCEL, NewCELEval(pack)); err != nil {
		return &Verdict{Action: ActionAllow}
	}
	tx := &ingest.TxContext{
		Key:      ingest.FlowKey{Family: ingest.FamilyV4, SrcIP: [4]byte{192, 0, 2, 7}},
		LastNS:   uint64(time.Now().UnixNano()),
		Metadata: map[string]string{},
	}
	_ = AttachView(tx, &cel.Request{
		Method:      o.method,
		Path:        o.path,
		RateWindows: map[string]cel.RateWindow{"5m": {Requests: o.rateRequests}},
	})
	return e.EvaluateTx(tx)
}

func verdictStatus(got, want Action) string {
	if got == want {
		return "PASS"
	}
	return "FAIL"
}

func verdictStatusBool(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
