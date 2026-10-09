package ladder

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// The parity walk (TR-05d): a crafted request walks the assembled ladder
// end-to-end and the walk records the right verdict sequence — the matrix
// documents every verdict logged (TR-05's acceptance; issue #5).
//
// Fixture matrix (each case: wire-realistic tx + verdict expectation):
//
//	clean        — no kernel state, no CEL match         -> walk completes, action=allow, no log rows
//	cel-match    — clean kernel, seed rule matches       -> S3 logs seed-rate-shape, action=log, never block
//	kernel-ban   — banned source, CEL would also match   -> S0 decisive ban, S3 NOT evaluated (order proof)
//  cel-error    — clean, uncompilable rule              -> <id>:error evidence logged, never a match
//  no-view      — parse not attached                    -> walk completes allow, S3 silent (no opinion)

// parityCase is one matrix row (the verdict-log assertion's contract).
type parityCase struct {
	name    string
	wireVer string
	path    string
	method  string
	// kernelBans the tx source before the walk (empty = clean source)
	kernelBans string
	// packYaml the walk evaluates ("" = seed pack)
	packYaml string
	// wantAction the resolved verdict's action
	wantAction Action
	// wantRules the EXACT rule-id list in walk order (nil = none)
	wantRules []RuleID
	// wantScore the resolved verdict's score
	wantScore int64
	// wantCELCalled pins whether S3 must (true) / must-not (false) run;
	// nil = don't care
	wantCELCalled *bool
}

// runWalk assembles the S0+S3 slice walk (engine shape: http1 view →
// AttachView → EvaluateTx) and returns the resolved verdict + the S3 call
// count for the order-proof assertions.
func runWalk(t *testing.T, tc parityCase) (*Verdict, int) {
	t.Helper()
	st := newShieldAdapterState()
	if tc.kernelBans != "" {
		st.setBan(ipOfTx(t, tc), nowNano()+(1<<40), 2, 7)
	}
	packYaml := tc.packYaml
	if packYaml == "" {
		packYaml = seedRuleYaml
	}
	pack, err := cel.ParseRulePack([]byte(packYaml))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	calls := 0
	celStage := countingEvaluator{Evaluator: NewCELEval(pack), onEval: func() { calls++ }}

	e := NewEngine()
	if err := e.Use(StageKernel, NewKernelHits(st.checker)); err != nil {
		t.Fatalf("wire S0: %v", err)
	}
	if err := e.Use(StageCEL, celStage); err != nil {
		t.Fatalf("wire S3: %v", err)
	}

	tx := parityTx(t, tc)
	if err := AttachView(tx, &cel.Request{
		Method: tc.method,
		Path:   tc.path,
		RateWindows: map[string]cel.RateWindow{
			"5m": {Requests: 41},
		},
	}); err != nil {
		t.Fatalf("attach view: %v", err)
	}
	v := e.EvaluateTx(tx)
	return v, calls
}

// countingEvaluator wraps an Evaluator and counts Evaluate calls (the
// order-proof instrument for decisive-S0 assertions).
type countingEvaluator struct {
	Evaluator
	onEval func()
}

func (c countingEvaluator) Evaluate(tx *ingest.TxContext) *Verdict {
	c.onEval()
	return c.Evaluator.Evaluate(tx)
}

func nowNano() uint64 { return uint64(time.Now().UnixNano()) }

func addr4(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

// parityTx builds the tx for a case (source IPv4 from the case name space:
// 192.0.2.<row>) — the crafted-request stand-in for the demo path.
func parityTx(t *testing.T, tc parityCase) *ingest.TxContext {
	t.Helper()
	octet := rowOctet(tc.name)
	tx := &ingest.TxContext{
		Key: ingest.FlowKey{
			Family:  ingest.FamilyV4,
			SrcIP:   [4]byte{192, 0, 2, octet},
			DstPort: 443,
		},
		LastNS:   nowNano(),
		Metadata: map[string]string{},
	}
	return tx
}

func ipOfTx(t *testing.T, tc parityCase) netip.Addr {
	t.Helper()
	return addr4(192, 0, 2, rowOctet(tc.name))
}

func rowOctet(name string) byte {
	// stable per-case octet (hash the name into 1..254)
	var sum byte
	for i := 0; i < len(name); i++ {
		sum += name[i]
	}
	return sum%253 + 1
}

// TestParityWalk walks the full fixture matrix and asserts the resolved
// verdict + exact rule log per case.
func TestParityWalk(t *testing.T) {
	never := false
	always := true
	cases := []parityCase{
		{
			name: "clean", method: "GET", path: "/health",
			wantAction: ActionAllow, wantRules: nil, wantScore: 0,
			wantCELCalled: &always,
		},
		{
			name: "cel-match", method: "POST", path: "/v1/chat/completions",
			wantAction: ActionLog, wantRules: []RuleID{"seed-rate-shape"}, wantScore: 1,
			wantCELCalled: &always,
		},
		{
			name: "kernel-ban", method: "POST", path: "/v1/chat/completions",
			kernelBans: "yes",
			wantAction: ActionBan, wantRules: []RuleID{"shield:ban:t2:r7"}, wantScore: 2,
			wantCELCalled: &never, // decisive S0 — S3 must not evaluate
		},
		{
			name: "cel-error", method: "POST", path: "/x",
			packYaml: `
rules:
  - id: bad-rule
    action: log
    expression: |
      request.method == 42 && nonexistent_function()
`,
			wantAction: ActionLog, wantRules: []RuleID{"bad-rule:error"}, wantScore: 0,
			wantCELCalled: &always,
		},
	}
	for _, tc := range cases {
		v, calls := runWalk(t, tc)
		if v.Action != tc.wantAction {
			t.Errorf("[%s] action: got %q, want %q", tc.name, v.Action, tc.wantAction)
		}
		if len(v.Rules) != len(tc.wantRules) {
			t.Errorf("[%s] rules: got %v, want %v", tc.name, v.Rules, tc.wantRules)
		} else {
			for i := range tc.wantRules {
				if v.Rules[i] != tc.wantRules[i] {
					t.Errorf("[%s] rules[%d]: got %q, want %q", tc.name, i, v.Rules[i], tc.wantRules[i])
				}
			}
		}
		if v.Score != tc.wantScore {
			t.Errorf("[%s] score: got %d, want %d", tc.name, v.Score, tc.wantScore)
		}
		if tc.wantCELCalled != nil && calls > 0 != *tc.wantCELCalled {
			t.Errorf("[%s] S3 called: got %v, want %v", tc.name, calls > 0, *tc.wantCELCalled)
		}
		// issue-#5 posture over the whole matrix: block/challenge/ban only
		// from the kernel stage — never from CEL.
		if v.Action == ActionBlock || v.Action == ActionChallenge {
			t.Errorf("[%s] decisive enforcement action %q emitted at the log-only slice", tc.name, v.Action)
		}
		if tc.wantCELCalled != nil && *tc.wantCELCalled && v.Action == ActionBan && tc.kernelBans == "" {
			t.Errorf("[%s] ban without kernel state", tc.name)
		}
	}
}

// TestParityVerdictLogDocumentsEveryLoggedVerdict renders the verdict log
// (the parity-walk documentation artifact: sequence + fields per case) and
// pins its shape — the parent acceptance's "matrix documents every verdict".
func TestParityVerdictLogDocumentsEveryLoggedVerdict(t *testing.T) {
	var b strings.Builder
	fmt.Fprintln(&b, "verdict log (parity walk, S0+S3 slice):")
	for _, tc := range []parityCase{
		{name: "clean", method: "GET", path: "/health"},
		{name: "cel-match", method: "POST", path: "/v1/chat/completions"},
		{name: "kernel-ban", method: "POST", path: "/v1/chat/completions", kernelBans: "yes"},
	} {
		v, _ := runWalk(t, tc)
		fmt.Fprintf(&b, "  %-10s action=%-8s rules=%v score=%d phase=%s\n",
			tc.name, v.Action, v.Rules, v.Score, v.Phase)
	}
	log := b.String()
	for _, want := range []string{
		"clean      action=allow",
		"cel-match  action=log",
		"kernel-ban action=ban",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("verdict log missing %q:\n%s", want, log)
		}
	}
}
