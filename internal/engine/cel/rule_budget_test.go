package cel

import (
	"testing"
)

// TR-17 (issue #17, the spec's CEL DSL + goal G4): a cost budget declared on an applied
// pack's rule rides the apply → compile → load chain and enforces at
// evaluation. The pack (configmap pack.yaml, the spec's RuleSet content
// half) is the authoring surface the apply chain resolves; the budget is
// part of its wire, so the rule cannot be re-authored under the bundle
// without the budget riding every digest.

// budgetedSeedRuleYaml is the seed rule shape with a declared budget (one
// in-pack field added; the expression is the spec's CEL example verbatim).
const budgetedSeedRuleYaml = `rules:
  - id: TR02-001-budget
    name: chat-completions-rate-shape
    description: the §11.3 seed example under an unusable budget
    action: log
    costBudget: 1
    expression: |
      request.method == "POST" &&
      path.matches("/v1/chat/*") &&
      request.rate_windows["5m"].requests > 40
`

// TR-91 census: spec citation inside the raw string above; kept (conversion would change behavior)

// TestPackDeclaredCostBudgetAborts: an evaluation that cannot fit the
// pack-declared budget reports the error verdict — never a silent
// match=false with error=false (H-1 discipline, from the applied pack).
func TestPackDeclaredCostBudgetAborts(t *testing.T) {
	pack, err := ParseRulePack([]byte(budgetedSeedRuleYaml))
	if err != nil {
		t.Fatalf("parse budgeted pack: %v", err)
	}
	v, err := pack.Rules[0].Eval(Request{
		Method:      "POST",
		Path:        "/v1/chat/completions",
		RateWindows: map[string]RateWindow{"5m": {Requests: 41}},
	})
	if err == nil {
		t.Fatalf("pack-declared budget enforced nowhere: eval succeeded with %+v (want the budget abort)", v)
	}
	if !v.Error {
		t.Fatalf("verdict.error=false on the budget abort; want the error verdict, got %+v", v)
	}
	if v.Match {
		t.Fatalf("verdict.match=true on the budget abort; a budget abort never matches")
	}
}

// TestPackDeclaredBudgetGenerousStillMatches: a generous declared budget
// never changes the verdict — the budget is a ceiling, not a filter.
func TestPackDeclaredBudgetGenerousStillMatches(t *testing.T) {
	pack, err := ParseRulePack([]byte(`rules:
  - id: budget-generous
    action: log
    costBudget: 100000
    expression: request.method == "POST"
`))
	if err != nil {
		t.Fatalf("parse generous pack: %v", err)
	}
	v, err := pack.Rules[0].Eval(Request{Method: "POST", Path: "/x"})
	if err != nil {
		t.Fatalf("generous budget aborted the eval: %v", err)
	}
	if !v.Match {
		t.Fatalf("generous declared budget flipped the match: %+v", v)
	}
	if v.Error {
		t.Fatalf("generous declared budget produced an error verdict: %+v", v)
	}
}

// TestPackDeclaredBudgetNegativeRejected: a negative budget cannot decode
// into the wire field — the pack parse rejects it instead of silently
// dropping the declaration into the default budget (malformed-input edge).
func TestPackDeclaredBudgetNegativeRejected(t *testing.T) {
	if _, err := ParseRulePack([]byte(`rules:
  - id: budget-negative
    action: log
    costBudget: -3
    expression: request.method == "POST"
`)); err == nil {
		t.Fatal("negative costBudget parsed clean; want a decode rejection")
	}
}
