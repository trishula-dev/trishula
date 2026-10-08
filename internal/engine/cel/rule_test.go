package cel

import (
	"os"
	"testing"
)

// TR-02 seed acceptance (issue #2): one CEL rule from PRD §11.3, compiled and
// evaluated over the §11.3 structured request view, cost-budgeted from day one.
//
// Test contract: tests import ONLY our package API (never cel-go directly).
// RED state = every symbol below is undefined; GREEN = the API exists and the
// seed rule passes the fixture cases.

const seedPackPath = "../../../rules/cel/seed.yaml"

func TestLoadRulePack(t *testing.T) {
	// Malformed YAML is generated at runtime: a repo file that fails
	// check-yaml would block pre-commit for every developer.
	broken := t.TempDir() + "/broken.yaml"
	if err := os.WriteFile(broken, []byte("rules: [not: {a: list}\n"), 0o600); err != nil {
		t.Fatalf("write broken pack: %v", err)
	}
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"seed pack loads", seedPackPath, false},
		{"missing file errors", "testdata/no-such-pack.yaml", true},
		{"invalid yaml errors", broken, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pack, err := LoadRulePack(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadRulePack(%q) err=%v wantErr=%v", tc.path, err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if len(pack.Rules) != 1 {
				t.Fatalf("seed = %d rules, want 1 (TR-02: exactly one seed rule)", len(pack.Rules))
			}
			r := pack.Rules[0]
			// §11.3 expression lands in the pack verbatim; log-only seed.
			if r.Action != ActionLog {
				t.Fatalf("seed action = %q, want %q", r.Action, ActionLog)
			}
			if r.ID == "" || r.Name == "" || r.Expression == "" {
				t.Fatalf("seed rule fields unset: id=%q name=%q expr=%d bytes",
					r.ID, r.Name, len(r.Expression))
			}
		})
	}
}

func TestSeedRuleEval(t *testing.T) {
	cases := loadRequestCases(t, "testdata/sample_request.yaml")
	pack, err := LoadRulePack(seedPackPath)
	if err != nil {
		t.Fatalf("load seed: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			v, err := pack.Rules[0].Eval(tc.Request)
			if tc.Expected.Error {
				if err == nil {
					t.Fatalf("expected error verdict, got nil err with %v", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("Eval unexpected error: %v", err)
			}
			if v.Match != tc.Expected.Match {
				t.Fatalf("match=%v want %v", v.Match, tc.Expected.Match)
			}
			if v.Error {
				t.Fatalf("verdict.error=true, want false")
			}
		})
	}
}

func TestCostBudgetAborts(t *testing.T) {
	// H-1: the budget is enforced by the environment, not checked after
	// success. A budget so low the real expression can never fit must yield
	// an error verdict — never a silent match=false with error=false, and
	// never a successful eval.
	pack, err := LoadRulePack(seedPackPath)
	if err != nil {
		t.Fatalf("load seed: %v", err)
	}
	if err := pack.Rules[0].SetCostBudget(1); err != nil {
		t.Fatalf("SetCostBudget(1): %v", err)
	}
	v, err := pack.Rules[0].Eval(Request{
		Method: "POST",
		Path:   "/v1/chat/completions",
		RateWindows: map[string]RateWindow{
			"5m": {Requests: 41},
		},
	})
	if err == nil {
		t.Fatalf("over-budget eval returned err=nil (silent); want budget error")
	}
	if !v.Error {
		t.Fatalf("verdict.error=false on budget abort; want error verdict")
	}
	if v.Match {
		t.Fatalf("verdict.match=true on budget abort; budget abort must not match")
	}
}

func TestCompileError(t *testing.T) {
	// Load ≠ compile: a syntactically valid pack with an uncompilable
	// expression loads; the compile failure surfaces at Eval as an error.
	pack, err := LoadRulePack("testdata/bad_expr_rules.yaml")
	if err != nil {
		t.Fatalf("bad_expr_rules must still LOAD (load≠compile): %v", err)
	}
	_ = pack
	if _, err := pack.Rules[0].Eval(Request{Method: "GET", Path: "/"}); err == nil {
		t.Fatalf("compile error must surface at Eval as an error, got nil")
	}
}

func loadRequestCases(t *testing.T, path string) []RequestCase {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	cases, err := ParseRequestCases(data)
	if err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	if len(cases) != 4 {
		t.Fatalf("fixture has %d cases, want 4", len(cases))
	}
	return cases
}
