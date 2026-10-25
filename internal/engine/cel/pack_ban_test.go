package cel

// TR-195 (issue #237) / TR-197 (issue #239) — the operator's shared manual
// surface: a rule pack can carry `action: ban`. The match = a DIRECT ban
// (not scored): the engine answers 403 with decision `ban`, names the rule,
// and emits a direct would-ban record for the enforcer's kernel write.
// The decision rides the issue threads; the parse gate lives here.
import "testing"

func TestBanActionParses(t *testing.T) {
	yml := []byte("rules:\n  - id: OPS-BAN-001\n    name: manual-ban\n    description: test\n    action: ban\n    expression: request.method == \"GET\"\n")
	pack, err := ParseRulePack(yml)
	if err != nil {
		t.Fatalf("ban action pack: %v", err)
	}
	if pack.Rules[0].Action != ActionBan {
		t.Fatalf("action = %q, want %q", pack.Rules[0].Action, ActionBan)
	}
	if !(func() bool { a := Action("ban"); return a.Valid() })() {
		t.Fatal("ActionBan must read valid")
	}
}
