package ladder

import (
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/cel"
)

// TR-17 (issue #17, the spec's CEL DSL plus its shadow-first lifecycle rule): the apply/swap seam on the S3
// stage is load-disciplined. SetPack compile-probes the incoming pack
// before the swap (the same gate Load runs: load ≠ eval — an
// uncompilable or budget-aborted rule fails the SWAP, never becomes
// per-request ":error" evidence); the installed pack keeps serving on a
// rejected swap (fail closed, the spec's per-replica atomic swap).

// TestSetPackRejectsUncompilablePackAndKeepsPrevious: a pack whose rule
// cannot compile is rejected at the swap and the installed pack continues
// to serve — the reload can never trade a working pack for error
// evidence on every request.
func TestSetPackRejectsUncompilablePackAndKeepsPrevious(t *testing.T) {
	tx, ev := celTx(t, seedRuleYaml, "POST", "/v1/chat/completions",
		map[string]int64{"5m": 41})
	if frag := ev.Evaluate(tx); frag == nil || frag.Action != ActionLog {
		t.Fatalf("pre-swap baseline missing: %+v", frag)
	}
	// load ≠ compile: the pack parses (an undeclared top-level name
	// fails the checker — go-cel-env gotcha for map-typed views).
	bad, err := cel.ParseRulePack([]byte(`rules:
  - id: broken-swap
    action: log
    expression: undeclared_variable == true
`))
	if err != nil {
		t.Fatalf("uncompilable pack must still parse (load ≠ compile): %v", err)
	}
	if err := ev.SetPack(bad); err == nil {
		t.Fatal("SetPack accepted an uncompilable pack (the swap would trade every request for :error evidence)")
	}
	if frag := ev.Evaluate(tx); frag == nil || frag.Action != ActionLog {
		t.Fatalf("previous pack not serving after the rejected swap: %+v", frag)
	}
	if frag := ev.Evaluate(tx); frag != nil {
		for _, id := range frag.Rules {
			if strings.HasSuffix(string(id), ":error") {
				t.Fatalf("error evidence after the rejected swap: %+v", frag.Rules)
			}
		}
	}
}
