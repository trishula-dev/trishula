package operator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TR-17 (issue #17, the spec's CEL DSL plus goal G4): the WAFPolicy apply declares the CEL
// evaluation cost budget (spec.celBudget); Compile carries the declared
// budget on the bundle wire and Load enforces it at the compile-probe —
// a policy whose budget cannot fit a single rule evaluation never loads.

// TestCompileCarriesPolicyCELBudget: the budget declared on the apply
// surface rides the compiled bundle (the rule-pack wire carries it
// per rule; the rule-pack digests cover it with the rest of the pack).
func TestCompileCarriesPolicyCELBudget(t *testing.T) {
	// The apply surface keeps its wire decode: the policy arrives as the
	// CR's JSON, so the test decodes through bytes the same way.
	var policy v1alpha1.WAFPolicy
	if err := json.Unmarshal([]byte(`{
		"metadata": {"name": "policy-a", "namespace": "lab"},
		"spec": {
			"defaultAction": "log",
			"modeFlags": {"shadow": true},
			"celBudget": 5
		}
	}`), &policy); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	b, err := Compile(policy)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	wire, err := json.Marshal(&b)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	if !strings.Contains(string(wire), `"costBudget":5`) {
		t.Fatalf("bundle wire carries no declared budget: %s", wire)
	}
}

// TestLoadRejectsUnusableDeclaredBudget: the engine's load gate enforces
// the declared budget — a rule that cannot finish the compile-probe under
// its own declared budget fails the LOAD (never loads and errors every
// request later); the previous bundle stands (the spec's fail-closed swap rule).
func TestLoadRejectsUnusableDeclaredBudget(t *testing.T) {
	pack, err := cel.ParseRulePack([]byte(`rules:
  - id: budget-one
    action: log
    costBudget: 1
    expression: request.method == "POST"
`))
	if err != nil {
		t.Fatalf("parse budgeted pack: %v", err)
	}
	b, err := Compile(v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "budget-policy", Namespace: "lab"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionLog,
		},
	})
	if err != nil {
		t.Fatalf("compile seed bundle: %v", err)
	}
	b.RulePacks = []cel.RulePack{*pack}
	digests, err := PackDigests(b.RulePacks)
	if err != nil {
		t.Fatalf("digest spliced pack: %v", err)
	}
	b.RulePackDigests = digests
	if _, err := Load(b); err == nil {
		t.Fatal("load accepted a bundle whose rule cannot finish one evaluation under its declared budget")
	}
}
