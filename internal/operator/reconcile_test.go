package operator

// TR-08c (issue #76, M9) — the reconcile half of the apply→effect round
// trip: WAFPolicy CRs compile against a v0 rule-pack source (cmd/operator
// stubs it with a ConfigMap resolver; the test stubs it with a map), a
// policy whose custom rule does not compile ships NO bundle (fail closed),
// and Decide adds rule provenance (which rule matched, which action).
// RED state: Reconcile, Outcome, RulePackSource, CompilePacks, Decide and
// cel.Request.Query are undefined; GREEN defines them.

import (
	"context"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// srcMap is the v0 RulePackSource shape: rule-set refs resolve to CEL rule
// packs fetched from the policy's own namespace. Unresolved names are
// missing, not errors (the resolver reports the lookup; Reconcile turns a
// missing ref into a compile failure — fail closed, never under-enforce by
// silently dropping a rule set).
type srcMap map[string]cel.RulePack

func (m srcMap) RulePack(_ context.Context, ns, name string) (cel.RulePack, bool, error) {
	p, ok := m[ns+"/"+name]
	return p, ok, nil
}

// sqliPack mirrors lab/dx1/manifests/dx1-wafpolicy.yaml: one enforced rule
// matching SQLi probes in the query string of the §10.3 chat-completions
// route (the M9 lab rule).
func sqliPack(t *testing.T) cel.RulePack {
	t.Helper()
	const yaml = `
rules:
  - id: TR08C-001
    name: sqli-in-chat-query
    description: blocks SQLi UNION probes in query strings on the chat route
    action: enforce
    expression: |
      request.method == "POST" &&
      path.matches("/v1/chat/*") &&
      request.query.contains("UNION")
`
	p, err := cel.ParseRulePack([]byte(yaml))
	if err != nil {
		t.Fatalf("parse sqli pack: %v", err)
	}
	return *p
}

// fixturePolicyWithRef is the DX1 gate policy: block on the fail path,
// inline+shadow planes, one named rule-set ref (v0 resolution = the named
// rule pack from the policy's namespace).
func fixturePolicyWithRef() v1alpha1.WAFPolicy {
	return v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "chat-completions-gate", Namespace: "dx1"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionBlock,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shadow: true},
			RuleSets: []v1alpha1.RuleSetRef{{
				Name:   "dx1-sqli",
				Source: v1alpha1.RuleSetSource{CRSVersion: "4.x", Profile: v1alpha1.CRSProfilePL1},
			}},
		},
	}
}

// TestReconcileCompilesPolicyWithCustomPack: compile-on-apply — the policy
// resolves its named rule pack, the bundle carries the seed pack first and
// the custom pack second, digests cover both, Load gates it, and Decide
// returns the custom rule's verdict with provenance. The benign probe stays
// a clean no-match.
func TestReconcileCompilesPolicyWithCustomPack(t *testing.T) {
	out := Reconcile(context.Background(),
		[]v1alpha1.WAFPolicy{fixturePolicyWithRef()},
		srcMap{"dx1/dx1-sqli": sqliPack(t)})
	if len(out) != 1 {
		t.Fatalf("outcomes = %d, want 1", len(out))
	}
	o := out[0]
	if o.Key != "dx1/chat-completions-gate" {
		t.Errorf("outcome key = %q, want dx1/chat-completions-gate", o.Key)
	}
	if o.Err != nil {
		t.Fatalf("compile error: %v", o.Err)
	}
	if o.Bundle == nil {
		t.Fatal("compile success must carry a bundle")
	}
	if got := len(o.Bundle.RulePacks); got != 2 {
		t.Fatalf("rule packs = %d, want 2 (seed + custom)", got)
	}
	if id := o.Bundle.RulePacks[0].Rules[0].ID; id != "TR02-001" {
		t.Errorf("first pack rule = %q, want the seed rule TR02-001", id)
	}
	if id := o.Bundle.RulePacks[1].Rules[0].ID; id != "TR08C-001" {
		t.Errorf("second pack rule = %q, want TR08C-001", id)
	}
	if got := len(o.Bundle.RulePackDigests); got != 2 {
		t.Errorf("digests = %d, want 2", got)
	}
	if _, err := Load(*o.Bundle); err != nil {
		t.Fatalf("bundle must load: %v", err)
	}

	ev, err := Load(*o.Bundle)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d, err := ev.Decide(cel.Request{Method: "POST", Path: "/v1/chat/completions", Query: "q=UNION%20SELECT"})
	if err != nil {
		t.Fatalf("decide sqli probe: %v", err)
	}
	if d.RuleID != "TR08C-001" {
		t.Errorf("decided rule = %q, want TR08C-001", d.RuleID)
	}
	if got := d.RuleAction; got != "enforce" {
		t.Errorf("decided rule action = %q, want enforce", got)
	}
	if d2, err := ev.Decide(cel.Request{Method: "POST", Path: "/v1/chat/completions", Query: "q=greeting"}); err != nil || d2.RuleID != "" {
		t.Errorf("benign probe must stay a clean no-match, got %+v err %v", d2, err)
	}
}

// TestReconcileFailClosedOnUncompilableRule (M9 failure path): a rule pack
// that parses but does not compile, or a rule-set ref that resolves to
// nothing, yields an error outcome with NO bundle — the policy never ships a
// distribution unit and the traffic keeps its previous shape.
func TestReconcileFailClosedOnUncompilableRule(t *testing.T) {
	t.Run("uncompilable-expression", func(t *testing.T) {
		p := sqliPack(t)
		p.Rules[0].Expression = "(1 +"
		out := Reconcile(context.Background(),
			[]v1alpha1.WAFPolicy{fixturePolicyWithRef()}, srcMap{"dx1/dx1-sqli": p})
		o := out[0]
		if o.Bundle != nil {
			t.Fatalf("uncompilable rule must not ship a bundle, got %d packs", len(o.Bundle.RulePacks))
		}
		if o.Err == nil {
			t.Fatal("outcome must carry the compile error")
		}
		if !strings.Contains(o.Err.Error(), "TR08C-001") && !strings.Contains(o.Err.Error(), "compile") {
			t.Errorf("error should name the failing rule/compile, got: %v", o.Err)
		}
	})
	t.Run("missing-rule-pack", func(t *testing.T) {
		out := Reconcile(context.Background(),
			[]v1alpha1.WAFPolicy{fixturePolicyWithRef()}, srcMap{})
		o := out[0]
		if o.Bundle != nil {
			t.Fatal("missing rule pack must not ship a bundle")
		}
		if o.Err == nil || !strings.Contains(o.Err.Error(), "dx1-sqli") {
			t.Errorf("error should name the unresolved ref, got: %v", o.Err)
		}
	})
}
