package operator

// TR-195 leaf 1 (issue #237; issue #239): the manual ban surface. A rule
// pack carries `action: ban`; the match folds to the block class and sets
// BanDirect — the engine reads both (the 403 + the decision=ban response,
// and the direct would-ban emission). The Decide + cel.Request shapes ride
// the reconcile_test fixtures.
import (
	"context"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	cel "github.com/trishula-dev/trishula/internal/engine/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func banPack(t *testing.T) cel.RulePack {
	t.Helper()
	const y = `
rules:
  - id: OPS-BAN-01
    name: manual-ban
    description: a manual ban on the secret route for the offending source
    action: ban
    expression: |
      request.method == "GET" && path.matches("/secret/*")
`
	p, err := cel.ParseRulePack([]byte(y))
	if err != nil {
		t.Fatalf("parse ban pack: %v", err)
	}
	return *p
}

func banFixturePolicy() v1alpha1.WAFPolicy {
	return v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "manual-ban-gate", Namespace: "dx1"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionPass,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shadow: true},
			RuleSets: []v1alpha1.RuleSetRef{{
				Name:   "ops-ban",
				Source: v1alpha1.RuleSetSource{CRSVersion: "4.x", Profile: v1alpha1.CRSProfilePL1},
			}},
		},
	}
}

func TestDecideBanRuleFoldsBlockAndFlagsDirect(t *testing.T) {
	out := Reconcile(context.Background(),
		[]v1alpha1.WAFPolicy{banFixturePolicy()},
		srcMap{"dx1/ops-ban": banPack(t)})
	if len(out) != 1 || out[0].Err != nil {
		t.Fatalf("reconcile outcomes bad: %+v", out)
	}
	ev, err := Load(*out[0].Bundle)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d, err := ev.Decide(cel.Request{Method: "GET", Path: "/secret/x"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !d.Match || d.RuleID != "OPS-BAN-01" {
		t.Fatalf("match wrong: %+v", d)
	}
	if d.RuleAction != "ban" {
		t.Fatalf("rule action = %q, want ban", d.RuleAction)
	}
	if !d.BanDirect || d.Action != v1alpha1.DefaultActionBlock {
		t.Fatalf("fold wrong: %+v", d)
	}
	// the benign shape stays clean: no ban rides an unmatched route
	d2, err := ev.Decide(cel.Request{Method: "GET", Path: "/open"})
	if err != nil || d2.Match {
		t.Fatalf("clean no-match must stand, got %+v err %v", d2, err)
	}
}
