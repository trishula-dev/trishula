package operator

// TR-08c (issue #76, M9) — the reconcile half of the apply→effect round
// trip: WAFPolicy CRs compile against a v0 rule-pack source (cmd/operator
// stubs it with a ConfigMap resolver; the test stubs it with a map), a
// policy whose custom rule does not compile ships NO bundle (fail closed),
// and Decide adds rule provenance (which rule matched, which action).
// RED state: Reconcile, Outcome, RulePackSource, CompilePacks, Decide and
// cel.Request.Query are undefined; GREEN defines them.

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
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
// matching SQLi probes in the query string of the spec's chat-completions
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

// betaPack is the second tenant's rule pack: one enforced rule with its
// own id, so the separation test checks each bundle's rule ids by tenant.
func betaPack(t *testing.T) cel.RulePack {
	t.Helper()
	const yaml = `
rules:
  - id: TR25-001
    name: beta-delete-gate
    description: blocks DELETE requests in the beta tenant only
    action: enforce
    expression: |
      request.method == "DELETE"
`
	p, err := cel.ParseRulePack([]byte(yaml))
	if err != nil {
		t.Fatalf("parse beta pack: %v", err)
	}
	return *p
}

// TestReconcilePerTenantBundlesStaySeparate (TR-25, the spec's multi-tenancy requirement R8): two
// tenants' policies reconcile into separate bundles — each bundle binds
// its own namespace and carries ONLY its own namespace's custom packs. The
// seed pack (TR02-001) is the shared default plane, not a tenant's rule.
func TestReconcilePerTenantBundlesStaySeparate(t *testing.T) {
	mkPolicy := func(ns string) v1alpha1.WAFPolicy {
		return v1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "chat-gate", Namespace: ns},
			Spec: v1alpha1.WAFPolicySpec{
				DefaultAction: v1alpha1.DefaultActionBlock,
				ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true},
				RuleSets: []v1alpha1.RuleSetRef{{
					Name:   "sqli",
					Source: v1alpha1.RuleSetSource{CRSVersion: "4.x", Profile: v1alpha1.CRSProfilePL2},
				}},
			},
		}
	}
	src := srcMap{"alpha/sqli": sqliPack(t), "beta/sqli": betaPack(t)}
	out := Reconcile(context.Background(),
		[]v1alpha1.WAFPolicy{mkPolicy("alpha"), mkPolicy("beta")}, src)
	if len(out) != 2 {
		t.Fatalf("outcomes = %d, want 2 (one per tenant)", len(out))
	}
	byKey := map[string]Outcome{}
	for _, o := range out {
		if o.Err != nil {
			t.Fatalf("outcome %s: compile error: %v", o.Key, o.Err)
		}
		byKey[o.Key] = o
	}
	oA, okA := byKey["alpha/chat-gate"]
	oB, okB := byKey["beta/chat-gate"]
	if !okA || !okB {
		t.Fatalf("outcomes lack the two tenants' keys (alpha=%v beta=%v)", okA, okB)
	}
	if oA.Bundle.Tenant != "alpha" {
		t.Fatalf("alpha bundle tenant = %q, want alpha", oA.Bundle.Tenant)
	}
	if oB.Bundle.Tenant != "beta" {
		t.Fatalf("beta bundle tenant = %q, want beta", oB.Bundle.Tenant)
	}
	ids := func(b *Bundle) []string {
		var ids []string
		for _, p := range b.RulePacks {
			for _, r := range p.Rules {
				ids = append(ids, r.ID)
			}
		}
		return ids
	}
	if !slices.Contains(ids(oA.Bundle), "TR08C-001") || slices.Contains(ids(oA.Bundle), "TR25-001") {
		t.Errorf("alpha bundle pack ids = %v, want TR08C-001 and never beta's TR25-001", ids(oA.Bundle))
	}
	if !slices.Contains(ids(oB.Bundle), "TR25-001") || slices.Contains(ids(oB.Bundle), "TR08C-001") {
		t.Errorf("beta bundle pack ids = %v, want TR25-001 and never alpha's TR08C-001", ids(oB.Bundle))
	}
	if _, err := Load(*oA.Bundle); err != nil {
		t.Errorf("alpha bundle must load: %v", err)
	}
	if _, err := Load(*oB.Bundle); err != nil {
		t.Errorf("beta bundle must load: %v", err)
	}
	wireA, err := json.Marshal(oA.Bundle)
	if err != nil {
		t.Fatalf("marshal alpha bundle: %v", err)
	}
	wireB, err := json.Marshal(oB.Bundle)
	if err != nil {
		t.Fatalf("marshal beta bundle: %v", err)
	}
	if bytes.Equal(wireA, wireB) {
		t.Error("alpha and beta bundles are byte-identical on the wire (one artifact, not per-tenant)")
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

// TestReconcileRefResolutionIsNamespaceLocked (TR-25, the spec's multi-tenancy requirement R8): a
// rule-set ref resolves in the policy's namespace ONLY. A pack present in
// another namespace is a missing ref: the outcome fails closed.
func TestReconcileRefResolutionIsNamespaceLocked(t *testing.T) {
	out := Reconcile(context.Background(),
		[]v1alpha1.WAFPolicy{fixturePolicyWithRef()},
		srcMap{"beta/dx1-sqli": sqliPack(t)})
	o := out[0]
	if o.Bundle != nil {
		t.Fatal("a pack present only under another namespace must not resolve the ref (no bundle)")
	}
	if o.Err == nil || !strings.Contains(o.Err.Error(), "dx1-sqli") {
		t.Errorf("error should name the unresolved ref, got: %v", o.Err)
	}
}

// TestReconcileStampsCompileSplit pins the split write on the reconcile
// path (TR-40b): the reconcile stamps the per-field annotation onto the
// policy object it compiles, and the deployed operator's persist step
// carries the same object. A failed compile carries no stamp — a policy
// with no bundle claims no split.
func TestReconcileStampsCompileSplit(t *testing.T) {
	policies := []v1alpha1.WAFPolicy{routeClassPolicy()}
	out := Reconcile(context.Background(), policies, nil)
	if len(out) != 1 || out[0].Err != nil {
		t.Fatalf("Reconcile(route policy): out = %+v, want one clean compile", out)
	}
	if out[0].Bundle == nil || out[0].Bundle.FastPath == nil {
		t.Fatalf("reconcile bundle lost the kernel leg: %+v", out[0].Bundle)
	}
	got := policies[0].Annotations[CompileSplitAnnotation]
	if got == "" {
		t.Fatal("reconcile left no compile-split annotation on the policy object")
	}
	if bundle, err := Compile(routeClassPolicy()); err == nil {
		want, _ := compileSplitJSON(bundle.Split)
		if got != want {
			t.Errorf("annotation = %q, want %q", got, want)
		}
	}
	// The failed compile carries no stamp: an uncompilable policy reads no
	// split, not a stale one.
	failed := routeClassPolicy()
	failed.Name = "broken"
	failed.Spec.Routes = []v1alpha1.RouteMark{{Prefix: strings.Repeat("p", 65), Action: v1alpha1.RouteActionDrop}}
	failedIn := []v1alpha1.WAFPolicy{failed}
	if out := Reconcile(context.Background(), failedIn, nil); len(out) == 1 && out[0].Err == nil {
		t.Fatal("the oversized prefix compiled, want a compile failure")
	}
	if ann := failedIn[0].Annotations[CompileSplitAnnotation]; ann != "" {
		t.Errorf("the failed compile stamped %q, want no annotation", ann)
	}
}
