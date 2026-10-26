package operator

// The committed bundle-shape census (TR-40c, issue #189, child of TR-40
// #52). Every file under testdata/bundle-shapes is a real Compile output:
// the suite recompiles the policy behind each shape and pins the bytes. A
// drifted or hand-edited shape fails the suite, so the route gate always
// reads Compile-faithful bundles. The route gate reads the same files per
// bundle (test/route-e2e) and loads each one through the kernel verifier.

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	v1alpha1 "github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// shapesDir names the committed shape directory. Files carry a trailing
// newline (the repo's file hygiene), and the bytes stay byte-identical to
// Compile's canonical JSON rendering plus that newline.
const shapesDir = "testdata/bundle-shapes"

// shapeSpec is one committed shape's source: the policy plus the optional
// custom rule pack (the TR-196 CEL-class shapes).
type shapeSpec struct {
	policy v1alpha1.WAFPolicy
	rules  []cel.Rule
}

// compileShape compiles one shape's source to its bundle: the policy
// compile, then the optional pack splice (the seed pack stays first, the
// TR-08b contract) with the compiled CEL-class leg and the re-digests.
func compileShape(spec shapeSpec) *Bundle {
	b, err := Compile(spec.policy)
	if err != nil {
		panic(err)
	}
	if len(spec.rules) > 0 {
		pack := cel.RulePack{Rules: spec.rules}
		b.RulePacks = append(b.RulePacks, pack)
		if err := CompileFastPathCELRows(&b); err != nil {
			panic(err)
		}
	}
	return &b
}

// shapePolicies maps each committed shape file to its source. The policy
// set covers the compile surface: the 2-row route class, the 8-row bound
// corner, a single drop class, the kernel-free surface, a route class
// with a CRS rule-set ref, and the TR-196 CEL-class rows (one glob row,
// two rows, and a pack whose rules all route T2: no kernel leg).
func shapePolicies() map[string]shapeSpec {
	rm := func(p string, a v1alpha1.RouteAction) v1alpha1.RouteMark {
		return v1alpha1.RouteMark{Prefix: p, Action: a}
	}
	base := func(name string) v1alpha1.WAFPolicy {
		return v1alpha1.WAFPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ai-platform"},
			Spec: v1alpha1.WAFPolicySpec{
				DefaultAction: v1alpha1.DefaultActionBlock,
				ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shield: true},
			},
		}
	}
	two := base("route-class")
	two.Spec.Routes = []v1alpha1.RouteMark{
		rm("/v1/chat", v1alpha1.RouteActionForward),
		rm("/v1/admin", v1alpha1.RouteActionDrop),
	}
	eight := base("route-class-full")
	eight.Spec.Routes = []v1alpha1.RouteMark{
		rm("/v1/chat", v1alpha1.RouteActionForward),
		rm("/v1/admin", v1alpha1.RouteActionDrop),
		rm("/v1/completions", v1alpha1.RouteActionForward),
		rm("/v2/chat", v1alpha1.RouteActionForward),
		rm("/v2/admin", v1alpha1.RouteActionDrop),
		rm("/api/pay", v1alpha1.RouteActionDrop),
		rm("/api/health", v1alpha1.RouteActionForward),
		rm("/internal/health", v1alpha1.RouteActionForward),
	}
	drop := base("route-block")
	drop.Spec.Routes = []v1alpha1.RouteMark{rm("/blocked", v1alpha1.RouteActionDrop)}
	ruleset := base("route-crs")
	ruleset.Spec.Routes = two.Spec.Routes
	ruleset.Spec.RuleSets = []v1alpha1.RuleSetRef{{
		Name:   "owasp-crs",
		Source: v1alpha1.RuleSetSource{CRSVersion: "4.0.0", Profile: v1alpha1.CRSProfilePL1},
	}}
	celGlob := base("cel-class-glob")
	cel2row := base("cel-class-2row")
	celT2 := base("cel-class-t2pack")
	dxGlob := func(id, glob string) cel.Rule {
		return cel.Rule{ID: id, Action: cel.ActionEnforce,
			Expression: "request.method == \"POST\" && path.matches(\"" + glob + "\")"}
	}
	return map[string]shapeSpec{
		"route_class_2row.json":      {policy: two},
		"route_class_8row.json":      {policy: eight},
		"route_class_drop_only.json": {policy: drop},
		"no_kernel_fields.json":      {policy: base("engine-only")},
		"route_class_ruleset.json":   {policy: ruleset},
		"cel_class_glob.json": {policy: celGlob, rules: []cel.Rule{
			{ID: "DX-LAB-001", Action: cel.ActionEnforce,
				Expression: "request.method == \"POST\" && path.matches(\"/v1/chat/*\") && request.query.contains(\"UNION\")"},
		}},
		"cel_class_gm.json": {policy: celGlob, rules: []cel.Rule{
			{ID: "DX-LAB-020", Action: cel.ActionEnforce,
				Expression: "request.method == \"POST\" && path.matches(\"/v1/chat/*\")"},
		}},
		"cel_class_2row.json": {policy: cel2row, rules: []cel.Rule{
			dxGlob("DX-LAB-010", "/v1/chat/*"),
			dxGlob("DX-LAB-011", "/v1/auth"),
		}},
		"cel_class_t2pack.json": {policy: celT2, rules: []cel.Rule{
			{ID: "DX-LAB-101", Action: cel.ActionEnforce,
				Expression: "request.query.startsWith(\"x=1\")"},
		}},
	}
}

// TestCommittedBundleShapes pins the census: the committed shape file set
// matches the policy set, every committed file is byte-identical to its
// recompiled canonical JSON, and every shape passes the wire load gate.
func TestCommittedBundleShapes(t *testing.T) {
	entries, err := os.ReadDir(shapesDir)
	if err != nil {
		t.Fatalf("read the committed bundle shapes: %v", err)
	}
	committed := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		committed[e.Name()] = true
	}
	if len(committed) == 0 {
		t.Fatal("the committed bundle-shape set is empty; the gate needs shapes")
	}
	policies := shapePolicies()
	for name := range committed {
		if _, ok := policies[name]; !ok {
			t.Errorf("committed shape %s carries no policy; the shape set and the census drift", name)
		}
	}
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if !committed[name] {
				t.Fatalf("committed shape %s is missing; recompile the shapePolicies entry and write Marshal's bytes plus a newline", name)
			}
			b := compileShape(policies[name])
			data, err := json.Marshal(b)
			if err != nil {
				t.Fatalf("marshal shape %s: %v", name, err)
			}
			raw, err := os.ReadFile(shapesDir + "/" + name)
			if err != nil {
				t.Fatalf("read shape %s: %v", name, err)
			}
			if string(raw) != string(data)+"\n" {
				t.Fatalf("committed shape %s drifts from Compile output; recompile and rewrite the bytes plus a newline", name)
			}
			var back Bundle
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatalf("decode shape %s: %v", name, err)
			}
			if _, err := Load(back); err != nil {
				t.Fatalf("wire gate: Load(%s): %v", name, err)
			}
			if back.Tenant != policies[name].policy.Namespace {
				t.Errorf("shape %s tenant = %q, want %q", name, back.Tenant, policies[name].policy.Namespace)
			}
			if policies[name].policy.Spec.Routes == nil && back.FastPath != nil &&
				len(back.FastPath.CELRules) == 0 {
				t.Errorf("kernel-free shape %s carries a kernel leg: %+v", name, back.FastPath)
			}
			if len(policies[name].rules) > 0 {
				if back.FastPath == nil {
					// The T2-route shape: every rule routed T2, no
					// kernel leg, no kernel claim. The rule packs stay.
					if len(back.RulePacks) < 2 {
						t.Errorf("t2 shape %s carries %d packs, want the seed and the case pack", name, len(back.RulePacks))
					}
					return
				}
				// The compiled CEL-class rows read back per the shape: the
				// byte parity above already pins the leg; the row count
				// and the one-class shape read here.
				if back.FastPath == nil || len(back.FastPath.CELRules) != len(b.FastPath.CELRules) {
					t.Fatalf("cel shape %s: %d cel rows on the wire, want %d",
						name, len(back.FastPath.CELRules), len(b.FastPath.CELRules))
				}
				if len(back.FastPath.Routes) > 0 {
					t.Errorf("cel shape %s carries %d route rows; one leg rides one shape", name, len(back.FastPath.Routes))
				}
			}
			if policies[name].policy.Spec.Routes != nil {
				if back.FastPath == nil {
					t.Fatalf("shape %s carries no kernel leg, want %d route rows", name, len(policies[name].policy.Spec.Routes))
				}
				if got := len(back.FastPath.Routes); got != len(policies[name].policy.Spec.Routes) {
					t.Fatalf("shape %s carries %d route rows, want %d", name, got, len(policies[name].policy.Spec.Routes))
				}
				for _, field := range []string{"spec.routes[].prefix", "spec.routes[].action"} {
					if got := back.Split[field]; got != fastpath.VerdictKernel.String() {
						t.Errorf("shape %s split[%s] = %q, want %q", name, field, got, fastpath.VerdictKernel.String())
					}
				}
			}
		})
	}
}
