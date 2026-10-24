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
	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// shapesDir names the committed shape directory. Files carry a trailing
// newline (the repo's file hygiene), and the bytes stay byte-identical to
// Compile's canonical JSON rendering plus that newline.
const shapesDir = "testdata/bundle-shapes"

// shapePolicies maps each committed shape file to the policy it compiles
// from. The policy set covers the compile surface: the 2-row route class,
// the 8-row bound corner, a single drop class, the kernel-free surface,
// and a route class with a CRS rule-set ref.
func shapePolicies() map[string]v1alpha1.WAFPolicy {
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
	return map[string]v1alpha1.WAFPolicy{
		"route_class_2row.json":      two,
		"route_class_8row.json":      eight,
		"route_class_drop_only.json": drop,
		"no_kernel_fields.json":      base("engine-only"),
		"route_class_ruleset.json":   ruleset,
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
			b, err := Compile(policies[name])
			if err != nil {
				t.Fatalf("Compile(%s): %v", name, err)
			}
			data, err := json.Marshal(&b)
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
			if back.Tenant != policies[name].Namespace {
				t.Errorf("shape %s tenant = %q, want %q", name, back.Tenant, policies[name].Namespace)
			}
			if policies[name].Spec.Routes == nil && back.FastPath != nil {
				t.Errorf("kernel-free shape %s carries a kernel leg: %+v", name, back.FastPath)
			}
			if policies[name].Spec.Routes != nil {
				if back.FastPath == nil {
					t.Fatalf("shape %s carries no kernel leg, want %d route rows", name, len(policies[name].Spec.Routes))
				}
				if got := len(back.FastPath.Routes); got != len(policies[name].Spec.Routes) {
					t.Fatalf("shape %s carries %d route rows, want %d", name, got, len(policies[name].Spec.Routes))
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
