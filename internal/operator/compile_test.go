package operator

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/fastpath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TR-08b acceptance (issue #75): a WAFPolicy Go object (no cluster)
// compiles to a bundle whose CEL/seed rules load into the engine's
// TR-02-style env and evaluate. Test contract: tests use ONLY package APIs
// (v1alpha1, cel, operator) — never cel-go directly; RED state = the
// operator symbols below are undefined.
//
// The compile resolves a policy with no custom CEL rule sets to the seed
// rule pack (TR-02, rules/cel/seed.yaml): exactly one rule, the spec's
// rate-shape example, action=log. Every bundle embeds it as the default
// CEL plane so a minimal v0 policy is evaluable.
const wantSeedRuleID = "TR02-001"

func fixturePolicy() v1alpha1.WAFPolicy {
	return v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "seed-policy", Namespace: "lab"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionBlock,
			ModeFlags:     v1alpha1.PolicyModeFlags{Shadow: true},
		},
	}
}

// fixtureRequest is the spec's CEL fixture request: the boundary case above the
// seed rule's > 40 request threshold inside the /v1/chat/* glob.
func fixtureRequest() cel.Request {
	return cel.Request{
		Method: "POST",
		Path:   "/v1/chat/completions",
		RateWindows: map[string]cel.RateWindow{
			"5m": {Requests: 41},
		},
	}
}

// TestCompileLoadRoundTrip drives the in-process compile→load→eval chain:
// Compile(policy) → bundle → Load(bundle) → evaluator → verdict for a
// fixture request. A policy with no CEL rule sets carries the seed rule;
// the boundary request matches it (the sample_request.yaml expectation).
func TestCompileLoadRoundTrip(t *testing.T) {
	bundle, err := Compile(fixturePolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if bundle.FormatVersion != 1 {
		t.Fatalf("bundle format version = %d, want 1", bundle.FormatVersion)
	}
	if len(bundle.RulePacks) != 1 || len(bundle.RulePacks[0].Rules) != 1 || bundle.RulePacks[0].Rules[0].ID != wantSeedRuleID {
		t.Fatalf("bundle CEL plane = %+v, want one rule with id %s", bundle.RulePacks, wantSeedRuleID)
	}
	if bundle.KernelValues == nil {
		t.Fatalf("bundle.KernelValues = nil, want the empty §9.3 stub record") // TR-91 census: spec citation inside string literal; kept (conversion would change behavior)
	}

	eval, err := Load(bundle)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v, err := eval.Eval(fixtureRequest())
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if v.Error || v.Fatal {
		t.Fatalf("verdict error=%v fatal=%v detail=%q, want a clean eval", v.Error, v.Fatal, v.Detail)
	}
	if !v.Match {
		t.Fatalf("verdict match=%v, want true (boundary request inside the seed rate-shape rule)", v.Match)
	}
}

// TestCompileStampsTenantNamespace (TR-25, the spec's multi-tenancy requirement R8): every compiled
// bundle binds its tenant — the WAFPolicy's namespace — so a bundle never
// leaves the operator unqualified.
func TestCompileStampsTenantNamespace(t *testing.T) {
	bundle, err := Compile(fixturePolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if bundle.Tenant != "lab" {
		t.Fatalf("bundle tenant = %q, want %q (the policy namespace)", bundle.Tenant, "lab")
	}
}

// TestCompileRejectsTenantlessPolicy (TR-25, the spec's multi-tenancy requirement R8): a
// namespace-less WAFPolicy compiles to nothing (fail closed). An
// unqualified bundle cannot bind a tenant.
func TestCompileRejectsTenantlessPolicy(t *testing.T) {
	p := fixturePolicy()
	p.Namespace = ""
	if _, err := Compile(p); err == nil {
		t.Fatal("Compile accepted a namespace-less WAFPolicy (no tenant binding)")
	}
}

// TestLoadMismatchDetectsTampering closes the round trip's mismatch arm:
// a bundle whose rule expression was altered after compile must fail to
// load, not eval silently under tampered semantics.
func TestLoadMismatchDetectsTampering(t *testing.T) {
	bundle, err := Compile(fixturePolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	spoiled := bundle
	spoiled.RulePacks = append([]cel.RulePack(nil), bundle.RulePacks...)
	spoiled.RulePacks[0].Rules[0].Expression = "request.method == \"GET\""

	if _, err := Load(spoiled); err == nil {
		t.Fatalf("Load accepted a tampered bundle (expression altered post-compile); want mismatch error")
	}
}

// TestLoadRejectsTenantlessBundle (TR-25, the spec's multi-tenancy requirement R8): Load fails closed
// on a bundle without the tenant binding. The distribution unit never
// loads unqualified.
func TestLoadRejectsTenantlessBundle(t *testing.T) {
	bundle, err := Compile(fixturePolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	bundle.Tenant = ""
	if _, err := Load(bundle); err == nil {
		t.Fatal("Load accepted a bundle with no tenant binding")
	}
}

// routeClassPolicy is the fixture policy carrying the route class: one
// forward class and one drop class, rule sets absent.
func routeClassPolicy() v1alpha1.WAFPolicy {
	return v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "route-class", Namespace: "ai-platform"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionBlock,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shield: true},
			Routes: []v1alpha1.RouteMark{
				{Prefix: "/v1/chat", Action: v1alpha1.RouteActionForward},
				{Prefix: "/admin", Action: v1alpha1.RouteActionDrop},
			},
		},
	}
}

// TestCompileRouteClassCarriesKernelLeg pins the TR-40b compile leg: a
// WAFPolicy carrying the route class compiles through the census class set
// into the bundle's kernel leg (the template's placeholders), and the
// compile-split map rides beside it. The seed CEL plane stays intact.
func TestCompileRouteClassCarriesKernelLeg(t *testing.T) {
	bundle, err := Compile(routeClassPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	want := []FastPathRoute{
		{Prefix: "/v1/chat", Action: fastpath.RouteTemplateActionForward},
		{Prefix: "/admin", Action: fastpath.RouteTemplateActionDrop},
	}
	if bundle.FastPath == nil {
		t.Fatalf("bundle.FastPath = nil, want the route leg with %d rows", len(want))
	}
	if !reflect.DeepEqual(bundle.FastPath.Routes, want) {
		t.Errorf("bundle.FastPath.Routes = %v, want %v", bundle.FastPath.Routes, want)
	}
	if got, ok := bundle.Split["spec.routes[].prefix"]; !ok || got != fastpath.VerdictKernel.String() {
		t.Errorf("bundle.Split[spec.routes[].prefix] = %q ok=%v, want %q", got, ok, fastpath.VerdictKernel)
	}
	if got, ok := bundle.Split["spec.defaultAction"]; !ok || got != fastpath.VerdictSlowPath.String() {
		t.Errorf("bundle.Split[spec.defaultAction] = %q ok=%v, want %q", got, ok, fastpath.VerdictSlowPath)
	}
	if len(bundle.Split) != 7 {
		t.Errorf("bundle.Split carries %d pairs, want 7 (5 present slow-path rows + 2 route rows)", len(bundle.Split))
	}
	if len(bundle.RulePacks) != 1 || bundle.RulePacks[0].Rules[0].ID != wantSeedRuleID {
		t.Errorf("seed CEL plane lost: %v", bundle.RulePacks)
	}
}

// TestCompileRouteClassNoKernelLeg pins the honesty zero of the compile:
// a policy without the route class compiles NO kernel leg. The bundle
// carries the split map only, and an engine keeps loading it unchanged.
func TestCompileRouteClassNoKernelLeg(t *testing.T) {
	bundle, err := Compile(fixturePolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if bundle.FastPath != nil {
		t.Errorf("bundle.FastPath = %+v, want nil on a policy without the route class", bundle.FastPath)
	}
	if _, ok := bundle.Split["spec.routes[].prefix"]; ok {
		t.Errorf("bundle.Split carries a route row on a policy without routes: %v", bundle.Split)
	}
	if len(bundle.Split) == 0 {
		t.Errorf("bundle.Split carries no pairs; the present slow-path rows are missing")
	}
}

// TestCompileRouteClassFailClosed pins the compile-side template bounds:
// every contract violation fails closed with the offending cell named,
// and no bundle leaves the compile.
func TestCompileRouteClassFailClosed(t *testing.T) {
	long := strings.Repeat("a", fastpath.RouteTemplatePrefixMaxBytes+1)
	rows := []struct {
		name    string
		routes  []v1alpha1.RouteMark
		wantErr string
	}{
		{
			name:    "empty prefix",
			routes:  []v1alpha1.RouteMark{{Prefix: "", Action: v1alpha1.RouteActionForward}},
			wantErr: "spec.routes[0].prefix",
		},
		{
			name:    "65-byte prefix",
			routes:  []v1alpha1.RouteMark{{Prefix: long, Action: v1alpha1.RouteActionForward}},
			wantErr: "spec.routes[0].prefix",
		},
		{
			name:    "control byte inside the prefix",
			routes:  []v1alpha1.RouteMark{{Prefix: "/api\n", Action: v1alpha1.RouteActionForward}},
			wantErr: "spec.routes[0].prefix",
		},
		{
			name:    "nine routes",
			routes:  []v1alpha1.RouteMark{{Prefix: "/a", Action: v1alpha1.RouteActionForward}, {Prefix: "/b", Action: v1alpha1.RouteActionForward}, {Prefix: "/c", Action: v1alpha1.RouteActionForward}, {Prefix: "/d", Action: v1alpha1.RouteActionForward}, {Prefix: "/e", Action: v1alpha1.RouteActionDrop}, {Prefix: "/f", Action: v1alpha1.RouteActionDrop}, {Prefix: "/g", Action: v1alpha1.RouteActionDrop}, {Prefix: "/h", Action: v1alpha1.RouteActionDrop}, {Prefix: "/i", Action: v1alpha1.RouteActionDrop}},
			wantErr: "spec.routes",
		},
		{
			name:    "duplicate prefix",
			routes:  []v1alpha1.RouteMark{{Prefix: "/api", Action: v1alpha1.RouteActionForward}, {Prefix: "/api", Action: v1alpha1.RouteActionDrop}},
			wantErr: "spec.routes[1].prefix",
		},
	}
	for _, row := range rows {
		policy := routeClassPolicy()
		policy.Spec.Routes = row.routes
		bundle, err := Compile(policy)
		if err == nil {
			t.Errorf("%s: Compile succeeded, want a named compile failure", row.name)
			continue
		}
		if !strings.Contains(err.Error(), row.wantErr) {
			t.Errorf("%s: Compile err = %v, want it to name %q", row.name, err, row.wantErr)
		}
		if bundle.FormatVersion != 0 {
			t.Errorf("%s: Compile returned a bundle on the failure path", row.name)
		}
	}
}

// TestLoadGateValidatesFastPathLeg pins the load-side staging gate: a
// bundle whose kernel leg carries data the template contract cannot stage
// fails the load (tamper and corruption never reach the loader).
func TestLoadGateValidatesFastPathLeg(t *testing.T) {
	bundle, err := Compile(routeClassPolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rows := []struct {
		name    string
		routes  []FastPathRoute
		wantErr string
	}{
		{
			name:    "unknown action code",
			routes:  []FastPathRoute{{Prefix: "/admin", Action: 7}},
			wantErr: "spec.routes[0].action",
		},
		{
			name:    "65-byte prefix",
			routes:  []FastPathRoute{{Prefix: strings.Repeat("a", fastpath.RouteTemplatePrefixMaxBytes+1), Action: 0}},
			wantErr: "spec.routes[0].prefix",
		},
		{
			name: "duplicate prefix",
			routes: []FastPathRoute{
				{Prefix: "/admin", Action: 0}, {Prefix: "/admin", Action: 1},
			},
			wantErr: "spec.routes[1].prefix",
		},
		{
			name: "nine rows past the bound",
			routes: []FastPathRoute{
				{Prefix: "/a", Action: 0}, {Prefix: "/b", Action: 0}, {Prefix: "/c", Action: 0}, {Prefix: "/d", Action: 0},
				{Prefix: "/e", Action: 1}, {Prefix: "/f", Action: 1}, {Prefix: "/g", Action: 1}, {Prefix: "/h", Action: 1},
				{Prefix: "/i", Action: 1},
			},
			wantErr: "spec.routes",
		},
	}
	for _, row := range rows {
		tampered := bundle
		tampered.FastPath = &FastPathValues{Routes: row.routes}
		if _, err := Load(tampered); err == nil {
			t.Errorf("%s: Load accepted the kernel leg, want a staged gate failure", row.name)
			continue
		} else if !strings.Contains(err.Error(), row.wantErr) {
			t.Errorf("%s: Load err = %v, want it to name %q", row.name, err, row.wantErr)
		}
	}
}

// TestBundleRoundTripsThroughBytes pins the bundle's wire format: the
// JSON encoding decodes to an equal bundle (the spec's architecture: bundles are the signed
// distribution unit; the format is JSON, version 1). The TR-40b legs carry
// optional JSON legs and round-trip the same way.
func TestBundleRoundTripsThroughBytes(t *testing.T) {
	bundle, err := Compile(fixturePolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	data, err := json.Marshal(&bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	var back Bundle
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if !reflect.DeepEqual(bundle, back) {
		t.Fatalf("bundle round-trip drift:\n want %+v\n got  %+v", bundle, back)
	}
}
