package operator_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
)

// TR-08b acceptance (issue #75): a WAFPolicy Go object (no cluster)
// compiles to a bundle whose CEL/seed rules load into the engine's
// TR-02-style env and evaluate. Test contract: tests use ONLY package APIs
// (v1alpha1, cel, operator) — never cel-go directly; RED state = the
// operator symbols below are undefined.
//
// The compile resolves a policy with no custom CEL rule sets to the seed
// rule pack (TR-02, rules/cel/seed.yaml): exactly one rule, the §11.3
// rate-shape example, action=log. Every bundle embeds it as the default
// CEL plane so a minimal v0 policy is evaluable.
const seedRuleID = "TR02-001"

func fixturePolicy() v1alpha1.WAFPolicy {
	return v1alpha1.WAFPolicy{
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionBlock,
			ModeFlags:     v1alpha1.PolicyModeFlags{Shadow: true},
		},
	}
}

// fixtureRequest is the §11.3 fixture request: the boundary case above the
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
	if len(bundle.CELRules) != 1 || bundle.CELRules[0] != seedRuleID {
		t.Fatalf("bundle CEL rules = %v, want [%s]", bundle.CELRules, seedRuleID)
	}
	if bundle.KernelValues == nil {
		t.Fatalf("bundle.KernelValues = nil, want the empty §9.3 stub record")
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

// TestLoadMismatchDetectsTampering closes the round trip's mismatch arm:
// a bundle whose rule expression was altered after compile must fail to
// load, not eval silently under tampered semantics.
func TestLoadMismatchDetectsTampering(t *testing.T) {
	bundle, err := Compile(fixturePolicy())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	spoiled := bundle
	spoiled.CELRules = []string{seedRuleID}
	spoiled.RulePacks = append([]cel.RulePack(nil), bundle.RulePacks...)
	spoiled.RulePacks[0].Rules[0].Expression = "request.method == \"GET\""

	if _, err := Load(spoiled); err == nil {
		t.Fatalf("Load accepted a tampered bundle (expression altered post-compile); want mismatch error")
	}
}

// TestBundleRoundTripsThroughBytes pins the bundle's wire format: the
// JSON encoding decodes to an equal bundle (§8.1: bundles are the signed
// distribution unit; the format is JSON, version 1).
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
	if !reflect.DeepEqual(bundle, &back) {
		t.Fatalf("bundle round-trip drift:\n want %+v\n got  %+v", bundle, back)
	}
}
