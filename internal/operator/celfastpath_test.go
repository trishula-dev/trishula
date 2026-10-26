package operator

// The CEL fast-path class leg's load-gate contract rows (TR-196, issue
// #238). The leg rides the same fail-closed wire gate the route class
// carries: the rows re-validate on Load (bounds, printable bytes, the leg
// presence, the action vocabulary, the dup ids), and a bundle whose rules
// all route T2 carries no leg and no kernel claim. The degrade reads live
// on the load gate: a leg the loader refuses never installs, so the class
// stays at T2 and the previous bundle keeps serving.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// seedPackForTest parses the embedded seed pack (the same bytes Compile
// embeds; the test needs the pack to splice against).
func seedPackForTest(t *testing.T) cel.RulePack {
	t.Helper()
	pack, err := cel.ParseRulePack(seedPackBytes)
	if err != nil {
		t.Fatalf("seed pack: %v", err)
	}
	return *pack
}

// dxRule builds one in-class rule (the method compare, the glob, the
// query substring), exactly the DX-LAB-001 shape.
func dxRule(id string) cel.Rule {
	return cel.Rule{ID: id, Action: cel.ActionEnforce,
		Expression: "request.method == \"POST\" && path.matches(\"/v1/chat/*\") && request.query.contains(\"UNION\")"}
}

// TestCompileFastPathCELRowsFromPacks compiles the leg from the resolved
// packs and re-digests: the seed's rate rule routes T2, the in-class rule
// carries its row.
func TestCompileFastPathCELRowsFromPacks(t *testing.T) {
	seed := seedPackForTest(t)
	dx := cel.RulePack{Rules: []cel.Rule{
		{ID: "DX-LAB-020", Action: cel.ActionEnforce, Expression: `request.method == "POST" && path.matches("/v1/chat/*")`},
	}}
	b := Bundle{RulePacks: []cel.RulePack{seed, dx}}
	if err := CompileFastPathCELRows(&b); err != nil {
		t.Fatalf("CompileFastPathCELRows: %v", err)
	}
	if len(b.FastPath.CELRules) != 1 {
		t.Fatalf("%d cel rows, want 1 (the seed rule routes T2)", len(b.FastPath.CELRules))
	}
	if got := b.FastPath.CELRules[0].ID; got != "DX-LAB-020" {
		t.Fatalf("row id %q, want DX-LAB-020", got)
	}
	// The digests recompute over the spliced packs (two packs, two digests).
	if len(b.RulePackDigests) != 2 {
		t.Fatalf("%d digests, want 2", len(b.RulePackDigests))
	}
}

// TestLoadRefusesBoundsViolations reads the same gate the loader runs:
// rows past the bound and a star inside a decomposed leg fail closed.
func TestLoadRefusesBoundsViolations(t *testing.T) {
	base := func(rules []fastpath.FastPathCELRule) Bundle {
		seed := seedPackForTest(t)
		digests, err := PackDigests([]cel.RulePack{seed})
		if err != nil {
			t.Fatalf("digests: %v", err)
		}
		return Bundle{
			FormatVersion:   BundleFormatVersion,
			Tenant:          "ai-platform",
			RulePacks:       []cel.RulePack{seed},
			KernelValues:    &KernelValues{ACL4: map[string]string{}, ACL6: map[string]string{}, Verdicts: map[string]string{}},
			RulePackDigests: digests,
			FastPath:        &FastPathValues{CELRules: rules},
		}
	}
	rows := []struct {
		name  string
		rules []fastpath.FastPathCELRule
	}{
		{"an over-bound method", []fastpath.FastPathCELRule{{ID: "X", Action: fastpath.RouteTemplateActionDrop, Method: strings.Repeat("P", fastpath.FastPathCELMethodMaxBytes+1)}}},
		{"a star in a decomposed leg", []fastpath.FastPathCELRule{{ID: "X", Action: fastpath.RouteTemplateActionDrop, PathGlobPrefix: "/a*b"}}},
		{"a no-leg row", []fastpath.FastPathCELRule{{ID: "X", Action: fastpath.RouteTemplateActionDrop}}},
		{"an out-of-vocabulary action", []fastpath.FastPathCELRule{{ID: "X", Action: 9, Method: "POST"}}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if _, err := Load(base(row.rules)); err == nil {
				t.Fatal("Load: err nil, want the wire-gate reject")
			}
		})
	}
	t.Run("duplicate ids", func(t *testing.T) {
		rules := []fastpath.FastPathCELRule{
			{ID: "X", Action: fastpath.RouteTemplateActionDrop, Method: "POST"},
			{ID: "X", Action: fastpath.RouteTemplateActionDrop, Method: "GET"},
		}
		if _, err := Load(base(rules)); err == nil {
			t.Fatal("Load: err nil, want the duplicate-id reject")
		}
	})
}

// TestBundleCarriesNoKernelClaimForT2Rules pins the honesty row: a
// bundle whose packs carry only out-of-class rules compiles with no
// fastPath leg; the rules stay in the packs (the engine keeps them) and
// the load never reads a kernel claim.
func TestBundleCarriesNoKernelClaimForT2Rules(t *testing.T) {
	seed := seedPackForTest(t)
	t2 := cel.RulePack{Rules: []cel.Rule{{
		ID:         "DX-LAB-101",
		Action:     cel.ActionEnforce,
		Expression: "request.query.startsWith(\"x=1\")",
	}}}
	b := Bundle{FormatVersion: BundleFormatVersion, Tenant: "ai-platform", RulePacks: []cel.RulePack{seed, t2}}
	digests, err := PackDigests(b.RulePacks)
	if err != nil {
		t.Fatalf("digests: %v", err)
	}
	b.RulePackDigests = digests
	b.KernelValues = &KernelValues{ACL4: map[string]string{}, ACL6: map[string]string{}, Verdicts: map[string]string{}}
	if err := CompileFastPathCELRows(&b); err != nil {
		t.Fatalf("CompileFastPathCELRows: %v", err)
	}
	if b.FastPath != nil {
		t.Fatalf("the T2-only bundle carries a kernel leg: %+v", b.FastPath)
	}
	if _, err := Load(b); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The wire round-trips the shape (the byte-identical encode/decode).
	data, err := json.Marshal(&b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Bundle
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := Load(back); err != nil {
		t.Fatalf("Load(round-trip): %v", err)
	}
}

// TestCompilePolicyWithCELFastPathLeg compiles a v1alpha1 policy whose
// rule set resolves to the DX-LAB-001 pack: the rows land on the
// policy's bundle beside the routes leg, no claim beyond the rows.
func TestCompilePolicyWithCELFastPathLeg(t *testing.T) {
	policy := v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cel-lane", Namespace: "ai-platform"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionBlock,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shield: true},
		},
	}
	b, err := Compile(policy)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	b.RulePacks = append(b.RulePacks, cel.RulePack{Rules: []cel.Rule{
		dxRule("DX-LAB-001"), // the query leg rides the engine tier (the envelope gate)
		cel.Rule{ID: "DX-LAB-020", Action: cel.ActionEnforce, Expression: `request.method == "POST" && path.matches("/v1/chat/*")`},
	}})
	if err := CompileFastPathCELRows(&b); err != nil {
		t.Fatalf("CompileFastPathCELRows: %v", err)
	}
	if len(b.FastPath.CELRules) != 1 || b.FastPath.CELRules[0].ID != "DX-LAB-020" {
		t.Fatalf("leg = %+v, want the prefix row only (the query rule routes T2)", b.FastPath.CELRules)
	}
}
