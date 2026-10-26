package fastpath

// The CEL fast-path class compiler rows (TR-196, issue #238): the
// contract the construct census must satisfy. The class set is the
// census record's CEL vocabulary (docs/design/socket-plane/3-census.md
// section 4): the method equality (compare), the path glob (prefix and
// suffix segments at compile time), the query substring (bounded scan).
// Constructs outside the set reject at the compile gate (the rule routes
// the slow path, no kernel row, never a kernel claim).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/cel"
)

// ruleOf builds one pack rule for the census walk.
func ruleOf(id, action, expr string) cel.Rule {
	return cel.Rule{ID: id, Action: cel.Action(action), Expression: expr}
}

// TestGlobSegments decomposes the path glob at compile time: one star
// (or none) into the prefix and the suffix segments; a glob outside that
// form rejects (the class set covers prefix/suffix decomposition only).
func TestGlobSegments(t *testing.T) {
	rows := []struct {
		name  string
		glob  string
		want  CELGlobDecomp
		fails bool
	}{
		{"one star", "/v1/chat/*", CELGlobDecomp{Prefix: "/v1/chat/"}, false},
		{"leading star", "/*-admin", CELGlobDecomp{Prefix: "/", Suffix: "-admin"}, false},
		{"middle star", "/a*d", CELGlobDecomp{Prefix: "/a", Suffix: "d"}, false},
		{"literal full match", "/v1/chat", CELGlobDecomp{Prefix: "/v1/chat", Exact: true}, false},
		{"two stars", "/*x*y", CELGlobDecomp{}, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got, err := GlobSegments(row.glob)
			if row.fails {
				if err == nil {
					t.Fatalf("GlobSegments(%q): err nil, want the class-set reject", row.glob)
				}
				return
			}
			if err != nil {
				t.Fatalf("GlobSegments(%q): %v", row.glob, err)
			}
			if got.Prefix != row.want.Prefix || got.Suffix != row.want.Suffix || got.Exact != row.want.Exact {
				t.Fatalf("GlobSegments(%q) = %+v, want %+v", row.glob, got, row.want)
			}
		})
	}
}

// TestCensusConstructs censuses one construct per row: the class set
// names its constructs; anything else rejects with the construct named.
func TestCensusConstructs(t *testing.T) {
	inClass := []struct {
		name string
		expr string
		want []string
	}{
		{"method compare", `request.method == "POST"`, []string{"compare-method"}},
		{"path glob", `path.matches("/v1/chat/*")`, []string{"path-glob"}},
		{"query substring", `request.query.contains("UNION")`, []string{"query-substring"}},
		{"the DX-LAB-001 conjunction", `request.method == "POST" && path.matches("/v1/chat/*") && request.query.contains("UNION")`,
			[]string{"conjunction", "conjunction", "compare-method", "path-glob", "query-substring"}},
	}
	for _, row := range inClass {
		t.Run(row.name, func(t *testing.T) {
			got, err := CensusConstructs(row.expr)
			if err != nil {
				t.Fatalf("CensusConstructs: %v", err)
			}
			if len(got) != len(row.want) {
				t.Fatalf("census = %+v, want %+v", got, row.want)
			}
			for i, c := range got {
				if c.String() != row.want[i] {
					t.Fatalf("census[%d] = %q, want %q", i, c, row.want[i])
				}
			}
		})
	}
	outOfScope := []struct {
		name string
		expr string
	}{
		{"rate window read", `request.rate_windows["5m"].requests > 40`},
		{"stdlib string predicate", `request.query.startsWith("x")`},
		{"disjunction", `path.matches("/a") || path.matches("/b")`},
		{"negation", `!request.query.contains("x")`},
		{"undeclared name", `undeclared_top_level == "x"`},
	}
	for _, row := range outOfScope {
		t.Run(row.name, func(t *testing.T) {
			_, err := CensusConstructs(row.expr)
			if err == nil {
				t.Fatalf("CensusConstructs(%s): err nil, want the class-set reject", row.expr)
			}
		})
	}
}

// TestCompileCELFastPathRows compiles the pack rules to the template
// rows: the in-class rules carry one row in rule order, the out-of-class
// rules route T2 (the skip carries the rule id and the reason), the
// degenerate all-vacuous row fails the compile closed.
func TestCompileCELFastPathRows(t *testing.T) {
	pack := []cel.Rule{
		ruleOf("DX-LAB-001", "enforce", `request.method == "POST" && path.matches("/v1/chat/*") && request.query.contains("UNION")`),
		ruleOf("TR02-001", "log", `request.method == "POST" && path.matches("/v1/chat/*") && request.rate_windows["5m"].requests > 40`),
	}
	rows, skips, err := CompileCELFastPathRows(pack)
	if err != nil {
		t.Fatalf("CompileCELFastPathRows: %v", err)
	}
	// The walk ships the glob+method family at ONE staged row (the load
	// receipt). The query-substring rule rides the engine tier: the glob
	// and the query passes composite over the walk's 1M verifier
	// envelope at any row count. The rate rule routes T2 twice over: the
	// census verdict, then the row-bound envelope seat.
	if skipCount := len(skips); skipCount != 2 || skips[0].RuleID != "DX-LAB-001" || skips[1].RuleID != "TR02-001" {
		t.Fatalf("skips = %+v, want both rules routed T2 in order", skips)
	}
	if len(rows) != 0 {
		t.Fatalf("%d rows, want none (both rules carry a routed leg)", len(rows))
	}
}

// TestCompileCELFastPathRowsComposeRow proves the shipped family: the
// method equality + the prefix glob ride one compiled row. The suffix
// and the query legs route T2.
func TestCompileCELFastPathRowsComposeRow(t *testing.T) {
	pack := []cel.Rule{
		ruleOf("DX-LAB-020", "enforce", `request.method == "POST" && path.matches("/v1/chat/*")`),
	}
	rows, skips, err := CompileCELFastPathRows(pack)
	if err != nil {
		t.Fatalf("CompileCELFastPathRows: %v", err)
	}
	if len(skips) != 0 {
		t.Fatalf("skips = %+v, want none (the globe+method family compiles)", skips)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1 compiled row", len(rows))
	}
	r := rows[0]
	if r.ID != "DX-LAB-020" || r.Method != "POST" ||
		r.PathGlobPrefix != "/v1/chat/" || r.PathGlobSuffix != "" || r.QuerySubstring != "" {
		t.Fatalf("row = %+v", r)
	}
}

// TestCompileCELFastPathRowsSuffixRoutesSlowPath proves the suffix leg's
// skip row: the leading-star glob rides the engine tier (the verifier
// envelope: the third body composites the pair receipts over 1M).
func TestCompileCELFastPathRowsSuffixRoutesSlowPath(t *testing.T) {
	pack := []cel.Rule{
		ruleOf("DX-LAB-003", "enforce", `request.method == "POST" && path.matches("/*-admin")`),
	}
	rows, skips, err := CompileCELFastPathRows(pack)
	if err != nil {
		t.Fatalf("CompileCELFastPathRows: %v", err)
	}
	if len(rows) != 0 || len(skips) != 1 || skips[0].RuleID != "DX-LAB-003" {
		t.Fatalf("rows %+v skips %+v, want the suffix rule routed T2", rows, skips)
	}
	if skips[0].Reason == "" {
		t.Fatal("skip reason empty, want the envelope reason row")
	}
}

// TestCompileCELFastPathRowsQueryRoutesSlowPath proves the query leg's
// skip row at any row count (the load receipt: two rows still composite
// the passes over the envelope).
func TestCompileCELFastPathRowsQueryRoutesSlowPath(t *testing.T) {
	pack := []cel.Rule{
		ruleOf("DX-LAB-101", "enforce", `request.query.contains("UNION")`),
	}
	rows, skips, err := CompileCELFastPathRows(pack)
	if err != nil {
		t.Fatalf("CompileCELFastPathRows: %v", err)
	}
	if len(rows) != 0 || len(skips) != 1 || skips[0].RuleID != "DX-LAB-101" {
		t.Fatalf("rows %+v skips %+v, want the query rule routed T2", rows, skips)
	}
	if skips[0].Reason == "" {
		t.Fatal("skip reason empty, want the envelope reason row")
	}
}

// TestCompileCELFastPathRowsBound reads the bound shape: the first
// in-class rule fills the envelope seat; every later rule routes T2 with
// the seat reason. The wire row bound stays a hard failure behind the
// envelope gate.
func TestCompileCELFastPathRowsBound(t *testing.T) {
	pack := make([]cel.Rule, 0, FastPathCELMaxRules+1)
	for i := 0; i <= FastPathCELMaxRules; i++ {
		pack = append(pack, ruleOf(fmt.Sprintf("R%02d", i), "enforce", `request.method == "POST" && path.matches("/v1/chat/*")`))
	}
	rows, skips, err := CompileCELFastPathRows(pack)
	if err != nil {
		t.Fatalf("CompileCELFastPathRows: %v", err)
	}
	if len(rows) != FastPathCELEnvelopeRows {
		t.Fatalf("%d rows, want the envelope seat count %d", len(rows), FastPathCELEnvelopeRows)
	}
	if len(skips) != FastPathCELMaxRules+1-FastPathCELEnvelopeRows {
		t.Fatalf("%d skips, want the over-seat rules routed T2", len(skips))
	}
	for _, sk := range skips {
		if sk.Reason == "" {
			t.Fatalf("skip %+v carries no reason", sk)
		}
	}
}

// TestFastPathCELRuleValidation gates the wire row: the bounds, the
// printable bytes, the action vocabulary, the leg presence.
func TestFastPathCELRuleValidation(t *testing.T) {
	good := FastPathCELRule{ID: "DX-LAB-001", Action: RouteTemplateActionDrop,
		Method: "POST", PathGlobPrefix: "/v1/chat/", QuerySubstring: "UNION"}
	if err := ValidateFastPathCELRule(good); err != nil {
		t.Fatalf("ValidateFastPathCELRule(good): %v", err)
	}
	bad := []struct {
		name string
		row  FastPathCELRule
	}{
		{"no legs", FastPathCELRule{ID: "X", Action: RouteTemplateActionDrop}},
		{"method past the bound", FastPathCELRule{ID: "X", Action: RouteTemplateActionDrop, Method: strings.Repeat("P", FastPathCELMethodMaxBytes+1)}},
		{"glob prefix past the bound", FastPathCELRule{ID: "X", Action: RouteTemplateActionDrop,
			PathGlobPrefix: strings.Repeat("a", FastPathCELGlobPrefixMaxBytes+1)}},
		{"glob suffix past the bound", FastPathCELRule{ID: "X", Action: RouteTemplateActionDrop,
			PathGlobSuffix: strings.Repeat("a", FastPathCELGlobSuffixMaxBytes+1)}},
		{"query past the bound", FastPathCELRule{ID: "X", Action: RouteTemplateActionDrop,
			QuerySubstring: strings.Repeat("u", FastPathCELQueryMaxBytes+1)}},
		{"star in a decomposed leg", FastPathCELRule{ID: "X", Action: RouteTemplateActionDrop, PathGlobPrefix: "/a*b"}},
		{"action vocabulary", FastPathCELRule{ID: "X", Action: 9, Method: "POST"}},
		{"non-printable", FastPathCELRule{ID: "X", Action: RouteTemplateActionDrop, Method: "PO\x01"}},
	}
	for _, row := range bad {
		t.Run(row.name, func(t *testing.T) {
			if err := ValidateFastPathCELRule(row.row); err == nil {
				t.Fatalf("ValidateFastPathCELRule(%s): err nil, want the reject", row.name)
			}
		})
	}
}
