package fastpath

// The CEL fast-path class compiler leg (TR-196, issue #238): the construct
// census of the record part 3 (docs/design/socket-plane/3-census.md
// section 4, the CEL vocabulary rows) and the glob decomposition, both at
// compile time. A rule whose constructs carry the census class set
// compiles to the template primitive set's compiled row form; every other
// rule routes the slow path (the ladder's F5: the tier-2 route, no kernel
// row, no kernel claim). The class never compiles a kernel program here —
// the compiled rows are the loader's staging truth; the kernel stays
// decision-free over them.
//
// Class set (the class-2 constructs), one conjunction tree:
//
//   - `request.method == "LIT"` — the method compare.
//   - `path.matches("GLOB")` (also `request.path.matches`) — the path
//     glob, decomposed at compile time into the prefix and the suffix
//     segments (one star, or none for the exact literal; the star crosses
//     `/`, exactly the engine's file-glob semantics).
//   - `request.query.contains("LIT")` — the query substring.
//   - conjunctions (`&&`) of the above.
//
// Anything else — the rate-window read, the stdlib string predicates,
// disjunctions, negations, undeclared names — is outside the class set:
// the census rejects with the construct named and the rule routes the
// slow path. The engine keeps the rule (the rule packs carry it); the
// kernel carries no row for it.

import (
	"fmt"
	"strings"

	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types/ref"

	gocel "cel.dev/cel-go/cel"

	"github.com/trishula-dev/trishula/internal/engine/cel"
)

// The compiled-row bounds (the template primitive's row shape; the C
// carries the same figures — bpf/flow_tc.c's fp leg — and the loader
// re-checks every bound). Each bound names the class-set boundary: a
// rule whose literal passes it routes the slow path.
const (
	// FastPathCELEnvelopeRows is the staged-row bound the shipped walk
	// proves (the load receipt: the one-row walk loads; the second row
	// composites the passes over the 1M verifier envelope). A rule past
	// this bound rides the engine tier (the envelope gate).
	FastPathCELEnvelopeRows = 1
	// FastPathCELMaxRules is the compiled-row bound per bundle. A policy
	// whose in-class rules pass it fails the compile closed (the route
	// class's template-bound posture).
	FastPathCELMaxRules = 8
	// FastPathCELMethodMaxBytes is the method-literal bound.
	FastPathCELMethodMaxBytes = 8
	// FastPathCELGlobPrefixMaxBytes is the glob-prefix bound.
	FastPathCELGlobPrefixMaxBytes = 48
	// FastPathCELGlobSuffixMaxBytes is the glob-suffix bound.
	FastPathCELGlobSuffixMaxBytes = 16
	// FastPathCELQueryMaxBytes is the query-substring literal bound (the
	// C carries the same figure: bpf/flow_tc.c's fp_rule_val.query =
	// FP_QUERY_MAX 8; the extract window and the row literal share the
	// field, and a literal past the window never completes the compare).
	FastPathCELQueryMaxBytes = 8
)

// Construct is one census construct class of the record's CEL vocabulary.
type Construct string

// The census construct classes (the class set).
const (
	// ConstructCompareMethod is the method-equality compare.
	ConstructCompareMethod Construct = "compare-method"
	// ConstructPathGlob is the path glob (the prefix/suffix segments at
	// compile time, the record's adapted construct).
	ConstructPathGlob Construct = "path-glob"
	// ConstructQuerySubstring is the query substring over the bounded
	// scan (the record's adapted construct).
	ConstructQuerySubstring Construct = "query-substring"
	// ConstructConjunction is the conjunction of the class-set constructs.
	ConstructConjunction Construct = "conjunction"
)

// String returns the construct name.
func (c Construct) String() string { return string(c) }

// CELGlobDecomp is the compile-time glob decomposition: the prefix and
// the suffix segments, or the exact literal when the glob carries no
// star. Prefix/Suffix carry no star (the decomposition output; the
// kernel compares bytes).
type CELGlobDecomp struct {
	Prefix string
	Suffix string
	Exact  bool
}

// GlobSegments decomposes a path glob at compile time: zero stars = the
// exact literal; one star = the prefix and the suffix segments (the star
// crosses `/`, the engine's file-glob semantics). More than one star
// rejects: the class set covers the prefix/suffix decomposition only
// (the census record's adapted construct row).
func GlobSegments(glob string) (CELGlobDecomp, error) {
	stars := strings.Count(glob, "*")
	switch stars {
	case 0:
		return CELGlobDecomp{Prefix: glob, Exact: true}, nil
	case 1:
		i := strings.IndexByte(glob, '*')
		return CELGlobDecomp{Prefix: glob[:i], Suffix: glob[i+1:]}, nil
	default:
		return CELGlobDecomp{}, fmt.Errorf("glob carries %d stars; the class set decomposes one star (prefix/suffix) or none (exact)", stars)
	}
}

// FastPathCELRule is one compiled CEL-class row (the bundle's
// fastPath.wire form; the compiled row truth the loader stages into the
// kernel map). The legs carry the decomposed compile-time forms: a row
// never carries a star. A row carries at least one non-empty leg.
type FastPathCELRule struct {
	// ID is the rule id (the rule pack's provenance; the kernel row
	// index rides the row's order).
	ID string `json:"id"`
	// Action is the kernel action code (0 forward+mark, 1 drop).
	Action uint8 `json:"action"`
	// Method is the method-literal bytes (empty = the leg absent).
	Method string `json:"method,omitempty"`
	// PathGlobPrefix is the glob's prefix segment (the exact leg = the
	// full literal with PathExact).
	PathGlobPrefix string `json:"pathGlobPrefix,omitempty"`
	// PathGlobSuffix is the glob's suffix segment (empty = absent).
	PathGlobSuffix string `json:"pathGlobSuffix,omitempty"`
	// PathExact marks a zero-star glob: the path equals the prefix
	// literal exactly.
	PathExact bool `json:"pathExact,omitempty"`
	// QuerySubstring is the query-substring literal (empty = absent).
	QuerySubstring string `json:"querySubstring,omitempty"`
}

// CELSkip is one rule's slow-path route: the rule id and the reason the
// class set rejects it (the compile gate's reject row; the rule stays in
// the rule packs, the engine evaluates it — the kernel carries no row).
type CELSkip struct {
	// RuleID is the routed rule's id.
	RuleID string
	// Reason is the reject row verbatim.
	Reason string
}

// celLegs is one rule's compiled leg set (the walk's output before the
// row render).
type celLegs struct {
	method    string
	pre       string
	suf       string
	exact     bool
	hasGlob   bool
	query     string
	construct []Construct
}

// CensusConstructs walks a rule's parsed CEL AST and names one construct
// class per class-set node; a node outside the set rejects with the
// construct named (the compile gate's reject). The class is syntactic:
// the parse walks the AST the same parser the engine compiles with; the
// value gate (the bounds, the vacuous literals) rides the row compile.
func CensusConstructs(expr string) ([]Construct, error) {
	legs, err := censusWalk(expr)
	if err != nil {
		return nil, err
	}
	return legs.construct, nil
}

// censusWalk parses one expression and returns its compiled leg set: the
// class-set constructs fold into the legs; a construct outside the set
// rejects with the construct named.
func censusWalk(expr string) (*celLegs, error) {
	env, err := gocel.NewEnv()
	if err != nil {
		return nil, fmt.Errorf("census: env: %w", err)
	}
	parsed, iss := env.Parse(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("census: %w", iss.Err())
	}
	legs := &celLegs{}
	if err := walkLegs(parsed.NativeRep().Expr(), legs); err != nil {
		return nil, err
	}
	return legs, nil
}

// walkLegs walks one AST node. Conjunctions recurse into the args and
// merge; an atom must be exactly one class-set construct. Two atoms of
// the same kind reject (one row carries one leg per kind).
func walkLegs(e celast.Expr, legs *celLegs) error {
	switch e.Kind() {
	case celast.CallKind:
		c := e.AsCall()
		switch c.FunctionName() {
		case "_&&_":
			legs.construct = append(legs.construct, ConstructConjunction)
			for _, a := range c.Args() {
				if err := walkLegs(a, legs); err != nil {
					return err
				}
			}
			return nil
		case "_==_":
			return walkMethodCompare(c.Args(), legs)
		case "matches":
			if !c.IsMemberFunction() {
				return fmt.Errorf("census: the top-level matches call sits outside the class set")
			}
			return matchesGlob(c.Target(), c.Args(), legs)
		case "contains":
			if !c.IsMemberFunction() {
				return fmt.Errorf("census: the top-level contains call sits outside the class set")
			}
			return queryContains(c.Target(), c.Args(), legs)
		default:
			return fmt.Errorf("census: call %q sits outside the class set", c.FunctionName())
		}
	case celast.LiteralKind, celast.IdentKind, celast.SelectKind:
		return fmt.Errorf("census: a bare %v node carries no class-set construct", e.Kind())
	default:
		return fmt.Errorf("census: an unexpected AST node kind %v sits outside the class set", e.Kind())
	}
}

// walkMethodCompare reads the method-equality compare: one arg is
// request.method, the other a string literal; either arg order reads.
func walkMethodCompare(args []celast.Expr, legs *celLegs) error {
	if legs.method != "" {
		return fmt.Errorf("census: the rule carries two method compares; one row carries one compare leg")
	}
	var lit string
	found := 0
	for _, a := range args {
		if a.Kind() == celast.LiteralKind {
			s, ok := literalString(a)
			if !ok {
				return fmt.Errorf("census: a non-string literal in the method compare sits outside the class set")
			}
			lit = s
			found++
			continue
		}
		if isRequestMethodSelect(a) {
			found++
		}
	}
	if found != 2 {
		return fmt.Errorf("census: the compare carries no request.method select or no string literal; outside the class set")
	}
	legs.method = lit
	legs.construct = append(legs.construct, ConstructCompareMethod)
	return nil
}

// matchesGlob reads the path-glob construct: the target covers the path
// shorthand (an ident `path`) or the explicit request.path select; the
// argument is the glob string literal, decomposed at compile time.
func matchesGlob(target celast.Expr, args []celast.Expr, legs *celLegs) error {
	if legs.hasGlob {
		return fmt.Errorf("census: the rule carries two path globs; one row carries one glob leg")
	}
	if !isPathTarget(target) {
		return fmt.Errorf("census: the matches target reads no request path; outside the class set")
	}
	if len(args) != 1 || args[0].Kind() != celast.LiteralKind {
		return fmt.Errorf("census: the glob argument is not a string literal; outside the class set")
	}
	glob, ok := literalString(args[0])
	if !ok {
		return fmt.Errorf("census: the glob argument is not a string literal; outside the class set")
	}
	seg, err := GlobSegments(glob)
	if err != nil {
		return fmt.Errorf("census: the glob %q: %w", glob, err)
	}
	legs.hasGlob = true
	legs.pre = seg.Prefix
	legs.suf = seg.Suffix
	legs.exact = seg.Exact
	legs.construct = append(legs.construct, ConstructPathGlob)
	return nil
}

// queryContains reads the query-substring construct: the target is the
// request.query select; the argument is the substring string literal.
func queryContains(target celast.Expr, args []celast.Expr, legs *celLegs) error {
	if legs.query != "" {
		return fmt.Errorf("census: the rule carries two query substrings; one row carries one substring leg")
	}
	if !isRequestQuerySelect(target) {
		return fmt.Errorf("census: the contains target reads no request query; outside the class set")
	}
	if len(args) != 1 || args[0].Kind() != celast.LiteralKind {
		return fmt.Errorf("census: the substring argument is not a string literal; outside the class set")
	}
	sub, ok := literalString(args[0])
	if !ok {
		return fmt.Errorf("census: the substring argument is not a string literal; outside the class set")
	}
	legs.query = sub
	legs.construct = append(legs.construct, ConstructQuerySubstring)
	return nil
}

// literalString reads a literal node's Go string.
func literalString(e celast.Expr) (string, bool) {
	v, ok := e.AsLiteral().(ref.Val)
	if !ok {
		return "", false
	}
	s, ok := v.Value().(string)
	return s, ok
}

// isRequestMethodSelect reads request.method (one select over the
// request ident).
func isRequestMethodSelect(e celast.Expr) bool {
	if e.Kind() != celast.SelectKind {
		return false
	}
	s := e.AsSelect()
	if s.FieldName() != "method" {
		return false
	}
	return s.Operand().Kind() == celast.IdentKind && s.Operand().AsIdent() == "request"
}

// isRequestQuerySelect reads request.query.
func isRequestQuerySelect(e celast.Expr) bool {
	if e.Kind() != celast.SelectKind {
		return false
	}
	s := e.AsSelect()
	return s.FieldName() == "query" && s.Operand().Kind() == celast.IdentKind && s.Operand().AsIdent() == "request"
}

// isPathTarget covers both path bindings the env declares: the `path`
// ident shorthand and the request.path select.
func isPathTarget(e celast.Expr) bool {
	if e.Kind() == celast.IdentKind {
		return e.AsIdent() == "path"
	}
	if e.Kind() != celast.SelectKind {
		return false
	}
	return e.AsSelect().FieldName() == "path" && isRequestIdent(e.AsSelect().Operand())
}

// isRequestIdent reads the request top-level ident.
func isRequestIdent(e celast.Expr) bool {
	return e.Kind() == celast.IdentKind && e.AsIdent() == "request"
}

// CompileCELFastPathRows compiles rule-pack rules into the compiled
// CEL-class rows, in rule order. A rule outside the class set routes the
// slow path: the skip carries the rule id and the reject reason; the row
// list carries none of it. The leg bounds (method, glob, substring) and
// the empty literals route T2 the same way; the row bound fails the
// compile closed (the template envelope; the route class's posture); a
// row with no leg after the value gate fails closed (the compiled row
// would match every request; never stage that shape).
func CompileCELFastPathRows(rules []cel.Rule) ([]FastPathCELRule, []CELSkip, error) {
	rows := make([]FastPathCELRule, 0, len(rules))
	var skips []CELSkip
	for _, r := range rules {
		legs, err := censusWalk(r.Expression)
		if err != nil {
			skips = append(skips, CELSkip{RuleID: r.ID, Reason: err.Error()})
			continue
		}
		row := FastPathCELRule{ID: r.ID}
		row.Action = actionCode(r.Action)
		// The value gate: an empty or oversized literal routes T2 (the
		// class-set boundary; the rule stays an engine rule).
		if legs.method != "" {
			if !printable(legs.method) {
				skips = append(skips, CELSkip{RuleID: r.ID, Reason: "the method literal carries a non-printable byte"})
				continue
			}
			if len(legs.method) > FastPathCELMethodMaxBytes {
				skips = append(skips, CELSkip{RuleID: r.ID, Reason: fmt.Sprintf("the method literal carries %d bytes; the row bound is %d", len(legs.method), FastPathCELMethodMaxBytes)})
				continue
			}
			row.Method = legs.method
		}
		if legs.hasGlob {
			for _, seg := range []string{legs.pre, legs.suf} {
				if seg != "" && !printable(seg) {
					skips = append(skips, CELSkip{RuleID: r.ID, Reason: "the path glob carries a non-printable byte"})
					continue
				}
			}
			if len(legs.pre) > FastPathCELGlobPrefixMaxBytes || len(legs.suf) > FastPathCELGlobSuffixMaxBytes {
				skips = append(skips, CELSkip{RuleID: r.ID, Reason: fmt.Sprintf("the glob segments carry %d+%d bytes; the row bounds are %d+%d", len(legs.pre), len(legs.suf), FastPathCELGlobPrefixMaxBytes, FastPathCELGlobSuffixMaxBytes)})
				continue
			}
			if legs.suf != "" {
				// The envelope gate (the load receipt; the record's
				// section 12): the suffix pass composites with the glob
				// pass and the third body pushes the walk over the
				// 1M-verifier bound. The rule routes the engine tier.
				skips = append(skips, CELSkip{RuleID: r.ID, Reason: "the glob-suffix leg composites over the walk's 1M verifier envelope; the rule routes the engine tier"})
				continue
			}
			row.PathGlobPrefix = legs.pre
			row.PathGlobSuffix = legs.suf
			row.PathExact = legs.exact
		}
		if legs.query != "" {
			// The envelope gate (the load receipt; the record's
			// section 12): the query pass composites with a second pass
			// (the glob body; the method+suffix compose) and busts the
			// 1M-verifier bound at any row count. The rule routes the
			// engine tier.
			skips = append(skips, CELSkip{RuleID: r.ID, Reason: "the query-substring leg composites with any second pass over the walk's 1M verifier envelope; the rule routes the engine tier"})
			continue
		}

		if row.Method == "" && row.PathGlobPrefix == "" && row.PathGlobSuffix == "" && row.QuerySubstring == "" {
			return nil, nil, fmt.Errorf("compile: rule %s carries no non-vacuous leg; the compiled row would match every request", r.ID)
		}
		if len(rows) >= FastPathCELEnvelopeRows {
			// The envelope gate (the load receipt; the record's
			// section 12): the walk proves one staged row; a second
			// row composites the passes over the 1M-verifier bound.
			// The rule routes the engine tier.
			skips = append(skips, CELSkip{RuleID: r.ID, Reason: "the staged-row count sits past the walk's verified envelope; the rule routes the engine tier"})
			continue
		}
		if len(rows) >= FastPathCELMaxRules {
			return nil, nil, fmt.Errorf("compile: %d in-class rules; the row bound is %d (offending rule %s)", len(rows)+1, FastPathCELMaxRules, r.ID)
		}
		rows = append(rows, row)
	}
	return rows, skips, nil
}

// actionCode maps the pack action onto the part-1 kernel action codes:
// enforce and ban stop the request; log and none record.
func actionCode(a cel.Action) uint8 {
	switch a {
	case cel.ActionEnforce, cel.ActionBan:
		return RouteTemplateActionDrop
	default:
		return RouteTemplateActionForward
	}
}

// printable reads every byte in the printable-ASCII band (the same
// discipline the route class's prefix carries).
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ValidateFastPathCELRule gates one wire row (the loader's re-check over
// tamper and corruption: bounds, printable bytes, the leg presence, the
// action vocabulary, the star-free decomposed legs). The row the compile
// emitted and the row on the wire must agree cell by cell.
func ValidateFastPathCELRule(row FastPathCELRule) error {
	if row.ID == "" {
		return fmt.Errorf("fastPath cel row: id is required")
	}
	switch row.Action {
	case RouteTemplateActionForward, RouteTemplateActionDrop:
	default:
		return fmt.Errorf("fastPath cel row %s: action code %d is outside the template vocabulary", row.ID, row.Action)
	}
	for name, s := range map[string]string{
		"method":     row.Method,
		"globPrefix": row.PathGlobPrefix,
		"globSuffix": row.PathGlobSuffix,
		"querySub":   row.QuerySubstring,
	} {
		if !printable(s) {
			return fmt.Errorf("fastPath cel row %s: %s carries a non-printable byte", row.ID, name)
		}
		if strings.Contains(s, "*") {
			return fmt.Errorf("fastPath cel row %s: %s carries a star; the compiled legs carry no star", row.ID, name)
		}
	}
	if l := len(row.Method); l > FastPathCELMethodMaxBytes {
		return fmt.Errorf("fastPath cel row %s: method carries %d bytes; the bound is %d", row.ID, l, FastPathCELMethodMaxBytes)
	}
	if l := len(row.PathGlobPrefix); l > FastPathCELGlobPrefixMaxBytes {
		return fmt.Errorf("fastPath cel row %s: globPrefix carries %d bytes; the bound is %d", row.ID, l, FastPathCELGlobPrefixMaxBytes)
	}
	if l := len(row.PathGlobSuffix); l > FastPathCELGlobSuffixMaxBytes {
		return fmt.Errorf("fastPath cel row %s: globSuffix carries %d bytes; the bound is %d", row.ID, l, FastPathCELGlobSuffixMaxBytes)
	}
	if l := len(row.QuerySubstring); l > FastPathCELQueryMaxBytes {
		return fmt.Errorf("fastPath cel row %s: querySub carries %d bytes; the bound is %d", row.ID, l, FastPathCELQueryMaxBytes)
	}
	if row.PathExact && row.PathGlobPrefix == "" {
		return fmt.Errorf("fastPath cel row %s: pathExact wants a pathGlobPrefix literal", row.ID)
	}
	if row.Method == "" && row.PathGlobPrefix == "" && row.QuerySubstring == "" {
		// A suffix-only glob leg (a leading-star glob) counts: it is a
		// leg on its own. Every other empty shape carries no leg at all.
		if row.PathGlobSuffix == "" {
			return fmt.Errorf("fastPath cel row %s: carries no leg", row.ID)
		}
	}
	return nil
}
