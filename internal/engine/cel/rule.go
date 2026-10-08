package cel

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/env"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

// Request is the §11.3 structured request view, seed scope: the view grows
// field-by-field as the rules that need it land (no speculative fields).
// JSON tags rule the decode: sigs.k8s.io/yaml converts YAML→JSON and decodes
// via encoding/json — json-name matching is case-insensitive but NOT
// underscore-tolerant, so multi-word fields must carry explicit tags.
type Request struct {
	Method      string                `yaml:"method" json:"method"`
	Path        string                `yaml:"path" json:"path"`
	RateWindows map[string]RateWindow `yaml:"rate_windows" json:"rate_windows"`
}

// RateWindow is one precomputed rate-accounting window value
// (§11.3's request.rate_windows; keyed by window size, e.g. "5m").
// The cel tag exposes the §11.3 field name (requests, lowercase) through the
// native-type registry (ext.NativeTypes with ParseStructTag); the json tag
// keeps the fixture decode aligned with the same name.
type RateWindow struct {
	Requests int64 `yaml:"requests" json:"requests" cel:"requests"`
}

// Verdict is the per-rule outcome. Error verdicts NEVER carry match (fail
// safe): an over-budget or uncompilable rule resolves error, never a silent
// false that could later be mistaken for a clean no-match.
type Verdict struct {
	Match  bool
	Error  bool
	Fatal  bool   // true when the rule cannot evaluate at all (compile failure)
	Cost   uint64 // actual interpreter cost consumed by this eval
	Detail string // failure detail (budget abort, compile failure)
}

// evalBudget is the default per-evaluation cost budget (§11.3: cost-budgeted
// from day one). The seed rule's expression is well inside it.
const evalBudget uint64 = 100_000

// Rule is one declarative CEL entry: pack metadata plus a compile-once,
// eval-many program under a per-evaluation cost budget (§11.3, H-1).
// Not goroutine-safe: TR-04 ingest owns the concurrency decision.
type Rule struct {
	ID          string `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Action      Action `yaml:"action" json:"action"`
	// Expression is the CEL source; compiled lazily on first Eval.
	Expression string `yaml:"expression" json:"expression"`

	// compiled state (not serialized). Compile is once per expression; the
	// cost budget is a program option, so a budget change re-plans (never
	// re-compiles).
	env    *cel.Env
	ast    *cel.Ast
	prg    cel.Program
	budget uint64
}

// SetCostBudget sets the per-evaluation cost budget. H-1: the budget is
// enforced by the environment during evaluation (cel.CostLimit): an
// over-budget eval aborts mid-flight with an error — it never returns a
// silent match=false.
func (r *Rule) SetCostBudget(n uint64) error {
	if n == 0 {
		return errors.New("cost budget must be > 0")
	}
	r.budget = n
	r.prg = nil // re-planned on next Eval
	return nil
}

// Eval compiles (once) and evaluates the rule against req. The returned Go
// error mirrors the structured error verdict; a clean no-match is
// (Verdict{Match:false}, nil).
func (r *Rule) Eval(req Request) (Verdict, error) {
	prg, err := r.programForEval()
	if err != nil {
		return Verdict{Error: true, Fatal: true, Detail: err.Error()}, err
	}
	out, details, evalErr := prg.Eval(r.activation(req))
	v := Verdict{}
	if details != nil && details.ActualCost() != nil {
		v.Cost = *details.ActualCost()
	}
	if evalErr != nil {
		// Budget aborts land here ("runtime cost limit exceeded"): fail
		// safe as an error verdict, never a silent match.
		v.Error = true
		v.Detail = evalErr.Error()
		return v, evalErr
	}
	match, ok := asBool(out)
	if !ok {
		err := fmt.Errorf("rule %q: non-bool result %T", r.ID, out)
		return Verdict{Error: true, Detail: err.Error()}, err
	}
	v.Match = match
	return v, nil
}

// activation builds the eval-time bindings. Top-level `path` is the §11.3
// shorthand for request.path (the PRD's own example uses it verbatim).
func (r *Rule) activation(req Request) map[string]any {
	return map[string]any{
		"request": map[string]any{
			"method":       req.Method,
			"path":         req.Path,
			"rate_windows": req.RateWindows,
		},
		"path": req.Path,
	}
}

// programForEval compiles once and plans once per budget.
func (r *Rule) programForEval() (cel.Program, error) {
	budget := r.budget
	if budget == 0 {
		budget = evalBudget
	}
	if r.env == nil {
		if err := r.compile(); err != nil {
			return nil, err
		}
	}
	if r.prg == nil || r.budget != budget {
		p, err := r.env.Program(r.ast, cel.CostLimit(budget))
		if err != nil {
			return nil, fmt.Errorf("plan program (budget %d): %w", budget, err)
		}
		r.prg, r.budget = p, budget
	}
	return r.prg, nil
}

// compile builds the environment and the checked AST exactly once.
func (r *Rule) compile() error {
	if strings.TrimSpace(r.Expression) == "" {
		return errors.New("rule has no expression")
	}
	env, err := cel.NewCustomEnv(
		// Seed view (§11.3): request.method / request.path strings and
		// request.rate_windows keyed by window size. Map values stay dyn at
		// check time; selector/index mistakes surface as eval errors.
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		// §11.3 shorthand: path == request.path.
		cel.Variable("path", cel.StringType),
		// Drop the stdlib RE2 `matches` family entirely (global + member
		// overloads): the seed's glob semantics must not collide with it,
		// and §9.5 later gates any RE2 surface behind an input-length
		// budget under a distinct name.
		cel.StdLib(cel.StdLibSubset(withoutRE2Matches())),
		// path.matches(glob): §11.3 example syntax with FILE-GLOB semantics
		// (* crosses "/"): "/v1/chat/*" matches /v1/chat/a/b but not
		// /v1/chat or /v1/chatabc. Declared here because stdlib RE2
		// matches is excluded above; seed decision recorded for the
		// §11.3 DSL pin.
		matchesGlobOption(),
		// Register the native RateWindow type (cel: struct tag → the §11.3
		// lowercase field name) so check+eval resolve
		// request.rate_windows[..].requests via reflection on the Go
		// struct rather than proto descriptors.
		ext.NativeTypes(ext.ParseStructTag("cel"), reflect.TypeOf(RateWindow{})),
	)
	if err != nil {
		return fmt.Errorf("cel env: %w", err)
	}
	ast, iss := env.Compile(r.Expression)
	if iss.Err() != nil {
		return fmt.Errorf("compile rule %q: %w", r.ID, iss.Err())
	}
	r.env, r.ast = env, ast
	return nil
}

// asBool unwraps a CEL eval result into a bool.
func asBool(out any) (bool, bool) {
	switch v := out.(type) {
	case bool:
		return v, true
	case ref.Val:
		b, ok := v.Value().(bool)
		return b, ok
	}
	return false, false
}

// withoutRE2Matches excludes the stdlib RE2 matches family (global
// "matches" overload + member "matches_string") from the CEL standard
// library so the seed's glob-semantics member overload can own the name.
func withoutRE2Matches() *env.LibrarySubset {
	return &env.LibrarySubset{
		ExcludeFunctions: []*env.Function{
			{Name: "matches"},
		},
	}
}

// matchesGlobOption declares the member function matches(glob) over string
// receivers with file-glob semantics (globToRegexp).
func matchesGlobOption() cel.EnvOption {
	return cel.Function("matches",
		cel.MemberOverload("string_matches_glob",
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.BoolType,
			cel.BinaryBinding(func(subject, pattern ref.Val) ref.Val {
				sub, ok := subject.Value().(string)
				if !ok {
					return types.NewErr("matches: receiver is not a string")
				}
				glob, ok := pattern.Value().(string)
				if !ok {
					return types.NewErr("matches: pattern is not a string")
				}
				re, err := regexp.Compile(globToRegexp(glob))
				if err != nil {
					return types.NewErr("matches: invalid glob: " + err.Error())
				}
				return types.Bool(re.MatchString(sub))
			}),
		),
	)
}

// globToRegexp converts a file-style glob to an anchored RE2 pattern.
// '*' matches any run of characters including '/'; everything else is
// literal. No '**' distinction yet: recorded in the seed spec, revisit when
// a rule needs it.
func globToRegexp(glob string) string {
	var b strings.Builder
	b.WriteString(`^`)
	for _, ch := range glob {
		if ch == '*' {
			b.WriteString(`[\s\S]*`)
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(ch)))
	}
	b.WriteString(`$`)
	return b.String()
}
