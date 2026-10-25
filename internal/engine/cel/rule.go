package cel

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/env"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
)

// Request is the spec's structured request view, seed scope: the view grows
// field-by-field as the rules that need it land (no speculative fields).
// JSON tags rule the decode: sigs.k8s.io/yaml converts YAML→JSON and decodes
// via encoding/json — json-name matching is case-insensitive but NOT
// underscore-tolerant, so multi-word fields must carry explicit tags.
type Request struct {
	Method      string                `yaml:"method" json:"method"`
	Path        string                `yaml:"path" json:"path"`
	Query       string                `yaml:"query" json:"query"`
	RateWindows map[string]RateWindow `yaml:"rate_windows" json:"rate_windows"`
	// Auth is the request.auth vocabulary (TR-198, issue #240): the
	// claims-policy view the S3 stage resolves from the precondition
	// channel (the gateway's verified identity metadata) or the optional
	// in-engine verifier bundle. The zero value reads verified=false —
	// the record's gate holds on every wiring miss.
	Auth Auth `yaml:"auth" json:"auth"`
}

// RateWindow is one precomputed rate-accounting window value
// (the spec's request.rate_windows; keyed by window size, e.g. "5m").
// The cel tag exposes the spec's field name (requests, lowercase) through the
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

// evalBudget is the default per-evaluation cost budget (the spec's CEL DSL: cost-budgeted
// from day one). The seed rule's expression is well inside it.
const evalBudget uint64 = 100_000

// Clock supplies the engine's epoch (seconds) the CEL binding "now" carries.
// The default = the wall clock; the wiring may pin it (tests, replay).
// NIL = the binding stays unset and a rule reading `now` eval-errors —
// the record's rule: CEL never reads a clock, the engine supplies the
// epoch; a stage without the supply serves no time comparison (the
// fail-safe, not a silent 0).
type Clock func() int64

// DefaultClock is the wall-epoch clock the auth-stage wiring installs.
func DefaultClock() Clock { return nowEpoch }

// Rule is one declarative CEL entry: pack metadata plus a compile-once,
// eval-many program under a per-evaluation cost budget (the spec's CEL requirements, H-1).
// CostBudget rides the pack's wire (TR-17: a rule authored in an applied
// pack declares its own ceiling and the pack digest covers it; 0 = unset =
// the policy's budget or the package default) and SetCostBudget is the
// programmatic set on the same field. Not goroutine-safe: TR-04 ingest
// owns the concurrency decision.
type Rule struct {
	ID          string `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Action      Action `yaml:"action" json:"action"`
	// Expression is the CEL source; compiled lazily on first Eval.
	Expression string `yaml:"expression" json:"expression"`
	// CostBudget is the per-evaluation cost budget on this rule: declared
	// by the pack's own wire (TR-17) or set programmatically
	// (SetCostBudget). 0 = unset — the policy's celBudget or the package
	// default (evalBudget) applies.
	CostBudget uint64 `yaml:"costBudget,omitempty" json:"costBudget,omitempty"`

	// compiled state (not serialized). Compile is once per expression;
	// the cost budget is a program option, so a budget change re-plans
	// (never re-compiles: SetCostBudget resets the program and the next
	// Eval plans under the new budget).
	env *cel.Env
	ast *cel.Ast
	prg cel.Program

	// clock is the engine-supplied epoch the "now" binding reads (the
	// expiry comparison's engine half; nil = no "now" binding).
	clock Clock
}

// SetClock pins the engine-supplied epoch the rule's eval binds to "now"
// (the record's expiry rule: rules compare request.auth.expiry_epoch
// against the engine-supplied epoch; CEL never reads a clock). The bind
// resets the planned program; the next Eval re-plans.
func (r *Rule) SetClock(c Clock) {
	r.clock = c
	r.prg = nil
}

// SetCostBudget sets the per-evaluation cost budget. H-1: the budget is
// enforced by the environment during evaluation (cel.CostLimit): an
// over-budget eval aborts mid-flight with an error — it never returns a
// silent match=false.
func (r *Rule) SetCostBudget(n uint64) error {
	if n == 0 {
		return errors.New("cost budget must be > 0")
	}
	r.CostBudget = n
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

// activation builds the eval-time bindings. Top-level `path` is the spec's
// shorthand for request.path (the spec's own example uses it verbatim).
// request.auth is the claims vocabulary (TR-198): the engine-sanitised view
// (empty containers, never nil) so every read over the miss stays clean.
// The engine-supplied epoch rides `now` only when a clock is pinned (the
// record's expiry rule); without the pin a time rule stops at an eval
// error — the fail-safe, never a fabricated 0.  request.auth is kept
// sanitised so the reads never dereference nil containers.
func (r *Rule) activation(req Request) map[string]any {
	reqView := map[string]any{
		"method":       req.Method,
		"path":         req.Path,
		"query":        req.Query,
		"rate_windows": req.RateWindows,
		"auth":         req.Auth.Sanitised(),
	}
	activation := map[string]any{
		"request": reqView,
		"path":    req.Path,
	}
	if r.clock != nil {
		activation["now"] = r.clock()
	}
	return activation
}

// programForEval compiles once and plans once per budget: the budget is a
// program option, so the plan carries the resolved ceiling (CostBudget,
// else evalBudget) exactly once; SetCostBudget resets the program and the
// next Eval re-plans under the new value.
func (r *Rule) programForEval() (cel.Program, error) {
	budget := r.CostBudget
	if budget == 0 {
		budget = evalBudget
	}
	if r.env == nil {
		if err := r.compile(); err != nil {
			return nil, err
		}
	}
	if r.prg == nil {
		p, err := r.env.Program(r.ast, cel.CostLimit(budget))
		if err != nil {
			return nil, fmt.Errorf("plan program (budget %d): %w", budget, err)
		}
		r.prg = p
	}
	return r.prg, nil
}

// compile builds the environment and the checked AST exactly once.
func (r *Rule) compile() error {
	if strings.TrimSpace(r.Expression) == "" {
		return errors.New("rule has no expression")
	}
	env, err := cel.NewCustomEnv(
		// Seed view (the spec's CEL section): request.method / request.path strings and
		// request.rate_windows keyed by window size. Map values stay dyn at
		// check time; selector/index mistakes surface as eval errors.
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		// The spec's shorthand: path == request.path.
		cel.Variable("path", cel.StringType),
		// The engine-supplied epoch (TR-198's expiry rule): the binding the
		// wiring pins; a stage without the pin serves no time rule.
		cel.Variable("now", cel.IntType),
		// Drop the stdlib RE2 `matches` family entirely (global + member
		// overloads): the seed's glob semantics must not collide with it,
		// and the spec's kernel rate-accounting section later gates any RE2 surface behind an input-length
		// budget under a distinct name.
		cel.StdLib(cel.StdLibSubset(withoutRE2Matches())),
		// path.matches(glob): the spec's example syntax with FILE-GLOB semantics
		// (* crosses "/"): "/v1/chat/*" matches /v1/chat/a/b but not
		// /v1/chat or /v1/chatabc. Declared here because stdlib RE2
		// matches is excluded above; seed decision recorded for the
		// The spec's DSL pin.
		matchesGlobOption(),
		// Register the native RateWindow type (cel: struct tag → the spec's
		// lowercase field name) so check+eval resolve
		// request.rate_windows[..].requests via reflection on the Go
		// struct rather than proto descriptors.
		ext.NativeTypes(ext.ParseStructTag("cel"), reflect.TypeOf(RateWindow{})),
		// TR-198: the request.auth vocabulary rides the same native-type
		// registration: verified/subject/issuer/audiences/scopes/
		// expiry_epoch/claims resolve via the struct's cel tags.
		ext.NativeTypes(ext.ParseStructTag("cel"), reflect.TypeOf(Auth{})),
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
					return types.NewErrFromString("matches: invalid glob: " + err.Error())
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
