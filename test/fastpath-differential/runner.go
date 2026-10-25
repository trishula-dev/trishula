// Package fastpathdifferential (TR-40d) is the shadow differential harness
// for the socket-plane fast path [child of TR-40 #52]: the route-class
// decision stream shadow-runs against the engine verdict stream on one
// committed corpus, and the run reports the match census plus the mismatch
// budget.
//
// Two streams, one gate:
//
//   - fast path: the route template semantics per frame — header checks,
//     the bounded request-line scan, the LPM row match, the action — run
//     through the userspace projection (model.go) everywhere, and through
//     the committed kernel object on the kernel-gated leg (the tagged e2e).
//   - engine: the loaded bundle evaluation — internal/operator
//     Compile/Load/Eval over the corpus view plus the policy default
//     action — the reference the engine (T2) resolves on every forward.
//
// The match criterion: a case reads matched when both streams resolve it,
// when every drop carries compiled drop-row backing, when every miss reads
// forward, and — on the kernel leg — when the kernel return value equals
// the projected decision. Plane-split differences (a compiled drop beside
// a non-decisive engine verdict, or a forward beside a decisive one) are
// reported, never scored: the engine stays the detection authority. The
// budget rows live in budgets.go; the record:
// docs/design/socket-plane/4-compiler-census.md (section 10).
//
// The harness claims no enforcement and records no wall. Host CI runs the
// kernel-free gate; the kernel leg runs as the tagged e2e on a kernel host
// (linux build tag plus the fastpath_diff_e2e job tag plus the root/euid
// skip gate).
package fastpathdifferential

import (
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"

	v1alpha1 "github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	routetemplate "github.com/trishula-dev/trishula/internal/fastpath/routetemplate"
	operator "github.com/trishula-dev/trishula/internal/operator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

//go:embed corpus/*.yaml
var corpusFS embed.FS

// LoadCorpus loads every embedded corpus case (corpus/*.yaml) in name
// order. A case that fails schema validation fails the whole load (a
// malformed corpus case is a harness bug, never a silent skip).
func LoadCorpus() (Corpus, error) {
	entries, err := corpusFS.ReadDir("corpus")
	if err != nil {
		return Corpus{}, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	cases := make([]Case, 0, len(names))
	for _, n := range names {
		b, err := corpusFS.ReadFile("corpus/" + n)
		if err != nil {
			return Corpus{}, err
		}
		var c Case
		if err := yaml.UnmarshalStrict(b, &c); err != nil {
			return Corpus{}, fmt.Errorf("corpus case %s: %w", n, err)
		}
		if c.Name == "" {
			return Corpus{}, fmt.Errorf("corpus case %s: empty name", n)
		}
		if c.Frame.EtherType != "ipv4" && c.Frame.EtherType != "ipv6" {
			return Corpus{}, fmt.Errorf("corpus case %s: frame.ethertype %q (ipv4|ipv6)", c.Name, c.Frame.EtherType)
		}
		if c.Frame.TCPDoff < 1 || c.Frame.TCPDoff > 15 {
			return Corpus{}, fmt.Errorf("corpus case %s: frame.tcpDoff %d out of range", c.Name, c.Frame.TCPDoff)
		}
		if c.Expect.Outcome != OutcomeDrop && c.Expect.Outcome != OutcomeForward {
			return Corpus{}, fmt.Errorf("corpus case %s: expect.outcome %q (drop|forward)", c.Name, c.Expect.Outcome)
		}
		if c.Expect.Marked && c.Expect.RowID < 0 {
			return Corpus{}, fmt.Errorf("corpus case %s: marked case carries rowid %d", c.Name, c.Expect.RowID)
		}
		if c.Skipped && c.Skip == "" {
			return Corpus{}, fmt.Errorf("corpus case %s: a skip must carry its reason", c.Name)
		}
		if len(c.Policy.Routes) > 0 && len(c.Policy.Rules) > 0 {
			return Corpus{}, fmt.Errorf("corpus case %s: routes and rules ride one case (one fast-path class per case)", c.Name)
		}
		for _, r := range c.Policy.Rules {
			if r.ID == "" || strings.TrimSpace(r.Expression) == "" {
				return Corpus{}, fmt.Errorf("corpus case %s: rule needs id and expression", c.Name)
			}
			switch cel.Action(r.Action) {
			case cel.ActionLog, cel.ActionEnforce, cel.ActionNone, cel.ActionBan:
			default:
				return Corpus{}, fmt.Errorf("corpus case %s: rule %q action %q outside the pack vocabulary", c.Name, r.ID, r.Action)
			}
		}
		cases = append(cases, c)
	}
	return Corpus{Cases: cases}, nil
}

// Corpus is the loaded case list (name order).
type Corpus struct {
	Cases []Case `json:"cases"`
}

// The fast-path decision vocabulary (the part-1 action primitives).
const (
	OutcomeDrop    = "drop"
	OutcomeForward = "forward"
)

// The route-decision shape classes the corpus inventory covers. The
// coverage gate counts the materialized cases per class. The cel-* rows
// carry the TR-196 CEL-class shapes: the compare leg, the glob legs, the
// query substring leg, the T2 route (an out-of-class rule carries no
// kernel row) and the extraction-cap fail-open quirk.
var ShapeClasses = []string{
	"drop-row", "forward-row", "miss", "malformed-frame", "size-quirk", "nul-shape",
	"cel-compare-row", "cel-glob-row", "cel-query-row", "cel-t2-route", "cel-cap-quirk",
}

// Case is one corpus entry: the policy fixture, the synthetic frame, the
// engine view, the shape classes and the pinned expectation.
type Case struct {
	Name    string   `json:"name"`
	Surface string   `json:"surface"`
	Skipped bool     `json:"skipped,omitempty"`
	Skip    string   `json:"skip,omitempty"`
	Policy  Policy   `json:"policy"`
	Frame   Frame    `json:"frame"`
	View    View     `json:"view"`
	Classes []string `json:"classes"`
	Expect  Expect   `json:"expect"`
}

// Policy is the corpus policy fixture: the route rows plus the default
// action (the engine's no-match disposition). The TR-196 cases (the CEL
// fast-path class) carry Rules instead of Routes: the two classes never
// ride one case (one fast-path class per case; the loader rejects the
// mixed shape, the corpus schema enforces it).
type Policy struct {
	DefaultAction string     `json:"defaultAction"`
	Routes        []RouteRow `json:"routes"`
	// Rules are the case's own CEL rule pack (the CEL fast-path class,
	// TR-196 issue #238): the compile resolves them into the bundle
	// beside the seed pack. Empty = no case pack.
	Rules []RuleRow `json:"rules,omitempty"`
}

// RuleRow is one spec CEL rule of the case pack (id, action, expression
// verbatim; the parse gate validates the envelope).
type RuleRow struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Expression string `json:"expression"`
}

// RouteRow is one spec.routes[] row (the census `route` class).
type RouteRow struct {
	Prefix string `json:"prefix"`
	Action string `json:"action"`
}

// Frame is the synthetic frame the harness builds: the ethertype, the TCP
// data offset (the malformed class drives it under 5), the request line
// bytes and the 'x' pad that pins the size-word quirks.
type Frame struct {
	EtherType string `json:"ethertype"`
	TCPDoff   int    `json:"tcpDoff"`
	Line      string `json:"line"`
	Pad       int    `json:"pad"`
}

// View is the engine request view (the spec's §11.3 view seed scope).
type View struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query"`
	Rate5M int    `json:"rate5m"`
}

// Expect is the pinned fast-path expectation (outcome, mark, row id).
type Expect struct {
	Outcome string `json:"outcome"`
	Marked  bool   `json:"marked"`
	RowID   int    `json:"rowid,omitempty"`
}

// EngineStream is one case's engine-side surface: the loaded bundle
// evaluation plus the staged template rows (the compiled policy truth).
type EngineStream struct {
	// Eval is the loaded bundle (internal/operator Load).
	Eval *operator.Eval
	// Bundle is the compiled bundle (the split + the kernel leg ride in).
	Bundle *operator.Bundle
	// Rows are the staged route rows (routetemplate.Stage): the compiled
	// row truth the fail-open projection reads.
	Rows []routetemplate.RouteStage
	// CELRows are the compiled CEL-class rows (TR-196): the fast-path
	// tier's compiled row truth from the bundle's fastPath leg. Nil or
	// empty when the bundle carries no CEL-class rule.
	CELRows []fastpath.FastPathCELRule
	// DefaultAction is the policy's no-match disposition.
	DefaultAction string
}

// CompileCase builds the engine stream for one case: the corpus policy →
// internal/operator Compile → Load → routetemplate.Stage. The seed rule
// pack is a corpus invariant (the v0 surface carries exactly one log rule)
// and the loader fails closed without it. A TR-196 case (the CEL class)
// carries its own rule pack: the splice rides the seed (the TR-08b
// contract keeps the seed pack first) and the digests recompute. The CEL
// fast-path rows land with the compile leg; at this state the staged CEL
// truth is nil and the class cases carry pinned deltas (RED on record).
func CompileCase(c Case) (EngineStream, error) {
	spec := v1alpha1.WAFPolicySpec{
		DefaultAction: v1alpha1.DefaultAction(c.Policy.DefaultAction),
		ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shadow: true},
	}
	for _, r := range c.Policy.Routes {
		spec.Routes = append(spec.Routes, v1alpha1.RouteMark{Prefix: r.Prefix, Action: v1alpha1.RouteAction(r.Action)})
	}
	policy := v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: "fastpath-diff"},
		Spec:       spec,
	}
	b, err := operator.Compile(policy)
	if err != nil {
		return EngineStream{}, fmt.Errorf("compile case %s: %w", c.Name, err)
	}
	if len(b.RulePacks) != 1 || len(b.RulePacks[0].Rules) != 1 {
		return EngineStream{}, errors.New("fastpathdifferential: the corpus invariant needs exactly one seed rule")
	}
	if r := b.RulePacks[0].Rules[0]; r.ID != "TR02-001" || r.Action != cel.ActionLog {
		return EngineStream{}, fmt.Errorf("fastpathdifferential: seed rule %q action %q, want TR02-001/log", r.ID, r.Action)
	}
	if len(c.Policy.Rules) > 0 {
		casePack := cel.RulePack{}
		for _, r := range c.Policy.Rules {
			casePack.Rules = append(casePack.Rules, cel.Rule{
				ID:         r.ID,
				Action:     cel.Action(r.Action),
				Expression: r.Expression,
			})
		}
		b.RulePacks = []cel.RulePack{b.RulePacks[0], casePack}
		// The CEL-class leg recomputes (the compile gate runs on the
		// spliced packs; the rows land on the bundle's fastPath leg).
		if err := operator.CompileFastPathCELRows(&b); err != nil {
			return EngineStream{}, fmt.Errorf("cel leg case %s: %w", c.Name, err)
		}
	}
	e, err := operator.Load(b)
	if err != nil {
		return EngineStream{}, fmt.Errorf("load case %s: %w", c.Name, err)
	}
	rows, err := routetemplate.Stage(&b)
	if err != nil {
		if b.FastPath == nil && err == routetemplate.ErrNoKernelLeg {
			// A rules-only case (the CEL class) carries no route leg;
			// the route rows read empty and the CEL rows carry the leg.
			rows = nil
		} else {
			return EngineStream{}, fmt.Errorf("stage case %s: %w", c.Name, err)
		}
	}
	var celRows []fastpath.FastPathCELRule
	if b.FastPath != nil && len(b.FastPath.CELRules) > 0 {
		celRows = b.FastPath.CELRules
	}
	return EngineStream{Eval: e, Bundle: &b, Rows: rows, CELRows: celRows, DefaultAction: c.Policy.DefaultAction}, nil
}

// EngineDecision is the engine verdict stream's resolution for one case.
type EngineDecision struct {
	// Action names the resolved disposition in the ladder vocabulary the
	// corpus streams project onto: allow, log, block.
	Action string
	// Decisive marks a stop-the-walk verdict (block; the seed rule is log
	// at v0 and never decisive).
	Decisive bool
	// Matched marks a rule match (the seed rule resolved, action log).
	Matched bool
}

// Evaluate resolves the engine stream for one view through Decide (the
// engine's decisive-outcome resolver): the matched rule's own action sets
// the disposition (enforce/ban stop the walk; log/none record it), else
// the policy default applies. The seed rule is CompileCase's corpus
// invariant, so a seed match never carries an error at v0; an eval error
// (the fail-closed FailedRule row) resolves as the error verdict (fail
// safe, never a match) and the projection reports the case unresolved.
func (s EngineStream) Evaluate(v View) (EngineDecision, error) {
	d, err := s.Eval.Decide(cel.Request{
		Method: v.Method,
		Path:   v.Path,
		Query:  v.Query,
		RateWindows: map[string]cel.RateWindow{
			"5m": {Requests: int64(v.Rate5M)},
		},
	})
	if err != nil {
		return EngineDecision{Action: "error"}, err
	}
	if d.FailedRule != "" {
		// The fail-closed row: a rule error never decides a match (the
		// spec's CEL DSL); the projection reports the case unresolved.
		return EngineDecision{Action: "error"}, nil
	}
	if d.Match {
		decisive := d.RuleAction == string(cel.ActionEnforce) || d.RuleAction == string(cel.ActionBan)
		action := "log"
		if decisive {
			action = "block"
		}
		return EngineDecision{Action: action, Decisive: decisive, Matched: true}, nil
	}
	switch v1alpha1.DefaultAction(s.DefaultAction) {
	case v1alpha1.DefaultActionBlock, v1alpha1.DefaultActionChallenge:
		return EngineDecision{Action: "block", Decisive: true}, nil
	case v1alpha1.DefaultActionLog:
		return EngineDecision{Action: "log"}, nil
	default:
		return EngineDecision{Action: "allow"}, nil
	}
}

// Projection is one case's shadow run: the fast-path decision, the engine
// decision, the mismatch class and the pinned-delta finding (if any).
type Projection struct {
	// Fast is the userspace decision-stream read for the case frame.
	Fast Decision
	// Engine is the engine verdict stream's read for the case view.
	Engine EngineDecision
	// Class names the mismatch budget class of the pair (or "agreement").
	Class string
	// SplitSub names the plane-split sub-shape when Class is plane-split.
	SplitSub string
	// PinDelta names the pinned-expectation delta verbatim; empty holds.
	PinDelta string
	// ShapeCounts are the case's declared shape classes.
	ShapeCounts []string
}

// ProjectCase runs both streams for one case and classifies the pair.
// The kernel leg never runs here: this projection is the kernel-free
// userspace stream the gate drives on every host. One fast-path class
// rules the case: the CEL class (the compiled rows) when the case
// carries rules, the route class over the LPM rows otherwise.
func ProjectCase(c Case) (Projection, error) {
	stream, err := CompileCase(c)
	if err != nil {
		return Projection{}, err
	}
	frame := BuildFrame(c.Frame)
	fast := TemplateDecision(stream.Rows, frame)
	if len(stream.CELRows) > 0 {
		fast = CELRulesDecision(stream.CELRows, frame)
	}
	engine, err := stream.Evaluate(c.View)
	if err != nil {
		// The error verdict resolves (fail safe); the projection reports
		// the case unresolved against the budget row.
		return Projection{Fast: fast, Engine: engine, Class: "unresolved-engine", ShapeCounts: c.Classes}, nil
	}
	p := Projection{Fast: fast, Engine: engine, ShapeCounts: c.Classes}
	p.Class, p.SplitSub = classify(fast, engine, stream.Rows, stream.CELRows)
	p.PinDelta = pinDelta(c, fast)
	return p, nil
}

// classify names the mismatch budget class of one (fast, engine) pair.
// The classes are exhaustive by construction; "unexplained" stays the
// defensive row for a state the projector does not name (a future decision
// state needs a budget row, never a silent pass). The drop-row backing
// reads the case's own leg: the route rows or the compiled CEL rows (one
// class rides one case; the two legs never stage together).
func classify(fast Decision, engine EngineDecision, rows []routetemplate.RouteStage, celRows []fastpath.FastPathCELRule) (string, string) {
	if fast.Drop {
		// Row truth: a drop is backed only by a staged drop row (the mark
		// names it). Anything else is the fail-open class.
		backed := false
		if fast.Marked {
			if int(fast.RowID) < len(rows) && rows[fast.RowID].Action == fastpath.RouteTemplateActionDrop {
				backed = true
			}
			if int(fast.RowID) < len(celRows) && celRows[fast.RowID].Action == fastpath.RouteTemplateActionDrop {
				backed = true
			}
		}
		if !backed {
			return "failopen-drop", ""
		}
		if engine.Decisive {
			// The engine stops the walk too: co-block agreement.
			return "agreement", "co-block"
		}
		// A compiled drop beside a non-decisive engine verdict: the plane
		// split (the class split, census section 6). Reported, not scored.
		return "plane-split", "drop-vs-nondecisive"
	}
	if engine.Decisive {
		// The engine stops the walk the fast path forwarded: T2 re-entry
		// (part 2, degradation). Reported, not scored.
		return "plane-split", "forward-vs-decisive"
	}
	return "agreement", ""
}

// pinDelta names the corpus expectation delta verbatim (empty holds).
func pinDelta(c Case, fast Decision) string {
	want := c.Expect.Outcome
	got := OutcomeForward
	if fast.Drop {
		got = OutcomeDrop
	}
	if want != got {
		return fmt.Sprintf("outcome %s, want %s", got, want)
	}
	if c.Expect.Marked != fast.Marked {
		return fmt.Sprintf("marked %s, want %s", markedWord(fast.Marked), markedWord(c.Expect.Marked))
	}
	if fast.Marked && fast.RowID != uint32(c.Expect.RowID) {
		return fmt.Sprintf("rowid %d, want %d", fast.RowID, c.Expect.RowID)
	}
	return ""
}

func markedWord(m bool) string {
	if m {
		return "true"
	}
	return "false"
}

// Census is one gate run's counts: the pin parity, the shape inventory and
// the live mismatch budget counts.
type Census struct {
	Cases   int
	Ran     int
	Skipped int
	Pinned  int // the pinned-parity case count (pinned deltas excluded)
	// Deltas carry the case name plus the verbatim pinned delta.
	Deltas []string
	// Shapes counts the materialized shape classes.
	Shapes map[string]int
	// Live carries the live mismatch budget class counts.
	Live map[string]int
	// SplitSubs carries the plane-split sub-shape counts.
	SplitSubs map[string]int
}

// RunCorpus runs every case of the corpus through the kernel-free shadow
// projection. Skips count separately; every other case contributes one
// pair and its shape classes.
func RunCorpus(c Corpus) (Census, error) {
	res := Census{Shapes: map[string]int{}, Live: map[string]int{}, SplitSubs: map[string]int{}}
	res.Cases = len(c.Cases)
	for _, c := range c.Cases {
		if c.Skipped {
			res.Skipped++
			continue
		}
		p, err := ProjectCase(c)
		if err != nil {
			return res, err
		}
		res.Ran++
		res.Live[p.Class]++
		if p.Class == "plane-split" {
			res.SplitSubs[p.SplitSub]++
		}
		for _, s := range p.ShapeCounts {
			res.Shapes[s]++
		}
		if p.PinDelta != "" {
			res.Deltas = append(res.Deltas, fmt.Sprintf("%s: %s", c.Name, p.PinDelta))
			continue
		}
		res.Pinned++
	}
	return res, nil
}
