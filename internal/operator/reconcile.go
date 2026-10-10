package operator

// TR-08c (issue #76, M9) — the reconcile half of the apply→effect round
// trip in-process (the k8s API layer around these calls is the deployed
// operator, a later TR-08 slice; the DX1 lab wires its thin pod's flow
// through the same functions):
//
//	Reconcile(policies, rulePackSource) → per-policy compile Outcomes
//	→ (on success) a Bundle the engine's --bundle leg Loads and consults.
//
// Fail closed (§8, §2.3): a policy whose rule sets do not resolve or whose
// CEL does not compile produces an error outcome and NO bundle — traffic
// keeps its previous shape (the previous bundle, or none). Errors never
// widen enforcement; they only ever shrink it. A nil RulePackSource is
// fine for policies with no custom rule sets (v0 default: the seed pack,
// TR-02); the CEL query field (request.query, §11.3 structured request)
// rides this slice — the lab's SQLi rule keys on it.

import (
	"context"
	"fmt"
	"strings"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
)

// RulePackSource resolves a policy's named rule-set refs to CEL rule packs
// (the rule-pack half of §16.2's RuleSet objects). ns/name are the
// RuleSetRef's namespace and name; ok=false is a MISSING ref — Reconcile
// turns that into a compile failure (fail closed: an unresolved rule set
// must never silently under-enforce), never a resolver transport error
// unless the resolver itself returns one.
type RulePackSource interface {
	RulePack(ctx context.Context, ns, name string) (cel.RulePack, bool, error)
}

// Outcome is one policy's compile result: the compiled Bundle on success
// (nil on failure), the compile error otherwise, and the ref key the
// bundle lands under (`<namespace>/<name>`, same key shape as the seed
// rule's id convention).
type Outcome struct {
	// Key is "<namespace>/<name>" of the reconciled WAFPolicy.
	Key string
	// Bundle is the compiled artifact on success; nil on failure.
	Bundle *Bundle
	// Err is the compile failure on the error path (unresolved ref,
	// uncompilable CEL, unknown actions); nil on success.
	Err error
}

// Reconcile compiles each policy against the rule-pack source. A nil
// source skips custom-pack resolution (policies must then be custom-free:
// a ref with a nil source is a compile failure, no ambiguity). One output
// per input, in order; no policy failure affects the others.
func Reconcile(ctx context.Context, policies []v1alpha1.WAFPolicy, src RulePackSource) []Outcome {
	out := make([]Outcome, len(policies))
	for i := range policies {
		p := &policies[i]
		o := Outcome{Key: p.Namespace + "/" + p.Name}
		b, err := compileResolved(ctx, p, src)
		if err != nil {
			o.Err = err
		} else {
			o.Bundle = &b
		}
		out[i] = o
	}
	return out
}

// compileResolved compiles one policy with the v0 custom-pack resolution:
// each RuleSetRef resolves to a CEL rule pack from the policy's own
// namespace; the seed pack always rides first (TR-08b contract: every
// bundle embeds the default CEL plane).
func compileResolved(ctx context.Context, p *v1alpha1.WAFPolicy, src RulePackSource) (Bundle, error) {
	b, err := Compile(*p)
	if err != nil {
		return Bundle{}, fmt.Errorf("reconcile %s/%s: %w", p.Namespace, p.Name, err)
	}
	if len(p.Spec.RuleSets) == 0 {
		return b, nil
	}
	if src == nil {
		return Bundle{}, fmt.Errorf("reconcile %s/%s: rule set %q has no resolver (nil RulePackSource)", p.Namespace, p.Name, p.Spec.RuleSets[0].Name)
	}
	packs := make([]cel.RulePack, 0, len(p.Spec.RuleSets)+1)
	packs = append(packs, b.RulePacks...)
	for _, rs := range p.Spec.RuleSets {
		pack, ok, err := src.RulePack(ctx, p.Namespace, rs.Name)
		if err != nil {
			return Bundle{}, fmt.Errorf("reconcile %s/%s: rule set %q resolve: %w", p.Namespace, p.Name, rs.Name, err)
		}
		if !ok {
			return Bundle{}, fmt.Errorf("reconcile %s/%s: rule set %q unresolved in namespace %q (no rule-pack source entry)", p.Namespace, p.Name, rs.Name, p.Namespace)
		}
		if err := validatePackRules(pack); err != nil {
			return Bundle{}, fmt.Errorf("reconcile %s/%s: rule set %q: %w", p.Namespace, p.Name, rs.Name, err)
		}
		packs = append(packs, pack)
	}
	b.RulePacks = packs
	digests, err := packDigests(b.RulePacks)
	if err != nil {
		return Bundle{}, fmt.Errorf("reconcile %s/%s: %w", p.Namespace, p.Name, err)
	}
	// Rule provenance rides the bundle's own record today (ids are in the
	// packs); the reconcile log line names the pack ids it compiled.
	b.RulePackDigests = digests
	return b, nil
}

// validatePackRules gates a resolved pack's actions and compile-checks its
// rules in the engine env (load ≠ compile is Load's gate; this is the
// reconcile-side gate so an uncompilable rule never reaches a Bundle —
// the M9 failure path shows NO bundle for the broken policy, not a bundle
// that fails at the engine's Load).
//
// Note: Compile's digest record happens before custom packs append (the
// seed-only path recomputes nothing); the appended path above re-digests
// the full pack list.
func validatePackRules(pack cel.RulePack) error {
	for i := range pack.Rules {
		r := &pack.Rules[i]
		if !r.Action.Valid() {
			return fmt.Errorf("rule %s: unknown action %q", r.ID, r.Action)
		}
		if _, err := r.Eval(cel.Request{}); err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
	}
	return nil
}

// Decision is the decisive outcome of one request through a loaded
// bundle: which rule matched (provenance, §16.2 status surface) and which
// action applies (the rule's, else the policy's defaultAction when no
// rule fires). Error verdicts never decide a match — fail safe (§11.3):
// a rule that cannot evaluate reports its error and the ladder's
// fail-closed default (DefaultActionBlock) protects the route.
func (e *Eval) Decide(req cel.Request) (Decision, error) {
	d := Decision{DefaultAction: e.policy.DefaultAction}
	for i := range e.rulePacks {
		rules := e.rulePacks[i].Rules
		for j := range rules {
			v, err := rules[j].Eval(req)
			if err != nil {
				if d.FailedRule == "" {
					d.FailedRule = rules[j].ID
					d.Detail = err.Error()
				}
				continue
			}
			if v.Match {
				d.Match = true
				d.RuleID = rules[j].ID
				d.RuleName = rules[j].Name
				d.RuleAction = string(rules[j].Action)
				if rules[j].Action == cel.ActionEnforce {
					d.Action = v1alpha1.DefaultActionBlock // an enforced match stops the request
				}
				return d, nil
			}
		}
	}
	d.Action = e.policy.DefaultAction
	return d, nil
}

// Decision is the per-request outcome (the verdict plumbing Compile's
// package comment defers to TR-08c): provenance (which rule) + the action
// the enforcement stage applies. A clean no-match carries the policy's
// defaultAction with no provenance.
type Decision struct {
	// Match is true when a rule fired (provenance below).
	Match bool
	// RuleID/RuleName identify the matched rule (empty on no-match).
	RuleID   string
	RuleName string
	// RuleAction is the matched rule's own action log/enforce/none.
	RuleAction string
	// Action is the decisive action for the request: the rule's (enforce →
	// block today), or the policy's defaultAction on no-match.
	Action v1alpha1.DefaultAction
	// DefaultAction is the policy's defaultAction (echoed for the log line
	// when no rule matched).
	DefaultAction v1alpha1.DefaultAction
	// FailedRule names the first rule whose evaluation errored (fail-safe
	// bookkeeping, never a match). Eval errors with an enforced rule's
	// provenance never surface — fail closed at the decision: with any
	// rule error, the decision is the fail-closed default.
	FailedRule string
	// Detail is the eval-failure detail for the operator log.
	Detail string
}

// EvalRulePacks reports the loaded bundle's rule packs (the count is the
// engine log's consult-activation evidence; the packs themselves stay
// internal). Nil-safe: a zero count means no packs loaded.
func (e *Eval) EvalRulePacks() []cel.RulePack {
	if e == nil {
		return nil
	}
	return e.rulePacks
}

// compile-time guard: strings stays for future decision log formatting.
var _ = strings.TrimSpace
