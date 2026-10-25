// Package cel implements the spec's CEL section (the developer-facing DSL): rule packs
// compile to cost-budgeted CEL programs over the spec's structured request
// view and evaluate to log/enforce/none verdicts.
//
// Seed contract (TR-02): exactly one rule, the spec's CEL rate-shape example,
// expression verbatim, action=log. v0 verdicts are log-only — enforcement
// lands with the ScoredWindowBan engine (TR-09/TR-10).
package cel

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// Action is the spec's per-rule action (log|enforce|none today; the full
// ladder vocabulary lands with TR-05's short-circuit ladder).
type Action string

// Action values accepted in rule packs.
const (
	ActionLog     Action = "log"
	ActionEnforce Action = "enforce"
	ActionNone    Action = "none"
	// ActionBan (TR-195/TR-197, the operator's decision): the operator's manual
	// ban surface. A matching ban-rule emits a DIRECT would-ban (reason = the
	// rule id) for the enforcer's kernel write, and the request answers 403
	// with decision `ban`. Every other path keeps ScoredWindowBan's scored
	// crossing; a rule never re-implements the algorithm.
	ActionBan Action = "ban"
)

// Valid reports whether a is one of the accepted action values.
func (a Action) Valid() bool {
	switch a {
	case ActionLog, ActionEnforce, ActionNone, ActionBan:
		return true
	}
	return false
}

// RulePack is the loaded but NOT-yet-compiled pack (load ≠ compile: a
// syntactically valid pack whose expression does not compile loads fine; the
// compile failure surfaces at Eval as an error verdict, TestCompileError).
type RulePack struct {
	Rules []Rule `yaml:"rules" json:"rules"`
	// AuthVerifier is the pack's optional verifier bundle (TR-198): the
	// operator supplies the HS256/RS256 keys, the claims source the S3
	// stage verifies the bearer token against when the gateway's verified
	// identity metadata channel carries no identity. The parse builds the
	// Verifier ONCE (fail closed: an unparsable key fails the pack).
	AuthVerifier *VerifierConfig `yaml:"verifier,omitempty" json:"verifier,omitempty"`

	// verifier is the AuthVerifier's parsed form (not serialized: the
	// bundle re-parses at load).
	verifier *Verifier
}

// Verifier returns the pack's parsed verifier bundle (nil = none).
func (p *RulePack) Verifier() *Verifier {
	if p == nil {
		return nil
	}
	return p.verifier
}

// LoadRulePack reads a rule-pack YAML file from disk.
func LoadRulePack(path string) (*RulePack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load rule pack: %w", err)
	}
	return ParseRulePack(data)
}

// ParseRulePack decodes rule-pack YAML bytes and validates the envelope
// (rules present, ids set, known actions, non-empty expressions).
// Expression compilation is deferred to Rule.Eval.
func ParseRulePack(data []byte) (*RulePack, error) {
	var pack RulePack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("parse rule pack: %w", err)
	}
	if len(pack.Rules) == 0 {
		return nil, errors.New("parse rule pack: empty rules list")
	}
	for i := range pack.Rules {
		r := &pack.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("rule[%d]: id is required", i)
		}
		if r.Action == "" {
			r.Action = ActionLog
		}
		if !r.Action.Valid() {
			return nil, fmt.Errorf("rule %q: unknown action %q", r.ID, r.Action)
		}
		if strings.TrimSpace(r.Expression) == "" {
			return nil, fmt.Errorf("rule %q: expression is required", r.ID)
		}
	}
	if pack.AuthVerifier != nil {
		v, err := NewVerifier(*pack.AuthVerifier)
		if err != nil {
			return nil, fmt.Errorf("parse rule pack: %w", err)
		}
		pack.verifier = v
	}
	return &pack, nil
}
