// Package cel implements PRD §11.3 (the developer-facing DSL): rule packs
// compile to cost-budgeted CEL programs over the §11.3 structured request
// view and evaluate to log/enforce/none verdicts.
//
// Seed contract (TR-02): exactly one rule, the §11.3 rate-shape example,
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

// Action is the §11.3 per-rule action (log|enforce|none today; the full
// ladder vocabulary lands with TR-05's short-circuit ladder).
type Action string

// Action values accepted in rule packs.
const (
	ActionLog     Action = "log"
	ActionEnforce Action = "enforce"
	ActionNone    Action = "none"
)

// Valid reports whether a is one of the accepted action values.
func (a Action) Valid() bool {
	switch a {
	case ActionLog, ActionEnforce, ActionNone:
		return true
	}
	return false
}

// RulePack is the loaded but NOT-yet-compiled pack (load ≠ compile: a
// syntactically valid pack whose expression does not compile loads fine; the
// compile failure surfaces at Eval as an error verdict, TestCompileError).
type RulePack struct {
	Rules []Rule `yaml:"rules" json:"rules"`
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
	return &pack, nil
}
