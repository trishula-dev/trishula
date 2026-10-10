package positive

import (
	"encoding/json"
	"fmt"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// Result is the S4 per-request outcome as one ladder fragment: ladder
// vocabulary Action/Rules, the S4 phase, the exhaustive violation list
// on ActionLog (nil = clean), and Decisive from the ladder vocabulary.
type Result struct {
	Action      ladder.Action
	Rules       []ladder.RuleID
	Phase       ladder.Phase
	Diagnostics []Diagnostic
}

// Decisive reports whether the fragment stops the walk (v0: never —
// ActionLog/ActionAllow are non-decisive; enforcement arrives v1).
func (r *Result) Decisive() bool { return r.Action.Decisive() }

// RequestEvaluator drives the policy per request. Check is safe for
// concurrent use when the Policy's read-only maps are (they are: loaded
// once, never mutated after LoadPolicy returns).
//
// The §11.3 view arrives through RequestBodyView — the body-carrying
// view wrapper this slice reads instead of cel.Request (whose body
// fields land with the typed engine plumbing, not this stage).
type RequestEvaluator struct {
	policy *Policy
}

// NewRequestEvaluator builds the S4 stage around a loaded policy.
func NewRequestEvaluator(p *Policy) *RequestEvaluator { return &RequestEvaluator{policy: p} }

// Evaluate produces the S4 fragment for one transaction: nil view → nil
// (no opinion); unmatched route → nil (policy default = pass-through);
// matched route → the schema verdict over the body.
func (e *RequestEvaluator) Evaluate(tx *ingest.TxContext) *Result {
	if e == nil || e.policy == nil || tx == nil {
		return nil
	}
	view, ok := RequestBodyView(tx)
	if !ok {
		return nil // no attached view: no opinion
	}
	schema := e.policy.match(view.Path)
	if schema == nil {
		return nil // fail-open default: no schema → pass-through (v0)
	}
	diags, err := validateBody(schema, view.Body)
	if err != nil {
		if isValidateBodyError(err) {
			// Undecodable body: fail-closed inside the validator —
			// one diagnostic, never a pass.
			return &Result{
				Action:      ladder.ActionLog,
				Rules:       []ladder.RuleID{RuleIDSchemaViolation},
				Phase:       ladder.PhaseRequestBody,
				Diagnostics: []Diagnostic{Diagnostic(fmt.Sprintf("body: %s", err))},
			}
		}
		return nil // defensive: no other error class exists today
	}
	if len(diags) == 0 {
		return &Result{Action: ladder.ActionAllow, Rules: nil, Phase: ladder.PhaseRequestBody}
	}
	return &Result{
		Action:      ladder.ActionLog,
		Rules:       []ladder.RuleID{RuleIDSchemaViolation},
		Phase:       ladder.PhaseRequestBody,
		Diagnostics: diags,
	}
}

// bodyView is the body-carrying §11.3 view this slice evaluates (head
// fields + the raw encoded body; the JSON-tag decode matches the
// AttachView convention — sigs.k8s.io/yaml/json decode rules).
type bodyView struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
}

// bodyViewMetaKey is the tx-Metadata slot THIS slice reads (a distinct
// slot from ladder's request_view_json: the body-carrying view is a
// wider view object; aliasing the key with a different shape would
// corrupt the S0 consumers' decode).
const bodyViewMetaKey = "request_body_view_json"

// AttachRequestBodyView stores a body-carrying §11.3 view on the tx
// (engine plumbing + tests; JSON keeps ingest decoupled from positive,
// mirroring ladder.AttachView).
func AttachRequestBodyView(tx *ingest.TxContext, v *bodyView) error {
	if tx == nil || v == nil {
		return fmt.Errorf("attach body view: nil tx or view")
	}
	if tx.Metadata == nil {
		tx.Metadata = map[string]string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("attach body view: %w", err)
	}
	tx.Metadata[bodyViewMetaKey] = string(b)
	return nil
}

// RequestBodyView reads the attached body-carrying view back
// (ok=false = none attached).
func RequestBodyView(tx *ingest.TxContext) (*bodyView, bool) {
	if tx == nil {
		return nil, false
	}
	raw, ok := tx.Metadata[bodyViewMetaKey]
	if !ok || raw == "" {
		return nil, false
	}
	var v bodyView
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, false
	}
	return &v, true
}
