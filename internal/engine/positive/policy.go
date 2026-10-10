package positive

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// DefaultSchema is the fail-open default action when no schema matches a
// route (v0: pass through; enforcement flips per policy in v1).
const DefaultSchema = ladder.ActionAllow

// RuleIDSchemaViolation names the S4 diagnostic rule in fragments and
// walk verdicts (ladder RuleID convention: "surface:what").
const RuleIDSchemaViolation = ladder.RuleID("positive:violation")

// routeSpec is one OpenAPI path-item entry as the v0 subset accepts it
// (method → operation, each with at most one JSON request body schema).
type routeSpec struct {
	operationID string
	schema      *Schema
}

// Policy maps route patterns to route schemas and carries the default
// action for unmatched routes (§11.5: unmatched path → policy action).
// Match is exact in v0 (the §11.5 route-prefix binding lands with the
// APISpec CRD); this is also the in-memory shape the CRD will wrap.
type Policy struct {
	routes  map[string]routeSpec // exact path → schema (v0 match)
	Default ladder.Action        // action when no schema matches
}

// openAPIDoc is the v0-subset document envelope (strict decode: unknown
// DOC-level keys are load errors too).
type openAPIDoc struct {
	OpenAPI string                 `json:"openapi"`
	Info    openAPIInfo            `json:"info"`
	Paths   map[string]openAPIPath `json:"paths"`
}

// openAPIInfo is the required info block (title+version only).
type openAPIInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

// openAPIPath is one path-item: the v0 subset accepts only `post`.
type openAPIPath struct {
	Post *openAPIOperation `json:"post"`
}

// openAPIOperation is one operation object: requestBody → content →
// application/json → schema.
type openAPIOperation struct {
	OperationID string              `json:"operationId"`
	RequestBody *openAPIRequestBody `json:"requestBody"`
}

// openAPIRequestBody carries required plus the content map.
type openAPIRequestBody struct {
	Required bool                       `json:"required"`
	Content  map[string]json.RawMessage `json:"content"`
}

// LoadPolicy loads one policy from an OpenAPI 3.1 document file: strict
// decode, subset-checked compile, exactly-one-route enforcement (the
// v0 demo scope — a second route is an operator surprise to reject, not
// to silently widen into).
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	return parsePolicy(data)
}

// parsePolicy compiles a policy from document bytes (LoadPolicy's body;
// split for testability).
func parsePolicy(data []byte) (*Policy, error) {
	var doc openAPIDoc
	if err := loadSchemaYAML(data, &doc); err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	if doc.OpenAPI != "3.1.0" {
		return nil, fmt.Errorf("load policy: openapi %q is not \"3.1.0\" (v0 subset)", doc.OpenAPI)
	}
	if doc.Info.Title == "" || doc.Info.Version == "" {
		return nil, fmt.Errorf("load policy: info.title and info.version are required")
	}
	if len(doc.Paths) != 1 {
		return nil, fmt.Errorf("load policy: exactly one route is in the v0 scope, got %d paths", len(doc.Paths))
	}
	p := &Policy{routes: make(map[string]routeSpec, 1), Default: DefaultSchema}
	for path, item := range doc.Paths {
		if item.Post == nil {
			return nil, fmt.Errorf("load policy: path %q carries no post operation (v0 subset)", path)
		}
		op := item.Post
		if op.RequestBody == nil {
			return nil, fmt.Errorf("load policy: path %q post has no requestBody (v0 validates the body)", path)
		}
		raw, ok := op.RequestBody.Content["application/json"]
		if !ok {
			return nil, fmt.Errorf(`load policy: path %q post requestBody has no "application/json" content (v0 subset)`, path)
		}
		var media struct {
			Schema json.RawMessage `json:"schema"`
		}
		if err := json.Unmarshal(raw, &media); err != nil {
			return nil, fmt.Errorf("load policy: path %q content: %w", path, err)
		}
		if len(media.Schema) == 0 {
			return nil, fmt.Errorf(`load policy: path %q content carries no "schema"`, path)
		}
		s, err := compileSchemaNode(media.Schema)
		if err != nil {
			return nil, fmt.Errorf("load policy: path %q: %w", path, err)
		}
		if s.typ != "object" {
			return nil, fmt.Errorf("load policy: path %q: request body schema must be an object", path)
		}
		p.routes[path] = routeSpec{operationID: op.OperationID, schema: s}
	}
	return p, nil
}

// match returns the schema for a view's path (nil = no schema matches —
// the policy default applies). V0 match is exact per path.
func (p *Policy) match(path string) *Schema {
	if p == nil {
		return nil
	}
	rs, ok := p.routes[path]
	if !ok {
		return nil
	}
	return rs.schema
}

// errNoView is the nil-view/decode contract (sentinel for callers that
// need errors.Is; the evaluator maps it to "no opinion").
var errNoView = errors.New("positive: no attached view")

// validateBodyError is a hard failure inside the validator itself (the
// body cannot be decoded at all — never a schema verdict, never a pass:
// fail-closed for undecodable input).
type validateBodyError struct {
	err error
}

func (e *validateBodyError) Error() string { return e.err.Error() }
func (e *validateBodyError) Unwrap() error { return e.err }

// isValidateBodyError reports whether err is a validator failure.
func isValidateBodyError(err error) bool {
	var vbe *validateBodyError
	return errors.As(err, &vbe)
}

// splitEnum renders an enum list the way diagnostics name it
// ("[assistant system user]" — space-joined, bracketed).
func splitEnum(vals []string) string {
	return "[" + strings.Join(vals, " ") + "]"
}
