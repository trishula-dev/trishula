package positive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// Diagnostic is one schema violation, worded to name the exact field
// path (the acceptance contract: "body.messages[2].role: …").
type Diagnostic string

// validateBody checks one encoded JSON body against the schema and
// returns EVERY violation (diagnostics must be exhaustive — a developer
// fixes their client in one round-trip, not N). A body that cannot be
// decoded at all is a validateBodyError (fail-closed), never a pass.
func validateBody(s *Schema, body []byte) ([]Diagnostic, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, &validateBodyError{err: fmt.Errorf("body is not valid JSON: %w", err)}
	}
	var diags []Diagnostic
	walkSchema(s, v, "body", &diags)
	return diags, nil
}

// walkSchema recurses one schema node against one decoded JSON value,
// appending per-field diagnostics with the exact path prefix.
func walkSchema(s *Schema, v any, path string, diags *[]Diagnostic) {
	switch s.typ {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			*diags = append(*diags, Diagnostic(fmt.Sprintf("%s: expected object, got %s", path, jsonKind(v))))
			return
		}
		for _, req := range s.required {
			if _, present := m[req]; !present {
				*diags = append(*diags, Diagnostic(fmt.Sprintf("%s: required field %q missing", path, req)))
			}
		}
		for name, ps := range s.properties {
			mv, present := m[name]
			if !present {
				continue // absence is required's business, above
			}
			walkSchema(ps, mv, path+"."+name, diags)
		}
	case "array":
		arr, ok := v.([]any)
		if !ok {
			*diags = append(*diags, Diagnostic(fmt.Sprintf("%s: expected array, got %s", path, jsonKind(v))))
			return
		}
		for i, iv := range arr {
			walkSchema(s.items, iv, path+"["+strconv.Itoa(i)+"]", diags)
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			*diags = append(*diags, Diagnostic(fmt.Sprintf("%s: expected string, got %s", path, jsonKind(v))))
			return
		}
		if s.maxLength != nil && runeLen(str) > *s.maxLength {
			*diags = append(*diags, Diagnostic(fmt.Sprintf("%s: length %d exceeds maxLength %d", path, runeLen(str), *s.maxLength)))
		}
		if s.pattern != nil && !s.pattern.MatchString(str) {
			*diags = append(*diags, Diagnostic(fmt.Sprintf("%s: value %q does not match pattern", path, str)))
		}
		if len(s.enum) > 0 {
			allowed := false
			for _, e := range s.enum {
				if str == e {
					allowed = true
					break
				}
			}
			if !allowed {
				*diags = append(*diags, Diagnostic(fmt.Sprintf("%s: value %q not in enum %s", path, str, splitEnum(s.enum))))
			}
		}
	case "number":
		if _, ok := v.(json.Number); !ok {
			*diags = append(*diags, Diagnostic(fmt.Sprintf("%s: expected number, got %s", path, jsonKind(v))))
		}
	}
}

// runeLen is the character length (UTF-8 runes are characters here; the
// maxLength contract stays character-based, matching OpenAPI).
func runeLen(s string) int { return len([]rune(s)) }

// jsonKind names a decoded JSON value the way diagnostics word it
// (object/array/string/number/boolean/null).
func jsonKind(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	}
	return "unknown"
}
