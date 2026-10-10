// Package positive implements the §11.5 positive-security stage (ladder
// slot S4, TR-13): validate what a request IS before spending rungs on
// what it DOES — an OpenAPI 3.1 subset loaded once per route, then driven
// per request over the attached §11.3 view.
//
// v0 slice (TR-13a): the GREEN surface is
//   - Schema — the OpenAPI route schema (v0 subset, strict decode),
//   - LoadPolicy — schema + policy load from a document,
//   - RequestEvaluator.Evaluate — the per-request Result fragment
//     (ladder vocabulary; violations → ActionLog + diagnostics),
//   - RuleIDSchemaViolation — the S4 rule id.
//
// Response-side schema (the §11.5 exfiltration guard) is Phase 2 of the
// roadmap (§20.2); headers/query/path parameter validation are named
// v0.1 follow-ups. See README.md for the CRD plan.
package positive

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sigs.k8s.io/yaml"
)

// Schema is one route's request-body schema — the v0 subset of OpenAPI
// 3.1 (§11.5): object/array/string/number with required, enum, maxLength
// and pattern. Everything outside the subset is a LOAD error (strict
// decode + keyword whitelist, TestLoadStrict), so a schema the gate
// cannot fully express fails loudly instead of partially.
type Schema struct {
	typ        string             // object | array | string | number
	required   []string           // object: required member names
	properties map[string]*Schema // object: member schemas
	items      *Schema            // array: element schema
	enum       []string           // string: enum membership
	maxLength  *int               // string: length cap (characters)
	pattern    *regexp.Regexp     // string: match requirement
}

// schemaTypes is the v0 type vocabulary (anything else is a load error —
// boolean nulls and integer discrimination are v0.1 follow-ups).
var schemaTypes = map[string]bool{"object": true, "array": true, "string": true, "number": true}

// allowedSchemaKeys is the keyword whitelist inside a Schema node
// (properties map keys are FIELD names, not keywords — the recursion
// walks values, so field names never hit this whitelist).
var allowedSchemaKeys = map[string]bool{
	"type": true, "required": true, "properties": true,
	"items": true, "enum": true, "maxLength": true, "pattern": true,
}

// keysAllowedByType is the type-scoped whitelist: a keyword valid in the
// subset but meaningless for the declared type still refuses the load
// (strictness rule — half-expressed schemas are the danger).
var keysAllowedByType = map[string]map[string]bool{
	"object": {"type": true, "required": true, "properties": true},
	"array":  {"type": true, "items": true},
	"string": {"type": true, "enum": true, "maxLength": true, "pattern": true},
	"number": {"type": true},
}

// compileSchema builds a Schema from one JSON-decoded OpenAPI schema node
// (json.RawMessage map: the yaml round-trip already converted the doc;
// RawMessage keeps the raw keyword values for exact JSON-side checks).
func compileSchema(raw map[string]json.RawMessage) (*Schema, error) {
	typRaw, ok := raw["type"]
	if !ok {
		return nil, fmt.Errorf(`schema: missing "type" (required in the v0 subset)`)
	}
	var typ string
	if err := json.Unmarshal(typRaw, &typ); err != nil {
		return nil, fmt.Errorf("schema: %q is not a string", "type")
	}
	if !schemaTypes[typ] {
		return nil, fmt.Errorf("schema: type %q is not in the v0 subset (object|array|string|number)", typ)
	}
	for k := range raw {
		if !allowedSchemaKeys[k] {
			return nil, fmt.Errorf("schema: %q is not allowed (v0 subset)", k)
		}
		if !keysAllowedByType[typ][k] {
			return nil, fmt.Errorf("schema: keyword %q does not apply to type %q", k, typ)
		}
	}
	s := &Schema{typ: typ}
	switch typ {
	case "object":
		if err := compileObject(raw, s); err != nil {
			return nil, err
		}
	case "array":
		itemsRaw, ok := raw["items"]
		if !ok {
			return nil, fmt.Errorf("schema: array without %q (required in the v0 subset)", "items")
		}
		items, err := compileSchemaNode(itemsRaw)
		if err != nil {
			return nil, fmt.Errorf("schema.items: %w", err)
		}
		s.items = items
	case "string":
		if err := compileString(raw, s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// compileSchemaNode compiles one raw schema node (object form enforced).
func compileSchemaNode(raw json.RawMessage) (*Schema, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("not a schema object: %w", err)
	}
	return compileSchema(m)
}

// compileObject fills the object constraints (required ⊆ properties —
// an incoherent schema is a load error, never a silent half-gate).
func compileObject(raw map[string]json.RawMessage, s *Schema) error {
	propsRaw, ok := raw["properties"]
	if !ok {
		return fmt.Errorf("schema: object without %q (required in the v0 subset)", "properties")
	}
	var props map[string]json.RawMessage
	if err := json.Unmarshal(propsRaw, &props); err != nil {
		return fmt.Errorf("schema.properties: %w", err)
	}
	if len(props) == 0 {
		return fmt.Errorf("schema.properties: empty (an allowlist of nothing refuses everything; declare the fields)")
	}
	s.properties = make(map[string]*Schema, len(props))
	for name, node := range props {
		ps, err := compileSchemaNode(node)
		if err != nil {
			return fmt.Errorf("schema.properties.%s: %w", name, err)
		}
		s.properties[name] = ps
	}
	if reqRaw, ok := raw["required"]; ok {
		var req []any
		if err := json.Unmarshal(reqRaw, &req); err != nil {
			return fmt.Errorf("schema.required: %w", err)
		}
		if len(req) == 0 {
			return fmt.Errorf("schema.required: empty list (omit the keyword instead)")
		}
		for _, r := range req {
			name, ok := r.(string)
			if !ok || name == "" {
				return fmt.Errorf("schema.required: entries must be non-empty strings")
			}
			if _, known := s.properties[name]; !known {
				return fmt.Errorf("schema.required: field %q has no properties entry", name)
			}
			s.required = append(s.required, name)
		}
	}
	return nil
}

// compileString fills the string constraints (enum membership, maxLength,
// pattern — the v0 string vocabulary).
func compileString(raw map[string]json.RawMessage, s *Schema) error {
	if enumRaw, ok := raw["enum"]; ok {
		var vals []any
		if err := json.Unmarshal(enumRaw, &vals); err != nil {
			return fmt.Errorf("schema.enum: %w", err)
		}
		if len(vals) == 0 {
			return fmt.Errorf("schema.enum: empty list (omit the keyword instead)")
		}
		for _, v := range vals {
			str, ok := v.(string)
			if !ok || str == "" {
				return fmt.Errorf("schema.enum: entries must be non-empty strings (v0: string enums only)")
			}
			s.enum = append(s.enum, str)
		}
	}
	if mlRaw, ok := raw["maxLength"]; ok {
		var f float64
		if err := json.Unmarshal(mlRaw, &f); err != nil {
			return fmt.Errorf("schema.maxLength: %w", err)
		}
		if f < 1 || f != float64(int(f)) {
			return fmt.Errorf("schema.maxLength: %v is not a positive integer", f)
		}
		n := int(f)
		s.maxLength = &n
	}
	if patRaw, ok := raw["pattern"]; ok {
		var p string
		if err := json.Unmarshal(patRaw, &p); err != nil {
			return fmt.Errorf("schema.pattern: %w", err)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("schema.pattern: %w", err)
		}
		s.pattern = re
	}
	return nil
}

// loadSchemaYAML is the single strict-decode entry (sigs.k8s.io/yaml
// converts YAML→JSON, then decodes by json tag with unknown-field
// rejection — the repo's fixture-decode convention).
func loadSchemaYAML(data []byte, out any) error {
	return yaml.UnmarshalStrict(data, out, yaml.DisallowUnknownFields)
}
