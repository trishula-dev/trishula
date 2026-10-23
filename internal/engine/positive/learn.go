package positive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// GREEN (TR-18): learn-mode discovery over observed samples. The walk
// pins: endpoint extraction (the spec's positive-security section), JSON-schema inference with
// per-path cardinality tracking, unrepresentable records for every
// shape the v0 subset cannot describe, and the materialized route
// document the strict v0 loader accepts. The drift read lives in
// drift.go.

// enumInferMax is the distinct-value cap for enum inference: values seen
// under this bound become the learned enum; a wider census stays a plain
// string (a long-tail value census must not become an enforced enum).
const enumInferMax = 8

// docVersion is the OpenAPI version the materialized document declares
// (the same fixed version the v0 loader accepts, TR-13a).
const docVersion = "3.1.0"

// Sample is one observed request feeding discovery (the spec's learn mode):
// the method, the exact path and the raw encoded JSON body — the same
// body-carrying view shape the S4 evaluator reads. The caller owns the
// sampling loop (deps injected: the discoverer consumes data, never a
// socket or a clock).
type Sample struct {
	Method string
	Path   string
	Body   json.RawMessage
}

// SkippedMethod counts the samples discovery recorded but could not
// infer in the v0 subset: any method outside `post` (the spec's v0 subset:
// body-only, post-only, TR-13a).
type SkippedMethod struct {
	Method string
	Path   string
	Count  int
}

// FieldCardinality is the tracked observation statistics for one field
// path (the spec's "JSON-schema inference with cardinality tracking"):
// presence ratio drives required inference, the distinct-value census
// drives enum inference, and the length census drives maxLength.
type FieldCardinality struct {
	Path      string   // schema-position path ("body.messages[].role")
	Present   int      // observations at the path
	Seen      int      // parent instances (objects or array values)
	Kinds     []string // observed value kinds, sorted
	Distinct  int      // distinct string values (census stops above the cap)
	Values    []string // the distinct values, sorted; nil above the cap
	OverCap   bool     // the distinct census exceeds enumInferMax
	MaxLength int      // longest observed string value (runes)
}

// LearnedRoute is one discovered endpoint: the inferred schema, its
// cardinality records and the honest gaps (no object body observed,
// undecodable bodies, unrepresentable field shapes).
type LearnedRoute struct {
	Path            string
	Schema          *Schema            // nil = no decodable object body observed
	Cardinality     []FieldCardinality // sorted by path
	Unrepresentable []string           // field paths outside the v0 subset, sorted
	Samples         int                // post samples for the route
	Undecodable     int                // post samples with a nil body, invalid JSON or a non-object root
}

// LearnedSpec is the learn-mode artifact (the spec's positive-security section): the discovered
// endpoints over the observed window. It is the shape the future APISpec
// CR diff tooling reads; reviewed enforcement still loads through the
// strict v0 loader (TR-13a). Diff application into the APISpec CR is a
// named 2026.01-rc2 follow-up (the CRD does not exist yet).
type LearnedSpec struct {
	Routes  map[string]*LearnedRoute
	Skipped []SkippedMethod // sorted by method, then path
	Samples int             // every sample observed, routed or skipped
}

// Discoverer folds observed samples into per-endpoint cardinality tracks
// and infers the learned spec on read. Not safe for concurrent use
// (single-writer discovery loop; fold per-worker instances in the host).
type Discoverer struct {
	routes  map[string]*routeObs
	skipped map[skippedKey]int
	samples int
}

// skippedKey is the (Method, Path) identity of skipped samples.
type skippedKey struct {
	Method string
	Path   string
}

// routeObs is the accumulator for one observed path: the schema-position
// census plus the unrepresentable records. The root object always sits
// at the "body" site.
type routeObs struct {
	samples     int
	undecodable int
	nodes       map[string]*obsNode
	unrep       map[string]bool
}

// obsNode is the value census at one schema-position site. present
// counts the value observations and seen the parent instances at the
// last walk (the required-inference denominator); object values also
// count objs for their children; the string census feeds the enum
// (values, overCap) and the length census feeds maxLength (maxLen).
type obsNode struct {
	present int
	seen    int
	kinds   map[string]bool
	objs    int
	values  map[string]bool
	overCap bool
	maxLen  int
}

// NewDiscoverer builds an empty discovery accumulator.
func NewDiscoverer() *Discoverer {
	return &Discoverer{
		routes:  map[string]*routeObs{},
		skipped: map[skippedKey]int{},
	}
}

// Observe folds one sample into the tracks: endpoint extraction (exact
// path, per method) plus the per-site value census. Undecodable bodies
// count on the route and never abort the window. The caller-bug refusal
// is an empty path or method.
func (d *Discoverer) Observe(s Sample) error {
	if d == nil {
		return fmt.Errorf("observe: nil discoverer")
	}
	if s.Path == "" {
		return fmt.Errorf("observe: empty path")
	}
	if s.Method == "" {
		return fmt.Errorf("observe: empty method")
	}
	d.samples++
	if s.Method != "POST" {
		d.skipped[skippedKey{s.Method, s.Path}]++
		return nil
	}
	ro := d.route(s.Path)
	ro.samples++
	var v any
	if s.Body != nil {
		dec := json.NewDecoder(bytes.NewReader(s.Body))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			v = nil
		}
	}
	root, ok := v.(map[string]any)
	if !ok {
		ro.undecodable++ // no body, no decode, or a non-object root
		return nil
	}
	rootSite := ro.node("body")
	rootSite.present++
	rootSite.objs++
	rootSite.kinds[jsonKind(root)] = true
	for name := range root {
		observeField(ro, "body", name, root[name])
	}
	return nil
}

// observeField folds one object member: presence on the field node, then
// the value walk under the field path. The parent denominator is the
// object instance count as of this sample (the final walk carries the
// window-final total).
func observeField(ro *routeObs, sitePath, name string, v any) {
	fieldPath := sitePath + "." + name
	n := ro.node(fieldPath)
	n.present++
	n.seen = ro.nodes[sitePath].objs
	observeValue(ro, fieldPath, v)
}

// observeElement folds one array element onto the array's element site
// ("path[]"): element values carry their kinds there, element objects
// count instances for their own fields.
func observeElement(ro *routeObs, fieldPath string, v any) {
	elPath := fieldPath + "[]"
	el := ro.node(elPath)
	el.present++
	el.seen = ro.nodes[fieldPath].present
	observeValue(ro, elPath, v)
}

// observeValue folds one decoded value into the node its path names: the
// kind census, then the string/length and object/array recursions.
func observeValue(ro *routeObs, path string, v any) {
	n := ro.node(path)
	n.kinds[jsonKind(v)] = true
	switch val := v.(type) {
	case string:
		if !n.overCap {
			n.values[val] = true
			if len(n.values) > enumInferMax {
				n.overCap = true // the census exceeds the cap: the field stays a plain string
				n.values = map[string]bool{}
			}
		}
		if l := runeLen(val); l > n.maxLen {
			n.maxLen = l
		}
	case map[string]any:
		n.objs++
		for name := range val {
			observeField(ro, path, name, val[name])
		}
	case []any:
		for _, item := range val {
			observeElement(ro, path, item)
		}
	}
}

// route lazily builds one route accumulator.
func (d *Discoverer) route(path string) *routeObs {
	ro, ok := d.routes[path]
	if !ok {
		ro = &routeObs{nodes: map[string]*obsNode{}, unrep: map[string]bool{}}
		ro.node("body")
		d.routes[path] = ro
	}
	return ro
}

// node lazily builds one schema-position node on the route.
func (ro *routeObs) node(path string) *obsNode {
	n, ok := ro.nodes[path]
	if !ok {
		n = &obsNode{kinds: map[string]bool{}, values: map[string]bool{}}
		ro.nodes[path] = n
	}
	return n
}

// Spec infers the learned spec from the observed window (a pure read:
// the tracks stay intact across calls; the unrepresentable marks are
// deterministic and re-derived).
func (d *Discoverer) Spec() *LearnedSpec {
	spec := &LearnedSpec{Routes: map[string]*LearnedRoute{}, Samples: d.samples}
	spec.Skipped = make([]SkippedMethod, 0, len(d.skipped))
	for k, n := range d.skipped {
		spec.Skipped = append(spec.Skipped, SkippedMethod{Method: k.Method, Path: k.Path, Count: n})
	}
	sortSkipped(spec.Skipped)
	for path, ro := range d.routes {
		lr := &LearnedRoute{Path: path, Samples: ro.samples, Undecodable: ro.undecodable}
		if ro.nodes["body"].objs > 0 {
			lr.Schema = ro.inferObject("body")
		}
		lr.Cardinality = ro.cards()
		for p := range ro.unrep {
			lr.Unrepresentable = append(lr.Unrepresentable, p)
		}
		sort.Strings(lr.Unrepresentable)
		spec.Routes[path] = lr
	}
	return spec
}

// inferObject infers one object site's schema: per-child field
// inference, and required = the fields present in every observed object
// instance. An object whose every field is unrepresentable marks itself
// unrepresentable and produces no schema.
func (ro *routeObs) inferObject(sitePath string) *Schema {
	parent := ro.nodes[sitePath]
	s := &Schema{typ: "object"}
	for _, name := range ro.directFields(sitePath) {
		fieldPath := sitePath + "." + name
		child, ok := ro.inferField(fieldPath)
		if !ok {
			continue // the field already carries its unrepresentable mark
		}
		if s.properties == nil {
			s.properties = map[string]*Schema{}
		}
		s.properties[name] = child
		if ro.nodes[fieldPath].present == parent.objs {
			s.required = append(s.required, name)
		}
	}
	if len(s.properties) == 0 {
		ro.unrep[sitePath] = true // every observed field sits outside the v0 subset
		return nil
	}
	sort.Strings(s.required)
	return s
}

// inferField infers one field's schema from its census. Kind-consistent
// observations only: mixed kinds and shapes outside the v0 subset
// (boolean, null, array elements never observed) refuse the field and
// mark it unrepresentable — never a half-expressed schema.
func (ro *routeObs) inferField(fieldPath string) (*Schema, bool) {
	n := ro.nodes[fieldPath]
	switch {
	case soloKind(n, "object"):
		obj := ro.inferObject(fieldPath)
		if obj == nil {
			return nil, false // the site carried its unrepresentable mark
		}
		return obj, true
	case soloKind(n, "array"):
		el := ro.nodes[fieldPath+"[]"]
		if el == nil || el.present == 0 {
			ro.unrep[fieldPath] = true // element shape never observed: no honest items schema
			return nil, false
		}
		var items *Schema
		switch {
		case soloKind(el, "object"):
			items = ro.inferObject(fieldPath + "[]")
			if items == nil {
				return nil, false
			}
		case soloKind(el, "string"):
			items = stringSchema(el)
		case soloKind(el, "number"):
			items = &Schema{typ: "number"}
		default:
			ro.unrep[fieldPath] = true // element kinds mixed or outside the subset
			return nil, false
		}
		return &Schema{typ: "array", items: items}, true
	case soloKind(n, "string"):
		return stringSchema(n), true
	case soloKind(n, "number"):
		return &Schema{typ: "number"}, true
	default:
		ro.unrep[fieldPath] = true // boolean, null or mixed kinds
		return nil, false
	}
}

// stringSchema fills the string schema from the census: the enum under
// the cap and the measured maxLength. Patterns are never inferred — an
// inferred pattern would invent a contract the samples do not carry.
func stringSchema(n *obsNode) *Schema {
	s := &Schema{typ: "string"}
	if !n.overCap && len(n.values) > 0 {
		for v := range n.values {
			s.enum = append(s.enum, v)
		}
		sort.Strings(s.enum)
	}
	if n.maxLen > 0 {
		max := n.maxLen
		s.maxLength = &max
	}
	return s
}

// soloKind reports whether the node carries exactly one kind.
func soloKind(n *obsNode, kind string) bool { return n != nil && len(n.kinds) == 1 && n.kinds[kind] }

// directFields names the site's direct child fields: node paths one
// position under the site, excluding deeper sites (a dot in the
// remainder) and element sites (a [] tail).
func (ro *routeObs) directFields(sitePath string) []string {
	prefix := sitePath + "."
	out := make([]string, 0, len(ro.nodes))
	for p := range ro.nodes {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := p[len(prefix):]
		if strings.Contains(rest, ".") || strings.HasSuffix(rest, "[]") {
			continue
		}
		out = append(out, rest)
	}
	sort.Strings(out)
	return out
}

// cards flattens the route's schema-position nodes into the sorted
// cardinality read.
func (ro *routeObs) cards() []FieldCardinality {
	out := make([]FieldCardinality, 0, len(ro.nodes))
	for path, n := range ro.nodes {
		c := FieldCardinality{Path: path, Present: n.present, Seen: n.seen, OverCap: n.overCap, MaxLength: n.maxLen}
		for k := range n.kinds {
			c.Kinds = append(c.Kinds, k)
		}
		sort.Strings(c.Kinds)
		if n.overCap {
			c.Distinct = enumInferMax + 1 // the known bound: at least cap+1 distinct values
		} else {
			c.Distinct = len(n.values)
			for v := range n.values {
				c.Values = append(c.Values, v)
			}
			sort.Strings(c.Values)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// sortSkipped orders the skipped records (method, then path).
func sortSkipped(list []SkippedMethod) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Method != list[j].Method {
			return list[i].Method < list[j].Method
		}
		return list[i].Path < list[j].Path
	})
}

// Materialize renders the learned route back into exactly one
// single-route OpenAPI 3.1 document — the bytes the strict v0 loader
// accepts (TR-13a). This is the closure seam: a learned spec carries the
// same shapes the reviewed document carries.
func (s *LearnedSpec) Materialize(path, title, version string) ([]byte, error) {
	if s == nil || s.Routes == nil {
		return nil, fmt.Errorf("materialize: no learned spec")
	}
	r, ok := s.Routes[path]
	if !ok {
		return nil, fmt.Errorf("materialize: no samples observed for path %q", path)
	}
	if r.Schema == nil {
		return nil, fmt.Errorf("materialize: path %q carries no decodable object body", path)
	}
	b, err := yaml.Marshal(map[string]any{
		"openapi": docVersion,
		"info":    map[string]any{"title": title, "version": version},
		"paths": map[string]any{
			path: map[string]any{
				"post": map[string]any{
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{"schema": schemaNode(r.Schema)},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("materialize: %w", err)
	}
	return b, nil
}

// schemaNode renders one schema back into the document node shape (the
// exact subset vocabulary the strict loader accepts).
func schemaNode(s *Schema) map[string]any {
	n := map[string]any{"type": s.typ}
	switch s.typ {
	case "object":
		props := map[string]any{}
		for name, ps := range s.properties {
			props[name] = schemaNode(ps)
		}
		n["properties"] = props
		if len(s.required) > 0 {
			n["required"] = s.required
		}
	case "array":
		n["items"] = schemaNode(s.items)
	case "string":
		if len(s.enum) > 0 {
			n["enum"] = s.enum
		}
		if s.maxLength != nil {
			n["maxLength"] = *s.maxLength
		}
	}
	return n
}
