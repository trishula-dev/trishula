package positive

import (
	"encoding/json"
	"errors"
)

// RED (TR-18): learn-mode discovery harness. Types are the contract; the
// method bodies are stubs pending the GREEN commit. The GREEN work pins:
// endpoint extraction over observed samples, JSON-schema inference with
// cardinality tracking, the materialized OpenAPI route doc, and the
// live-vs-reviewed drift read.

// enumInferMax is the distinct-value cap for enum inference (values seen
// under this bound become the learned enum; a wider set stays a plain
// string — a long-tail value census must not become an enforced enum).
const enumInferMax = 8

// Sample is one observed request feeding discovery (§11.5 learn mode):
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
// infer in the v0 subset: any method outside `post` (§11.5 v0 subset:
// body-only, post-only, TR-13a).
type SkippedMethod struct {
	Method string
	Path   string
	Count  int
}

// FieldCardinality is the tracked observation statistics for one field
// path (§11.5 "JSON-schema inference with cardinality tracking"):
// presence ratio drives required inference, the distinct-value census
// drives enum inference, and the length census drives maxLength.
type FieldCardinality struct {
	Path      string
	Present   int
	Seen      int
	Kinds     []string
	Distinct  int
	Values    []string
	OverCap   bool
	MaxLength int
}

// LearnedRoute is one discovered endpoint: the inferred schema, its
// cardinality records and the honest gaps (no object body observed,
// undecodable bodies, unrepresentable field shapes).
type LearnedRoute struct {
	Path            string
	Schema          *Schema
	Cardinality     []FieldCardinality
	Unrepresentable []string
	Samples         int
	Undecodable     int
}

// LearnedSpec is the learn-mode artifact (§11.5): the discovered
// endpoints over the observed window. It is the shape the future APISpec
// CR diff tooling reads; reviewed enforcement still loads through the
// strict v0 loader (TR-13a).
type LearnedSpec struct {
	Routes  map[string]*LearnedRoute
	Skipped []SkippedMethod
	Samples int
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

// routeObs is the accumulator for one observed path.
type routeObs struct {
	samples     int
	undecodable int
	root        *siteObs
	unrep       map[string]bool
}

// siteObs tracks one schema-position site: the object instances seen
// there and the child-field observations under it.
type siteObs struct {
	objs   int
	val    *valObs
	fields map[string]*valObs
}

// valObs is the value census at one field or element site.
type valObs struct {
	present int
	kinds   map[string]bool
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

// Observe folds one sample into the tracks (RED stub).
func (d *Discoverer) Observe(s Sample) error {
	return nil
}

// Spec infers the learned spec from the observed window (RED stub).
func (d *Discoverer) Spec() *LearnedSpec {
	return &LearnedSpec{Routes: map[string]*LearnedRoute{}}
}

// Materialize renders the learned route back into exactly one
// single-route OpenAPI 3.1 document — the bytes the strict v0 loader
// accepts (RED stub).
func (s *LearnedSpec) Materialize(path, title, version string) ([]byte, error) {
	return nil, errors.New("materialize: stub")
}
