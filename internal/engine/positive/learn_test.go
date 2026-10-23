package positive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// NOTE (TR-18): discovery and drift are new behaviour with no existing
// home table (the S4 table tests pin per-request validation) — hence new
// test functions rather than rows, per the AGENTS.md decision procedure.

// fxToSample maps a request fixture onto a discovery sample (method +
// path + raw encoded body, the body-carrying view shape).
func fxToSample(fx requestFixture) Sample {
	return Sample{Method: fx.Method, Path: fx.Path, Body: fx.Body}
}

// TestDiscovererEndpointExtraction: samples group by exact path; post
// bodies drive per-route routes; non-post samples carry counts on the
// skipped record (v0 subset: post-only, TR-13a) instead of vanishing;
// the samples ledger reconciles.
func TestDiscovererEndpointExtraction(t *testing.T) {
	dec := decodeFixtures(t, loadFixture(t, "requests.yaml"))
	s1 := dec["conforming-full"]
	s3 := dec["malformed-many"]

	d := NewDiscoverer()
	if err := d.Observe(fxToSample(s1)); err != nil {
		t.Fatalf("observe chat: %v", err)
	}
	if err := d.Observe(fxToSample(s3)); err != nil {
		t.Fatalf("observe chat: %v", err)
	}
	if err := d.Observe(Sample{Method: "POST", Path: "/v1/embeddings", Body: json.RawMessage(`{"input":"hi","model":"m"}`)}); err != nil {
		t.Fatalf("observe embeddings: %v", err)
	}
	if err := d.Observe(Sample{Method: "POST", Path: "/v1/embeddings", Body: json.RawMessage(`not json`)}); err != nil {
		t.Fatalf("observe embeddings: %v", err)
	}
	if err := d.Observe(Sample{Method: "GET", Path: "/v1/models"}); err != nil {
		t.Fatalf("observe get: %v", err)
	}
	if err := d.Observe(Sample{Method: "POST", Path: "/v1/models", Body: json.RawMessage(`not json`)}); err != nil {
		t.Fatalf("observe models: %v", err)
	}
	// The caller-bug contract: a sample without a path or method is
	// refused, never folded.
	if err := d.Observe(Sample{Method: "POST", Path: ""}); err == nil {
		t.Error("empty-path sample: nil error, want refusal")
	}
	if err := d.Observe(Sample{Method: "", Path: "/v1/x"}); err == nil {
		t.Error("empty-method sample: nil error, want refusal")
	}

	spec := d.Spec()
	if spec.Samples != 6 {
		t.Fatalf("spec.Samples = %d, want 6", spec.Samples)
	}
	for _, path := range []string{"/v1/chat/completions", "/v1/embeddings", "/v1/models"} {
		if spec.Routes[path] == nil {
			t.Fatalf("routes lack %q (have %d route keys)", path, len(spec.Routes))
		}
	}
	if len(spec.Routes) != 3 {
		t.Fatalf("route count = %d, want 3", len(spec.Routes))
	}
	chat := spec.Routes["/v1/chat/completions"]
	if chat.Samples != 2 || chat.Undecodable != 0 {
		t.Errorf("chat samples=%d undecodable=%d, want 2/0", chat.Samples, chat.Undecodable)
	}
	emb := spec.Routes["/v1/embeddings"]
	if emb.Samples != 2 || emb.Undecodable != 1 {
		t.Errorf("embeddings samples=%d undecodable=%d, want 2/1", emb.Samples, emb.Undecodable)
	}
	// A route with no decodable body carries no schema (honest gap,
	// never a fabricated schema).
	mods := spec.Routes["/v1/models"]
	if mods.Schema != nil {
		t.Errorf("models route carries a schema without a decodable body")
	}
	if mods.Samples != 1 || mods.Undecodable != 1 {
		t.Errorf("models samples=%d undecodable=%d, want 1/1", mods.Samples, mods.Undecodable)
	}
	if len(spec.Skipped) != 1 || spec.Skipped[0].Method != "GET" || spec.Skipped[0].Path != "/v1/models" || spec.Skipped[0].Count != 1 {
		t.Errorf("skipped records = %+v, want exactly one GET /v1/models count 1", spec.Skipped)
	}
	// The ledger invariant: every sample is either a route sample or a
	// skipped record.
	routed := 0
	for _, r := range spec.Routes {
		routed += r.Samples
	}
	skippedTotal := 0
	for _, s := range spec.Skipped {
		skippedTotal += s.Count
	}
	if routed+skippedTotal != spec.Samples {
		t.Errorf("ledger broken: routed %d + skipped %d != samples %d", routed, skippedTotal, spec.Samples)
	}
}

// TestInferenceTypes: the value census drives the inferred subset schema
// — object/array/string/number shapes, required from full presence,
// enum from the distinct-value census, maxLength from the length census.
func TestInferenceTypes(t *testing.T) {
	d := NewDiscoverer()
	const b1 = `{"name":"alpha","count":3,"tags":["a","b"],"meta":{"k":"v"},"level":"warn"}`
	const b2 = `{"name":"beta","count":9,"tags":["b","c"],"meta":{"k":"x"},"level":"error"}`
	const b3 = `{"name":"alpha1","count":9,"tags":["c"],"meta":{"k":"v"},"level":"warn"}`
	for _, body := range []string{b1, b2, b3} {
		if err := d.Observe(Sample{Method: "POST", Path: "/v1/infer", Body: json.RawMessage(body)}); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	route := d.Spec().Routes["/v1/infer"]
	if route == nil || route.Schema == nil {
		t.Fatalf("inferred route/schema nil")
	}
	s := route.Schema
	if s.typ != "object" || len(s.properties) != 5 {
		t.Fatalf("root: type %q properties %d, want object with 5 fields", s.typ, len(s.properties))
	}
	if len(s.required) != 5 {
		t.Fatalf("required = %v, want all 5 fields required (present 3 of 3)", s.required)
	}
	name := s.properties["name"]
	if name.typ != "string" || name.maxLength == nil || *name.maxLength != 6 ||
		!enumHas(name, "alpha", "alpha1", "beta") {
		t.Errorf("name inference wrong: type %q maxLength %v enum %v", name.typ, name.maxLength, name.enum)
	}
	if s.properties["count"].typ != "number" {
		t.Errorf("count: type %q, want number", s.properties["count"].typ)
	}
	tags := s.properties["tags"]
	if tags.typ != "array" || tags.items == nil || tags.items.typ != "string" ||
		tags.items.maxLength == nil || *tags.items.maxLength != 1 {
		t.Errorf("tags inference wrong: type %q items %v maxLength %v", tags.typ, tags.items, tags.items.maxLength)
	}
	meta := s.properties["meta"]
	if meta.typ != "object" || !requiredHas(meta, "k") || meta.properties["k"].typ != "string" ||
		meta.properties["k"].enum == nil || !enumHas(meta.properties["k"], "v", "x") {
		t.Errorf("meta inference wrong: type %q required %v", meta.typ, meta.required)
	}
	level := s.properties["level"]
	if !enumHas(level, "error", "warn") || len(level.enum) != 2 {
		t.Errorf("level enum %v, want [error warn]", level.enum)
	}

	// The cardinality read: presence, parent instances, kinds, the
	// distinct-value census and the length census are data.
	cards := map[string]FieldCardinality{}
	for _, c := range route.Cardinality {
		cards[c.Path] = c
	}
	lv := cards["body.level"]
	if lv.Present != 3 || lv.Seen != 3 || len(lv.Kinds) != 1 || lv.Kinds[0] != "string" ||
		lv.Distinct != 2 || lv.MaxLength != 5 {
		t.Errorf("body.level card = %+v", lv)
	}
	el := cards["body.tags[]"]
	if el.Present != 5 || el.Seen != 3 {
		t.Errorf("body.tags[] card = %+v, want present 5 seen 3", el)
	}
}

// TestInferenceUnrepresentable: shapes the v0 subset cannot describe stay
// OUT of the inferred schema and carry explicit records — siblings still
// infer (a poisoned field never poisons the whole object), and an entity
// whose every field is unrepresentable carries no schema at all.
func TestInferenceUnrepresentable(t *testing.T) {
	d := NewDiscoverer()
	const b1 = `{"flag":true,"note":"x"}`
	const b2 = `{"v1":1,"v2":"x","note":"y"}`
	const b3 = `{"v1":"y","v2":2,"note":"z"}`
	for _, body := range []string{b1, b2, b3} {
		if err := d.Observe(Sample{Method: "POST", Path: "/v1/flag", Body: json.RawMessage(body)}); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	if err := d.Observe(Sample{Method: "POST", Path: "/v1/wide", Body: json.RawMessage(`{"opt":[]}`)}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	spec := d.Spec()

	flag := spec.Routes["/v1/flag"]
	if flag == nil || flag.Schema == nil {
		t.Fatalf("flag route/schema nil")
	}
	for _, bad := range []string{"flag", "v1", "v2"} {
		if _, ok := flag.Schema.properties[bad]; ok {
			t.Errorf("%s: unrepresentable field inferred into the schema — want excluded", bad)
		}
	}
	if flag.Schema.properties["note"] == nil || flag.Schema.properties["note"].typ != "string" {
		t.Errorf("note: a clean sibling did not infer (properties count %d)", len(flag.Schema.properties))
	}
	for _, want := range []string{"body.flag", "body.v1", "body.v2"} {
		if !containsStr(flag.Unrepresentable, want) {
			t.Errorf("unrepresentable records %v lack %q", flag.Unrepresentable, want)
		}
	}
	if len(flag.Unrepresentable) != 3 {
		t.Errorf("unrepresentable records = %v, want exactly 3", flag.Unrepresentable)
	}
	if c := cardOf(flag.Cardinality, "body.flag"); c == nil || len(c.Kinds) != 1 || c.Kinds[0] != "boolean" {
		t.Errorf("body.flag card = %+v, want kinds [boolean]", c)
	}

	wide := spec.Routes["/v1/wide"]
	if wide == nil {
		t.Fatalf("wide route nil")
	}
	if wide.Schema != nil {
		t.Errorf("wide: an entity with no representable field carries a schema — want nil")
	}
	for _, want := range []string{"body", "body.opt"} {
		if !containsStr(wide.Unrepresentable, want) {
			t.Errorf("wide unrepresentable records %v lack %q", wide.Unrepresentable, want)
		}
	}
}

// TestMaterializeRoundTrip: the learned route renders into one single-
// route OpenAPI 3.1 document that the strict v0 loader accepts, and the
// reloaded schema verifies the observed body clean — the closure proof
// tying learn mode back to the enforcement path (TR-13a loader).
func TestMaterializeRoundTrip(t *testing.T) {
	dec := decodeFixtures(t, loadFixture(t, "requests.yaml"))
	s1 := dec["conforming-full"]
	d := NewDiscoverer()
	for _, body := range []string{string(s1.Body), `{"model":"llama3-8b","messages":[{"role":"user","content":"z"}],"temperature":0.7}`} {
		if err := d.Observe(Sample{Method: "POST", Path: "/v1/chat/completions", Body: json.RawMessage(body)}); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	if err := d.Observe(Sample{Method: "POST", Path: "/v1/empty", Body: json.RawMessage(`not json`)}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	spec := d.Spec()

	doc, err := spec.Materialize("/v1/chat/completions", "learn demo", "1.0.0")
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	p := filepath.Join(t.TempDir(), "learned.yaml")
	if err := os.WriteFile(p, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := LoadPolicy(p)
	if err != nil {
		t.Fatalf("strict loader refused the learned doc: %v", err)
	}
	sch := pol.match("/v1/chat/completions")
	if sch == nil {
		t.Fatal("reloaded policy lost the learned route")
	}
	diags, err := validateBody(sch, []byte(s1.Body))
	if err != nil {
		t.Fatalf("validateBody: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("reloaded schema rejects the observed body: %v", diags)
	}
	if _, err := spec.Materialize("/v1/no/such", "t", "v"); err == nil {
		t.Error("materialize of an unsampled route: nil error, want refusal")
	}
	if _, err := spec.Materialize("/v1/empty", "t", "v"); err == nil {
		t.Error("materialize of a route without a decodable body: nil error, want refusal")
	}
}

// containsStr reports whether list carries s.
func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// cardOf finds one cardinality record by path.
func cardOf(cards []FieldCardinality, path string) *FieldCardinality {
	for i := range cards {
		if cards[i].Path == path {
			return &cards[i]
		}
	}
	return nil
}

// enumHas reports whether the schema's enum carries every value.
func enumHas(s *Schema, want ...string) bool {
	if len(s.enum) < len(want) {
		return false
	}
	for _, w := range want {
		if !containsStr(s.enum, w) {
			return false
		}
	}
	return true
}

// requiredHas reports whether the schema requires the field.
func requiredHas(s *Schema, name string) bool {
	return containsStr(s.required, name)
}
