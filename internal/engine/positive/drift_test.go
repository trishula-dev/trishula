package positive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDriftReportKinds: the full drift table against the reviewed
// fixture policy — every divergence kind the walk reads off the
// cardinality census, with per-kind counts and the endpoint ledger.
func TestDriftReportKinds(t *testing.T) {
	dec := decodeFixtures(t, loadFixture(t, "requests.yaml"))
	s1 := dec["conforming-full"]
	s3 := dec["malformed-many"]
	reviewed, err := LoadPolicy(filepath.Join("testdata", "openapi-chat.yaml"))
	if err != nil {
		t.Fatalf("load reviewed policy: %v", err)
	}

	longModel := strings.Repeat("a", 41)
	d := NewDiscoverer()
	bodies := []string{
		string(s1.Body), // model string, temperature number
		`{"model":"llama3-8b","messages":[{"role":"assistant","content":"y"}],"temperature":0.7}`, // clean variant
		string(s3.Body), // model number, role wheel, temperature string
		`{"model":"` + longModel + `","messages":[{"role":"user","content":"z"}],"temperature":"hot"}`,
	}
	for _, body := range bodies {
		if err := d.Observe(Sample{Method: "POST", Path: "/v1/chat/completions", Body: json.RawMessage(body)}); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	if err := d.Observe(Sample{Method: "POST", Path: "/v1/embeddings", Body: json.RawMessage(`{"input":"t"}`)}); err != nil {
		t.Fatalf("observe embeddings: %v", err)
	}
	if err := d.Observe(Sample{Method: "GET", Path: "/v1/models"}); err != nil {
		t.Fatalf("observe get: %v", err)
	}

	rep := Drift(d.Spec(), reviewed)
	if rep.LiveSamples != 6 || rep.LiveEndpoints != 2 || rep.ReviewedRoutes != 1 {
		t.Fatalf("ledger = samples %d endpoints %d reviewed %d, want 6/2/1", rep.LiveSamples, rep.LiveEndpoints, rep.ReviewedRoutes)
	}

	key := func(kind DiffKind, route, path string) string {
		return string(kind) + "|" + route + "|" + path
	}
	got := map[string]Diff{}
	for _, diff := range rep.Diffs {
		got[key(diff.Kind, diff.Route, diff.Path)] = diff
	}
	wantRows := []string{
		key(DiffUnrepresentable, "/v1/chat/completions", "body.model"),
		key(DiffTypeDrift, "/v1/chat/completions", "body.model"),
		key(DiffEnumEscape, "/v1/chat/completions", "body.model"),
		key(DiffLengthOverflow, "/v1/chat/completions", "body.model"),
		key(DiffUnrepresentable, "/v1/chat/completions", "body.temperature"),
		key(DiffTypeDrift, "/v1/chat/completions", "body.temperature"),
		key(DiffRequiredDrift, "/v1/chat/completions", "body.temperature"),
		key(DiffRequiredDrift, "/v1/chat/completions", "body.messages[].role"),
		key(DiffEnumEscape, "/v1/chat/completions", "body.messages[].role"),
		key(DiffEndpointAdded, "/v1/embeddings", ""),
	}
	for _, w := range wantRows {
		diff, ok := got[w]
		if !ok {
			t.Errorf("report lacks row %q (has %d rows total)", w, len(rep.Diffs))
			continue
		}
		_ = diff
	}
	if len(rep.Diffs) != len(wantRows) {
		t.Errorf("report has %d rows, want exactly %d: %v", len(rep.Diffs), len(wantRows), renderDiffs(rep.Diffs))
	}

	wantCounts := map[DiffKind]int{
		DiffEndpointAdded: 1, DiffTypeDrift: 2, DiffEnumEscape: 2,
		DiffLengthOverflow: 1, DiffRequiredDrift: 2, DiffUnrepresentable: 2,
	}
	if len(rep.Counts) != len(wantCounts) {
		t.Errorf("counts entries = %d, want %d (%v)", len(rep.Counts), len(wantCounts), rep.Counts)
	}
	for kind, n := range wantCounts {
		if rep.Counts[kind] != n {
			t.Errorf("counts[%s] = %d, want %d", kind, rep.Counts[kind], n)
		}
	}

	// The notes carry the measured evidence, not adjectives.
	if m := got[key(DiffLengthOverflow, "/v1/chat/completions", "body.model")]; !strings.Contains(m.Note, "41") || !strings.Contains(m.Note, "32") {
		t.Errorf("length_overflow note = %q, want the observed 41 against the reviewed 32", m.Note)
	}
	if m := got[key(DiffRequiredDrift, "/v1/chat/completions", "body.messages[].role")]; !strings.Contains(m.Note, "reviewed required") || !strings.Contains(m.Note, "live optional") {
		t.Errorf("role required_drift note = %q, want both directions", m.Note)
	}
	if m := got[key(DiffEnumEscape, "/v1/chat/completions", "body.messages[].role")]; !strings.Contains(m.Note, `"wheel"`) {
		t.Errorf("role enum_escape note = %q, want the escaped value", m.Note)
	}
}

// TestDriftFieldMissing: a reviewed field with zero observations in the
// window reads as exactly one missing-field row (required in the
// reviewed schema, but no presence evidence — no required-drift row on
// zero presence).
func TestDriftFieldMissing(t *testing.T) {
	const doc = `openapi: 3.1.0
info: {title: t, version: v}
paths:
  /v1/quiet:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [model, pad]
              properties:
                model:
                  type: string
                  enum: [a, b]
                pad:
                  type: string`
	reviewed, err := parsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("parse reviewed doc: %v", err)
	}
	d := NewDiscoverer()
	for _, body := range []string{`{"model":"a"}`, `{"model":"b"}`} {
		if err := d.Observe(Sample{Method: "POST", Path: "/v1/quiet", Body: json.RawMessage(body)}); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	rep := Drift(d.Spec(), reviewed)
	if len(rep.Diffs) != 1 {
		t.Fatalf("report rows = %v, want exactly one field_missing row", renderDiffs(rep.Diffs))
	}
	m := rep.Diffs[0]
	if m.Kind != DiffFieldMissing || m.Route != "/v1/quiet" || m.Path != "body.pad" {
		t.Errorf("row = %+v, want field_missing on body.pad", m)
	}
	if !rep.HasDrift() {
		t.Error("HasDrift false with one divergence row")
	}
}

// TestDriftCleanPair: the learned spec against a reviewed copy of
// itself reads zero divergence — learn mode never manufactures drift;
// the materialize→load seam is the reviewed copy.
func TestDriftCleanPair(t *testing.T) {
	dec := decodeFixtures(t, loadFixture(t, "requests.yaml"))
	s1 := dec["conforming-full"]
	d := NewDiscoverer()
	for _, body := range []string{string(s1.Body), `{"model":"llama3-8b","messages":[{"role":"user","content":"z"}],"temperature":0.7}`} {
		if err := d.Observe(Sample{Method: "POST", Path: "/v1/chat/completions", Body: json.RawMessage(body)}); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	live := d.Spec()
	doc, err := live.Materialize("/v1/chat/completions", "learn demo", "1.0.0")
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	p := filepath.Join(t.TempDir(), "learned.yaml")
	if err := os.WriteFile(p, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	reviewed, err := LoadPolicy(p)
	if err != nil {
		t.Fatalf("load reviewed copy: %v", err)
	}
	rep := Drift(live, reviewed)
	if rep.HasDrift() {
		t.Fatalf("self-pair drift rows: %v", renderDiffs(rep.Diffs))
	}
	if rep.LiveEndpoints != 1 || rep.ReviewedRoutes != 1 {
		t.Errorf("ledger = endpoints %d reviewed %d, want 1/1", rep.LiveEndpoints, rep.ReviewedRoutes)
	}
}

// renderDiffs renders a row list for failure output.
func renderDiffs(diffs []Diff) string {
	out := make([]string, 0, len(diffs))
	for _, d := range diffs {
		out = append(out, string(d.Kind)+"|"+d.Route+"|"+d.Path)
	}
	return strings.Join(out, " ")
}
