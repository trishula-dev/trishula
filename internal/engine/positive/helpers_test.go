package positive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
	"sigs.k8s.io/yaml"
)

// requestFixture is one named request sample (testdata/requests.yaml):
// the §11.3 head fields plus the raw encoded body the validator reads.
type requestFixture struct {
	Name        string          `json:"name" yaml:"name"`
	Method      string          `json:"method" yaml:"method"`
	ContentType string          `json:"content_type" yaml:"content_type"`
	Path        string          `json:"path" yaml:"path"`
	Body        json.RawMessage `json:"body" yaml:"body"`
}

// testState bundles the S4 evaluator and the engine walking it, plus the
// tx carrying the attached body-carrying §11.3 view for the fixture case.
type testState struct {
	ev  *RequestEvaluator
	eng *ladder.Engine
	tx  *ingest.TxContext
	fx  requestFixture
}

// buildTestState assembles the S4 stage + engine under test from the repo
// fixtures (the GREEN assembly; the watched-RED fatal is gone). The walk
// engine carries ONLY the S4 slot — fragments from other stages cannot
// mask the verdicts these tests assert.
func buildTestState(t *testing.T, caseName string) *testState {
	t.Helper()
	if caseName == "" {
		t.Fatal("test bug: empty case name")
	}
	pol, err := LoadPolicy(filepath.Join("testdata", "openapi-chat.yaml"))
	if err != nil {
		t.Fatalf("load policy fixture: %v", err)
	}
	fx := decodeFixtures(t, loadFixture(t, "requests.yaml"))[caseName]
	if fx.Name == "" {
		t.Fatalf("fixture case %q not found", caseName)
	}
	tx := &ingest.TxContext{}
	if err := AttachRequestBodyView(tx, &bodyView{Method: fx.Method, Path: fx.Path, Body: fx.Body}); err != nil {
		t.Fatalf("attach body view: %v", err)
	}
	ev := NewRequestEvaluator(pol)
	eng := ladder.NewEngine()
	if err := eng.Use(ladder.StageSchema, schemaStage{ev}); err != nil {
		t.Fatalf("wire S4: %v", err)
	}
	return &testState{ev: ev, eng: eng, tx: tx, fx: fx}
}

// schemaStage adapts RequestEvaluator to the ladder.Evaluator interface
// (Stage pins S4; Evaluate projects the Result into the ladder Verdict).
type schemaStage struct{ ev *RequestEvaluator }

// Stage pins the fixed S4 slot (the adapter's whole point).
func (s schemaStage) Stage() ladder.Stage { return ladder.StageSchema }

// Evaluate projects one Result fragment into the ladder vocabulary.
func (s schemaStage) Evaluate(tx *ingest.TxContext) *ladder.Verdict {
	r := s.ev.Evaluate(tx)
	if r == nil {
		return nil
	}
	return &ladder.Verdict{Action: r.Action, Rules: r.Rules, Phase: r.Phase}
}

// loadFixture reads a testdata file relative to this package (os.ReadFile
// keeps the fixture hermetic — no network, no generator).
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// txWithBodyView attaches a body-carrying view to a fresh tx (the
// AttachRequestBodyView contract, exercised directly).
func txWithBodyView(t *testing.T, method, path string, body json.RawMessage) *ingest.TxContext {
	t.Helper()
	tx := &ingest.TxContext{}
	if err := AttachRequestBodyView(tx, &bodyView{Method: method, Path: path, Body: body}); err != nil {
		t.Fatalf("attach body view: %v", err)
	}
	return tx
}

// decodeFixtures builds the name→case table from the request fixture doc.
// Body stays json.RawMessage — the validator consumes encoded JSON, never
// Go maps, so the fixture cannot smuggle pre-parsed values past the gate.
func decodeFixtures(t *testing.T, data []byte) map[string]requestFixture {
	t.Helper()
	var doc struct {
		Cases []requestFixture `json:"cases" yaml:"cases"`
	}
	if err := yaml.UnmarshalStrict(data, &doc); err != nil {
		t.Fatalf("decode requests.yaml: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("decode requests.yaml: empty cases list")
	}
	out := map[string]requestFixture{}
	for _, c := range doc.Cases {
		if _, dup := out[c.Name]; dup {
			t.Fatalf("requests.yaml: duplicate case name %q", c.Name)
		}
		out[c.Name] = c
	}
	return out
}
