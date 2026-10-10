package positive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
	"sigs.k8s.io/yaml"
)

// requestFixture is one named request sample (testdata/requests.yaml):
// the §11.3 head fields plus the raw encoded body the validator reads.
type requestFixture struct {
	Name        string          `json:"name"`
	Method      string          `json:"method"`
	ContentType string          `json:"content_type"`
	Path        string          `json:"path"`
	Body        json.RawMessage `json:"body"`
}

// testState bundles the S4 evaluator and the engine walking it, plus the
// tx carrying the attached §11.3 view for the named fixture case.
type testState struct {
	ev *greenEvaluator
	// eng is GREEN's wired ladder engine (RED: nil — the walk assertions
	// never run because buildTestState RED-fatals first).
	eng *ladder.Engine
	tx  *ingest.TxContext
	fx  requestFixture
}

// RED placeholder surface — GREEN (TR-13a) replaces this block with the
// production types (the real RequestEvaluator with Evaluate, the real
// Fragment struct, the real LoadPolicy function); the shapes asserted in
// positive_test.go are pinned here in RED-compile form.
type greenEvaluator struct {
	v0 *struct{} // GREEN: the loaded *Policy
}

// Evaluate is the RED-state method on the placeholder evaluator: it
// keeps the tests compile-clean while buildTestState still RED-fatals
// (GREEN binds the real evaluator; this method dies with it).
func (e *greenEvaluator) Evaluate(tx *ingest.TxContext) *greenFragment {
	_ = tx
	return nil
}

// greenFragment carries the RED fragment/assert surface (GREEN re-points
// the fields at the production struct + real Decisive method).
type greenFragment struct {
	Action      ladder.Action
	Diagnostics []string
	decisiveFn  func() bool
}

// Decisive mirrors the ladder.Action vocabulary through the placeholder.
func (f *greenFragment) Decisive() bool {
	if f == nil || f.decisiveFn == nil {
		return f != nil && f.Action.Decisive()
	}
	return f.decisiveFn()
}

// greenPolicy carries the RED Policy surface (GREEN re-points).
type greenPolicy struct{ v0 *struct{} }

// greenRuleID is GREEN's RuleIDSchemaViolation constant site (RED names
// the literal the tests assert; GREEN binds the production constant).
const greenRuleID = ladder.RuleID("positive:violation")

// buildTestState assembles the S4 stage + engine under test from the repo
// fixtures. GREEN replaces the fatal with the real assembly.
func buildTestState(t *testing.T, caseName string) *testState {
	t.Helper()
	if caseName == "" {
		t.Fatal("test bug: empty case name")
	}
	t.Fatalf("GREEN pending (TR-13a): buildTestState not implemented — watched RED")
	return nil
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

// txWithView attaches a view to a fresh tx (S0 contract, mirror).
func txWithView(t *testing.T, view *cel.Request) *ingest.TxContext {
	t.Helper()
	tx := &ingest.TxContext{}
	if err := ladder.AttachView(tx, view); err != nil {
		t.Fatalf("attach view: %v", err)
	}
	return tx
}

// decodeFixtures builds the name→case table from the request fixture doc.
// Body stays json.RawMessage — the validator consumes encoded JSON, never
// Go maps, so the fixture cannot smuggle pre-parsed values past the gate.
func decodeFixtures(t *testing.T, data []byte) map[string]requestFixture {
	t.Helper()
	var doc struct {
		Cases []requestFixture `json:"cases"`
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
