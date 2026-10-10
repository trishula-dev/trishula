package positive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// TestConformingPasses: a schema-conforming chat request produces no
// diagnostics and a non-decisive allow fragment; the walk stays clean
// (no violation rule on a conforming request).
func TestConformingPasses(t *testing.T) {
	st := buildTestState(t, "conforming-full")
	frag := st.ev.Evaluate(st.tx)
	if frag == nil {
		t.Fatal("nil fragment")
	}
	if len(frag.Diagnostics) != 0 {
		t.Fatalf("diagnostics on conforming request: %v", frag.Diagnostics)
	}
	if frag.Action != ladder.ActionAllow || frag.Decisive() {
		t.Fatalf("conforming fragment: action %q decisive=%v, want non-decisive allow", frag.Action, frag.Decisive())
	}
	if frag.Phase != ladder.PhaseRequestBody {
		t.Fatalf("fragment phase %q, want %q", frag.Phase, ladder.PhaseRequestBody)
	}
	got := st.eng.EvaluateTx(st.tx)
	if got.Action != ladder.ActionAllow || len(got.Rules) != 0 {
		t.Fatalf("walk = %q rules %v, want clean allow with no S4 rule on a conforming request", got.Action, got.Rules)
	}
}

// TestMalformedRejected: a malformed body is rejected with ALL diagnostics
// naming the exact violated field paths — the acceptance criterion's
// second half.
func TestMalformedRejected(t *testing.T) {
	st := buildTestState(t, "malformed-many")
	frag := st.ev.Evaluate(st.tx)
	if frag == nil {
		t.Fatal("nil fragment")
	}
	if frag.Action != ladder.ActionLog || frag.Decisive() {
		t.Fatalf("shadow posture broken: action %q decisive=%v", frag.Action, frag.Decisive())
	}
	for _, want := range []string{
		`body.model: expected string, got number`,
		`body.messages[1]: required field "role" missing`,
		`body.messages[2].role: value "wheel" not in enum [system user assistant]`,
		"body.temperature: expected number, got string",
	} {
		if !containsDiag(frag.Diagnostics, want) {
			t.Errorf("diagnostics %v lack %q", frag.Diagnostics, want)
		}
	}
	if len(frag.Diagnostics) != 4 {
		t.Errorf("diagnostics count = %d, want exactly 4", len(frag.Diagnostics))
	}
	// The walk carries the S4 rule id and resolves log (shadow: logged,
	// never enforced; decisive block is v1's policy flip).
	got := st.eng.EvaluateTx(st.tx)
	if got.Action != ladder.ActionLog {
		t.Fatalf("walk action = %q, want log (shadow posture)", got.Action)
	}
	if !containsRule(got.Rules, RuleIDSchemaViolation) {
		t.Fatalf("walk rules %v lack %q", got.Rules, RuleIDSchemaViolation)
	}
	if got.Phase != ladder.PhaseRequestBody {
		t.Fatalf("walk phase %q, want %q", got.Phase, ladder.PhaseRequestBody)
	}
}

// TestUnknownPathDefault: a path with no schema matching takes the policy
// default action with no diagnostics (fail-open v0 default: pass-through).
func TestUnknownPathDefault(t *testing.T) {
	st := buildTestState(t, "conforming-full")
	unknown := txWithBodyView(t, "GET", "/no/such/route", json.RawMessage(`{"any":"thing"}`))
	frag := st.ev.Evaluate(unknown)
	if frag != nil {
		t.Fatalf("unknown path: got fragment %+v, want nil (policy pass-through)", frag)
	}
	v := st.eng.EvaluateTx(unknown)
	if v.Action != ladder.ActionAllow || len(v.Rules) != 0 {
		t.Fatalf("unknown path walk = %q rules %v, want clean allow", v.Action, v.Rules)
	}
}

// TestNilViewNoOpinion: a tx carrying no view at all gets no S4 opinion
// (the nil-view contract; the walk stays clean).
func TestNilViewNoOpinion(t *testing.T) {
	st := buildTestState(t, "conforming-full")
	frag := st.ev.Evaluate(new(ingest.TxContext))
	if frag != nil {
		t.Fatalf("nil-view tx: got fragment %+v, want nil", frag)
	}
	if v := st.eng.EvaluateTx(new(ingest.TxContext)); v.Action != ladder.ActionAllow || len(v.Rules) != 0 {
		t.Fatalf("nil-view walk = %q rules %v, want clean allow", v.Action, v.Rules)
	}
}

// TestPatternAndMaxLength: the remaining string keywords exercised off
// the chat fixture (pattern requirement, maxLength cap) — diagnostics
// still name the exact field path.
func TestPatternAndMaxLength(t *testing.T) {
	const body = `{"model":"m","messages":[{"role":"user","content":"ok"}],"token":"aB!","pad":"0123456789abcdef"}`
	s := &Schema{typ: "object", properties: map[string]*Schema{
		"token": {typ: "string", pattern: regexp.MustCompile(`^[A-Za-z0-9]*$`)},
		"pad":   {typ: "string", maxLength: intp(8)},
	}, required: []string{"model", "messages"}}
	diags, err := validateBody(s, []byte(body))
	if err != nil {
		t.Fatalf("validateBody: %v", err)
	}
	if !containsDiag(diags, `body.token: value "aB!" does not match pattern`) {
		t.Errorf("diagnostics %v lack pattern violation", diags)
	}
	if !containsDiag(diags, `body.pad: length 16 exceeds maxLength 8`) {
		t.Errorf("diagnostics %v lack maxLength violation", diags)
	}
	if len(diags) != 2 {
		t.Errorf("diagnostics count = %d, want exactly 2", len(diags))
	}
}

// intp is a test-local *int builder (schema literals stay readable).
func intp(n int) *int { return &n }

// TestLoadStrict rejects every doc-level construct outside the v0 subset —
// a schema the gate cannot fully express must fail loudly, never silently
// partially (the strictness rule; contract table in policy_test.go).
func TestLoadStrict(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, doc, wantErr string
	}{
		{
			name: "ref_indirection",
			doc: `openapi: 3.1.0
info: {title: t, version: v}
paths:
  /v1/chat/completions:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                model:
                  $ref: '#/components/schemas/M'`,
			wantErr: `missing "type"`,
		},
		{
			name: "unsupported_field_name",
			doc: `openapi: 3.1.0
info: {title: t, version: v}
paths:
  /v1/chat/completions:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                model:
                  type: string
                  format: uuid`,
			wantErr: `"format" is not allowed`,
		},
		{
			name: "unknown_keyword",
			doc: `openapi: 3.1.0
info: {title: t, version: v}
paths:
  /v1/chat/completions:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              if: {properties: {model: {const: gpt-4o-mini}}}`,
			wantErr: `"if" is not allowed`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(p, []byte(tc.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadPolicy(p)
			if err == nil || !containsLoadErr(err, tc.wantErr) {
				t.Errorf("LoadPolicy error = %v, want it to name %q", err, tc.wantErr)
			}
		})
	}
}

// containsRule reports whether rules carries id.
func containsRule(rules []ladder.RuleID, id ladder.RuleID) bool {
	for _, r := range rules {
		if r == id {
			return true
		}
	}
	return false
}

// containsDiag reports whether diags carries the exact diagnostic line.
func containsDiag(diags []Diagnostic, want string) bool {
	for _, d := range diags {
		if string(d) == want {
			return true
		}
	}
	return false
}

// containsLoadErr reports whether the strict-load error names the
// violating construct (json's unknown-field error quotes the key:
// `unknown field "components"` — matched by key, the actionable part).
func containsLoadErr(err error, want string) bool {
	return err != nil && strings.Contains(err.Error(), want)
}
