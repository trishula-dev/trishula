package positive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/cel"
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
		`body.messages[1].role: required field "role" missing`,
		`body.messages[2].role: value "wheel" not in enum [assistant system user]`,
		"body.temperature: expected number, got string",
	} {
		if !containsDiag(frag.Diagnostics, want) {
			t.Errorf("diagnostics %v lack %q", frag.Diagnostics, want)
		}
	}
	if len(frag.Diagnostics) != 4 {
		t.Errorf("diagnostics count = %d, want exactly 4", len(frag.Diagnostics))
	}
}

// TestUnknownPathDefault: a path with no schema matching takes the policy
// default action with no diagnostics (fail-open v0 default: pass-through).
func TestUnknownPathDefault(t *testing.T) {
	st := buildTestState(t, "conforming-full")
	unknown := txWithView(t, &cel.Request{Method: "GET", Path: "/no/such/route"})
	frag := st.ev.Evaluate(unknown)
	if frag != nil {
		t.Fatalf("unknown path: got fragment %+v, want nil (policy pass-through)", frag)
	}
	v := st.eng.EvaluateTx(unknown)
	if v.Action != ladder.ActionAllow || len(v.Rules) != 0 {
		t.Fatalf("unknown path walk = %q rules %v, want clean allow", v.Action, v.Rules)
	}
}

// TestLoadStrict rejects every doc-level construct outside the v0 subset —
// a schema the gate cannot fully express must fail loudly, never silently
// partially (the strictness rule).
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
              $ref: '#/components/schemas/Body'
components:
  schemas:
    Body: {type: object}`,
			wantErr: `"$ref" is not allowed`,
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
			_, err := greenLoadPolicy(p) // RED: nil var → the nil-check panic IS the watched failure
			if err == nil {              // GREEN: the real loader returns ("$…" is not allowed) errors
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
func containsDiag(diags []string, want string) bool {
	for _, d := range diags {
		if d == want {
			return true
		}
	}
	return false
}
