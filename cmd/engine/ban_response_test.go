package main

// TR-195 leaf 1 (issue #237): the manual ban surface end to end on the
// handler: a matched ban-rule reads decision=ban + the 403 + the owning
// rule id, and the direct would-ban lands in the evidence JSONL the flag
// names. The clean shape forwards untouched.
import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	cel "github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/operator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func compileBanBundle(t *testing.T) []byte {
	t.Helper()
	const y = `
rules:
  - id: OPS-BAN-01
    name: manual-ban
    description: a manual ban on the secret route for the offending source
    action: ban
    expression: |
      request.method == "GET" && path.matches("/secret/*")
`
	pack, err := cel.ParseRulePack([]byte(y))
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	policy := v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ban-gate", Namespace: "dx1"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionPass,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shadow: true},
		},
	}
	bundle, err := operator.Compile(policy)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	bundle.RulePacks = []cel.RulePack{*pack}
	digests, err := operator.PackDigests(bundle.RulePacks)
	if err != nil {
		t.Fatalf("digests: %v", err)
	}
	bundle.RulePackDigests = digests
	b, err := json.Marshal(&bundle)
	if err != nil {
		t.Fatalf("bundle json: %v", err)
	}
	return b
}

func TestEngineBanRuleRespondsBandWritesEvidence(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	evidencePath := filepath.Join(t.TempDir(), "bans.jsonl")
	banEvidencePath = evidencePath
	defer func() { banEvidencePath = "" }()

	eng, err := newEngineHandlerWithBundle(upstream.URL, "engine", compileBanBundle(t))
	if err != nil {
		t.Fatalf("engine handler: %v", err)
	}
	host := httptest.NewServer(eng)
	defer host.Close()

	probe, _ := http.NewRequest(http.MethodGet, host.URL+"/secret/x", nil)
	resp, err := http.DefaultClient.Do(probe)
	if err != nil {
		t.Fatalf("ban probe: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("ban probe status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Trishula-Decision"); got != "ban" {
		t.Errorf("X-Trishula-Decision = %q, want ban", got)
	}
	if got := resp.Header.Get("X-Trishula-Rule"); got != "OPS-BAN-01" {
		t.Errorf("X-Trishula-Rule = %q, want OPS-BAN-01", got)
	}
	if !strings.Contains(string(body), "banned by OPS-BAN-01") {
		t.Errorf("body = %q, want the banned-by line", string(body))
	}

	// the evidence line: the enforcer's kernel-write input (leaf 2 reads it)
	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("evidence file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("evidence lines = %d, want 1", len(lines))
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("evidence decode: %v", err)
	}
	if rec["verdict"] != "would-ban" || rec["tier"] != "manual-rule" {
		t.Errorf("evidence record wrong: mode=%v verdict=%v tier=%v", rec["mode"], rec["verdict"], rec["tier"])
	}
	if rec["key"] == "" {
		t.Error("evidence key empty (the offender key = the receipt chain)")
	}

	// the clean route forwards; the evidence count holds at 1
	clean, _ := http.NewRequest(http.MethodGet, host.URL+"/open", nil)
	resp2, err := http.DefaultClient.Do(clean)
	if err != nil {
		t.Fatalf("clean probe: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("clean probe = %d, want 200", resp2.StatusCode)
	}
	raw2, _ := os.ReadFile(evidencePath)
	n := strings.Count(string(raw2), "\n")
	if n != 1 {
		t.Errorf("evidence lines after the clean probe = %d, want 1", n)
	}
}
