package main

// TR-08c (issue #76, M9) — the engine leg of the apply→effect round trip:
// cmd/engine loads the operator's bundle (Compile→Load, in-process at v0)
// via --bundle and consults it in the proxy handler before forwarding
// (PRD §5.2 step 1). RED state: newEngineHandlerWithBundle and Decide are
// undefined (build failure); GREEN defines them.
//
// Contract: tests use only package APIs (operator, cel) — never cel-go
// directly; the bundle bytes are the operator's Compile output (JSON wire
// format v1) exactly as the lab's configmap path delivers them.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/operator"
)

// sqliPack is the enforced rule pack the lab policy resolves (the same
// fixture as the reconcile test): SQLi probes in the chat route's query.
const sqliPackYAML = `
rules:
  - id: TR08C-001
    name: sqli-in-chat-query
    description: blocks SQLi UNION probes in query strings on the chat route
    action: enforce
    expression: |
      request.method == "POST" &&
      path.matches("/v1/chat/*") &&
      request.query.contains("UNION")
`

// compileLabBundle compiles the DX1 gate policy with the SQLi rule pack and
// returns its JSON bundle bytes (real Compile output, not a hand-built stub).
func compileLabBundle(t *testing.T) []byte {
	t.Helper()
	pack, err := cel.ParseRulePack([]byte(sqliPackYAML))
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	policy := v1alpha1.WAFPolicy{
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionBlock,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shadow: true},
		},
	}
	bundle, err := operator.Compile(policy)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if bundle.KernelValues == nil {
		t.Fatal("Compile must always set kernelValues")
	}
	bundle.RulePacks = []cel.RulePack{*pack}
	digests, err := operator.PackDigests(bundle.RulePacks)
	if err != nil {
		t.Fatalf("digests: %v", err)
	}
	bundle.RulePackDigests = digests
	b, err := json.Marshal(&bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return b
}

// TestEngineBundleBlocksSQLi: the M9 effect at the HTTP surface. One
// engine host, the loaded bundle consults each request before forwarding:
// a SQLi probe is decided (403 with the enforced rule's id named in the
// response detail header); the benign request forwards to the upstream.
func TestEngineBundleBlocksSQLi(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	bundle := compileLabBundle(t)
	eng, err := newEngineHandlerWithBundle(upstream.URL, "engine", bundle)
	if err != nil {
		t.Fatalf("build engine handler: %v", err)
	}
	host := httptest.NewServer(eng)
	defer host.Close()

	probe, _ := http.NewRequest(http.MethodPost, host.URL+"/v1/chat/completions?q=UNION%20SELECT", nil)
	resp, err := http.DefaultClient.Do(probe)
	if err != nil {
		t.Fatalf("sqli probe: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("sqli probe status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Trishula-Decision"); got != "enforce" {
		t.Errorf("X-Trishula-Decision = %q, want enforce", got)
	}
	if got := resp.Header.Get("X-Trishula-Rule"); got != "TR08C-001" {
		t.Errorf("X-Trishula-Rule = %q, want TR08C-001", got)
	}
	if string(body) == "upstream-body" {
		t.Error("blocked request must not carry the upstream body")
	}

	benign, _ := http.NewRequest(http.MethodPost, host.URL+"/v1/chat/completions?q=greeting", nil)
	resp2, err := http.DefaultClient.Do(benign)
	if err != nil {
		t.Fatalf("benign probe: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("benign probe status = %d, want 200 (forwarded)", resp2.StatusCode)
	}
	if string(body2) != "upstream-body" {
		t.Errorf("benign probe body = %q, want the upstream body", string(body2))
	}
	if resp2.Header.Get("X-Trishula-Hop") != "engine" {
		t.Error("benign probe must keep the hop marker")
	}
}

// TestEngineHandlerTransparentWithoutBundle: the TR-06 contract intact —
// the handler without --bundle stays the pure transparent proxy (no
// decision consult), so lab/dx1 setup without a bundle degenerates safely.
func TestEngineHandlerTransparentWithoutBundle(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	host := httptest.NewServer(newEngineHandler(upstream.URL, "engine"))
	defer host.Close()

	resp, err := http.Post(host.URL+"/v1/chat/completions?q=UNION%20SELECT", "", nil)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (transparent forward)", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Trishula-Decision"); got != "" {
		t.Errorf("X-Trishula-Decision = %q, want absent without a bundle", got)
	}
}

// TestBuildEngineHandlerBundleLoadFailures: fail closed at load — the
// handler constructor rejects a corrupt bundle (digest mismatch) rather
// than proxying unaudited.
func TestBuildEngineHandlerBundleLoadFailures(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Run("corrupt-bundle", func(t *testing.T) {
		b := compileLabBundle(t)
		var bundle operator.Bundle
		if err := json.Unmarshal(b, &bundle); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		bundle.RulePackDigests[0] = "sha256-deadbeef"
		corrupt, _ := json.Marshal(&bundle)
		if _, err := newEngineHandlerWithBundle(upstream.URL, "engine", corrupt); err == nil {
			t.Fatal("corrupt bundle must fail Load, not proxy unaudited")
		}
	})
}

// Compile-time silence: the eval surface the consult uses (the operator's
// Decide) must accept a request view with Method/Path/Query — the lab's
// SQLi rule keys on request.query. A compile-time reference keeps the
// dependency explicit; context stays unused in tests but the resolver API
// (RulePack(ctx,…)) is exercised in internal/operator tests.
var _ = context.Background
var _ = operator.Load
