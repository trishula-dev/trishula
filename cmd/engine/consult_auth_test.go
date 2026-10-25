// Copyright 2026 OWASP. All rights reserved.
// Use of this source code is governed by the project's BSD-style license
// that can be found in the LICENSE file.
package main

// TR-198 (issue #240) — the consult surface carries the request.auth
// vocabulary end to end over HTTP: the bundle's verifier verifies the
// Authorization header's bearer token, then Decide applies the claims
// gate. The receipt: no token → 403 block; an unscoped token → 403 block;
// a scoped token → 200 forward.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/operator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// authConsultPackYAML is the fixture pack: the HS256 bundle + the deny rule
// over /orders/* (the record's S3 example, membership form).
const authConsultPackYAML = `
verifier:
  hs256SecretsHex:
    - 7db1b6ac2f0e39c74e6b2f9a551d0c48
rules:
  - id: auth:scope_insufficient
    name: orders-read-claims-gate
    description: gates /orders/* on verified + read:orders
    action: enforce
    expression: |
      path.matches("/orders/*") &&
      (!request.auth.verified || !("read:orders" in request.auth.scopes))
`

// compileAuthBundle compiles the consult policy with the auth pack (real
// Compile output; the seed pack rides every bundle).
func compileAuthBundle(t *testing.T) []byte {
	t.Helper()
	pack, err := cel.ParseRulePack([]byte(authConsultPackYAML))
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	policy := v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "dx1-auth", Namespace: "dx1"},
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
		t.Fatalf("marshal bundle: %v", err)
	}
	return b
}

// hsBearerToken signs the test's bearer token (the engine never issues).
func hsBearerToken(t *testing.T, keyHex, payload string) string {
	t.Helper()
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	in := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TestConsultAuthGateEndToEnd: one engine host, the bundle's verifier + the
// claims gate over HTTP.
func TestConsultAuthGateEndToEnd(t *testing.T) {
	const keyHex = "7db1b6ac2f0e39c74e6b2f9a551d0c48"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	bundle := compileAuthBundle(t)
	eng, err := newEngineHandlerWithBundle(upstream.URL, "engine", bundle, nil)
	if err != nil {
		t.Fatalf("build engine handler: %v", err)
	}
	host := httptest.NewServer(eng)
	defer host.Close()

	scoped := hsBearerToken(t, keyHex, `{"sub":"u1","scope":"read:orders"}`)
	unscoped := hsBearerToken(t, keyHex, `{"sub":"u2","scope":"read:chat"}`)
	broke := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u3"}`)) + "." + "bad-sig"
	cases := []struct {
		name   string
		token  string
		status int
		rule   string
	}{
		{"no-token-blocks", "", http.StatusForbidden, "auth:scope_insufficient"},
		{"broken-token-blocks", broke, http.StatusForbidden, "auth:scope_insufficient"},
		{"unscoped-token-blocks", unscoped, http.StatusForbidden, "auth:scope_insufficient"},
		{"scoped-token-forwards", scoped, http.StatusOK, ""},
	}
	for _, tc := range cases {
		probe, _ := http.NewRequest(http.MethodGet, host.URL+"/orders/7", nil)
		if tc.token != "" {
			probe.Header.Set("Authorization", "Bearer "+tc.token)
		}
		resp, err := http.DefaultClient.Do(probe)
		if err != nil {
			t.Fatalf("[%s] probe: %v", tc.name, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("[%s] status: got %d, want %d (verified=false must gate the allow path)", tc.name, resp.StatusCode, tc.status)
		}
		if got := resp.Header.Get("X-Trishula-Decision"); tc.rule != "" && got != "block" {
			t.Errorf("[%s] X-Trishula-Decision: got %q, want block", tc.name, got)
		}
		if got := resp.Header.Get("X-Trishula-Rule"); got != tc.rule {
			t.Errorf("[%s] X-Trishula-Rule: got %q, want %q", tc.name, got, tc.rule)
		}
		resp.Body.Close()
	}
}
