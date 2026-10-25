// Copyright 2026 OWASP. All rights reserved.
// Use of this source code is governed by the project's BSD-style license
// that can be found in the LICENSE file.
package ladder

// TR-198 (issue #240) — the S3 claims-stage unit tests beside the
// conformance walk: the channel pair, the bundle path on the ladder, the
// wiring errors and the shadow-posture pin over the composed stage.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

func TestAttachVerifiedIdentityRoundTrip(t *testing.T) {
	tx := &ingest.TxContext{Metadata: map[string]string{}}
	vi := &cel.VerifiedIdentity{Verified: true, Claims: map[string]any{"sub": "u1"}}
	if err := AttachVerifiedIdentity(tx, vi); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got := VerifiedIdentityFrom(tx)
	if got == nil || !got.Verified || got.AuthView().Subject != "u1" {
		t.Fatalf("readback: got %+v, want the attached identity", got)
	}
	if err := AttachVerifiedIdentity(&ingest.TxContext{}, nil); err == nil {
		t.Error("a nil identity attach must error (wiring)")
	}
}

func TestVerifiedIdentityMissStaysNil(t *testing.T) {
	// No channel slot: nil.
	if got := VerifiedIdentityFrom(&ingest.TxContext{}); got != nil {
		t.Fatalf("a channel-less tx reads %+v, want nil", got)
	}
	// Unusable bytes: nil (the miss; never a fabricated identity).
	tx := &ingest.TxContext{Metadata: map[string]string{verifiedIdentityMetaKey: "{not json"}}
	if got := VerifiedIdentityFrom(tx); got != nil {
		t.Fatalf("unusable channel bytes read %+v, want nil", got)
	}
}

func TestAuthCLEmptyPackWiringError(t *testing.T) {
	if _, err := NewAuthCEL(nil); err == nil {
		t.Error("a nil pack must reject at wiring")
	}
	if _, err := NewAuthCEL(&cel.RulePack{}); err == nil {
		t.Error("an empty pack must reject at wiring")
	}
}

// authBundlePackYaml is the bundle-carrying pack fixture: the HS256 key rides
// the pack's verifier block; the deny rule gates /orders/* on the
// membership read.
const authBundlePackYaml = `
verifier:
  hs256SecretsHex:
    - e0124a6fbc2d1e0d8f1cfdbb6a41cbfc
rules:
  - id: auth:scope_insufficient
    name: orders-read-claims-gate
    description: gates /orders/* on verified + read:orders
    action: enforce
    expression: |
      path.matches("/orders/*") &&
      (!request.auth.verified || !("read:orders" in request.auth.scopes))
`

// TestAuthCELBundleVerifiesBearerOnWalk: no channel metadata — the pack's
// verifier bundle is the fallback source; a valid bearer token admits, a
// broken one gates the allow path.
func TestAuthCELBundleVerifiesBearerOnWalk(t *testing.T) {
	t.Helper()
	pack, err := cel.ParseRulePack([]byte(authBundlePackYaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stage, err := NewAuthCEL(pack)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	secret := mustUnhex(t, "e0124a6fbc2d1e0d8f1cfdbb6a41cbfc")
	good := hsFixtureToken(t, secret, `{"sub":"u1","scope":"read:orders"}`)

	e := NewEngine()
	if err := e.Use(StageKernel, NewKernelHits(newShieldAdapterState().checker)); err != nil {
		t.Fatalf("wire S0: %v", err)
	}
	if err := e.Use(StageCEL, stage); err != nil {
		t.Fatalf("wire the S3 stage: %v", err)
	}
	newTx := func(token string) *ingest.TxContext {
		tx := &ingest.TxContext{Key: ingest.FlowKey{Family: ingest.FamilyV4}, Metadata: map[string]string{}}
		if err := AttachView(tx, &cel.Request{Method: "GET", Path: "/orders/7"}); err != nil {
			t.Fatalf("attach view: %v", err)
		}
		if token != "" {
			tx.Metadata[bearerHeaderMetaKey] = "Bearer " + token
		}
		return tx
	}
	cases := []struct {
		name       string
		token      string
		wantAction Action
	}{
		{"good-bearer-admits", good, ActionAllow},
		{"no-bearer-denies", "", ActionBlock},
		{"broken-bearer-denies", "x.y.z", ActionBlock},
	}
	for _, tc := range cases {
		tx := newTx(tc.token)
		v := e.EvaluateTx(tx)
		if v.Action != tc.wantAction {
			t.Errorf("[%s] action: got %q, want %q", tc.name, v.Action, tc.wantAction)
		}
		if tc.wantAction == ActionBlock {
			if len(v.Rules) != 1 || v.Rules[0] != RuleID("auth:scope_insufficient") {
				t.Errorf("[%s] rules: got %v, want [auth:scope_insufficient]", tc.name, v.Rules)
			}
		} else if len(v.Rules) != 0 {
			t.Errorf("[%s] admitted walk carries no rule ids: got %v", tc.name, v.Rules)
		}
	}
}

// TestAuthCELShadowPostureStaysLog: the seed log-shape through the auth
// stage stays the log fold (the shadow posture; the promotion is the
// enforce declaration, the record's lifecycle).
func TestAuthCELShadowPostureStaysLog(t *testing.T) {
	pack, err := cel.ParseRulePack([]byte(seedRuleYaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stage, err := NewAuthCEL(pack)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	tx := &ingest.TxContext{Key: ingest.FlowKey{Family: ingest.FamilyV4}, Metadata: map[string]string{}}
	if err := AttachView(tx, &cel.Request{
		Method: "POST", Path: "/v1/chat/completions",
		RateWindows: map[string]cel.RateWindow{"5m": {Requests: 41}},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	frag := stage.Evaluate(tx)
	if frag == nil {
		t.Fatal("the matching seed rule produced no fragment")
	}
	if frag.Action != ActionLog || len(frag.Rules) != 1 || frag.Rules[0] != "seed-rate-shape" {
		t.Fatalf("shadow posture: got %+v (action %q), want log with [seed-rate-shape]", frag, frag.Action)
	}
}

// TestAuthCELErrorEvidenceStaysEvidence: an eval error inside the pack
// stays the :error evidence (never a claim decision).
func TestAuthCELErrorEvidenceStaysEvidence(t *testing.T) {
	badPack := `
rules:
  - id: auth:broken
    action: enforce
    expression: request.method == 42 && nonexistent_function()
`
	pack, err := cel.ParseRulePack([]byte(badPack))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stage, err := NewAuthCEL(pack)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	tx := &ingest.TxContext{Key: ingest.FlowKey{Family: ingest.FamilyV4}, Metadata: map[string]string{}}
	if err := AttachView(tx, &cel.Request{Method: "GET", Path: "/orders/1"}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	frag := stage.Evaluate(tx)
	if frag == nil {
		t.Fatal("the error rule produced no evidence fragment")
	}
	if frag.Action == ActionBlock {
		t.Fatal("eval error evidence must never become the decisive block (fail safe)")
	}
	if len(frag.Rules) != 1 || !strings.HasSuffix(string(frag.Rules[0]), ":error") {
		t.Fatalf("evidence ids: got %v, want the :error suffix", frag.Rules)
	}
}

// --- fixture helpers ----------------------------------------------------

func mustUnhex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		t.Fatalf("hex fixture: %v", err)
	}
	return raw
}

// hsFixtureToken signs a compact HS256 JWT the fixture bundle verifies.
func hsFixtureToken(t *testing.T, secret []byte, payload string) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
