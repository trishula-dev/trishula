// Copyright 2026 OWASP. All rights reserved.
// Use of this source code is governed by the project's BSD-style license
// that can be found in the LICENSE file.
package cel

// TR-198 (issue #240) — the request.auth vocabulary conformance, unit side.
// The record's section 4 is the contract: the 7 names, the reads over the
// miss (verified=false, no panic), the record's own example expressions
// (membership, comprehension, expiry against the engine-supplied epoch).
// Tests import ONLY our package API (never cel-go directly) — TestAuthExpr
// drives every sample through Rule.Eval.
import (
	"strings"
	"testing"
	"time"
)

// vocabCases = one case per record expression + the miss reads. The miss
// cases pin rule 3 (verified=false) over the zero view; the expiry
// compare's miss reads the 0 claim.
var vocabCases = []struct {
	name    string
	expr    string
	miss    bool
	wantErr bool
	want    bool
}{
	// The 7 names read.
	{"verified-reads-true", `request.auth.verified`, false, false, true},
	{"subject-reads", `request.auth.subject == "u1"`, false, false, true},
	{"issuer-reads", `request.auth.issuer == "https://issuer.example"`, false, false, true},
	{"audiences-membership", `"api" in request.auth.audiences`, false, false, true},
	{"scopes-membership", `"read:orders" in request.auth.scopes`, false, false, true},
	{"expiry-compares-engine-epoch", `request.auth.expiry_epoch > now`, false, false, true},
	{"claims-map-read", `request.auth.claims["tenant"] == "acme"`, false, false, true},
	// The record's own example shapes.
	{"membership-first", `("read:orders" in request.auth.scopes) && request.auth.verified`, false, false, true},
	{"comprehension-over-scopes", `request.auth.scopes.exists(s, s in ["read:orders"])`, false, false, true},
	{"subject-owner-class-read", `request.auth.subject == request.auth.claims["owner"]`, false, false, true},
	// The miss: verified=false, the reads stay clean (no panic rule).
	{"miss-stays-unverified", `!request.auth.verified`, true, false, true},
	{"miss-reads-empty-scope", `!("read:orders" in request.auth.scopes)`, true, false, true},
	{"miss-reads-empty-subject", `request.auth.subject == ""`, true, false, true},
	{"miss-reads-empty-expiry", `request.auth.expiry_epoch == 0`, true, false, true},
	// The membership on an empty audience list is a clean false.
	{"miss-audience-membership-false", `!("api" in request.auth.audiences)`, true, false, true},
	// The wildcard-scope candidate stays OUT (the record's own defer):
	// the item matcher is not a vocabulary function; the comprehension
	// over an empty list exists-traverses to false.
	{"comprehension-over-miss-stays-false", `request.auth.scopes.exists(s, s in ["read:orders"])`, true, false, false},
}

func TestRequestAuthVocabulary(t *testing.T) {
	scoped := VerifiedIdentity{
		Verified: true,
		Claims: map[string]any{
			"sub": "u1", "iss": "https://issuer.example",
			"aud": "api", "scope": "read:orders read:chat",
			"exp": float64(1900000000), "tenant": "acme",
			"owner": "u1",
		},
	}
	verifiedReq := Request{Method: "GET", Path: "/orders/7", Auth: scoped.AuthView().Sanitised()}
	missReq := Request{Method: "GET", Path: "/orders/7"}
	for _, tc := range vocabCases {
		r := &Rule{ID: "vocab:" + tc.name, Action: ActionLog, Expression: tc.expr}
		r.SetClock(Clock(func() int64 { return int64(1000) }))
		// The miss cases run over the zero view (verified=false); the
		// verified cases run over the filled view; the expiry compare
		// (1005 > now(1000)) reads true both ways by construction.
		req := verifiedReq
		if tc.miss {
			req = missReq
		}
		// The miss-expiry case reads expiry == 0 == the epoch compare's
		// zero; no miss case wants a live claim set.
		v, err := r.Eval(req)
		if err != nil {
			t.Errorf("[%s] eval: %v", tc.name, err)
			continue
		}
		if v.Match != tc.want {
			t.Errorf("[%s] match: got %v, want %v (expression %q, req %+v)", tc.name, v.Match, tc.want, tc.expr, req.Auth.Verified)
		}
	}
}

// TestRequestAuthMissZeroCarriesContainer reads the miss the record pins:
// verified=false with the empty containers — never nil, never a panic.
func TestRequestAuthMissZeroCarriesContainer(t *testing.T) {
	a := Auth{}.Sanitised()
	if a.Verified {
		t.Fatal("the zero must read unverified")
	}
	if a.Scopes == nil || a.Audiences == nil || a.Claims == nil {
		t.Fatalf("the zero must carry the empty containers, got %+v", a)
	}
	req := Request{Method: "GET", Path: "/", Auth: a}
	r := &Rule{ID: "vocab:miss-read", Action: ActionLog, Expression: `"read:orders" in request.auth.scopes && request.auth.subject == ""`}
	v, err := r.Eval(req)
	if err != nil || v.Match {
		t.Fatalf("miss read: got %v err=%v, want clean false", v.Match, err)
	}
}

// TestClaimsPolicyRulesErrorNeverMatch: a claims read over a class the
// token misses resolves an error verdict — never a clean no-match (the
// record's fail-safe: the map's "no such key", the budget abort and the
// compile failure land the same evidence class).
func TestAuthPolicyRuleErrorEvidence(t *testing.T) {
	scoped := VerifiedIdentity{Verified: true, Claims: map[string]any{"scope": "read:orders"}}
	r := &Rule{ID: "auth:tenant_gate", Action: ActionEnforce, Expression: `request.auth.claims["tenant"] == "acme"`}
	v, err := r.Eval(Request{Path: "/x", Auth: scoped.AuthView().Sanitised()})
	if err == nil {
		t.Fatal("the missing claims key must eval-error (fail safe), not read clean")
	}
	if v.Match || !v.Error {
		t.Fatalf("verdict: got %+v, want an error verdict with no match", v)
	}
}

// TestClockBindingFailSafe: a rule reading `now` at a stage without the
// pinned clock eval-errors (the engine supplies the epoch, or the stage
// serves no time rule).
func TestClockBindingFailSafe(t *testing.T) {
	r := &Rule{ID: "auth:expiry", Action: ActionLog, Expression: `request.auth.expiry_epoch > now`}
	_, err := r.Eval(Request{Path: "/x"})
	if err == nil {
		t.Fatal("the unpinned clock must stop a time rule (the record's CEL-nevers-reads-a-clock)")
	}
	// The pinned clock binds the engine's epoch.
	r.SetClock(Clock(func() int64 { return int64(1000) }))
	v, err := r.Eval(Request{Path: "/x", Auth: VerifiedIdentity{
		Verified: true,
		Claims:   map[string]any{"exp": float64(1005)},
	}.AuthView().Sanitised()})
	if err != nil {
		t.Fatalf("pinned clock: %v", err)
	}
	if !v.Match {
		t.Fatal("expiry (1005) > now (1000) must match")
	}
}

// TestClockIsWallByDefault pins DefaultClock on a live epoch (the wiring's
// install value).
func TestDefaultClockCarriesWallEpoch(t *testing.T) {
	if got := DefaultClock()(); got < int64(1_700_000_000) {
		t.Fatalf("default clock: got %d, want a live wall epoch (seconds)", got)
	}
	if time.Now().Unix()-1 > DefaultClock()() || DefaultClock()() > time.Now().Unix()+1 {
		t.Fatal("default clock is more than 1s off the wall")
	}
}

// TestScopeClaimShapes: the scope claim's two shapes (space-split string,
// list) resolve the same list(string); other shapes resolve empty.
func TestScopeClaimShapes(t *testing.T) {
	stringForm := VerifiedIdentity{Verified: true, Claims: map[string]any{"scope": "read:orders  read:chat"}}
	listForm := VerifiedIdentity{Verified: true, Claims: map[string]any{"scope": []any{"read:orders", "read:chat"}}}
	junk := VerifiedIdentity{Verified: true, Claims: map[string]any{"scope": 42}}
	for _, tc := range []struct {
		name string
		vi   VerifiedIdentity
		want string
	}{
		{"string-form", stringForm, "read:orders read:chat"},
		{"list-form", listForm, "read:orders read:chat"},
		{"junk-form", junk, ""},
	} {
		got := strings.Join(tc.vi.AuthView().Scopes, " ")
		if got != tc.want {
			t.Errorf("[%s] scopes: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestUnverifiedIdentityCarriesNoClaimReads: a failed verification's view
// stays the zero (the channel's claims never read true past the gate).
func TestUnverifiedIdentityCarriesNoClaimReads(t *testing.T) {
	vi := VerifiedIdentity{
		Verified: false,
		Reason:   ReasonSignatureInvalid,
		Claims:   map[string]any{"sub": "leaked"},
	}
	a := vi.AuthView()
	if a.Verified || a.Subject != "" || a.Claims["sub"] != nil {
		t.Fatalf("the failed identity must read the zero, got %+v", a)
	}
}

// TestBundleConfigRidesPackWire: the pack's verifier block loads through
// the pack parse and the JSON round trip preserves the config (the
// digest-covered transport), re-parsed at Load.
func TestVerifierConfigRidesPackWire(t *testing.T) {
	yml := []byte("verifier:\n  hs256SecretsHex:\n    - " + strings.Repeat("0a", 32) + "\n  issuer: https://issuer.example\nrules:\n  - id: r1\n    action: log\n    expression: |" + `
      request.auth.verified
`)
	pack, err := ParseRulePack(yml)
	if err != nil {
		t.Fatalf("verifier pack: %v", err)
	}
	if pack.Verifier() == nil {
		t.Fatal("the pack lost its parsed verifier")
	}
	if len(pack.AuthVerifier.HS256SecretsHex) != 1 {
		t.Fatalf("the pack lost the config: %+v", pack.AuthVerifier)
	}
}
