// Copyright 2026 OWASP. All rights reserved.
// Use of this source code is governed by the project's BSD-style license
// that can be found in the LICENSE file.
package cel

// TR-198 (issue #240) — the in-engine verifier bundle's unit tests (the
// optional HS256/RS256 verify the operator supplies). The record's
// precondition mapping is the output contract: token_absent /
// token_expired / signature_invalid / issuer_mismatch / audience_mismatch,
// verified=false without claims on every failure.
//
// Tests generate the tokens themselves: the engine never issues tokens.
import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

// rsaHash is the PKCS-1 v1.5 hash the RS256 family verifies with.
const rsaHash = crypto.SHA256

// hsToken signs one compact JWT with an HS256 key.
func hsToken(t *testing.T, secret []byte, head, payload string) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(head)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// hsSecret16 makes a 16-byte random secret.
func hsSecret16(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("random secret: %v", err)
	}
	return raw
}

func TestVerifierHS256RoundTrip(t *testing.T) {
	secret := hsSecret16(t)
	v, err := NewVerifier(VerifierConfig{HS256SecretsHex: []string{hex.EncodeToString(secret)}})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	token := hsToken(t, secret, `{"alg":"HS256","typ":"JWT"}`, `{"sub":"u1","scope":"read:orders","exp":1900000000}`)
	got := v.Verify(token, 1000)
	if !got.Verified {
		t.Fatalf("valid token: got %+v, want verified", got)
	}
	a := got.AuthView()
	if a.Subject != "u1" || len(a.Scopes) != 1 || a.Scopes[0] != "read:orders" || a.ExpiryEpoch != 1900000000 {
		t.Fatalf("claims read: %+v", a)
	}
	// The byte-flip denies.
	bad := []byte(token)
	bad[10] ^= 0x01
	if fail := v.Verify(string(bad), 1000); fail.Verified || fail.Reason != ReasonSignatureInvalid {
		t.Fatalf("tampered token: got %+v, want unverified + signature_invalid", fail)
	}
}

func TestVerifierRS256RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	v, err := NewVerifier(VerifierConfig{RS256PublicPEM: []string{pemKey}})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1"}`))
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, rsaHash, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	if got := v.Verify(token, 1000); !got.Verified || got.AuthView().Subject != "u1" {
		t.Fatalf("RS256 round trip: got %+v, want verified", got)
	}
	// A mismatched key denies.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}))
	v2, err := NewVerifier(VerifierConfig{RS256PublicPEM: []string{otherPEM}})
	if err != nil {
		t.Fatalf("other verifier: %v", err)
	}
	if fail := v2.Verify(token, 1000); fail.Verified || fail.Reason != ReasonSignatureInvalid {
		t.Fatalf("wrong key: got %+v, want unverified", fail)
	}
}

func TestVerifierFailureTokens(t *testing.T) {
	secret := hsSecret16(t)
	v, err := NewVerifier(VerifierConfig{
		HS256SecretsHex: []string{hex.EncodeToString(secret)},
		Issuer:          "https://issuer.example",
		Audiences:       []string{"api"},
		// 10 s leeway: the verifier's own tolerance on exp.
		ExpiryLeewaySec: 10,
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	token := func(payload string) string {
		return hsToken(t, secret, `{"alg":"HS256"}`, payload)
	}
	now := int64(1000)
	cases := []struct {
		name   string
		token  string
		now    int64
		reason string
	}{
		{"absent", "", now, ReasonTokenAbsent},
		{"not-a-jwt", "garbage", now, ReasonSignatureInvalid},
		{"two-segments", "a.b", now, ReasonSignatureInvalid},
		{"unknown-alg", hsToken(t, secret, `{"alg":"none"}`, `{}`), now, ReasonSignatureInvalid},
		{"expired", token(`{"iss":"https://issuer.example","aud":"api","exp":900}`), now, ReasonTokenExpired},
		{"issuer-mismatch", token(`{"iss":"https://other.example","aud":"api","exp":1900}`), now, ReasonIssuerMismatch},
		{"audience-mismatch", token(`{"iss":"https://issuer.example","aud":"other","exp":1900}`), now, ReasonAudienceMismatch},
		{"audience-missing", token(`{"iss":"https://issuer.example","exp":1900}`), now, ReasonAudienceMismatch},
		{"valid-inside-leeway", token(`{"iss":"https://issuer.example","aud":"api","exp":991}`), now, ""},
		{"leeway-off-by-one", token(`{"iss":"https://issuer.example","aud":"api","exp":990}`), now, ReasonTokenExpired},
	}
	for _, tc := range cases {
		got := v.Verify(tc.token, tc.now)
		if tc.reason == "" {
			if !got.Verified {
				t.Errorf("[%s] got %+v, want verified", tc.name, got)
			}
			continue
		}
		if got.Verified || got.Reason != tc.reason {
			t.Errorf("[%s] got %+v, want unverified + %q", tc.name, got, tc.reason)
		}
		if len(got.Claims) > 0 {
			t.Errorf("[%s] a failed check carries claims (%v): never — the claims set stays out", tc.name, got.Claims)
		}
	}
}

func TestVerifierConfigErrors(t *testing.T) {
	cases := []VerifierConfig{
		{},                                // no keys
		{HS256SecretsHex: []string{"zz"}}, // not hex
		{HS256SecretsHex: []string{""}},   // empty key
		{RS256PublicPEM: []string{"not a pem"}},
	}
	for i, cfg := range cases {
		if _, err := NewVerifier(cfg); err == nil {
			t.Errorf("case %d: config accepted (want a fail-closed error)", i)
		}
	}
}

func TestResolveIdentityOrder(t *testing.T) {
	secret := hsSecret16(t)
	bundle, err := NewVerifier(VerifierConfig{HS256SecretsHex: []string{hex.EncodeToString(secret)}})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	channel := &VerifiedIdentity{Verified: true, Claims: map[string]any{"sub": "channel"}}
	// 1. The channel wins over the bundle.
	a := ResolveIdentity(channel, bundle, "ignored", 1000)
	if a.Subject != "channel" {
		t.Fatalf("channel-first: got %+v, want the channel's subject", a)
	}
	// 2. The bundle verifies the token (a good token beats the miss).
	tok := hsToken(t, secret, `{"alg":"HS256"}`, `{"sub":"u2"}`)
	a = ResolveIdentity(nil, bundle, tok, 1000)
	if a.Subject != "u2" {
		t.Fatalf("bundle-verify: got %+v, want the bundle subject", a)
	}
	// 3. A FAILED bundle verify reads the unverified zero (the record's
	//    gate does not read true past a failed precondition).
	a = ResolveIdentity(nil, bundle, "broken.token.here", 1000)
	if a.Verified || a.Subject != "" {
		t.Fatalf("failed verify: got %+v, want the zero", a)
	}
	// 4. A bundle set + NO token reads the miss (unverified).
	a = ResolveIdentity(nil, bundle, "", 1000)
	if a.Verified {
		t.Fatalf("no token: got %+v, want the unverified zero", a)
	}
	// 5. No source at all = the sanitised zero.
	a = ResolveIdentity(nil, nil, "", 1000)
	if a.Verified || a.Claims == nil {
		t.Fatalf("no source: got %+v, want the sanitised zero", a)
	}
}

// TestVerifierPayloadAudienceList: a token audience in list form matches
// the pin set (the aud claim's list shape).
func TestVerifierPayloadAudienceList(t *testing.T) {
	secret := hsSecret16(t)
	bundle, err := NewVerifier(VerifierConfig{HS256SecretsHex: []string{hex.EncodeToString(secret)}, Audiences: []string{"api"}})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	tok := hsToken(t, secret, `{"alg":"HS256"}`, `{"aud":["api","other"]}`)
	if got := bundle.Verify(tok, 1000); !got.Verified {
		t.Fatalf("list audience: got %+v, want verified", got)
	}
}

// TestExpiryMissingStaysVerified: a token without exp stays verifiable —
// the registered claims are the verifier's checks against its config; this
// bundle pins none for exp beyond the present-value compare at the leeway.
func TestVerifierExpiryMissingStaysVerified(t *testing.T) {
	secret := hsSecret16(t)
	bundle, err := NewVerifier(VerifierConfig{HS256SecretsHex: []string{hex.EncodeToString(secret)}})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	got := bundle.Verify(hsToken(t, secret, `{"alg":"HS256"}`, `{"sub":"u1"}`), 1000)
	if !got.Verified {
		t.Fatalf("exp-free token: got %+v, want verified", got)
	}
}
