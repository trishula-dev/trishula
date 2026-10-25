// Copyright 2026 OWASP. All rights reserved.
// Use of this source code is governed by the project's BSD-style license
// that can be found in the LICENSE file.
package cel

// TR-198 (issue #240) — the request.auth vocabulary and the claims surface.
// Source of truth: docs/design/auth-jwt-verdict.md (the TR-45 record),
// adopted as written:
//
//   - the verifier stays external; Trishula references claims and stores
//     nothing (§6.3 the vault boundary — TR-91 census: spec citation in the
//     comment body; kept verbatim, the conversion would renumber);
//   - S3 is the one claims-policy stage (after the CRS short-circuit, before
//     schema gating, §11.3);
//   - the vocabulary names are the record's 7 fields (section 4): 1 name per
//     claim class, no speculative field;
//   - the engine fills the names from the precondition channel only: the
//     gateway's verified identity metadata. The authorization header
//     carries the token bytes to the verifier; it never reads as a claim
//     source. The optional in-engine HS256/RS256 verifier bundle is the
//     second source: the operator supplies it and the engine verifies the
//     bearer token itself;
//   - the engine leaves request.auth.verified = false when the precondition
//     misses or fails. CEL reads the miss; no rule panics;
//   - CEL never reads a clock: rules compare request.auth.expiry_epoch
//     against the engine-supplied epoch (the rule-level Clock, the "now"
//     binding).
//
// The two sources compose in one order: the gateway's verified identity
// metadata wins when the channel carries it (the gateway is the upstream
// verifier, the record's owner); the in-engine bundle is the fallback. One
// decision, ResolveIdentity, both transports share it.

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Auth is the request.auth vocabulary of the claims policy (the record's
// section 4, the 7 names, adopted as written). The struct is the native CEL
// value under request.auth (the RateWindow pattern: the cel tag carries the
// spec's lowercase name; the yaml/json tags keep the fixture + wire decodes
// aligned with the same names).
type Auth struct {
	// Verified gates every allow path. The engine fills it false when the
	// precondition misses or fails; CEL reads the miss.
	Verified bool `yaml:"verified" json:"verified" cel:"verified"`
	// Subject is the sub claim.
	Subject string `yaml:"subject" json:"subject" cel:"subject"`
	// Issuer is the iss claim.
	Issuer string `yaml:"issuer" json:"issuer" cel:"issuer"`
	// Audiences is the aud claim (list(string)). Empty, never nil: the
	// membership read stays a clean false on the miss.
	Audiences []string `yaml:"audiences" json:"audiences" cel:"audiences"`
	// Scopes is the scope claim (list(string)): the string claim splits on
	// spaces; the list claim lists. Empty, never nil.
	Scopes []string `yaml:"scopes" json:"scopes" cel:"scopes"`
	// ExpiryEpoch is the exp claim in epoch seconds. CEL comparisons read it
	// against the engine-supplied epoch ("now"); CEL never reads a clock.
	ExpiryEpoch int64 `yaml:"expiry_epoch" json:"expiry_epoch" cel:"expiry_epoch"`
	// Claims is the raw claim map (map(string, dyn)): tenant names and the
	// classes beyond the named reads stay visible through it. Auth-failure
	// verdict records carry claim names, never claim values (§15.4).
	Claims map[string]any `yaml:"claims" json:"claims" cel:"claims"`
}

// sanitised returns the zero-safe copy: the empty containers stand in for
// nil, so every CEL read over a miss stays a clean value read (the record's
// no-panic rule), never a nil dereference error.
func (a Auth) Sanitised() Auth {
	if a.Audiences == nil {
		a.Audiences = []string{}
	}
	if a.Scopes == nil {
		a.Scopes = []string{}
	}
	if a.Claims == nil {
		a.Claims = map[string]any{}
	}
	return a
}

// verifiedIdentityReason tokens are the record's precondition words
// (the auth:<condition> taxonomy): the tokens the precondition (the
// verifier) emits; the S3 CEL view reads the vocabulary names only.
const (
	ReasonTokenAbsent      = "token_absent"
	ReasonTokenExpired     = "token_expired"
	ReasonSignatureInvalid = "signature_invalid"
	ReasonIssuerMismatch   = "issuer_mismatch"
	ReasonAudienceMismatch = "audience_mismatch"
)

// VerifiedIdentity is the precondition channel's one unit: the verified
// identity metadata the gateway attaches (the gateway's own verifier owns
// the signature and the registered claims against its config). The engine
// never re-verifies this channel and never reads the token bytes back out
// of it; a failed verification travels as verified=false plus the reason.
type VerifiedIdentity struct {
	// Verified is the channel's own verification result.
	Verified bool `yaml:"verified" json:"verified"`
	// Reason is the precondition's reason token on a failed verification
	// (empty when Verified). The S3 vocabulary does not carry it: the
	// verdict-record mapping owns the tokens (the stage-stamp naming is
	// TR-47's record).
	Reason string `yaml:"reason,omitempty" json:"reason,omitempty"`
	// Claims is the raw claim map the verifier resolved. Unverified
	// identities carry no claims; the view stays empty (fail safe).
	Claims map[string]any `yaml:"claims,omitempty" json:"claims,omitempty"`
}

// AuthView builds the request.auth vocabulary view from the channel unit:
// the verified read fills the names; the miss stays verified=false with
// empty reads (the record's zeroed miss, not an error).
func (v VerifiedIdentity) AuthView() Auth {
	if !v.Verified {
		return Auth{}.Sanitised()
	}
	a := Auth{Verified: true, Claims: v.Claims}
	a.Subject = stringClaim(a.Claims, "sub")
	a.Issuer = stringClaim(a.Claims, "iss")
	a.Audiences = stringListClaim(a.Claims, "aud")
	a.Scopes = splitScopeClaim(a.Claims)
	a.ExpiryEpoch = intClaim(a.Claims, "exp")
	return a.Sanitised()
}

// stringClaim reads a string claim (empty on any other shape).
func stringClaim(claims map[string]any, name string) string {
	switch v := claims[name].(type) {
	case string:
		return v
	}
	return ""
}

// stringListClaim reads a claim as list(string): a string stays a one-item
// list; a list keeps its string items (the aud claim's two shapes).
func stringListClaim(claims map[string]any, name string) []string {
	switch v := claims[name].(type) {
	case string:
		if v == "" {
			return []string{}
		}
		return []string{v}
	case []string:
		return append([]string{}, v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{}
}

// splitScopeClaim reads the scope claim: the string form splits on spaces
// (the scope-space convention); the list form lists. Empty on anything else.
func splitScopeClaim(claims map[string]any) []string {
	fields := stringListClaim(claims, "scope")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, strings.Fields(f)...)
	}
	return out
}

// intClaim reads a numeric claim (json numbers decode as float64) into an
// int64 (0 on any other shape).
func intClaim(claims map[string]any, name string) int64 {
	switch v := claims[name].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

// VerifierConfig is the operator's verifier bundle (the record's optional
// in-engine HS256/RS256 verify): the keys, the issuer/audience
// expectations and the expiry leeway. The claim of §8.3 holds: the bundle
// verifies tokens; it never fetches JWKS inline with request evaluation.
type VerifierConfig struct {
	// HS256SecretsHex are the shared secrets in hex (one byte run each;
	// any key matching verifies).
	HS256SecretsHex []string `yaml:"hs256SecretsHex" json:"hs256SecretsHex,omitempty"`
	// RS256PublicPEM are the RS256 public keys in PEM (PKIX or PKCS-1 form).
	RS256PublicPEM []string `yaml:"rs256PublicPEM" json:"rs256PublicPEM,omitempty"`
	// Issuer pins the iss claim (empty = no pin).
	Issuer string `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	// Audiences pin the aud claim: a token must carry at least one of them
	// (empty = no pin).
	Audiences []string `yaml:"audiences,omitempty" json:"audiences,omitempty"`
	// ExpiryLeewaySec tolerates epochs (the verifier's own clock duty; the
	// CEL view stays clock-free). 0 = strict.
	ExpiryLeewaySec int64 `yaml:"expiryLeewaySec,omitempty" json:"expiryLeewaySec,omitempty"`
}

// Verifier is the parsed bundle: the keys decoded once, the checks on
// every Verify. Not goroutine-safe for config edits; Verify takes only
// immutable state. TR-04 ingest owns the concurrency decision.
type Verifier struct {
	cfg   VerifierConfig
	hs256 [][]byte
	rs256 []*rsa.PublicKey
}

// NewVerifier parses the bundle once (fail closed: an unparsable key is a
// config error, never a per-request surprise). A bundle with no keys is an
// error — a silent keyless verifier would verify nothing and read verified.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	v := &Verifier{cfg: cfg}
	for i, sh := range cfg.HS256SecretsHex {
		raw, err := hex.DecodeString(strings.TrimSpace(sh))
		if err != nil {
			return nil, fmt.Errorf("verifier: hs256 secret %d is not hex: %w", i, err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("verifier: hs256 secret %d is empty", i)
		}
		v.hs256 = append(v.hs256, raw)
	}
	for i, pel := range cfg.RS256PublicPEM {
		key, err := parseRS256PublicPEM(pel)
		if err != nil {
			return nil, fmt.Errorf("verifier: rs256 key %d: %w", i, err)
		}
		v.rs256 = append(v.rs256, key)
	}
	if len(v.hs256) == 0 && len(v.rs256) == 0 {
		return nil, errors.New("verifier: no keys (hs256SecretsHex and rs256PublicPEM both empty)")
	}
	return v, nil
}

// parseRS256PublicPEM decodes one PEM key (PKIX first, then PKCS-1).
func parseRS256PublicPEM(pel string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pel))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if pk, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rk, ok := pk.(*rsa.PublicKey); ok {
			return rk, nil
		}
		return nil, fmt.Errorf("PKIX key is %T, want an RSA public key", pk)
	}
	rk, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("neither PKIX nor PKCS-1 form: %w", err)
	}
	return rk, nil
}

// Verify checks one compact-JWT token against the bundle's keys and the
// configured expectations at now (epoch seconds). The rule is the record's
// precondition mapping: token absent/expired, signature invalid, issuer
// mismatch, audience mismatch. The return never panics and never carries a
// claim set on a failure (verified=false, the reason token, no claims).
func (v *Verifier) Verify(token string, now int64) VerifiedIdentity {
	if v == nil {
		return VerifiedIdentity{Reason: ReasonTokenAbsent}
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return VerifiedIdentity{Reason: ReasonTokenAbsent}
	}
	seg := strings.Split(token, ".")
	if len(seg) != 3 {
		return VerifiedIdentity{Reason: ReasonSignatureInvalid}
	}
	signingInput := seg[0] + "." + seg[1]
	hdr, err := decodeSegment(seg[0])
	if err != nil {
		return VerifiedIdentity{Reason: ReasonSignatureInvalid}
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdr, &h) != nil || h.Alg == "" {
		return VerifiedIdentity{Reason: ReasonSignatureInvalid}
	}
	sig, err := base64.RawURLEncoding.DecodeString(seg[2])
	if err != nil {
		return VerifiedIdentity{Reason: ReasonSignatureInvalid}
	}
	claims, err := decodeSegment(seg[1])
	if err != nil {
		return VerifiedIdentity{Reason: ReasonSignatureInvalid}
	}
	var payload map[string]any
	if json.Unmarshal(claims, &payload) != nil || payload == nil {
		payload = map[string]any{}
	}
	digest := sha256.Sum256([]byte(signingInput))
	switch h.Alg {
	case "HS256":
		ok := false
		for _, key := range v.hs256 {
			sum := hmac.New(sha256.New, key)
			sum.Write([]byte(signingInput))
			if hmac.Equal(sum.Sum(nil), sig) {
				ok = true
				break
			}
		}
		if !ok {
			return VerifiedIdentity{Reason: ReasonSignatureInvalid}
		}
	case "RS256":
		ok := false
		for _, key := range v.rs256 {
			if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil {
				ok = true
				break
			}
		}
		if !ok {
			return VerifiedIdentity{Reason: ReasonSignatureInvalid}
		}
	default:
		// No other family verifies (the record's HS256/RS256 bundle;
		// ES256/EdDSA stay the external verifier's surface — §9.1 no
		// kernel crypto stays outside this decision either).
		return VerifiedIdentity{Reason: ReasonSignatureInvalid}
	}
	if exp := intClaim(payload, "exp"); exp > 0 && exp+v.cfg.ExpiryLeewaySec <= now {
		return VerifiedIdentity{Reason: ReasonTokenExpired}
	}
	if v.cfg.Issuer != "" {
		if iss, _ := payload["iss"].(string); iss != v.cfg.Issuer {
			return VerifiedIdentity{Reason: ReasonIssuerMismatch}
		}
	}
	if len(v.cfg.Audiences) > 0 {
		tokAud := stringListClaim(payload, "aud")
		found := false
		for _, want := range v.cfg.Audiences {
			for _, got := range tokAud {
				if got == want {
					found = true
					break
				}
			}
		}
		if !found {
			return VerifiedIdentity{Reason: ReasonAudienceMismatch}
		}
	}
	return VerifiedIdentity{Verified: true, Claims: payload}
}

// decodeSegment decodes one unpadded base64url JWT segment.
func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

// ResolveIdentity is the ONE claim-source decision both transports share:
// the gateway's verified identity metadata first (the channel unit), then
// the in-engine bundle over the token bytes, then the verified=false zero.
// A resolved failure is the same zero: verified=false, no claim names read
// true (the record's no-panic rule).
func ResolveIdentity(vi *VerifiedIdentity, v *Verifier, token string, now int64) Auth {
	if vi != nil {
		return vi.AuthView().Sanitised()
	}
	if v != nil && token != "" {
		return v.Verify(token, now).AuthView().Sanitised()
	}
	return Auth{}.Sanitised()
}

// nowEpoch is the wall epoch the engine wiring binds when it sets a clock.
func nowEpoch() int64 { return time.Now().Unix() }
