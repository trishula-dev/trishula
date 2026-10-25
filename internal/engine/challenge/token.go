package challenge

// token.go — TR-197 leaf 1 (issue #239): the signed challenge token.
// The engine mints one when the verdict resolves challenge; the redirect
// hop verifies it. Shape: base64url(payload) + "." + base64url(hmac) where
// the payload carries the expiry (unix seconds), a 16-byte nonce and the
// minter's state string. The verifier = one-shot per token (the replay
// window: a consumed nonce refuses) and refuses anything past the expiry.
//
// The signature = HMAC-SHA256 over the payload bytes with the operator's
// key (the -challenge-key flag's secret; the CRD carries no key material).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMalformed    = errors.New("challenge: malformed token")
	ErrBadSignature = errors.New("challenge: bad signature")
	ErrExpired      = errors.New("challenge: token expired")
	ErrReplay       = errors.New("challenge: replayed token")
)

// payload is the signed state (the JSON body; the field names stable).
type payload struct {
	Exp   int64  `json:"exp"`   // the expiry (unix seconds)
	Nonce string `json:"nonce"` // the hex nonce (the one-shot mark)
	State string `json:"state"` // the minter's round-trip string
}

var b64NoPad = base64.RawURLEncoding

// TokenVerifier mints and verifies challenge tokens. A consumed token
// never verifies twice (the nonce set; the entries expire with the
// token's own expiry so the map never grows unbounded).
type TokenVerifier struct {
	key  []byte
	used map[string]int64 // nonce → expiry (unix seconds)
}

// NewVerifier builds the token surface over an operator key. The key must
// carry at least 16 bytes (a short key panics: the refusal is the
// constructor's, not the verifier's).
func NewVerifier(key []byte) *TokenVerifier {
	if len(key) < 16 {
		panic("challenge: the key must be at least 16 bytes")
	}
	return &TokenVerifier{key: append([]byte(nil), key...), used: map[string]int64{}}
}

// Mint produces one signed token for the state. ttl caps the token's
// life; now decides the window.
func (v *TokenVerifier) Mint(state string, ttl time.Duration, now time.Time) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("challenge: nonce: %w", err)
	}
	p := payload{
		Exp:   now.Add(ttl).Unix(),
		Nonce: b64NoPad.EncodeToString(nonce),
		State: state,
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return b64NoPad.EncodeToString(body) + "." + v.sign(body), nil
}

// Verify checks the signature, the expiry and the one-shot window, and
// returns the minted state on a pass. Every refusal = a distinct error
// (the redirect hop's log reads the reason).
func (v *TokenVerifier) Verify(tok string, now time.Time) (string, error) {
	bodyB64, sigB64, ok := strings.Cut(tok, ".")
	if !ok {
		return "", fmt.Errorf("%w: no separator", ErrMalformed)
	}
	body, err := b64NoPad.DecodeString(bodyB64)
	if err != nil {
		return "", fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	if !hmac.Equal([]byte(v.sign(body)), []byte(sigB64)) {
		return "", ErrBadSignature
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return "", fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	if now.Unix() >= p.Exp {
		return "", ErrExpired
	}
	if exp, seen := v.used[p.Nonce]; seen && exp >= now.Unix() {
		return "", ErrReplay
	}
	v.used[p.Nonce] = p.Exp
	v.gc(now)
	return p.State, nil
}

// sign HMACs the payload and returns the base64url (no pad) form; the
// compare runs on the bytes through hmac.Equal (constant time).
func (v *TokenVerifier) sign(body []byte) string {
	m := hmac.New(sha256.New, v.key)
	m.Write(body)
	return b64NoPad.EncodeToString(m.Sum(nil))
}

// gc drops consumed nonces whose tokens already expired (the map bound).
func (v *TokenVerifier) gc(now time.Time) {
	for n, exp := range v.used {
		if exp < now.Unix() {
			delete(v.used, n)
		}
	}
}
