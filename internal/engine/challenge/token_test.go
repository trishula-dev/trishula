package challenge

// TR-197 leaf 1 (issue #239): the challenge token — the acceptance and the
// failure contract, written first.
//
// The token = the signed redirect state the engine mints when the verdict
// resolves challenge: base64url(payload) + "." + base64url(HMAC-SHA256).
// The payload = the expiry (unix seconds), the nonce (16 random bytes),
// the state (the round-trip string the minter gave), and the proof probe
// parameter (leaf 2 carries the solver; the token carries the name here).
//
// Failure contract:
//   - a token past its expiry refuses (ErrExpired) — the exit criterion
//     "the token replay beyond the TTL refuses".
//   - a tampered payload, a dropped byte or a wrong key refuses
//     (ErrBadSignature).
//   - a structurally broken token refuses (ErrMalformed).
//   - a second Verify of the same token refuses (the one-shot replay
//     window; the nonce cache is the verifier's).
//
// Acceptance: mint → Verify returns the same state, inside the expiry.
import (
	"strings"
	"testing"
	"time"
)

func TestMintVerifyRoundTrip(t *testing.T) {
	v := NewVerifier([]byte("0123456789abcdef0123456789abcdef")) // 32-byte key
	tok, err := v.Mint("rid-1:/api/login", 5*time.Minute, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if strings.Count(tok, ".") != 1 {
		t.Fatalf("token shape wrong: %q", tok)
	}
	state, err := v.Verify(tok, time.Unix(1_800_000_000+60, 0)) // inside the TTL
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if state != "rid-1:/api/login" {
		t.Errorf("state = %q, want the minted state", state)
	}
}

func TestVerifyRefusesExpiredToken(t *testing.T) {
	v := NewVerifier([]byte("0123456789abcdef0123456789abcdef"))
	tok, _ := v.Mint("s-1", 5*time.Minute, time.Unix(1_800_000_000, 0))
	if _, err := v.Verify(tok, time.Unix(1_800_000_000+5*60-1, 0)); err != nil {
		t.Fatalf("inside-TTL verify failed: %v", err)
	}
	_, err := v.Verify(tok, time.Unix(1_800_000_000+5*60+1, 0))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("past-TTL verify = %v, want the expiry refusal", err)
	}
}

func TestVerifyRefusesTamperedAndWrongKey(t *testing.T) {
	v := NewVerifier([]byte("0123456789abcdef0123456789abcdef"))
	tok, _ := v.Mint("s-2", 5*time.Minute, time.Unix(1_800_000_000, 0))
	now := time.Unix(1_800_000_000+30, 0)

	payload, sig, _ := strings.Cut(tok, ".")
	flipped := payload[:2] + string(payload[2]^0x20) + payload[3:]
	other := NewVerifier([]byte("ffffffffffffffffffffffffffffffff"))
	for name, tv := range map[string]struct {
		ver *TokenVerifier
		tok string
	}{
		"tampered payload": {v, flipped + "." + sig},
		"truncated sig":    {v, payload + "." + sig[:len(sig)-4]},
		"wrong key":        {other, tok},
	} {
		if _, err := tv.ver.Verify(tv.tok, now); err == nil {
			t.Errorf("%s: verify passed, want a refusal", name)
		}
	}
}

func TestVerifyRefusesOneShotReplay(t *testing.T) {
	v := NewVerifier([]byte("0123456789abcdef0123456789abcdef"))
	tok, _ := v.Mint("s-3", 5*time.Minute, time.Unix(1_800_000_000, 0))
	now := time.Unix(1_800_000_000+30, 0)
	if _, err := v.Verify(tok, now); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if _, err := v.Verify(tok, now); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Errorf("second verify = %v, want the replay refusal", err)
	}
}
