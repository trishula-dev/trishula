package challenge

// eow.go — TR-197 leaf 3 (issue #239): the evidence-of-work probe. The
// hop's problem = a signed short-TTL token whose state carries the salt
// and the difficulty ("salt=<hex>;diff=<bits>"). The solver searches a
// counter whose sha256(salt:counter) hex starts with `diff` zero bits.
// The verifier: the hash check then the one-shot consume of BOTH tokens
// (the problem and the original). The solve returns the pass token — a
// second mint with the state = the original request path (the consult
// reads it back and forwards matching requests for its TTL).

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ProblemDifficulty is the default probe work: 16 bits ≈ 65k sha256
// calls — sub-second for a browser, a real cost for a script (the
// spec's "small hash probe"; the operator tunes at the CRD slice).
const ProblemDifficulty = 16

// problemTTL keeps the solver's window short (the probe re-issues by
// re-running the challenge hop).
const problemTTL = 5 * time.Minute

type Problem struct {
	Salt string
	Diff int
}

// MintProblem signs a fresh probe over salt+difficulty (the verifier's
// key signs; the short TTL bounds the solver's window).
func MintProblem(v *TokenVerifier, diff int, now time.Time) (Problem, string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return Problem{}, "", fmt.Errorf("challenge: problem salt: %w", err)
	}
	salt := hex.EncodeToString(buf)
	tok, err := v.Mint(fmt.Sprintf("salt=%s;diff=%d", salt, diff), problemTTL, now)
	return Problem{Salt: salt, Diff: diff}, tok, err
}

// ParseProblem reads the problem token back (the peek form: reading the
// problem consumes nothing).
func ParseProblem(v *TokenVerifier, ptok string, now time.Time) (Problem, error) {
	state, err := v.VerifyPeek(ptok, now)
	if err != nil {
		return Problem{}, err
	}
	var p Problem
	for _, kv := range strings.Split(state, ";") {
		k, val, ok := strings.Cut(kv, "=")
		if !ok {
			return Problem{}, fmt.Errorf("%w: problem state %q", ErrMalformed, state)
		}
		switch k {
		case "salt":
			p.Salt = val
		case "diff":
			fmt.Sscanf(val, "%d", &p.Diff)
		}
	}
	if p.Salt == "" || p.Diff == 0 {
		return Problem{}, fmt.Errorf("%w: problem state %q", ErrMalformed, state)
	}
	return p, nil
}

// SolveProof searches the nonce whose sha256(salt:nonce) hex carries the
// difficulty's zero-bit prefix; returns the nonce and the attempts made.
func SolveProof(salt string, diff int) (string, int) {
	need := diff / 8
	if diff%8 != 0 {
		need++
	}
	// Bit-exact prefix check over the raw digest.
	buf := []byte(salt + ":")
	for n := 0; ; n++ {
		nbuf := append(buf[:len(buf)], []byte(fmt.Sprintf("%d", n))...)
		sum := sha256.Sum256(nbuf)
		if diffCheck(sum, diff) {
			return fmt.Sprintf("%d", n), n + 1
		}
		_ = need
	}
}

func diffCheck(sum [32]byte, diff int) bool {
	whole := diff / 8
	rem := diff % 8
	for i := 0; i < whole; i++ {
		if sum[i] != 0 {
			return false
		}
	}
	if rem != 0 && sum[whole] >= 1<<(8-rem) {
		return false
	}
	return true
}

// VerifyProof checks one proposed answer against the salt at the
// difficulty.
func VerifyProof(salt, answer string, diff int) bool {
	if !isHex(answer) {
		return false
	}
	sum := sha256.Sum256([]byte(salt + ":" + answer))
	return diffCheck(sum, diff)
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// MintPass issues the pass grant for an original request path (state =
// "pass:<path>"); the consult peeks it per request.
func MintPass(v *TokenVerifier, path string, ttl time.Duration, now time.Time) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: empty pass path", ErrMalformed)
	}
	return v.Mint("pass:"+path, ttl, now)
}

// VerifyPassPeek checks the pass cookie's token without consuming (the
// grant is reusable for its TTL) and returns the granted path.
func VerifyPassPeek(v *TokenVerifier, ptok string, now time.Time) (string, error) {
	state, err := v.VerifyPeek(ptok, now)
	if err != nil {
		return "", err
	}
	path, ok := strings.CutPrefix(state, "pass:")
	if !ok {
		return "", fmt.Errorf("%w: pass state %q", ErrMalformed, state)
	}
	return path, nil
}
