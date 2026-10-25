package challenge

// TR-197 leaf 3 (issue #239): the evidence-of-work probe — the contract
// tests first.
//
//   - The problem GET consumes NOTHING: a token peeked twice still
//     verifies (the solver downloads the problem, computes, then solves).
//     VerifyPeek checks the signature + the expiry only.
//   - Verify (the solve) consumes the one-shot window: a consumed token
//     refuses.
//   - The proof: sha256(salt ":" answer) must carry the difficulty's hex
//     zero prefix. A wrong answer, a wrong salt or a short answer fails.
//   - The problem = itself a signed token (state "salt=<hex>;diff=<n>"),
//     a short TTL; the tamper refuses.
import (
	"strings"
	"testing"
	"time"
)

func TestVerifyPeekDoesNotConsume(t *testing.T) {
	v := NewVerifier([]byte("0123456789abcdef0123456789abcdef"))
	tok, _ := v.Mint("s-peek", 5*time.Minute, time.Unix(1_800_000_000, 0))
	now := time.Unix(1_800_000_000+30, 0)
	for i := 0; i < 3; i++ {
		if _, err := v.VerifyPeek(tok, now); err != nil {
			t.Fatalf("peek %d refused: %v (the peek consumes nothing)", i+1, err)
		}
	}
	if _, err := v.VerifyPeek(tok, time.Unix(1_800_000_000+5*60+1, 0)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("a past-expiry peek = %v, want the expiry refusal (the peek keeps the expiry rule)", err)
	}
	// The solve still consumes once, then refuses.
	if _, err := v.Verify(tok, now); err != nil {
		t.Fatalf("the solve verify failed: %v", err)
	}
	if _, err := v.Verify(tok, now); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Errorf("the consumed token verified again = %v, want the replay refusal", err)
	}
}

func TestProofVerdictShape(t *testing.T) {
	const salt = "a3f1c2"
	real, _ := SolveProof(salt, 16)
	if !VerifyProof(salt, real, 16) {
		t.Fatal("SolveProof's own answer refused (the check and the solve disagree)")
	}
	if VerifyProof(salt, "0", 16) {
		t.Fatal("an answer that solves nothing was accepted")
	}
	if VerifyProof(salt, "zzz", 16) {
		t.Fatal("a non-hex answer was accepted")
	}
}

func TestProofDifficultyDrivesWork(t *testing.T) {
	// A 4-bit difficulty solves on the first try for almost any suffix; a
	// 16-bit difficulty needs ~65k tries. The count readback pins the work
	// growth (the probe stays small but real).
	_, n4 := SolveProof("d1e2f3a4b5", 4)
	_, n16 := SolveProof("d1e2f3a4b5", 16)
	if n4 >= n16 {
		t.Fatalf("solve work did not grow with difficulty: 4-bit=%d 16-bit=%d", n4, n16)
	}
	if !VerifyProof("d1e2f3a4b5", "x", 4) == false {
		t.Fatal("the 4-bit fixture refused")
	}
}
