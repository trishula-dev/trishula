package main

// TR-197 leaf 3 (issue #239): the evidence-of-work flow end to end on the
// engine listener.
//
//	429 challenge → GET the hop (no proof) = the signed problem →
//	solve the probe → GET the hop with the solution = 200 + the pass
//	cookie → retry the original request WITH the cookie = forwarded to
//	the upstream.
//
// Failure contract:
//   - the expired original token on the hop = 403.
//   - the wrong answer = 403.
//   - the retry without the pass cookie = 429 again (the bot that fails
//     the challenge stays on the wall).
import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/challenge"
)

func solveHost(t *testing.T) http.Handler {
	t.Helper()
	return newChallengeHost(t, compileChallengePolicyBundle(t), []byte("0123456789abcdef0123456789abcdef"))
}

func TestEvidenceOfWorkFlow(t *testing.T) {
	h := solveHost(t)
	path := "/api/login"

	// step 1: the challenged request = 429 + the redirect.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://engine.local"+path, nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("the challenge probe = %d, want 429", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("no redirect minted")
	}

	// step 2: the hop without a solution = 200 + the signed problem.
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "http://engine.local"+loc, nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("the problem hop = %d, want 200", w2.Code)
	}
	var probTok, salt string
	var diff int
	for _, line := range strings.Split(w2.Body.String(), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "problem-token="):
			probTok = strings.TrimPrefix(line, "problem-token=")
		case strings.HasPrefix(line, "salt="):
			salt = strings.TrimPrefix(line, "salt=")
		case strings.HasPrefix(line, "diff="):
			if _, err := fmt.Sscanf(line, "diff=%d", &diff); err != nil {
				t.Fatalf("the diff line %q: %v", line, err)
			}
		}
	}
	if probTok == "" || salt == "" || diff == 0 {
		t.Fatalf("the problem page malformed:\n%s", w2.Body.String())
	}

	// step 3: the wrong answer = 403.
	solve := loc + "&problem=" + probTok + "&answer=1"
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "http://engine.local"+solve, nil))
	if w3.Code != http.StatusForbidden {
		t.Fatalf("the wrong-answer solve = %d, want 403", w3.Code)
	}

	// step 4: the real solve = 200 + the pass cookie.
	answer, _ := challenge.SolveProof(salt, diff)
	w4 := httptest.NewRecorder()
	h.ServeHTTP(w4, httptest.NewRequest(http.MethodGet,
		"http://engine.local"+loc+"&problem="+probTok+"&answer="+answer, nil))
	if w4.Code != http.StatusOK {
		t.Fatalf("the solve = %d, want 200", w4.Code)
	}
	cookie := w4.Header().Get("Set-Cookie")
	if !strings.HasPrefix(cookie, "trishula_pass=") {
		t.Fatalf("the solve granted no pass cookie: %q", cookie)
	}
	passTok := strings.TrimPrefix(strings.Split(cookie, ";")[0], "trishula_pass=")

	// step 5: the retry with the pass cookie = forwarded to the upstream.
	retry := httptest.NewRequest(http.MethodGet, "http://engine.local"+path, nil)
	retry.Header.Set("Cookie", "trishula_pass="+passTok)
	w5 := httptest.NewRecorder()
	h.ServeHTTP(w5, retry)
	if w5.Code != http.StatusOK || w5.Body.String() != "upstream-body" {
		t.Fatalf("the retried request = %d %q, want the forwarded upstream body", w5.Code, w5.Body.String())
	}

	// step 6: the retry WITHOUT the pass cookie = 429 again.
	w6 := httptest.NewRecorder()
	h.ServeHTTP(w6, httptest.NewRequest(http.MethodGet, "http://engine.local"+path, nil))
	if w6.Code != http.StatusTooManyRequests {
		t.Fatalf("the challenge-less retry = %d, want 429", w6.Code)
	}
}

func TestHopRefusesExpiredProblemAndTamper(t *testing.T) {
	h := solveHost(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://engine.local/api/login", nil))
	loc := w.Header().Get("Location")

	// an expired ORIGINAL token = 403 on the hop (the problem never mints).
	// Construct the expiry via a mint far in the past is not possible from
	// the surface; instead the tamper path: flip the token's first byte.
	u := loc[len("/__trishula/challenge?token="):]
	u = "AAAA" + u[4:]
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest(http.MethodGet,
		"http://engine.local/__trishula/challenge?token="+u, nil))
	if w2.Code != http.StatusForbidden {
		t.Fatalf("the tampered hop = %d, want 403", w2.Code)
	}

	// the tampered problem token on the solve = 403.
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "http://engine.local"+loc, nil))
	var probTok string
	for _, line := range strings.Split(w3.Body.String(), "\n") {
		if strings.HasPrefix(line, "problem-token=") {
			probTok = strings.TrimSpace(line)[len("problem-token="):]
		}
	}
	bad := "AAAA" + probTok[4:]
	solve := loc + "&problem=" + bad + "&answer=7"
	w4 := httptest.NewRecorder()
	h.ServeHTTP(w4, httptest.NewRequest(http.MethodGet, "http://engine.local"+solve, nil))
	if w4.Code != http.StatusForbidden {
		t.Fatalf("the tampered problem solve = %d, want 403", w4.Code)
	}
}
