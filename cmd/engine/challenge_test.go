package main

// TR-197 leaf 2 (issue #239): the challenge surface on the engine
// listener. The acceptance and the failure contract, written first:
//
//   - a challenge verdict answers 429 with a Location header carrying the
//     minted token URL (/__trishula/challenge?token=...).
//   - GET on that URL with a valid token = 200 and a body naming the
//     accepted state.
//   - the SAME token a second time = 403 (the one-shot replay window).
//   - a tampered token = 403.
//   - a challenge verdict with NO key configured = 403 and no redirect
//     (the mechanism off = the deterministic refuse).
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
	"github.com/trishula-dev/trishula/internal/operator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func compileChallengePolicyBundle(t *testing.T) []byte {
	t.Helper()
	policy := v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "challenge-gate", Namespace: "dx1"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionChallenge,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shadow: true},
		},
	}
	b, err := operator.Compile(policy)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	data, err := json.Marshal(&b)
	if err != nil {
		t.Fatalf("bundle json: %v", err)
	}
	return data
}

func newChallengeHost(t *testing.T, bundle []byte, key []byte) http.Handler {
	t.Helper()
	box := &bundleBox{challenge: newChallengeTokenVerifier(key)}
	e, err := loadBundle(bundle)
	if err != nil {
		t.Fatalf("bundle load: %v", err)
	}
	box.set(bundle, e)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream-body"))
	}))
	t.Cleanup(upstream.Close)
	return newEngineHandlerWithBox(upstream.URL, "engine", box)
}

func TestChallengeVerdictRedirectsWithToken(t *testing.T) {
	h := newChallengeHost(t, compileChallengePolicyBundle(t), []byte("0123456789abcdef0123456789abcdef"))
	req, _ := http.NewRequest(http.MethodGet, "http://engine.local/api/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("challenge probe = %d, want 429", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/__trishula/challenge?token=") {
		t.Fatalf("Location = %q, want the challenge redirect URL", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location parse: %v", err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatal("the redirect carries no token")
	}

	// The redirect hop: the first GET = 200, the state accepted.
	hop, _ := http.NewRequest(http.MethodGet, "http://engine.local"+loc, nil)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, hop)
	if w2.Code != http.StatusOK {
		t.Fatalf("the verified hop = %d, want 200", w2.Code)
	}

	// The re-read: the hop peeks (nothing consumed); the same token =
	// the problem page again (the replay refusal moved to the solve in
	// leaf 3).
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, hop)
	if w3.Code != http.StatusOK {
		t.Fatalf("the re-read hop = %d, want 200 (the peek consumes nothing)", w3.Code)
	}

	// The tamper: a flipped payload byte = 403.
	bad := loc[:len("/__trishula/challenge?token=")] + strings.ToUpper(tok[:1]) + tok[1:]
	w4 := httptest.NewRecorder()
	h.ServeHTTP(w4, httptest.NewRequest(http.MethodGet, "http://engine.local"+bad, nil))
	if w4.Code != http.StatusForbidden {
		t.Fatalf("the tampered hop = %d, want 403", w4.Code)
	}
}

func TestChallengeWithoutKeyRefuses(t *testing.T) {
	h := newChallengeHost(t, compileChallengePolicyBundle(t), nil)
	req, _ := http.NewRequest(http.MethodGet, "http://engine.local/api/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("challenge without a key = %d, want 403 (no mechanism = refuse)", w.Code)
	}
	if w.Header().Get("Location") != "" {
		t.Error("challenge without a key must not mint a redirect")
	}
}
