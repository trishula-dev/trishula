package main

// TR-06 (issue #6) — PR A: minimal transparent reverse proxy shape for the
// engine host. The proxy proves the v1 integration posture (PRD §10.3
// variant A): the engine sits behind the gateway as a plain Gateway API
// backend and forwards transparently to the upstream pool. No CEL/ladder
// wiring yet — that integration lands in a later slice.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// red engineProxyUpstream: the engine host proxies requests to the configured
// upstream, preserving method, path, query and headers both ways.
func TestEngineProxyForwardsToUpstream(t *testing.T) {
	var seenMethod, seenPath, seenURI, seenHopHeader string
	var seenAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		seenURI = r.URL.RawQuery
		seenHopHeader = r.Header.Get("X-Hop")
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("X-Upstream-Node", "pool-a")
		w.Header().Set("X-Upstream-Status-Meta", "from-upstream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	eng := httptest.NewServer(newEngineHandler(upstream.URL, ""))
	defer eng.Close()

	req, _ := http.NewRequest(http.MethodGet, eng.URL+"/v1/chat/completions?model=x", nil)
	req.Header.Set("X-Hop", "hop-value")
	req.Header.Set("Authorization", "Bearer tok_123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request to engine host: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "upstream-body" {
		t.Errorf("proxied body = %q, want upstream body", got)
	}
	if seenMethod != http.MethodGet {
		t.Errorf("upstream saw method %q, want GET", seenMethod)
	}
	if seenPath != "/v1/chat/completions" {
		t.Errorf("upstream saw path %q, want /v1/chat/completions", seenPath)
	}
	if seenURI != "model=x" {
		t.Errorf("upstream saw rawquery %q, want model=x", seenURI)
	}
	if seenHopHeader != "hop-value" {
		t.Errorf("upstream did not receive request header X-Hop (got %q)", seenHopHeader)
	}
	if seenAuth != "Bearer tok_123" {
		t.Errorf("upstream did not receive Authorization header (got %q)", seenAuth)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("proxied status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Upstream-Node") != "pool-a" {
		t.Errorf("response headers from upstream lost (X-Upstream-Node=%q)", resp.Header.Get("X-Upstream-Node"))
	}
}

// red hop headers: engine adds X-Trishula-Hop so hop-by-hop evidence can
// distinguish which hop answered; request headers reaching the upstream stay
// untouched apart from proxy-mandated X-Forwarded-For.
func TestEngineProxyAddsHopHeader(t *testing.T) {
	var seenXFWD string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenXFWD = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	eng := httptest.NewServer(newEngineHandler(upstream.URL, "engine-hop-marker"))
	defer eng.Close()

	req, _ := http.NewRequest(http.MethodGet, eng.URL+"/ping", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Trishula-Hop"); got != "engine-hop-marker" {
		t.Errorf("X-Trishula-Hop = %q, want engine-hop-marker", got)
	}
	if seenXFWD == "" {
		t.Error("upstream saw no X-Forwarded-For; transparent proxy must append it")
	}
}

// red /healthz: outside the proxy path, engine health answers ok on /healthz.
func TestEngineProxyHealthz(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("healthz must not reach the upstream, hit %s", r.URL.Path)
	}))
	defer upstream.Close()

	eng := httptest.NewServer(newEngineHandler(upstream.URL, ""))
	defer eng.Close()

	resp, err := http.Get(eng.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) != "ok" {
		t.Errorf("healthz body = %q, want ok", string(body))
	}
}
