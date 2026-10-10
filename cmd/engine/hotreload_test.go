package main

// TR-08c (issue #76, M9) — the lab transport shapes: the polled bundle path
// (consult inactive until a valid bundle arrives, no restart) and the
// -receive-bundle exec delivery into that path.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEngineBundlePathHotReload: the M9 lab transport — the engine starts
// with NO bundle at the polled path (consult inactive, transparent), the
// bundle lands in the file, the consult activates without a restart; a
// subsequent corrupt write keeps the previously loaded bundle.
func TestEngineBundlePathHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "upstream-body")
	}))
	defer upstream.Close()

	handlerEngine, box := newEngineHandlerWithBundlePath(context.Background(), upstream.URL, "engine", path, 20*time.Millisecond)
	host := httptest.NewServer(handlerEngine)
	defer host.Close()

	// Phase 1: no bundle — transparent (403 absent, forward).
	resp, err := http.Post(host.URL+"/v1/chat/completions?q=UNION%20SELECT", "", nil)
	if err != nil {
		t.Fatalf("phase1 probe: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Trishula-Decision") != "" {
		t.Errorf("phase1 (no bundle) = %d (want 200 transparent), decision %q", resp.StatusCode, resp.Header.Get("X-Trishula-Decision"))
	}

	// Phase 2: the bundle lands (the -receive-bundle delivery); the poller
	// activates the consult within the tick budget.
	if err := receiveBundle(path, strings.NewReader(string(compileLabBundle(t))), io.Discard); err != nil {
		t.Fatalf("receive bundle: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && box.get() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	if box.get() == nil {
		t.Fatal("consult did not activate after the bundle landed")
	}
	resp2, err := http.Post(host.URL+"/v1/chat/completions?q=UNION%20SELECT", "", nil)
	if err != nil {
		t.Fatalf("phase2 probe: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("phase2 (bundle active) = %d, want 403", resp2.StatusCode)
	}

	// Phase 3: corrupt content keeps the previous bundle (fail conservative).
	before := box.get()
	if err := os.WriteFile(path, []byte(`{"formatVersion":99}`), 0o644); err != nil {
		t.Fatalf("corrupt write: %v", err)
	}
	deadline = time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) && box.get() == before {
		time.Sleep(10 * time.Millisecond)
	}
	if box.get() != before {
		t.Error("corrupt reload must keep the previously loaded bundle")
	}
	resp3, err := http.Post(host.URL+"/v1/chat/completions?q=UNION%20SELECT", "", nil)
	if err != nil {
		t.Fatalf("phase3 probe: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden {
		t.Errorf("phase3 (corrupt reload) = %d, want 403 (previous bundle stands)", resp3.StatusCode)
	}
}

// TestReceiveBundleSemantics: bytes land whole at the target path; empty
// stdin is an error (never truncate the consulted bundle to nothing).
func TestReceiveBundleSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")
	if err := receiveBundle(path, strings.NewReader(`{"formatVersion":1}`), io.Discard); err != nil {
		t.Fatalf("receive: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"formatVersion":1}` {
		t.Errorf("received file = %q (err %v), want the stdin bytes", data, err)
	}
	if _, err := os.Stat(path + ".part"); err == nil {
		t.Error("the .part temp file must be gone after the rename")
	}
	if err := receiveBundle(path, strings.NewReader(""), io.Discard); err == nil {
		t.Error("empty stdin must error, not truncate the bundle")
	}
	data, err = os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Errorf("bundle after failed receive = %q (err %v), want intact", data, err)
	}
}

// TestIsReceiveModeArgv: the mode key parses with one or two dashes and a
// following path argument.
func TestIsReceiveModeArgv(t *testing.T) {
	if p, ok := isReceiveMode([]string{"-receive-bundle", "/tmp/b"}); !ok || p != "/tmp/b" {
		t.Errorf("single dash = %q %v, want /tmp/b true", p, ok)
	}
	if _, ok := isReceiveMode([]string{"--listen", ":8080"}); ok {
		t.Error("server args must not trip the receive mode")
	}
}

// compile-time silence for the json import (used indirectly by the lab
// fixture in bundle_test.go).
var _ = json.Marshal
