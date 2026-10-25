package main

// TR-34 (issue #34) — the engine TLS-termination secondary mode, the spec's
// §6.3 non-goal carve-out with the R4 mitigation (optional, feature-gated;
// gateway-owned termination is the default). The gate resolves from the
// --tls-cert/--tls-key pair; with the pair set the engine terminates TLS on
// its own listener and serves the unchanged host behind it — the TR-06
// proxy, the TR-08c consult, the same decision surfaces.
//
// RED state: tlsTerminationSpec, errTLSPair and engineListener are undefined
// (build failure); GREEN defines them and wires the flags in main().
// Kernel-free: pure-Go host tests. The kernel plane is untouched — the
// shield's tls_seen flow hint records client-side TLS on the wire (the
// spec's §9.1 rule: the kernel never depends on a termination path), and the
// socket-plane transport constraints hold: TCP/TLS only at this listener, no
// HTTP/3 surface, no fast-path or HPACK behavior change (docs/design/
// socket-plane-fast-path.md sections 3.1 and 3.2).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTLSPair writes a self-signed ECDSA server pair to a temp directory
// (the in-test stand-in for the operator-supplied cert; no key material is
// committed). Returns the two paths the gate consumes.
func writeTLSPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trishula-engine-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := writeFile0600(certPath, certPEM); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := writeFile0600(keyPath, keyPEM); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// writeFile0600 writes cert and key material with owner-only permissions.
func writeFile0600(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// tlsTestClient trusts the in-test self-signed pair with InsecureSkipVerify
// (test-only; production loads the operator's pair and verifies identity).
func tlsTestClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

// hostUpstream answers the plain-HTTP pool shape the engine forwards to
// downstream of its termination (the lab's plaintext Service backend).
func hostUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Node", "pool-a")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-body")
	}))
	t.Cleanup(up.Close)
	return up
}

// serveEngineListener runs the host on the built listener in the background
// (a Serve error before the first request fails the test via the probe
// timeouts).
func serveEngineListener(t *testing.T, ln net.Listener, handler http.Handler) {
	t.Helper()
	go func() { _ = (&http.Server{Handler: handler}).Serve(ln) }()
}

// The gate is feature-gated and all-or-nothing: the pair off = the default
// plaintext listener (gateway-owned termination); the pair split = a boot
// error, never a half-open listener; the pair set = the secondary mode with
// the TLS 1.2 floor pinned.
func TestTLSTerminationModeIsFeatureGated(t *testing.T) {
	rows := []struct {
		name     string
		certFile string
		keyFile  string
		wantTLS  bool
		wantPair bool
	}{
		{name: "default-off-is-plaintext", certFile: "", keyFile: "", wantTLS: false},
		{name: "cert-without-key-is-a-boot-error", certFile: "/tmp/only.crt", keyFile: "", wantPair: true},
		{name: "key-without-cert-is-a-boot-error", certFile: "", keyFile: "/tmp/only.key", wantPair: true},
		{name: "pair-set-is-the-secondary-mode", certFile: "tls.crt", keyFile: "tls.key", wantTLS: true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			cfg, err := tlsTerminationSpec(row.certFile, row.keyFile)
			if row.wantPair {
				if !errors.Is(err, errTLSPair) {
					t.Fatalf("split pair err = %v, want errTLSPair", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("spec err = %v, want nil", err)
			}
			if row.wantTLS && cfg == nil {
				t.Fatal("pair set: spec is nil, want the TLS spec")
			}
			if !row.wantTLS && cfg != nil {
				t.Fatalf("pair off: spec %v, want nil (the plaintext default stays)", cfg)
			}
			if row.wantTLS && cfg.MinVersion != tls.VersionTLS12 {
				t.Fatalf("TLS floor = %#x, want the TLS 1.2 pin", cfg.MinVersion)
			}
		})
	}
}

// The secondary mode serves the same host behind the engine-terminated
// listener: healthz, the transparent forward, the hop marker — and the
// default mode stays plaintext with no surprise TLS.
func TestTLSTerminationServesTheSameHost(t *testing.T) {
	certPath, keyPath := writeTLSPair(t)

	t.Run("engine-terminated-leg-serves-the-host", func(t *testing.T) {
		up := hostUpstream(t)
		ln, err := engineListener("127.0.0.1:0", certPath, keyPath)
		if err != nil {
			t.Fatalf("engineListener: %v", err)
		}
		defer ln.Close()
		serveEngineListener(t, ln, newEngineHandler(up.URL, "engine"))
		addr := ln.Addr().String()
		client := tlsTestClient()

		resp, err := client.Get("https://" + addr + "/healthz")
		if err != nil {
			t.Fatalf("healthz over the engine-terminated leg: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Errorf("healthz = %d %q, want 200 ok", resp.StatusCode, string(body))
		}

		resp2, err := client.Get("https://" + addr + "/v1/chat/completions?model=x")
		if err != nil {
			t.Fatalf("proxy over the engine-terminated leg: %v", err)
		}
		body2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK || string(body2) != "upstream-body" {
			t.Errorf("proxied = %d %q, want 200 upstream-body", resp2.StatusCode, string(body2))
		}
		if resp2.Header.Get("X-Trishula-Hop") != "engine" {
			t.Error("X-Trishula-Hop lost across the engine-terminated leg")
		}
		if resp2.Header.Get("X-Upstream-Node") != "pool-a" {
			t.Error("upstream response headers lost across the engine-terminated leg")
		}
	})

	t.Run("tls-1-1-client-is-rejected-at-the-floor", func(t *testing.T) {
		up := hostUpstream(t)
		ln, err := engineListener("127.0.0.1:0", certPath, keyPath)
		if err != nil {
			t.Fatalf("engineListener: %v", err)
		}
		defer ln.Close()
		serveEngineListener(t, ln, newEngineHandler(up.URL, ""))
		old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS11,
		}}, Timeout: 5 * time.Second}
		resp, err := old.Get("https://" + ln.Addr().String() + "/healthz")
		if err == nil {
			resp.Body.Close()
			t.Error("TLS 1.1 client connected, want a handshake refusal at the 1.2 floor")
		}
	})

	t.Run("default-mode-stays-plaintext", func(t *testing.T) {
		up := hostUpstream(t)
		ln, err := engineListener("127.0.0.1:0", "", "")
		if err != nil {
			t.Fatalf("engineListener: %v", err)
		}
		defer ln.Close()
		serveEngineListener(t, ln, newEngineHandler(up.URL, "engine"))

		resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
		if err != nil {
			t.Fatalf("plaintext request on the default listener: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("plaintext healthz = %d, want 200 (the default mode unchanged)", resp.StatusCode)
		}
		if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp",
			ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}); err == nil {
			_ = conn.Close()
			t.Error("TLS handshake met the default listener, want plaintext only (no surprise TLS)")
		}
	})
}

// The consult contract rides the terminated leg unchanged: the decision
// surfaces (X-Trishula-Decision, X-Trishula-Rule, the 403 block) read the
// same over TLS as over the gateway-terminated plaintext leg.
func TestTLSTerminationKeepsTheConsultPath(t *testing.T) {
	certPath, keyPath := writeTLSPair(t)
	up := hostUpstream(t)
	bundle := compileLabBundle(t)
	handler, err := newEngineHandlerWithBundle(up.URL, "engine", bundle, nil)
	if err != nil {
		t.Fatalf("build engine handler: %v", err)
	}
	ln, err := engineListener("127.0.0.1:0", certPath, keyPath)
	if err != nil {
		t.Fatalf("engineListener: %v", err)
	}
	defer ln.Close()
	serveEngineListener(t, ln, handler)
	client := tlsTestClient()

	probe, _ := http.NewRequest(http.MethodPost,
		"https://"+ln.Addr().String()+"/v1/chat/completions?q=UNION%20SELECT", nil)
	resp, err := client.Do(probe)
	if err != nil {
		t.Fatalf("sqli probe over the terminated leg: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("sqli probe = %d, want the 403 block", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Trishula-Decision"); got != "block" {
		t.Errorf("X-Trishula-Decision = %q, want block over the terminated leg", got)
	}
	if got := resp.Header.Get("X-Trishula-Rule"); got != "TR08C-001" {
		t.Errorf("X-Trishula-Rule = %q, want TR08C-001 over the terminated leg", got)
	}

	benign, _ := http.NewRequest(http.MethodPost,
		"https://"+ln.Addr().String()+"/v1/chat/completions?q=greeting", nil)
	resp2, err := client.Do(benign)
	if err != nil {
		t.Fatalf("benign probe over the terminated leg: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || string(body) != "upstream-body" {
		t.Errorf("benign probe = %d %q, want the forward", resp2.StatusCode, string(body))
	}
	if resp2.Header.Get("X-Trishula-Hop") != "engine" {
		t.Error("benign probe lost the hop marker over the terminated leg")
	}
}
