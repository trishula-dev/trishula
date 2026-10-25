package main

// TR-203 L3 (issue #264, leaf 3) — the engine inline H3 listener: TR-34's TLS
// termination mode gains the QUIC/HTTP-3 listener. The mode stays opt-in
// (decision 1: the default stays the gateway-terminated path); the gate
// resolves from the --h3-listen flag plus the unchanged --tls-cert/--tls-key
// pair.
//
// RED state: h3ListenSpec, startH3Listener, altSvcHandler, errH3NeedsTLS and
// the QPACK codec are undefined (build failure); GREEN defines them.
// Kernel-free: pure-Go host tests, the same surface family as tls_test.go.
// The QUIC transport is the Go team's golang.org/x/net/quic — already a
// direct module dependency of this repo; the RFC 9114 request layer and the
// QPACK static-table subset are this file's repo-owned surface (the ADR
// statement rides the lane's PR body).
//
// Scope (docs/design/h3-ingress-posture.md, the TR-29 record):
// - the alt-svc advertisement rides the h1/h2 TLS responses of the opt-in mode
// - the h3 request view = the engine's own ladder path: the same handler
//   (the consult, the verdict, the proxy) answers h3 requests
// - probe P5 (the 0-RTT posture): the mode rejects 0-RTT — the transport
//   accepts no early data and the listener pins no session-resumption
//   material; the test row pins the posture's config surface
// - the kernel plane is untouched; the lab cue manifests are the L2 lane's.

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/quic"
)

// h3TestConnect dials one h3 test connection to the listener's UDP address.
// The in-test client trusts the self-signed pair (test-only; production loads
// the operator's pair and verifies identity).
func h3TestConnect(t *testing.T, addr string) *quic.Conn {
	t.Helper()
	ep, err := quic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("client endpoint: %v", err)
	}
	t.Cleanup(func() { _ = ep.Close(context.Background()) })
	conn, err := ep.Dial(context.Background(), "udp", addr, &quic.Config{
		TLSConfig: &tls.Config{NextProtos: []string{"h3"}, InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("h3 dial %s: %v", addr, err)
	}
	return conn
}

// h3TestRequest sends one h3 request and reads the full response. The test
// client mirrors the RFC 9114 request shape: the control stream (SETTINGS)
// opens first, the request stream carries one HEADERS frame plus optional
// DATA frames. The response reads back one HEADERS frame plus DATA frames
// until the stream's fin.
func h3TestRequest(t *testing.T, conn *quic.Conn, method, path string, extra http.Header, body string) (status int, headers http.Header, respBody []byte) {
	t.Helper()
	// the client control stream: type 0x00 + SETTINGS (QPACK capacity 0)
	ctrl, err := conn.NewSendOnlyStream(context.Background())
	if err != nil {
		t.Fatalf("control stream: %v", err)
	}
	var ctrlBuf []byte
	ctrlBuf = h3AppendVarint(ctrlBuf, h3StreamTypeControl)
	settings := h3AppendSetting(nil, h3SettingQPACKMaxTableCapacity, 0)
	ctrlBuf = h3AppendFrame(ctrlBuf, h3FrameSettings, settings)
	if _, err := ctrl.Write(ctrlBuf); err != nil {
		t.Fatalf("control write: %v", err)
	}
	if err := ctrl.Flush(); err != nil {
		t.Fatalf("control flush: %v", err)
	}

	// the request stream: HEADERS + optional DATA, then the send fin
	st, err := conn.NewStream(context.Background())
	if err != nil {
		t.Fatalf("request stream: %v", err)
	}
	fields := []hpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "localhost"},
		{Name: ":path", Value: path},
	}
	for _, name := range h3SortedNames(extra) {
		for _, v := range extra[name] {
			fields = append(fields, hpack.HeaderField{Name: name, Value: v})
		}
	}
	block, err := qpackEncodeHeaders(fields)
	if err != nil {
		t.Fatalf("qpack encode: %v", err)
	}
	var reqBuf []byte
	reqBuf = h3AppendFrame(reqBuf, h3FrameHeaders, block)
	if body != "" {
		reqBuf = h3AppendFrame(reqBuf, h3FrameData, []byte(body))
	}
	if _, err := st.Write(reqBuf); err != nil {
		t.Fatalf("request write: %v", err)
	}
	if err := st.Flush(); err != nil {
		t.Fatalf("request flush: %v", err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("request close: %v", err)
	}

	// the response: HEADERS frame first, then DATA frames until the fin
	headers = http.Header{}
	sawHead := false
	for {
		typ, payload, ferr := h3ReadFrame(st, h3MaxFrameLen)
		if ferr == io.EOF {
			break
		}
		if ferr != nil {
			t.Fatalf("read response frame: %v", ferr)
		}
		switch typ {
		case h3FrameHeaders:
			if sawHead {
				break // a trailer section; the test ignores trailers
			}
			sawHead = true
			got, derr := qpackDecodeHeaderBlock(payload)
			if derr != nil {
				t.Fatalf("qpack decode response: %v", derr)
			}
			for _, f := range got {
				if f.Name == ":status" {
					status, _ = strconv.Atoi(f.Value)
					continue
				}
				headers.Add(f.Name, f.Value)
			}
		case h3FrameData:
			respBody = append(respBody, payload...)
		}
	}
	if !sawHead {
		t.Fatal("response carried no HEADERS frame")
	}
	return status, headers, respBody
}

// h3SortedNames reads header names in sorted order (deterministic frames).
func h3SortedNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sortStrings(names)
	return names
}

// sortStrings orders a string slice in place (the sort's test-only shim).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// TR-203 L3 — the gate rows. The h3 listener is opt-in: the flag off = no
// UDP surface (the default gateway-terminated posture, decision 1); the
// address without the TLS pair = a boot error, never a half-open listener;
// the opt-in leg = TLS 1.3 (the QUIC floor) with the unchanged L4 key-exchange
// profile and the h3 ALPN.
func TestInlineH3GateIsOptIn(t *testing.T) {
	certPath, keyPath := writeTLSPair(t)
	rows := []struct {
		name     string
		certFile string
		keyFile  string
		h3Addr   string
		wantOff  bool
		wantGate bool
		wantErr  bool
	}{
		{name: "default-off-is-the-gateway-terminated-posture", certFile: "", keyFile: "", h3Addr: "", wantOff: true},
		{name: "h3-address-without-the-cert-pair-is-a-boot-error", certFile: "", keyFile: "", h3Addr: ":8443", wantErr: true},
		{name: "h3-address-with-a-split-pair-is-a-boot-error", certFile: certPath, keyFile: "", h3Addr: ":8443", wantErr: true},
		{name: "h3-address-with-the-pair-is-the-optin-listener", certFile: certPath, keyFile: keyPath, h3Addr: "127.0.0.1:0", wantGate: true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			cfg, err := h3ListenSpec(row.certFile, row.keyFile, row.h3Addr)
			if row.wantErr {
				if !errors.Is(err, errH3NeedsTLS) {
					t.Fatalf("gate err = %v, want errH3NeedsTLS", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("spec err = %v, want nil", err)
			}
			if row.wantOff && cfg != nil {
				t.Fatalf("flag off: spec %v, want nil (the default mode carries no UDP surface)", cfg)
			}
			if !row.wantGate {
				return
			}
			if cfg == nil {
				t.Fatal("opt-in: spec is nil, want the h3 spec")
			}
			if got := cfg.tls.MinVersion; got != tls.VersionTLS13 {
				t.Fatalf("h3 TLS floor = %#x, want the QUIC TLS 1.3 pin", got)
			}
			if got := cfg.tls.NextProtos; len(got) != 1 || got[0] != "h3" {
				t.Fatalf("h3 ALPN = %v, want exactly [h3]", got)
			}
			if got, want := cfg.tls.CurvePreferences, tlsPQCKeyExchange; !curveSetEqual(got, want) {
				t.Fatalf("h3 key-exchange set = %v, want the unchanged L4 profile %v", got, want)
			}
			if cfg.tls.ClientSessionCache != nil {
				t.Fatal("h3 TLS config carries a session cache; want nil (the 0-RTT posture: no resumption material)")
			}
			if cfg.tls.Certificates == nil || len(cfg.tls.Certificates) != 1 {
				certCount := 0
				if cfg.tls.Certificates != nil {
					certCount = len(cfg.tls.Certificates)
				}
				t.Fatalf("h3 cert pairs loaded = %d, want 1", certCount)
			}
		})
	}
}

// curveSetEqual compares the key-exchange offer sets.
func curveSetEqual(got, want []tls.CurveID) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TR-203 L3 — the alt-svc advertisement. The opt-in mode advertises the h3
// alternative on the h1/h2 TLS responses (the value carries the bound UDP
// port); the default (plaintext, no h3) carries no Alt-Svc header.
func TestInlineH3AltSvcAdvertisement(t *testing.T) {
	certPath, keyPath := writeTLSPair(t)

	t.Run("the-opt-in-mode-advertises-alt-svc-on-the-tls-leg", func(t *testing.T) {
		up := hostUpstream(t)
		base := newEngineHandler(up.URL, "engine")
		wrapped := altSvcHandler(base, `h3=":8443"`)
		ln, err := engineListener("127.0.0.1:0", certPath, keyPath)
		if err != nil {
			t.Fatalf("engineListener: %v", err)
		}
		defer ln.Close()
		serveEngineListener(t, ln, wrapped)

		resp, err := tlsTestClient().Get("https://" + ln.Addr().String() + "/healthz")
		if err != nil {
			t.Fatalf("healthz over the TLS leg: %v", err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Alt-Svc"); got != `h3=":8443"` {
			t.Fatalf("Alt-Svc = %q, want h3=\":8443\" (the opt-in advertisement)", got)
		}
		if resp.TLS == nil {
			t.Fatal("the answered leg is not TLS")
		}
	})

	t.Run("the-default-mode-carries-no-alt-svc", func(t *testing.T) {
		up := hostUpstream(t)
		ln, err := engineListener("127.0.0.1:0", "", "")
		if err != nil {
			t.Fatalf("engineListener: %v", err)
		}
		defer ln.Close()
		serveEngineListener(t, ln, newEngineHandler(up.URL, "engine"))

		resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
		if err != nil {
			t.Fatalf("plaintext healthz: %v", err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Alt-Svc"); got != "" {
			t.Fatalf("Alt-Svc = %q on the default mode, want none", got)
		}
	})

	t.Run("the-tls-mode-without-the-h3-opt-in-carries-no-alt-svc", func(t *testing.T) {
		up := hostUpstream(t)
		ln, err := engineListener("127.0.0.1:0", certPath, keyPath)
		if err != nil {
			t.Fatalf("engineListener: %v", err)
		}
		defer ln.Close()
		serveEngineListener(t, ln, newEngineHandler(up.URL, "engine"))

		resp, err := tlsTestClient().Get("https://" + ln.Addr().String() + "/healthz")
		if err != nil {
			t.Fatalf("healthz over the TLS leg: %v", err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Alt-Svc"); got != "" {
			t.Fatalf("Alt-Svc = %q with the h3 flag off, want none", got)
		}
	})
}

// TR-203 L3 — the h3 request view = the engine's own ladder path. The same
// handler answers over the QUIC leg: healthz, the transparent proxy with the
// hop marker, the consult block verdict, and a bodied POST.
func TestInlineH3ServesTheEngineView(t *testing.T) {
	certPath, keyPath := writeTLSPair(t)
	startListener := func(t *testing.T, handler http.Handler) *h3Server {
		t.Helper()
		cfg, err := h3ListenSpec(certPath, keyPath, "127.0.0.1:0")
		if err != nil {
			t.Fatalf("h3ListenSpec: %v", err)
		}
		h3s, err := startH3Listener(cfg, handler)
		if err != nil {
			t.Fatalf("startH3Listener: %v", err)
		}
		t.Cleanup(func() { _ = h3s.Close() })
		return h3s
	}

	t.Run("healthz-answers-over-h3", func(t *testing.T) {
		up := hostUpstream(t)
		h3s := startListener(t, newEngineHandler(up.URL, ""))
		conn := h3TestConnect(t, h3s.Addr())
		defer func() { _ = conn.Close() }()
		status, _, body := h3TestRequest(t, conn, http.MethodGet, "/healthz", nil, "")
		if status != http.StatusOK || string(body) != "ok" {
			t.Errorf("h3 healthz = %d %q, want 200 ok", status, string(body))
		}
	})

	t.Run("the-proxy-forwards-with-the-hop-marker-over-h3", func(t *testing.T) {
		up := hostUpstream(t)
		h3s := startListener(t, newEngineHandler(up.URL, "engine"))
		conn := h3TestConnect(t, h3s.Addr())
		defer func() { _ = conn.Close() }()
		status, hdrs, body := h3TestRequest(t, conn, http.MethodGet, "/v1/chat/completions?model=x", nil, "")
		if status != http.StatusOK || string(body) != "upstream-body" {
			t.Errorf("h3 proxied = %d %q, want 200 upstream-body", status, string(body))
		}
		if hdrs.Get("x-trishula-hop") != "engine" {
			t.Errorf("X-Trishula-Hop lost across the h3 leg: %v", hdrs)
		}
		if hdrs.Get("x-upstream-node") != "pool-a" {
			t.Errorf("upstream response headers lost across the h3 leg: %v", hdrs)
		}
	})

	t.Run("the-consult-block-runs-the-ladder-over-h3", func(t *testing.T) {
		up := hostUpstream(t)
		bundle := compileLabBundle(t)
		handler, err := newEngineHandlerWithBundle(up.URL, "engine", bundle, nil)
		if err != nil {
			t.Fatalf("build engine handler: %v", err)
		}
		h3s := startListener(t, handler)
		conn := h3TestConnect(t, h3s.Addr())
		defer func() { _ = conn.Close() }()
		status, hdrs, _ := h3TestRequest(t, conn, http.MethodPost, "/v1/chat/completions?q=UNION%20SELECT", nil, "")
		if status != http.StatusForbidden {
			t.Errorf("sqli probe over h3 = %d, want the 403 block", status)
		}
		if got := hdrs.Get("x-trishula-decision"); got != "block" {
			t.Errorf("X-Trishula-Decision = %q, want block over the h3 leg", got)
		}
		if got := hdrs.Get("x-trishula-rule"); got != "TR08C-001" {
			t.Errorf("X-Trishula-Rule = %q, want TR08C-001 over the h3 leg", got)
		}
	})

	t.Run("a-post-with-a-body-forwards-the-body-over-h3", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			w.Header().Set("Echoed-Len", strconv.Itoa(len(b)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		}))
		t.Cleanup(up.Close)
		h3s := startListener(t, newEngineHandler(up.URL, "engine"))
		conn := h3TestConnect(t, h3s.Addr())
		defer func() { _ = conn.Close() }()
		payload := `{"prompt":"hello"}`
		status, hdrs, body := h3TestRequest(t, conn, http.MethodPost, "/v1/chat/completions",
			http.Header{"Content-Type": []string{"application/json"}}, payload)
		if status != http.StatusOK || string(body) != payload {
			t.Errorf("h3 POST = %d %q, want 200 with the body forwarded", status, string(body))
		}
		if hdrs.Get("echoed-len") != strconv.Itoa(len(payload)) {
			t.Errorf("upstream body length = %v, want the forwarded body size", hdrs.Get("echoed-len"))
		}
	})
}

// TR-203 L3 — the malformed-request boundary. A garbage QPACK block errors
// the stream, never the process: the listener stays up and the next
// connection still gets its answer. The engine never panics on a malformed
// request (the repo's detection-path rule).
func TestInlineH3RejectsMalformedAndStaysUp(t *testing.T) {
	certPath, keyPath := writeTLSPair(t)
	up := hostUpstream(t)
	cfg, err := h3ListenSpec(certPath, keyPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("h3ListenSpec: %v", err)
	}
	h3s, err := startH3Listener(cfg, newEngineHandler(up.URL, ""))
	if err != nil {
		t.Fatalf("startH3Listener: %v", err)
	}
	defer func() { _ = h3s.Close() }()

	// a garbage head: valid framing, undecodable QPACK instructions. The
	// stream terminates (the reset or the connection close both count);
	// the process never crashes.
	conn := h3TestConnect(t, h3s.Addr())
	ctrl, err := conn.NewSendOnlyStream(context.Background())
	if err != nil {
		t.Fatalf("control stream: %v", err)
	}
	var ctrlBuf []byte
	ctrlBuf = h3AppendVarint(ctrlBuf, h3StreamTypeControl)
	ctrlBuf = h3AppendFrame(ctrlBuf, h3FrameSettings, h3AppendSetting(nil, h3SettingQPACKMaxTableCapacity, 0))
	if _, err := ctrl.Write(ctrlBuf); err != nil {
		t.Fatalf("control write: %v", err)
	}
	if err := ctrl.Flush(); err != nil {
		t.Fatalf("control flush: %v", err)
	}
	st, err := conn.NewStream(context.Background())
	if err != nil {
		t.Fatalf("request stream: %v", err)
	}
	if _, err := st.Write(h3AppendFrame(nil, h3FrameHeaders, []byte{0xFF, 0x7F, 0x7F, 0x7F, 0x01})); err != nil {
		t.Fatalf("garbage write: %v", err)
	}
	if err := st.Flush(); err != nil {
		t.Fatalf("garbage flush: %v", err)
	}
	st.CloseWrite()
	buf := make([]byte, 64)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, rerr := st.Read(buf)
		if rerr != nil || time.Now().After(deadline) {
			break
		}
	}
	_ = conn.Close()
	// the listener stays up: a fresh connection still answers
	conn2 := h3TestConnect(t, h3s.Addr())
	defer func() { _ = conn2.Close() }()
	status, _, body := h3TestRequest(t, conn2, http.MethodGet, "/healthz", nil, "")
	if status != http.StatusOK || string(body) != "ok" {
		t.Fatalf("post-malformed healthz = %d %q, want 200 ok (the listener stays up)", status, string(body))
	}
}

// TR-203 L3 — the QPACK codec pins itself against the RFC 9204 golden bytes
// (Appendix B and the field-line figures). The vectors are the RFC's, not the
// roundtrip's: the codec reads the canonical byte forms directly.
func TestQPACKCodecMatchesTheRFCGolden(t *testing.T) {
	rows := []struct {
		name string
		wire []byte
		want []hpack.HeaderField
	}{
		{
			// RFC 9204 Appendix B.1: RIC=0, Base=0, literal with static
			// name reference: :path=/index.html
			name: "b1-literal-with-static-name-reference",
			wire: []byte{0x00, 0x00, 0x51, 0x0b, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c},
			want: []hpack.HeaderField{{Name: ":path", Value: "/index.html"}},
		},
		{
			// Indexed field line, T=1 static, index 17: :method=GET
			name: "indexed-static-17-method-get",
			wire: []byte{0x00, 0x00, 0xD1},
			want: []hpack.HeaderField{{Name: ":method", Value: "GET"}},
		},
		{
			// Literal field line with literal name; N=0, no Huffman:
			// 0b001_0_0_1010, "user-agent", then the 8-bit-prefixed value.
			name: "literal-with-literal-name-and-value",
			wire: append(append([]byte{0x00, 0x00, 0x2A}, []byte("user-agent")...), 0x03, 'a', 'b', 'c'),
			want: []hpack.HeaderField{{Name: "user-agent", Value: "abc"}},
		},
		{
			// A Huffman-coded value (H=1). The value bytes come from
			// golang.org/x/net/http2/hpack's encoder (the RFC 7541
			// Appendix B table), not from this repo's codec.
			name: "huffman-coded-value-string",
			wire: func() []byte {
				huff := hpack.AppendHuffmanString(nil, "hello")
				wire := append([]byte{0x00, 0x00, 0x26}, []byte("x-test")...)
				return append(append(wire, byte(0x80|len(huff))), huff...)
			}(),
			want: []hpack.HeaderField{{Name: "x-test", Value: "hello"}},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got, err := qpackDecodeHeaderBlock(row.wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got) != len(row.want) {
				t.Fatalf("decoded %d fields %v, want %d", len(got), got, len(row.want))
			}
			for i := range row.want {
				if got[i].Name != row.want[i].Name {
					t.Errorf("field %d name = %q, want %q", i, got[i].Name, row.want[i].Name)
				}
				if got[i].Value != row.want[i].Value {
					t.Errorf("field %d value = %q, want %q", i, got[i].Value, row.want[i].Value)
				}
			}
		})
	}
}

// TR-203 L3, probe P5 — the 0-RTT posture reads reject. The record's rule:
// the transcript pins the posture. The posture's config surface: the QUIC
// transport the listener runs on accepts no early data (the transport's
// documented limitation, quoted in the lane's PR body and the posture
// record's dated read), and the listener pins no session-resumption material
// (a nil session cache), so no early data ever reaches the ladder.
func TestInlineH3ZeroRTTPostureIsReject(t *testing.T) {
	certPath, keyPath := writeTLSPair(t)
	cfg, err := h3ListenSpec(certPath, keyPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("h3ListenSpec: %v", err)
	}
	if cfg == nil {
		t.Fatal("opt-in: spec is nil, want the h3 spec")
	}
	if cfg.tls.ClientSessionCache != nil {
		t.Error("0-RTT posture: the h3 TLS config carries a session cache; want nil")
	}
	if cfg.quic.TLSConfig != cfg.tls {
		t.Error("0-RTT posture: the QUIC transport and the TLS config diverge; want one shared config")
	}
	if cfg.quic.StatelessResetKey != ([32]byte{}) {
		t.Error("0-RTT posture: the transport config carries a stateless-reset key; want the zero key (the opt-in listener adds no secret surface)")
	}
}
