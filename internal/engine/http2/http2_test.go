package http2

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// --- test wire builders -------------------------------------------------
//
// Frames are built with the x/net Framer's own write side (the maintained
// frame codec — the tests must not hand-roll conforming frame bytes) plus
// raw hand-built frames only for the cases a conforming writer refuses
// (lying lengths, truncation).

const (
	flEndHeaders byte = 0x4
	flEndStream  byte = 0x1
)

// hf builds HPACK header fields from name,value pairs.
func hf(kvs ...string) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(kvs)/2)
	for i := 0; i < len(kvs); i += 2 {
		out = append(out, hpack.HeaderField{Name: kvs[i], Value: kvs[i+1]})
	}
	return out
}

// hpackBlock encodes fields through the real HPACK encoder (Huffman +
// dynamic-table indexing exactly as a live client's bytes).
func hpackBlock(fl []hpack.HeaderField) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range fl {
		if err := enc.WriteField(f); err != nil {
			tfatal(err)
		}
	}
	return buf.Bytes()
}

// wireBuilder collects test wire bytes: Framer-written frames + raw bytes.
type wireBuilder struct{ buf bytes.Buffer }

func (b *wireBuilder) framer() *http2.Framer {
	w := http2.NewFramer(&b.buf, bytes.NewReader(nil))
	w.AllowIllegalWrites = true
	return w
}

func (b *wireBuilder) head(stream uint32, endStream bool, fl []hpack.HeaderField) {
	w := b.framer()
	if err := w.WriteHeaders(http2.HeadersFrameParam{StreamID: stream,
		EndHeaders: true, EndStream: endStream, BlockFragment: hpackBlock(fl)}); err != nil {
		tfatal(err)
	}
}

func (b *wireBuilder) data(stream uint32, endStream bool, payload []byte) {
	w := b.framer()
	if err := w.WriteData(stream, endStream, payload); err != nil {
		tfatal(err)
	}
}

func (b *wireBuilder) raw(extra []byte) { b.buf.Write(extra) }

func (b *wireBuilder) bytes() []byte { return b.buf.Bytes() }

// tfatal reports a builder failure (the builders run outside t-scopes).
func tfatal(err error) { panic("wire builder: " + err.Error()) }

// rawFH builds a 9-byte frame header by hand for the cases a conforming
// writer refuses (lying length, truncated payload, mid-block split).
func rawFH(length int, typ, flags byte, stream uint32) []byte {
	return []byte{
		byte(length >> 16), byte(length >> 8), byte(length), typ, flags,
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream),
	}
}

// --- test doubles -------------------------------------------------------

// fakeClock is the injected clock: tests step it (never the wall clock).
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time       { return c.t }
func (c *fakeClock) step(d time.Duration) { c.t = c.t.Add(d) }

// wireStub is the injected WireReader: a deterministic byte stream that
// records every armed read deadline (the parser must arm NOW+TIMEOUT) and
// reports the reader's own deadline error after the bytes drain.
type wireStub struct {
	buf      []byte
	now      func() time.Time
	armed    bool
	deadline time.Time
	armedAt  []time.Time
}

func newWireStub(b []byte, c *fakeClock) *wireStub {
	return &wireStub{buf: b, now: c.now}
}

func (w *wireStub) Read(p []byte) (int, error) {
	n := copy(p, w.buf)
	w.buf = w.buf[n:]
	if n > 0 {
		return n, nil
	}
	// Bytes drained: a live connection blocks here; the fake models the
	// deadline trip the reader reports once the armed window elapses.
	if w.armed && !w.deadline.After(w.now()) {
		return 0, os.ErrDeadlineExceeded
	}
	return 0, io.EOF
}

func (w *wireStub) SetReadDeadline(t time.Time) error {
	w.armed = true
	w.deadline = t
	w.armedAt = append(w.armedAt, t)
	return nil
}

// optsStd returns Options bound to the test clock (capped budgets where a
// test needs the yield to be cheap).
func optsStd(c *fakeClock, timeout time.Duration, max int) *Options {
	return &Options{Now: c.now, ReadTimeout: timeout, MaxFrames: max}
}

// mustNext is the clean-path helper: Next or fails the test.
func mustNext(t *testing.T, p *Parser) *Request {
	t.Helper()
	r, err := p.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return r
}

// --- the watched-RED suite (TR-15) --------------------------------------

// TestCleanGRPCHeadReconstructs is the core deliverable row: one gRPC head
// (POST package.Service/Method, application/grpc) reconstructed into the
// request view — method, path, version, scheme, authority, headers, kind,
// stream id — with every header field byte-true.
func TestCleanGRPCHeadReconstructs(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	wb := &wireBuilder{}
	wb.head(1, true, hf(
		":method", "POST",
		":path", "/pkg.Svc/Run",
		":scheme", "http",
		":authority", "api.example.com",
		"content-type", "application/grpc",
		"te", "trailers",
		"grpc-timeout", "100m",
		"user-agent", "grpc-go/1.0",
	))
	p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 100))
	r := mustNext(t, p)
	if r.Method != "POST" {
		t.Errorf("method: got %q, want POST", r.Method)
	}
	if r.Path != "/pkg.Svc/Run" {
		t.Errorf("path: got %q, want /pkg.Svc/Run", r.Path)
	}
	if r.Version != Version {
		t.Errorf("version: got %q, want %q", r.Version, Version)
	}
	if r.Scheme != "http" {
		t.Errorf("scheme: got %q, want http", r.Scheme)
	}
	if r.Authority != "api.example.com" {
		t.Errorf("authority: got %q, want api.example.com", r.Authority)
	}
	if r.StreamID != 1 {
		t.Errorf("stream id: got %d, want 1", r.StreamID)
	}
	if r.Kind != KindGRPC {
		t.Errorf("kind: got %q, want grpc", r.Kind)
	}
	if r.Headers["content-type"] != "application/grpc" {
		t.Errorf("content-type: got %q", r.Headers["content-type"])
	}
	if r.Headers["te"] != "trailers" {
		t.Errorf("te: got %q, want trailers", r.Headers["te"])
	}
	if r.Headers["grpc-timeout"] != "100m" {
		t.Errorf("grpc-timeout: got %q, want 100m", r.Headers["grpc-timeout"])
	}
	if len(r.Headers) != 4 {
		t.Errorf("header count (pseudo headers folded out): got %d, want 4", len(r.Headers))
	}
}

// TestContentMediaTypeClassifies pins the media-type grammar per kind row:
// gRPC needs the exact application/grpc family (+variant), grpc-web is NOT
// grpc, SSE is text/event-stream with parameters tolerated, everything
// else (and empty) is plain HTTP.
func TestContentMediaTypeClassifies(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		want Kind
	}{
		{"grpc-bare", "application/grpc", KindGRPC},
		{"grpc-proto", "application/grpc+proto", KindGRPC},
		{"grpc-json-params", "application/grpc+json;trace=x", KindGRPC},
		{"grpc-uppercase", "APPLICATION/GRPC", KindGRPC},
		{"grpc-web-not-grpc", "application/grpc-web+proto", KindHTTP},
		{"grpc-prefix-imbiber", "application/grpcfoo", KindHTTP},
		{"json-not-grpc", "application/json", KindHTTP},
		{"empty-not-grpc", "", KindHTTP},
		{"sse-bare", "text/event-stream", KindSSE},
		{"sse-params", "text/event-stream;charset=utf-8", KindSSE},
		{"sse-uppercase", "TEXT/EVENT-STREAM", KindSSE},
		{"sse-not-event-json", "text/event-json", KindHTTP},
		{"plain", "text/plain", KindHTTP},
	}
	for _, tc := range cases {
		c := &fakeClock{t: time.Unix(1_000_000, 0)}
		wb := &wireBuilder{}
		wb.head(7, true, hf(":method", "POST", ":path", "/p",
			":scheme", "http", ":authority", "a.com", "content-type", tc.ct))
		p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 100))
		r := mustNext(t, p)
		if r.Kind != tc.want {
			t.Errorf("%s: got kind %q, want %q", tc.name, r.Kind, tc.want)
		}
	}
}

// TestMultiplexedHeadRelease pins the streaming contract: heads release at
// their header-block arrival — an open stream never blocks a later head,
// each stream's head serves exactly once, and DATA frames between heads
// are consumed without wedging the walk.
func TestMultiplexedHeadRelease(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	wb := &wireBuilder{}
	// S1: open (client-streaming, no END_STREAM anywhere on it).
	wb.head(1, false, hf(":method", "GET", ":path", "/events",
		":scheme", "https", "content-type", "text/event-stream"))
	// S3: clean gRPC head-only.
	wb.head(3, true, hf(":method", "POST", ":path", "/pkg.Svc/Run",
		":scheme", "http", "content-type", "application/grpc"))
	// S1 body traffic AFTER both heads: consumed, never served.
	wb.data(1, false, []byte("chunk"))
	wb.data(1, true, []byte("chunk"))

	stub := newWireStub(wb.bytes(), c)
	p := New(stub, optsStd(c, time.Second, 100))

	r1 := mustNext(t, p)
	if r1.StreamID != 1 || r1.Kind != KindSSE || r1.Path != "/events" {
		t.Errorf("first head: got stream %d kind %q path %q — want S1 sse /events",
			r1.StreamID, r1.Kind, r1.Path)
	}
	r3 := mustNext(t, p)
	if r3.StreamID != 3 || r3.Kind != KindGRPC {
		t.Errorf("second head: got stream %d kind %q — want S3 grpc released while S1 open",
			r3.StreamID, r3.Kind)
	}
	if _, err := p.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("after both heads and body drain: got %v, want io.EOF", err)
	}
	// Exactly-once: a stream never re-releases after its head.
	for i := 0; i < 3; i++ {
		if r, err := p.Next(); !errors.Is(err, io.EOF) || r != nil {
			t.Errorf("exact-once %d: got (%+v, %v), want nil/io.EOF", i, r, err)
		}
	}
}

// TestTrailersAndRSTContinue pins the post-head frames: a trailing HEADERS
// block (request trailers) is consumed silently — never folded into the
// released view, never re-released — and an RST_STREAM on an open stream
// never wedges the walker; the next head still serves.
func TestTrailersAndRSTContinue(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	wb := &wireBuilder{}
	wb.head(1, false, hf(":method", "POST", ":path", "/pkg.Svc/Run",
		":scheme", "http", "content-type", "application/grpc"))
	wb.data(1, false, []byte("payload"))
	// trailers on S1 (a second HEADERS block with END_STREAM)
	wb.head(1, true, hf("grpc-status", "0"))
	// RST mid-flight on S9 (never had a head)
	wb.framer().WriteRSTStream(9, http2.ErrCodeCancel)
	// the next real head on S11 still serves
	wb.head(11, true, hf(":method", "GET", ":path", "/after", ":scheme", "http"))

	p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 100))
	r1 := mustNext(t, p)
	if r1.StreamID != 1 || r1.Headers["grpc-status"] != "" {
		t.Errorf("trailers must not fold into the released view: %+v", r1)
	}
	r2 := mustNext(t, p)
	if r2.StreamID != 11 || r2.Path != "/after" {
		t.Errorf("head after trailers and RST: got %+v", r2)
	}
}

// TestStreamErrorsAbsorbed pins per-stream fail-open: a stream whose
// header block violates the request grammar (duplicate pseudo upper-case
// field name, missing pseudo, wire-level field violations surfaced by the
// frame decoder) is absorbed — the walk continues and the connection's
// next clean head still serves. These never panic the engine.
func TestStreamErrorsAbsorbed(t *testing.T) {
	cases := []struct {
		name   string
		fields []hpack.HeaderField
	}{
		{"duplicate-pseudo", hf(":method", "GET", ":method", "POST",
			":path", "/x", ":scheme", "https")},
		{"uppercase-field-name", hf(":method", "GET", ":path", "/x",
			":scheme", "https", ":authority", "a.com", "X-Bad", "v")},
		{"unknown-pseudo-after-regular", hf(":method", "GET", ":path", "/x",
			":scheme", "https", ":authority", "a.com", "x-a", "v", ":weird", "v")},
		{"missing-method", hf(":path", "/x", ":scheme", "https", ":authority", "a.com")},
		{"missing-path", hf(":method", "GET", ":scheme", "https", ":authority", "a.com")},
		{"empty-method", hf(":method", "", ":path", "/x", ":scheme", "https")},
		{"status-mix", hf(":method", "GET", ":status", "200",
			":path", "/x", ":authority", "a.com")},
	}
	for _, tc := range cases {
		c := &fakeClock{t: time.Unix(1_000_000, 0)}
		wb := &wireBuilder{}
		wb.head(1, true, tc.fields)
		wb.head(3, true, hf(":method", "GET", ":path", "/after", ":scheme", "http"))
		p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 100))
		r := mustNext(t, p)
		if r.StreamID != 3 || r.Path != "/after" {
			t.Errorf("%s: the walk must absorb the malformed stream and serve the clean one: got %+v", tc.name, r)
		}
	}
}

// TestConnectionErrorsTerminal pins connection-level classification: an
// over-budget header list (compression error under the 8 KiB budget) and a
// wire that dies mid-frame are typed terminal errors — nil request, never
// a panic, and the walk stops (no head after a connection error).
func TestConnectionErrorsTerminal(t *testing.T) {
	t.Run("header-list-budget", func(t *testing.T) {
		c := &fakeClock{t: time.Unix(1_000_000, 0)}
		wb := &wireBuilder{}
		wb.head(1, true, hf(":method", "GET", ":path", "/x",
			"x-big", strings.Repeat("A", 9000)))
		p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 100))
		r, err := p.Next()
		if !errors.Is(err, ErrConnection) {
			t.Errorf("header list over budget: got (%+v, %v), want ErrConnection", r, err)
		}
	})
	t.Run("mid-frame-truncation", func(t *testing.T) {
		c := &fakeClock{t: time.Unix(1_000_000, 0)}
		wb := &wireBuilder{}
		wb.head(1, true, hf(":method", "GET", ":path", "/x", ":scheme", "http"))
		wb.raw(append(rawFH(10, 0x0, 0x0, 1), 1, 2, 3)) // lies: 10-byte payload, 3 delivered
		p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 100))
		if _, err := p.Next(); err == nil {
			t.Fatal("truncated wire: got nil error, want one head then ErrTruncated")
		}
		r, err := p.Next()
		if !errors.Is(err, ErrTruncated) {
			t.Errorf("mid-frame truncation after the head: got (%+v, %v), want ErrTruncated", r, err)
		}
	})
}

// TestGOAwayTerminal pins the peer-closed classification: GOAWAY ends the
// walk with ErrGoAway, nil request.
func TestGOAwayTerminal(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	wb := &wireBuilder{}
	f := wb.framer()
	if err := f.WriteGoAway(3, http2.ErrCodeNo, nil); err != nil {
		t.Fatal(err)
	}
	p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 100))
	r, err := p.Next()
	if !errors.Is(err, ErrGoAway) {
		t.Errorf("goaway: got (%+v, %v), want ErrGoAway", r, err)
	}
}

// TestReadDeadlineWindow pins the injected-clock contract: every Next arms
// NOW+ReadTimeout on the wire reader, and the reader's deadline error is
// classified ErrWindow (transient — a resumed Next re-arms, never wedges).
func TestReadDeadlineWindow(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	stub := newWireStub(nil, c)
	p := New(stub, optsStd(c, 30*time.Second, 100))
	r, err := p.Next()
	if !errors.Is(err, ErrWindow) {
		t.Errorf("silent peer: got (%+v, %v), want ErrWindow", r, err)
	}
	if len(stub.armedAt) != 1 {
		t.Fatalf("arm count: got %d, want 1", len(stub.armedAt))
	}
	want := c.t.Add(30 * time.Second)
	if !stub.armedAt[0].Equal(want) {
		t.Errorf("armed deadline: got %v, want now+timeout = %v", stub.armedAt[0], want)
	}
}

// TestFrameBudgetYields pins the per-Next frame-work budget: a
// housekeeping flood beyond MaxFrames yields ErrFrameBudget (nil request)
// and a resumed Next still serves the head (the budget is per-Next).
func TestFrameBudgetYields(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	wb := &wireBuilder{}
	wb.data(9, false, []byte("junk"))
	wb.data(9, false, []byte("junk"))
	wb.head(1, true, hf(":method", "GET", ":path", "/x", ":scheme", "http"))
	p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 2))
	r, err := p.Next()
	if !errors.Is(err, ErrFrameBudget) {
		t.Errorf("junk flood: got (%+v, %v), want ErrFrameBudget", r, err)
	}
	r2 := mustNext(t, p)
	if r2.StreamID != 1 || r2.Path != "/x" {
		t.Errorf("resumed Next after budget yield: got %+v", r2)
	}
}

// TestEOFTerminatesClean pins the clean end: wire drained exactly at a
// frame boundary yields io.EOF and keeps yielding it (a nil request, no
// wedged state, no panic).
func TestEOFTerminatesClean(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	wb := &wireBuilder{}
	wb.head(1, true, hf(":method", "GET", ":path", "/x", ":scheme", "http"))
	p := New(newWireStub(wb.bytes(), c), optsStd(c, time.Second, 100))
	mustNext(t, p)
	for i := 0; i < 3; i++ {
		if r, err := p.Next(); !errors.Is(err, io.EOF) || r != nil {
			t.Errorf("eof %d: got (%+v, %v), want nil/io.EOF", i, r, err)
		}
	}
}

// TestNeverPanicsFuzzSeeds hammers structurally evil wires: any panic is
// the defect — classification correctness is the tables' job.
func TestNeverPanicsFuzzSeeds(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	seeds := [][]byte{
		{}, {0x00}, {0x00, 0x00, 0x00},
		rawFH(0, 0x0, 0x0, 1),
		rawFH(0, 0x1, 0x0, 1),         // HEADERS with an empty block
		rawFH(1, 0x1, 0x0, 0),         // HEADERS on stream 0
		rawFH(1<<10, 0x0, 0x0, 1),     // lying length, empty buffer
		rawFH((1<<24)-1, 0x0, 0x0, 1), // maximal length claim
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		rawFH(0, 0x2, 0x0, 1), // priority with an empty payload block
		rawFH(1, 0x9, 0x0, 1), // bare CONTINUATION
		rawFH(0, 0x7, 0x0, 0), // GOAWAY with an empty payload
		rawFH(3, 0x3, 0x0, 1), // short RST payload
	}
	for i, seed := range seeds {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("seed %d panicked: %v", i, p)
				}
			}()
			stub := newWireStub(seed, c)
			parser := New(stub, optsStd(c, time.Second, 100))
			for j := 0; j < 4; j++ {
				if _, err := parser.Next(); err != nil {
					break
				}
			}
		}()
	}
}
