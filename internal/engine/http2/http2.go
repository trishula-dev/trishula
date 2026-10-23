// Package http2 reconstructs an HTTP/2 (h2c) request HEAD from wire frames
// into the structured request view the rules operate on — the h2 sibling of
// the http1 head parse (TR-15; PRD §8.2 parser row "Parser: HTTP/1.1,
// HTTP/2, gRPC, WS"; §8.3 h2c leg; §11.3 view shape).
//
// Slice boundary (mirrors the http1 slice, TR-05b): the parser reads the
// request HEAD ONLY — HEADERS (+ CONTINUATION) frames. DATA, trailers,
// RST_STREAM, settings and other housekeeping frames are consumed with
// bounded accounting and are never served as view material (request-body
// inspection is its own slice). A stream's head releases the moment its
// header block reconstructs — the parser never waits on body progress, so
// an open stream (client-streaming gRPC, long-lived SSE request) never
// blocks the other heads on the connection.
//
// gRPC and SSE are content-classified on the same view (Kind): content-type
// application/grpc + variants = a gRPC head (:path = the full method),
// text/event-stream = an SSE head — classification is content-based and
// direction-agnostic at this slice.
//
// Bounded-parse discipline (§9.4 mirrored in userspace, R7b): every Next
// walks at most MaxFrames frames and arms a read deadline (the injected
// clock) on the wire reader, so a silent peer or a housekeeping frame flood
// can never pin the engine's parse loop. The HPACK header-list budget is
// the Framer's MaxHeaderListSize. All malformed-input cases are explicit
// typed errors, never panics (the engine never panics on a malformed
// request); per-stream protocol errors are absorbed (fail-open per stream —
// the connection keeps serving its other heads), connection-level errors
// terminate the walk typed.
//
// Kernel-free: the wire source is the injected WireReader (a test feeds
// synthetic frame bytes; the gateway leg hands the established connection)
// and the clock is injected (Options.Now) so the deadline window is
// deterministic in CI — no kernel plane, no sockets (CI runs pure-Go
// packages; AGENTS.md: engine parse layers run the full gate host-side
// in package tests).
//
// GREEN PENDING: Next is a RED stub — the frame walk over the injected
// reader (x/net/http2 Framer + hpack decode) lands with the GREEN commit.
package http2

import (
	"errors"
	"io"
	"time"
)

// Version is the view's version string for every h2-reconstructed head
// (the h2 request shape carries no version wire field; HTTP/2.0 is the
// de-facto reconstruction convention, as net/http reports it).
const Version = "HTTP/2.0"

// Kind classifies the request over the h2 leg (content-based, TR-15).
type Kind string

const (
	// KindHTTP is a plain HTTP request head (no gRPC or SSE media type).
	KindHTTP Kind = "http"
	// KindGRPC is a gRPC head: content-type application/grpc (+variant),
	// :path = the full RPC method (package.Service/Method).
	KindGRPC Kind = "grpc"
	// KindSSE is an SSE head: content-type text/event-stream (parameters
	// tolerated). Classification is content-based; the RESPONSE-side SSE
	// reassembly mechanism (R7b) is a later slice at the response leg.
	KindSSE Kind = "sse"
)

// Bounds for the bounded-parse discipline (§9.4 mirrored; the wire budget
// is explicit, never ambient).
const (
	// DefaultHeaderListSize is the HPACK header-list budget (bytes summed
	// over name+value; MAX_HEADER_LIST_SIZE semantics).
	DefaultHeaderListSize uint32 = 8 * 1024
	// DefaultMaxFrames is the per-Next frame-work budget: at most this
	// many frames are consumed before a head must surface (a housekeeping
	// flood yields ErrFrameBudget instead of pinning the loop).
	DefaultMaxFrames = 1 << 14
	// DefaultReadTimeout is the per-Next read window: the clock-armed
	// deadline on the wire reader (a silent peer yields ErrWindow).
	DefaultReadTimeout = 30 * time.Second
)

// Malformed-input classification: explicit values (errors.Is-able), never
// bare strings — the h1 error-family contract carried over.
var (
	// ErrConnection is a connection-level frame or HPACK error (the peer
	// violated the wire contract beyond one stream). Terminal: the parser
	// stops serving heads; the walk error carries the code detail.
	ErrConnection = errors.New("http2: connection-level wire error")
	// ErrBadPseudo is a request head missing a required pseudo header or
	// carrying an empty value (the Framer passes missing-required through
	// by contract; this layer classifies it).
	ErrBadPseudo = errors.New("http2: request head missing required pseudo header")
	// ErrWindow is the read deadline elapsed (Options.ReadTimeout, armed
	// under Options.Now) before any head reconstructed. Transient: a
	// resumed Next re-arms the deadline (the connection may still serve).
	ErrWindow = errors.New("http2: read deadline elapsed before the next head")
	// ErrFrameBudget is Options.MaxFrames frames consumed without a head.
	// Transient like ErrWindow: the walk yields, a resumed Next continues.
	ErrFrameBudget = errors.New("http2: frame work budget exhausted before the next head")
	// ErrGoAway is a peer GOAWAY: no further requests arrive (terminal).
	ErrGoAway = errors.New("http2: peer GOAWAY closed the connection")
	// ErrTruncated is the wire ending mid-frame (connection died inside a
	// frame payload; distinguishable from the clean frame-boundary EOF).
	ErrTruncated = errors.New("http2: wire ended mid-frame")
)

// Request is the §11.3 view head scope reconstructed from one h2 stream's
// HEADERS block. Same-view contract as http1.Request (method/path/version
// + header map; it extends the view, it does not fork it): h2 pseudo
// headers fold into the named fields, regular fields carry their
// lowercase wire names with duplicate fields comma-folded.
type Request struct {
	StreamID  uint32            `json:"stream_id"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Version   string            `json:"version"`
	Scheme    string            `json:"scheme"`
	Authority string            `json:"authority"`
	Headers   map[string]string `json:"headers"`
	Kind      Kind              `json:"kind"`
}

// WireReader is the injected connection-side frame source. SetReadDeadline
// is how the parser arms its clock-based read window (the deadline error
// from the reader's Read is classified as ErrWindow) — net.Conn satisfies
// the interface; the gateway leg hands the established connection; tests
// feed synthetic frame bytes.
type WireReader interface {
	io.Reader
	SetReadDeadline(t time.Time) error
}

// Options carries the injected dependencies and budgets. Nil selects the
// defaults; a zero MaxFrames selects DefaultMaxFrames (only a positive
// value overrides).
type Options struct {
	// Now is the injected clock arm read deadlines (default: time.Now).
	Now func() time.Time
	// ReadTimeout is the per-Next read window armed on the wire reader.
	ReadTimeout time.Duration
	// MaxFrames is the per-Next frame-work budget.
	MaxFrames int
}

// Parser walks one h2 connection's frames from the injected WireReader
// (TR-15). Single-goroutine by contract (TR-04 ingest owns the
// concurrency decision, mirroring the ladder's Rule).
type Parser struct {
	w       WireReader
	now     func() time.Time
	timeout time.Duration
	max     int
}

// New builds a connection parser over w. opts may be nil (defaults apply).
func New(w WireReader, opts *Options) *Parser {
	if opts == nil {
		opts = &Options{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	timeout := opts.ReadTimeout
	if timeout <= 0 {
		timeout = DefaultReadTimeout
	}
	max := opts.MaxFrames
	if max <= 0 {
		max = DefaultMaxFrames
	}
	return &Parser{w: w, now: now, timeout: timeout, max: max}
}

// Next reconstructs the next request head from the wire and returns it,
// released exactly once per stream (head-release semantics: never waits on
// body progress; an open stream never blocks a later head).
//
// Per-frame consumption follows RFC 9113: housekeeping frames (SETTINGS,
// PING, WINDOW_UPDATE, PRIORITY, unknown types) are consumed silently;
// DATA frames are consumed and dropped (head-only slice); a second HEADERS
// block on a released stream is trailers — consumed, never re-released,
// never folded into the frozen view. Per-stream protocol errors (bad
// pseudo headers, wire-level field violations) are absorbed — the walk
// continues so the connection's other heads still serve. Connection-level
// errors (ErrConnection, ErrTruncated) and ErrGoAway terminate the walk
// typed; io.EOF at a frame boundary is the clean end of the wire.
func (p *Parser) Next() (*Request, error) {
	// RED stub: the frame walk is the pending GREEN work (Framer-over-
	// WireReader + HPACK meta headers + classification). The zero-value
	// return makes every suite expectation fail on camera until it lands.
	return &Request{}, nil
}
