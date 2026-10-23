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
// The frame codec is golang.org/x/net/http2's Framer with ReadMetaHeaders
// (the maintained HPACK implementation: static + dynamic table, Huffman,
// CONTINUATION assembly) — the connection's HPACK state lives on the one
// Framer for the connection's life. No connection preface: the gateway leg
// is post-negotiation h2 (h2c or ALPN), which both deliver framed traffic
// past the preface. Duplicate regular header fields keep the LAST value —
// the same overwrite rule the http1 view's header map uses (same-view
// parity).
package http2

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
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

	// maxReadFrameSize caps one frame read: a frame claiming a larger
	// payload is a wire violation the Framer refuses (typed below).
	maxReadFrameSize = 1 << 20
	// hpackDynTableBytes is the HPACK dynamic table's default size (4096
	// bytes, the SETTINGS_HEADER_TABLE_SIZE default).
	hpackDynTableBytes = 4096
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
	// by contract; this layer classifies it). Per-stream: absorbed, the
	// walk continues.
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
// lowercase wire names with the last duplicate's value (the http1 header
// map's rule, same-view parity).
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
	// Now is the injected clock that arms read deadlines (default:
	// time.Now).
	Now func() time.Time
	// ReadTimeout is the per-Next read window armed on the wire reader.
	ReadTimeout time.Duration
	// MaxFrames is the per-Next frame-work budget.
	MaxFrames int
}

// Parser walks one h2 connection's frames from the injected WireReader
// (TR-15). Single-goroutine by contract (TR-04 ingest owns the
// concurrency decision, mirroring the ladder's Rule). The connection's
// HPACK decoder state is per-Parser: one parser serves ONE connection.
type Parser struct {
	fr      *http2.Framer
	w       WireReader
	now     func() time.Time
	timeout time.Duration
	max     int
	// released marks the streams whose head reconstructed (exactly-once
	// release; a later HEADERS block on a marked stream is trailers).
	released map[uint32]bool
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
	fr := http2.NewFramer(io.Discard, w)
	fr.ReadMetaHeaders = hpack.NewDecoder(hpackDynTableBytes, func(hpack.HeaderField) {})
	fr.MaxHeaderListSize = DefaultHeaderListSize
	fr.SetMaxReadFrameSize(maxReadFrameSize)
	return &Parser{fr: fr, w: w, now: now, timeout: timeout, max: max,
		released: map[uint32]bool{}}
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
// typed; io.EOF at a frame boundary is the clean end of the wire;
// ErrWindow and ErrFrameBudget are transient yields (a resumed Next
// re-arms its window and budget).
func (p *Parser) Next() (*Request, error) {
	if err := p.w.SetReadDeadline(p.now().Add(p.timeout)); err != nil {
		return nil, fmt.Errorf("%w: arm read window: %v", ErrConnection, err)
	}
	for n := 0; n < p.max; n++ {
		f, err := p.fr.ReadFrame()
		switch {
		case err == nil:
			// dispatched below
		case errors.Is(err, io.EOF):
			return nil, io.EOF
		case errors.Is(err, io.ErrUnexpectedEOF):
			return nil, fmt.Errorf("%w: %v", ErrTruncated, err)
		case isDeadline(err):
			return nil, ErrWindow
		}
		if err != nil {
			// Remaining protocol errors split by scope (RFC 9113 §5.4.3):
			// stream-scoped errors absorb; connection-scoped terminate.
			if se, ok := err.(http2.StreamError); ok {
				p.released[se.StreamID] = true
				continue
			}
			return nil, fmt.Errorf("%w: %v", ErrConnection, err)
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			if p.released[f.StreamID] {
				continue // trailers (or a repeat block): never a second release
			}
			r, verr := viewOf(f)
			if verr != nil {
				p.released[f.StreamID] = true // malformed head: stream absorbs it
				continue
			}
			p.released[f.StreamID] = true
			return r, nil
		case *http2.GoAwayFrame:
			return nil, fmt.Errorf("%w (last stream %d, code %v)",
				ErrGoAway, f.LastStreamID, f.ErrCode)
		default:
			// DATA, SETTINGS, PING, WINDOW_UPDATE, PRIORITY, RST_STREAM,
			// unknown types: consumed and dropped at the head-only slice.
		}
	}
	return nil, fmt.Errorf("%w (%d frames walked, none a head)", ErrFrameBudget, p.max)
}

// viewOf folds one reconstructed header block into the request view. The
// Framer has already rejected unknown pseudo headers, response/request
// mixes, duplicate pseudo headers and invalid field names/values at the
// stream scope; this layer classifies what passes: a head missing its
// required :method/:path (or carrying an empty one) is ErrBadPseudo.
func viewOf(f *http2.MetaHeadersFrame) (*Request, error) {
	v := &Request{StreamID: f.StreamID, Version: Version, Headers: map[string]string{}}
	for _, fl := range f.Fields {
		name, value := strings.ToLower(fl.Name), fl.Value
		switch name {
		case ":method":
			v.Method = value
		case ":path":
			v.Path = value
		case ":scheme":
			v.Scheme = value
		case ":authority":
			v.Authority = value
		}
		if strings.HasPrefix(name, ":") {
			continue // pseudo headers fold; only regular fields join the map
		}
		v.Headers[name] = value
	}
	if v.Method == "" || v.Path == "" {
		return nil, fmt.Errorf("%w: stream %d", ErrBadPseudo, v.StreamID)
	}
	v.Kind = classify(v.Headers["content-type"])
	return v, nil
}

// classify maps the content-type media type (case-insensitive, parameters
// tolerated) to the view's Kind. gRPC needs the exact application/grpc
// family — the bare type or the +variant (+proto, +json, +custom);
// grpc-web and look-alike prefixes (application/grpcfoo) are not gRPC.
func classify(contentType string) Kind {
	media := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(media, ';'); i >= 0 {
		media = strings.TrimSpace(media[:i])
	}
	switch {
	case media == "application/grpc" || strings.HasPrefix(media, "application/grpc+"):
		return KindGRPC
	case media == "text/event-stream":
		return KindSSE
	default:
		return KindHTTP
	}
}

// isDeadline reports whether the read error is the armed window's deadline
// trip (the reader's own timeout shape) rather than a transport failure.
func isDeadline(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
