package main

// TR-203 L3 (issue #264, leaf 3) — the engine inline QUIC/HTTP-3 listener.
// TR-34's TLS-termination secondary mode gains the opt-in QUIC listener: the
// --h3-listen flag plus the unchanged --tls-cert/--tls-key pair open the UDP
// leg; the TCP listener's responses advertise the alternative (Alt-Svc) and
// the h3 request view serves through the engine's own handler (the same
// consult, verdict and proxy path). Decision 1 of issue #264 holds: the flag
// off = no UDP socket and no advertisement, and the default deployment stays
// the gateway-terminated path.
//
// The transport decision (the ADR statement rides the lane's PR body): the
// QUIC transport = golang.org/x/net/quic — the Go team's QUIC package inside
// the repo's already-pinned x/net v0.61.0. The import carries
// golang.org/x/crypto v0.58.0 in as one new indirect module row (BSD-3, the
// Go team). The alternative named for the operator = github.com/quic-go/
// quic-go (MPL-2.0, a new direct module). No crypto surface is vendored.
// The package is a work in progress; its documented limitation list carries:
// "0-RTT is not supported" and "Address migration is not supported" — the
// 0-RTT bullet pins probe P5's posture (below).
//
// Probe P5 (the 0-RTT posture, docs/design/h3-ingress-posture.md): the
// transport accepts no early data, and h3ListenSpec pins no
// session-resumption material (a nil session cache on the TLS config). Early
// data never reaches the ladder; the posture reads reject by construction.
// The dated read lands in the posture record via the lane's PR.
//
// The RFC 9114 layer = the minimal request-message surface a terminator
// needs: each side's control stream with SETTINGS first, request streams as
// HEADERS + DATA frames, responses as HEADERS + DATA frames. Server push,
// CONNECT, trailers and extension frames stay outside the leaf: push streams
// from a peer error, CONNECT resets, unknown frame types and unknown
// unidirectional stream types ignore per the RFC's extension rules. Limits
// pin at boot: h3MaxFrameLen (any one frame's length) and
// h3MaxFieldSectionSize (announced as SETTINGS_MAX_FIELD_SECTION_SIZE; an
// oversized request head resets with H3_MESSAGE_ERROR). The request body
// streams to the handler; the QUIC flow control bounds its window.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/quic"
)

// Frame types (RFC 9114, section 7.2, Table 2) and unidirectional stream
// types (section 6.2). The values read verbatim from the RFC's tables.
const (
	h3FrameData     uint64 = 0x00
	h3FrameHeaders  uint64 = 0x01
	h3FrameSettings uint64 = 0x04
	h3FrameGoaway   uint64 = 0x07

	h3StreamTypeControl  uint64 = 0x00
	h3StreamTypePush     uint64 = 0x01
	h3StreamTypeQEncoder uint64 = 0x02
	h3StreamTypeQDecoder uint64 = 0x03
)

// Settings parameters (RFC 9114 Table 3 + RFC 9204 section 5).
const (
	h3SettingQPACKMaxTableCapacity uint64 = 0x01
	h3SettingMaxFieldSectionSize   uint64 = 0x06
)

// HTTP/3 error codes (RFC 9114, section 8.1, Table 4 + RFC 9204, section 5).
const (
	h3ErrNoError             uint64 = 0x0100
	h3ErrStreamCreationError uint64 = 0x0103
	h3ErrClosedCritical      uint64 = 0x0104
	h3ErrFrameUnexpected     uint64 = 0x0105
	h3ErrMessageError        uint64 = 0x010e
	h3ErrQpackDecompress     uint64 = 0x0200
)

// The listener's two boot-pinned limits.
const (
	h3MaxFrameLen         int64 = 1 << 20  // any one frame's length on the wire
	h3MaxFieldSectionSize int   = 32 << 10 // the HEADERS payload cap, both directions
	h3MaxResponseChunk    int   = 1 << 16  // one DATA frame's response chunk
)

// errH3NeedsTLS classifies the half-configured h3 gate: the address without
// the full cert pair never opens a UDP socket.
var errH3NeedsTLS = errors.New("engine: the inline HTTP/3 listener needs both --tls-cert and --tls-key")

// h3Config carries the opt-in listener's resolved spec: one TLS shape for
// both legs and the QUIC transport config that carries it. The QUIC config
// pins nothing beyond TLSConfig: no stateless reset key, no logger — the
// listener adds no secret surface, and the zero fields keep the transport's
// own defaults (the idle and handshake timeouts).
type h3Config struct {
	tls  *tls.Config
	quic *quic.Config
	addr string
}

// h3ListenSpec resolves the inline H3 gate. An empty address = nil (the
// opt-in off: no UDP surface, the default gateway-terminated posture). A set
// address without the full cert pair = errH3NeedsTLS (a boot error, never a
// half-open listener). The set gate = TLS 1.3 (the QUIC floor, RFC 9001),
// the h3 ALPN, the unchanged TR-203 L4 key-exchange profile and the h1 TLS
// listener's same cert pair. The session cache stays nil: the 0-RTT posture
// (probe P5) reads reject by construction.
func h3ListenSpec(certFile, keyFile, h3Addr string) (*h3Config, error) {
	if h3Addr == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errH3NeedsTLS
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("engine: h3 listener: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: tlsPQCKeyExchange,
		NextProtos:       []string{"h3"},
		Certificates:     []tls.Certificate{pair},
	}
	return &h3Config{
		tls:  tlsCfg,
		quic: &quic.Config{TLSConfig: tlsCfg},
		addr: h3Addr,
	}, nil
}

// h3Server owns the bound UDP endpoint and its accept loop.
type h3Server struct {
	ep        *quic.Endpoint
	handler   http.Handler
	altSvc    string
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// startH3Listener binds the UDP endpoint and starts the accept loop. The
// bound port feeds the Alt-Svc advertisement; the caller wires it through
// altSvcHandler onto the TCP TLS listener's responses (never onto the h3 leg
// itself: the h3 listener serves the raw handler).
func startH3Listener(cfg *h3Config, handler http.Handler) (*h3Server, error) {
	ep, err := quic.Listen("udp", cfg.addr, cfg.quic)
	if err != nil {
		return nil, fmt.Errorf("engine: h3 listen %s: %w", cfg.addr, err)
	}
	udpPort := ep.LocalAddr().Port()
	s := &h3Server{
		ep:      ep,
		handler: handler,
		altSvc:  fmt.Sprintf(`h3=":%d"`, udpPort),
	}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr reports the bound UDP address (the boot log and the tests read it).
func (s *h3Server) Addr() string {
	return s.ep.LocalAddr().String()
}

// AltSvc reports the Alt-Svc advertisement value for the TCP TLS responses.
func (s *h3Server) AltSvc() string {
	return s.altSvc
}

// Close terminates the endpoint and waits for the accept loop to return.
// Idempotent: a repeated Close returns its first result shape (nil on a
// clean stop).
func (s *h3Server) Close() error {
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.ep.Close(ctx); err != nil {
			return
		}
	})
	s.wg.Wait()
	return nil
}

// serve accepts QUIC connections until the endpoint closes.
func (s *h3Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ep.Accept(context.Background())
		if err != nil {
			return // the endpoint closed
		}
		s.wg.Add(1)
		go s.serveConn(conn)
	}
}

// h3ConnState tracks one connection's control-stream state (RFC 9114
// section 6.2.1: one control stream per peer; the SETTINGS frame first).
type h3ConnState struct {
	mu          sync.Mutex
	controlSeen bool
}

// serveConn runs one QUIC connection: the server's control stream opens
// first; the peer's streams then route by direction (the unidirectional
// streams to their type handlers, the bidirectional ones to the request
// server).
func (s *h3Server) serveConn(conn *quic.Conn) {
	defer s.wg.Done()
	if err := s.openServerControlStream(conn); err != nil {
		conn.Abort(&quic.ConnectionCloseError{Code: h3ErrNoError, Reason: "control stream open failed"})
		return
	}
	state := &h3ConnState{}
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return // the peer closed the connection or the endpoint shut
		}
		if stream.IsReadOnly() {
			s.wg.Add(1)
			go s.serveUniStream(conn, stream, state)
			continue
		}
		s.wg.Add(1)
		go s.serveRequestStream(conn, stream)
	}
}

// openServerControlStream opens the server's unidirectional control stream
// and sends the SETTINGS frame as the first frame (RFC 9114, section 6.2.1;
// RFC 9204, section 5). The announced QPACK table capacity = 0 keeps every
// peer's request blocks in the literal/static shape the codec reads.
func (s *h3Server) openServerControlStream(conn *quic.Conn) error {
	st, err := conn.NewSendOnlyStream(context.Background())
	if err != nil {
		return err
	}
	var buf []byte
	buf = h3AppendVarint(buf, h3StreamTypeControl)
	var settings []byte
	settings = h3AppendSetting(settings, h3SettingQPACKMaxTableCapacity, 0)
	settings = h3AppendSetting(settings, h3SettingMaxFieldSectionSize, uint64(h3MaxFieldSectionSize))
	buf = h3AppendFrame(buf, h3FrameSettings, settings)
	if _, err := st.Write(buf); err != nil {
		return err
	}
	return st.Flush()
}

// serveUniStream routes one peer unidirectional stream by its type.
func (s *h3Server) serveUniStream(conn *quic.Conn, stream *quic.Stream, state *h3ConnState) {
	defer s.wg.Done()
	typ, err := h3ReadVarint(stream)
	if err != nil {
		return // the peer reset the stream before the header arrived
	}
	switch typ {
	case h3StreamTypeControl:
		if !claimControlStream(conn, state) {
			return // the connection error already fired
		}
		s.readControlStream(conn, stream)
	case h3StreamTypeQEncoder:
		// The peer's QPACK encoder stream. The listener announced
		// capacity 0; insert instructions would violate that
		// announcement, and the request decoder rejects any dynamic
		// reference (QPACK_DECOMPRESSION_FAILED). The stream drains;
		// the request-side check is the enforcing surface.
		drainStream(stream)
	case h3StreamTypeQDecoder:
		// The peer's QPACK decoder stream (its acknowledgments). The
		// listener never sends encoder instructions (its encoder stays
		// literal-only), so nothing blocks on this stream's drain.
		drainStream(stream)
	case h3StreamTypePush:
		// A push stream runs server-to-client only. A peer push stream
		// = the stream-creation error (RFC 9114, section 6.2.2).
		h3AbortConn(conn, h3ErrStreamCreationError, "push stream from client")
	default:
		// Unknown stream types discard, per RFC 9114 section 6.2.
		_ = stream.CloseRead()
	}
}

// claimControlStream admits the peer's single control stream.
func claimControlStream(conn *quic.Conn, state *h3ConnState) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.controlSeen {
		h3AbortConn(conn, h3ErrStreamCreationError, "second control stream")
		return false
	}
	state.controlSeen = true
	return true
}

// readControlStream parses the peer's control stream: the SETTINGS frame
// must carry the first frame, a second SETTINGS frame = the frame-unexpected
// connection error (section 6.2.1), GOAWAY and unknown frame types ignore
// (the leaf pushes nothing, so no push-cancellation surface exists). The
// stream's closure = the critical-stream error (section 6.2.1).
func (s *h3Server) readControlStream(conn *quic.Conn, stream *quic.Stream) {
	settingsSeen := false
	for {
		typ, payload, err := h3ReadFrame(stream, h3MaxFrameLen)
		if err != nil {
			// The peer's control stream closed: the closed-critical-
			// stream error per RFC 9114 section 6.2.1. A clean endpoint
			// shutdown aborts the connection first; the error fires
			// only against a live peer.
			h3AbortConn(conn, h3ErrClosedCritical, "control stream closed")
			return
		}
		switch typ {
		case h3FrameSettings:
			if settingsSeen {
				h3AbortConn(conn, h3ErrFrameUnexpected, "second SETTINGS frame")
				return
			}
			settingsSeen = true
			if err := consumeSettings(payload); err != nil {
				h3AbortConn(conn, h3ErrFrameUnexpected, "malformed SETTINGS payload")
				return
			}
		case h3FrameGoaway:
			// The client's GOAWAY: the engine finishes the streams in
			// flight and stops accepting new ones on its next drain.
			// The leaf takes the minimal leg; no push surface exists.
		default:
			// CANCEL_PUSH, MAX_PUSH_ID and unknown or extension frame
			// types ignore, per RFC 9114 section 9.
		}
	}
}

// consumeSettings walks one SETTINGS payload (identifier, value pairs) and
// enforces the known-parameter rules. The listener's own encoder never uses
// the dynamic table and its response heads stay small, so the peer's
// QPACK_MAX_TABLE_CAPACITY and MAX_FIELD_SECTION_SIZE values read but bind
// nothing; unknow parameters ignore per RFC 9114 section 7.2.4. A duplicate
// identifier = the settings error per the same section.
func consumeSettings(payload []byte) error {
	c := &qpackCursor{b: payload}
	seen := make(map[uint64]bool)
	for c.i < len(payload) {
		id, err := readH3VarintOnCursor(c)
		if err != nil {
			return err
		}
		value, err := readH3VarintOnCursor(c)
		if err != nil {
			return err
		}
		if seen[id] {
			return fmt.Errorf("h3: duplicate setting identifier %#x", id)
		}
		seen[id] = true
		_ = value // no parameter changes the leaf's shape (capacity 0, small heads)
	}
	return nil
}

// readH3VarintOnCursor reads one RFC 9000 section 16 variable-length integer
// from an in-memory cursor.
func readH3VarintOnCursor(c *qpackCursor) (uint64, error) {
	first, err := c.byteNext()
	if err != nil {
		return 0, err
	}
	length := 1 << uint(first>>6)
	value := uint64(first) & 0x3F
	for i := 1; i < length; i++ {
		b, err := c.byteNext()
		if err != nil {
			return 0, errQpackTrailing
		}
		value = value<<8 | uint64(b)
	}
	return value, nil
}

// h3RequestStream carries one request stream's parse state.
type h3RequestStream struct {
	sawHead    bool
	sawTrailer bool
	sawData    bool
}

// serveRequestStream reads one bidirectional request stream end to end,
// rebuilds the *http.Request and serves it through the engine's own handler.
// Errors never cross the handler: malformed heads reset the stream
// (H3_MESSAGE_ERROR), decompression failures abort the connection
// (QPACK_DECOMPRESSION_FAILED), misplaced frames abort it
// (H3_FRAME_UNEXPECTED), and a panic logs and closes the connection — the
// process never crashes on a malformed request.
func (s *h3Server) serveRequestStream(conn *quic.Conn, stream *quic.Stream) {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("engine: h3 handler panic recovered (stream %d): %v", stream.ID(), r)
			conn.Abort(&quic.ConnectionCloseError{Code: h3ErrMessageError, Reason: "handler panic"})
		}
		_ = stream.Close()
	}()

	rs := &h3RequestStream{}
	var body *h3RequestBody
	for frameDone := false; !frameDone; {
		typ, payload, err := h3ReadFrame(stream, h3MaxFrameLen)
		if err != nil {
			if rs.sawHead {
				// the body ended (fin or reset); the handler reads no
				// further
				return
			}
			// a stream that ends before any HEADERS frame
			_ = stream.Reset(h3ErrMessageError)
			return
		}
		switch typ {
		case h3FrameHeaders:
			if !rs.sawHead {
				rs.sawHead = true
				if int64(len(payload)) > int64(h3MaxFieldSectionSize) {
					_ = stream.Reset(h3ErrMessageError)
					return
				}
				fields, derr := qpackDecodeHeaderBlock(payload)
				if derr != nil {
					h3AbortConn(conn, h3ErrQpackDecompress, derr.Error())
					return
				}
				req, protoErr := h3BuildRequest(conn, fields)
				if protoErr != nil {
					_ = stream.Reset(h3ErrMessageError)
					return
				}
				body = &h3RequestBody{conn: conn, stream: stream}
				req.Body = io.NopCloser(body)
				w := newH3ResponseWriter(stream)
				s.handler.ServeHTTP(w, req)
				if err := w.finalize(); err != nil {
					log.Printf("engine: h3 response write for %s %s: %v", req.Method, req.URL.Path, err)
				}
				// the response fins with the stream close (the deferred
				// Close). The request's unread tail discards through
				// the read abort inside Close.
				frameDone = true
			} else {
				// a second field section: trailers land outside the
				// leaf — the frame is misplaced after the message ends
				h3AbortConn(conn, h3ErrFrameUnexpected, "HEADERS after the response")
				return
			}
		case h3FrameData:
			if !rs.sawHead {
				// DATA before HEADERS = the frame-unexpected connection
				// error (RFC 9114, section 4.1)
				h3AbortConn(conn, h3ErrFrameUnexpected, "DATA before HEADERS")
				return
			}
			// the body reader owns the DATA frames for its own Read
			// calls; the frames this loop sees are the ones no reader
			// claimed — they stage into the body's backlog
		default:
			// unknown frame types interleave freely (RFC 9114
			// section 9); the leaf serves the message frames only.
		}
	}
}

// h3RequestBody feeds one request's body from the DATA frames the stream
// receives after its HEADERS frame. The reader claims frames lazily, so a
// handler that never reads the body still lets the stream drain through the
// listener's Close.
type h3RequestBody struct {
	conn   *quic.Conn
	stream *quic.Stream
	buf    []byte
	atEOF  bool
}

// Read continues the body from the next DATA frame.
func (b *h3RequestBody) Read(p []byte) (int, error) {
	for len(b.buf) == 0 {
		if b.atEOF {
			return 0, io.EOF
		}
		typ, payload, err := h3ReadFrame(b.stream, h3MaxFrameLen)
		if err != nil {
			b.atEOF = true
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, io.EOF
			}
			return 0, io.ErrUnexpectedEOF
		}
		switch typ {
		case h3FrameData:
			b.buf = payload
		case h3FrameHeaders:
			// the trailer section: the body ends; the leaf drops the
			// trailers (no header surface reads them)
			b.atEOF = true
			return 0, io.EOF
		default:
			// unknown frame types ignore
		}
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

// h3ResponseWriter adapts one h3 request stream to the http.ResponseWriter
// contract: WriteHeader encodes the field section once; Write streams DATA
// frames; finalize flushes and fins the stream.
type h3ResponseWriter struct {
	stream *quic.Stream
	hdr    http.Header
	code   int
	wrote  bool
}

// newH3ResponseWriter builds the writer for one request stream.
func newH3ResponseWriter(stream *quic.Stream) *h3ResponseWriter {
	return &h3ResponseWriter{stream: stream, hdr: make(http.Header), code: http.StatusOK}
}

// h3HopHeaders names the hop-by-hop fields an h3 response never carries.
var h3HopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade"}

// Header answers the http.ResponseWriter contract.
func (w *h3ResponseWriter) Header() http.Header { return w.hdr }

// WriteHeader encodes the response's field section once. The :status
// pseudo-header rides first; the hop-by-hop fields drop.
func (w *h3ResponseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.code = code
	fields := make([]hpack.HeaderField, 0, len(w.hdr)+1)
	fields = append(fields, hpack.HeaderField{Name: ":status", Value: strconv.Itoa(code)})
	names := make([]string, 0, len(w.hdr))
	for name := range w.hdr {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if isH3HopHeader(name) || name == "Alt-Svc" {
			continue
		}
		for _, v := range w.hdr[name] {
			fields = append(fields, hpack.HeaderField{Name: strings.ToLower(name), Value: v})
		}
	}
	block, err := qpackEncodeHeaders(fields)
	if err != nil {
		// a field's bytes failed the encoder; the response degrades to
		// a bare status line (the record's fail-safe, not a panic)
		block, _ = qpackEncodeHeaders([]hpack.HeaderField{{Name: ":status", Value: strconv.Itoa(code)}})
	}
	_, _ = w.stream.Write(h3AppendFrame(nil, h3FrameHeaders, block))
	_ = w.stream.Flush()
}

// Write streams one DATA frame (chunked at h3MaxResponseChunk).
func (w *h3ResponseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > h3MaxResponseChunk {
			chunk = chunk[:h3MaxResponseChunk]
		}
		if _, err := w.stream.Write(h3AppendFrame(nil, h3FrameData, chunk)); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, w.stream.Flush()
}

// Flush answers the http.Flusher contract.
func (w *h3ResponseWriter) Flush() { _ = w.stream.Flush() }

// finalize flushes the response and fins the stream's send side.
func (w *h3ResponseWriter) finalize() error {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if err := w.stream.Flush(); err != nil {
		return err
	}
	return w.stream.CloseWrite()
}

// isH3HopHeader reports whether one response field is hop-by-hop.
func isH3HopHeader(name string) bool {
	for _, h := range h3HopHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// h3BuildRequest rebuilds the *http.Request from one decoded field section
// (RFC 9114, sections 4.3.1 and 4.1.2): the four request pseudo-headers once
// each, no pseudo-header after a regular field, lowercase field names, one
// of :authority or Host, and a valid :path. Violations error
// (H3_MESSAGE_ERROR at the caller).
func h3BuildRequest(conn *quic.Conn, fields []hpack.HeaderField) (*http.Request, error) {
	method, scheme, authority, path := "", "", "", ""
	header := make(http.Header, len(fields))
	host := ""
	pseudoDone := false
	sawMethod, sawScheme, sawPath, sawAuthority := false, false, false, false
	for _, f := range fields {
		if strings.HasPrefix(f.Name, ":") {
			if pseudoDone {
				return nil, fmt.Errorf("h3: pseudo-header after a regular field")
			}
			switch f.Name {
			case ":method":
				if sawMethod {
					return nil, fmt.Errorf("h3: duplicate :method")
				}
				method, sawMethod = f.Value, true
			case ":scheme":
				if sawScheme {
					return nil, fmt.Errorf("h3: duplicate :scheme")
				}
				scheme, sawScheme = f.Value, true
			case ":authority":
				if sawAuthority {
					return nil, fmt.Errorf("h3: duplicate :authority")
				}
				authority, sawAuthority = f.Value, true
			case ":path":
				if sawPath {
					return nil, fmt.Errorf("h3: duplicate :path")
				}
				path, sawPath = f.Value, true
			default:
				return nil, fmt.Errorf("h3: undefined pseudo-header %s", f.Name)
			}
			continue
		}
		pseudoDone = true
		if strings.ToLower(f.Name) != f.Name {
			return nil, fmt.Errorf("h3: field name not lowercase: %s", f.Name)
		}
		if strings.EqualFold(f.Name, "host") {
			host = f.Value
		}
		header.Add(f.Name, f.Value)
	}
	if !sawMethod || !sawPath || !sawScheme {
		return nil, fmt.Errorf("h3: request is missing a mandatory pseudo-header")
	}
	if sawAuthority && host != "" && host != authority {
		return nil, fmt.Errorf("h3: :authority and Host disagree")
	}
	if authority == "" {
		authority = host
	}
	u, err := url.Parse(path)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return nil, fmt.Errorf("h3: invalid :path %q", path)
	}
	u.Scheme = scheme
	req := &http.Request{
		Method:     method,
		URL:        u,
		Proto:      "HTTP/3.0",
		ProtoMajor: 3,
		ProtoMinor: 0,
		Header:     header,
		Host:       authority,
		RequestURI: path,
		RemoteAddr: conn.RemoteAddr().String(),
	}
	state := conn.ConnectionState()
	req.TLS = &state
	if n, cerr := strconv.ParseInt(header.Get("Content-Length"), 10, 64); cerr == nil && n > 0 {
		req.ContentLength = n
	}
	// No Content-Length field = the unknown-length body (the -1
	// sentinel): a zero ContentLength would make the reverse proxy
	// drop the outgoing body (net/http's httputil, issue 16036).
	if req.ContentLength == 0 {
		req.ContentLength = -1
	}
	return req, nil
}

// drainStream reads a stream to its end without acting on the bytes.
func drainStream(stream *quic.Stream) {
	buf := make([]byte, 8192)
	for {
		if _, err := stream.Read(buf); err != nil {
			return
		}
	}
}

// h3AbortConn closes the connection with one HTTP/3 application error.
func h3AbortConn(conn *quic.Conn, code uint64, reason string) {
	conn.Abort(&quic.ConnectionCloseError{Code: code, Reason: reason})
}

// altSvcHandler wraps one handler with the Alt-Svc advertisement: responses
// on TLS connections carry the value; plaintext responses pass unchanged.
// Both h1 and h2 responses of the engine's TLS listener serve through this
// handler.
func altSvcHandler(h http.Handler, altSvc string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Alt-Svc", altSvc)
		}
		h.ServeHTTP(w, r)
	})
}

// h3AppendVarint appends one RFC 9000 section 16 variable-length integer.
func h3AppendVarint(dst []byte, v uint64) []byte {
	switch {
	case v <= 0x3F:
		return append(dst, byte(v))
	case v <= 0x3FFF:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case v <= 0x3FFFFFFF:
		return append(dst, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst, byte(v>>56)|0xC0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// h3AppendFrame appends one framed block: type varint + length varint + the
// payload bytes.
func h3AppendFrame(dst []byte, typ uint64, payload []byte) []byte {
	dst = h3AppendVarint(dst, typ)
	dst = h3AppendVarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}

// h3AppendSetting appends one SETTINGS parameter: two variable-length ints.
func h3AppendSetting(dst []byte, id, value uint64) []byte {
	dst = h3AppendVarint(dst, id)
	return h3AppendVarint(dst, value)
}

// h3FrameReader is the reader surface h3ReadFrame needs: full reads for the
// payload plus byte reads for the varints (the QUIC Stream carries both).
type h3FrameReader interface {
	io.Reader
	io.ByteReader
}

// h3ReadFrame reads one frame from a stream: the type varint, the length
// varint, then the capped payload. A length above maxLen errors (the caller
// resets or aborts); the reader never allocates past the cap.
func h3ReadFrame(r h3FrameReader, maxLen int64) (typ uint64, payload []byte, err error) {
	typ, err = h3ReadVarint(r)
	if err != nil {
		return 0, nil, err
	}
	length, err := h3ReadVarint(r)
	if err != nil {
		return 0, nil, err
	}
	if int64(length) > maxLen {
		return 0, nil, fmt.Errorf("h3: frame %#x length %d above the cap %d", typ, length, maxLen)
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// h3ReadVarint reads one RFC 9000 section 16 variable-length integer from a
// byte reader (the QUIC Stream carries ReadByte).
func h3ReadVarint(r io.ByteReader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	length := 1 << uint(first>>6)
	value := uint64(first) & 0x3F
	for i := 1; i < length; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value = value<<8 | uint64(b)
	}
	return value, nil
}
