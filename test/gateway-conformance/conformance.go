package gatewayconformance

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/http1"
	"github.com/trishula-dev/trishula/internal/engine/http2"
	xhttp2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Finding is one conformance verdict: the profile, the engine-leg
// contract row it drove, the case name, and the observed-vs-expected
// detail a failing cell names in a red CI log.
type Finding struct {
	Profile string
	Row     string
	Case    string
	Pass    bool
	Detail  string
}

// Misuse classification for the lane's own contract errors (explicit
// values, errors.Is-able — the h1/h2 error-family contract).
var (
	// ErrNotImplemented: the lane's verdict surface is pending its
	// GREEN commit (TR-26): the drive path over the engine parse
	// packages. The record and profile data validate already.
	ErrNotImplemented = errors.New("gatewayconformance: verdict surface not implemented")
	// ErrProfile: the profile data violated the lane's shape contract
	// (Validate's findings, classified for the Run boundary).
	ErrProfile = errors.New("gatewayconformance: profile shape contract violated")
	// ErrDrive: the injected surface pair is incomplete (a nil leg).
	ErrDrive = errors.New("gatewayconformance: injected drive surface incomplete")
)

// Drive is the injected engine-leg surface pair the lane checks: the
// h1 head parse and the h2 head drive over one wire byte sequence.
// The production pair (NewDrive) binds the merged engine parse
// packages; a test binds its own twin. The lane never opens sockets
// or reads a clock of its own.
type Drive struct {
	// H1 parses one h1 upstream head from the wire bytes.
	H1 func(wire []byte) (*http1.Request, error)
	// H2 drives one h2c upstream wire sequence and returns its head.
	H2 func(wire []byte) (*http2.Request, error)
}

// NewDrive binds the production pair: internal/engine/http1.Parse and
// a http2 connection parser over the rendered wire (fixed injected
// clock — the parse window is deterministic in CI, never ambient).
func NewDrive() Drive {
	now := func() time.Time { return time.Unix(1700000000, 0) }
	return Drive{
		H1: func(wire []byte) (*http1.Request, error) {
			return http1.Parse(wire)
		},
		H2: func(wire []byte) (*http2.Request, error) {
			p := http2.New(wireStubFrom(wire), &http2.Options{Now: now})
			return p.Next()
		},
	}
}

// Run drives one profile's cases through the injected engine-leg
// surfaces and returns one finding per row: the parity case, each h2
// case, and the plain-backend view-shape check over the parsed views.
// Misuse errors (profile shape, incomplete drive) carry the typed
// error; a conformance MISS is never an error — it is a false Finding
// the caller gates on.
func Run(p Profile, d Drive) ([]Finding, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProfile, err)
	}
	if d.H1 == nil || d.H2 == nil {
		return nil, ErrDrive
	}
	return nil, ErrNotImplemented
}

// renderWire writes a case's frames through the x/net Framer write
// side + the real HPACK encoder (conforming bytes, never hand-rolled).
func renderWire(frames []Frame) ([]byte, error) {
	var buf bytes.Buffer
	w := xhttp2.NewFramer(&buf, bytes.NewReader(nil))
	for _, f := range frames {
		switch f.Type {
		case "headers":
			var block bytes.Buffer
			enc := hpack.NewEncoder(&block)
			for _, fl := range f.Fields {
				if err := enc.WriteField(fl); err != nil {
					return nil, fmt.Errorf("gatewayconformance: hpack encode: %v", err)
				}
			}
			if err := w.WriteHeaders(xhttp2.HeadersFrameParam{StreamID: f.Stream,
				EndHeaders: true, EndStream: f.EndStream, BlockFragment: block.Bytes()}); err != nil {
				return nil, fmt.Errorf("gatewayconformance: head frame: %v", err)
			}
		case "data":
			if err := w.WriteData(f.Stream, f.EndStream, f.Payload); err != nil {
				return nil, fmt.Errorf("gatewayconformance: data frame: %v", err)
			}
		default:
			return nil, fmt.Errorf("gatewayconformance: frame type %q unknown", f.Type)
		}
	}
	return buf.Bytes(), nil
}

// wireStub feeds rendered wire bytes as an http2.WireReader (the
// synthetic-frame connection; SetReadDeadline accepts the armed
// window — the drive clock is the fixed injected one).
type wireStub struct {
	r *bytes.Reader
}

func wireStubFrom(b []byte) *wireStub { return &wireStub{r: bytes.NewReader(b)} }

func (w *wireStub) Read(p []byte) (int, error) { return w.r.Read(p) }

func (w *wireStub) SetReadDeadline(t time.Time) error { return nil }
