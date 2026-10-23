package gatewayconformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	// ErrProfile: the profile data violated the lane's shape contract
	// (Validate's finding, classified at the Run boundary).
	ErrProfile = errors.New("gatewayconformance: profile shape contract violated")
	// ErrDrive: the injected surface pair is incomplete (a nil leg).
	ErrDrive = errors.New("gatewayconformance: injected drive surface incomplete")
	// ErrWire: a profile's wire form failed to render (renderWire,
	// classified at the Run boundary).
	ErrWire = errors.New("gatewayconformance: profile wire form failed to render")
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
// Misuse errors (profile shape, incomplete drive, render failure)
// carry the typed error; a conformance MISS is never an error — it is
// a false Finding whose detail carries the observed against the
// expected (a red lane log names its row without re-running anything).
func Run(p Profile, d Drive) ([]Finding, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProfile, err)
	}
	if d.H1 == nil || d.H2 == nil {
		return nil, ErrDrive
	}
	fs := make([]Finding, 0, 4)

	// The parity case parses once; both legs feed the parity row and
	// the parsed views feed the plain-backend view-shape row.
	h1v, h1err := d.H1(p.Parity.H1Wire)
	h2v, h2err := driveWire(d, p.Parity.Frames)
	fs = append(fs, parityFinding(p.ID, p.Parity, h1v, h1err, h2v, h2err))
	h2Views := make([]*http2.Request, 0, len(p.H2)+1)
	if h2v != nil {
		h2Views = append(h2Views, h2v)
	}
	for _, c := range p.H2 {
		f, v := driveCase(p.ID, c, d)
		fs = append(fs, f)
		if v != nil {
			h2Views = append(h2Views, v)
		}
	}
	fs = append(fs, viewShapeFinding(p.ID, h1v, h2Views))
	return fs, nil
}

// driveWire renders a case's frames and drives them through the
// injected h2 surface.
func driveWire(d Drive, frames []Frame) (*http2.Request, error) {
	wire, err := renderWire(frames)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWire, err)
	}
	return d.H2(wire)
}

// parityFinding checks RowSameViewParity: equal method and path, and
// every shared client header on both legs (names case-folded — h2
// wire names are lowercase, h1 keeps the sent case).
func parityFinding(profileID string, pc ParityCase, h1v *http1.Request, h1err error, h2v *http2.Request, h2err error) Finding {
	f := Finding{Profile: profileID, Row: RowSameViewParity, Case: pc.Name, Pass: true}
	if h1err != nil {
		return miss(f, "h1 leg parse: "+h1err.Error())
	}
	if h2err != nil {
		return miss(f, "h2c leg parse: "+h2err.Error())
	}
	if h1v.Method != h2v.Method {
		return miss(f, fmt.Sprintf("method %q over h1 against %q over h2c", h1v.Method, h2v.Method))
	}
	if h1v.Path != h2v.Path {
		return miss(f, fmt.Sprintf("path %q over h1 against %q over h2c", h1v.Path, h2v.Path))
	}
	for name, want := range pc.Shared {
		got1, ok1 := lookupFold(h1v.Headers, name)
		got2, ok2 := lookupFold(h2v.Headers, name)
		if !ok1 || !ok2 {
			return miss(f, fmt.Sprintf("shared header %q: present h1 %v, present h2c %v", name, ok1, ok2))
		}
		if got1 != want || got2 != want {
			return miss(f, fmt.Sprintf("shared header %q: h1 %q, h2c %q, want %q", name, got1, got2, want))
		}
	}
	return f
}

// driveCase checks one h2 case against its pinned want (the full-view
// compare for the ingress row; the kind and method path for the gRPC
// row). The parsed view returns for the view-shape collector.
func driveCase(profileID string, c H2Case, d Drive) (Finding, *http2.Request) {
	f := Finding{Profile: profileID, Row: c.Contract, Case: c.Name, Pass: true}
	v, err := driveWire(d, c.Frames)
	if err != nil {
		return miss(f, "drive: "+err.Error()), nil
	}
	if detail := compareWant(v, c.Want); detail != "" {
		return miss(f, detail), v
	}
	return f, v
}

// compareWant names the first observed-vs-expected difference between
// a reconstructed view and its pinned want (empty = the cell holds).
func compareWant(v *http2.Request, w Want) string {
	if v.Method != w.Method {
		return fmt.Sprintf("method %q, want %q", v.Method, w.Method)
	}
	if v.Path != w.Path {
		return fmt.Sprintf("path %q, want %q", v.Path, w.Path)
	}
	if v.Scheme != w.Scheme {
		return fmt.Sprintf("scheme %q, want %q", v.Scheme, w.Scheme)
	}
	if v.Authority != w.Authority {
		return fmt.Sprintf("authority %q, want %q", v.Authority, w.Authority)
	}
	if v.Kind != w.Kind {
		return fmt.Sprintf("kind %q, want %q", v.Kind, w.Kind)
	}
	if !mapsEqual(v.Headers, w.Headers) {
		return fmt.Sprintf("header map %v, want %v", v.Headers, w.Headers)
	}
	return ""
}

// viewShapeFinding checks RowPlainBackendView: the parsed views carry
// exactly the §11.3 head fields — the view never grows a
// gateway-endpoint or implementation-specific field (a set compare:
// the field inventory is the contract, key order never is).
func viewShapeFinding(profileID string, h1v *http1.Request, h2vs []*http2.Request) Finding {
	f := Finding{Profile: profileID, Row: RowPlainBackendView, Case: "view-shape", Pass: true}
	wantH1 := []string{"method", "path", "version", "headers"}
	wantH2 := []string{"stream_id", "method", "path", "version", "scheme", "authority", "headers", "kind"}
	if h1v != nil {
		got := sortedKeys(h1v)
		if !sameSet(got, wantH1) {
			return miss(f, fmt.Sprintf("h1 view carries %v, want the §11.3 head shape %v", got, wantH1))
		}
	}
	for _, v := range h2vs {
		got := sortedKeys(v)
		if !sameSet(got, wantH2) {
			return miss(f, fmt.Sprintf("h2 view carries %v, want the §11.3 head shape %v", got, wantH2))
		}
	}
	return f
}

// sameSet compares two field-name sets with order out of the compare.
func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	m := make(map[string]bool, len(want))
	for _, name := range want {
		m[name] = true
	}
	for _, name := range got {
		if !m[name] {
			return false
		}
	}
	return true
}

// sortedKeys lists one view's JSON field keys sorted (the §11.3 head
// shape check's projection over the JSON tags).
func sortedKeys(v any) []string {
	b, err := json.Marshal(v)
	if err != nil {
		return []string{"unmarshalable"}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return []string{"unmarshalable"}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mapsEqual compares two header maps exactly (same keys, same values).
func mapsEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, wv := range want {
		if gv, ok := got[k]; !ok || gv != wv {
			return false
		}
	}
	return true
}

// lookupFold finds a header map value by case-folded name.
func lookupFold(m map[string]string, name string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// miss flips a finding to its failed state with the observed detail.
func miss(f Finding, detail string) Finding {
	f.Pass = false
	f.Detail = detail
	return f
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
					return nil, fmt.Errorf("hpack encode: %v", err)
				}
			}
			if err := w.WriteHeaders(xhttp2.HeadersFrameParam{StreamID: f.Stream,
				EndHeaders: true, EndStream: f.EndStream, BlockFragment: block.Bytes()}); err != nil {
				return nil, fmt.Errorf("head frame: %v", err)
			}
		case "data":
			if err := w.WriteData(f.Stream, f.EndStream, f.Payload); err != nil {
				return nil, fmt.Errorf("data frame: %v", err)
			}
		default:
			return nil, fmt.Errorf("frame type %q unknown", f.Type)
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
