package gatewayconformance

import (
	"fmt"
	"strings"

	"github.com/trishula-dev/trishula/internal/engine/http2"
	"golang.org/x/net/http2/hpack"
)

// Engine-leg contract rows (Gateway-API contract terms as they bind the Trishula
// backend side, the leg this lane drives). Names carry the `engine:`
// prefix so they never collide with the spec's honest-delta row ids.
const (
	// RowSameViewParity: contract terms 1+4, engine side — the same
	// logical request over the h1 upstream leg and over the h2c
	// upstream leg reconstructs the same view head (method, path
	// plus the client-set headers). The upstream protocol is
	// invisible to the ladder; this is the abstraction-honesty probe.
	RowSameViewParity = "engine:same-view-parity"
	// RowH2CIngress: contract term 4 — h2c engine ingress
	// (appProtocol: kubernetes.io/h2c): the profile's h2c upstream
	// head parses into the full spec head view, pseudo fields fold
	// into the named fields and every regular field joins the map.
	RowH2CIngress = "engine:h2c-ingress"
	// RowGRPCRecognized: contract term 4 — gRPC framing recognized: an
	// application/grpc head classifies KindGRPC and :path carries the
	// full RPC method, whatever implementation forwarded it.
	RowGRPCRecognized = "engine:grpc-recognized"
	// RowPlainBackendView: contract term 1, engine side — the engine is a
	// plain Service backend that never selects endpoints: the
	// reconstructed views carry exactly the spec head fields and no
	// gateway-endpoint or implementation-specific fields.
	RowPlainBackendView = "engine:plain-backend-view"
)

// ContractRows is the engine-leg contract row set Run drives. The four
// ids are the only rows the lane's verdicts name; the contract's gateway-leg
// terms (weighted steering, readiness, failOpen fallback, TLS mode,
// binding) bind no case here — they are the delta record's
// per-gateway rows.
var ContractRows = map[string]bool{
	RowSameViewParity:   true,
	RowH2CIngress:       true,
	RowGRPCRecognized:   true,
	RowPlainBackendView: true,
}

// Frame is one h2 wire frame of a profile case, written through
// golang.org/x/net/http2's Framer write side (the maintained frame
// codec — the xhttp2 import never hand-rolls conforming bytes).
type Frame struct {
	Type      string              // "headers" | "data"
	Stream    uint32              // the stream id the frame belongs to
	EndStream bool                // the END_STREAM flag the leg carries
	Fields    []hpack.HeaderField // headers frames
	Payload   []byte              // data frames
}

// Want is the spec head reconstruction an h2 case pins. Headers is
// the exact map (regular fields only — pseudo fields fold into the
// named struct fields); Scheme carries the profile's tested plaintext
// hop value (contract term 4 plus the spec's per-mode visibility rule: the engine leg is plain).
type Want struct {
	Method    string
	Path      string
	Scheme    string
	Authority string
	Kind      http2.Kind
	Headers   map[string]string
}

// ParityCase drives RowSameViewParity: one logical request, delivered
// once as the profile's h1 upstream bytes and once as its h2c frames.
// Shared lists the client-set headers both legs must carry (names
// case-folded: h2 wire names are lowercase, h1 keeps the sent case).
type ParityCase struct {
	Name   string
	H1Wire []byte
	Frames []Frame
	Shared map[string]string
}

// H2Case drives RowH2CIngress or RowGRPCRecognized.
type H2Case struct {
	Name     string
	Contract string  // the engine-leg contract row this case binds
	Frames   []Frame // the h2c upstream wire sequence
	Want     Want    // the pinned reconstruction
}

// Role says which side of the spec's honest-delta lane a profile represents.
type Role string

const (
	// RoleReference is the reference implementation (the spec's Gateway API integration). The live e2e
	// gate for this role is lab/dx1 (nightly); the profile here holds
	// the same contract at the parse layer.
	RoleReference Role = "reference"
	// RoleSecondary is the secondary-gateway lane member (the spec's R12 risk row).
	RoleSecondary Role = "secondary"
)

// Profile is one Gateway API implementation's engine-leg conformance
// data: the wire shapes its data plane sends toward the engine Service
// on the steered upstream leg, plus the reconstruction each shape must
// yield. A shape is lane DATA (the tested upstream-leg form the
// implementation's documented forwarding produces), never a behaviour
// claim beyond this lane's cells.
type Profile struct {
	ID          string
	Impl        string
	Role        Role
	Version     string
	VersionNote string
	Parity      ParityCase
	H2          []H2Case
}

// Validate checks one profile's lane data: identity pins, a parity
// case that carries both legs plus shared headers, h2 cases bound to
// real contract rows, and complete wire forms and wants.
func (p Profile) Validate() error {
	if p.ID == "" || p.Impl == "" || p.Version == "" || p.VersionNote == "" {
		return fmt.Errorf("gatewayconformance: profile %q: empty id, impl or version pin", p.ID)
	}
	if p.Role != RoleReference && p.Role != RoleSecondary {
		return fmt.Errorf("gatewayconformance: profile %q: unknown role %q", p.ID, p.Role)
	}
	if p.Parity.Name == "" || len(p.Parity.H1Wire) == 0 || len(p.Parity.Frames) == 0 || len(p.Parity.Shared) == 0 {
		return fmt.Errorf("gatewayconformance: profile %q: parity case carries no both-leg shape", p.ID)
	}
	h2c, grpc := false, false
	for _, c := range p.H2 {
		if !ContractRows[c.Contract] {
			return fmt.Errorf("gatewayconformance: profile %q: case %q binds unknown contract row %q", p.ID, c.Name, c.Contract)
		}
		if c.Name == "" || c.Want.Scheme == "" || c.Want.Authority == "" ||
			c.Want.Method == "" || c.Want.Path == "" || c.Want.Kind == "" || c.Want.Headers == nil {
			return fmt.Errorf("gatewayconformance: profile %q: incomplete h2 case %q", p.ID, c.Name)
		}
		for _, f := range c.Frames {
			if f.Type != "headers" && f.Type != "data" {
				return fmt.Errorf("gatewayconformance: profile %q: frame type %q unknown", p.ID, f.Type)
			}
			if f.Type == "headers" && len(f.Fields) == 0 {
				return fmt.Errorf("gatewayconformance: profile %q: headers frame carries no fields", p.ID)
			}
			if f.Type == "data" && f.Payload == nil {
				return fmt.Errorf("gatewayconformance: profile %q: data frame carries no payload", p.ID)
			}
		}
		switch c.Contract {
		case RowH2CIngress:
			h2c = true
		case RowGRPCRecognized:
			grpc = true
		}
	}
	if !h2c || !grpc {
		return fmt.Errorf("gatewayconformance: profile %q: the h2c ingress and gRPC recognition cases are missing", p.ID)
	}
	return nil
}

// hfPairs builds hpack header fields from name,value pairs.
func hfPairs(kvs ...string) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(kvs)/2)
	for i := 0; i+1 < len(kvs); i += 2 {
		out = append(out, hpack.HeaderField{Name: kvs[i], Value: kvs[i+1]})
	}
	return out
}

// headerMap folds hpack fields into the header map (regular fields
// only, lowercase names) — the reconstruction a case pins.
func headerMap(fls []hpack.HeaderField) map[string]string {
	m := map[string]string{}
	for _, f := range fls {
		if strings.HasPrefix(f.Name, ":") {
			continue
		}
		m[strings.ToLower(f.Name)] = f.Value
	}
	return m
}

// headFrames is the one-HEADERS-frame wire sequence for a head.
func headFrames(stream uint32, fields []hpack.HeaderField) []Frame {
	return []Frame{{Type: "headers", Stream: stream, EndStream: true, Fields: fields}}
}

// LoadProfiles returns the lane's two profiles: the NGF reference
// (the chart version the dx1 lab pins) and the Envoy Gateway secondary
// (the current envoyproxy/gateway release pin). Versions are the pins
// R3's mitigation means: pin supported versions.
func LoadProfiles() []Profile {
	// One logical steered request family per profile: a GET
	// /v1/chat/completions (shared by the h1 and h2c parity legs), a
	// POST JSON head on the h2c leg (the ingress case), and a gRPC
	// method head on the h2c leg (the recognition case). The gateway's
	// own forwarded-add headers differ per implementation (its
	// documented forwarding behaviour); the lane's contract is that
	// all of them land as regular header-map fields and never reshape
	// the view.
	shared := map[string]string{
		"authorization": "Bearer demo-token",
		"content-type":  "application/json",
	}

	// NGF (NGINX data plane): the FWD header set on the upstream leg.
	//
	//   h1 leg: as above, Host carries the authority.
	//
	ngxAdds := hfPairs("x-forwarded-for", "203.0.113.7", "x-forwarded-proto", "https")
	ngxParityF := append(hfPairs(
		":method", "GET", ":path", "/v1/chat/completions",
		":scheme", "http", ":authority", "api.example.com",
		"authorization", "Bearer demo-token", "content-type", "application/json"), ngxAdds...)
	ngxIngressF := append(hfPairs(
		":method", "POST", ":path", "/v1/chat/completions",
		":scheme", "http", ":authority", "api.example.com",
		"authorization", "Bearer demo-token", "content-type", "application/json",
		"user-agent", "dx1-client/1"), ngxAdds...)
	ngxGRPCF := append(hfPairs(
		":method", "POST", ":path", "/ingest.v1.Ingest/Process",
		":scheme", "http", ":authority", "ingest.example.com",
		"content-type", "application/grpc",
		"authorization", "Bearer demo-token", "user-agent", "grpc-client/1"), ngxAdds...)
	ngxH1 := "GET /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Authorization: Bearer demo-token\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\n" +
		"X-Forwarded-Proto: https\r\n\r\n"

	// Envoy Gateway: Envoy's upstream request headers (XFF, the
	// forwarded proto, x-request-id).
	envoyAdds := hfPairs("x-forwarded-for", "203.0.113.7",
		"x-forwarded-proto", "https", "x-request-id", "tr-lane-01")
	envoyParityF := append(hfPairs(
		":method", "GET", ":path", "/v1/chat/completions",
		":scheme", "http", ":authority", "api.example.com",
		"authorization", "Bearer demo-token", "content-type", "application/json"), envoyAdds...)
	envoyIngressF := append(hfPairs(
		":method", "POST", ":path", "/v1/chat/completions",
		":scheme", "http", ":authority", "api.example.com",
		"authorization", "Bearer demo-token", "content-type", "application/json",
		"user-agent", "dx1-client/1"), envoyAdds...)
	envoyGRPCF := append(hfPairs(
		":method", "POST", ":path", "/ingest.v1.Ingest/Process",
		":scheme", "http", ":authority", "ingest.example.com",
		"content-type", "application/grpc",
		"authorization", "Bearer demo-token", "user-agent", "grpc-client/1"), envoyAdds...)
	envoyH1 := "GET /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Authorization: Bearer demo-token\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\n" +
		"X-Request-Id: tr-lane-01\r\n\r\n"

	return []Profile{
		{
			ID:          "ngf",
			Impl:        "NGINX Gateway Fabric (NGF)",
			Role:        RoleReference,
			Version:     "2.7.2",
			VersionNote: "the chart version lab/dx1 pins (NGF_CHART_VERSION); Gateway API v1.5.1 standard channel",
			Parity: ParityCase{
				Name:   "steered GET over both legs",
				H1Wire: []byte(ngxH1),
				Frames: headFrames(1, ngxParityF),
				Shared: shared,
			},
			H2: []H2Case{
				{Name: "h2c steered POST", Contract: RowH2CIngress, Frames: headFrames(3, ngxIngressF), Want: Want{
					Method: "POST", Path: "/v1/chat/completions", Scheme: "http",
					Authority: "api.example.com", Kind: http2.KindHTTP,
					Headers: headerMap(ngxIngressF)}},
				{Name: "h2c gRPC method", Contract: RowGRPCRecognized, Frames: headFrames(5, ngxGRPCF), Want: Want{
					Method: "POST", Path: "/ingest.v1.Ingest/Process", Scheme: "http",
					Authority: "ingest.example.com", Kind: http2.KindGRPC,
					Headers: headerMap(ngxGRPCF)}},
			},
		},
		{
			ID:          "envoy-gw",
			Impl:        "Envoy Gateway",
			Role:        RoleSecondary,
			Version:     "1.9.2",
			VersionNote: "envoyproxy/gateway release pin (v1.9.2, released 2026-09-28)",
			Parity: ParityCase{
				Name:   "steered GET over both legs",
				H1Wire: []byte(envoyH1),
				Frames: headFrames(1, envoyParityF),
				Shared: shared,
			},
			H2: []H2Case{
				{Name: "h2c steered POST", Contract: RowH2CIngress, Frames: headFrames(3, envoyIngressF), Want: Want{
					Method: "POST", Path: "/v1/chat/completions", Scheme: "http",
					Authority: "api.example.com", Kind: http2.KindHTTP,
					Headers: headerMap(envoyIngressF)}},
				{Name: "h2c gRPC method", Contract: RowGRPCRecognized, Frames: headFrames(5, envoyGRPCF), Want: Want{
					Method: "POST", Path: "/ingest.v1.Ingest/Process", Scheme: "http",
					Authority: "ingest.example.com", Kind: http2.KindGRPC,
					Headers: headerMap(envoyGRPCF)}},
			},
		},
	}
}
