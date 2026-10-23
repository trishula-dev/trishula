// Package gatewayconformance implements the PRD §10 secondary-gateway
// conformance lane (TR-26; PRD §10.5 portability honest-delta and
// §20.1 R12): the engine leg of the §10.2 Gateway API contract, checked
// in CI against BOTH the NGF reference profile and the Envoy Gateway
// secondary profile.
//
// The lane's falsifiable claim: the engine leg is
// implementation-independent — a steered request head reconstructs the
// same §11.3 view whatever conformant Gateway-API implementation
// delivers it, so an NGF-specific assumption wired into the parse
// surface shows up as a conformance-row violation against the second
// profile the day it is written, not in production portability. This
// is the R12 mitigation in-repo: "secondary-gateway CI lane (Envoy GW)
// keeps abstractions honest".
//
// Slice boundary (one concern): the lane drives the ENGINE-LEG
// contract rows — same-view parity, h2c ingress, gRPC recognition, and
// the plain-backend view shape — through the merged engine parse
// packages (internal/engine/http1, internal/engine/http2) over
// synthetic profile frames. Gateway-leg capabilities (steering,
// canary weights, weight-0 failOpen fallback, TLS mode, EPP) are
// gateway behaviour: they stay in the typed delta record with their
// per-gateway verify marker and are never claimed by this lane's
// verdicts. The live kind lab holds the reference implementation's
// e2e run (lab/dx1, nightly); a secondary live leg is its own slice.
//
// Kernel-free and socket-free: profile wire forms are synthetic bytes
// fed through the injected Drive surface (wire stubs, fixed clock), so
// the lane runs in the hosted CI gate (`go test ./...`) per AGENTS.md.
//
// The delta record is also the R12 per-release review artifact: the
// nine §10.5 rows stand in typed data, with each row's leg, expected
// reference/secondary behaviour and honest degradation from the PRD
// table verbatim.
package gatewayconformance

import (
	"fmt"
)

// Leg says which plane a §10.5 delta row lives on:
// LegGateway (gateway behaviour per Gateway API implementation),
// LegEngine (Trishula's engine leg, driveable in CI), LegKernel
// (the eBPF shield plane, gateway-independent by contract).
type Leg string

const (
	// LegGateway marks gateway-leg rows (never claimed by this lane).
	LegGateway Leg = "gateway"
	// LegEngine marks engine-leg rows (driveable here).
	LegEngine Leg = "engine"
	// LegKernel marks the shield rows (kernel plane, lab-gated).
	LegKernel Leg = "kernel"
)

// Row encodes one §10.5 portability honest-delta row with the PRD
// table's wording verbatim: Reference and Secondary carry the table's
// expectation cells, Degradation its degradation cell, Leg the plane
// the capability lives on, PerGatewayVerify the rows the PRD marks
// "verify per gateway" (an implementation-class row the lane must not
// auto-claim).
type Row struct {
	ID               string
	Capability       string
	Reference        string
	Secondary        string
	Degradation      string
	Leg              Leg
	PerGatewayVerify bool
}

// Delta is the loaded §10.5 honest-delta table keyed by row id.
type Delta struct {
	ByID map[string]Row
}

// LoadDelta returns the §10.5 honest-delta table. Rows are verbatim
// from the PRD table (nine rows). LoadDelta fails on any malformed or
// double id — the record never ships a silently-fudged row.
func LoadDelta() (Delta, error) {
	rows := []Row{
		{ID: "steer-http", Capability: "Steer HTTP to engine Service", Reference: "✅ core", Secondary: "✅ core",
			Degradation: "none", Leg: LegGateway},
		{ID: "h2c-to-engine", Capability: "h2c to engine", Reference: "✅", Secondary: "✅ common",
			Degradation: "none", Leg: LegEngine},
		{ID: "weighted-canary", Capability: "Weighted canary/shadow ramp", Reference: "✅", Secondary: "✅ core",
			Degradation: "none", Leg: LegGateway},
		{ID: "readiness-gated-pools", Capability: "Readiness-gated pools", Reference: "✅", Secondary: "✅ universal",
			Degradation: "none", Leg: LegGateway},
		{ID: "gateway-tls-terminate", Capability: "Gateway TLS termination", Reference: "✅ `Terminate`", Secondary: "✅ table stakes",
			Degradation: "none", Leg: LegGateway},
		{ID: "weight0-fallback-failopen", Capability: "Weight-0 fallback `backendRef` for failOpen", Reference: "✅",
			Secondary:   "implementable on conformant impls; **verify per gateway**",
			Degradation: "failOpen may need header-based fallback instead", Leg: LegGateway, PerGatewayVerify: true},
		{ID: "extproc-nohop", Capability: "ext_proc no-hop mode", Reference: "— (v2 on Envoy-family)",
			Secondary: "Envoy-family only", Degradation: "Variant A everywhere else", Leg: LegGateway, PerGatewayVerify: true},
		{ID: "epp-model-pool", Capability: "EPP model-pool steering", Reference: "✅ documented[39]", Secondary: "GIE-conformant impls",
			Degradation: "static weights elsewhere", Leg: LegGateway, PerGatewayVerify: true},
		{ID: "shield-gateway-independent", Capability: "Shield (eBPF)", Reference: "✅ gateway-independent",
			Secondary:   "✅ gateway-independent",
			Degradation: "none", Leg: LegKernel},
	}
	d := Delta{ByID: make(map[string]Row, len(rows))}
	for _, r := range rows {
		if r.ID == "" || r.Capability == "" || r.Reference == "" || r.Secondary == "" || r.Degradation == "" {
			return Delta{}, fmt.Errorf("gatewayconformance: delta row %+v: empty cell", r)
		}
		switch r.Leg {
		case LegGateway, LegEngine, LegKernel:
		default:
			return Delta{}, fmt.Errorf("gatewayconformance: delta row %q: unknown leg %q", r.ID, r.Leg)
		}
		if r.Leg != LegGateway && r.PerGatewayVerify {
			return Delta{}, fmt.Errorf("gatewayconformance: delta row %q: per-gateway verify outside a gateway-leg row", r.ID)
		}
		if _, dup := d.ByID[r.ID]; dup {
			return Delta{}, fmt.Errorf("gatewayconformance: delta row %q doubles an earlier row", r.ID)
		}
		d.ByID[r.ID] = r
	}
	if len(d.ByID) != 9 {
		return Delta{}, fmt.Errorf("gatewayconformance: delta table carries %d rows, want the §10.5 table's 9", len(d.ByID))
	}
	return d, nil
}
