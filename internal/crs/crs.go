// Package crs — TR-07 PR A red-phase verification: the compile surface
// (verdict struct, options, NewFromFile) exists; every method is a
// not-implemented stub pending the GREEN slice. The RED commit's suite
// must fail here.
package crs

import (
	"errors"
	"net/netip"
	"time"
)

// errNotImplemented marks every pending GREEN surface (the RED state).
var errNotImplemented = errors.New("crs: not implemented (TR-07 GREEN pending)")

// PhaseRequestHeaders / PhaseRequestBody are the CR request phases this
// slice evaluates (Coraza phase-1 / phase-2); response phases land with
// the response-side slice.
const (
	PhaseRequestHeaders = 1
	PhaseRequestBody    = 2
)

// Match is one rule contribution inside an evaluated phase (a Coraza
// MatchedRule projected: rule id, phase, disruptive flag).
type Match struct {
	RuleID     int
	Phase      int
	Disruptive bool
}

// Verdict is the shadow-verdict shape for one CR request across both
// phases: per-phase matches plus the interruption evidence (a
// disruptive phase-2 deny leaves an interruption carrying the denying
// rule id and its HTTP status).
type Verdict struct {
	Phase1Matches []Match
	Phase2Matches []Match
	Interrupted   bool
	InterruptRule int
	InterruptStat int
}

// Options carry the per-request scope (request line, headers, body) plus
// the injected peer scope Coraza transactions are keyed on. The clock is
// not used by the SecLang run itself (no time-based rules in the seed
// snippet); it stamps the tx scope for parity/telemetry correlation.
type Options struct {
	Method  string
	URI     string
	Version string
	Headers map[string]string
	Body    []byte
	Client  netip.Addr
	Port    int
	Now     time.Time
}

// Evaluator is the shadow evaluation surface the parity harness drives:
// load once, evaluate many (thread-safe).
type Evaluator interface {
	Evaluate(opts Options) (Verdict, error)
}

// NewFromFile loads a SecLang directive file (CRS ruleset:
// crs-setup.conf.example + the PL1 profile) into an evaluator.
func NewFromFile(path string) (Evaluator, error) {
	return nil, errNotImplemented
}
