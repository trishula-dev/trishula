// parsegate.go (TR-199): the parse-layer conformance rejects map to the
// ladder vocabulary here — the conformance verdict record's section 4
// table ("h1 framing ambiguity → reject at request; close discipline
// stays at the gateway"). The checks are parse-layer material
// (internal/engine/http1/framing.go); the reject TABLE — the verdict
// class and the rule ids — is the ladder's. Grammar checks are never
// rule material: no matcher or CRS rule exists for these classes.
package ladder

import (
	"errors"

	"github.com/trishula-dev/trishula/internal/engine/http1"
)

// The parse-layer conformance reject cells (the record's reject table):
// the block verdict per the record's mapping row, the rule id naming the
// parse-layer class. Reject-on-ambiguity posture: the request never
// reaches CRS (pre-CRS: the parse product predates the walk; the
// framing reject is decisive and short-circuits everything).
const (
	// RuleIDFramingCLTE = the CL+TE class (RFC 9112 section 6.1).
	RuleIDFramingCLTE RuleID = "http1:framing-cl-te"
	// RuleIDFramingDupCL = the duplicate-CL class (RFC 9112 section 6.3;
	// differing values, and equal values under the strict posture).
	RuleIDFramingDupCL RuleID = "http1:framing-dup-cl"
)

// ParseGateVerdict maps one h1 parse outcome to the record's reject
// table. nil = not a conformance reject: a clean parse walks the ladder
// exactly as before, and a non-framing parse error stays the caller's
// typed-error surface (the TR-05b taxonomy; no invented cells here).
// The framing cells carry the block verdict (decisive: the record's
// grammar-violation mapping — "reject at request: block, local 4xx") at
// the request-headers phase, with the class rule id as provenance.
func ParseGateVerdict(parseErr error) *Verdict {
	switch {
	case parseErr == nil:
		return nil
	case errors.Is(parseErr, http1.ErrFramingCLTE):
		return &Verdict{Action: ActionBlock, Rules: []RuleID{RuleIDFramingCLTE}, Phase: PhaseRequestHeaders}
	case errors.Is(parseErr, http1.ErrFramingDupCL):
		return &Verdict{Action: ActionBlock, Rules: []RuleID{RuleIDFramingDupCL}, Phase: PhaseRequestHeaders}
	}
	return nil
}
