// framing.go (TR-199): the h1 framing-ambiguity reject classes, live in
// Parse — the conformance verdict record's verdict table row 2 ("engine
// parse layer"): the classes the record names, each an explicit typed
// error, each rejected at the moment the head becomes ambiguous.
//
// The classes (RFC 9112 sections 6.1 and 6.3; the record's reject table):
//
//   - CL+TE: Content-Length and Transfer-Encoding on one head. RFC 9112
//     section 6.1 lets a server reject the request or honor the
//     Transfer-Encoding alone, and MUST close after. The engine owns the
//     strict cell (reject) per the record: "Grammar checks are
//     parse-layer material"; the value is the attack signal itself (a
//     pool's framing read differs from the engine's head read — F2: no
//     body reads exist to reconcile one).
//   - duplicate CL: a second Content-Length field line. Differing values
//     = the RFC 9112 section 6.3 invalid-CL MUST set (400 + close).
//     Equal values = the RFC's recipient-MAY freedom (treat as one
//     value), which the engine resolves STRICTLY at the WAF altitude:
//     an ambiguity the pool may read another way is the desync signal
//     (the record's conformance rule, first paragraph; Go net/http
//     trims + deduplicates the same shape — the engine owns the
//     stricter cell, the borrowed-strictness row upgraded one step).
//
// Deferred with the record's coding-validity row (NOT built here): the
// transfer-coding validity set (section 6.3's non-final chunked MUST)
// and the single-field comma-list CL value (section 6.3's MAY case).
// The rule ids and the verdict mapping live in the ladder package
// (internal/engine/ladder/parsegate.go): the checks are parse-layer
// material, the verdict cells are ladder material (the record's section
// 4 table maps the violation classes to the verdict vocabulary).
package http1

import "errors"

// The framing-ambiguity reject classes (TR-199). errors.Is-able
// (classification contracts: never bare strings, never panics).
var (
	// ErrFramingCLTE = Content-Length + Transfer-Encoding together
	// (RFC 9112 section 6.1; the record's reject-table class).
	ErrFramingCLTE = errors.New("http1: framing ambiguity: Content-Length with Transfer-Encoding (RFC 9112 section 6.1)")
	// ErrFramingDupCL = duplicate Content-Length field values (RFC 9112
	// section 6.3; the differing-values MUST set, the equal-values MAY
	// freedom resolved strict: reject-on-ambiguity).
	ErrFramingDupCL = errors.New("http1: framing ambiguity: duplicate Content-Length values (RFC 9112 section 6.3)")
)
