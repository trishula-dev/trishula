// Package ml implements the §14 ML tiers seam on ladder stage S7 (TR-21):
// FeatureView v1 extraction from the parsed §11.3 view, the in-band scorer
// under a hard latency budget (§20.1 R6), and the async judge contract —
// suspicious-only, non-blocking, verdicts cached (TTL + model tag).
//
// The binding §14.2 rule shapes every type here: ML reads structured
// feature views derived from engine + eBPF events, never raw wire data.
// The S7 fragment is LOG-only at this slice (the ladder v0 posture);
// JudgeVerdict carries no action, so a judge result can annotate, never
// decide — verdicts are never LLM-only (§14.2 item 4).
//
// Slice boundary (v0):
//   - the Model seam takes any context-honoring scorer; the v0 reference
//     model is an untrained deterministic linear scorer — no detection
//     claim rides it;
//   - a cgo ONNX runtime build is out (repo rule: no CGO in Go code); the
//     ONNX adapter is a named follow-up on the same Model seam;
//   - §14.2 items outside this slice stay out: the T2 request-verdict
//     cache and kernel map write-back (§13.3 loop), the T3 escalation pod,
//     decoded-payload/session/fingerprint feature families, and the
//     learning lifecycle. FeatureView v1 fields are additive; absent
//     families land when their producers exist.
package ml

import (
	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// FeatureViewVersion is the version tag stamped on every extracted view
// (§14.2 item 1: FeatureView v1, stable, version-tagged). Fields are
// additive across versions; consumers key cache and evidence records on
// the version they were built against.
const FeatureViewVersion = "v1"

// FeatureView is the canonical per-request feature vector (§14.2 item 1).
// v0 carries the field families the current inputs fill: the §11.3
// request view (method/path/query, rate windows) and the flow cheap
// counters (§9.5, via the ingest tx). Every field is an aggregate — no
// raw payload text rides the view into scoring or evidence.
type FeatureView struct {
	// Version is the FeatureView schema tag (FeatureViewVersion).
	Version string
	// Method is the request method (one-hot encoding happens in the model,
	// not here).
	Method string
	// PathLen is the request-target byte length (path + query).
	PathLen int
	// PathEntropy is the Shannon entropy in bits per byte over the request
	// target (path + query); 0 on an empty target. Range [0, 8].
	PathEntropy float64
	// SpecialCharRatio is the fraction of bytes outside the alphabetic,
	// digit and common-URL classes (- . / _ ~) over the request target;
	// 0 on an empty target. Range [0, 1].
	SpecialCharRatio float64
	// QueryParams counts the non-empty &-separated query segments (param
	// names carry the §14.2 param-count family; values are dropped).
	QueryParams int
	// WindowRequests is the largest §11.3 rate-window value attached to the
	// request (the engine contribution; 0 when none).
	WindowRequests int64
	// FlowPackets is the tx flow-packet counter (the §9.5 eBPF cheap
	// counter contribution).
	FlowPackets uint64
}

// Extract builds the FeatureView for one tx from its parsed §11.3 request
// view (ladder.AttachView is the attachment contract). It reports false
// when the view is nil — the extractor never fabricates features for an
// absent parse; the parse stages own the tx.
func Extract(view *cel.Request, tx *ingest.TxContext) (FeatureView, bool) {
	return FeatureView{}, false // TR-21 RED stub: GREEN lands the §14.2 extraction
}

// Signature is the normalized request signature (§14.2 item 5): the
// signature that verdict-cache keys key on. v0 normalization keeps the
// method, the target and the param NAMES, and drops param values — two
// requests of one shape share one signature.
func Signature(fv FeatureView) string {
	return "" // TR-21 RED stub: GREEN lands the §14.2 normalization
}
