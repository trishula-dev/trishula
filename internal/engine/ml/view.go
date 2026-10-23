// Package ml implements the spec's ML tiers seam on ladder stage S7 (TR-21):
// FeatureView v1 extraction from the spec's parsed request view, the in-band scorer
// under a hard latency budget (the spec's R6 risk row), and the async judge contract —
// suspicious-only, non-blocking, verdicts cached (TTL + model tag).
//
// The spec's binding ML-hand-off rule shapes every type here: ML reads structured
// feature views derived from engine + eBPF events, never raw wire data.
// The S7 fragment is LOG-only at this slice (the ladder v0 posture);
// JudgeVerdict carries no action, so a judge result can annotate, never
// decide — verdicts are never LLM-only (the spec's hand-off item 4).
//
// Slice boundary (v0):
//   - the Model seam takes any context-honoring scorer; the v0 reference
//     model is an untrained deterministic linear scorer — no detection
//     claim rides it;
//   - a cgo ONNX runtime build is out (repo rule: no CGO in Go code); the
//     ONNX adapter is a named follow-up on the same Model seam;
//   - Hand-off items outside this slice stay out: the T2 request-verdict
//     cache and kernel map write-back (the spec's ban-algorithm loop), the T3 escalation pod,
//     decoded-payload/session/fingerprint feature families, and the
//     learning lifecycle. FeatureView v1 fields are additive; absent
//     families land when their producers exist.
package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strings"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
)

// FeatureViewVersion is the version tag stamped on every extracted view
// (the spec's hand-off item 1: FeatureView v1, stable, version-tagged). Fields are
// additive across versions; consumers key cache and evidence records on
// the version they were built against.
const FeatureViewVersion = "v1"

// FeatureView is the canonical per-request feature vector (the spec's hand-off item 1).
// v0 carries the field families the current inputs fill: the spec's
// request view (method/path/query, rate windows) and the flow cheap
// counters (the spec's kernel rate accounting, via the ingest tx). Every field is an aggregate — no
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
	// names carry the spec's param-count family; values are dropped).
	QueryParams int
	// WindowRequests is the largest rate-window value from the spec's view attached to the
	// request (the engine contribution; 0 when none).
	WindowRequests int64
	// FlowPackets is the tx flow-packet counter (the spec's eBPF cheap
	// counter contribution).
	FlowPackets uint64
}

// Extract builds the FeatureView for one tx from its parsed spec request view
// view (ladder.AttachView is the attachment contract). It reports false
// when the view is nil — the extractor never fabricates features for an
// absent parse; the parse stages own the tx.
func Extract(view *cel.Request, tx *ingest.TxContext) (FeatureView, bool) {
	if view == nil {
		return FeatureView{}, false // never fabricate features for an absent parse
	}
	target := view.Path + view.Query
	fv := FeatureView{
		Version:          FeatureViewVersion,
		Method:           view.Method,
		PathLen:          len(view.Path),
		PathEntropy:      shannonEntropy(target),
		SpecialCharRatio: specialCharRatio(target),
		QueryParams:      len(queryParamNames(view.Query)),
	}
	for _, w := range view.RateWindows {
		if w.Requests > fv.WindowRequests {
			fv.WindowRequests = w.Requests
		}
	}
	if tx != nil {
		fv.FlowPackets = tx.Packets
	}
	return fv, true
}

// Signature is the normalized request signature (the spec's hand-off item 5): the key the
// judge-verdict cache keys on. v0 normalization keeps the method, the path
// and the sorted param NAMES — param values are dropped entirely, so two
// requests of one shape share one signature. The digest is SHA-256 hex: the
// signature keys evidence and caches, and the raw values never land in a
// key surface.
func Signature(view *cel.Request) string {
	if view == nil {
		return ""
	}
	names := queryParamNames(view.Query)
	sort.Strings(names)
	h := sha256.New()
	h.Write([]byte(view.Method))
	h.Write([]byte{0x1f})
	h.Write([]byte(view.Path))
	h.Write([]byte{0x1f})
	h.Write([]byte(strings.Join(names, "\x1e")))
	return hex.EncodeToString(h.Sum(nil))
}

// queryParamNames splits the query's non-empty &-segments into param names
// (one home for the v0 name normalization; values drop at the first '=').
func queryParamNames(query string) []string {
	names := make([]string, 0, 8)
	for _, seg := range strings.Split(query, "&") {
		if seg == "" {
			continue
		}
		if i := strings.IndexByte(seg, '='); i >= 0 {
			seg = seg[:i]
		}
		names = append(names, seg)
	}
	return names
}

// specialCharRatio is the spec's char-class statistic: the fraction of
// request-target bytes outside the alphabetic, digit and common-URL
// classes (- . / _ ~). Empty targets report 0.
func specialCharRatio(target string) float64 {
	if len(target) == 0 {
		return 0
	}
	special := 0
	for i := 0; i < len(target); i++ {
		if !commonTargetByte(target[i]) {
			special++
		}
	}
	return float64(special) / float64(len(target))
}

// commonTargetByte is the v0 common class: bytes safe to carry in a URL.
func commonTargetByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '-' || b == '.' || b == '/' || b == '_' || b == '~':
		return true
	}
	return false
}

// shannonEntropy is the spec's entropy statistic over the request target:
// -Σ p·log2 p per byte, in [0, 8]. An empty target reports 0.
func shannonEntropy(target string) float64 {
	if len(target) == 0 {
		return 0
	}
	var seen [256]int
	for i := 0; i < len(target); i++ {
		seen[target[i]]++
	}
	e := 0.0
	n := float64(len(target))
	for _, c := range seen {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}
