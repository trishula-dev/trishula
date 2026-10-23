// model.go carries the in-band (T1) model seam (§14.2 T1 "ONNX inline")
// and the v0 reference model: every inline scorer plugs one interface,
// scores a FeatureView under the stage's context deadline, and carries an
// id that tags verdicts, cache entries and evidence.
package ml

import (
	"context"
)

// Model is the T1 in-band model seam (§14.2 item 2: ONNX inline,
// tree/linear tabular models, µs-class). Score maps one FeatureView to a
// score in [0, 1]. The context carries the stage's hard budget deadline
// (§20.1 R6): a model MUST honor it and report its error — the budget
// gate in the stage relies on the context, never on wall-clock
// measurement.
type Model interface {
	ID() string
	Score(ctx context.Context, fv FeatureView) (float64, error)
}

// LinearWeights is the §14.2 linear-family scorer's weight table. Each
// feature enters the sum normalized to [0, 1] by its fixed v0 cap
// (linCap), so a weight is a unitless family multiplier.
type LinearWeights struct {
	// Intercept is the base score.
	Intercept float64
	// NonGet weights any non-GET method (the v0 one-hot method family).
	NonGet float64
	// PathLen weights the path byte length (capped 256).
	PathLen float64
	// PathEntropy weights the target entropy (capped 8).
	PathEntropy float64
	// SpecialCharRatio weights the special-char ratio (already [0, 1]).
	SpecialCharRatio float64
	// QueryParams weights the param count (capped 32).
	QueryParams float64
	// WindowRequests weights the largest rate-window value (capped 1000).
	WindowRequests float64
	// FlowPackets weights the flow packet counter (capped 100).
	FlowPackets float64
}

// LinearModel is the v0 reference model: an untrained, deterministic
// linear scorer over FeatureView (µs-class tabular work; no detection
// claim rides it). The ONNX runtime adapter plugs the Model seam in a
// later slice — a cgo build is out here (repo rule: no CGO in Go code).
type LinearModel struct {
	id string
	w  LinearWeights
}

// NewLinearModel builds the reference scorer. An empty id is a wiring
// error: the id tags verdicts, cache entries and evidence records.
func NewLinearModel(id string, w LinearWeights) (LinearModel, error) {
	return LinearModel{}, nil // TR-21 RED stub
}

// ID returns the model tag.
func (m LinearModel) ID() string { return m.id }

// Score computes sigmoid(weights over the normalized FeatureView). The
// reference model honors a dead context up front (the budget contract).
func (m LinearModel) Score(ctx context.Context, fv FeatureView) (float64, error) {
	return 0, nil // TR-21 RED stub
}
