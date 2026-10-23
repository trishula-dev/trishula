// model.go carries the in-band (T1) model seam (the spec's T1 "ONNX inline" hand-off)
// and the v0 reference model: every inline scorer plugs one interface,
// scores a FeatureView under the stage's context deadline, and carries an
// id that tags verdicts, cache entries and evidence.
package ml

import (
	"context"
	"fmt"
	"math"
)

// Model is the T1 in-band model seam (the spec's hand-off item 2: ONNX inline,
// tree/linear tabular models, µs-class). Score maps one FeatureView to a
// score in [0, 1]. The context carries the stage's hard budget deadline
// (the spec's R6 risk row): a model MUST honor it and report its error — the budget
// gate in the stage relies on the context, never on wall-clock
// measurement.
type Model interface {
	ID() string
	Score(ctx context.Context, fv FeatureView) (float64, error)
}

// LinearWeights is the spec's linear-family scorer's weight table. Each
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
	if id == "" {
		return LinearModel{}, fmt.Errorf("linear model: empty id (the id tags verdicts + cache entries)")
	}
	return LinearModel{id: id, w: w}, nil
}

// ID returns the model tag.
func (m LinearModel) ID() string { return m.id }

// Score computes sigmoid(weights over the normalized FeatureView). The
// reference model honors a dead context up front (the budget contract).
func (m LinearModel) Score(ctx context.Context, fv FeatureView) (float64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	z := m.w.Intercept
	if fv.Method != "GET" {
		z += m.w.NonGet
	}
	z += m.w.PathLen * linCap(float64(fv.PathLen), 256)
	z += m.w.PathEntropy * linCap(fv.PathEntropy, 8)
	z += m.w.SpecialCharRatio * fv.SpecialCharRatio
	z += m.w.QueryParams * linCap(float64(fv.QueryParams), 32)
	z += m.w.WindowRequests * linCap(float64(fv.WindowRequests), 1000)
	z += m.w.FlowPackets * linCap(float64(fv.FlowPackets), 100)
	return 1 / (1 + math.Exp(-z)), nil
}

// linCap normalizes a raw family value to [0, 1] by a fixed cap: values
// at or above the cap report 1, below report v/cap, negatives report 0.
func linCap(v, cap float64) float64 {
	if v >= cap {
		return 1
	}
	if v < 0 {
		return 0
	}
	return v / cap
}
