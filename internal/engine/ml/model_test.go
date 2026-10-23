package ml

import (
	"context"
	"testing"
)

// TestLinearModelContract pins the in-band model seam contract on the v0
// reference model: fixed weights + one view = one deterministic score in
// the open interval (0, 1); a dead context reports its error (the budget
// contract); an empty id is a wiring error.
func TestLinearModelContract(t *testing.T) {
	m, err := NewLinearModel("ref-line-v0", LinearWeights{Intercept: -0.5, PathEntropy: 0.75})
	if err != nil {
		t.Fatalf("NewLinearModel: %v", err)
	}
	if m.ID() != "ref-line-v0" {
		t.Errorf("ID: got %q, want ref-line-v0", m.ID())
	}
	v1, err := m.Score(context.Background(), FeatureView{Version: FeatureViewVersion, PathEntropy: 6})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	v2, err := m.Score(context.Background(), FeatureView{Version: FeatureViewVersion, PathEntropy: 6})
	if err != nil {
		t.Fatalf("Score (repeat): %v", err)
	}
	if v1 != v2 {
		t.Errorf("Score: not deterministic (%g vs %g)", v1, v2)
	}
	if v1 <= 0 || v1 >= 1 {
		t.Errorf("Score: got %g, want inside (0, 1)", v1)
	}
	cx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Score(cx, FeatureView{}); err == nil {
		t.Error("Score: nil error on a dead context (the budget contract needs it)")
	}
	if _, err := NewLinearModel("", LinearWeights{}); err == nil {
		t.Error("NewLinearModel: nil error for an empty id")
	}
}
