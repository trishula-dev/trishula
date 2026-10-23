package ml

import (
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/cel"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// --- fixtures -----------------------------------------------------------

// txWithView builds a tx carrying a parsed §11.3 view (ladder.AttachView is
// the attachment contract) plus flow counters for the eBPF contribution
// (§9.5).
func txWithView(t *testing.T, method, path, query string, windows map[string]int64, packets uint64) *ingest.TxContext {
	t.Helper()
	tx := &ingest.TxContext{
		Key:      ingest.FlowKey{Family: ingest.FamilyV4},
		Packets:  packets,
		Metadata: map[string]string{},
	}
	view := &cel.Request{Method: method, Path: path, Query: query}
	if len(windows) > 0 {
		rw := map[string]cel.RateWindow{}
		for k, n := range windows {
			rw[k] = cel.RateWindow{Requests: n}
		}
		view.RateWindows = rw
	}
	if err := ladder.AttachView(tx, view); err != nil {
		t.Fatalf("AttachView: %v", err)
	}
	return tx
}

// fvOf extracts a FeatureView through the real pipeline shape.
func fvOf(t *testing.T, method, path, query string, windows map[string]int64, packets uint64) FeatureView {
	t.Helper()
	tx := txWithView(t, method, path, query, windows, packets)
	fv, ok := Extract(ladder.TxView(tx), tx)
	if !ok {
		t.Fatal("Extract: ok=false on a tx with an attached view")
	}
	return fv
}

// --- extraction tests ----------------------------------------------------

// TestExtractFeatureViewFields pins the §14.2 FeatureView v1 field families
// the v0 inputs can fill (one concern per row: method, target, params,
// counters, windows).
func TestExtractFeatureViewFields(t *testing.T) {
	tx := txWithView(t, "POST", "/v1/chat/completions", "a=b&c=d&e", map[string]int64{"5m": 41, "1m": 9}, 7)
	view := ladder.TxView(tx)
	if view == nil {
		t.Fatal("TxView returned nil for an attached view")
	}
	fv, ok := Extract(view, tx)
	if !ok {
		t.Fatal("Extract: ok=false on a tx with an attached view")
	}
	if fv.Version != FeatureViewVersion {
		t.Errorf("version: got %q, want %q", fv.Version, FeatureViewVersion)
	}
	if fv.Method != "POST" {
		t.Errorf("method: got %q, want POST", fv.Method)
	}
	if fv.PathLen != len(view.Path) {
		t.Errorf("pathLen: got %d, want %d (path + query bytes)", fv.PathLen, len(view.Path))
	}
	if fv.QueryParams != 3 {
		t.Errorf("queryParams: got %d, want 3 (non-empty &-separated segments)", fv.QueryParams)
	}
	if fv.FlowPackets != 7 {
		t.Errorf("flowPackets: got %d, want 7 (the eBPF cheap counter)", fv.FlowPackets)
	}
	if fv.WindowRequests != 41 {
		t.Errorf("windowRequests: got %d, want 41 (the largest window value)", fv.WindowRequests)
	}
}

// TestExtractEntropyAndCharClass pins the char-class statistics: exact
// special-char ratios per row, entropy zero on a flat target, positive on
// a varied one, bounds [0, 8] everywhere.
func TestExtractEntropyAndCharClass(t *testing.T) {
	rows := []struct {
		name      string
		path      string
		query     string
		wantRatio float64
		wantZero  bool // entropy expected exactly 0
	}{
		{"flat repeated target", "/aaaaaaaa", "", 0, true},
		{"varied punctuated target", "", "!@#$%&*()", 1.0, false},
		{"plain static path", "/healthz", "", 0, false},
		{"mixed target", "/ab!c", "a|b", 0.25, false},
		{"empty target", "", "", 0, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			fv := fvOf(t, "GET", r.path, r.query, nil, 0)
			if fv.SpecialCharRatio != r.wantRatio {
				t.Errorf("specialCharRatio: got %g, want %g", fv.SpecialCharRatio, r.wantRatio)
			}
			if r.wantZero && fv.PathEntropy != 0 {
				t.Errorf("pathEntropy: got %g, want 0", fv.PathEntropy)
			}
			if !r.wantZero && fv.PathEntropy <= 0 {
				t.Errorf("pathEntropy: got %g, want > 0", fv.PathEntropy)
			}
			if fv.PathEntropy < 0 || fv.PathEntropy > 8 {
				t.Errorf("pathEntropy: got %g, out of bounds [0, 8]", fv.PathEntropy)
			}
		})
	}
}

// TestExtractNoView pins the no-fabrication rule: a nil view yields
// ok=false and a zero view.
func TestExtractNoView(t *testing.T) {
	fv, ok := Extract(nil, &ingest.TxContext{})
	if ok {
		t.Error("Extract: ok=true for a nil view")
	}
	if fv != (FeatureView{}) {
		t.Errorf("Extract: got %+v, want the zero view", fv)
	}
}

// --- signature tests ------------------------------------------------------

// TestSignatureNormalization pins the §14.2 normalized request signature:
// method + target + param names, values dropped, names order-insensitive.
func TestSignatureNormalization(t *testing.T) {
	base := fvOf(t, "GET", "/a/b", "x=1&y=2", nil, 0)
	rows := []struct {
		name string
		fv   FeatureView
		same bool
	}{
		{"same shape, values swapped", fvOf(t, "GET", "/a/b", "x=9&y=8", nil, 0), true},
		{"same shape, names reordered", fvOf(t, "GET", "/a/b", "y=2&x=1", nil, 0), true},
		{"same shape twice", fvOf(t, "GET", "/a/b", "x=1&y=2", nil, 0), true},
		{"different method", fvOf(t, "POST", "/a/b", "x=1&y=2", nil, 0), false},
		{"different path", fvOf(t, "GET", "/a/c", "x=1&y=2", nil, 0), false},
		{"different param names", fvOf(t, "GET", "/a/b", "x=1&z=2", nil, 0), false},
	}
	want := Signature(base)
	if want == "" {
		t.Fatal("Signature returned an empty string for a real fixture")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := Signature(r.fv)
			if (got == want) != r.same {
				t.Errorf("Signature: got %q vs base %q — same=%v want=%v", got, want, got == want, r.same)
			}
		})
	}
}
