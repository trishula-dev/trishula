package bench

// Guard: the percentile estimator is the nearest-rank rule, exactly, on
// pinned inputs. One concern: the percentile math the spec's budget-table p50/p99
// reports stand on.
import (
	"testing"
)

func TestPercentileNearestRank(t *testing.T) {
	cases := []struct {
		name string
		xs   []float64
		p    float64
		want float64
	}{
		{name: "n8 p50", xs: []float64{3, 1, 4, 1, 5, 9, 2, 6}, p: 0.50, want: 3},
		{name: "n8 p99", xs: []float64{3, 1, 4, 1, 5, 9, 2, 6}, p: 0.99, want: 9},
		{name: "n8 p25", xs: []float64{3, 1, 4, 1, 5, 9, 2, 6}, p: 0.25, want: 1},
		{name: "n5 p50 exact half", xs: []float64{10, 20, 30, 40, 50}, p: 0.50, want: 30},
		{name: "n5 p99", xs: []float64{10, 20, 30, 40, 50}, p: 0.99, want: 50},
		{name: "n5 p20 exact boundary", xs: []float64{10, 20, 30, 40, 50}, p: 0.20, want: 10},
		{name: "p0 clamps to first", xs: []float64{10, 20, 30}, p: 0, want: 10},
		{name: "p1 clamps to last", xs: []float64{10, 20, 30}, p: 1, want: 30},
	}
	for _, tc := range cases {
		got := Percentile(tc.xs, tc.p)
		if got != tc.want {
			t.Errorf("%s: Percentile = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := Percentile(nil, 0.99); got != 0 {
		t.Errorf("empty input: Percentile = %v, want 0", got)
	}
	if got := Percentile([]float64{1}, 0.99); got != 1 {
		t.Errorf("n1 p99: Percentile = %v, want 1", got)
	}
}
