package fastpathdifferential

// The kernel-free gate: the corpus shadow run on both decision streams
// (userspace fast-path projection plus the engine verdict stream), the
// parity census and the mismatch budget read. This test is the CI report;
// host CI runs it with the `go test -tags coraza.rule.no_regex_multiline
// -p 1 ./...` step of go-build.yml (kernel-free).
//
// The kernel-gated leg carries its own e2e file (e2e_diff_linux_test.go,
// tagged linux plus the fastpath_diff_e2e job tag plus the root/euid skip
// gate) and proves the projection against the committed kernel object.

import (
	"strconv"
	"testing"
)

// TestFastPathDifferential runs the shadow differential over the whole
// corpus: one parity census, one shape inventory, one budget read. A
// pinned delta that a live walk confirms is a corpus finding: re-pin with
// the fresh recorded run, keep the old pin in the finding trail.
func TestFastPathDifferential(t *testing.T) {
	corpus, err := LoadCorpus()
	if err != nil {
		t.Fatalf("corpus load: %v", err)
	}
	res, err := RunCorpus(corpus)
	if err != nil {
		t.Fatalf("shadow run: %v", err)
	}

	t.Logf("fastpath-differential census: cases %d, ran %d, skipped %d",
		res.Cases, res.Ran, res.Skipped)
	t.Logf("fastpath-differential census: parity %d/%d, pinned deltas %d",
		res.Pinned, res.Ran, len(res.Deltas))
	shapes := ""
	for _, s := range ShapeClasses {
		shapes += s + " " + strconv.Itoa(res.Shapes[s]) + " "
	}
	t.Logf("fastpath-differential census: shapes %s", shapes)
	t.Logf("fastpath-differential census: plane-split %d (drop-vs-nondecisive %d, forward-vs-decisive %d)",
		res.Live["plane-split"], res.SplitSubs["drop-vs-nondecisive"], res.SplitSubs["forward-vs-decisive"])

	for _, d := range res.Deltas {
		t.Errorf("pinned delta: %s", d)
	}
	for _, v := range VerifyBudgets(res.Live) {
		t.Logf("fastpath-differential budget row %s: live %d, %s", v.Class, v.Live, v.Detail)
		if !v.Holds {
			t.Errorf("budget row %s: %s", v.Class, v.Detail)
		}
	}
}

// TestCorpusCoversRouteDecisions counts the materialized shape classes and
// holds the inventory contract: every shape class the record names carries
// at least one materialized case, and no case names a class outside the
// contract. The count reads from the materialized corpus, never from a
// remembered minimum.
func TestCorpusCoversRouteDecisions(t *testing.T) {
	corpus, err := LoadCorpus()
	if err != nil {
		t.Fatalf("corpus load: %v", err)
	}
	contract := map[string]bool{}
	for _, s := range ShapeClasses {
		contract[s] = true
	}
	counts := map[string]int{}
	for _, c := range corpus.Cases {
		if len(c.Classes) == 0 {
			t.Errorf("corpus case %s: no shape class", c.Name)
		}
		for _, s := range c.Classes {
			if !contract[s] {
				t.Errorf("corpus case %s: class %q outside the contract", c.Name, s)
			}
			counts[s]++
		}
	}
	for _, s := range ShapeClasses {
		t.Logf("fastpath-differential corpus: class %s carries %d case(s)", s, counts[s])
		if counts[s] < 1 {
			t.Errorf("corpus class %s carries %d cases; the inventory needs at least one", s, counts[s])
		}
	}
}
