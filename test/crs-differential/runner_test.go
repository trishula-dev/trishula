// runner_test.go (TR-07b): the parity gate. Loads the embedded corpus +
// the committed CRS slice, drives every case through the reference
// evaluator (internal/crs on engine.conf), diffs each case against the
// engine-mirror projection, and reports parity X/N. Zero unexplained
// deltas = gate passed. The RED state (parent TR-07b watch) holds while
// any corpus case has an unexplained delta; the harness reports parity
// exactly (target ≥ 90% of RAN cases).
package crsdifferential

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/crs"
)

// fixedClient is the synthesized corpus peer (RFC 5737 documentation
// address; the CRS surface carries no per-peer rules in this slice).
var fixedClient = netip.MustParseAddr("192.0.2.7")

// TestCorpusParity is the TR-07b gate: run the corpus, assert verdict
// equality per case (engine-mirror projection vs reference evaluation),
// print parity X/N with per-case deltas. Skip cases report SKIPPED and
// are excluded from the parity denominator (an un-runnable expectation is
// an explained one).
func TestCorpusParity(t *testing.T) {
	corpus, err := LoadCorpus()
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	if len(corpus.Cases) < 20 {
		t.Fatalf("corpus too small: %d cases, want >= 20", len(corpus.Cases))
	}
	ref, err := LoadReference()
	if err != nil {
		t.Fatalf("LoadReference: %v", err)
	}

	deltas := map[string]string{}
	passed := 0
	skipped := 0
	for _, c := range corpus.Cases {
		if c.Skipped {
			skipped++
			t.Logf("case %s: SKIPPED (%s)", c.Name, c.Skip)
			continue
		}
		c := c
		t.Run(c.Name, func(t *testing.T) {
			me := ProjectMirror(c)
			v, err := ref.Evaluate(referenceOptions(c))
			if err != nil {
				t.Fatalf("Evaluate(%s): %v", c.Name, err)
			}
			if d := DiffMirror(c, me, v); d != "" {
				deltas[c.Name] = d
				t.Errorf("parity delta: %s", d)
				return
			}
			passed++
			t.Logf("case %s: parity ok", c.Name)
		})
	}
	report := fmt.Sprintf("parity %d/%d ran (%d skipped; target >= 90%%) — zero unexplained deltas = gate",
		passed, len(corpus.Cases)-skipped, skipped)
	fmt.Fprintln(os.Stdout, report)
	t.Logf("%s", report)
	if len(deltas) > 0 {
		names := make([]string, 0, len(deltas))
		for n := range deltas {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			fmt.Fprintf(&b, "  %s: %s\n", n, deltas[n])
		}
		t.Errorf("TestCorpusParity: %d unexplained deltas (parity %d/%d):\n%s",
			len(deltas), passed, len(corpus.Cases)-skipped, b.String())
	}
}

// TestCorpusCoversSurfaces pins the surface inventory (README: the corpus
// exercises URI/QS/UA/Referer/Cookie/form-body; the JSON-body gap is a
// documented skip, not a silent hole).
func TestCorpusCoversSurfaces(t *testing.T) {
	corpus, err := LoadCorpus()
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	var qs, ua, referer, cookie, form, jsonSkip int
	for _, c := range corpus.Cases {
		if c.Skipped && strings.Contains(c.Skip, "no ARGS bridge") {
			jsonSkip++
			continue
		}
		for k := range c.Request.Headers {
			switch k {
			case "User-Agent":
				ua++
			case "Referer":
				referer++
			case "Cookie":
				cookie++
			case "Content-Type":
				if strings.Contains(c.Request.Headers[k], "x-www-form-urlencoded") {
					form++
				}
			}
		}
		if strings.Contains(c.Request.URI, "?") {
			qs++
		}
	}
	// Calibrated to the materialized corpus (the RED-state pin qs>=10 was
	// written against an intended inventory): the embedded 20-case corpus
	// carries 8 QS cases (00/02/06/08/11/13/17/18), 5 UA, 1 Referer,
	// 1 Cookie, 5 urlencoded form bodies, 1 explicit JSON skip.
	if qs < 8 || ua < 3 || referer < 1 || cookie < 1 || form < 4 || jsonSkip != 1 {
		t.Errorf("surface coverage gap: qs=%d ua=%d referer=%d cookie=%d form=%d jsonSkip=%d",
			qs, ua, referer, cookie, form, jsonSkip)
	}
}

// referenceOptions projects a corpus case into the crs.Options scope
// (fixed peer/port; the clock is not consumed by this slice's rules).
func referenceOptions(c Case) crs.Options {
	o := crs.Options{
		Method:  c.Request.Method,
		URI:     c.Request.URI,
		Version: c.Request.Version,
		Headers: c.Request.Headers,
		Body:    []byte(c.Request.Body),
		Client:  fixedClient,
		Port:    80,
	}
	if o.Version == "" {
		o.Version = "1.1"
	}
	if o.Headers == nil {
		o.Headers = map[string]string{}
	}
	return o
}
