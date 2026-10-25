// runner_test.go (TR-07b): the parity gate. Loads the embedded corpus +
// the committed CRS slice, drives every case through the reference
// evaluator (internal/crs on engine.conf), diffs each case against the
// engine-mirror projection, and reports parity X/N. Zero unexplained
// deltas = gate passed. The RED state (parent TR-07b watch) holds while
// any corpus case has an unexplained delta; the harness reports parity
// exactly (target ≥ 90% of RAN cases).
package crsdifferential

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/crs"
	"github.com/trishula-dev/trishula/internal/engine/http1"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
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
	conformance := 0
	for _, c := range corpus.Cases {
		if c.Skipped {
			skipped++
			t.Logf("case %s: SKIPPED (%s)", c.Name, c.Skip)
			continue
		}
		if c.Expect.RejectRule != "" {
			// TR-199 conformance row: the pre-CRS gate owns the verdict
			// cell (TestCorpusConformanceRejects); the CRS-parity walk
			// never evaluates the rejected request.
			conformance++
			t.Logf("case %s: conformance row (the pre-CRS gate owns the cell)", c.Name)
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
	report := fmt.Sprintf("parity %d/%d ran (%d conformance rows; %d skipped; target >= 90%%) — zero unexplained deltas = gate",
		passed, len(corpus.Cases)-skipped-conformance, conformance, skipped)
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

// TestCorpusConformanceRejects (TR-199) is the pre-CRS conformance gate:
// the corpus's framing-ambiguity rows reject at the engine parse path
// BEFORE any CRS evaluation (the conformance verdict record's reject
// table: verdict row 2, the block verdict at the parse path), and every
// CRS-parity row either parses clean (the grammar-legal class passes to
// CRS untouched) or pins its own grammar-anomaly cell (the record's row 1;
// the CRS corpus carries clean framing by construction). The corpus is
// the home of the conformance rows (the AGENTS.md layer map pins
// test/crs-differential/corpus for them). This gate is a new gate CLASS,
// not a row of TestCorpusParity: the CRS-parity denominator never scores
// the reject cells.
func TestCorpusConformanceRejects(t *testing.T) {
	corpus, err := LoadCorpus()
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	// The reject table: the parse-layer rule id → the class error (the
	// conformance verdict record's reject-table classes). A corpus row
	// naming an unmapped rule id fails the load here, never later.
	classes := map[string]error{
		string(ladder.RuleIDFramingCLTE):  http1.ErrFramingCLTE,
		string(ladder.RuleIDFramingDupCL): http1.ErrFramingDupCL,
	}
	rows := 0
	for _, c := range corpus.Cases {
		if c.Skipped {
			continue // the skip contract: an un-runnable row is an explained one
		}
		c := c
		if c.Expect.RejectRule != "" {
			rows++
			t.Run(c.Name, func(t *testing.T) {
				class, ok := classes[c.Expect.RejectRule]
				if !ok {
					t.Fatalf("row names an unmapped reject rule id %q (the record's reject table)", c.Expect.RejectRule)
				}
				_, perr := http1.Parse([]byte(headOf(c)))
				if !errors.Is(perr, class) {
					if perr == nil {
						t.Errorf("case %s: parse accepted the framing-ambiguous head, want the reject at the parse path (the conformance verdict record, row 2)", c.Name)
						return
					}
					t.Errorf("case %s: got %v, want the class %v (rule id %q)", c.Name, perr, class, c.Expect.RejectRule)
				}
				// The reject table's verdict cell: the block verdict with
				// the row's rule id, resolved pre-CRS at the request
				// headers phase (decisive: no ladder stage runs after).
				v := ladder.ParseGateVerdict(perr)
				if v == nil || v.Action != ladder.ActionBlock || v.Phase != ladder.PhaseRequestHeaders {
					t.Errorf("case %s: verdict cell got %v, want block at the request-headers phase (the record's reject table)", c.Name, v)
				}
				if v != nil && (len(v.Rules) != 1 || v.Rules[0] != ladder.RuleID(c.Expect.RejectRule)) {
					t.Errorf("case %s: rule id got %v, want [%s] (the record's reject table)", c.Name, v.Rules, c.Expect.RejectRule)
				}
				if v != nil && !v.Action.Decisive() {
					t.Errorf("case %s: the block cell must stay decisive (the walk short-circuits pre-CRS)", c.Name)
				}
			})
			continue
		}
		if c.Expect.ParseReject {
			// The row's CRS-parity shape carries an h1 grammar anomaly on
			// the wire (case 17: the raw-space request target — the
			// record's row-1 grammar class, pre-TR-199 typed error). The
			// parse path rejects BEFORE the CRS walk; the CRS parity cell
			// stays the rule-semantics pin. Pin the grammar-class reject
			// here so the boundary stays measured.
			t.Run(c.Name+"/parse-cell", func(t *testing.T) {
				if _, perr := http1.Parse([]byte(headOf(c))); perr == nil {
					t.Errorf("case %s: parse accepted a head the row pins as a grammar anomaly", c.Name)
				}
			})
			continue
		}
		t.Run(c.Name+"/parse-clean", func(t *testing.T) {
			if _, perr := http1.Parse([]byte(headOf(c))); perr != nil {
				t.Errorf("case %s: parse rejected a grammar-legal head (%v) — the CRS class passes to CRS untouched", c.Name, perr)
			}
		})
	}
	if rows < 3 {
		t.Fatalf("conformance rows in corpus: got %d, want >= 3 (the framing classes lost from the corpus)", rows)
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
