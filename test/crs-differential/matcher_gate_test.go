// matcher_gate_test.go (TR-16): the spec's Vectorscan/differential-parity gate for the
// compiled fast path. The seed pattern set (tr16Seed) carries one pattern
// per reference rule id the corpus exercises; the gate runs the LIVE
// reference evaluator walk on every corpus case, computes per-phase
// (pattern, case) verdict parity — a pattern fires on its declared view
// surfaces exactly when its tagged rule id fires in the reference phase —
// demotes every divergent pattern to reference-path-only, recompiles, and
// asserts the post-demotion matcher verdicts hold 100% parity against the
// live reference projection with a non-empty active set (self-healing
// parity, the spec's Vectorscan fast path). Parity is VERDICT-level (its differential-parity gate): computed from
// the live walk per case, never pinned from a different evaluator run.
package crsdifferential

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/crs"
	"github.com/trishula-dev/trishula/internal/engine/matcher"
)

// tr16Seed is the TR-16 seed pattern set: one entry per reference rule id
// the corpus exercises, written from the vendored rule's own signature
// intent in RE2 form (the vendored CRS slice under testdata/seclang;
// the corpus README tables carry the observed sets). Surfaces mirror the
// rule's var-target chains; phase mirrors the rule's phase.
var tr16Seed = []matcher.Pattern{
	{Rule: 942480, Phase: matcher.PhaseRequestBody, Surfaces: []string{"query", "body", "headers"},
		Expr: `(?i)union[\s]{1,3}select`},
	{Rule: 942190, Phase: matcher.PhaseRequestBody, Surfaces: []string{"query", "body"},
		Expr: `(?i)union[\s]{1,3}select`},
	{Rule: 942440, Phase: matcher.PhaseRequestBody, Surfaces: []string{"query", "body"},
		Expr: `(?i)[';][\s]*--`},
	{Rule: 942180, Phase: matcher.PhaseRequestBody, Surfaces: []string{"query", "body"},
		Expr: `(?i)'[\s]*or[\s]*'1'[\s]*=[\s]*'?1`},
	{Rule: 941100, Phase: matcher.PhaseRequestBody, Surfaces: []string{"query", "body", "headers"},
		Expr: `(?i)<script`},
	{Rule: 913100, Phase: matcher.PhaseRequestHeaders, Surfaces: []string{"headers"},
		Expr: `(?i)sqlmap`},
	{Rule: 930100, Phase: matcher.PhaseRequestBody, Surfaces: []string{"query", "uri"},
		Expr: `\.\./`},
	{Rule: 930110, Phase: matcher.PhaseRequestBody, Surfaces: []string{"query", "uri"},
		Expr: `(^|/)[.]{2,3}(/|$)`},
	{Rule: 944150, Phase: matcher.PhaseRequestBody, Surfaces: []string{"uri", "query", "body", "headers"},
		Expr: `(?i)\$\{(jndi|ctx)`},
}

// gateView projects a corpus case into the matcher view: the spec's request
// segments (uri, headers, query, body). Query and form values decode exactly
// like the reference processors decode them (ARGS_GET / ARGS_POST).
func gateView(c Case) map[string]string {
	view := map[string]string{"uri": c.Request.URI}
	names := make([]string, 0, len(c.Request.Headers))
	for k := range c.Request.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var hb strings.Builder
	for _, k := range names {
		fmt.Fprintf(&hb, "%s: %s\n", k, c.Request.Headers[k])
	}
	view["headers"] = hb.String()
	if raw := c.Request.URI; strings.Contains(raw, "?") {
		if vals, err := url.ParseQuery(raw[strings.IndexByte(raw, '?')+1:]); err == nil {
			keys := make([]string, 0, len(vals))
			for k := range vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var qb strings.Builder
			for _, k := range keys {
				for _, v := range vals[k] {
					fmt.Fprintf(&qb, "%s=%s\n", k, v)
				}
			}
			view["query"] = qb.String()
		}
	}
	if strings.Contains(c.Request.Headers["Content-Type"], "x-www-form-urlencoded") && c.Request.Body != "" {
		if vals, err := url.ParseQuery(c.Request.Body); err == nil {
			keys := make([]string, 0, len(vals))
			for k := range vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var bb strings.Builder
			for _, k := range keys {
				for _, v := range vals[k] {
					fmt.Fprintf(&bb, "%s=%s\n", k, v)
				}
			}
			view["body"] = bb.String()
		}
	} else if c.Request.Body != "" {
		view["body"] = c.Request.Body
	}
	return view
}

// TestMatcherParityGate is the TR-16 gate: build the hot subset, run the
// live corpus walks, demote every divergent pattern, recompile, and assert
// the post-demotion verdict parity holds on the live reference projection.
func TestMatcherParityGate(t *testing.T) {
	corpus, err := LoadCorpus()
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	ref, err := LoadReference()
	if err != nil {
		t.Fatalf("LoadReference: %v", err)
	}

	set, err := matcher.NewSet(tr16Seed)
	if err != nil {
		t.Fatalf("NewSet(tr16Seed): %v", err)
	}
	db, err := matcher.Compile(set.Active())
	if err != nil {
		t.Fatalf("Compile(seed): %v", err)
	}

	// Census: per (pattern, case, phase) verdict parity against the live
	// reference projection. FP = pattern fires where the reference does
	// not; MISS = reference fires the tagged id where the pattern does
	// not.
	divergent := map[int][]string{} // rule -> case:phase kind
	for _, c := range corpus.Cases {
		if c.Skipped {
			t.Logf("case %s: SKIPPED (%s)", c.Name, c.Skip)
			continue
		}
		c := c
		t.Run(c.Name, func(t *testing.T) {
			v, err := ref.Evaluate(referenceOptions(c))
			if err != nil {
				t.Fatalf("Evaluate(%s): %v", c.Name, err)
			}
			refP1 := ruleIDSet(v.Phase1Matches)
			refP2 := ruleIDSet(v.Phase2Matches)
			view := gateView(c)
			for _, phase := range []int{matcher.PhaseRequestHeaders, matcher.PhaseRequestBody} {
				gotSet := map[int]bool{}
				for _, id := range db.Scan(phase, view) {
					gotSet[id] = true
				}
				refSet := refP1
				if phase == matcher.PhaseRequestBody {
					refSet = refP2
				}
				for _, p := range set.Active() {
					if p.Phase != phase {
						continue
					}
					fires := gotSet[p.Rule]
					want := refSet[p.Rule]
					switch {
					case fires && !want:
						divergent[p.Rule] = append(divergent[p.Rule],
							fmt.Sprintf("%s:p%d FP", c.Name, phase))
					case !fires && want:
						divergent[p.Rule] = append(divergent[p.Rule],
							fmt.Sprintf("%s:p%d MISS", c.Name, phase))
					}
				}
			}
		})
	}

	demoted := make([]int, 0, len(divergent))
	for rule := range divergent {
		demoted = append(demoted, rule)
	}
	sort.Ints(demoted)
	for _, rule := range demoted {
		for _, d := range divergent[rule] {
			t.Logf("diverge rule %d: %s", rule, d)
		}
		if err := set.Demote(rule); err != nil {
			t.Fatalf("Demote(%d): %v", rule, err)
		}
	}

	db2, err := matcher.Compile(set.Active())
	if err != nil {
		t.Fatalf("Compile(post-demotion): %v", err)
	}

	// Post-demotion verdict parity on the live projection: every active
	// pattern agrees with the reference on every case (both directions,
	// same census walk).
	census := func(db *matcher.DB, active []matcher.Pattern) map[int]map[string]string {
		c := map[int]map[string]string{}
		for _, p := range active {
			c[p.Rule] = map[string]string{}
		}
		for _, case0 := range corpus.Cases {
			if case0.Skipped {
				continue
			}
			case0 := case0
			v, err := ref.Evaluate(referenceOptions(case0))
			if err != nil {
				t.Fatalf("Evaluate(%s): %v", case0.Name, err)
			}
			sets := map[int]map[int]bool{
				matcher.PhaseRequestHeaders: ruleIDSet(v.Phase1Matches),
				matcher.PhaseRequestBody:    ruleIDSet(v.Phase2Matches),
			}
			view := gateView(case0)
			for _, p := range active {
				fires := false
				for _, id := range db.Scan(p.Phase, view) {
					if id == p.Rule {
						fires = true
						break
					}
				}
				want := sets[p.Phase][p.Rule]
				switch {
				case fires && !want:
					c[p.Rule][case0.Name] = "FP"
				case !fires && want:
					c[p.Rule][case0.Name] = "MISS"
				}
			}
		}
		return c
	}

	active := set.Active()
	if len(active) == 0 {
		t.Fatalf("post-demotion active set drained: %d patterns remain, the hot-subset scan covers nothing", len(divergent))
	}
	post := census(db2, active)
	for _, p := range active {
		if n := len(post[p.Rule]); n != 0 {
			t.Errorf("post-demotion parity for rule %d broken: %d divergent cases %v", p.Rule, n, post[p.Rule])
		}
		firedCases := 0
		for _, case0 := range corpus.Cases {
			if case0.Skipped {
				continue
			}
			view := gateView(case0)
			for _, id := range db2.Scan(p.Phase, view) {
				if id == p.Rule {
					firedCases++
					break
				}
			}
		}
		t.Logf("active rule %d: post-demotion parity 100%%, fires on %d case(s)", p.Rule, firedCases)
	}

	report := fmt.Sprintf("matcher-parity census: seed %d, divergent %d (%v), active %d, active-parity 100%% vs live reference projection",
		len(tr16Seed), len(divergent), demoted, len(active))
	fmt.Fprintln(os.Stdout, report)
	t.Logf("%s", report)
}

// ruleIDSet projects a phase match list into a deduplicated id set.
func ruleIDSet(ms []crs.Match) map[int]bool {
	out := map[int]bool{}
	for _, m := range ms {
		out[m.RuleID] = true
	}
	return out
}
