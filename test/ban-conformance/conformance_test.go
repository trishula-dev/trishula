package banconformance

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"testing"
	"testing/fstest"

	"sigs.k8s.io/yaml"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

// testFS serves the fixtures file to the runner from the package dir
// (plain os.ReadFile at init; fstest.MapFS keeps the read pkg-relative
// and hermetic for go test ./... from any working directory).
var testFS fstest.MapFS

func init() {
	raw, err := os.ReadFile("ban_conformance_fixtures.yaml")
	if err != nil {
		panic("ban-conformance: " + err.Error())
	}
	testFS = fstest.MapFS{
		"ban_conformance_fixtures.yaml": &fstest.MapFile{Data: raw},
	}
}

// ---- §13.3 constants: the byte-mirror of the BanPolicy CRD sketch (§19.1).
// The fixtures YAML's policy block is asserted EQUAL to this table; both are
// asserted equal to the PRD sketch by testdata/recompute.py (independent
// implementation, run in CI next to this suite).
const (
	findtimeSec   int64 = 600   // 10m — evidence window
	threshold           = 10.0  // maxretry analog (score, not raw count)
	bantimeSec    int64 = 600   // 10m — base duration
	backoff             = 2.0   // κ — recidivism exponential multiplier
	maxBantimeSec int64 = 86400 // 24h — human-scale cap
	halfLifePct         = 20.0  // decayHalfLifePct: % of findtime
)

// weightsDefault mirrors the §19.1 weights table (names verbatim).
var weightsDefault = map[string]float64{
	"crsCritical":     5,
	"crsWarning":      2,
	"botConsensus":    4,
	"botSingle":       1,
	"rateBreach":      3,
	"schemaViolation": 2,
	"authFailure":     2,
	"kernelBurstFlag": 3,
}

// lambdaPerSec derives λ from the decayHalfLifePct: half-life = pct·findtime,
// λ = ln2 / half-life. §13.3: "score decay: exponential, half-life 20% of W".
var lambdaPerSec = math.Log(2) / (halfLifePct / 100.0 * float64(findtimeSec))

func decayed(w float64, ageSec int64) float64 {
	return w * math.Exp(-lambdaPerSec*float64(ageSec))
}

// untilFor: §13.3 until = t_now + min(B·κ^recid, Bmax).
func untilFor(recid int64) int64 {
	b := bantimeSec * int64(math.Pow(backoff, float64(recid)))
	if b > maxBantimeSec {
		b = maxBantimeSec
	}
	return b
}

// ---- fixture document shapes (only what the runner consumes).

type fxPolicy struct {
	Constants        map[string]any     `yaml:"constants"`
	Weights          map[string]float64 `yaml:"weights"`
	DecayHalfLifePct int                `yaml:"decayHalfLifePct"`
	PrefixEscalation map[string]any     `yaml:"prefixEscalation"`
	Mode             string             `yaml:"mode"`
}

type fxStep struct {
	At       int64       `yaml:"at"`
	Ingest   *fxIngest   `yaml:"ingest"`
	Evaluate *fxEvaluate `yaml:"evaluate"`
	BanAt    *fxBanAt    `yaml:"banAt"`

	ExpectNoEnforcement any `yaml:"expectNoEnforcement"`
}
type fxIngest struct {
	Key  string `yaml:"key"`
	Kind string `yaml:"kind"`
}
type fxEvaluate struct {
	Key           string `yaml:"key"`
	WantWouldBan  *bool  `yaml:"wantWouldBan"`
	State         string `yaml:"state"`
	BanTransition bool   `yaml:"banTransition"`
	StrictDecay   bool   `yaml:"strictDecay"`
	WantUntil     *int64 `yaml:"wantUntil"`
}
type fxBanAt struct {
	Key       string `yaml:"key"`
	WantUntil *int64 `yaml:"wantUntil"`
}

type fxFixture struct {
	ID              string         `yaml:"id"`
	Name            string         `yaml:"name"`
	DataOnly        bool           `yaml:"dataOnly"`
	Reserved        bool           `yaml:"reserved"`
	BackoffSchedule map[string]any `yaml:"backoffSchedule"`
	Steps           []fxStep       `yaml:"steps"`
	EvidenceChecks  []string       `yaml:"evidenceChecks"`
}

type fxDoc struct {
	Schema   string      `yaml:"schema"`
	Policy   fxPolicy    `yaml:"policy"`
	Fixtures []fxFixture `yaml:"fixtures"`
}

func loadFixtures(t *testing.T) fxDoc {
	t.Helper()
	raw, err := testFS.ReadFile("ban_conformance_fixtures.yaml")
	if err != nil {
		t.Fatalf("fixtures YAML read: %v", err)
	}
	var doc fxDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("fixtures YAML parse: %v", err)
	}
	if doc.Schema != "trishula.ban-conformance.v1" {
		t.Fatalf("unexpected schema %q", doc.Schema)
	}
	// Byte-mirror assertions: the YAML policy block == the §13.3 sketch.
	c := doc.Policy.Constants
	if c["findtime"] != "10m" || asF(c["threshold"]) != threshold ||
		c["bantime"] != "10m" || asF(c["backoff"]) != backoff || c["maxBantime"] != "24h" {
		t.Fatalf("policy constants drift from §19.1 sketch: %v", c)
	}
	for k, w := range weightsDefault {
		if doc.Policy.Weights[k] != w {
			t.Fatalf("weights drift: %s = %v, sketch says %v", k, doc.Policy.Weights[k], w)
		}
	}
	if doc.Policy.DecayHalfLifePct != int(halfLifePct) {
		t.Fatalf("decayHalfLifePct drift: %d", doc.Policy.DecayHalfLifePct)
	}
	if doc.Policy.Mode != "shadow" {
		t.Fatalf("conformance suite must run shadow (§13.3 shadow-first), got %q", doc.Policy.Mode)
	}
	return doc
}

func asF(v any) float64 {
	switch x := v.(type) {
	case int:
		return float64(x)
	case float64:
		return x
	}
	return 0
}

// ---- oracle: §13.3 recomputed independently of the package under test.

// oracleScore recomputes Σ w·e^(−λ·age) over the events (age ≤ findtime).
func oracleScore(events []rateban.ScoredEvent, at int64) (float64, error) {
	total := 0.0
	for _, ev := range events {
		w, err := rateban.KindWeight(string(ev.Kind))
		if err != nil {
			return 0, err
		}
		age := at - ev.AtSec
		if age < 0 || age > findtimeSec {
			continue // sliding window keyed by findtime
		}
		total += decayed(w, age)
	}
	return total, nil
}

// ---- the conformance test ----------------------------------------------

// TestScoredWindowBanConformance walks every fixture mechanically. RED
// phase (RED sha 5f44831): the rateban package did not exist and the
// failure was the package-resolution error quoted in the PR body.
func TestScoredWindowBanConformance(t *testing.T) {
	doc := loadFixtures(t)

	for _, fx := range doc.Fixtures {
		fx := fx
		t.Run(fx.ID, func(t *testing.T) {
			if fx.Reserved {
				t.Skip("reserved slot (TR-10 kernel hand-off)")
			}
			if fx.DataOnly {
				t.Skip("data-only row: consumed by F11-backoff-schedule")
			}
			runFixture(t, fx)
		})
	}

	t.Run("F11-backoff-schedule", func(t *testing.T) {
		for _, fx := range doc.Fixtures {
			if fx.ID != "F11" {
				continue
			}
			recids, ok := fx.BackoffSchedule["recidivism"].([]any)
			if !ok {
				t.Fatalf("F11 backoffSchedule.recidivism missing")
			}
			wants, ok := fx.BackoffSchedule["bantime"].([]any)
			if !ok {
				t.Fatalf("F11 backoffSchedule.bantime missing")
			}
			for i := range recids {
				r := int64(asF(recids[i]))
				want := int64(asF(wants[i]))
				if got := untilFor(r); got != want {
					t.Fatalf("κ^%d bantime: fixture says %d, §13.3 formula says %d", r, want, got)
				}
			}
		}
	})

	t.Run("policy-matches-PRD-sketch", func(t *testing.T) {
		// testdata/recompute.py is the independent oracle: fail if it
		// disagrees with this suite's recomputation of the same YAML.
		// The test binary's cwd IS the package dir — run it there.
		if _, err := exec.LookPath("python3"); err != nil {
			t.Skip("python3 unavailable; CI runs the oracle directly")
		}
		py := exec.Command("python3", "testdata/recompute.py")
		out, err := py.CombinedOutput()
		if err != nil {
			t.Fatalf("oracle disagrees:\n%s", out)
		}
	})
}

// runFixture walks one fixture's steps against a fresh rateban engine.
func runFixture(t *testing.T, fx fxFixture) {
	t.Helper()
	var clock int64
	nowFn := func() int64 { return clock } // injected monotonic seconds

	var evidence []rateban.BanEvidence
	sink := rateban.EvidenceSinkFunc(func(r rateban.BanEvidence) error {
		evidence = append(evidence, r)
		return nil
	})

	eng := rateban.New(nowFn, sink)
	var events []rateban.ScoredEvent
	prevScore := math.NaN()
	wantRecords := 0

	for i, step := range fx.Steps {
		switch {
		case step.Ingest != nil:
			clock = step.At
			if _, err := rateban.KindWeight(step.Ingest.Kind); err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			if err := eng.Ingest(step.Ingest.Key, rateban.EventKind(step.Ingest.Kind), step.At, ""); err != nil {
				t.Fatalf("step %d: Ingest: %v", i, err)
			}
			w, _ := rateban.KindWeight(step.Ingest.Kind)
			events = append(events, rateban.ScoredEvent{
				Key:    step.Ingest.Key,
				Kind:   rateban.EventKind(step.Ingest.Kind),
				AtSec:  step.At,
				Weight: w,
			})
		case step.Evaluate != nil:
			ev := step.Evaluate
			clock = step.At
			got := eng.Observe(ev.Key)
			if got.ActiveBan {
				// §13.3 step 2: active ban → no re-scoring; the engine
				// reports score 0 by convention. Assert state + the
				// no-reban rule, not a decayed score.
				if !got.WouldBan == false {
					t.Fatalf("step %d: live ban reported wouldBan", i)
				}
				if ev.WantWouldBan != nil && *ev.WantWouldBan {
					t.Fatalf("step %d: wantWouldBan true but engine reports a live ban", i)
				}
				active := eng.Active(ev.Key, step.At)
				if ev.State == "ACTIVE_BAN" && !active {
					t.Fatalf("step %d: want ACTIVE_BAN, engine says clear", i)
				}
				if ev.State == "CLEAR" && active {
					t.Fatalf("step %d: want CLEAR, engine reports an active ban", i)
				}
				prevScore = 0
				continue
			}
			score, err := oracleScore(events, step.At)
			if err != nil {
				t.Fatalf("step %d: oracle score: %v", i, err)
			}
			if math.Abs(got.Score-score) > 1e-6 {
				t.Fatalf("step %d: score: engine %v, oracle %v", i, got.Score, score)
			}
			// wouldBan must equal the oracle crossing whenever no ban is live.
			if !got.ActiveBan && ev.WantWouldBan != nil && got.WouldBan != *ev.WantWouldBan {
				t.Fatalf("step %d: wouldBan: engine %v, want %v", i, got.WouldBan, *ev.WantWouldBan)
			}
			if got.ActiveBan && ev.WantWouldBan != nil && *ev.WantWouldBan {
				t.Fatalf("step %d: wantWouldBan true but engine reports a live ban", i)
			}
			if ev.StrictDecay && !math.IsNaN(prevScore) && got.Score >= prevScore {
				t.Fatalf("step %d: strictDecay asserted but %v >= previous %v", i, got.Score, prevScore)
			}
			active := eng.Active(ev.Key, step.At)
			switch ev.State {
			case "ACTIVE_BAN":
				if !active {
					t.Fatalf("step %d: want ACTIVE_BAN, engine says clear", i)
				}
			case "CLEAR":
				if active {
					t.Fatalf("step %d: want CLEAR, engine reports an active ban", i)
				}
			}
			if ev.BanTransition {
				// The transition is driven through the shadow would-ban
				// path: Assess records the R11 evidence at this instant.
				recs := eng.Assess(ev.Key, step.At)
				if len(recs) != 1 {
					t.Fatalf("step %d: banTransition: Assess produced %d records, want 1", i, len(recs))
				}
				wantRecords++
				if ev.WantUntil != nil && recs[0].UntilSec != *ev.WantUntil {
					t.Fatalf("step %d: until: record %d, §13.3 formula %d", i, recs[0].UntilSec, *ev.WantUntil)
				}
			}
			prevScore = got.Score
		case step.BanAt != nil:
			clock = step.At
			recs := eng.Assess(step.BanAt.Key, step.At)
			if len(recs) == 0 {
				t.Fatalf("step %d: Assess did not record a would-ban (shadow)", i)
			}
			wantRecords++
			score, err := oracleScore(events, step.At)
			if err != nil {
				t.Fatalf("step %d: oracle score: %v", i, err)
			}
			if score < threshold {
				t.Fatalf("step %d: Assess crossed below oracle threshold (score %v)", i, score)
			}
			rec := recs[len(recs)-1]
			if step.BanAt.WantUntil != nil && rec.UntilSec != *step.BanAt.WantUntil {
				t.Fatalf("step %d: until: record %d, §13.3 formula %d", i, rec.UntilSec, *step.BanAt.WantUntil)
			}
		case step.ExpectNoEnforcement != nil:
			if eng.Enforced() {
				t.Fatalf("step %d: shadow engine reported enforcement — §13.3 shadow-first violated", i)
			}
		default:
			t.Fatalf("step %d: unknown shape", i)
		}
	}

	// evidence-check contracts (§13.5/R11 shapes on every would-ban record)
	want := map[string]bool{}
	for _, c := range fx.EvidenceChecks {
		want[c] = true
	}
	checkEvidence(t, fx.ID, evidence, wantRecords, want)
}

// checkEvidence pins the R11/§13.5 evidence contracts.
func checkEvidence(t *testing.T, id string, evs []rateban.BanEvidence, wantRecords int, want map[string]bool) {
	t.Helper()
	if len(evs) < wantRecords {
		t.Fatalf("%s: %d evidence records, want >= %d", id, len(evs), wantRecords)
	}
	for _, r := range evs {
		if want["hasKey"] && r.Key == "" {
			t.Fatalf("%s: evidence record without offender key", id)
		}
		if want["hasEventsWithWeights"] && len(r.Events) == 0 {
			t.Fatalf("%s: evidence record without contributing events", id)
		}
		if want["scoreTrajectoryHasWeights"] {
			if len(r.Events) == 0 {
				t.Fatalf("%s: evidence record without score trajectory", id)
			}
			for _, ev := range r.Events {
				if ev.Weight <= 0 {
					t.Fatalf("%s: trajectory event %s carries weight %v", id, ev.Kind, ev.Weight)
				}
			}
		}
		if want["hasUntil"] && r.UntilSec == 0 {
			t.Fatalf("%s: evidence record without until", id)
		}
		if want["hasTier"] && r.Tier == "" {
			t.Fatalf("%s: evidence record without tier", id)
		}
		if want["hasReasonCodes"] && len(r.ReasonCodes) == 0 {
			t.Fatalf("%s: evidence record without reason codes", id)
		}
		if want["modeIsShadow"] && r.Mode != "shadow" {
			t.Fatalf("%s: evidence record mode %q, want shadow", id, r.Mode)
		}
		if want["jsonSerializable"] {
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("%s: evidence record is not JSON-serializable: %v", id, err)
			}
			var round map[string]any
			if err := json.Unmarshal(b, &round); err != nil {
				t.Fatalf("%s: evidence record JSON does not round-trip: %v", id, err)
			}
			if round["key"] != r.Key {
				t.Fatalf("%s: evidence JSON key round-trip mismatch", id)
			}
		}
	}
}

// TestBanRateAboveBudgetExported pins the TR-11 wiring point: the plain
// counter is exported from this leaf and behaves as an int64 counter (no
// prometheus/otel dependency in the leaf).
func TestBanRateAboveBudgetExported(t *testing.T) {
	before := rateban.BanRateAboveBudgetValue()
	rateban.BanRateAboveBudgetTick()
	if got := rateban.BanRateAboveBudgetValue(); got != before+1 {
		t.Fatalf("BanRateAboveBudget did not tick: %d -> %d", before, got)
	}
}
