package banconformance

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

// ---- §13.3 constants: the byte-mirror of the BanPolicy CRD sketch (§19.1).
// The fixtures YAML's policy block is asserted EQUAL to this table; both are
// asserted equal to the PRD sketch by testdata/recompute.py (independent
// implementation, run in CI next to this suite).
const (
	findtimeSec   = 600 // 10m — evidence window
	threshold     = 10  // maxretry analog (score, not raw count)
	bantimeSec    = 600 // 10m — base duration
	backoff       = 2   // κ — recidivism exponential multiplier
	maxBantimeSec = 86400 // 24h — human-scale cap
	halfLifePct   = 20  // decayHalfLifePct: % of findtime
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

// lambda derives λ from the decayHalfLifePct: half-life = pct·findtime,
// λ = ln2 / half-life. §13.3 "score decay: exponential, half-life 20% of W".
var lambdaPerSec = math.Log(2) / (halfLifePct / 100.0 * findtimeSec)

func decayed(w float64, ageSec int) float64 {
	return w * math.Exp(-lambdaPerSec*float64(ageSec))
}

// untilFor: §13.3 until = t_now + min(B·κ^recid, Bmax).
func untilFor(recid int) int64 {
	b := float64(bantimeSec) * math.Pow(backoff, float64(recid))
	if b > maxBantimeSec {
		b = maxBantimeSec
	}
	return int64(b)
}

// ---- fixture document shapes (only what the runner consumes).

type fxPolicy struct {
	Constants         map[string]any    `yaml:"constants"`
	Weights           map[string]float64 `yaml:"weights"`
	DecayHalfLifePct  int               `yaml:"decayHalfLifePct"`
	PrefixEscalation  map[string]any    `yaml:"prefixEscalation"`
	Mode              string            `yaml:"mode"`
}

type fxStep struct {
	At                  any             `yaml:"at"` // int seconds; absent on expectNoEnforcement
	Ingest              *fxIngest       `yaml:"ingest"`
	Evaluate            *fxEvaluate     `yaml:"evaluate"`
	BanAt               *fxBanAt        `yaml:"banAt"`
	ExpectNoEnforcement any             `yaml:"expectNoEnforcement"`
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
	ID             string   `yaml:"id"`
	Name           string   `yaml:"name"`
	DataOnly       bool     `yaml:"dataOnly"`
	Reserved       bool     `yaml:"reserved"`
	BackoffSchedule map[string]any `yaml:"backoffSchedule"`
	Steps          []fxStep `yaml:"steps"`
	EvidenceChecks []string `yaml:"evidenceChecks"`
}

type fxDoc struct {
	Schema   string      `yaml:"schema"`
	Policy   fxPolicy    `yaml:"policy"`
	Fixtures []fxFixture `yaml:"fixtures"`
}

func loadFixtures(t *testing.T) fxDoc {
	t.Helper()
	var doc fxDoc
	if err := yaml.Unmarshal(fixturesYAML, &doc); err != nil {
		t.Fatalf("fixtures YAML parse: %v", err)
	}
	if doc.Schema != "trishula.ban-conformance.v1" {
		t.Fatalf("unexpected schema %q", doc.Schema)
	}
	// Byte-mirror assertions: the YAML policy block == the §13.3 sketch.
	c := doc.Policy.Constants
	if c["findtime"] != "10m" || c["threshold"] != float64(threshold) ||
		c["bantime"] != "10m" || c["backoff"] != float64(backoff) || c["maxBantime"] != "24h" {
		t.Fatalf("policy constants drift from §19.1 sketch: %v", c)
	}
	for k, w := range weightsDefault {
		if doc.Policy.Weights[k] != w {
			t.Fatalf("weights drift: %s = %v, sketch says %v", k, doc.Policy.Weights[k], w)
		}
	}
	if doc.Policy.DecayHalfLifePct != halfLifePct {
		t.Fatalf("decayHalfLifePct drift: %d", doc.Policy.DecayHalfLifePct)
	}
	if doc.Policy.Mode != "shadow" {
		t.Fatalf("conformance suite must run shadow (§13.3 shadow-first), got %q", doc.Policy.Mode)
	}
	return doc
}

// ---- oracle: §13.3 recomputed independently of the package under test.

// oracleScore recomputesΣ w·e^(−λ·age) over the events (age ≤ findtime).
func oracleScore(events []rateban.ScoredEvent, at int64) (float64, error) {
	total := 0.0
	for _, ev := range events {
		w, err := rateban.KindWeight(ev.Kind)
		if err != nil {
			return 0, err
		}
		age := at - ev.AtSec
		if age < 0 || age > findtimeSec {
			continue // sliding window keyed by findtime
		}
		total += decayed(w, int(age))
	}
	return total, nil
}

// ---- the conformance test ----------------------------------------------

// TestScoredWindowBanConformance walks every fixture mechanically. This is
// the RED-phase test: at the RED sha the rateban package does not exist, and
// the failure is the package-resolution error quoted in the PR body.
func TestScoredWindowBanConformance(t *testing.T) {
	doc := loadFixtures(t)

	for _, fx := range doc.Fixtures {
		fx := fx
		t.Run(fx.ID, func(t *testing.T) {
			if fx.Reserved {
				t.Skip("reserved slot (TR-10 kernel hand-off)")
			}
			if fx.DataOnly {
				t.Skip("data-only row: consumed by the schedule assertion below")
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
				r, _ := recids[i].(int)
				want, _ := wants[i].(int)
				if got := untilFor(r); int(got) != want {
					t.Fatalf("κ^%d bantime: fixture says %d, §13.3 formula says %d", r, want, got)
				}
			}
		}
	})

	t.Run("policy-matches-PRD-sketch", func(t *testing.T) {
		// testdata/recompute.py is the independent oracle: fail if it
		// disagrees with this suite's recomputation of the same YAML.
		py := exec.Command("python3", "testdata/recompute.py")
		py.Dir = "test/ban-conformance"
		out, err := py.CombinedOutput()
		if err != nil {
			t.Fatalf("oracle disagrees:\n%s", out)
		}
	})
}

// runFixture walks one fixture's steps against a fresh rateban engine.
func runFixture(t *testing.T, fx fxFixture) {
	t.Helper()
	clock := int64(0)
	nowFn := func() int64 { return clock } // injected monotonic seconds

	var evidence []rateban.BanEvidence
	sink := rateban.EvidenceSinkFunc(func(r rateban.BanEvidence) error {
		evidence = append(evidence, r)
		return nil
	})

	eng := rateban.New(nowFn, sink)
	var events []rateban.ScoredEvent
	prevScore := math.NaN()
	nBanTransitions := 0

	for i, step := range fx.Steps {
		switch {
		case step.Ingest != nil:
			clock = int64(step.At)
			w, err := rateban.KindWeight(step.Ingest.Kind)
			if err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			_ = w
			if err := eng.Ingest(step.Ingest.Key, step.Ingest.Kind, step.At, ""); err != nil {
				t.Fatalf("step %d: Ingest: %v", i, err)
			}
			events = append(events, rateban.ScoredEvent{
				Key:    step.Ingest.Key,
				Kind:   rateban.EventKind(step.Ingest.Kind),
				AtSec:  int64(step.At),
				Weight: rateban.DefaultWeights()[step.Ingest.Kind],
			})
		case step.Evaluate != nil:
			ev := step.Evaluate
			clock = int64(step.At)
			got := eng.Observe(ev.Key)
			score, err := oracleScore(events, int64(step.At))
			if err != nil {
				t.Fatalf("step %d: oracle score: %v", i, err)
			}
			if math.Abs(float64(got.Score)-score) > 1e-6 {
				t.Fatalf("step %d: score: engine %v, oracle %v", i, got.Score, score)
			}
			if ev.StrictDecay && !math.IsNaN(prevScore) && float64(got.Score) >= prevScore {
				t.Fatalf("step %d: strictDecay asserted but %v >= previous %v", i, got.Score, prevScore)
			}
			if ev.WantWouldBan != nil && got.WouldBan != *ev.WantWouldBan {
				t.Fatalf("step %d: wouldBan: engine %v, want %v", i, got.WouldBan, *ev.WantWouldBan)
			}
			active := eng.Active(ev.Key, int64(step.At))
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
				nBanTransitions++
			}
			prevScore = float64(got.Score)
		case step.BanAt != nil:
			clock = int64(step.At)
			rec := assess(t, eng, step.BanAt.Key, int64(step.At))
			if rec == nil {
				t.Fatalf("step %d: Assess did not record a would-ban (shadow)", i)
			}
			score, err := oracleScore(events, int64(step.At))
			if err != nil {
				t.Fatalf("step %d: oracle score: %v", i, err)
			}
			if score < threshold {
				t.Fatalf("step %d: Assess crossed below oracle threshold (score %v)", i, score)
			}
			nBanTransitions++
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
	checkEvidence(t, fx.ID, evidence, nBanTransitions, want)
}

// assess runs the shadow would-ban path and returns the newest evidence
// record (nil = none).
func assess(t *testing.T, eng *rateban.Engine, key string, at int64) *rateban.BanEvidence {
	t.Helper()
	rec := eng.Assess(key, at)
	if rec == nil {
		return nil
	}
	return &rec[0] // most recent record for the key
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
		if want["scoreTrajectoryHasWeights"] {
			// the full §13.5 trajectory: every contributing event with its weight
			if len(r.Events) == 0 {
				t.Fatalf("%s: evidence record without contributing events", id)
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
		if want["jsonSerializable"] {
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("%s: evidence record is not JSON-serializable: %v", id, err)
			}
			if !json.Valid(b) {
				t.Fatalf("%s: evidence record marshaled invalid JSON", id)
			}
		}
		if want["modeIsShadow"] && r.Mode != "shadow" {
			t.Fatalf("%s: evidence record mode %q, want shadow", id, r.Mode)
		}
	}
}

// TestBanRateAboveBudgetExported pins the TR-11 wiring point: the plain
// counter exists, is exported, and is a plain int64 (no prometheus/otel
// dependency in this leaf).
func TestBanRateAboveBudgetExported(t *testing.T) {
	if rateban.BanRateAboveBudget == nil {
		t.Fatal("BanRateAboveBudget not exported from internal/engine/rateban")
	}
	before := *rateban.BanRateAboveBudget
	*rateban.BanRateAboveBudget++
	if *rateban.BanRateAboveBudget != before+1 {
		t.Fatal("BanRateAboveBudget is not a mutable plain counter")
	}
	*rateban.BanRateAboveBudget-- // leave it as found
}
