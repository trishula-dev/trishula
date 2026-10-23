package botdef

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// behaviorVectors loads the published vector set (the §12.1 behavioral
// contract walks through the injectable loader).
func behaviorVectors(t *testing.T) []BehaviorVector {
	t.Helper()
	f, err := os.Open("testdata/behavior_vectors.json")
	if err != nil {
		t.Fatalf("open behavior vectors: %v", err)
	}
	defer f.Close()
	vs, err := LoadBehaviorVectors(f)
	if err != nil {
		t.Fatalf("load behavior vectors: %v", err)
	}
	return vs
}

// TestBehaviorWindowsVectors is the published-vector table: each vector
// replays its single-source request stream at the scripted clock offsets
// and pins the detector ids the final Observe emits. It is a table test
// (rows = vectors) because the behaviour under test is a multi-observe
// window sequence — the single-input evaluation tables of the neighbouring
// homes cannot express per-source state across a stream.
func TestBehaviorWindowsVectors(t *testing.T) {
	base := time.Unix(1735689600, 0).UTC()
	for _, v := range behaviorVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			cfg := DefaultBehaviorWindowConfig()
			now := base
			cfg.Now = func() time.Time { return now }
			bw := NewBehaviorWindows(cfg)
			src := netip.MustParseAddr(v.Source)

			var got []DetectorVerdict
			for _, ev := range v.Events {
				now = base.Add(time.Duration(ev.OffsetMS) * time.Millisecond)
				got = bw.Observe(src, BehaviorObservation{Path: ev.Path, Status: ev.Status})
			}

			gotIDs := make([]ladder.RuleID, 0, len(got))
			for _, dv := range got {
				gotIDs = append(gotIDs, dv.ID)
				if dv.Confidence == 0 {
					t.Errorf("detector %v fired with confidence 0 — §12.1 wants a real confidence", dv.ID)
				}
				if dv.Evidence == "" {
					t.Errorf("detector %v fired with no evidence ref — §12.1 wants (id, confidence, evidence)", dv.ID)
				}
				if dv.Family != FamilyBehavioral {
					t.Errorf("behavioral windows emitted family %q, want behavioral", dv.Family)
				}
			}
			wantIDs := slices.Clone(v.Expect.DetectorIDs)
			slices.Sort(gotIDs)
			slices.Sort(wantIDs)
			if !slices.Equal(gotIDs, wantIDs) {
				t.Errorf("vector %s final observe: detector ids %v, want %v", v.Name, gotIDs, wantIDs)
			}
		})
	}
}

// TestMergePolicyConsensus is the §12.1 merge table: the rule counts
// DISTINCT families above the confidence floor; consensus is decisive,
// a single family keeps the log tier. It is a new table because Merge is
// a new decision surface (the existing tables pin fragments, not merges).
func TestMergePolicyConsensus(t *testing.T) {
	cases := []struct {
		name         string
		vs           []DetectorVerdict
		policy       MergePolicy
		wantAction   ladder.Action
		wantFamilies []Family
	}{
		{
			name: "single behavioral family logs",
			vs: []DetectorVerdict{
				{ID: ruleBotSpread, Family: FamilyBehavioral, Confidence: 60, Evidence: "distinct=13 requests=16"},
			},
			policy:       DefaultMergePolicy(),
			wantAction:   ladder.ActionLog,
			wantFamilies: []Family{FamilyBehavioral},
		},
		{
			name: "headers+behavioral consensus challenges",
			vs: []DetectorVerdict{
				{ID: ruleBotHeaders, Family: FamilyHeaders, Confidence: 80, Evidence: "hf=abc123"},
				{ID: ruleBotSpread, Family: FamilyBehavioral, Confidence: 60, Evidence: "distinct=13 requests=16"},
			},
			policy:       DefaultMergePolicy(),
			wantAction:   ladder.ActionChallenge,
			wantFamilies: []Family{FamilyBehavioral, FamilyHeaders},
		},
		{
			name: "ja4 prior stays out of consensus",
			vs: []DetectorVerdict{
				{ID: ruleBotJA4, Family: FamilyTLS, Confidence: 25, Evidence: "t13d4907h2_0d8feac7bc37_7395dae3b2f3"},
				{ID: ruleBotHeaders, Family: FamilyHeaders, Confidence: 80, Evidence: "hf=abc123"},
			},
			policy:       DefaultMergePolicy(),
			wantAction:   ladder.ActionLog,
			wantFamilies: []Family{FamilyHeaders},
		},
		{
			name: "min families three keeps two silent",
			vs: []DetectorVerdict{
				{ID: ruleBotHeaders, Family: FamilyHeaders, Confidence: 80, Evidence: "hf=abc123"},
				{ID: ruleBotSpread, Family: FamilyBehavioral, Confidence: 60, Evidence: "distinct=13 requests=16"},
			},
			policy:       MergePolicy{MinFamilies: 3, ConsensusAction: ladder.ActionChallenge, ConfidenceFloor: 50},
			wantAction:   ladder.ActionLog,
			wantFamilies: []Family{FamilyBehavioral, FamilyHeaders},
		},
		{
			name: "zero floor lets the prior count",
			vs: []DetectorVerdict{
				{ID: ruleBotJA4, Family: FamilyTLS, Confidence: 25, Evidence: "t13d4907h2_0d8feac7bc37_7395dae3b2f3"},
				{ID: ruleBotHeaders, Family: FamilyHeaders, Confidence: 80, Evidence: "hf=abc123"},
			},
			policy:       MergePolicy{MinFamilies: 2, ConsensusAction: ladder.ActionChallenge, ConfidenceFloor: 0},
			wantAction:   ladder.ActionChallenge,
			wantFamilies: []Family{FamilyHeaders, FamilyTLS},
		},
		{
			name: "log consensus action stays non-decisive",
			vs: []DetectorVerdict{
				{ID: ruleBotHeaders, Family: FamilyHeaders, Confidence: 80, Evidence: "hf=abc123"},
				{ID: ruleBotSpread, Family: FamilyBehavioral, Confidence: 60, Evidence: "distinct=13 requests=16"},
			},
			policy:       MergePolicy{MinFamilies: 2, ConsensusAction: ladder.ActionLog, ConfidenceFloor: 50},
			wantAction:   ladder.ActionLog,
			wantFamilies: []Family{FamilyBehavioral, FamilyHeaders},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, fams := Merge(tc.vs, tc.policy)
			if action != tc.wantAction {
				t.Errorf("resolved action = %q, want %q", action, tc.wantAction)
			}
			if !slices.Equal(fams, tc.wantFamilies) {
				t.Errorf("contributing families = %v, want %v", fams, tc.wantFamilies)
			}
		})
	}
}

// TestDetectorBehavioralWiring pins the §12.1 S5 wiring: behavioral
// windows observe through the detector; a one-family source keeps the
// log tier; a two-family source resolves the decisive challenge on the
// breach observe; a zero policy holds the log tier. It is a new test
// function because each case drives a multi-observe sequence through a
// wired ladder engine — no single-observe row home covers it.
func TestDetectorBehavioralWiring(t *testing.T) {
	const loopPath = "/api/items/1"
	obs := &BehaviorObservation{Path: loopPath, Status: 200}
	toolHV := &HeaderView{
		Method:  "GET",
		Version: "1.1",
		Headers: [][2]string{{"Host", "t.example"}},
	}

	mkTx := func(t *testing.T, ip string, port uint16, attachObs bool, attachHV bool) *ingest.TxContext {
		t.Helper()
		m := ingest.NewTxManager()
		var k ingest.FlowKey
		k.SrcIP = netip.MustParseAddr(ip).As4()
		k.DstIP = netip.MustParseAddr("10.10.0.10").As4()
		k.SrcPort, k.DstPort, k.Family = port, 443, ingest.FamilyV4
		tx := m.NoteFlow(k)
		if attachObs {
			if err := AttachBehaviorObservation(tx, obs); err != nil {
				t.Fatalf("attach observation: %v", err)
			}
		}
		if attachHV {
			if err := AttachHeaderView(tx, toolHV); err != nil {
				t.Fatalf("attach header view: %v", err)
			}
		}
		return tx
	}

	walkN := func(t *testing.T, d *Detector, tx *ingest.TxContext, n int) *ladder.Verdict {
		t.Helper()
		e := ladder.NewEngine()
		if err := e.Use(ladder.StageBots, d); err != nil {
			t.Fatalf("Use(S5): %v", err)
		}
		var v *ladder.Verdict
		for i := 0; i < n; i++ {
			v = e.EvaluateTx(tx)
			if v == nil {
				t.Fatalf("walk %d: nil verdict", i+1)
			}
		}
		return v
	}

	t.Run("behavior-only burst stays log tier", func(t *testing.T) {
		d := NewDetector()
		tx := mkTx(t, "192.0.2.70", 40001, true, false)
		v := walkN(t, d, tx, paceBreachLoop())
		if hasRule(v.Rules, ruleBotPace) {
			t.Logf("pace rule present after burst as expected")
		} else {
			t.Errorf("burst verdict rules = %v, want %v present", v.Rules, ruleBotPace)
		}
		if v.Action != ladder.ActionLog {
			t.Errorf("single-family burst action = %q, want log (one family never triggers, §12.1)", v.Action)
		}
		if v.Score < botScorePace {
			t.Errorf("burst verdict score = %d, want >= %d (the pace contribution)", v.Score, botScorePace)
		}
		line := LabLogLine(tx)
		if !strings.Contains(line, "action=log") || !strings.Contains(line, "rules=bot:pace") {
			t.Errorf("burst lab line = %q, want the behavioral render (action=log, rules=bot:pace)", line)
		}
	})

	t.Run("headers+behavioral consensus challenges on the breach observe", func(t *testing.T) {
		d := NewDetector()
		tx := mkTx(t, "192.0.2.71", 40002, true, true)
		v := walkN(t, d, tx, paceBreachLoop())
		if v.Action != ladder.ActionChallenge {
			t.Errorf("two-family consensus action = %q, want challenge (§12.1)", v.Action)
		}
		if !hasRule(v.Rules, ruleBotPace) || !hasRule(v.Rules, ruleBotHeaders) {
			t.Errorf("consensus verdict rules = %v, want both %v and %v", v.Rules, ruleBotHeaders, ruleBotPace)
		}
		line := LabLogLine(tx)
		if !strings.Contains(line, "action=challenge") || !strings.Contains(line, "+behavioral") {
			t.Errorf("consensus lab line = %q, want action=challenge and the behavioral detector set", line)
		}
	})

	t.Run("zero policy holds the log tier", func(t *testing.T) {
		d := NewDetector()
		d.Policy = MergePolicy{}
		tx := mkTx(t, "192.0.2.72", 40003, true, true)
		v := walkN(t, d, tx, paceBreachLoop())
		if v.Action != ladder.ActionLog {
			t.Errorf("zero-policy consensus action = %q, want log (the non-decisive action is the off switch)", v.Action)
		}
	})
}

// paceBreachLoop is the wiring-burst loop count: the pace threshold plus
// one, so the breach lands inside the loop.
func paceBreachLoop() int { return DefaultBehaviorWindowConfig().PaceMaxRequests + 1 }

// hasRule reports whether the rule id is in the walk's rules.
func hasRule(rules []ladder.RuleID, id ladder.RuleID) bool {
	for _, r := range rules {
		if r == id {
			return true
		}
	}
	return false
}
