package rateban

// dos_test.go pins the behavioural DoS detector surface (the spec's
// DoS-response engine-plane duties). Table rows only — the package's
// decision procedure: pure functions get rows, and the cue wiring shares
// one suite with the evidence assertions.

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSlowlorisRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    FlowFeatures
		want bool
	}{
		{
			name: "bulk data flow is clean: large segments",
			f:    FlowFeatures{Segs: 40, Bytes: 40 * 1350, FirstNS: 1_000_000_000, LastNS: 1_000_000_000 + 40*1e9},
			want: false,
		},
		{
			name: "short burst is clean: the span leg fails",
			f:    FlowFeatures{Segs: 28, Bytes: 28 * 10, FirstNS: 1_000_000_000, LastNS: 3_500_000_000},
			want: false,
		},
		{
			name: "few segments is clean: the segment leg fails",
			f:    FlowFeatures{Segs: 3, Bytes: 3 * 10, FirstNS: 1_000_000_000, LastNS: 1_000_000_000 + 40*1e9},
			want: false,
		},
		{
			name: "trickle over the window is the suspect shape",
			f:    FlowFeatures{Segs: 28, Bytes: 28 * 10, FirstNS: 1_000_000_000, LastNS: 1_000_000_000 + 34*1e9},
			want: true,
		},
		{
			name: "unset window never guesses",
			f:    FlowFeatures{Segs: 64, Bytes: 64, FirstNS: 0, LastNS: 40 * 1e9},
			want: false,
		},
		{
			name: "inverted timestamps are clean",
			f:    FlowFeatures{Segs: 30, Bytes: 300, FirstNS: 40 * 1e9, LastNS: 1 * 1e9},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SlowlorisSuspect(tc.f); got != tc.want {
				t.Errorf("row %s: SlowlorisSuspect=%v, want %v (segs=%d bytes=%d)", tc.name, got, tc.want, tc.f.Segs, tc.f.Bytes)
			}
		})
	}
}

func TestRapidResetRows(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resets  int
		streams int
		want    bool
	}{
		{
			name:   "clean connection: no resets",
			resets: 0, streams: 40,
			want: false,
		},
		{
			name:   "under the ratio stays clean",
			resets: 7, streams: 40,
			want: false,
		},
		{
			name:   "storm ratio over the stream floor is suspect",
			resets: 24, streams: 40,
			want: true,
		},
		{
			name:   "storm ratio under the stream floor is clean",
			resets: 10, streams: 12,
			want: false,
		},
		{
			name:   "a single stream never carries the shape",
			resets: 4, streams: 4,
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RapidResetSuspect(tc.resets, tc.streams); got != tc.want {
				t.Errorf("row %s: RapidResetSuspect=%v, want %v (resets=%d streams=%d)", tc.name, got, tc.want, tc.resets, tc.streams)
			}
		})
	}
}

// TestIngestCueWiring pins the cue path: cues ingest under the
// kernel-counter escalation kind, a crossing emits ONE would-ban record
// through the injected sink with the shared note on it, and nothing enforces.
func TestIngestCueWiring(t *testing.T) {
	var recs []BanEvidence
	sink := EvidenceSinkFunc(func(r BanEvidence) error {
		recs = append(recs, r)
		return nil
	})
	now := int64(10_000)
	e := New(func() int64 { return now }, sink)

	// Three rapid-reset cues at one key: 3 x 3 (kernelBurstFlag) under T.
	// The fourth crosses.
	cues := make([]Cue, 0, 4)
	for i := 0; i < 4; i++ {
		cues = append(cues, Cue{
			Key:   "9.9.9.9",
			Class: CueRapidReset,
			AtSec: now,
			Note:  fmt.Sprintf("rapid_reset_suspect (resets=%d streams=%d)", 24+i, 40),
		})
	}
	out, err := e.IngestCues(cues)
	if err != nil {
		t.Fatalf("IngestCues: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("row crossing-at-the-fourth: records=%d, want 1 (%v)", len(out), out)
	}
	if !strings.Contains(out[0].Note, "rapid_reset_suspect") {
		t.Errorf("row crossing-at-the-fourth: the record note must name the cue class, got %q", out[0].Note)
	}
	if out[0].Verdict != "would-ban" || out[0].Tier != "scored-window" {
		t.Errorf("row crossing-at-the-fourth: verdict=%q tier=%q, want would-ban/scored-window", out[0].Verdict, out[0].Tier)
	}
	if len(recs) != 1 {
		t.Errorf("row crossing-at-the-fourth: sink records=%d, want 1 (the same record reaches the sink)", len(recs))
	}
	if e.Enforced() {
		t.Errorf("row crossing-at-the-fourth: a cue run must never enforce")
	}

	// A live would-be ban holds: further cues on the key never re-ban.
	rerun := cues[0]
	out2, err2 := e.IngestCues([]Cue{rerun})
	if err2 != nil || len(out2) != 0 {
		t.Errorf("row live-ban-holds: records=%d err=%v, want none (active ban, no re-scoring)", len(out2), err2)
	}

	// A lone cue never bans (3 x 3 under T); a fresh key crosses on its
	// own window (4 x 3 over T) in the same walk.
	e2 := New(func() int64 { return now }, sink)
	lone := []Cue{
		{Key: "8.8.8.8", Class: CueSlowloris, AtSec: now, Note: "slowloris_suspect (segs=28 bytes/seg=10 span=34s)"},
		{Key: "7.7.7.7", Class: CueSlowloris, AtSec: now + 1, Note: "slowloris_suspect (segs=64)"},
		{Key: "7.7.7.7", Class: CueSlowloris, AtSec: now + 2, Note: "slowloris_suspect (segs=96)"},
		{Key: "7.7.7.7", Class: CueSlowloris, AtSec: now + 3, Note: "slowloris_suspect (segs=128)"},
		{Key: "7.7.7.7", Class: CueSlowloris, AtSec: now + 4, Note: "slowloris_suspect (segs=160)"},
	}
	got, errCues := e2.IngestCues(lone)
	if errCues != nil {
		t.Fatalf("row lone-cue-never-bans: %v", errCues)
	}
	if len(got) != 1 || got[0].Key != "7.7.7.7" {
		t.Errorf("row lone-cue-never-bans: records=%v, want one would-ban at 7.7.7.7", got)
	}
	if active := e2.Active("8.8.8.8", now); active {
		t.Errorf("row lone-cue-never-bans: the lone cue at 8.8.8.8 never bans")
	}
}

// TestNotePropagation pins the evidence-note rule the cue path relies on:
// the record note is the newest contributing event's note — the reading
// that crossed the threshold; an empty crossing note keeps the record
// note empty (the v0 contract).
func TestNotePropagation(t *testing.T) {
	var recs []BanEvidence
	e := New(func() int64 { return 100 }, EvidenceSinkFunc(func(r BanEvidence) error {
		recs = append(recs, r)
		return nil
	}))
	// 5 + 5 + 1 = 11 at t=100 (with decay): crosses T, all within the
	// window, all carrying one shared note.
	for _, ev := range []struct {
		kind EventKind
		at   int64
	}{
		{KindCRSCritical, 98},
		{KindCRSCritical, 99},
		{KindBotSingle, 99},
	} {
		if err := e.Ingest("5.5.5.5", ev.kind, ev.at, "shared-shape-note"); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}
	e.Assess("5.5.5.5", 100)
	if len(recs) != 1 {
		t.Fatalf("row shared-note: records=%d, want 1", len(recs))
	}
	if recs[0].Note != "shared-shape-note" {
		t.Errorf("row shared-note: Note=%q, want shared-shape-note", recs[0].Note)
	}

	e2 := New(func() int64 { return 103 }, EvidenceSinkFunc(func(r BanEvidence) error {
		recs = append(recs, r)
		return nil
	}))
	// 4 x 3 = 12: the window crosses with notes that differ; the crossing
	// reading (the newest event) names the record.
	for i, note := range []string{"note-a", "note-b", "note-c", "note-d"} {
		if err := e2.Ingest("6.6.6.6", KindKernelBurstFlag, int64(100+i), note); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}
	e2.Assess("6.6.6.6", 103)
	last := recs[len(recs)-1]
	if last.Note != "note-d" {
		t.Errorf("row crossing-note: Note=%q, want note-d (the newest event's note)", last.Note)
	}
}

// TestIngestCueSinkError pins the wiring surface: a failing sink stays the
// engine's contract (the engine surfaces a failed record loudly);
// IngestCues never swallows it.
func TestIngestCueSinkError(t *testing.T) {
	boom := errors.New("sink down")
	e := New(func() int64 { return 100 }, EvidenceSinkFunc(func(r BanEvidence) error {
		return boom
	}))
	cues := make([]Cue, 0, 4)
	for i := 0; i < 4; i++ { // 4 x 3 crosses T: the record path runs
		cues = append(cues, Cue{Key: "9.9.9.9", Class: CueRapidReset, AtSec: 100, Note: "rapid_reset_suspect"})
	}
	defer func() {
		if recover() == nil {
			t.Errorf("row sink-error: a failed record must surface (the engine)")
		}
	}()
	_, _ = e.IngestCues(cues)
}
