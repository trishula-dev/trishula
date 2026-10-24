package rateban

import (
	"errors"
	"time"
)

// dos.go carries the behavioural DoS detector surface of the ban plane
// (the spec's DoS-response section, the engine-plane duties): the slowloris
// shape over kernel flow features and the h2 rapid-reset shape over parser
// frame ratios. TR-31.
//
// The split the spec fixes (its kernel-plane section + its DoS-response
// posture): the kernel counts — segments, bytes and their first/last
// timestamps reach this plane as read-time projections of the shield's
// per-flow map; the engine decides. A cue NEVER enforces: it ingests under
// the ban table's kernel-counter escalation kind (kernelBurstFlag — kernel
// counters alone never issue a ban, they escalate evidence) and rides the
// same shadow record path and evidence sink as every other event kind.
//
// The detector thresholds are the leaf defaults (the CRD knobs land with
// the policy slice); the ban engine's constants are NOT re-declared here —
// the conformance suite byte-mirrors those.

// CueClass names one behavioural DoS detector class. The values are the
// surface names the evidence note carries (the spec's h2 section names the
// flag: tx.flags.rapid_reset_suspect).
type CueClass string

const (
	// CueSlowloris is the connection-starvation shape: many tiny segments
	// over a long per-flow window (the kernel flow_stats map feeds it).
	CueSlowloris CueClass = "slowloris_suspect"
	// CueRapidReset is the h2 open-then-cancel storm shape: the reset
	// ratio over a connection's stream head count passes the threshold.
	CueRapidReset CueClass = "rapid_reset_suspect"
)

// FlowFeatures is the engine-side projection of one flow's detector
// counters (the shield's per-flow map: seg/byte counters + the first/last
// counted-segment timestamps). The caller reads the map (pinned under the
// §-cross-plane share) and fills the struct; NS fields are the kernel
// clock's nanoseconds.
type FlowFeatures struct {
	Segs    uint32
	Bytes   uint32
	FirstNS uint64
	LastNS  uint64
}

// Cue is one behavioural DoS cue ready for the ban path: the offender key,
// the detector class and the measured shape in the note. The note is the
// R11 analyst's reading: `slowloris_suspect (segs=28 bytes/seg=10 span=34s)`.
type Cue struct {
	Key   string
	Class CueClass
	AtSec int64
	Note  string
}

// The leaf defaults (the CRD knobs land with the policy slice). Each name
// reads as its threshold.
const (
	// SlowlorisMinSegs: at least this many counted segments make a flow's
	// window worth reading; below it the segment count alone cannot carry
	// the shape.
	SlowlorisMinSegs = 24
	// SlowlorisMaxBytesPerSeg: the trickle ceiling — segments this small
	// (bytes, arithmetic mean over the window) carry header dribble, not
	// request bodies.
	SlowlorisMaxBytesPerSeg = 64
	// SlowlorisMinSpanSec: the window leg — a starvation connection holds
	// its flow open over tens of seconds; a burst never spans this far.
	SlowlorisMinSpanSec = 30
	// RapidResetMinStreams: the stream floor — a connection below it
	// cannot carry a storm, only an unlucky cancellation.
	RapidResetMinStreams = 16
	// RapidResetMinRatioPct: the reset-ratio floor (percent of opened
	// streams) at and above which a connection reads as a storm.
	RapidResetMinRatioPct = 50
)

// SlowlorisSuspect reports whether one flow's features carry the
// connection-starvation shape: at least SlowlorisMinSegs segments, a
// window span of SlowlorisMinSpanSec seconds or more, and bytes per
// segment at SlowlorisMaxBytesPerSeg or less — headers trickling
// byte-wise for the whole window. An unset or inverted window is clean:
// the detector never guesses.
func SlowlorisSuspect(f FlowFeatures) bool {
	if f.Segs < SlowlorisMinSegs {
		return false
	}
	if f.FirstNS == 0 || f.LastNS < f.FirstNS {
		return false
	}
	spanSec := int64(f.LastNS-f.FirstNS) / int64(time.Second)
	if spanSec < SlowlorisMinSpanSec {
		return false
	}
	// Segs >= SlowlorisMinSegs >= 1: the mean never divides by zero.
	return uint64(f.Bytes)/uint64(f.Segs) <= SlowlorisMaxBytesPerSeg
}

// RapidResetSuspect reports whether one connection's frame accounting
// carries the h2 storm shape: at least RapidResetMinStreams stream heads
// and a reset ratio at RapidResetMinRatioPct percent or more.
func RapidResetSuspect(resets int, streams int) bool {
	if streams < RapidResetMinStreams {
		return false
	}
	return resets*100 >= streams*RapidResetMinRatioPct
}

// IngestCues drives the cue path: every cue ingests under the ban table's
// kernel-counter escalation kind (kernelBurstFlag — kernel counters alone
// never issue a ban, they escalate evidence) with the cue class + the
// measured shape in the note, then the shadow Assess runs, so a crossing
// emits its would-ban record through the SAME evidence sink as every other
// event kind. A failing ingest never stops the walk (fail-open: the
// remaining cues still reach the ban path); the errors join on the return.
// No enforcement: the records stay "would-ban" (the shadow contract;
// the kernel write is the ban adapter's job, never this one's).
func (e *Engine) IngestCues(cues []Cue) ([]BanEvidence, error) {
	var recs []BanEvidence
	var errs []error
	for _, c := range cues {
		// kernelBurstFlag is the ban weights table's kernel-counter row:
		// the DoS cue is a kernel-plane or parser-plane counter escalation,
		// and the note (the cue class + shape) is the R11 analyst's reading.
		if err := e.Ingest(c.Key, KindKernelBurstFlag, c.AtSec, c.Note); err != nil {
			errs = append(errs, err)
			continue
		}
		recs = append(recs, e.Assess(c.Key, c.AtSec)...)
	}
	return recs, errors.Join(errs...)
}
