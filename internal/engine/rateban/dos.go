package rateban

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

// SlowlorisSuspect reports whether one flow's features carry the
// connection-starvation shape: at least MinSegs segments, a window span of
// MinSpanSec seconds or more, and bytes per segment at MaxBytesPerSeg or
// less — headers trickling byte-wise for the whole window. A flow that
// fails any leg is clean: the detector never guesses.
func SlowlorisSuspect(f FlowFeatures) bool {
	// inert stub; the TR-31 GREEN commit fills the shape
	return false
}

// RapidResetSuspect reports whether one connection's frame accounting
// carries the h2 storm shape: at least MinStreams stream heads with a
// stream-reset ratio at MinRatioPct percent or more.
func RapidResetSuspect(resets int, streams int) bool {
	// inert stub; the TR-31 GREEN commit fills the ratio
	return false
}

// IngestCues drives the cue path: every cue ingests under the kernel-counter
// escalation kind with its class + shape in the note, then the shadow Assess
// runs, so a crossing emits its would-ban record through the SAME evidence
// sink as every other event kind. A failing ingest never stops the walk
// (fail-open: the remaining cues still reach the ban path); the errors join
// on the return. No enforcement: the records stay "would-ban" (the shadow
// contract; enforcement is the ban adapter's job).
func (e *Engine) IngestCues(cues []Cue) ([]BanEvidence, error) {
	// inert stub; the TR-31 GREEN commit wires Ingest + Assess
	return nil, nil
}
