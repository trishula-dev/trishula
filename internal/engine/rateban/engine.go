package rateban

import (
	"math"
	"sort"
	"sync"
)

// BanEvidence is the R11/§13.5 ban-evidence record: the shadow run's
// account of one would-ban, shaped so a false positive is diagnosable in
// minutes — what happened, which events contributed at which weights, the
// score trajectory, the would-be ban window and tier. JSON-serializable by
// contract (the OTLP log record (§15)/trishulactl ban list --output json
// consumers), so every field is a JSON-native type and struct tags are
// lowerCamel stable wire names.
//
// Shadow (TR-09) fills every field ABOVE the enforcement seam: nothing in
// the record claims a drop or a kernel write happened — Verdict is
// explicitly "would-ban".
type BanEvidence struct {
	// Key is the offender key (the source string the events were recorded under).
	Key string `json:"key"`
	// Mode is the policy mode that produced this record: "shadow".
	Mode string `json:"mode"`
	// Verdict is what the algorithm determined: "would-ban" (shadow) —
	// an enforcement run (TR-10) writes "ban".
	Verdict string `json:"verdict"`
	// Tier is the §13.4 ladder tier this would-ban maps to: "scored-window"
	// (§13.3 step 3 fixes the tier name).
	Tier string `json:"tier"`
	// Score is the decayed §13.3 score at the crossing (T at minimum).
	Score float64 `json:"score"`
	// Threshold is the T the score crossed (redundant by design: the
	// reader of one record must not need the CRD to diagnose it).
	Threshold float64 `json:"threshold"`
	// Events is the contributing evidence: the window's weighted events,
	// oldest first — the §13.5 "score trajectory (the contributing events
	// with weights)".
	Events []EvidenceEvent `json:"events"`
	// ReasonCodes names the weight contributors (§13.3 step 3:
	// reason_codes = weight contributors) — deduped event kinds, in
	// first-seen order.
	ReasonCodes []string `json:"reasonCodes"`
	// AtSec is the crossing instant (monotonic seconds, engine clock).
	AtSec int64 `json:"atSec"`
	// UntilSec is when the would-be ban expires: AtSec +
	// min(bantime·κ^recidivism, maxBantime). Expiry parity with the
	// shield loader: the ban holds while now < UntilSec; at
	// now >= UntilSec it is over (BanVal.Expired semantics).
	UntilSec int64 `json:"untilSec"`
	// Recidivism is the count of prior bans for this key when this record
	// was produced (0 = first ban; the κ exponent applied is this value).
	Recidivism int `json:"recidivism"`
	// BantimeSec is the applied base duration for this would-be ban
	// (bantime·κ^recidivism, capped at maxBantime) — the record is
	// self-contained for FP diagnosis.
	BantimeSec int64 `json:"bantimeSec"`
	// Note is an optional operator-facing annotation (v0: empty).
	Note string `json:"note,omitempty"`
}

// EvidenceEvent is one contributing event in a BanEvidence record.
type EvidenceEvent struct {
	// Kind is the §13.3 event kind (BanPolicy weights-table name).
	Kind string `json:"kind"`
	// Weight is the §13.3 weight the kind contributed.
	Weight float64 `json:"weight"`
	// AtSec is when the event was ingested (monotonic seconds).
	AtSec int64 `json:"atSec"`
}

// EvidenceSink receives one record per would-ban determination. In shadow
// this is the ONLY side effect an Engine produces (§13.3 shadow-first:
// verdicts + logs without enforcement). TR-11's OTLP pipeline implements
// it; tests collect.
type EvidenceSink interface {
	Record(BanEvidence) error
}

// EvidenceSinkFunc adapts a func to EvidenceSink.
type EvidenceSinkFunc func(BanEvidence) error

// Record implements EvidenceSink.
func (f EvidenceSinkFunc) Record(r BanEvidence) error { return f(r) }

// BanRateAboveBudget is the exported metric counter TR-11 wires (M6/
// BanRateAboveBudget alert, §21; R11 mitigation row in the PRD). Plain
// *int64 so this leaf stays free of prometheus/otel — the TR-11 exporter
// owns rates/alarms; here it is incremented once per would-ban the shadow
// path emits.
var BanRateAboveBudget = new(int64)

// ScoredEvent is one weighted event as ingested (the §13.3 evidence atom:
// offender key + event kind + the weight the kind carries + timestamp).
// Exposed so the conformance runner and the TR-10 wire adapter can share
// one representation of "which events, which weights".
type ScoredEvent struct {
	// Key is the offender key the event belongs to.
	Key string `json:"key"`
	// Kind is the §13.3 event kind (BanPolicy weights-table name).
	Kind EventKind `json:"kind"`
	// Weight is the §13.3 weight of Kind at ingest time.
	Weight float64 `json:"weight"`
	// AtSec is the event's monotonic-second timestamp (engine clock).
	AtSec int64 `json:"atSec"`
	// Note is an optional operator annotation (v0: empty).
	Note string `json:"note,omitempty"`
}

// WouldBan is the shadow decision returned by Observe/Assess.
type WouldBan struct {
	// Key is the offender key.
	Key string `json:"key"`
	// Score is the decayed §13.3 score at this instant.
	Score float64 `json:"score"`
	// WouldBan is true when score >= threshold and no live ban holds.
	WouldBan bool `json:"wouldBan"`
	// ActiveBan is true while the key is under a live (not expired) ban.
	ActiveBan bool `json:"activeBan"`
	// UntilSec is the live/last ban expiry (0 = none).
	UntilSec int64 `json:"untilSec"`
	// Recidivism is the completed ban count (κ exponent for the next ban).
	Recidivism int `json:"recidivism"`
}

// keyState is the §13.3 per-source state (events sliding window, live ban,
// recidivism). Guarded by Engine.mu.
type keyState struct {
	events     []eventRec // append-only; expired entries are dropped on upkeep
	untilSec   int64      // live ban expiry (0 = none)
	recidivism int        // completed bans so far
}

type eventRec struct {
	atSec  int64
	kind   string
	weight float64
}

// Engine is ScoredWindowBan v1 (§13.3) in shadow. It is safe for
// concurrent use. The clock and evidence sink are injected — kernel-free,
// telemetry-sink-free construction (the leaf imports no observability).
type Engine struct {
	mu    sync.Mutex
	nowFn func() int64 // monotonic seconds
	sink  EvidenceSink
	state map[string]*keyState
}

// New builds a shadow ScoredWindowBan engine on an injected monotonic
// seconds clock and evidence sink (§13.3 decision loop, step 4 only:
// automatic expiry; early release is §13.6 workflow, out of TR-09 scope).
func New(nowFn func() int64, sink EvidenceSink) *Engine {
	if nowFn == nil {
		panic("rateban: nil clock")
	}
	if sink == nil {
		panic("rateban: nil evidence sink")
	}
	return &Engine{
		nowFn: nowFn,
		sink:  sink,
		state: map[string]*keyState{},
	}
}

// Ingest feeds one ScoredEvent (offender key + event kind; the kind picks
// the §13.3 weight — an unknown kind is an error, never a guessed weight).
// The event is stamped by the caller's atSec (the engine clock's value at
// the observation), kept under the sliding window keyed by FindtimeSec.
func (e *Engine) Ingest(key string, kind EventKind, atSec int64, note string) error {
	w, err := KindWeight(string(kind))
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.state[key]
	if s == nil {
		s = &keyState{}
		e.state[key] = s
	}
	s.events = append(s.events, eventRec{atSec: atSec, kind: string(kind), weight: w})
	e.upkeep(s, atSec)
	return nil
}

// Observe runs §13.3 steps 1-2 at the current clock: recompute the score
// over the window, honor a live ban (no re-scoring), and return the
// decision WITHOUT recording it (Observe is read-only; Assess records).
func (e *Engine) Observe(key string) WouldBan {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.nowFn()
	s := e.state[key]
	wb := WouldBan{Key: key}
	if s == nil {
		wb.Score = 0
		return wb
	}
	e.upkeep(s, now)
	if s.untilSec > now {
		// §13.3 step 2: state ACTIVE_BAN and now < until: enforcement
		// continues; no re-scoring → the reported score is 0 by
		// convention (nothing was computed), WouldBan false.
		wb.ActiveBan = true
		wb.UntilSec = s.untilSec
		wb.Recidivism = s.recidivism
		return wb
	}
	wb.Score = e.score(s, now)
	wb.WouldBan = wb.Score >= Threshold
	wb.Recidivism = s.recidivism
	return wb
}

// Assess runs §13.3 step 3 in shadow at the given instant: if score >= T
// (and no live ban holds), increment recidivism, compute until = now +
// min(B·κ^recid, Bmax), emit the R11 ban-evidence record to the sink, and
// bump the exported BanRateAboveBudget counter — with NO enforcement side
// effect (Verdict stays "would-ban"; TR-10 writes kernels).
func (e *Engine) Assess(key string, atSec int64) []BanEvidence {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.state[key]
	var recs []BanEvidence
	if s == nil {
		return recs
	}
	e.upkeep(s, atSec)
	if s.untilSec > atSec {
		return recs // step 2: live ban — no re-scoring, no re-ban within bantime
	}
	score := e.score(s, atSec)
	if score < Threshold {
		return recs
	}
	untilDelta := untilFor(s.recidivism)
	rec := BanEvidence{
		Key:        key,
		Mode:       "shadow",
		Verdict:    "would-ban",
		Tier:       "scored-window",
		Score:      score,
		Threshold:  Threshold,
		AtSec:      atSec,
		UntilSec:   atSec + untilDelta,
		Recidivism: s.recidivism,
		BantimeSec: untilDelta,
	}
	s.recidivism++                  // §13.3 step 3: recidivism[s] += 1
	s.untilSec = atSec + untilDelta // the shadow state still tracks the would-be window
	for _, ev := range s.events {
		age := atSec - ev.atSec
		if age < 0 || age > FindtimeSec {
			continue
		}
		rec.Events = append(rec.Events, EvidenceEvent{Kind: ev.kind, Weight: ev.weight, AtSec: ev.atSec})
		if !contains(rec.ReasonCodes, ev.kind) {
			rec.ReasonCodes = append(rec.ReasonCodes, ev.kind)
		}
	}
	if err := e.sink.Record(rec); err != nil {
		// §13.5: every ban decision emits its record. A sink failure
		// here means the shadow path cannot evidence the decision —
		// surface it loudly rather than silently deciding.
		panic(err)
	}
	atomicRateTick() // BanRateAboveBudget++
	recs = append(recs, rec)
	return recs
}

// Active reports whether the key is under a live ban at now: the shield
// loader parity (BanVal.Expired): the ban holds while now < until; expiry
// is now >= until.
func (e *Engine) Active(key string, now int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.state[key]
	if s == nil {
		return false
	}
	return s.untilSec > now
}

// Enforced reports whether this engine wrote any enforcement state. In
// TR-09 shadow this is always false — pinned by the conformance suite
// (expectNoEnforcement) so a future enforcement leak fails RED here.
func (e *Engine) Enforced() bool { return false }

// score is §13.3 step 1: Σ w_i·e^(−λ·(now−t_i)) over events in the window.
func (e *Engine) score(s *keyState, now int64) float64 {
	total := 0.0
	for _, ev := range s.events {
		age := now - ev.atSec
		if age < 0 || age > FindtimeSec {
			continue
		}
		total += ev.weight * math.Exp(-lambdaDecay*float64(age))
	}
	return total
}

// upkeep drops window-stale events (age > findtime) and clears a ban whose
// expiry passed (automatic expiry, §13.3 step 4: now >= until).
func (e *Engine) upkeep(s *keyState, now int64) {
	kept := s.events[:0]
	for _, ev := range s.events {
		if now-ev.atSec <= FindtimeSec {
			kept = append(kept, ev)
		}
	}
	s.events = kept
	if s.untilSec != 0 && now >= s.untilSec {
		s.untilSec = 0 // §13.3 step 4: automatic at until
	}
}

// untilFor: min(bantime·κ^recid, maxBantime) — the §13.3 until delta.
func untilFor(recidivism int) int64 {
	b := BantimeSec * int64(math.Pow(Backoff, float64(recidivism)))
	if b > MaxBantimeSec {
		b = MaxBantimeSec
	}
	return b
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// sortEvents is unused today but kept for the §13.5 trajectory
// oldest-first guarantee if events ever arrive out of order upstream.
func sortEvents(evs []EvidenceEvent) {
	sort.Slice(evs, func(i, j int) bool { return evs[i].AtSec < evs[j].AtSec })
}
