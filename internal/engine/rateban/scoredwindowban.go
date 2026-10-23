// Package rateban implements ScoredWindowBan v1 (the spec's ban algorithm) as its own
// engine leaf: weighted event scores in a sliding findtime window, decayed
// exponentially at a half-life of decayHalfLifePct of the window, with
// recidivism-kappa bantime backoff capped at maxBantime.
//
// TR-09 ships the SKELETON IN SHADOW: scores, would-ban determinations and
// ban-evidence records only — nothing here enforces (no kernel map writes,
// no verdict actions). Enforcement is TR-10's contract; the evidence record
// shape is the R11 contract (a false positive must be diagnosable in
// minutes: what happened, which weighted events, when, with which result).
//
// Kernel-free and telemetry-clean by construction (README §engine): the
// clock is injected (now fn), the evidence sink is an interface, and the
// only metric surface is the plain exported counter BanRateAboveBudget —
// TR-11 wires that counter into its exporter; this leaf imports neither
// prometheus nor otel.
//
// The spec's ban-algorithm text is authoritative; test/ban-conformance reproduces
// it from the fixtures + an independent Python oracle (testdata/recompute.py).
package rateban

import (
	"fmt"
	"math"
)

// Ban-algorithm constants — the BanPolicy CRD defaults (the reference-implementation sketch), names
// verbatim. Do not "improve" these here: the conformance suite byte-mirrors
// the sketch, and per-vertical presets are reference-implementation BanPolicy recipes, not
// code forks.
const (
	// findtime W = 10m: the evidence window (fail2ban analog: findtime).
	FindtimeSec int64 = 600
	// threshold T = 10: ban score (fail2ban analog: maxretry — score, not raw count).
	Threshold = 10.0
	// bantime B = 10m: base ban duration (fail2ban analog: bantime).
	BantimeSec int64 = 600
	// backoff κ = 2: recidivism exponential multiplier (fail2ban analog: recidive jail).
	Backoff = 2.0
	// maxBantime Bmax = 24h: human-scale cap — permanence is a decision,
	// not an accident (the spec's ban algorithm).
	MaxBantimeSec int64 = 86400
	// decayHalfLifePct = 20: score-decay half-life as % of findtime
	// (staleness by design, the spec's ban algorithm).
	DecayHalfLifePct = 20.0
)

// EventKind enumerates the spec's ban-algorithm weighted event kinds. The wire names are
// the BanPolicy weights-table keys (the reference-implementation sketch) — never renamed locally.
type EventKind string

const (
	KindCRSCritical     EventKind = "crsCritical"
	KindCRSWarning      EventKind = "crsWarning"
	KindBotConsensus    EventKind = "botConsensus"
	KindBotSingle       EventKind = "botSingle"
	KindRateBreach      EventKind = "rateBreach"
	KindSchemaViolation EventKind = "schemaViolation"
	KindAuthFailure     EventKind = "authFailure"
	KindKernelBurstFlag EventKind = "kernelBurstFlag"
)

// lambdaDecay is λ in the ban algorithm's score: e^(−λ·age) with half-life
// DecayHalfLifePct% of FindtimeSec — i.e. λ = ln2 / (0.2 · 600 s).
var lambdaDecay = math.Ln2 / (DecayHalfLifePct / 100.0 * float64(FindtimeSec))

// DefaultWeights mirrors the ban algorithm's weights table (the reference-implementation sketch, names
// verbatim):
//
//	CRS critical match +5 · CRS warning match +2
//	bot consensus verdict +4 · single-detector bot hit +1
//	rate-window breach +3 · schema violation +2
//	auth failure (401/403) +2 · kernel EWMA burst flag +3
func DefaultWeights() map[string]float64 {
	return map[string]float64{
		"crsCritical":     5,
		"crsWarning":      2,
		"botConsensus":    4,
		"botSingle":       1,
		"rateBreach":      3,
		"schemaViolation": 2,
		"authFailure":     2,
		"kernelBurstFlag": 3,
	}
}

// KindWeight resolves one event kind's ban-algorithm weight (error: unknown kind —
// callers decide policy; the engine never invents a weight).
func KindWeight(k string) (float64, error) {
	w, ok := DefaultWeights()[k]
	if !ok {
		return 0, fmt.Errorf("rateban: unknown event kind %q", k)
	}
	return w, nil
}
