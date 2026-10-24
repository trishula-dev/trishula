// Package banconformance owns the ScoredWindowBan v1 spec-reproduction
// fixtures (spec section 13.3: "implementations must reproduce it from this
// spec alone (a conformance test does exactly that)"). internal/cuegen
// derives test/ban-conformance/ban_conformance_fixtures.yaml from the `doc`
// value; the Go runner (test/ban-conformance/conformance_test.go) and the
// independent Python oracle (testdata/recompute.py) keep reading that file.
// A change to a fixture is a change here, never in the derived file: the
// golden-diff gate rejects hand edits.
// Structure rules of the record:
//
//   - The YAML carries fixture STRUCTURE only — integer times, event kinds,
//     booleans. Every numeric expectation (score windows, would-ban, until,
//     backoff schedule) is recomputed from the section 13.3 formulas by the
//     runner and cross-checked by testdata/recompute.py; nothing is
//     hand-tuned.
//   - Clock convention: monotonic integer seconds t = 0, 1, 2 ... injected
//     via the engine's nowFn.
//
// `wantUntil` semantics: Assess at time a with recidivism r returns
// until = a + min(bantime·backoff^r, maxBantime). The r for each banAt is
// the count of PRIOR ban transitions for the key.
// TR-46 (issue #192), census row "Ban-conformance fixtures" — CUE-owned.
package banconformance

// EventKind is one ScoredEvent kind (the weights table names them verbatim).
#EventKind: "crsCritical" | "crsWarning" | "botConsensus" | "botSingle" |
	"rateBreach" | "schemaViolation" | "authFailure" | "kernelBurstFlag"

// IngestStep feeds ScoredEvent (weight from policy).
#IngestStep: {
	at: int
	ingest: {
		key:  string
		kind: #EventKind
	}
}

// EvalStep runs Observe/Assess; assertions:
//
//   - wantWouldBan: bool — the shadow decision at this instant
//   - state: CLEAR | ACTIVE_BAN
//   - wantScoreSum is implicit: the observed score must equal the section
//     13.3 formula Σ w·e^(−λ·age) over this key's ingests at `at`
//     (runner-computed)
#EvalStep: {
	at: int
	evaluate: {
		key:            string
		state?:         "CLEAR" | "ACTIVE_BAN"
		wantWouldBan?:  bool
		banTransition?: bool
		strictDecay?:   bool
		wantUntil?:     int
	}
}

// BanAtStep runs Assess at `at` and asserts the shadow would-ban record's
// until.
#BanAtStep: {
	at: int
	banAt: {
		key:       string
		wantUntil: int
	}
}

// NoEnforcementStep (fixture level): fail if anything but the evidence sink
// was touched (shadow, section 13.3).
#NoEnforcementStep: {
	expectNoEnforcement: true
}

#Step: #IngestStep | #EvalStep | #BanAtStep | #NoEnforcementStep

// EvidenceCheck is one evidence-record assertion the runner runs.
#EvidenceCheck: "modeIsShadow" | "hasKey" | "hasEventsWithWeights" |
	"scoreTrajectoryHasWeights" | "hasUntil" | "hasTier" |
	"hasReasonCodes" | "jsonSerializable"

// Fixture is one spec-reproduction case.
#Fixture: {
	id:   string
	name: string
	steps: [...#Step]
	evidenceChecks?: [...#EvidenceCheck]
	dataOnly?: true
	reserved?: true
	backoffSchedule?: {
		recidivism: [...int]
		bantime: [...int]
	}
}

// BanPolicy mirrors the section 19.1 sketch (constants + weight names
// verbatim). conformance_test.go and testdata/recompute.py assert this
// block EQUAL to their own constant tables.
#BanPolicy: {
	constants: {
		findtime:   "10m"
		threshold:  10
		bantime:    "10m"
		backoff:    2
		maxBantime: "24h"
	}
	weights: {
		crsCritical:     5
		crsWarning:      2
		botConsensus:    4
		botSingle:       1
		rateBreach:      3
		schemaViolation: 2
		authFailure:     2
		kernelBurstFlag: 3
	}
	decayHalfLifePct: 20
	prefixEscalation: {
		enabled: false
		minKeys: 8
		window:  "10m"
	}
	mode: "shadow"
}

// doc is the derived-content source of the committed fixtures file.
doc: {
	schema: "trishula.ban-conformance.v1"
	policy: #BanPolicy
	fixtures: [...#Fixture]
}

doc: {
	policy: {}
	fixtures: [
		// --- score accumulation from weighted events ------------------------
		{
			id:   "F01"
			name: "mixed kinds accumulate below threshold (decay visible across evals)"
			steps: [
				{at: 10, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 15, ingest: {key: "203.0.113.50", kind: "crsWarning"}},
				{at: 20, ingest: {key: "203.0.113.50", kind: "botSingle"}},
				{at: 20, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
				{at: 21, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false, strictDecay: true}},
			]
			evidenceChecks: []
		},
		// --- unlike kinds carry unlike weights ------------------------------
		{
			id:   "F02"
			name: "same instants as F01, bot-consensus-dominant mix scores differently"
			steps: [
				{at: 10, ingest: {key: "203.0.113.50", kind: "botConsensus"}},
				{at: 15, ingest: {key: "203.0.113.50", kind: "botConsensus"}},
				{at: 20, ingest: {key: "203.0.113.50", kind: "botSingle"}},
				{at: 20, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
			]
			evidenceChecks: []
		},
		// --- threshold crossing -> would-ban --------------------------------
		{
			id:   "F03"
			name: "crsCritical + botConsensus stays under, third event crosses"
			steps: [
				{at: 0, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 1, ingest: {key: "203.0.113.50", kind: "botConsensus"}},
				{at: 2, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
				{at: 3, ingest: {key: "203.0.113.50", kind: "botConsensus"}},
				{at: 3, evaluate: {key: "203.0.113.50", wantWouldBan: true, banTransition: true}},
			]
			evidenceChecks: ["hasKey", "hasEventsWithWeights", "scoreTrajectoryHasWeights", "hasUntil", "hasTier", "hasReasonCodes", "jsonSerializable"]
		},
		// --- shadow: ban decided, never enforced ----------------------------
		{
			id:   "F04"
			name: "would-ban under shadow records evidence, touches nothing else"
			steps: [
				{at: 0, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 1, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 2, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 3, ingest: {key: "203.0.113.50", kind: "rateBreach"}},
				{at: 3, evaluate: {key: "203.0.113.50", wantWouldBan: true, banTransition: true}},
				{expectNoEnforcement: true},
			]
			evidenceChecks: ["modeIsShadow", "hasKey", "hasEventsWithWeights", "scoreTrajectoryHasWeights", "hasUntil", "hasTier", "hasReasonCodes", "jsonSerializable"]
		},
		// --- ban expiry semantics: now >= until (shield loader parity) ------
		{
			id:   "F05"
			name: "ACTIVE_BAN one second before until, CLEAR at until"
			steps: [
				{at: 0, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 1, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 2, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 3, ingest: {key: "203.0.113.50", kind: "rateBreach"}},
				{at: 5, banAt: {key: "203.0.113.50", wantUntil: 605}},
				{at: 599, evaluate: {key: "203.0.113.50", state: "ACTIVE_BAN", wantWouldBan: false}},
				{at: 600, evaluate: {key: "203.0.113.50", state: "ACTIVE_BAN", wantWouldBan: false}},
				{at: 605, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
			]
			evidenceChecks: ["hasUntil", "hasTier"]
		},
		// --- no re-ban within bantime ----------------------------------------
		{
			id:   "F06"
			name: "mid-ban evaluate never re-bans and never re-arms"
			steps: [
				{at: 0, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 1, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 2, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 3, ingest: {key: "203.0.113.50", kind: "rateBreach"}},
				{at: 4, ingest: {key: "203.0.113.50", kind: "botConsensus"}},
				{at: 5, banAt: {key: "203.0.113.50", wantUntil: 605}},
				{at: 300, evaluate: {key: "203.0.113.50", state: "ACTIVE_BAN", wantWouldBan: false}},
				{at: 604, evaluate: {key: "203.0.113.50", state: "ACTIVE_BAN", wantWouldBan: false}},
			]
			evidenceChecks: ["hasUntil"]
		},
		// --- sliding-window retention keyed by findtime ----------------------
		{
			id:   "F07"
			name: "events older than findtime drop out entirely"
			steps: [
				{at: 0, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 1, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 2, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 3, evaluate: {key: "203.0.113.50", wantWouldBan: true, banTransition: true}},
				{at: 608, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
			]
			evidenceChecks: ["hasUntil"]
		},
		// --- decay at decayHalfLifePct: stale mass shrinks below threshold ---
		{
			id:   "F08"
			name: "decayed window under threshold despite raw weight over it"
			steps: [
				{at: 4, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 11, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 18, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 120, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
			]
			evidenceChecks: []
		},
		// --- stale remainder + fresh singular event cannot re-cross alone ----
		{
			id:   "F09"
			name: "after expiry, one fresh event plus stale remainder stays clear"
			steps: [
				{at: 0, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 1, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 2, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 2, banAt: {key: "203.0.113.50", wantUntil: 602}},
				{at: 602, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
				{at: 603, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 603, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
			]
			evidenceChecks: ["hasUntil"]
		},
		// --- recross after expiry is a LEGAL re-ban with κ backoff -----------
		{
			id:   "F10"
			name: "second ban after expiry doubles bantime (recidivism 1)"
			steps: [
				{at: 0, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 1, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 2, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 2, banAt: {key: "203.0.113.50", wantUntil: 602}},
				{at: 700, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 701, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 702, ingest: {key: "203.0.113.50", kind: "crsCritical"}},
				{at: 702, banAt: {key: "203.0.113.50", wantUntil: 1902}},
				{at: 1901, evaluate: {key: "203.0.113.50", state: "ACTIVE_BAN", wantWouldBan: false}},
				{at: 1902, evaluate: {key: "203.0.113.50", state: "CLEAR", wantWouldBan: false}},
			]
			evidenceChecks: ["hasUntil", "hasTier"]
		},
		// --- recidivism backoff schedule (data row; Go unit test consumes) ---
		{
			id:       "F11"
			name:     "κ=2 walk caps at maxBantime (recidivism 0..8)"
			dataOnly: true
			backoffSchedule: {
				recidivism: [0, 1, 2, 3, 4, 5, 6, 7, 8]
				bantime: [600, 1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400]
			}
			steps: []
			evidenceChecks: []
		},
		// --- reserved: TR-10 kernel hand-off (score parity with section 8) ---
		{
			id:       "TR10-15"
			name:     "reserved slot for TR-10's kernel-side score parity walk"
			reserved: true
			dataOnly: true
			steps: []
			evidenceChecks: []
		},
	]
}

// header is the comment block the derivation prepends (provenance only; it
// never carries data).
header: """
	# ScoredWindowBan v1 spec-reproduction fixtures (spec section 13.3: "implementations
	# must reproduce it from this spec alone (a conformance test does exactly
	# that)").
	#
	# The YAML carries fixture STRUCTURE only — integer times, event kinds,
	# booleans. Every numeric expectation (score windows, would-ban, until,
	# backoff schedule) is recomputed from the section 13.3 formulas by the runner
	# and cross-checked by testdata/recompute.py; nothing here is hand-tuned.
	#
	# Clock convention: monotonic integer seconds t = 0, 1, 2 ... injected via
	# the engine's nowFn.
	#
	# Step vocabulary (mechanical):
	#   ingest {at, key, kind}            feed ScoredEvent (weight from policy)
	#   evaluate {at, key, want*}         run Observe/Assess; assertions:
	#     wantWouldBan  bool              shadow decision at this instant
	#     state         CLEAR | ACTIVE_BAN
	#     wantScoreSum  implicit          observed score must equal the section 13.3
	#                                   formula Σ w·e^(−λ·age) over this key's
	#                                   ingests at `at` (runner-computed)
	#   banAt {at, key, wantUntil}        run Assess at `at` and assert the
	#                                   shadow would-ban record's until
	#   expectNoEnforcement (fixture)     fail if anything but the evidence sink
	#                                   was touched (shadow section 13.3)
	#
	# `wantUntil` semantics: Assess at time a with recidivism r returns
	# until = a + min(bantime·backoff^r, maxBantime). The r for each banAt is
	# the count of PRIOR ban transitions for the key.
	#
	# Generated by internal/cuegen from cue/banconformance (TR-46, issue #192):
	# hand edits fail the golden-diff gate; change the CUE source instead.
	"""
