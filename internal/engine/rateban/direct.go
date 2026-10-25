package rateban

import "fmt"

// direct.go — TR-195 leaf 1 (issue #237; the operator's decision): the
// manual ban surface. A rule pack carrying `action: ban` produces a DIRECT
// would-ban on match: no score, no window, no threshold — the rule IS the
// decision. The record feeds the same BanEnforcer the scored path feeds
// (the kernel row + the evidence record read it unchanged), so the manual
// act and the automatic act carry one enforcement shape + one FP-diagnosis
// story. The verdict string stays "would-ban": the kernel write is the
// enforcer's job, never the caller's (the shadow contract holds).
//
// Tier "manual-rule" is the enforcement-tier name this record carries; the
// reason code names the owning rule (ruleBan:<ruleID>) so the evidence
// reads the cause.

// DirectBan builds the would-ban record one manual rule match produces.
// key = the offender key (the source the event read), ruleID = the owning
// rule pack entry, atSec = the engine clock's reading, note = the operator
// facing annotation (the dynamic signature's printable form; empty keeps
// the field absent).
func DirectBan(key, ruleID string, atSec int64, note string) BanEvidence {
	return BanEvidence{
		Key:         key,
		Mode:        "manual",
		Verdict:     "would-ban",
		Tier:        "manual-rule",
		Score:       0,
		Threshold:   Threshold,
		Events:      []EvidenceEvent{{Kind: "ruleBan", Weight: 0, AtSec: atSec}},
		ReasonCodes: []string{"ruleBan:" + ruleID},
		AtSec:       atSec,
		UntilSec:    atSec + BantimeSec,
		Recidivism:  0,
		BantimeSec:  BantimeSec,
		Note:        note,
	}
}

// DirectBanNote is the printable dynamic signature for a manual rule: what
// matched, in the evidence note's form (the request view's facts the rule
// read live).
func DirectBanNote(method, path, ruleID string) string {
	return fmt.Sprintf("manual rule %s matched %s %s", ruleID, method, path)
}
