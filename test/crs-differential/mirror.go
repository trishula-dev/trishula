// mirror.go (TR-07b): the engine-mirror stage of the CRS differential
// harness. The mirror asserts corpus expectations per case against the
// REFERENCE projection (internal/crs on the committed engine.conf). The
// latched S2 ladder slot is NOT wired into the engine here — parity of the
// CRS verdict shape is pinned against crs.Evaluator only (the ladder
// consumes the projected verdict with later slices).
package crsdifferential

import (
	"fmt"
	"sort"

	"github.com/trishula-dev/trishula/internal/crs"
)

// MirrorExpectation is the engine-mirror's per-case assertion sheet:
// the pinned setup-echo ids (engine-mirror-noise, README), the demotion
// evidence (941010 phase-1 marker), and the attack-id sets the mirror
// replicates from the reference surface (seed + off-seed).
type MirrorExpectation struct {
	// PinnedNoise are the setup/echo phase-1 ids (900000/900110/900990)
	// that every request carries; the engine mirror drops phase-3 echoes
	// and asserts exactly these.
	PinnedNoise []int
	// Demoted1941010 is the 941010 demotion evidence: the reference
	// phase-1 match set carries the id when the marker rule 990002 ran.
	Demoted1941010 bool
	// AttackP2 is the phase-2 attack-rule id set the mirror pins for the
	// case (seed + off-seed, unioned).
	AttackP2 []int
	// SqliFP/XssFP (issue #290): the fingerprint-class pins (the corpus
	// expect rows; ProjectMirror copies them verbatim).
	SqliFP string
	XssFP  bool
}

// ProjectMirror projects one corpus case into the mirror expectation the
// way the latched S2 slot would replicate the CRS surface: the pinned
// setup echo, the demotion marker, and the phase-2 attack ids (the
// corpus's seed + off-seed sets, unioned — the mirror pins the OBSERVED
// attack surface, never the raw match list order).
func ProjectMirror(c Case) MirrorExpectation {
	attack := append([]int{}, c.Expect.Phase2Seed...)
	attack = append(attack, c.Expect.Phase2Offseed...)
	sort.Ints(attack)
	attack = uniqueSorted(attack)
	return MirrorExpectation{
		PinnedNoise:    c.Expect.Phase1Pinned,
		Demoted1941010: c.Expect.P1941010,
		AttackP2:       attack,
		SqliFP:         c.Expect.SqliFP,
		XssFP:          c.Expect.XssFP,
	}
}

// DiffMirror diffs one mirror expectation against the reference verdict
// (crs.Evaluator projection). Returns the unexplained delta ("" = parity
// on this case): a delta is any pinned id the reference missed, a
// reference setup echo the corpus did not pin, demotion-evidence
// disagreement, or an attack id present on one side only.
func DiffMirror(c Case, me MirrorExpectation, ref crs.Verdict) string {
	refNoise := []int{}
	for _, m := range ref.Phase1Matches {
		if isNoiseID(m.RuleID) {
			refNoise = append(refNoise, m.RuleID)
		}
	}
	if !equalSets(me.PinnedNoise, refNoise) {
		return fmt.Sprintf("noise pin mismatch: want %v, reference %v", me.PinnedNoise, refNoise)
	}
	if me.Demoted1941010 != hasID(ref.Phase1Matches, 941010) {
		return fmt.Sprintf("941010 demotion evidence: want %v, reference %v",
			me.Demoted1941010, hasID(ref.Phase1Matches, 941010))
	}
	refAttack := []int{}
	for _, m := range ref.Phase2Matches {
		if !isNoiseID(m.RuleID) {
			refAttack = append(refAttack, m.RuleID)
		}
	}
	refAttack = uniqueSorted(refAttack)
	if !equalSets(me.AttackP2, refAttack) {
		onlyRef, _ := setDiff(me.AttackP2, refAttack)
		_, onlyLive := setDiff(me.AttackP2, refAttack)
		return fmt.Sprintf("phase-2 attack set: mirror %v vs reference %v (mirror-only %v, reference-only %v)",
			me.AttackP2, refAttack, onlyRef, onlyLive)
	}
	if d := diffFingerprints(me.SqliFP, me.XssFP, firedCarrierClasses(ref), ref.Fingerprints); d != "" {
		return d
	}
	return ""
}

// carrierIDs (issue #290) lists the libinjection carrier rule ids of one
// class, sorted ascending — the fired-carrier message names them exactly.
func carrierIDs(class string) []int {
	ids := []int{}
	for id, c := range crs.FingerprintCarriers {
		if c == class {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	return ids
}

// firedCarrierClasses (issue #290) collects the libinjection carrier
// classes that fired on the reference verdict across both phases. The
// map names the classes (crs.FingerprintCarriers is the rule→class map).
func firedCarrierClasses(ref crs.Verdict) map[string]bool {
	fired := map[string]bool{}
	for _, m := range ref.Phase1Matches {
		if c, ok := crs.FingerprintCarriers[m.RuleID]; ok {
			fired[c] = true
		}
	}
	for _, m := range ref.Phase2Matches {
		if c, ok := crs.FingerprintCarriers[m.RuleID]; ok {
			fired[c] = true
		}
	}
	return fired
}

// diffFingerprints (issue #290) diffs the corpus fingerprint-class pins
// against the reference's libinjection evidence, both directions: a row
// pinning the SQLi fingerprint requires EXACTLY that fingerprint (one
// distinct value over the case's SQLi-class carriers); a row pinning the
// XSS class requires at least one XSS-class evidence row; a row pinning a
// class absent (the benign-clean shape: empty sqli_fp + false xss_fp)
// requires ZERO evidence. The reverse check (Greptile review 4532586207):
// a FIRED carrier requires evidence of its class — a case with no pin
// where a carrier fired and no evidence row exists fails with the fired
// carrier ids named.
func diffFingerprints(wantSQLi string, wantXSS bool, fired map[string]bool, ev []crs.Fingerprint) string {
	var sqli []string
	sqliRows, xssRows := 0, 0
	xss := 0
	for _, f := range ev {
		switch f.Class {
		case crs.FingerprintClassSQLi:
			sqli = append(sqli, f.FP)
			sqliRows++
		case crs.FingerprintClassXSS:
			xss++
			xssRows++
		}
	}
	if fired[crs.FingerprintClassSQLi] && sqliRows == 0 {
		return fmt.Sprintf("SQLi carrier rules fired without fingerprint evidence: %v fired, want >= 1 sqli-class row, got 0",
			carrierIDs(crs.FingerprintClassSQLi))
	}
	if fired[crs.FingerprintClassXSS] && xssRows == 0 {
		return fmt.Sprintf("XSS carrier rules fired without fingerprint evidence: %v fired, want >= 1 xss-class row, got 0",
			carrierIDs(crs.FingerprintClassXSS))
	}
	sqli = uniqueSortedStrings(sqli)
	if wantSQLi == "" {
		if len(sqli) > 0 {
			return fmt.Sprintf("sqli fingerprint class fired on a no-pin row: %v", sqli)
		}
	} else {
		if len(sqli) != 1 || sqli[0] != wantSQLi {
			return fmt.Sprintf("sqli fingerprint: want %q, reference %v", wantSQLi, sqli)
		}
	}
	if wantXSS {
		if xss == 0 {
			return "xss fingerprint class: want the class, reference carries none"
		}
	} else if xss > 0 {
		return fmt.Sprintf("xss fingerprint class fired on a no-pin row: %d rows", xss)
	}
	return ""
}

// noiseIDs are the setup/echo ids pinned as engine-mirror noise (README
// delta table): the crs-setup SecAction echo (900000), the scoring
// threshold SecAction (900110) and the setup-version echo (900990).
var noiseIDs = map[int]bool{900000: true, 900110: true, 900990: true}

func isNoiseID(id int) bool { return noiseIDs[id] }

func hasID(ms []crs.Match, id int) bool {
	for _, m := range ms {
		if m.RuleID == id {
			return true
		}
	}
	return false
}

// equalSets compares two int sets order-free (both already unique-sorted
// by the callers; defensive re-sort here).
func equalSets(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// setDiff returns (in-a-not-b, in-b-not-a).
func setDiff(a, b []int) (onlyA, onlyB []int) {
	inB := map[int]bool{}
	for _, v := range b {
		inB[v] = true
	}
	for _, v := range a {
		if !inB[v] {
			onlyA = append(onlyA, v)
		}
	}
	inA := map[int]bool{}
	for _, v := range a {
		inA[v] = true
	}
	for _, v := range b {
		if !inA[v] {
			onlyB = append(onlyB, v)
		}
	}
	return
}

// uniqueSortedStrings sorts and de-duplicates a string slice (the
// fingerprint-class comparisons diff distinct values positionally).
func uniqueSortedStrings(in []string) []string {
	src := make([]string, len(in))
	copy(src, in)
	sort.Strings(src)
	out := make([]string, 0, len(src))
	for i, v := range src {
		if i == 0 || v != src[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// uniqueSorted sorts and de-duplicates an int slice. Callers diff the
// result positionally (equalSets), so SORT FIRST: a stable merge of a
// duplicate into a non-adjacent position would otherwise survive as a
// phantom member and report a parity delta where the sets agree.
func uniqueSorted(in []int) []int {
	src := make([]int, len(in))
	copy(src, in)
	sort.Ints(src)
	out := make([]int, 0, len(src))
	for i, v := range src {
		if i == 0 || v != src[i-1] {
			out = append(out, v)
		}
	}
	return out
}
