package botdef

import (
	"slices"

	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// Family is the spec's detector family a verdict belongs to. Consensus is
// counted over FAMILIES: a family contributes when any of its detectors
// clears the confidence floor (the spec's consensus rule: two or more families
// triggers action).
type Family string

const (
	// FamilyTLS is the JA4/JA4S handshake plane, matched at the
	// termination hop (the spec's detector families).
	FamilyTLS Family = "tls"
	// FamilyHeaders is the header-plane fingerprint family (the spec's detector families).
	FamilyHeaders Family = "headers"
	// FamilyBehavioral is the behavioral family: per-source sliding
	// windows over request pacing, auth-failure ratios and endpoint
	// uniqueness (the spec's detector families; scoring runs in userspace).
	FamilyBehavioral Family = "behavioral"
)

// DetectorVerdict is the spec's per-detector emission:
// (detector_id, confidence, evidence_ref). A detector never emits a bare
// boolean — the confidence carries strength, the evidence ref carries the
// observed value the confidence stands on.
type DetectorVerdict struct {
	ID         ladder.RuleID // detector id; doubles as the ladder rule id
	Family     Family        // the detector family this detector belongs to
	Confidence uint8         // 0-100; below the floor = prior, not detection
	Evidence   string        // evidence ref (the observed value or ratio)
}

// MergePolicy is the spec's merge rule, configurable per WAFPolicy (the CR
// wiring arrives with the operator slice; v1 injects the policy).
type MergePolicy struct {
	// MinFamilies is the consensus threshold over DISTINCT families.
	// The effective floor is 2: a single family never triggers (the spec's consensus rule —
	// a single-detector match logs and scores).
	MinFamilies int
	// ConsensusAction is the action consensus resolves (the spec's verdict integration: v1 ships
	// challenge as a verdict action). A non-decisive value keeps the
	// merged fragment on the log tier (the off switch for the policy).
	ConsensusAction ladder.Action
	// ConfidenceFloor: verdicts below it score no consensus. The floor
	// keeps priors out of the count (the spec's honest-limits note: JA4 alone is a cost raiser,
	// never identity).
	ConfidenceFloor uint8
}

// DefaultMergePolicy returns the spec's consensus posture: a consensus of two
// families challenges; a single family logs and scores.
func DefaultMergePolicy() MergePolicy {
	return MergePolicy{
		MinFamilies:     2,
		ConsensusAction: ladder.ActionChallenge,
		ConfidenceFloor: 50,
	}
}

// Merge folds the spec's per-detector verdicts into the resolved S5 action:
// MinFamilies DISTINCT families at or above the confidence floor trigger
// ConsensusAction when decisive; every other shape keeps the log tier. It
// returns the resolved action plus the contributing family set, sorted
// (the lab render and the conformance tests read it back).
func Merge(vs []DetectorVerdict, p MergePolicy) (ladder.Action, []Family) {
	want := p.MinFamilies
	if want < 2 {
		want = 2 // the spec's consensus floor: a single family never triggers
	}
	seen := make(map[Family]struct{}, 3)
	fams := make([]Family, 0, 3)
	for _, dv := range vs {
		if dv.Confidence < p.ConfidenceFloor {
			continue // below the floor: a prior, not a detection
		}
		if _, ok := seen[dv.Family]; !ok {
			seen[dv.Family] = struct{}{}
			fams = append(fams, dv.Family)
		}
	}
	slices.Sort(fams)
	if len(fams) >= want && p.ConsensusAction.Decisive() {
		return p.ConsensusAction, fams
	}
	return ladder.ActionLog, fams
}
