package operator

// The compile-split write path (the census record's split section): the
// operator stamps the per-field annotation and the summary condition onto
// the policy object it already compiles. No new CRD version and no new
// write plumbing ride this file: the in-object record is the surface, and
// the deployed operator's persist step (TR-08c) reads the same object.
//
// Two-stage honesty rule. The compile stamps kernel-free provable reasons
// only. The round-trip stamps the reasons that need a live verifier stage
// (Compiled, VerifierRejected, EnvelopeExceeded). A bundle never reads as
// loaded before the verifier accepts it, and the surface never reports
// "enforced" — the split vocabulary names dispositions, never enforcement.

import (
	"encoding/json"
	"fmt"

	v1alpha1 "github.com/trishula-dev/trishula/api/v1alpha1"
	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
)

// CompileSplitAnnotation is the per-field compile-split annotation key
// (the census record's split section). The value is the bundle's Split
// map rendered as JSON.
const CompileSplitAnnotation = "trishula.security/compile-split"

// FastPathCompiledCondition is the summary-condition type of the split
// surface (the Gateway API condition vocabulary).
const FastPathCompiledCondition = "FastPathCompiled"

// StampCompileSplit stamps the compile stage of the split onto the policy
// object: the per-field annotation from the bundle's Split map, plus the
// summary condition when the reason is provable kernel-free. A bundle
// whose kernel leg is pending reads no condition yet — the round-trip
// completes the summary after the verifier stage.
//
// STUB (TR-40b RED): a no-op. The watched-RED suite pins the real stamps.
func StampCompileSplit(policy *v1alpha1.WAFPolicy, bundle *Bundle) error {
	return nil
}

// StampFastPathRoundTrip stamps the round-trip stage of the split: the
// verifier-proved summary condition. reason carries one of the
// verifier-proved vocabulary values (Compiled, VerifierRejected,
// EnvelopeExceeded); a compile-stage reason fails the stamp — the compile
// stage never borrows the round-trip's verdict.
//
// STUB (TR-40b RED): a no-op. The watched-RED suite pins the real stamps.
func StampFastPathRoundTrip(policy *v1alpha1.WAFPolicy, reason fastpath.Reason, message string) error {
	return nil
}

// compileSplitJSON renders the bundle's split map as the annotation value
// (encoding/json sorts map keys, so the rendering is deterministic).
func compileSplitJSON(split map[string]string) (string, error) {
	data, err := json.Marshal(split)
	if err != nil {
		return "", fmt.Errorf("compile-split annotation: %w", err)
	}
	return string(data), nil
}
