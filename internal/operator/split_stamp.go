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
	"errors"
	"fmt"

	v1alpha1 "github.com/trishula-dev/trishula/api/v1alpha1"
	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
func StampCompileSplit(policy *v1alpha1.WAFPolicy, bundle *Bundle) error {
	if policy == nil || bundle == nil {
		return errors.New("compile-split stamp: nil policy or bundle")
	}
	if len(bundle.Split) == 0 {
		return errors.New("compile-split stamp: bundle carries no split map (the compile must produce one)")
	}
	value, err := compileSplitJSON(bundle.Split)
	if err != nil {
		return err
	}
	if policy.Annotations == nil {
		policy.Annotations = map[string]string{}
	}
	policy.Annotations[CompileSplitAnnotation] = value
	if bundle.FastPath == nil {
		// Kernel-free provable summary: nothing compiled to the kernel
		// path, and classification alone proves it.
		setFastPathCondition(policy, fastpath.ReasonNoKernelFields,
			"no classified field compiles to the kernel path")
	}
	return nil
}

// StampFastPathRoundTrip stamps the round-trip stage of the split: the
// verifier-proved summary condition. reason carries one of the
// verifier-proved vocabulary values (Compiled, VerifierRejected,
// EnvelopeExceeded); a compile-stage reason fails the stamp — the compile
// stage never borrows the round-trip's verdict.
func StampFastPathRoundTrip(policy *v1alpha1.WAFPolicy, reason fastpath.Reason, message string) error {
	if policy == nil {
		return errors.New("round-trip stamp: nil policy")
	}
	switch reason {
	case fastpath.ReasonCompiled, fastpath.ReasonVerifierRejected, fastpath.ReasonEnvelopeExceeded:
	default:
		return fmt.Errorf("round-trip stamp: reason %q is a compile-stage verdict, not a round-trip one", reason)
	}
	setFastPathCondition(policy, reason, message)
	return nil
}

// setFastPathCondition sets the FastPathCompiled condition by type (one
// row; a later stamp replaces it). The status follows the reason: only
// Compiled reads True.
func setFastPathCondition(policy *v1alpha1.WAFPolicy, reason fastpath.Reason, message string) {
	status := metav1.ConditionFalse
	if reason == fastpath.ReasonCompiled {
		status = metav1.ConditionTrue
	}
	cond := metav1.Condition{
		Type:               FastPathCompiledCondition,
		Status:             status,
		Reason:             reason.String(),
		Message:            message,
		ObservedGeneration: policy.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i := range policy.Status.Conditions {
		if policy.Status.Conditions[i].Type == FastPathCompiledCondition {
			policy.Status.Conditions[i] = cond
			return
		}
	}
	policy.Status.Conditions = append(policy.Status.Conditions, cond)
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
