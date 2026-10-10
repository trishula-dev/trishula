// Package v1alpha1 holds the trishula.security/v1alpha1 API types: the v0
// CRD surface compiling into operator bundles and kernel maps. TR-08a
// carries the minimal WAFPolicy only; the remaining §16.2 CRDs (APISpec,
// RuleSet, BanPolicy, MLModel) arrive with later TR-08 slices.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DefaultAction is the default verdict for a route class when no rule set
// fires (§16.2 WAFPolicy). The values are the §19.1 WAFPolicy sketch's
// vocabulary: block | challenge | log | pass.
//
// +kubebuilder:validation:Enum=block;challenge;log;pass
type DefaultAction string

const (
	// DefaultActionBlock stops the request (decisive, §2.3).
	DefaultActionBlock DefaultAction = "block"
	// DefaultActionChallenge responds with the challenge flow.
	DefaultActionChallenge DefaultAction = "challenge"
	// DefaultActionLog records the verdict without enforcement.
	DefaultActionLog DefaultAction = "log"
	// DefaultActionPass forwards without a recorded verdict.
	DefaultActionPass DefaultAction = "pass"
)

// CRSProfile is the CRS paranoia level of a RuleSet source.
//
// +kubebuilder:validation:Enum=PL1;PL2;PL3
type CRSProfile string

const (
	// CRSProfilePL1 is the low-noise paranoia level.
	CRSProfilePL1 CRSProfile = "PL1"
	// CRSProfilePL2 is the reference profile (§17.2 benchmark mix).
	CRSProfilePL2 CRSProfile = "PL2"
	// CRSProfilePL3 is the strict paranoia level.
	CRSProfilePL3 CRSProfile = "PL3"
)

// PolicyModeFlags selects the enforcement planes a policy reaches (shadow
// runs the ladder verdict-only; promotion is a separate gate).
type PolicyModeFlags struct {
	// Inline steers the route class through the engine deep-inspection path.
	// +optional
	Inline bool `json:"inline,omitempty"`
	// Shield attaches the route class to the kernel fast path (ban/verdict
	// caches).
	// +optional
	Shield bool `json:"shield,omitempty"`
	// Shadow evaluates verdict-only; no enforcement.
	// +optional
	Shadow bool `json:"shadow,omitempty"`
}

// RuleSetSource describes where a rule set's definitions come from. The v0
// surface carries the CRS reference (custom rules arrive with TR-08b/c).
type RuleSetSource struct {
	// CRSVersion pins the OWASP CRS train the bundle resolves against.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	CRSVersion string `json:"crsVersion"`
	// Profile is the CRS paranoia level.
	//
	// +kubebuilder:validation:Enum=PL1;PL2;PL3
	Profile CRSProfile `json:"profile"`
}

// RuleSetRef binds one rule set into the policy. The compile resolves the
// ref against the cluster's RuleSet state (compile→load round trip lands
// with TR-08b).
type RuleSetRef struct {
	// Name is the referenced rule set (bundle name in the CR namespace).
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// Source declares the rule set's upstream.
	Source RuleSetSource `json:"source"`
}

// WAFPolicySpec is the desired policy state for a route class.
type WAFPolicySpec struct {
	// RuleSets lists the rule sets the policy compiles into its bundle.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	RuleSets []RuleSetRef `json:"ruleSets,omitempty"`
	// DefaultAction is the verdict applied when no rule set fires.
	//
	// +kubebuilder:validation:Enum=block;challenge;log;pass
	DefaultAction DefaultAction `json:"defaultAction"`
	// ModeFlags select the enforcement planes (inline, shield, shadow).
	ModeFlags PolicyModeFlags `json:"modeFlags"`
}

// WAFPolicy is the v0 CRD binding rule sets, the default action and the
// mode flags to a route class (PRD §16.2). Route selectors and failure
// semantics arrive with later TR-08 slices.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Default Action",type=string,JSONPath=`.spec.defaultAction`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type WAFPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WAFPolicySpec `json:"spec"`
}

// WAFPolicyList is a list of WAFPolicy objects.
//
// +kubebuilder:object:root=true
type WAFPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WAFPolicy `json:"items"`
}
