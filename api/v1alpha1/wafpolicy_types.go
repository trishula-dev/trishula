// Package v1alpha1 holds the trishula.security/v1alpha1 API types: the v0
// CRD surface compiling into operator bundles and kernel maps. TR-08a
// carries the minimal WAFPolicy only; the remaining CRDs of the spec's CRD set (APISpec,
// RuleSet, BanPolicy, MLModel) arrive with later TR-08 slices.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DefaultAction is the default verdict for a route class when no rule set
// fires (the spec's WAFPolicy CRD). The values are the reference-implementation WAFPolicy sketch's
// vocabulary: block | challenge | log | pass.
//
// +kubebuilder:validation:Enum=block;challenge;log;pass
type DefaultAction string

const (
	// DefaultActionBlock stops the request (decisive, the spec's first-decisive precedence rule).
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
	// CRSProfilePL2 is the reference profile (the spec's benchmark-plan mix).
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

// RouteAction is the kernel-path verdict one route class carries (the
// part-1 action primitives: forward, drop; the census record's class
// `route` carries one action per prefix).
//
// +kubebuilder:validation:Enum=forward;drop
type RouteAction string

const (
	// RouteActionForward marks the class pass-through. The template writes
	// the mark and forwards (the contract's default forward).
	RouteActionForward RouteAction = "forward"
	// RouteActionDrop marks the class kernel-dropped; the template writes
	// TC_ACT_SHOT on a hit.
	RouteActionDrop RouteAction = "drop"
)

// RouteMark selects one HTTP path-prefix class and the kernel-path action
// it carries (TR-40b: the route class lands on the surface; everything
// outside the listed prefixes routes to the slow path).
type RouteMark struct {
	// Prefix is the request path the class matches (byte prefix; printable
	// ASCII; the compile re-gates the bounds the kernel template carries).
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[\x20-\x7E]+$`
	Prefix string `json:"prefix"`
	// Action is the kernel-path verdict for the class.
	//
	// +kubebuilder:validation:Enum=forward;drop
	Action RouteAction `json:"action"`
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
	// CELBudget is the evaluation cost budget (the spec's CEL DSL plus goal G4) the compile
	// applies to every CEL rule this policy compiles that does not declare
	// its own (the rule pack's per-rule costBudget is the more specific
	// declaration and wins). 0 = unset = the engine's package default.
	//
	// +optional
	// +kubebuilder:validation:Minimum=0
	CELBudget uint64 `json:"celBudget,omitempty"`
	// ModeFlags select the enforcement planes (inline, shield, shadow).
	ModeFlags PolicyModeFlags `json:"modeFlags"`
	// Routes list the path-prefix classes the compile marks on the kernel
	// path (TR-40b, the census class `route`). Every request path outside
	// the listed prefixes carries the default forward, and every field
	// outside this list routes to the slow path (the compile-split record).
	//
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Routes []RouteMark `json:"routes,omitempty"`
}

// WAFPolicyStatus carries the compile-split honesty surface (the census
// record's split section): the summary condition over the per-field split.
// The per-field values ride the metadata annotation; conditions live here.
type WAFPolicyStatus struct {
	// Conditions carry the FastPathCompiled summary condition (Gateway API
	// condition vocabulary). The condition is a summary; it never
	// substitutes for the per-field split.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// WAFPolicy is the v0 CRD binding rule sets, the default action and the
// mode flags to a route class (the spec's CRD set). The route-selector
// fields (spec.routes) land with TR-40b; further failure semantics arrive
// with later TR-08 slices.
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
	// Status is the compile-split surface; the compile-to-load round-trip
	// stamps it (TR-40b). No CRD version bump rides this field: the status
	// subresource predates it.
	// +optional
	Status WAFPolicyStatus `json:"status,omitempty"`
}

// WAFPolicyList is a list of WAFPolicy objects.
//
// +kubebuilder:object:root=true
type WAFPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WAFPolicy `json:"items"`
}
