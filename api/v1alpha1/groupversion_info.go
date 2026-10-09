// Package v1alpha1 holds the trishula.security/v1alpha1 API types: the v0
// CRD surface compiling into operator bundles and kernel maps. TR-08a
// carries the minimal WAFPolicy only; the remaining CRDs (APISpec, RuleSet,
// BanPolicy, MLModel) arrive with later TR-08 slices.
//
// +groupName=trishula.security
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the contract API group (PRD: trishula.security is
// contractual for downstream consumers).
const GroupName = "trishula.security"

// GroupVersion is the trishula.security/v1alpha1 wire version.
var GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

// GroupVersionKind of the WAFPolicy CRD.
var GroupVersionKind = GroupVersion.WithKind("WAFPolicy")

// SchemeBuilder registers the v1alpha1 types into a runtime scheme.
var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme adds the trishula.security/v1alpha1 types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&WAFPolicy{},
		&WAFPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
