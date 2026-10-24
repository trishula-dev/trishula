package fastpath

// The split suite runs kernel-free on the host: the split is pure
// classification over present census fields. The split surface carries
// dispositions, never enforcement (the census record's split section).

import (
	"reflect"
	"testing"

	v1alpha1 "github.com/trishula-dev/trishula/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// routeClassPolicy is the fixture policy with the route class present: two
// prefixes, one forward class, one drop class. Rule sets stay absent.
func routeClassPolicy() v1alpha1.WAFPolicy {
	return v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "route-class", Namespace: "ai-platform"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionBlock,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shield: true},
			CELBudget:     5,
			Routes: []v1alpha1.RouteMark{
				{Prefix: "/v1/chat", Action: v1alpha1.RouteActionForward},
				{Prefix: "/admin", Action: v1alpha1.RouteActionDrop},
			},
		},
	}
}

// TestPolicySplitSplitsPresentFields pins the split over presence: one pair
// per classified present field, no pair for an absent field. Two rows: a
// policy carrying the route class (the route rows carry the kernel
// verdict; every other present row stays slow-path) and a policy without it
// (no kernel verdict anywhere — the NoKernelFields zero of the surface).
func TestPolicySplitSplitsPresentFields(t *testing.T) {
	rows := []struct {
		name   string
		policy v1alpha1.WAFPolicy
		want   map[string]Verdict
	}{
		{
			name:   "route-class policy",
			policy: routeClassPolicy(),
			want: map[string]Verdict{
				"spec.celBudget":        VerdictSlowPath,
				"spec.defaultAction":    VerdictSlowPath,
				"spec.modeFlags.inline": VerdictSlowPath,
				"spec.modeFlags.shield": VerdictSlowPath,
				"spec.routes[].prefix":  VerdictKernel,
				"spec.routes[].action":  VerdictKernel,
				"metadata.name":         VerdictSlowPath,
				"metadata.namespace":    VerdictSlowPath,
			},
		},
		{
			name: "no-routes policy",
			policy: v1alpha1.WAFPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "lab"},
				Spec: v1alpha1.WAFPolicySpec{
					DefaultAction: v1alpha1.DefaultActionLog,
					ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true},
				},
			},
			want: map[string]Verdict{
				"spec.defaultAction":    VerdictSlowPath,
				"spec.modeFlags.inline": VerdictSlowPath,
				"metadata.name":         VerdictSlowPath,
				"metadata.namespace":    VerdictSlowPath,
			},
		},
	}
	for _, row := range rows {
		got := PolicySplit(row.policy).Fields
		if !reflect.DeepEqual(got, row.want) {
			t.Errorf("%s: PolicySplit.Fields = %v, want %v", row.name, got, row.want)
		}
	}
}

// TestPolicySplitEmptyPolicyCarriesNothing pins the zero policy: nothing
// present, nothing split. An empty name and namespace carry no pairs, and
// an empty route list carries no kernel claim.
func TestPolicySplitEmptyPolicyCarriesNothing(t *testing.T) {
	split := PolicySplit(v1alpha1.WAFPolicy{})
	if len(split.Fields) != 0 {
		t.Errorf("PolicySplit on the zero policy carries %d pairs, want 0", len(split.Fields))
	}
}
