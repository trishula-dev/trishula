package operator

// The stamp suite pins the compile-split write path (the census record's
// split section): the compile stage stamps kernel-free provable reasons
// only, and the round-trip stage stamps the verifier-proved reasons. The
// write rides the policy object the operator already holds.

import (
	"testing"

	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// splitBundle builds the two stamp fixtures: a kernel-leg bundle (route
// class compiled, split map on board) and a no-kernel-leg bundle whose
// only honest summary is NoKernelFields.
func splitBundle(t *testing.T, withKernel bool) *Bundle {
	t.Helper()
	if withKernel {
		bundle, err := Compile(routeClassPolicy())
		if err != nil {
			t.Fatalf("Compile route policy: %v", err)
		}
		return &bundle
	}
	bundle, err := Compile(fixturePolicy())
	if err != nil {
		t.Fatalf("Compile plain policy: %v", err)
	}
	return &bundle
}

// TestStampCompileSplit pins the compile stage: the per-field annotation
// carries the bundle's split map as JSON on every compiled policy, and the
// summary condition appears only when the reason is provable kernel-free
// (NoKernelFields). A pending kernel leg reads no condition: the verifier
// proof owns it.
func TestStampCompileSplit(t *testing.T) {
	rows := []struct {
		name          string
		withKernel    bool
		wantCondition bool
		wantReason    fastpath.Reason
	}{
		{name: "kernel leg pending", withKernel: true, wantCondition: false},
		{name: "no kernel fields", withKernel: false, wantCondition: true, wantReason: fastpath.ReasonNoKernelFields},
	}
	for _, row := range rows {
		policy := routeClassPolicy()
		policy.Name = "split-check"
		bundle := splitBundle(t, row.withKernel)
		if err := StampCompileSplit(&policy, bundle); err != nil {
			t.Fatalf("%s: StampCompileSplit: %v", row.name, err)
		}
		want, err := compileSplitJSON(bundle.Split)
		if err != nil {
			t.Fatalf("%s: split JSON: %v", row.name, err)
		}
		if got := policy.Annotations[CompileSplitAnnotation]; got != want {
			t.Errorf("%s: annotation = %q, want %q", row.name, got, want)
		}
		conds := policy.Status.Conditions
		if !row.wantCondition {
			if len(conds) != 0 {
				t.Errorf("%s: status carries %d conditions, want none before the verifier proof", row.name, len(conds))
			}
			continue
		}
		if len(conds) != 1 {
			t.Fatalf("%s: status carries %d conditions, want the NoKernelFields summary", row.name, len(conds))
		}
		cond := conds[0]
		if cond.Type != FastPathCompiledCondition {
			t.Errorf("%s: condition type = %q, want %q", row.name, cond.Type, FastPathCompiledCondition)
		}
		if cond.Status != metav1.ConditionFalse {
			t.Errorf("%s: condition status = %q, want False", row.name, cond.Status)
		}
		if cond.Reason != row.wantReason.String() {
			t.Errorf("%s: condition reason = %q, want %q", row.name, cond.Reason, row.wantReason)
		}
	}
}

// TestStampFastPathRoundTrip pins the round-trip stage: a verifier-proved
// reason lands as the summary condition, a failed load lands as its own
// reason, and a compile-stage reason is refused — the stages never borrow
// each other's verdicts.
func TestStampFastPathRoundTrip(t *testing.T) {
	rows := []struct {
		name       string
		reason     fastpath.Reason
		wantStatus metav1.ConditionStatus
		wantErr    bool
	}{
		{name: "verifier accepted", reason: fastpath.ReasonCompiled, wantStatus: metav1.ConditionTrue},
		{name: "verifier rejected", reason: fastpath.ReasonVerifierRejected, wantStatus: metav1.ConditionFalse},
		{name: "compile-stage reason refused", reason: fastpath.ReasonNoKernelFields, wantErr: true},
	}
	for _, row := range rows {
		policy := routeClassPolicy()
		err := StampFastPathRoundTrip(&policy, row.reason, "evidence text")
		if row.wantErr {
			if err == nil {
				t.Errorf("%s: StampFastPathRoundTrip accepted a compile-stage reason", row.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: StampFastPathRoundTrip: %v", row.name, err)
		}
		if len(policy.Status.Conditions) != 1 {
			t.Fatalf("%s: status carries %d conditions, want 1", row.name, len(policy.Status.Conditions))
		}
		cond := policy.Status.Conditions[0]
		if cond.Type != FastPathCompiledCondition || cond.Reason != row.reason.String() || cond.Status != row.wantStatus {
			t.Errorf("%s: condition = %q/%q/%q, want %q/%s/%q", row.name, cond.Type, cond.Reason, cond.Status, FastPathCompiledCondition, row.wantStatus, row.reason)
		}
	}
}
