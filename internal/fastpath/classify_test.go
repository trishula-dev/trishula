package fastpath

// The suite runs kernel-free on the host (no linux build tag, no attach gate):
// the census classes and the field classifier are pure Go. The design record
// owns the row set: docs/design/socket-plane/4-compiler-census.md.

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/api/v1alpha1"
)

// specLeafPaths walks the CRD spec tree of api/v1alpha1 and returns every
// census path in the record's form: the JSON tree of WAFPolicySpec, with "[]"
// marking rule-set items ("spec.ruleSets[].name"). The walk keeps leaf
// primitives only, so a new surface field that skips the census fails here.
func specLeafPaths(t *testing.T) []string {
	t.Helper()
	var walk func(prefix string, ty reflect.Type) []string
	walk = func(prefix string, ty reflect.Type) []string {
		var out []string
		for _, f := range reflect.VisibleFields(ty) {
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			path := prefix + name
			ft := f.Type
			for ft.Kind() == reflect.Ptr || ft.Kind() == reflect.Slice {
				if ft.Kind() == reflect.Slice {
					path = path + "[]"
				}
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				out = append(out, walk(path+".", ft)...)
				continue
			}
			out = append(out, path)
		}
		sort.Strings(out)
		return out
	}
	return walk("spec.", reflect.TypeOf(v1alpha1.WAFPolicySpec{}))
}

// TestCensusMatchesSpecSurface pins the census row set to the CRD surface:
// every spec leaf of api/v1alpha1 carries a census row, and every row names a
// real spec field or one of the two stamped metadata fields. A missing row
// lets a new field compile outside the record; a stale row forges one.
func TestCensusMatchesSpecSurface(t *testing.T) {
	specRows := map[string]bool{}
	for _, path := range specLeafPaths(t) {
		if _, ok := fieldCensus[path]; !ok {
			t.Errorf("spec field %q sits on the CRD surface with no census row", path)
		}
		specRows[path] = true
	}
	wantControl := map[string]bool{"metadata.name": true, "metadata.namespace": true}
	for field := range fieldCensus {
		if !specRows[field] && !wantControl[field] {
			t.Errorf("census row %q matches no CRD spec field", field)
		}
	}
}

// TestClassifyV0SlowPathAllFields pins the honesty zero of the record: at the
// tracked v0 surface, every classified field routes to the slow path and no
// field carries the kernel verdict. The classifier test is the executable
// form of the record's census statement.
func TestClassifyV0SlowPathAllFields(t *testing.T) {
	rows := CensusRows()
	if len(rows) == 0 {
		t.Fatal("the census carries 0 rows")
	}
	for _, row := range rows {
		class, err := Classify(row.Field)
		if err != nil {
			t.Errorf("Classify(%q): %v", row.Field, err)
			continue
		}
		if class != row.Class {
			t.Errorf("Classify(%q) = %q, the census row carries %q", row.Field, class, row.Class)
		}
		if class.KernelEligible() {
			t.Errorf("v0 field %q classifies into kernel-eligible class %q — no v0 field sits in the §9.9 subset", row.Field, class)
		}
		if class.Verdict() == VerdictKernel {
			t.Errorf("v0 field %q carries the kernel verdict %q — the tracked surface compiles no field to the kernel path", row.Field, VerdictKernel)
		}
	}
}

// TestClassifyUnknownFailsClosed pins the fail-closed rule: a field outside
// the census never silently routes to the slow path, and an empty path is
// not a field.
func TestClassifyUnknownFailsClosed(t *testing.T) {
	for _, field := range []string{"spec.requestBodyInspection", "spec.jwt.issuer", "", "metadata"} {
		class, err := Classify(field)
		if !errors.Is(err, ErrUnknownField) {
			t.Errorf("Classify(%q) err = %v, want ErrUnknownField", field, err)
		}
		if class != "" {
			t.Errorf("Classify(%q) class = %q, want the empty class on failure", field, class)
		}
	}
}

// TestClassSetEligibilityAndGate pins the class semantics: the five subset
// classes of §9.9 sit kernel-eligible and ClassSlowPath sits outside, and the
// JWT hash/encode gate stays locked at the tracked evaluation (the
// kernel-module record: docs/design/socket-plane/1-mechanism.md).
func TestClassSetEligibilityAndGate(t *testing.T) {
	rows := []struct {
		class        Class
		wantEligible bool
		wantGate     GateState
	}{
		{ClassJWTAuthz, true, GateLocked},
		{ClassRBACAllowlist, true, GateOpen},
		{ClassRoute, true, GateOpen},
		{ClassTelemetry, true, GateOpen},
		{ClassHeaderMutation, true, GateOpen},
		{ClassSlowPath, false, GateOpen},
	}
	for _, row := range rows {
		if got := row.class.KernelEligible(); got != row.wantEligible {
			t.Errorf("Class(%q).KernelEligible() = %v, want %v", row.class, got, row.wantEligible)
		}
		if got := row.class.Gate(); got != row.wantGate {
			t.Errorf("Class(%q).Gate() = %q, want %q", row.class, got, row.wantGate)
		}
	}
}

// TestClassVerdictSplit pins the split vocabulary: outside the subset routes
// to the slow path, an open gate compiles to the kernel path, a locked gate
// reports gate-locked. The compile-split surface (the record's §5) records
// these values per field, never a wholesale enforced claim.
func TestClassVerdictSplit(t *testing.T) {
	rows := []struct {
		class Class
		want  Verdict
	}{
		{ClassJWTAuthz, VerdictGateLocked},
		{ClassRBACAllowlist, VerdictKernel},
		{ClassRoute, VerdictKernel},
		{ClassTelemetry, VerdictKernel},
		{ClassHeaderMutation, VerdictKernel},
		{ClassSlowPath, VerdictSlowPath},
	}
	for _, row := range rows {
		if got := row.class.Verdict(); got != row.want {
			t.Errorf("Class(%q).Verdict() = %q, want %q", row.class, got, row.want)
		}
	}
}
