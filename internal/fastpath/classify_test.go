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
			t.Errorf("v0 field %q classifies into kernel-eligible class %q — no v0 field sits in the kernel-offloadable subset", row.Field, class)
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

// TestCensusRouteRows pins the TR-40b census growth: the route-marking
// fields land on the surface, they carry the route class with an open
// gate, and the census carries exactly 12 rows. The record's growth rule
// governs: a class takes its row when its field lands, and the coverage
// test walks the tree against the row set.
func TestCensusRouteRows(t *testing.T) {
	rows := []struct {
		field     string
		wantClass Class
		wantGate  GateState
		wantV     Verdict
	}{
		{"spec.routes[].prefix", ClassRoute, GateOpen, VerdictKernel},
		{"spec.routes[].action", ClassRoute, GateOpen, VerdictKernel},
	}
	for _, row := range rows {
		class, err := Classify(row.field)
		if err != nil {
			t.Errorf("Classify(%q): %v", row.field, err)
			continue
		}
		if class != row.wantClass {
			t.Errorf("Classify(%q) = %q, want %q", row.field, class, row.wantClass)
		}
		if class.Gate() != row.wantGate {
			t.Errorf("Classify(%q).Gate() = %q, want %q", row.field, class.Gate(), row.wantGate)
		}
		if class.Verdict() != row.wantV {
			t.Errorf("Classify(%q).Verdict() = %q, want %q", row.field, class.Verdict(), row.wantV)
		}
	}
	if got, want := len(CensusRows()), 12; got != want {
		t.Errorf("CensusRows() carries %d rows, want %d (10 classified + 2 route rows)", got, want)
	}
}

// TestClassSetEligibilityAndGate pins the class semantics: the five subset
// classes of the spec's fast-path section sit kernel-eligible, ClassSlowPath
// sits outside, and the JWT hash/encode gate stays locked at the tracked
// evaluation (the kernel-module record:
// docs/design/socket-plane/1-mechanism.md).
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
// reports gate-locked. The compile-split surface (the record's split section)
// records these values per field, never a wholesale enforced claim.
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
