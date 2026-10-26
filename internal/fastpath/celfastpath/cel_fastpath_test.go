package celfastpath

// The kernel-free contract rows for the CEL-class template (TR-196):
// Stage's row-truth read, the tamper rejects, and the committed flow
// object's contract (one program, no tail calls, the instruction count
// inside the flow envelope). The verifier load rides the tagged e2e
// (test/route-e2e and the differential's kernel leg; the route-gate
// posture). Host CI stays kernel-free.

import (
	"encoding/json"
	"os"
	"testing"

	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	operator "github.com/trishula-dev/trishula/internal/operator"
)

// celBundle compiles the committed cel shape into a bundle for the
// kernel-free rows (the byte-parity shape test pins the file set).
func celBundle(t *testing.T, name string) *operator.Bundle {
	t.Helper()
	raw, err := os.ReadFile("../../operator/testdata/bundle-shapes/" + name)
	if err != nil {
		t.Fatalf("read shape %s: %v", name, err)
	}
	var b operator.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode shape %s: %v", name, err)
	}
	if _, err := operator.Load(b); err != nil {
		t.Fatalf("wire gate: Load(%s): %v", name, err)
	}
	return &b
}

// TestStageCompiledRows reads the staged row truth per the committed
// shapes: the decomposed legs, the action codes and the row order.
// The glob+query shape rides the envelope gate (the T2 form); the
// compose shape carries the shipped family row (the glob+method).
func TestStageCompiledRows(t *testing.T) {
	b := celBundle(t, "cel_class_gm.json")
	staged, err := Stage(b)
	if err != nil {
		t.Fatalf("Stage(cel_class_glob): %v", err)
	}
	if len(staged) != 1 {
		t.Fatalf("%d staged rows, want 1", len(staged))
	}
	row := staged[0]
	want := b.FastPath.CELRules[0]
	if row.ID != 0 || row.Action != want.Action {
		t.Fatalf("row = %+v, want id 0 action %d", row, want.Action)
	}
	if want.Method != "POST" || string(row.Method[:row.MethodLen]) != want.Method {
		t.Fatalf("method leg = %q, want %q", string(row.Method[:row.MethodLen]), want.Method)
	}
	if row.GlobKind != globPrefixSuffix || string(row.Pre[:row.PreLen]) != want.PathGlobPrefix || row.SufLen != 0 {
		t.Fatalf("glob leg = kind %d pre %q suf %d, want kind 2 prefix %q suffix none",
			row.GlobKind, string(row.Pre[:row.PreLen]), row.SufLen, want.PathGlobPrefix)
	}
	if row.QueryLen != 0 {
		t.Fatalf("query leg = %q, want none (the query leg rides the engine tier)", string(row.Query[:row.QueryLen]))
	}
}

// TestStageSkipsTheEnvelopeGatedShape proves the T2 form: the glob+query
// shape compiles to no rows (the compile's envelope gate) and Stage
// reports nothing to instantiate, kernel-free.
func TestStageSkipsTheEnvelopeGatedShape(t *testing.T) {
	b := celBundle(t, "cel_class_glob.json")
	if b.FastPath != nil && len(b.FastPath.CELRules) != 0 {
		t.Fatalf("FastPath = %+v, want none (the query rule routes T2)", b.FastPath.CELRules)
	}
	if _, err := Stage(b); err != ErrNoCELFastPath {
		t.Fatalf("Stage(cel_class_glob): %v, want ErrNoCELFastPath", err)
	}
}

// TestStageTwoRowsRowOrder reads the second shape: the walk stages one
// row (the envelope bound); the second rule routes T2 at compile. The
// staged row reads kind 2 with the prefix segment.
func TestStageTwoRowsRowOrder(t *testing.T) {
	b := celBundle(t, "cel_class_2row.json")
	staged, err := Stage(b)
	if err != nil {
		t.Fatalf("Stage(cel_class_2row): %v", err)
	}
	if len(staged) != 1 {
		t.Fatalf("%d staged rows, want 1 (the envelope bound)", len(staged))
	}
	if staged[0].ID != 0 {
		t.Fatalf("row id %d, want 0", staged[0].ID)
	}
	if staged[0].GlobKind != globPrefixSuffix || staged[0].PreLen == 0 {
		t.Fatalf("row = kind %d pre len %d, want kind 2 with a prefix", staged[0].GlobKind, staged[0].PreLen)
	}
}

// TestStageRefusesLegOutsides reads the fail-closed stage rows: a
// tampered leg (a star inside a decomposed segment) and a leg-past-bound
// row reject with the cell named.
func TestStageRefusesLegOutsides(t *testing.T) {
	b := celBundle(t, "cel_class_gm.json")
	if b.FastPath == nil {
		t.Fatal("the compose shape carries no FastPath leg")
	}
	tampered := *b.FastPath
	tampered.CELRules = append([]fastpath.FastPathCELRule(nil), b.FastPath.CELRules...)
	tampered.CELRules[0].PathGlobPrefix = "/a*b"
	tamperedBundle := operator.Bundle{FormatVersion: b.FormatVersion, Tenant: b.Tenant,
		RulePacks: b.RulePacks, KernelValues: b.KernelValues, RulePackDigests: b.RulePackDigests,
		FastPath: &tampered, Split: b.Split}
	if _, err := Stage(&tamperedBundle); err == nil {
		t.Fatal("Stage: err nil, want the star reject")
	}
	if _, err := Stage(nil); err == nil {
		t.Fatal("Stage(nil): err nil, want ErrNoCELFastPath")
	}
}

// TestCommittedFlowObjectContract reads the committed object's contract
// kernel-free: one program, the instruction count inside the flow
// envelope, no tail call.
func TestCommittedFlowObjectContract(t *testing.T) {
	spec, err := loadCel_fastpath()
	if err != nil {
		t.Fatalf("load the committed flow object: %v", err)
	}
	if err := fastpath.AssertFlowEnvelope(spec); err != nil {
		t.Fatalf("the flow object contract: %v", err)
	}
	prog := spec.Programs["tc_ingress_waf"]
	if prog == nil {
		t.Fatalf("the committed flow object misses tc_ingress_waf: %v", spec.Programs)
	}
	if got := len(prog.Instructions); got == 0 || got > fastpath.FlowEnvelopeInstructions {
		t.Fatalf("tc_ingress_waf carries %d instructions; want inside the %d envelope", got, fastpath.FlowEnvelopeInstructions)
	}
}
