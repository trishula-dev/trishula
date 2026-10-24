//go:build linux

package routee2e

// TR-40b (issue #188, child of TR-40 #52): the route-class end-to-end load
// proof. The test runs the full compile pathway under root on a Linux
// kernel: WAFPolicy → operator.Compile → bundle → routetemplate.Instantiate
// → a verifier-accepted load of the one route-mark program, then the split
// read-back from the stamped policy object.
//
// The kernel gate mirrors the residue posture (test/residue-e2e): root on
// Linux, BTF present. No netns and no attach ride this proof — the gate is
// the verifier load, not traffic. ROUTE_E2E_REQUIRED=1 (the CI step)
// turns every environment skip into a failure: a job that cannot run the
// load never reads as green.
//
//	sudo env PATH="$PATH" HOME="$HOME" ROUTE_E2E_REQUIRED=1 \
//	  go test -tags route_e2e -v ./test/route-e2e/
//
// The census record carries the boundary: docs/design/socket-plane/
// 4-compiler-census.md. No enforcement claim rides the split.

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"

	v1alpha1 "github.com/trishula-dev/trishula/api/v1alpha1"
	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	"github.com/trishula-dev/trishula/internal/fastpath/routetemplate"
	"github.com/trishula-dev/trishula/internal/operator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// routeKey mirrors the template's LPM key: 4 + 64 bytes, no padding.
type routeKey struct {
	Prefixlen uint32
	Prefix    [64]byte
}

// routeVal mirrors the template's route value: action + pad + id = 8 bytes.
type routeVal struct {
	Action uint8
	_      [3]byte
	ID     uint32
}

// mustKernel gates the kernel facilities. ROUTE_E2E_REQUIRED=1 turns every
// skip into a failure, so the CI gate never reads green vacuously.
func mustKernel(t *testing.T) {
	t.Helper()
	required := os.Getenv("ROUTE_E2E_REQUIRED") != ""
	if os.Geteuid() != 0 {
		if required {
			t.Fatal("ROUTE_E2E_REQUIRED: the load proof needs root")
		}
		t.Skip("route load proof needs root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		if required {
			t.Fatalf("ROUTE_E2E_REQUIRED: no BTF at /sys/kernel/btf/vmlinux: %v", err)
		}
		t.Skip("no BTF at /sys/kernel/btf/vmlinux")
	}
}

// routeClassPolicy is the e2e fixture: one forward class over the chat
// route, one drop class over the admin route, rule sets absent.
func routeClassPolicy() v1alpha1.WAFPolicy {
	return v1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "route-class", Namespace: "ai-platform"},
		Spec: v1alpha1.WAFPolicySpec{
			DefaultAction: v1alpha1.DefaultActionBlock,
			ModeFlags:     v1alpha1.PolicyModeFlags{Inline: true, Shield: true},
			Routes: []v1alpha1.RouteMark{
				{Prefix: "/v1/chat", Action: v1alpha1.RouteActionForward},
				{Prefix: "/v1/admin", Action: v1alpha1.RouteActionDrop},
			},
		},
	}
}

// wantSplitJSON is the exact annotation value for the fixture policy
// (encoding/json sorts map keys): 5 slow-path rows and 2 kernel rows.
const wantSplitJSON = `{"metadata.name":"slow-path","metadata.namespace":"slow-path",` +
	`"spec.defaultAction":"slow-path","spec.modeFlags.inline":"slow-path",` +
	`"spec.modeFlags.shield":"slow-path","spec.routes[].action":"kernel",` +
	`"spec.routes[].prefix":"kernel"}`

// TestRouteClassLoadProofE2E runs the compile pathway end to end:
// compile the route class, load the template through the verifier, then
// read the compile-split back from the stamped policy object.
func TestRouteClassLoadProofE2E(t *testing.T) {
	mustKernel(t)

	policy := routeClassPolicy()
	bundle, err := operator.Compile(policy)
	if err != nil {
		t.Fatalf("Compile(route class): %v", err)
	}
	if _, err := operator.Load(bundle); err != nil {
		t.Fatalf("Load(bundle): %v", err)
	}

	coll, err := routetemplate.Instantiate(&bundle)
	if err != nil {
		t.Fatalf("Instantiate(route template): %v", err)
	}
	defer coll.Close()

	// The one program loaded through the verifier, the TC plane.
	prog, ok := coll.Programs["route_mark"]
	if !ok || prog == nil {
		t.Fatalf("the loaded collection misses route_mark: %v", coll.Programs)
	}
	info, err := prog.Info()
	if err != nil {
		t.Fatalf("route_mark.Info(): %v", err)
	}
	if info.Type != ebpf.SchedCLS {
		t.Errorf("route_mark type = %v, want SchedCLS", info.Type)
	}

	// The bundle's routes staged into the template map: 2 rows, and the
	// admin row carries the drop code.
	m := coll.Maps["route_marks"]
	if m == nil {
		t.Fatalf("the loaded collection misses route_marks: %v", coll.Maps)
	}
	rows := map[string]routeVal{}
	var k routeKey
	var v routeVal
	it := m.Iterate()
	for it.Next(&k, &v) {
		rows[string(k.Prefix[:k.Prefixlen/8])] = v
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate route_marks: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("route_marks carries %d rows, want 2: %v", len(rows), rows)
	}
	if got := rows["/v1/admin"].Action; got != fastpath.RouteTemplateActionDrop {
		t.Errorf("route_marks[/v1/admin].Action = %d, want %d", got, fastpath.RouteTemplateActionDrop)
	}
	if got := rows["/v1/chat"].Action; got != fastpath.RouteTemplateActionForward {
		t.Errorf("route_marks[/v1/chat].Action = %d, want %d", got, fastpath.RouteTemplateActionForward)
	}

	// The split reads back per bundle: the annotation is the exact sorted
	// JSON of the compile-split map.
	stamped := routeClassPolicy()
	if err := operator.StampCompileSplit(&stamped, &bundle); err != nil {
		t.Fatalf("StampCompileSplit: %v", err)
	}
	if got := stamped.Annotations[operator.CompileSplitAnnotation]; got != wantSplitJSON {
		t.Errorf("annotation = %s, want %s", got, wantSplitJSON)
	}

	// The round-trip completes the summary after the verifier stage.
	if err := operator.StampFastPathRoundTrip(&stamped, fastpath.ReasonCompiled,
		"verifier accepted the route-mark template with 2 staged rows"); err != nil {
		t.Fatalf("StampFastPathRoundTrip: %v", err)
	}
	if len(stamped.Status.Conditions) != 1 {
		t.Fatalf("status carries %d conditions, want the FastPathCompiled summary", len(stamped.Status.Conditions))
	}
	cond := stamped.Status.Conditions[0]
	if cond.Type != operator.FastPathCompiledCondition ||
		cond.Status != metav1.ConditionTrue ||
		cond.Reason != fastpath.ReasonCompiled.String() {
		t.Errorf("condition = %q/%q/%q, want FastPathCompiled/True/Compiled", cond.Type, cond.Reason, cond.Status)
	}
}
