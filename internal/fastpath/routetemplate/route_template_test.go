package routetemplate

// The template suite is kernel-free: it pins the template contract at the
// C source (bounds, one program, no tail calls) and at the staged rows.
// The load proof runs as the tagged e2e on a Linux kernel (test/route-e2e).

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/trishula-dev/trishula/internal/fastpath"
	"github.com/trishula-dev/trishula/internal/operator"
)

// TestRouteTemplateContract pins the template contract at the C source
// (the census record's template contract): under 70 source lines, one
// program, no tail calls, bounded maps, compile-time bounds, and the
// compile-staged placeholders. The shield_contract freeze holds: this file
// is a sibling program, never an edit of shield_xdp.c.
func TestRouteTemplateContract(t *testing.T) {
	src, err := os.ReadFile("../../../bpf/route_mark.c")
	if err != nil {
		t.Fatalf("read the route template: %v", err)
	}
	text := string(src)
	if loc := countLoC(text); loc >= 70 {
		t.Errorf("the route template carries %d source lines, want under 70 (the template contract bound)", loc)
	}
	if strings.Contains(text, "bpf_tail_call") {
		t.Error("the route template references bpf_tail_call; v1 carries no tail calls")
	}
	if got := strings.Count(text, `SEC("tc")`); got != 1 {
		t.Errorf("the route template declares %d tc programs, want 1 (one program envelope)", got)
	}
	for _, want := range []string{
		"route_marks",
		"BPF_MAP_TYPE_LPM_TRIE",
		"BPF_F_NO_PREALLOC",
		"volatile const",
		"route_cfg",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the route template misses %q", want)
		}
	}
}

// countLoC counts the source lines: comment runs (/*...*/ and //) and
// blank lines stay out; every other line counts.
func countLoC(src string) int {
	clean := stripBlockComments(src)
	n := 0
	for _, line := range strings.Split(clean, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		n++
	}
	return n
}

// stripBlockComments removes /*...*/ spans so line counting reads code.
func stripBlockComments(src string) string {
	var b strings.Builder
	for {
		open := strings.Index(src, "/*")
		if open < 0 {
			b.WriteString(src)
			return b.String()
		}
		b.WriteString(src[:open])
		close1 := strings.Index(src[open+2:], "*/")
		if close1 < 0 {
			return b.String()
		}
		src = src[open+2+close1+2:]
	}
}

// stageBundle builds a bundle fastpath leg by hand (no compile here).
func stageBundle(rows []operator.FastPathRoute) *operator.Bundle {
	return &operator.Bundle{FastPath: &operator.FastPathValues{Routes: rows}}
}

// TestRouteTemplateStagesBundleLeg pins the kernel-free staging: the
// bundle's kernel leg turns into bounded LPM rows in policy order, and
// every contract violation fails closed with the offending cell named.
func TestRouteTemplateStagesBundleLeg(t *testing.T) {
	rows := []struct {
		name     string
		bundle   *operator.Bundle
		wantErr  string
		checkErr bool
		check    func(t *testing.T, stages []RouteStage)
	}{
		{
			name:    "no kernel leg",
			bundle:  &operator.Bundle{},
			wantErr: ErrNoKernelLeg.Error(),
		},
		{
			name: "two valid rows",
			bundle: stageBundle([]operator.FastPathRoute{
				{Prefix: "/v1/chat", Action: fastpath.RouteTemplateActionForward},
				{Prefix: "/v1/admin", Action: fastpath.RouteTemplateActionDrop},
			}),
			check: func(t *testing.T, stages []RouteStage) {
				if len(stages) != 2 {
					t.Fatalf("Stage rows = %d, want 2", len(stages))
				}
				if stages[0].PrefixLenBits != 8*8 || string(stages[0].Prefix[:8]) != "/v1/chat" || stages[0].Action != 0 || stages[0].ID != 0 {
					t.Errorf("row 0 = %+v, want /v1/chat 64 bits forward id 0", stages[0])
				}
				if stages[1].PrefixLenBits != 9*8 || string(stages[1].Prefix[:9]) != "/v1/admin" || stages[1].Action != 1 || stages[1].ID != 1 {
					t.Errorf("row 1 = %+v, want /v1/admin 72 bits drop id 1", stages[1])
				}
				for _, s := range stages {
					for _, b := range s.Prefix[int(s.PrefixLenBits/8):] {
						if b != 0 {
							t.Fatalf("row prefix bytes stay zero-filled past the prefix: %+v", s)
						}
					}
				}
			},
		},
		{
			name:    "65-byte prefix",
			bundle:  stageBundle([]operator.FastPathRoute{{Prefix: strings.Repeat("a", fastpath.RouteTemplatePrefixMaxBytes+1), Action: 0}}),
			wantErr: "spec.routes[0].prefix",
		},
		{
			name:    "unknown action code",
			bundle:  stageBundle([]operator.FastPathRoute{{Prefix: "/admin", Action: 7}}),
			wantErr: "spec.routes[0].action",
		},
		{
			name: "nine rows",
			bundle: stageBundle([]operator.FastPathRoute{
				{Prefix: "/1", Action: 0}, {Prefix: "/2", Action: 0}, {Prefix: "/3", Action: 0}, {Prefix: "/4", Action: 0},
				{Prefix: "/5", Action: 0}, {Prefix: "/6", Action: 0}, {Prefix: "/7", Action: 0}, {Prefix: "/8", Action: 0},
				{Prefix: "/9", Action: 0},
			}),
			wantErr: "9 rows",
		},
		{
			name: "duplicate prefix",
			bundle: stageBundle([]operator.FastPathRoute{
				{Prefix: "/api", Action: 0}, {Prefix: "/api", Action: 1},
			}),
			wantErr: "spec.routes[1].prefix",
		},
	}
	for _, row := range rows {
		stages, err := Stage(row.bundle)
		if row.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), row.wantErr) {
				t.Errorf("%s: Stage err = %v, want it to name %q", row.name, err, row.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: Stage: %v", row.name, err)
		}
		row.check(t, stages)
	}
}

// TestRouteTemplateObjectContract pins the committed object at the spec
// (kernel-free: the spec never touches the kernel): one TC program inside
// the envelope constant, the compile-staged placeholder, and the bounded
// route map. The Go mirrors carry the wire sizes the e2e reads. The
// envelope assertion is the contract formalization: Instantiate runs the
// same fastpath.AssertEnvelope call on every verifier load.
func TestRouteTemplateObjectContract(t *testing.T) {
	spec, err := loadRoute_mark()
	if err != nil {
		t.Fatalf("load committed route template object: %v", err)
	}
	if err := fastpath.AssertEnvelope(spec); err != nil {
		t.Fatalf("AssertEnvelope(committed route template): %v", err)
	}
	if len(spec.Programs) != 1 {
		t.Fatalf("the object carries %d programs, want 1 (one program envelope)", len(spec.Programs))
	}
	prog, ok := spec.Programs["route_mark"]
	if !ok || prog == nil {
		t.Fatalf("the object misses the route_mark program: %v", spec.Programs)
	}
	if prog.Type != ebpf.SchedCLS {
		t.Errorf("route_mark type = %v, want SchedCLS", prog.Type)
	}
	if got := len(prog.Instructions); got > fastpath.RouteEnvelopeInstructions {
		t.Errorf("route_mark carries %d instructions past the %d-instruction envelope", got, fastpath.RouteEnvelopeInstructions)
	}
	if spec.Variables["route_cfg"] == nil {
		t.Error("the object misses the route_cfg placeholder")
	}
	m, ok := spec.Maps["route_marks"]
	if !ok || m == nil {
		t.Fatalf("the object misses route_marks: %v", spec.Maps)
	}
	if m.Type != ebpf.LPMTrie {
		t.Errorf("route_marks type = %v, want LPMtrie", m.Type)
	}
	if m.MaxEntries != uint32(fastpath.RouteTemplateMaxEntries) {
		t.Errorf("route_marks max_entries = %d, want %d", m.MaxEntries, fastpath.RouteTemplateMaxEntries)
	}
	if m.Flags != 1 { // BPF_F_NO_PREALLOC
		t.Errorf("route_marks flags = %d, want 1 (BPF_F_NO_PREALLOC)", m.Flags)
	}
	if reflect.TypeOf(route_markRouteKey{}).Size() != 68 {
		t.Errorf("route key mirror size = %d, want 68 (4 + 64)", reflect.TypeOf(route_markRouteKey{}).Size())
	}
	if reflect.TypeOf(route_markRouteVal{}).Size() != 8 {
		t.Errorf("route value mirror size = %d, want 8", reflect.TypeOf(route_markRouteVal{}).Size())
	}
	if spec.Maps["route_marks"].KeySize != 68 || spec.Maps["route_marks"].ValueSize != 8 {
		t.Errorf("route map key/value sizes = %d/%d, want 68/8", spec.Maps["route_marks"].KeySize, spec.Maps["route_marks"].ValueSize)
	}
}

// TestInstantiateFailsKernelFree pins the instantiate surface's negative
// rows: every rejection fires before the kernel, and the error names the
// offending cell. The kernel load path carries its own proof in the route
// gate (test/route-e2e).
func TestInstantiateFailsKernelFree(t *testing.T) {
	nine := []operator.FastPathRoute{
		{Prefix: "/a", Action: fastpath.RouteTemplateActionForward},
		{Prefix: "/b", Action: fastpath.RouteTemplateActionForward},
		{Prefix: "/c", Action: fastpath.RouteTemplateActionForward},
		{Prefix: "/d", Action: fastpath.RouteTemplateActionForward},
		{Prefix: "/e", Action: fastpath.RouteTemplateActionDrop},
		{Prefix: "/f", Action: fastpath.RouteTemplateActionDrop},
		{Prefix: "/g", Action: fastpath.RouteTemplateActionDrop},
		{Prefix: "/h", Action: fastpath.RouteTemplateActionDrop},
		{Prefix: "/i", Action: fastpath.RouteTemplateActionDrop},
	}
	rows := []struct {
		name    string
		bundle  *operator.Bundle
		wantErr string
	}{
		{name: "nil bundle", bundle: nil, wantErr: ErrNoKernelLeg.Error()},
		{name: "no kernel leg", bundle: &operator.Bundle{}, wantErr: ErrNoKernelLeg.Error()},
		{
			name:    "nine-route leg past the row bound",
			bundle:  stageBundle(nine),
			wantErr: "spec.routes carries 9 rows; the template bound is 8 rows",
		},
	}
	for _, row := range rows {
		coll, err := Instantiate(row.bundle)
		if err == nil {
			if coll != nil {
				coll.Close()
			}
			t.Errorf("%s: Instantiate succeeded, want a named failure", row.name)
			continue
		}
		if coll != nil {
			coll.Close()
			t.Errorf("%s: Instantiate returned a collection on the failure path", row.name)
		}
		if !strings.Contains(err.Error(), row.wantErr) {
			t.Errorf("%s: Instantiate err = %v, want it to name %q", row.name, err, row.wantErr)
			continue
		}
		if strings.Contains(err.Error(), "verifier") {
			t.Errorf("%s: the failure names the verifier; the bound rejects kernel-free, before the load", row.name)
		}
	}
}
