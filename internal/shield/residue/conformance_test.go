package residue

// TR-35a conformance (issue #167): uninstall leaves zero kernel objects in
// the shield's census. The suite runs kernel-free. A simulated kernel state
// stands in for bpftool, and the sweeps read through the injected
// KernelRead. The simulation records the kernel behavior the TC attach path
// showed in TR-04d (issue #69): a clsact filter out-lives its loader and
// holds its program; the program holds its maps.
//
// The live kernel job (TR-35b, issue #168) binds real kernel handles and
// repeats the same assert after a real teardown.

import (
	"errors"
	"fmt"
	"testing"
)

func simScope() Scope {
	return Scope{
		BPFFSRoot: "/sys/fs/bpf/trishula",
		Programs:  []string{"shield_xdp", "tc_ingress_waf", "ban_xdp"},
		Maps: []string{
			"ban_table", "verdict_cache", "acl4",
			"events", "lost_events", "flow_stats", "probe_stats",
			"bans_v4", "ban_stats",
		},
		Ifaces: []string{"eth0"},
	}
}

// simObj is one object in the simulated kernel state.
type simObj struct {
	Object
	owner string // maps: the owning program; programs: ""
	pin   string // non-empty: pinned at this BPFFS path
	tcRef bool   // a TC filter references (keeps alive) this program
	xdp   bool   // an attached XDP link references this program
	coll  bool   // lives in the loader collection (fd closes on Close)
}

type simKernel struct {
	progs []*simObj
	maps  []*simObj
	links []*simObj
	pins  []*simObj
	tc    map[string][]*simObj
}

func newSimKernel() *simKernel { return &simKernel{tc: map[string][]*simObj{}} }

func (s *simKernel) prog(id string) *simObj {
	o := &simObj{Object: Object{Class: ClassProgram, ID: id}}
	s.progs = append(s.progs, o)
	return o
}
func (s *simKernel) mp(id, owner string) *simObj {
	o := &simObj{Object: Object{Class: ClassMap, ID: id}, owner: owner}
	s.maps = append(s.maps, o)
	return o
}
func (s *simKernel) pin(path string) *simObj {
	o := &simObj{Object: Object{Class: ClassPin, ID: path}}
	s.pins = append(s.pins, o)
	return o
}
func (s *simKernel) filter(iface, dir, progID string) *simObj {
	o := &simObj{Object: Object{Class: ClassTCFilter, ID: progID,
		Where: fmt.Sprintf("%s:%s", iface, dir)}}
	s.tc[iface] = append(s.tc[iface], o)
	return o
}

func (s *simKernel) ListPrograms() ([]Object, error) {
	out := make([]Object, 0, len(s.progs))
	for _, p := range s.progs {
		out = append(out, p.Object)
	}
	return out, nil
}

func (s *simKernel) ListMaps() ([]Object, error) {
	out := make([]Object, 0, len(s.maps))
	for _, m := range s.maps {
		out = append(out, m.Object)
	}
	return out, nil
}

func (s *simKernel) ListLinks() ([]Object, error) {
	out := make([]Object, 0, len(s.links))
	for _, l := range s.links {
		out = append(out, l.Object)
	}
	return out, nil
}

func (s *simKernel) ListPins(root string) ([]Object, error) {
	out := make([]Object, 0, len(s.pins))
	for _, p := range s.pins {
		out = append(out, p.Object)
	}
	return out, nil
}

func (s *simKernel) ListTCFilters(iface string) ([]Object, error) {
	out := make([]Object, 0, len(s.tc[iface]))
	for _, f := range s.tc[iface] {
		out = append(out, f.Object)
	}
	return out, nil
}

// drop removes o from its store.
func dropObj(store *[]*simObj, o *simObj) {
	out := (*store)[:0]
	for _, c := range *store {
		if c != o {
			out = append(out, c)
		}
	}
	*store = out
}

// install seeds the full production attach state on eth0: the XDP leg
// (shield_xdp + 3 maps + the attach link, unpinned) and the TC leg
// (tc_ingress_waf pinned under the subtree + 5 maps + ingress/egress
// filters). It returns the XDP link and the pinned program.
func (s *simKernel) install() (xdpLink, flow *simObj) {
	shield := s.prog("shield_xdp")
	shield.coll, shield.xdp = true, true
	for _, id := range []string{"ban_table", "verdict_cache", "acl4"} {
		s.mp(id, "shield_xdp").owner = shield.ID
	}
	l := &simObj{Object: Object{Class: ClassLink, ID: "shield_xdp", Where: "eth0"}}
	s.links = append(s.links, l)

	flow = s.prog("tc_ingress_waf")
	flow.pin = "/sys/fs/bpf/trishula/tc_ingress_waf"
	for _, id := range []string{"ban_table", "events", "lost_events", "flow_stats", "probe_stats"} {
		s.mp(id, "tc_ingress_waf").owner = flow.ID
	}
	s.pin(flow.pin)
	s.filter("eth0", "ingress", flow.ID)
	s.filter("eth0", "egress", flow.ID)
	flow.tcRef = true
	return l, flow
}

// closeOnlyTeardown models the current uninstall surface: Loader.Close()
// plus the attach harness's pin-file remove. What the kernels records:
//
//   - the link close detaches the XDP hook; the unpinned shield program
//     and its maps lose the last reference
//   - the collection close frees no pinned object
//   - nothing removes the TC clsact filters; each filter holds its
//     program, and the program holds its maps
//   - the pin file went; the BPFFS subtree holds no file (a directory is
//     not a census class)
func (s *simKernel) closeOnlyTeardown() {
	for _, l := range s.links {
		dropObj(&s.links, l)
	}
	for _, p := range append([]*simObj{}, s.progs...) {
		alive := p.pin != "" || p.tcRef || (p.xdp && false)
		if p.coll && !alive {
			dropObj(&s.progs, p)
		}
	}
	for _, m := range append([]*simObj{}, s.maps...) {
		if owner(s, m.owner) == nil &&
			m.pin == "" {
			dropObj(&s.maps, m)
		}
	}
	for _, p := range append([]*simObj{}, s.pins...) {
		dropObj(&s.pins, p)
	}
}

// owner returns the named program still alive in the state.
func owner(s *simKernel, id string) *simObj {
	for _, p := range s.progs {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func mustClean(t *testing.T, st *simKernel, sc Scope) {
	t.Helper()
	r, err := Census(st, sc)
	if err != nil {
		t.Fatalf("census: %v", err)
	}
	if !r.Clean() {
		t.Fatalf("uninstall left kernel residue: %s", r)
	}
}

// TestCensusCountsInstalledClasses pins the census inventory over the
// installed state: 2 programs, 8 maps, 1 link, 1 pin, 2 TC filters.
func TestCensusCountsInstalledClasses(t *testing.T) {
	st := newSimKernel()
	st.install()
	sc := simScope()
	r, err := Census(st, sc)
	if err != nil {
		t.Fatalf("census: %v", err)
	}
	want := map[Class]int{
		ClassMap: 8, ClassProgram: 2, ClassLink: 1,
		ClassPin: 1, ClassTCFilter: 2,
	}
	if len(r.Counts) != len(want) {
		t.Fatalf("census classes = %v, want every class counted %v", r.Counts, want)
	}
	for c, n := range want {
		if r.Counts[c] != n {
			t.Fatalf("census %s = %d, want %d (full report: %s)", c, r.Counts[c], n, r)
		}
	}
}

// TestCensusIgnoresForeignObjects: a foreign program, map, pin and TC
// filter never count as shield residue. The gate must not fail on them.
func TestCensusIgnoresForeignObjects(t *testing.T) {
	st := newSimKernel()
	st.install()
	st.prog("node_exporter_probe")
	st.mp("node_exporter_state", "node_exporter_probe").owner = "node_exporter_probe"
	st.pin("/sys/fs/bpf/node_exporter/xdp_probe")
	st.pin("/sys/fs/bpf/trishula-evil/tc_agent") // shares the root prefix, stays foreign
	st.filter("eth0", "ingress", "node_exporter_probe")
	st.filter("eth1", "egress", "tc_ingress_waf") // unmanaged iface stays foreign
	r, err := Census(st, simScope())
	if err != nil {
		t.Fatalf("census: %v", err)
	}
	if got := r.Counts; got[ClassMap] != 8 || got[ClassProgram] != 2 ||
		got[ClassPin] != 1 || got[ClassTCFilter] != 2 || got[ClassLink] != 1 {
		t.Fatalf("foreign objects leaked into the census: %s", r)
	}
}

// TestScopePinBoundary: the pin subtree boundary is exact.
func TestScopePinBoundary(t *testing.T) {
	sc := simScope()
	if !sc.Owned(Object{Class: ClassPin, ID: "/sys/fs/bpf/trishula/tc_ingress_waf"}) {
		t.Fatal("the subtree root's own pin must be owned")
	}
	if !sc.Owned(Object{Class: ClassPin, ID: "/sys/fs/bpf/trishula/prog/ban"}) {
		t.Fatal("a pin deep in the subtree must be owned")
	}
	for _, p := range []string{
		"/sys/fs/bpf/trishula",                // the root itself is not an object
		"/sys/fs/bpf/trishula-evil/tc_agent",  // prefix share without the boundary
		"/sys/fs/bpf/trishulaevil/x",          // same
		"/sys/fs/bpf/node_exporter/xdp_probe", // a foreign subtree
	} {
		if sc.Owned(Object{Class: ClassPin, ID: p}) {
			t.Fatalf("pin %q must stay foreign", p)
		}
	}
}

// TestCensusFailsClosed: a source that cannot read is unknown residue.
// The census refuses a clean verdict.
func TestCensusFailsClosed(t *testing.T) {
	st := newSimKernel()
	st.install()
	fail := &failingSource{KernelRead: st, failOn: "maps"}
	if _, err := Census(fail, simScope()); err == nil {
		t.Fatal("a failing source must fail the census (unknown ≠ zero)")
	}
}

type failingSource struct {
	KernelRead
	failOn string
}

func (f *failingSource) ListMaps() ([]Object, error) {
	return nil, errors.New("bpftool map show: exit 1")
}

// TestUninstallConformance: the uninstall contract. After the uninstall
// path runs, the census reads zero owned objects on every class. The
// current teardown surface is Loader.Close() — the TC filters stay (the
// RED state); the uninstall sweep (TR-35a GREEN) removes per-hook state
// and the BPFFS subtree, and the same assert reads zero.
func TestUninstallConformance(t *testing.T) {
	st := newSimKernel()
	st.install()
	st.closeOnlyTeardown()
	mustClean(t, st, simScope())
}
