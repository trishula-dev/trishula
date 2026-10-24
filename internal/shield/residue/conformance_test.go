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
	tcRef bool   // a live TC filter references (keeps alive) this program
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
// filters).
func (s *simKernel) install() {
	s.prog("shield_xdp")
	for _, id := range []string{"ban_table", "verdict_cache", "acl4"} {
		s.mp(id, "shield_xdp").owner = "shield_xdp"
	}
	l := &simObj{Object: Object{Class: ClassLink, ID: "shield_xdp", Where: "eth0"}}
	s.links = append(s.links, l)

	flow := s.prog("tc_ingress_waf")
	flow.pin = "/sys/fs/bpf/trishula/tc_ingress_waf"
	for _, id := range []string{"ban_table", "events", "lost_events", "flow_stats", "probe_stats"} {
		s.mp(id, "tc_ingress_waf").owner = flow.ID
	}
	s.pin(flow.pin)
	s.filter("eth0", "ingress", flow.ID)
	s.filter("eth0", "egress", flow.ID)
	flow.tcRef = true
}

// hasPin reports a live pin object at path.
func (s *simKernel) hasPin(path string) bool {
	for _, p := range s.pins {
		if p.ID == path {
			return true
		}
	}
	return false
}

// hasLinkTo reports a live link that references prog.
func (s *simKernel) hasLinkTo(prog string) bool {
	for _, l := range s.links {
		if l.ID == prog {
			return true
		}
	}
	return false
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

// dropUnreferenced applies the kernel refcount rule: a program survives
// while a pin, a TC filter or a link holds it; a map survives while its
// program holds it.
func (s *simKernel) dropUnreferenced() {
	sc := simScope()
	for _, p := range append([]*simObj{}, s.progs...) {
		if s.hasPin(p.pin) || p.tcRef || s.hasLinkTo(p.ID) {
			continue
		}
		if !sc.hasProgram(p.ID) {
			continue // foreign programs stay out of the sim's kernel drops
		}
		dropObj(&s.progs, p)
	}
	for _, m := range append([]*simObj{}, s.maps...) {
		if owner(s, m.owner) == nil && sc.hasMap(m.ID) {
			dropObj(&s.maps, m)
		}
	}
}

// closeOnlyTeardown models the current uninstall surface: Loader.Close()
// plus the attach harness's pin-file remove. What the kernel records:
//
//   - the link close detaches the XDP hook; the unpinned shield program
//     and its maps lose the last reference
//   - the collection close frees no pinned object
//   - nothing removes the TC clsact filters; each filter holds its
//     program, and the program holds its maps
//   - the pin file went; the BPFFS subtree holds no file (a directory is
//     not a census class)
func (s *simKernel) closeOnlyTeardown() {
	for _, l := range append([]*simObj{}, s.links...) {
		dropObj(&s.links, l)
	}
	for _, p := range append([]*simObj{}, s.pins...) {
		dropObj(&s.pins, p)
	}
	s.dropUnreferenced()
}

// ownsProg reports the program in the shield scope (the sim's
// teardown-effect rule: the sweep touches only shield-scoped state).
func ownsProg(id string) bool { return simScope().hasProgram(id) }

// ownsFilterTC reports an owned TC filter. A filter that references a
// scoped program or pins under the BPFFS root is the shield's filter.
func ownsFilterTC(sc Scope, f *simObj) bool {
	return sc.hasIface(f.Where) && (sc.hasProgram(f.ID) || sc.underRoot(f.ID))
}

// --- Uninstaller (the sim implementation of the teardown effects) -------

// DetachXDP removes the XDP leg: the attach link, then the referenced
// program and its maps that lose the last reference.
func (s *simKernel) DetachXDP(iface string) error {
	for _, l := range append([]*simObj{}, s.links...) {
		dropObj(&s.links, l)
	}
	s.dropUnreferenced()
	return nil
}

// DeleteTCFilters removes the shield's TC filters on iface. A foreign
// filter (a program outside the scope or a pin outside the root) stays.
func (s *simKernel) DeleteTCFilters(iface string) error {
	sc := simScope()
	kept := s.tc[iface][:0]
	for _, f := range s.tc[iface] {
		if !ownsFilterTC(sc, f) {
			kept = append(kept, f)
		}
	}
	s.tc[iface] = kept
	s.refreshTcRefs()
	s.dropUnreferenced()
	return nil
}

// refreshTcRefs recomputes the live tcRef flags from the filters present.
func (s *simKernel) refreshTcRefs() {
	sc := simScope()
	for _, p := range s.progs {
		p.tcRef = false
		for _, fs := range s.tc {
			for _, f := range fs {
				if f.ID == p.ID && ownsFilterTC(sc, f) {
					p.tcRef = true
				}
			}
		}
	}
}

// SweepPins deletes the pinned files under root. Files outside the root
// stay (foreign state); the root itself stays.
func (s *simKernel) SweepPins(root string) error {
	sc := simScope()
	for _, p := range append([]*simObj{}, s.pins...) {
		if sc.underRoot(p.ID) {
			dropObj(&s.pins, p)
		}
	}
	s.dropUnreferenced()
	return nil
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

// TestCensusCatchesCloseOnlyResidue: the census catches what the CURRENT
// teardown surface leaves (Loader.Close plus the pin-file remove). This is
// the RED row from the watched-RED run: one program, two TC filters, five
// maps stay alive on the managed interface. It stays as the regression row
// that proves the census still reads that residue.
func TestCensusCatchesCloseOnlyResidue(t *testing.T) {
	st := newSimKernel()
	st.install()
	st.closeOnlyTeardown()
	r, err := Census(st, simScope())
	if err != nil {
		t.Fatalf("census: %v", err)
	}
	want := map[Class]int{
		ClassMap: 5, ClassProgram: 1, ClassTCFilter: 2,
	}
	for c, n := range want {
		if r.Counts[c] != n {
			t.Fatalf("census %s = %d, want %d (full report: %s)", c, r.Counts[c], n, r)
		}
	}
	if r.Clean() {
		t.Fatal("close-only residue vanished from the census — the simulation drifted")
	}
}

// TestUninstallConformance: the uninstall contract. The teardown order
// (spec §16.4) runs over the managed interface: per-hook detach, TC filter
// removal, the BPFFS subtree sweep — then the census reads zero.
func TestUninstallConformance(t *testing.T) {
	st := newSimKernel()
	st.install()
	r, err := Uninstall(st, st, simScope())
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !r.Clean() {
		t.Fatalf("uninstall left kernel residue: %s", r)
	}
}

// TestUninstallKeepsForeignObjects: the sweep touches shield-scoped state
// only. A foreign pin and a foreign filter keep running after uninstall,
// and the census still reads clean.
func TestUninstallKeepsForeignObjects(t *testing.T) {
	st := newSimKernel()
	st.install()
	foreignPin := st.pin("/sys/fs/bpf/node_exporter/xdp_probe")
	foreignFilter := st.filter("eth0", "ingress", "node_exporter_probe")
	r, err := Uninstall(st, st, simScope())
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !r.Clean() {
		t.Fatalf("uninstall left kernel residue: %s", r)
	}
	if !st.hasPin(foreignPin.ID) {
		t.Fatal("the uninstall swept a foreign pin")
	}
	found := false
	for _, f := range st.tc["eth0"] {
		if f == foreignFilter {
			found = true
		}
	}
	if !found {
		t.Fatal("the uninstall removed a foreign TC filter")
	}
}

// TestUninstallIdempotent: a second uninstall over clean state stays clean.
func TestUninstallIdempotent(t *testing.T) {
	st := newSimKernel()
	st.install()
	if _, err := Uninstall(st, st, simScope()); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	r, err := Uninstall(st, st, simScope())
	if err != nil {
		t.Fatalf("second uninstall: %v", err)
	}
	if !r.Clean() {
		t.Fatalf("second uninstall left kernel residue: %s", r)
	}
}

// TestUninstallFailsClosed: an effect that fails stops the uninstall and
// reaches the caller; the census never prints a clean verdict.
func TestUninstallFailsClosed(t *testing.T) {
	st := newSimKernel()
	st.install()
	fail := &failingUninstaller{Uninstaller: st, failOn: "sweep"}
	if _, err := Uninstall(st, fail, simScope()); err == nil {
		t.Fatal("a failing teardown effect must fail the uninstall")
	}
}

type failingUninstaller struct {
	Uninstaller
	failOn string
}

func (f *failingUninstaller) SweepPins(root string) error {
	return errors.New("bpffs sweep: exit 1")
}
