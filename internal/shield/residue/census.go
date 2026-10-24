package residue

// Package residue is the TR-35a kernel-residue census (spec [§21 M7] and
// [§16.4]). The uninstall contract: zero kernel objects after teardown.
//
// The census reads these object classes: pinned maps, programs, links,
// BPFFS pins, TC filters on managed interfaces. An object counts when the
// scope owns it; foreign host objects stay out of the record.
//
// The census reads the kernel through the injected KernelRead handles. The
// teardown effects ride the injected Uninstaller. The conformance suite
// runs kernel-free over a simulated teardown state, so the host CI suite
// runs it without a kernel. The live kernel job (TR-35b, issue #168) binds
// the real kernel handles and asserts the same zero.
//
// [§21 M7]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates
// [§16.4]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#164-lifecycle-of-trishula-in-a-cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Class is one kernel object class the shield owns.
type Class string

// The classes the census records. They follow the M7 row: pinned maps,
// programs, links, BPFFS pins, TC filters on managed interfaces.
const (
	ClassMap      Class = "map"
	ClassProgram  Class = "program"
	ClassLink     Class = "link"
	ClassPin      Class = "pin"
	ClassTCFilter Class = "tc_filter"
)

// String returns the class name.
func (c Class) String() string { return string(c) }

// Object is one kernel object the census records.
//
//	ID carries the object identity: the kernel name for maps, programs and
//	links; the BPFFS path for pins; the program identity for TC filters.
//	Where carries the location: "iface:direction" for TC filters, the
//	attach interface for links, and the empty string for global lists.
type Object struct {
	Class Class
	ID    string
	Where string
}

// Scope selects the objects the shield owns.
//
//	BPFFSRoot is the pinned-object subtree (§16.4: /sys/fs/bpf/trishula/).
//	Programs and Maps list the kernel names the shield installs. Ifaces
//	lists the managed interfaces the shield attaches.
type Scope struct {
	BPFFSRoot string
	Programs  []string
	Maps      []string
	Ifaces    []string
}

// Validate reports a scope that cannot drive a census.
func (s Scope) Validate() error {
	if s.BPFFSRoot == "" {
		return errors.New("residue scope: empty BPFFSRoot")
	}
	if len(s.Programs) == 0 || len(s.Maps) == 0 {
		return errors.New("residue scope: empty program or map inventory")
	}
	return nil
}

func (s Scope) hasProgram(id string) bool {
	for _, p := range s.Programs {
		if id == p {
			return true
		}
	}
	return false
}

func (s Scope) hasMap(id string) bool {
	for _, m := range s.Maps {
		if id == m {
			return true
		}
	}
	return false
}

func (s Scope) hasIface(where string) bool {
	name := where
	if i := strings.IndexByte(where, ':'); i >= 0 {
		name = where[:i]
	}
	for _, in := range s.Ifaces {
		if name == in {
			return true
		}
	}
	return false
}

// underRoot reports path inside the scope root. The boundary is exact:
// "/sys/fs/bpf/trishula-evil" does not sit under "/sys/fs/bpf/trishula",
// and a path that never starts with the root is foreign.
func (s Scope) underRoot(path string) bool {
	root := strings.TrimSuffix(s.BPFFSRoot, "/")
	rest := strings.TrimPrefix(path, root)
	return rest != path && strings.HasPrefix(rest, "/")
}

// Owned reports whether the scope owns the object. A foreign object never
// counts as residue.
func (s Scope) Owned(o Object) bool {
	switch o.Class {
	case ClassMap:
		return s.hasMap(o.ID)
	case ClassProgram:
		return s.hasProgram(o.ID)
	case ClassLink:
		return s.hasProgram(o.ID)
	case ClassPin:
		return s.underRoot(o.ID)
	case ClassTCFilter:
		return s.hasIface(o.Where) && s.hasProgram(o.ID)
	default:
		return false
	}
}

// Report is one census read. Objects carries every owned object; Counts
// carries the per-class totals of that set.
type Report struct {
	Objects []Object
	Counts  map[Class]int
}

// Clean reports zero owned objects (the M7 uninstall contract).
func (r Report) Clean() bool { return len(r.Objects) == 0 }

// String renders the residue record: per-class counts, then each object.
// A clean report reads "residue: zero".
func (r Report) String() string {
	if r.Clean() {
		return "residue: zero"
	}
	classes := make([]string, 0, len(r.Counts))
	for c, n := range r.Counts {
		classes = append(classes, fmt.Sprintf("%d %s", n, c))
	}
	sort.Strings(classes)
	parts := append([]string{"residue:"}, strings.Join(classes, ", "))
	parts = append(parts, "objs:")
	for _, o := range r.Objects {
		parts = append(parts, fmt.Sprintf("%s %q @ %s", o.Class, o.ID, o.Where))
	}
	return strings.Join(parts, " ")
}

// KernelRead is the injected kernel handle set. One list method per class;
// the census holds no kernel code of its own.
//
//	ListPins walks the BPFFS subtree at root. ListTCFilters reads one
//	managed interface. A failing source fails the whole census: an
//	unreadable sweep is unknown residue, never a clean pass.
type KernelRead interface {
	ListPrograms() ([]Object, error)
	ListMaps() ([]Object, error)
	ListLinks() ([]Object, error)
	ListPins(root string) ([]Object, error)
	ListTCFilters(iface string) ([]Object, error)
}

// Census sweeps the kernel through k and returns the owned residue report.
func Census(k KernelRead, sc Scope) (Report, error) {
	if err := sc.Validate(); err != nil {
		return Report{}, err
	}
	if k == nil {
		return Report{}, errors.New("residue census: nil KernelRead")
	}

	r := Report{Counts: map[Class]int{}}
	add := func(o Object) {
		r.Objects = append(r.Objects, o)
		r.Counts[o.Class]++
	}

	progs, err := k.ListPrograms()
	if err != nil {
		return Report{}, fmt.Errorf("residue census: list programs: %w", err)
	}
	for _, o := range progs {
		if o.Class == "" {
			o.Class = ClassProgram
		}
		if sc.Owned(o) {
			add(o)
		}
	}

	maps, err := k.ListMaps()
	if err != nil {
		return Report{}, fmt.Errorf("residue census: list maps: %w", err)
	}
	for _, o := range maps {
		if o.Class == "" {
			o.Class = ClassMap
		}
		if sc.Owned(o) {
			add(o)
		}
	}

	links, err := k.ListLinks()
	if err != nil {
		return Report{}, fmt.Errorf("residue census: list links: %w", err)
	}
	for _, o := range links {
		if o.Class == "" {
			o.Class = ClassLink
		}
		if sc.Owned(o) {
			add(o)
		}
	}

	pins, err := k.ListPins(sc.BPFFSRoot)
	if err != nil {
		return Report{}, fmt.Errorf("residue census: list pins: %w", err)
	}
	for _, o := range pins {
		if o.Class == "" {
			o.Class = ClassPin
		}
		if sc.Owned(o) {
			add(o)
		}
	}

	for _, iface := range sc.Ifaces {
		filters, err := k.ListTCFilters(iface)
		if err != nil {
			return Report{}, fmt.Errorf("residue census: list tc filters: %w", err)
		}
		for _, o := range filters {
			if o.Class == "" {
				o.Class = ClassTCFilter
			}
			if sc.Owned(o) {
				add(o)
			}
		}
	}
	return r, nil
}
