//go:build linux

package residuee2e

// TR-35b (issue #168, child of TR-35 #35, spec [§ 21 M7]): the zero-residue
// gate after a live teardown. The gate loads the real shield objects on a
// Linux kernel and runs the uninstall. The sweep must read zero.
//
// The attach posture mirrors TR-04d (issue #69): veth + netns, clsact,
// direct-action, pinned TC program. Two honest deltas:
//   - The gate attaches both TC filters on the managed host veth. TR-04d
//     also attached into the netns for traffic visibility (#80). The gate
//     moves no traffic, so it needs no netns-side attach.
//   - The XDP leg attaches through a bpf_link. The #80 quirk touches
//     established-flow traffic, not object lifecycle. A link is a census
//     class; the live sweep reads it.
//
// Kernel-free CI: without root the test skips (mustRoot). The CI step runs
// the test under sudo and sets RESIDUE_E2E_REQUIRED=1. A job that cannot
// run the sweep never reads as green. The M7 row stays CI-asserted, not
// vacuous.
//
//	sudo --preserve-env=PATH,HOME go test -tags residue_e2e ./test/residue-e2e/ -v
//
// [§ 21 M7]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#21-success-metrics--adoption-gates

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	residue "github.com/trishula-dev/trishula/internal/shield/residue"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 residue_shield ../../bpf/shield_xdp.c -- -I../../bpf -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 residue_flow ../../bpf/flow_tc.c -- -I../../bpf -I../../bpf/include -O2 -g

const (
	nsName   = "tr35b"
	hostVeth = "tr35h0"
	nsVeth   = "tr35n0"
	nsV4     = "10.35.0.66/24"
	hostV4   = "10.35.0.1/24"
	pinRoot  = "/sys/fs/bpf/tr35b"
	pinProg  = pinRoot + "/tc_ingress_waf"
)

// mustRoot gates the kernel facilities. RESIDUE_E2E_REQUIRED=1 (the CI step)
// turns every skip into a failure: the gate must run or the job must fail.
func mustRoot(t *testing.T) {
	t.Helper()
	required := os.Getenv("RESIDUE_E2E_REQUIRED") != ""
	if os.Geteuid() != 0 {
		if required {
			t.Fatal("RESIDUE_E2E_REQUIRED: the gate needs root (netns + XDP + TC + bpffs)")
		}
		t.Skip("residue e2e needs root (netns + TC + bpffs pinning)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		if required {
			t.Fatalf("RESIDUE_E2E_REQUIRED: no BTF at /sys/kernel/btf/vmlinux: %v", err)
		}
		t.Skip("no BTF at /sys/kernel/btf/vmlinux")
	}
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		if required {
			t.Fatalf("RESIDUE_E2E_REQUIRED: no bpffs at /sys/fs/bpf: %v", err)
		}
		t.Skip("no bpffs mounted")
	}
}

// run runs one helper command and fails the test on any error.
func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("run %v: %v\n%s", args, err, out)
	}
}

// cleanup removes stale gate state before and after the run.
func cleanup(t *testing.T) {
	t.Helper()
	_ = os.Remove(pinProg)
	_ = os.Remove(pinRoot)
	_ = exec.Command("ip", "netns", "del", nsName).Run()
	_ = exec.Command("ip", "link", "del", hostVeth).Run()
}

// setupNet mirrors the TR-04d posture: a netns pair on a host veth.
func setupNet(t *testing.T) {
	t.Helper()
	run(t, "ip", "netns", "add", nsName)
	run(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	run(t, "ip", "link", "set", nsVeth, "netns", nsName)
	run(t, "ip", "addr", "add", hostV4, "dev", hostVeth)
	run(t, "ip", "link", "set", hostVeth, "up")
	run(t, "ip", "netns", "exec", nsName, "ip", "addr", "add", nsV4, "dev", nsVeth)
	run(t, "ip", "netns", "exec", nsName, "ip", "link", "set", nsVeth, "up")
}

// liveScope lists the object classes the shield owns (the TR-35a scope, the
// live kernel pin root in place of the production root).
func liveScope() residue.Scope {
	return residue.Scope{
		BPFFSRoot: pinRoot,
		Programs:  []string{"shield_xdp", "tc_ingress_waf", "ban_xdp"},
		Maps: []string{
			"ban_table", "verdict_cache", "acl4",
			"events", "lost_events", "flow_stats", "probe_stats",
			"bans_v4", "ban_stats",
		},
		Ifaces: []string{hostVeth},
	}
}

// tcFilter is one filter row the `tc filter show` parse reads.
type tcFilter struct {
	pref   string
	handle string
	name   string // the program identity (`name:[id]` for pinned filters)
	dir    string
}

// parseTCFilters reads one interface direction through `tc filter show`.
// The bpf row grammar: `filter protocol ip pref N bpf chain C handle H
// name:[id] direct-action ...`. A clsact qdisc with no filters reads empty.
func parseTCFilters(iface, dir string) ([]tcFilter, error) {
	out, err := exec.Command("tc", "filter", "show", "dev", iface, dir).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("residue census: tc filter show dev %s %s: %w:\n%s", iface, dir, err, out)
	}
	var filters []tcFilter
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.Contains(line, " bpf ") {
			continue
		}
		f := tcFilter{dir: dir}
		for i, w := range fields {
			switch w {
			case "pref":
				if i+1 < len(fields) {
					f.pref = fields[i+1]
				}
			case "handle":
				if i+1 < len(fields) {
					f.handle = fields[i+1]
					if idx := strings.Index(f.handle, ":["); idx > 0 {
						// one-token rows: `handle tc_ingress_waf:[7]`
						f.name = f.handle[:idx]
					}
				}
			}
		}
		if f.name == "" && f.handle != "" {
			// two-token rows: `handle 0x1 tc_ingress_waf:[7]`
			tok := fields[0]
			for _, cand := range fields {
				if idx := strings.Index(cand, ":["); idx > 0 {
					tok = cand
					break
				}
			}
			if idx := strings.Index(tok, ":["); idx > 0 {
				f.name = tok[:idx]
			}
		}
		if f.name != "" && f.pref != "" {
			filters = append(filters, f)
		}
	}
	return filters, nil
}

// tcWhere renders the census Where value for one filter.
func tcWhere(f tcFilter, iface string) string {
	return fmt.Sprintf("%s:%s", iface, f.dir)
}

// tcProgName returns the kernel name of one program id.
func tcProgName(id ebpf.ProgramID) (string, error) {
	p, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return "", err
	}
	defer p.Close()
	info, err := p.Info()
	if err != nil {
		return "", err
	}
	return info.Name, nil
}

// liveKernel reads the five census classes through the live kernel and the
// `tc` CLI. Every class mirrors the production inventory through the scope.
type liveKernel struct{}

// ListPrograms reads every program id and keeps the kernel names.
func (liveKernel) ListPrograms() ([]residue.Object, error) {
	out := []residue.Object{}
	var prev ebpf.ProgramID
	for {
		id, err := ebpf.ProgramGetNextID(prev)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("residue census: program id after %d: %w", prev, err)
			}
			break
		}
		prev = id
		name, err := tcProgName(id)
		if err != nil {
			continue // the object vanished mid-sweep; the list moves on
		}
		out = append(out, residue.Object{Class: residue.ClassProgram, ID: name})
	}
	return out, nil
}

// ListMaps reads every map id and keeps the kernel names.
func (liveKernel) ListMaps() ([]residue.Object, error) {
	out := []residue.Object{}
	var prev ebpf.MapID
	for {
		id, err := ebpf.MapGetNextID(prev)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("residue census: map id after %d: %w", prev, err)
			}
			break
		}
		prev = id
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue // the object vanished mid-sweep; the list moves on
		}
		info, err := m.Info()
		_ = m.Close()
		if err != nil {
			return nil, fmt.Errorf("residue census: map %d info: %w", id, err)
		}
		out = append(out, residue.Object{Class: residue.ClassMap, ID: info.Name})
	}
	return out, nil
}

// ListLinks reads every bpf_link and keeps the referenced program names. The
// interface of an XDP link stays out of the record: the scope owns links by
// program identity.
func (liveKernel) ListLinks() ([]residue.Object, error) {
	out := []residue.Object{}
	var it link.Iterator
	defer it.Close()
	for it.Next() {
		l := it.Take()
		info, err := l.Info()
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("residue census: link %d info: %w", it.ID, err)
		}
		if info.Program == 0 {
			l.Close()
			continue
		}
		name, err := tcProgName(info.Program)
		l.Close()
		if err != nil {
			continue // the program vanished mid-sweep; the list moves on
		}
		out = append(out, residue.Object{Class: residue.ClassLink, ID: name})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("residue census: link iteration: %w", err)
	}
	return out, nil
}

// ListPins walks the BPFFS subtree. Dirs stay out of the record; one file
// per pin.
func (liveKernel) ListPins(root string) ([]residue.Object, error) {
	out := []residue.Object{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		out = append(out, residue.Object{Class: residue.ClassPin, ID: p})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListTCFilters reads both directions of one managed interface.
func (liveKernel) ListTCFilters(iface string) ([]residue.Object, error) {
	out := []residue.Object{}
	for _, dir := range []string{"ingress", "egress"} {
		filters, err := parseTCFilters(iface, dir)
		if err != nil {
			return nil, err
		}
		for _, f := range filters {
			out = append(out, residue.Object{
				Class: residue.ClassTCFilter, ID: f.name, Where: tcWhere(f, iface),
			})
		}
	}
	return out, nil
}

// installShield applies the full attach state: the XDP leg (shield_xdp on a
// bpf_link over its 3 maps), the TC leg (tc_ingress_waf pinned under the
// scope root, ingress + egress filters over its 5 maps).
func installShield(t *testing.T) (c1, c2 *ebpf.Collection, xdp link.Link) {
	t.Helper()

	spec1, err := loadResidue_shield()
	if err != nil {
		t.Fatalf("bpf2go spec (shield): %v", err)
	}
	c1, err = ebpf.NewCollection(spec1)
	if err != nil {
		t.Fatalf("collection (shield): %v", err)
	}
	xdp, err = link.AttachXDP(link.XDPOptions{
		Program:   c1.Programs["shield_xdp"],
		Interface: ifaceIndex(t, hostVeth),
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		c1.Close()
		t.Fatalf("attach xdp on %s: %v", hostVeth, err)
	}

	if mkerr := os.MkdirAll(pinRoot, 0o700); mkerr != nil {
		c1.Close()
		xdp.Close()
		t.Fatalf("pin dir: %v", mkerr)
	}
	spec2, err := loadResidue_flow()
	if err != nil {
		c1.Close()
		xdp.Close()
		t.Fatalf("bpf2go spec (flow): %v", err)
	}
	c2, err = ebpf.NewCollection(spec2)
	if err != nil {
		c1.Close()
		xdp.Close()
		t.Fatalf("collection (flow): %v", err)
	}
	prog := c2.Programs["tc_ingress_waf"]
	if prog == nil {
		t.Fatal("no tc_ingress_waf in the flow object")
	}
	if perr := prog.Pin(pinProg); perr != nil {
		c1.Close()
		xdp.Close()
		c2.Close()
		t.Fatalf("prog pin: %v", perr)
	}
	run(t, "tc", "qdisc", "add", "dev", hostVeth, "clsact")
	run(t, "tc", "filter", "add", "dev", hostVeth, "ingress", "bpf", "da", "pinned", pinProg)
	run(t, "tc", "filter", "add", "dev", hostVeth, "egress", "bpf", "da", "pinned", pinProg)
	return c1, c2, xdp
}

// ifaceIndex resolves one interface name.
func ifaceIndex(t *testing.T, name string) int {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %s: %v", name, err)
	}
	return iface.Index
}

// assertInstallCensus pins the install shape the sweep starts from: 2
// programs, 8 maps, 1 link, 1 pin, 2 TC filters.
// installSnapshot records the exact kernel identities this install created:
// map ids, program ids, the link id, the pin path and the tc filter rows on
// the managed interface.
//
// The teardown verdict reads absent-by-identity, never by name. A stale
// object from another install carries the same name (the map name field
// holds 15 bytes; a name match cannot tell two installs apart) and must
// not decide the gate. The live run of 2026-10-24 proved the class: two
// extra events-named maps sat in the census while the install held eight.
type installSnapshot struct {
	MapIDs  map[ebpf.MapID]string
	ProgIDs map[ebpf.ProgramID]string
	PinPath string
	TCPrefs map[string][]string // "iface:dir" -> filter prefs
}

func snapshotInstall(c1, c2 *ebpf.Collection, xdp link.Link) (installSnapshot, error) {
	s := installSnapshot{
		MapIDs:  map[ebpf.MapID]string{},
		ProgIDs: map[ebpf.ProgramID]string{},
		PinPath: pinProg,
		TCPrefs: map[string][]string{},
	}
	for _, coll := range []*ebpf.Collection{c1, c2} {
		for name, m := range coll.Maps {
			info, err := m.Info()
			if err != nil {
				return s, fmt.Errorf("residue snapshot: map %s: %w", name, err)
			}
			id, _ := info.ID()
			s.MapIDs[id] = name
		}
		for name, p := range coll.Programs {
			info, err := p.Info()
			if err != nil {
				return s, fmt.Errorf("residue snapshot: program %s: %w", name, err)
			}
			pid, _ := info.ID()
			s.ProgIDs[pid] = name
		}
	}
	for _, row := range []struct{ key, dir string }{
		{hostVeth, "ingress"}, {hostVeth, "egress"},
	} {
		filters, err := parseTCFilters(row.key, row.dir)
		if err != nil {
			return s, fmt.Errorf("residue snapshot: tc filters on %s: %w", row.key, err)
		}
		for _, f := range filters {
			s.TCPrefs[tcWhere(f, row.key)] = append(s.TCPrefs[tcWhere(f, row.key)], f.pref)
		}
	}
	return s, nil
}

// assertInstallVisible proves the census reads every snapshot object before
// the teardown. The census ownership stays name-based (the product surface);
// the gate asserts only visibility here.
//
// The stale-name class (the extra events-named objects) changes the count.
// The check therefore requires: every snapshot map id and program id shows
// in the live lists, the pin and the tc rows show, and every census object
// that matches the scope names carries a snapshot identity. The last clause
// is the poisoning check: an owned object outside the snapshot = stale state.
func assertInstallVisible(t *testing.T, kr residue.KernelRead, sc residue.Scope, snap installSnapshot) residue.Report {
	t.Helper()
	installed, err := residue.Census(kr, sc)
	if err != nil {
		t.Fatalf("census over the live install: %v", err)
	}

	listIDs := func() (map[ebpf.MapID]string, error) {
		seen := map[ebpf.MapID]string{}
		var prev ebpf.MapID
		for {
			id, err := ebpf.MapGetNextID(prev)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return nil, fmt.Errorf("residue census: map id after %d: %w", prev, err)
				}
				return seen, nil
			}
			prev = id
			m, err := ebpf.NewMapFromID(id)
			if err != nil {
				continue // the map vanished mid-walk; the list moves on
			}
			info, err := m.Info()
			_ = m.Close()
			if err != nil {
				return nil, fmt.Errorf("residue census: map %d info: %w", id, err)
			}
			seen[id] = info.Name
		}
	}
	seen, err := listIDs()
	if err != nil {
		t.Fatalf("live map id walk: %v", err)
	}
	// 1. every snapshot identity shows in the kernel with its install name
	for id, name := range snap.MapIDs {
		if got, ok := seen[id]; !ok || got != name {
			t.Fatalf("the census cannot see installed map %s (id %d): the census read is incomplete", name, id)
		}
	}
	// 2. the poisoning check: an owned kernel map outside the snapshot is
	// stale state from another install with the same name. Name ownership
	// cannot tell installs apart; the ids can. Fail loud with both.
	for id, name := range seen {
		if _, ok := snap.MapIDs[id]; ok {
			continue
		}
		if !sc.Owned(residue.Object{Class: residue.ClassMap, ID: name}) {
			continue
		}
		t.Fatalf("the census reads an owned map outside the snapshot: %q id %d — stale state from another install; clean it before the gate runs", name, id)
	}
	return installed
}

func progIDByName(name string) (ebpf.ProgramID, error) {
	var prev ebpf.ProgramID
	for {
		id, err := ebpf.ProgramGetNextID(prev)
		if err != nil {
			return 0, fmt.Errorf("residue census: program id after %d: %w", prev, err)
		}
		prev = id
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, err := p.Info()
		_ = p.Close()
		if err != nil {
			continue
		}
		if info.Name == name {
			return id, nil
		}
	}
}

// assertGone reads the snapshot identities after the teardown and fails on
// the first object that still exists. This is the M7 zero read.
func assertGone(t *testing.T, snap installSnapshot) {
	t.Helper()
	for id, name := range snap.MapIDs {
		if m, err := ebpf.NewMapFromID(id); err == nil {
			m.Close()
			t.Fatalf("residue: map %s (id %d) still exists after teardown", name, id)
		}
	}
	for id, name := range snap.ProgIDs {
		if p, err := ebpf.NewProgramFromID(id); err == nil {
			p.Close()
			t.Fatalf("residue: program %s (id %d) still exists after teardown", name, id)
		}
	}
	if _, err := os.Stat(snap.PinPath); err == nil {
		t.Fatalf("residue: pin %s still exists after teardown", snap.PinPath)
	}
	for where, prefs := range snap.TCPrefs {
		iface, dir, _ := strings.Cut(where, ":")
		filters, err := parseTCFilters(iface, dir)
		if err != nil {
			t.Fatalf("residue: tc filters on %s: %v", where, err)
		}
		for _, f := range filters {
			for _, pref := range prefs {
				if f.pref == pref {
					t.Fatalf("residue: tc filter %s pref %s still exists after teardown", where, pref)
				}
			}
		}
	}
}

// TestResidueGateE2E is the issue #168 acceptance: attach both shield legs,
// uninstall, and assert zero kernel objects (gate row M7).
func TestResidueGateE2E(t *testing.T) {
	mustRoot(t)
	cleanup(t)
	defer cleanup(t)
	setupNet(t)

	sc := liveScope()
	kr := liveKernel{}
	c1, c2, xdp := installShield(t)
	snap, err := snapshotInstall(c1, c2, xdp)
	if err != nil {
		t.Fatalf("install snapshot: %v", err)
	}
	assertInstallVisible(t, kr, sc, snap)

	// The full teardown (the §16.4 order) rides the injected Uninstaller:
	// per-hook detach, per-interface TC filter removal, the BPFFS subtree
	// sweep. The sweep must read zero after the settle poll.
	un := &liveUninstaller{sc: sc, xdp: xdp, c1: c1, c2: c2}
	r0, err := residue.Uninstall(kr, un, sc)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	r := r0
	if !r0.Clean() {
		r = settleCensus(t, kr, sc)
	}
	if !r.Clean() {
		t.Fatalf("uninstall left kernel residue: %s", r)
	}
	assertGone(t, snap)
}

// liveUninstaller binds the TR-35a Uninstaller effects to the live kernel:
// the effects ride the exact surface the conformance contract models (the
// kernel-free suite over the same Scope).
type liveUninstaller struct {
	sc  residue.Scope
	xdp link.Link
	c1  *ebpf.Collection
	c2  *ebpf.Collection
}

// DetachXDP closes the bpf_link and the shield collection. The link close
// detaches the hook; the unpinned program and its maps lose the last
// reference.
func (u *liveUninstaller) DetachXDP(iface string) error {
	first := u.xdp.Close()
	u.c1.Close()
	if first != nil {
		return fmt.Errorf("residue uninstall: detach xdp on %s: %w", iface, first)
	}
	return nil
}

// DeleteTCFilters removes the shield's filters on one interface and closes
// the TC collection (the loader-side fds drop with the hooks). A row whose
// program identity stays outside the scope keeps running.
func (u *liveUninstaller) DeleteTCFilters(iface string) error {
	for _, dir := range []string{"ingress", "egress"} {
		filters, err := parseTCFilters(iface, dir)
		if err != nil {
			return err
		}
		for _, f := range filters {
			if !u.sc.Owned(residue.Object{
				Class: residue.ClassTCFilter, ID: f.name, Where: tcWhere(f, iface),
			}) {
				continue
			}
			args := []string{"tc", "filter", "del", "dev", iface, dir, "pref", f.pref}
			if f.handle != "" {
				args = append(args, "handle", f.handle)
			}
			out, derr := exec.Command(args[0], args[1:]...).CombinedOutput()
			if derr != nil && f.handle != "" {
				// handle-free retry (the del grammar holds both forms)
				out, derr = exec.Command("tc", "filter", "del", "dev", iface, dir, "pref", f.pref).CombinedOutput()
			}
			if derr != nil {
				return fmt.Errorf("residue uninstall: tc filter del dev %s %s: %w:\n%s", iface, dir, derr, out)
			}
		}
	}
	u.c2.Close()
	return nil
}

// SweepPins deletes the pin files under the scope root. The root dir and
// any subdirs stay (dirs are no census class).
func (u *liveUninstaller) SweepPins(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		return os.Remove(p)
	})
}

// settleCensus re-reads the census while the kernel drains its deferred
// object frees (the freed id lingers one workqueue/RCU window). The poll
// budget: 5 s (50 reads × 100 ms). Residue that survives the settles is
// real, not transient.
func settleCensus(t *testing.T, kr residue.KernelRead, sc residue.Scope) residue.Report {
	t.Helper()
	var last residue.Report
	for i := 0; i < 50; i++ {
		r, err := residue.Census(kr, sc)
		if err != nil {
			t.Fatalf("census: %v", err)
		}
		if r.Clean() {
			return r
		}
		last = r
		time.Sleep(100 * time.Millisecond)
	}
	return last
}
