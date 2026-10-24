package residue

// The uninstall sequence (spec [§16.4]): per-hook detach first, then the
// BPFFS subtree sweep, then the census reads zero. The kernel effects ride
// the injected Uninstaller; the census holds none. TR-35b (issue #168)
// binds the live kernel Uninstaller and asserts the same zero in CI.
//
// [§16.4]: https://github.com/trishula-dev/trishula/blob/main/docs/spec.md#164-lifecycle-of-trishula-in-a-cluster

import "fmt"

// Uninstaller carries the teardown effects for the sweep order:
//
//	DetachXDP removes the XDP leg on one managed interface: the link
//	close detaches the hook; the unpinned program and its maps lose the
//	last reference.
//	DeleteTCFilters removes the shield's TC filters on one interface. A
//	filter that pins under the BPFFS root is the shield's filter; a
//	foreign filter stays.
//	SweepPins deletes the pinned-object files under root. The subtree
//	root itself stays.
type Uninstaller interface {
	DetachXDP(iface string) error
	DeleteTCFilters(iface string) error
	SweepPins(root string) error
}

// Uninstall runs the teardown order over one managed interface set and
// returns the post-uninstall census. Fail order: an effect that fails stops
// the uninstall; an effect error reaches the caller, never a clean verdict.
// Use the returned Report for the zero assert (Report.Clean).
func Uninstall(k KernelRead, un Uninstaller, sc Scope) (Report, error) {
	if err := sc.Validate(); err != nil {
		return Report{}, err
	}
	if k == nil {
		return Report{}, fmt.Errorf("residue uninstall: nil KernelRead")
	}
	if un == nil {
		return Report{}, fmt.Errorf("residue uninstall: nil Uninstaller")
	}
	for _, iface := range sc.Ifaces {
		if err := un.DetachXDP(iface); err != nil {
			return Report{}, fmt.Errorf("residue uninstall: detach xdp on %s: %w", iface, err)
		}
		if err := un.DeleteTCFilters(iface); err != nil {
			return Report{}, fmt.Errorf("residue uninstall: delete tc filters on %s: %w", iface, err)
		}
	}
	if err := un.SweepPins(sc.BPFFSRoot); err != nil {
		return Report{}, fmt.Errorf("residue uninstall: sweep pins under %s: %w", sc.BPFFSRoot, err)
	}
	return Census(k, sc)
}
