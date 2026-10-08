//go:build linux

package shield

// Loader (TR-03 step 3, §9.2): attach the compiled shield to a kernel
// interface via cilium/ebpf; expose the engine→shield maps (ban/verdict
// producers) and the monotonic clock the ban expiry shares with the
// kernel (bpf_ktime_get_ns == CLOCK_MONOTONIC_RAW on Linux).
//
// PRD v4 §19.1 sketch's verdict_val omits port/proto width detail and
// ban/verdict keys were IPv4-only — defect #62's family-discriminated
// union is the wire contract here (banwire_test.go).

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native --type ban_key --type ban_val --type verdict_key --type verdict_val bpf_shield ../../bpf/shield_xdp.c -- -I../../bpf -O2 -g

// Loader owns the attached program, its links and the shared maps.
type Loader struct {
	coll *ebpf.Collection
	link link.Link
	maps ShieldMaps
}

// Attach loads the bpf2go objects and pins the XDP program on iface.
func Attach(iface string) (*Loader, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["shield_xdp"],
		Interface: ifaceIndex(iface),
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach xdp on %s: %w", iface, err)
	}
	return &Loader{
		link: l,
		coll: coll,
		maps: ShieldMaps{
			BanTable:     coll.Maps["ban_table"],
			VerdictCache: coll.Maps["verdict_cache"],
		},
	}, nil
}

// loadSpec loads the bpf2go-generated CollectionSpec for this platform.
func loadSpec() (*ebpf.CollectionSpec, error) {
	spec, err := loadBpf_shield()
	if err != nil {
		return nil, fmt.Errorf("bpf2go objects: %w", err)
	}
	return spec, nil
}

// AttachVeth is the test entrypoint (netns/veth harnesses).
func AttachVeth(t testing.TB, iface string) *Loader {
	l, err := Attach(iface)
	if err != nil {
		t.Fatalf("Attach(%s): %v", iface, err)
	}
	return l
}

// Maps exposes the producer maps (engine → shield).
func (l *Loader) Maps() ShieldMaps { return l.maps }

// Close detaches and closes everything (the pin discipline: nothing out-
// lives the loader unless pinning is explicitly requested — v0 pins none).
func (l *Loader) Close() error {
	first := l.link.Close()
	l.coll.Close()
	return first
}

// NowNS returns CLOCK_MONOTONIC nanoseconds — the same clock the kernel's
// bpf_ktime_get_ns reads, so Go-written until_ts values align with the
// in-kernel expiry comparisons. (v0: monotonic ≈ boot-time; a boot-id
// guard lands with the operator TR-08.)
func (l *Loader) NowNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime: %w", err)
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}

// --- wire helpers -----------------------------------------------------

// LookupBan reads a ban back (tests + operator tooling).
func (m ShieldMaps) LookupBan(key BanKey) (BanVal, bool, error) {
	var v BanVal
	err := m.BanTable.Lookup(&key, &v)
	if err != nil {
		return BanVal{}, false, nil // not found = clean miss
	}
	return v, true, nil
}

// CountBan asserts a key exists (e2e convenience).
func (m ShieldMaps) CountBan(key BanKey) (int, error) {
	_, ok, err := m.LookupBan(key)
	if err != nil {
		return 0, err
	}
	if ok {
		return 1, nil
	}
	return 0, nil
}

func ifaceIndex(name string) int {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return -1
	}
	return ifi.Index
}

// ShieldMaps carries the shared maps (aliases of coll.Maps entries).
type ShieldMaps struct {
	BanTable     *ebpf.Map
	VerdictCache *ebpf.Map
}

// SetBan writes one ban entry (family-discriminated; refuses zero expiry).
func (m ShieldMaps) SetBan(key BanKey, val BanVal) error {
	if val.UntilTS == 0 {
		return fmt.Errorf("SetBan: zero expiry (infinite bans forbidden)")
	}
	return m.BanTable.Put(key, val)
}
