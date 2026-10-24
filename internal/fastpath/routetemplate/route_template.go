// Package routetemplate carries the route-marking template instantiation
// (TR-40b, the census record's template contract): the compiled bundle's
// kernel-path leg stages into the committed bpf2go object, and Instantiate
// loads it through the verifier. One template carries one program; v1
// carries no tail calls and no pinned state.
//
// The template object is committed per architecture beside the shield
// build (bpf/route_mark.c, a sibling .c file; the shield contract stays
// frozen). Stage re-checks every template-contract bound kernel-free; any
// violation fails closed with the offending cell named. Instantiate is the
// kernel step: it fails on a verifier rejection, never on a request.
//
// The split surface claims no enforcement. The route template marks route
// classes; it never reports a policy "enforced".
package routetemplate

import (
	"errors"

	ebpf "github.com/cilium/ebpf"
	operator "github.com/trishula-dev/trishula/internal/operator"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 route_mark ../../bpf/route_mark.c -- -I../../bpf -O2 -g

// ErrNoKernelLeg reports a bundle without the kernel-path leg.
var ErrNoKernelLeg = errors.New("routetemplate: bundle carries no kernel-path leg (nothing to instantiate)")

// RouteStage is one staged route class: the template's route-map row.
// PrefixLenBits and Prefix form the LPM key; Action rides the value with
// ID (the class index in policy order).
type RouteStage struct {
	// Prefix is the raw prefix bytes, zero-filled past PrefixLenBits/8.
	Prefix [64]byte
	// PrefixLenBits is the LPM prefix length in bits.
	PrefixLenBits uint32
	// Action is the kernel action code (0 forward, 1 drop).
	Action uint8
	// ID is the class index in policy order (the skb mark value).
	ID uint32
}

// Stage re-checks the bundle's kernel leg against the template contract
// and returns the route rows to stage into the map. Kernel-free: no kernel
// object, no verifier, no load here — violations fail closed with the
// offending cell named.
//
// STUB (TR-40b RED): an inert error. The watched-RED suite pins the real
// staging; the GREEN commit replaces this body.
func Stage(bundle *operator.Bundle) ([]RouteStage, error) {
	return nil, errors.New("routetemplate: stage not implemented (TR-40b GREEN)")
}

// Instantiate fills the template's placeholders from the compiled bundle
// and loads the program through the verifier. The load is the proof: a
// verifier rejection fails the apply — never a request mid-flight.
//
// STUB (TR-40b RED): an inert error. The watched-RED e2e runs it on a
// Linux kernel; the GREEN commit replaces this body.
func Instantiate(bundle *operator.Bundle) (*ebpf.Collection, error) {
	return nil, errors.New("routetemplate: instantiate not implemented (TR-40b GREEN)")
}
