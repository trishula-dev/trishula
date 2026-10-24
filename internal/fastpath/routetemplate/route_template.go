// Package routetemplate carries the route-marking template instantiation
// (TR-40b, the census record's template contract): the compiled bundle's
// kernel-path leg stages into the committed bpf2go object, and Instantiate
// loads it through the verifier. One template carries one program; v1
// carries no tail calls and no pinned state.
//
// The template object is committed per architecture beside the shield
// build (bpf/route_mark.c, a sibling .c file; the shield contract stays
// frozen, and the contract test pins that). Stage re-checks every
// template-contract bound kernel-free; any violation fails closed with the
// offending cell named. Instantiate is the kernel step: it fails on a
// verifier rejection — the apply fails, never a request mid-flight.
//
// The split surface claims no enforcement. The route template marks route
// classes; it never reports a policy "enforced".
package routetemplate

import (
	"errors"
	"fmt"

	ebpf "github.com/cilium/ebpf"

	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	operator "github.com/trishula-dev/trishula/internal/operator"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 route_mark ../../../bpf/route_mark.c -- -I../../../bpf -I../../../bpf/include -O2 -g

// ErrNoKernelLeg reports a bundle without the kernel-path leg.
var ErrNoKernelLeg = errors.New("routetemplate: bundle carries no kernel-path leg (nothing to instantiate)")

// tcActOK is the TC_ACT_OK code (the template's default forward).
const tcActOK uint32 = 0

// RouteStage is one staged route class: the template's route-map row.
// PrefixLenBits and Prefix form the LPM key; Action rides the value with
// ID (the class index in policy order, the skb mark value).
type RouteStage struct {
	// Prefix is the raw prefix bytes, zero-filled past PrefixLenBits/8.
	Prefix [fastpath.RouteTemplatePrefixMaxBytes]byte
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
// offending cell named (the census field path plus the row index). The
// cell names match the compile and Load gates.
func Stage(bundle *operator.Bundle) ([]RouteStage, error) {
	if bundle == nil || bundle.FastPath == nil {
		return nil, ErrNoKernelLeg
	}
	rows := bundle.FastPath.Routes
	if len(rows) > fastpath.RouteTemplateMaxEntries {
		return nil, fmt.Errorf("spec.routes carries %d rows; the template bound is %d rows", len(rows), fastpath.RouteTemplateMaxEntries)
	}
	staged := make([]RouteStage, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for i, r := range rows {
		if r.Prefix == "" {
			return nil, fmt.Errorf("spec.routes[%d].prefix is required", i)
		}
		if len(r.Prefix) > fastpath.RouteTemplatePrefixMaxBytes {
			return nil, fmt.Errorf("spec.routes[%d].prefix carries %d bytes; the template bound is %d bytes", i, len(r.Prefix), fastpath.RouteTemplatePrefixMaxBytes)
		}
		if seen[r.Prefix] {
			return nil, fmt.Errorf("spec.routes[%d].prefix %q repeats an earlier row", i, r.Prefix)
		}
		seen[r.Prefix] = true
		switch r.Action {
		case fastpath.RouteTemplateActionForward, fastpath.RouteTemplateActionDrop:
		default:
			return nil, fmt.Errorf("spec.routes[%d].action code %d is outside the template vocabulary", i, r.Action)
		}
		row := RouteStage{
			Action: r.Action,
			ID:     uint32(i),
		}
		copy(row.Prefix[:], r.Prefix)
		row.PrefixLenBits = uint32(len(r.Prefix)) * 8
		staged = append(staged, row)
	}
	return staged, nil
}

// Instantiate fills the template's placeholders from the compiled bundle
// and loads the program through the verifier. The load is the proof: a
// verifier rejection fails the apply — never a request mid-flight. The
// returned collection holds the one program and the staged route map; the
// caller attaches or closes it.
func Instantiate(bundle *operator.Bundle) (*ebpf.Collection, error) {
	if bundle == nil || bundle.FastPath == nil {
		return nil, ErrNoKernelLeg
	}
	staged, err := Stage(bundle)
	if err != nil {
		return nil, fmt.Errorf("routetemplate: %w", err)
	}
	spec, err := loadRoute_mark()
	if err != nil {
		return nil, fmt.Errorf("routetemplate: route template object: %w", err)
	}
	// The contract asserts kernel-free before the load: one program, the
	// instruction count inside the fastpath.RouteEnvelopeInstructions
	// envelope, no tail calls. A violated contract fails here, with the
	// offending cell named: the apply fails, never a request mid-flight.
	if err := fastpath.AssertEnvelope(spec); err != nil {
		return nil, fmt.Errorf("routetemplate: %w", err)
	}
	// The placeholders: the miss forward. v1 pins the contract's default
	// forward; a later compile slice carries it on the bundle.
	if err := spec.Variables["route_cfg"].Set(&route_markRouteCfg{DefaultFwd: tcActOK}); err != nil {
		return nil, fmt.Errorf("routetemplate: route_cfg placeholder: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("routetemplate: verifier rejected the route template: %w", err)
	}
	m := coll.Maps["route_marks"]
	if m == nil {
		coll.Close()
		return nil, errors.New("routetemplate: the loaded collection lost route_marks")
	}
	for _, row := range staged {
		key := route_markRouteKey{Prefixlen: row.PrefixLenBits, Prefix: row.Prefix}
		val := route_markRouteVal{Action: row.Action, Id: row.ID}
		if err := m.Put(&key, &val); err != nil {
			coll.Close()
			return nil, fmt.Errorf("routetemplate: stage route row %d: %w", row.ID, err)
		}
	}
	return coll, nil
}
