// Package celfastpath carries the socket class 2 template instantiation
// (TR-196, issue #238): the compiled bundle's CEL-class fast-path rows
// stage into the committed bpf2go flow object (bpf/flow_tc.c's fp leg),
// and Instantiate loads it through the verifier. The flow object carries
// one program (the TC classifier) and no tail calls; the fp rows are the
// compiled row truth the kernel evaluates, decision-free (§9.5).
//
// The template object is committed per architecture beside the shield
// and route builds (bpf/flow_tc.c, the ingest plane's own source; the
// ingest decoder files stay untouched — this package generates its own
// object pair). Stage re-checks every compiled-row bound kernel-free;
// any violation fails closed with the offending cell named. Instantiate
// is the kernel step: it fails on a verifier rejection — the apply
// fails, never a request mid-flight.
//
// The split surface claims no enforcement. The CEL-class rows carry the
// class 2 compiled row truth; the package never reports a policy
// "enforced". The boundary rides the TR-40b shape: no pinning, the
// loader attaches nothing.
package celfastpath

import (
	"errors"
	"fmt"

	ebpf "github.com/cilium/ebpf"

	fastpath "github.com/trishula-dev/trishula/internal/fastpath"
	operator "github.com/trishula-dev/trishula/internal/operator"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 cel_fastpath ../../../bpf/flow_tc.c -- -I../../../bpf -I../../../bpf/include -O2 -g

// ErrNoCELFastPath reports a bundle without compiled CEL-class rows
// (nothing to instantiate on this leg).
var ErrNoCELFastPath = errors.New("celfastpath: bundle carries no compiled CEL-class rows (nothing to instantiate)")

// The fp leg's glob kinds (the C's field vocabulary).
const (
	globNone         uint8 = 0
	globExact        uint8 = 1
	globPrefixSuffix uint8 = 2
)

// CELStage is one staged compiled row: the decomposed leg set the
// kernel's fp_rules map carries.
type CELStage struct {
	// ID is the row index (the mark value on a match).
	ID uint32
	// Action is the kernel action code (0 forward+mark, 1 drop).
	Action uint8
	// Method carries the method-literal bytes when MethodLen > 0.
	Method    [fastpath.FastPathCELMethodMaxBytes]byte
	MethodLen uint8
	// GlobKind is the fp leg's glob kind (0/1/2 above).
	GlobKind uint8
	Pre      [fastpath.FastPathCELGlobPrefixMaxBytes]byte
	PreLen   uint8
	Suf      [fastpath.FastPathCELGlobSuffixMaxBytes]byte
	SufLen   uint8
	Query    [fastpath.FastPathCELQueryMaxBytes]byte
	QueryLen uint8
}

// Stage re-checks the bundle's CEL-class leg against the compiled-row
// bounds and returns the staged rows. Kernel-free: no kernel object, no
// verifier, no load here — violations fail closed with the offending
// row named (the wire's row id).
func Stage(bundle *operator.Bundle) ([]CELStage, error) {
	if bundle == nil || bundle.FastPath == nil || len(bundle.FastPath.CELRules) == 0 {
		return nil, ErrNoCELFastPath
	}
	rows := bundle.FastPath.CELRules
	if len(rows) > fastpath.FastPathCELMaxRules {
		return nil, fmt.Errorf("the fastPath cel leg carries %d rows; the bound is %d rows", len(rows), fastpath.FastPathCELMaxRules)
	}
	staged := make([]CELStage, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for i, r := range rows {
		if err := fastpath.ValidateFastPathCELRule(r); err != nil {
			return nil, fmt.Errorf("the fastPath cel leg row %d: %w", i, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("the fastPath cel leg row %d: id %q repeats an earlier row", i, r.ID)
		}
		seen[r.ID] = true
		st := CELStage{
			ID:     uint32(i),
			Action: r.Action,
		}
		if r.PathExact {
			st.GlobKind = globExact
			st.PreLen = uint8(len(r.PathGlobPrefix))
			copy(st.Pre[:], r.PathGlobPrefix)
		} else if r.PathGlobPrefix != "" || r.PathGlobSuffix != "" {
			st.GlobKind = globPrefixSuffix
			st.PreLen = uint8(len(r.PathGlobPrefix))
			copy(st.Pre[:], r.PathGlobPrefix)
			st.SufLen = uint8(len(r.PathGlobSuffix))
			copy(st.Suf[:], r.PathGlobSuffix)
		}
		if r.Method != "" {
			st.MethodLen = uint8(len(r.Method))
			copy(st.Method[:], r.Method)
		}
		if r.QuerySubstring != "" {
			st.QueryLen = uint8(len(r.QuerySubstring))
			copy(st.Query[:], r.QuerySubstring)
		}
		staged = append(staged, st)
	}
	return staged, nil
}

// Instantiate fills the compiled rows into the committed flow object's
// fp_rules map and loads the program through the verifier. The load is
// the proof: a verifier rejection fails the apply — never a request
// mid-flight. The returned collection holds the one TC program and the
// staged rows; the caller attaches or closes it.
func Instantiate(bundle *operator.Bundle) (*ebpf.Collection, error) {
	staged, err := Stage(bundle)
	if err != nil {
		return nil, fmt.Errorf("celfastpath: %w", err)
	}
	spec, err := loadCel_fastpath()
	if err != nil {
		return nil, fmt.Errorf("celfastpath: the flow template object: %w", err)
	}
	// The compiled-row envelope: one program, no tail calls, the
	// instruction budget inside the recorded envelope (the census
	// record's template contract, the flow leg's own row).
	if err := fastpath.AssertFlowEnvelope(spec); err != nil {
		return nil, fmt.Errorf("celfastpath: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("celfastpath: verifier rejected the flow program: %w", err)
	}
	m := coll.Maps["fp_rules"]
	if m == nil {
		coll.Close()
		return nil, errors.New("celfastpath: the loaded collection lost fp_rules")
	}
	for _, row := range staged {
		val := cel_fastpathFpRuleVal{
			Id:        row.ID,
			Enabled:   1,
			Action:    row.Action,
			MethodLen: row.MethodLen,
			GlobKind:  row.GlobKind,
			PreLen:    row.PreLen,
			SufLen:    row.SufLen,
			QueryLen:  row.QueryLen,
		}
		copy(val.Method[:], row.Method[:])
		copy(val.Pre[:], row.Pre[:])
		copy(val.Suf[:], row.Suf[:])
		copy(val.Query[:], row.Query[:])
		key := row.ID
		if err := m.Put(&key, &val); err != nil {
			coll.Close()
			return nil, fmt.Errorf("celfastpath: stage the cel row %d: %w", row.ID, err)
		}
	}
	return coll, nil
}
