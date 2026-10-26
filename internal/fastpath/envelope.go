package fastpath

// The template envelope carries the template contract's program bounds
// (the census record's template contract, section 5): one assembled
// program targets one loadable unit, the instruction budget per program
// is a compile-time constant, and the tracked evaluation uses no tail
// calls. AssertEnvelope runs kernel-free over an instantiated template's
// object spec; any violation fails with the offending cell named.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	ebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// RouteEnvelopeInstructions is the program envelope constant (the census
// record's template contract: the instruction budget per program is a
// compile-time constant). The object contract test pins the committed
// program under it, and AssertEnvelope rejects any spec past it.
const RouteEnvelopeInstructions = 512

// AssertEnvelope asserts the template contract over an instantiated
// template's object spec, kernel-free: one program, the instruction count
// inside the envelope constant, and no tail call at any instruction. A
// violation fails with the offending cell named: the program symbol, or
// the instruction index of a tail call. The spec carries no kernel state;
// the assert never loads, attaches or verifies.
func AssertEnvelope(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("fastpath: envelope assert: nil spec")
	}
	if len(spec.Programs) != 1 {
		names := make([]string, 0, len(spec.Programs))
		for name := range spec.Programs {
			names = append(names, name)
		}
		sort.Strings(names)
		joined := strings.Join(names, ", ")
		if joined == "" {
			joined = "none"
		}
		return fmt.Errorf("fastpath: the instantiated template carries %d programs (%s); the contract is one program", len(spec.Programs), joined)
	}
	var name string
	var prog *ebpf.ProgramSpec
	for key, p := range spec.Programs {
		name, prog = key, p
	}
	if prog == nil {
		return fmt.Errorf("fastpath: envelope assert: program %q carries no spec", name)
	}
	if got := len(prog.Instructions); got > RouteEnvelopeInstructions {
		return fmt.Errorf("fastpath: template %q carries %d instructions past the %d-instruction envelope", name, got, RouteEnvelopeInstructions)
	}
	for i := range prog.Instructions {
		ins := &prog.Instructions[i]
		if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnTailCall {
			return fmt.Errorf("fastpath: template %q carries a tail call at instruction %d; the contract carries none", name, i)
		}
	}
	return nil
}

// FlowEnvelopeInstructions is the flow-program envelope constant (the
// census record's template contract, the flow-object row): the
// instruction budget per program is a compile-time constant. The
// committed object measures 3920 instructions at the shipped build
// (tc_ingress_waf, one program, the glob+method family; xlated 31360B on
// the VM load receipt); the envelope pins 4096 (the round contract
// figure, measured headroom stated in the record). The object-contract
// test pins the committed program under it and AssertFlowEnvelope
// rejects any spec past it.
const FlowEnvelopeInstructions = 4096

// AssertFlowEnvelope asserts the contract over the flow object's spec,
// kernel-free: one program (tc_ingress_waf), the instruction count inside
// the flow envelope constant, and no tail call. A violation fails with
// the offending cell named, the same shape AssertEnvelope reads.
func AssertFlowEnvelope(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("fastpath: flow envelope assert: nil spec")
	}
	if len(spec.Programs) != 1 {
		names := make([]string, 0, len(spec.Programs))
		for name := range spec.Programs {
			names = append(names, name)
		}
		sort.Strings(names)
		joined := strings.Join(names, ", ")
		if joined == "" {
			joined = "none"
		}
		return fmt.Errorf("fastpath: the flow object carries %d programs (%s); the contract is one program", len(spec.Programs), joined)
	}
	var name string
	var prog *ebpf.ProgramSpec
	for key, p := range spec.Programs {
		name, prog = key, p
	}
	if prog == nil {
		return fmt.Errorf("fastpath: flow envelope assert: program %q carries no spec", name)
	}
	if got := len(prog.Instructions); got > FlowEnvelopeInstructions {
		return fmt.Errorf("fastpath: flow program %q carries %d instructions past the %d-instruction envelope", name, got, FlowEnvelopeInstructions)
	}
	for i := range prog.Instructions {
		ins := &prog.Instructions[i]
		if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnTailCall {
			return fmt.Errorf("fastpath: flow program %q carries a tail call at instruction %d; the contract carries none", name, i)
		}
	}
	return nil
}
