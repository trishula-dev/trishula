package fastpath

// The envelope assertion suite (the census record's template contract,
// section 5). The assertion runs kernel-free over an instantiated
// template's object spec: one program, the instruction count inside the
// envelope constant, and no tail call at any instruction. A violation
// fails with the offending cell named: the program symbol, or the
// instruction index of a tail call. The committed route object passes the
// same assertion in the routetemplate suite.

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// envelopeSpec builds a kernel-free spec with one named program.
func envelopeSpec(name string, insns asm.Instructions) *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			name: {Instructions: insns},
		},
	}
}

// returnList builds count exit instructions.
func returnList(count int) asm.Instructions {
	insns := make(asm.Instructions, count)
	for i := range insns {
		insns[i] = asm.Return()
	}
	return insns
}

// TestAssertEnvelope pins the template contract over object specs, one
// violation class per row. Every violation names its cell.
func TestAssertEnvelope(t *testing.T) {
	rows := []struct {
		name string
		spec *ebpf.CollectionSpec
		want string
	}{
		{
			name: "one program inside the envelope",
			spec: envelopeSpec("route_mark", returnList(3)),
		},
		{
			name: "nil spec",
			spec: nil,
			want: "nil spec",
		},
		{
			name: "zero programs",
			spec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}},
			want: "carries 0 programs",
		},
		{
			name: "two programs",
			spec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
				"route_mark":  {Instructions: returnList(1)},
				"route_mark2": {Instructions: returnList(1)},
			}},
			want: "carries 2 programs (route_mark, route_mark2); the contract is one program",
		},
		{
			name: "past the instruction envelope",
			spec: envelopeSpec("route_mark", returnList(RouteEnvelopeInstructions+1)),
			want: "carries 513 instructions past the 512-instruction envelope",
		},
		{
			name: "tail call at instruction 0",
			spec: envelopeSpec("route_mark", asm.Instructions{asm.FnTailCall.Call()}),
			want: "carries a tail call at instruction 0",
		},
	}
	for _, row := range rows {
		err := AssertEnvelope(row.spec)
		if row.want == "" {
			if err != nil {
				t.Errorf("%s: AssertEnvelope: %v, want nil", row.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), row.want) {
			t.Errorf("%s: AssertEnvelope err = %v, want it to name %q", row.name, err, row.want)
		}
	}
}
