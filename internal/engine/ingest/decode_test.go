package ingest

import (
	"errors"
	"testing"
)

// TR-04b (issue #67, child of TR-04): ringbuf reader + FlowEvent decode.
// Kernel-free still: the reader is injected as an interface, synthetic
// records drive the RED tests; the real cilium ringbuf type plugs in
// behind the same interface in TR-04d.

func TestDecodeFlowEvent(t *testing.T) {
	// Wire shape per bpf/flow_tc.c (TR-04d will enforce the C side):
	// u64 ts, v4/v6 addrs, ports, flags, mark, payload_len, flags trio,
	// 128B path hint. Family byte rides the event (the C event carries
	// both addr families since #62).
	raw := syntheticEvent(synEvent{
		TS:       42,
		SrcIP4:   [4]byte{10, 66, 0, 66},
		SrcIP6:   ip6(0x20, 0x01), // 2001:: padding-filled
		DstIP4:   [4]byte{10, 66, 0, 1},
		DstIP6:   ip6(0x20, 0x02),
		SrcPort:  53000,
		DstPort:  443,
		Mark:     7,
		Payload:  1200,
		HTTPSeen: 1,
		Family:   4,
		Path:     "/v1/chat/completions",
	})
	ev, err := DecodeFlowEvent(raw)
	if err != nil {
		t.Fatalf("DecodeFlowEvent: %v", err)
	}
	if ev.Timestamp != 42 || ev.SrcPort != 53000 || ev.DstPort != 443 {
		t.Fatalf("header fields wrong: %+v", ev)
	}
	if ev.HTTPSeen != 1 || ev.Family != 4 {
		t.Fatalf("probe fields wrong: http=%d family=%d", ev.HTTPSeen, ev.Family)
	}
	if got := ev.PathString(); got != "/v1/chat/completions" {
		t.Fatalf("path hint = %q", got)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	// Truncated + oversized-unknown: log-and-continue shapes (the drain
	// loop must survive; DecodeFlowEvent returns classified errors).
	if _, err := DecodeFlowEvent([]byte{0x00, 0x01}); !errors.Is(err, ErrEventTooShort) {
		t.Fatalf("2-byte record: err=%v, want ErrEventTooShort", err)
	}
	big := make([]byte, MaxEventSize+1)
	if _, err := DecodeFlowEvent(big); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("oversized record: err=%v, want ErrEventTooLarge", err)
	}
}

func TestDrainSurvivesMalformedAndStops(t *testing.T) {
	m := NewTxManager()
	nowNS := uint64(100)
	m.now = func() uint64 { return nowNS }
	rd := newFakeRing(
		[]byte("garbage"), // too short → skipped
		syntheticEvent(synEvent{TS: 1, DstPort: 443, Family: 4,
			SrcIP4: [4]byte{10, 0, 0, 1}, DstIP4: [4]byte{10, 0, 0, 2}}),
		[]byte("0123456789abcdef0123456789abcdefZZZZ"), // structurally bad? no: too-short class
	)
	count, err := DrainFake(m, rd)
	if err != nil {
		t.Fatalf("DrainFake: %v", err)
	}
	if count != 1 {
		t.Fatalf("decoded %d events, want 1 (2 malformed skipped)", count)
	}
	if m.Len() != 1 {
		t.Fatalf("tx table = %d, want 1", m.Len())
	}
}
