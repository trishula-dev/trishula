package ingest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// FlowEvent mirrors bpf/flow_tc.c's struct flow_event (TR-04d lands the
// C; the wire contract is frozen HERE first per the #42 standard).
// Dual-stack per defect #62: both address families ride the event + the
// explicit family byte.
//
//	struct flow_event {
//	    __u64 ts_ns;
//	    __be32 saddr_v4; __u8 saddr_v6[16];
//	    __be32 daddr_v4; __u8 daddr_v6[16];
//	    __u16 sport, dport;
//	    __u8 tcp_flags;
//	    __u32 mark;
//	    __u16 payload_len;
//	    __u8 http_seen, h2_preface, tls_seen;
//	    __u8 family;              // 4 | 6 (KEY_AF_*)
//	    char path_hint[128];
//	};
const (
	EventHdrSize = 8 + 4 + 16 + 4 + 16 + 2 + 2 + 1 + 4 + 2 + 3 + 1 // 63: ts + addrs + ports + flags + mark + len + probes + family
	MaxEventSize = EventHdrSize + 128                              // + path hint
	PathHintLen  = 128
)

var (
	ErrEventTooShort = errors.New("flow event too short")
	ErrEventTooLarge = errors.New("flow event too large")
)

// FlowEvent is the decoded form (§19.1 sketch, dual-stack #62).
type FlowEvent struct {
	Timestamp  uint64
	SrcIP4     [4]byte
	SrcIP6     [16]byte
	DstIP4     [4]byte
	DstIP6     [16]byte
	SrcPort    uint16
	DstPort    uint16
	TCPFlags   uint8
	Mark       uint32
	PayloadLen uint16
	HTTPSeen   uint8
	H2Preface  uint8
	TLSSeen    uint8
	Family     uint8
	PathHint   [128]byte
}

// PathString returns the NUL-trimmed path hint.
func (e *FlowEvent) PathString() string {
	b := e.PathHint[:]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// DecodeFlowEvent wire-decodes one ringbuf record.
func DecodeFlowEvent(raw []byte) (*FlowEvent, error) {
	if len(raw) < EventHdrSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrEventTooShort, len(raw))
	}
	if len(raw) > MaxEventSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrEventTooLarge, len(raw))
	}
	r := bytes.NewReader(raw)
	var e FlowEvent
	if err := binary.Read(r, nativeEndian, &e.Timestamp); err != nil {
		return nil, err
	}
	if _, err := r.Read(e.SrcIP4[:]); err != nil {
		return nil, err
	}
	if _, err := r.Read(e.SrcIP6[:]); err != nil {
		return nil, err
	}
	if _, err := r.Read(e.DstIP4[:]); err != nil {
		return nil, err
	}
	if _, err := r.Read(e.DstIP6[:]); err != nil {
		return nil, err
	}
	tail := struct {
		SrcPort    uint16
		DstPort    uint16
		TCPFlags   uint8
		Mark       uint32
		PayloadLen uint16
		HTTPSeen   uint8
		H2Preface  uint8
		TLSSeen    uint8
		Family     uint8
	}{}
	if err := binary.Read(r, nativeEndian, &tail); err != nil {
		return nil, err
	}
	e.SrcPort, e.DstPort, e.TCPFlags = tail.SrcPort, tail.DstPort, tail.TCPFlags
	e.Mark, e.PayloadLen = tail.Mark, tail.PayloadLen
	e.HTTPSeen, e.H2Preface, e.TLSSeen, e.Family =
		tail.HTTPSeen, tail.H2Preface, tail.TLSSeen, tail.Family
	if _, err := r.Read(e.PathHint[:]); err != nil {
		return nil, err
	}
	return &e, nil
}

// Key projects the event onto the tx-layer FlowKey (family-explicit).
func (e *FlowEvent) Key() FlowKey {
	k := FlowKey{
		SrcIP:   e.SrcIP4,
		DstIP:   e.DstIP4,
		SrcIP6:  e.SrcIP6,
		DstIP6:  e.DstIP6,
		SrcPort: e.SrcPort,
		DstPort: e.DstPort,
		Family:  e.Family,
	}
	return k
}
