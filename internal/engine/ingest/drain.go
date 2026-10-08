package ingest

import (
	"encoding/binary"
	"sync/atomic"
)

// nativeEndian is the bpf2go target byte order (little-endian on every
// supported target: arm64 + x86; the C emit uses the same translation).
var nativeEndian = binary.LittleEndian

// RecordSource is the minimal reader surface the drain loop consumes: the
// cilium ringbuf.Reader satisfies it via its Read() channel in TR-04d;
// tests inject fakes. Records are raw event bytes.
type RecordSource interface {
	// Recv returns the next record (ok=false on clean EOF/close).
	Recv() (raw []byte, ok bool)
}

// DrainResult reports one drain pass (test + metric surface).
type DrainResult struct {
	Decoded  int
	Skipped  int    // malformed records (log-warned)
	RingLoss uint64 // placeholder: TR-04c's loss counter wiring
}

func DrainFake(m *TxManager, rd RecordSource) (int, error) {
	n := 0
	for {
		raw, ok := rd.Recv()
		if !ok {
			return n, nil
		}
		ev, err := DecodeFlowEvent(raw)
		if err != nil {
			// malformed → log-warn + continue (the contract: never fatal)
			continue
		}
		_ = m.NoteFlow(ev.Key())
		n++
	}
}

var _ = atomic.AddUint64
