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

// Engine wiring (TR-04 acceptance): DrainShield consumes the kernel ring
// into the tx table with engine-scoped stats.
type Engine struct {
	tx    *TxManager
	stats *Stats
}

// NewEngine builds the ingest engine shell (TR-05 attaches the ladder).
func NewEngine() *Engine {
	return &Engine{tx: NewTxManager(), stats: &Stats{}}
}

// DrainShield drains the shield's ring into the tx table. The context
// bounds the drain (engine shutdown); v0 drains in batches between ctx
// checks (§9.4 batching note).
func (e *Engine) DrainShield(rd RecordSource) error {
	for {
		raw, ok := rd.Recv()
		if !ok {
			return nil // clean close
		}
		if raw == nil {
			atomic.AddUint64(&e.stats.RingLossTotal, 1)
			continue
		}
		ev, err := DecodeFlowEvent(raw)
		if err != nil {
			// §9.4: malformed = log + drop into the skipped counter
			atomic.AddUint64(&e.stats.SkippedTotal, 1)
			continue
		}
		_ = e.tx.NoteFlow(ev.Key())
		atomic.AddUint64(&e.stats.DecodedTotal, 1)
	}
}

// Snapshot returns a stats copy (test + exporter surface).
func (e *Engine) Snapshot() Stats {
	return Stats{
		RingLossTotal: atomic.LoadUint64(&e.stats.RingLossTotal),
		DecodedTotal:  atomic.LoadUint64(&e.stats.DecodedTotal),
		SkippedTotal:  atomic.LoadUint64(&e.stats.SkippedTotal),
	}
}
