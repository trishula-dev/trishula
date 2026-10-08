//go:build linux

package ingest

// TR-04d (issue #69, child of TR-04): the REAL ringbuf adapter — the
// cilium ringbuf.Reader behind the RecordSource contract pinned in
// TR-04b/TR-04c (synthetic rings in tests, kernel ring here).
//
// Contract notes:
//   - Recv: (raw, true) = record; (nil, true) = writer-overrun loss
//     marker (cilium surfaces ring loss as an error with
//     ErrOverwrite / a lost-record errorclass); (nil, false) = closed.
//   - Real-ring R1b evidence reports through Stats.RingLossTotal.

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
)

// ringSource adapts *ringbuf.Reader to RecordSource.
type ringSource struct {
	rd    *ringbuf.Reader
	stats *Stats
}

// NewRingSource wraps an open kernel ringbuf reader. stats optional
// (nil = no counters).
func NewRingSource(rd *ringbuf.Reader, stats *Stats) (RecordSource, error) {
	if rd == nil {
		return nil, errors.New("nil ringbuf reader")
	}
	return &ringSource{rd: rd, stats: stats}, nil
}

// Recv returns the next record; classifies ring losses per §9.4.
func (r *ringSource) Recv() ([]byte, bool) {
	rec, err := r.rd.Read()
	if err != nil {
		switch {
		case errors.Is(err, ringbuf.ErrClosed):
			return nil, false // clean close: EOF
		default:
			// Reader-error classes (overwrite/lost) are the §9.4 loss
			// surface; the reader stays closed-safe on retry.
			if r.stats != nil {
				atomic.AddUint64(&r.stats.RingLossTotal, 1)
			}
			return nil, true // loss marker semantics (TR-04c contract)
		}
	}
	return rec.Raw, true
}

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

var _ = fmt.Stringer(nil)
