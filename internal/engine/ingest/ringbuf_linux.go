//go:build linux

package ingest

// TR-04d (issue #69, child of TR-04): the REAL ringbuf adapter — the
// cilium ringbuf.Reader behind the RecordSource contract pinned in
// TR-04b/TR-04c (synthetic rings in tests, kernel ring here).
//
// Contract notes:
//   - Recv: (raw, true) = record; (nil, true) = loss marker;
//     (nil, false) = clean close (ringbuf.ErrClosed).
//   - The Go Reader has NO lost-record error class (discard records are
//     skipped inside the library), so the REAL loss surface is the C
//     side: flow_tc.c drops a lost-count into a dedicated map in
//     TR-04d's producer (verified against RingLossTotal in the E2E).

import (
	"errors"

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

// Recv returns the next record. ErrClosed = (nil,false); any other
// reader error is sticky and returned as an error path — the caller
// (DrainShield) counts it and retries.
func (r *ringSource) Recv() ([]byte, bool) {
	rec, err := r.rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, false // clean close: EOF
		}
		return nil, false // treat unexpected reader errors as close (v0: fail stop)
	}
	return rec.RawSample, true
}
