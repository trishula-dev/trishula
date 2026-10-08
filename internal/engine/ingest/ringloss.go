package ingest

import "sync/atomic"

// Stats is the engine-scoped ingest telemetry (TR-11 binds
// trishula_shield_ring_dropped_total to RingLossTotal; PRD §9.4/§21).
// Atomic: the reader goroutine writes; OTel exporters read.
type Stats struct {
	RingLossTotal uint64 // records lost to ring overruns
	DecodedTotal  uint64 // clean decodes (lifecycle telemetry)
	SkippedTotal  uint64 // malformed records (log-warned)
}

// lossMarker tells the drain loop the writer overran: records before the
// next good record are gone (cilium ringbuf surfaces the same condition
// as an OutOfMemory/overrun errorclass on the real reader).
type lossMarker struct{}

// DrainStats returns the injectable stats handle (nil = counter-only).
func DrainStats(s *Stats) DrainOption { return DrainOption{s} }

// DrainOption carries optional drain configuration (v0: stats only).
type DrainOption struct{ stats *Stats }

// lossyRing is a synthetic ring interleaving loss markers with records.
type lossyRing struct {
	items []any // *synItem with bytes, or lossMarker
	i     int
}

type synItem struct {
	raw   []byte
	clean bool
}

// newLossyRing builds the interleaved test ring: bare lossMarker{} values
// (overrun) and syntheticEvent() bytes (decode me).
func newLossyRing(items ...any) *lossyRing {
	r := &lossyRing{}
	for _, it := range items {
		switch t := it.(type) {
		case lossMarker:
			r.items = append(r.items, t)
		case []byte:
			r.items = append(r.items, synItem{raw: t, clean: true})
		default:
			r.items = append(r.items, lossMarker{})
		}
	}
	return r
}

func (r *lossyRing) Recv() ([]byte, bool) {
	if r.i >= len(r.items) {
		return nil, false
	}
	it := r.items[r.i]
	r.i++
	if s, ok := it.(synItem); ok {
		return s.raw, true
	}
	return nil, true // lossMarker: ok=true + nil bytes = writer-overrun loss
}

// Drain is the loss-aware drain (TR-04c): per-pass results plus optional
// engine-scoped Stats; the loss marker bumps RingLoss(Total), malformed
// records bump Skipped(Total) exactly like TR-04b's pass, clean decodes
// bump Decoded counts.
func Drain(m *TxManager, rd RecordSource, opts ...DrainOption) DrainResult {
	var st *Stats
	for _, o := range opts {
		if o.stats != nil {
			st = o.stats
		}
	}
	var res DrainResult
	for {
		raw, ok := rd.Recv()
		if !ok {
			break
		}
		if raw == nil {
			// writer overrun: the record is GONE (not decodable)
			res.RingLoss++
			if st != nil {
				atomic.AddUint64(&st.RingLossTotal, 1)
			}
			continue
		}
		ev, err := DecodeFlowEvent(raw)
		if err != nil {
			res.Skipped++
			if st != nil {
				atomic.AddUint64(&st.SkippedTotal, 1)
			}
			continue
		}
		_ = m.NoteFlow(ev.Key())
		res.Decoded++
		if st != nil {
			atomic.AddUint64(&st.DecodedTotal, 1)
		}
	}
	return res
}
