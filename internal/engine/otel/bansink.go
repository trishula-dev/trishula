package otel

// bansink.go — TR-195 leaf 3 (issue #237): the verdict pipeline's ban
// sink. The rateban engine's evidence surface has two readers: the
// engine's own records (the JSONL the tests read) and the verdict
// pipeline's ban log record. The record states the ban key, tier, score,
// reasons and, when present, the dynamic signature verdict.dos.sig.

import (
	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

// BanLogSink emits every would-ban the rateban engine produces as a
// trishula.ban log record through the pipeline (EmitBan; the in-process
// exporter = the v0 surface, the collector cutover is the TR-08c/TR-23
// scope and reuses the schema verbatim).
type BanLogSink struct{ p *Pipeline }

// NewBanLogSink wires the pipeline as a rateban evidence sink. p must be
// non-nil.
func NewBanLogSink(p *Pipeline) *BanLogSink {
	if p == nil {
		panic("otel: nil pipeline")
	}
	return &BanLogSink{p: p}
}

// Record publishes one would-ban (EmitBan's error is the sink's error; a
// failed sink never hides the record — the engine's fanout joins it with
// the other sinks' receipts).
func (s *BanLogSink) Record(b rateban.BanEvidence) error {
	return s.p.EmitBan(b)
}
