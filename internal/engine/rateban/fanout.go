package rateban

import "errors"

// fanout.go — TR-195 leaf 3 (issue #237): one would-ban, many receipts.
// The ban engine owns ONE evidence sink seat; the operators of the surface
// (the JSONL receipts, the OTel verdict pipeline) share it through the
// fanout. Every sink receives the record; one failing sink never hides the
// others (the errors join; the receipts are fire-and-evidence, never
// enforcement: fail-open on sink health, fail-closed on records).

// FanoutSink fans one BanEvidence out to every sink, in order.
type FanoutSink []EvidenceSink

// Record delivers the record to every sink and joins the errors (empty
// fanout = a no-op; one bad sink never drops the others' receipts).
func (f FanoutSink) Record(r BanEvidence) error {
	var errs []error
	for _, s := range f {
		if s == nil {
			continue
		}
		if err := s.Record(r); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NewFanoutSink builds a fanout over the sinks (nil entries are skipped at
// record time; the sink list stays readable at construction).
func NewFanoutSink(sinks ...EvidenceSink) EvidenceSink {
	return FanoutSink(sinks)
}
