package shield

// TR-10 (issue #10) evidence sink — RED stub.
//
// A BanRecord is the §13.5 ban-evidence row for one enforcement act: the
// engine's R11 account carried verbatim, plus the enforcement deltas the
// shadow path cannot know (the kernel-clock publish instant, verdict
// enrichment, the publish outcome). Sinks are append-only JSONL in memory
// with an optional file sink for the lab.
type BanRecord struct{}

// JSONLEvidenceSink collects one BanRecord per ban. RED stub — the GREEN
// commit implements the buffer + file append.
type JSONLEvidenceSink struct{}

// NewJSONLEvidenceSink builds an empty evidence sink. RED stub.
func NewJSONLEvidenceSink() *JSONLEvidenceSink { panic("TR-10 GREEN pending: NewJSONLEvidenceSink") }

// Count returns the number of records buffered (memory is authoritative;
// the file is a lab projection). RED stub.
func (s *JSONLEvidenceSink) Count() int { panic("TR-10 GREEN pending: Count") }

// Records returns the buffered records oldest-first (for OTLP/log wiring
// and tests). RED stub.
func (s *JSONLEvidenceSink) Records() []BanRecord {
	panic("TR-10 GREEN pending: Records")
}

// AppendFile streams every buffered record as one JSON line to path
// (create/truncate), then flushes each new record on Record(). RED stub.
func (s *JSONLEvidenceSink) AppendFile(path string) error {
	panic("TR-10 GREEN pending: AppendFile")
}

// Record implements EvidenceSink (RED stub).
func (s *JSONLEvidenceSink) Record(r BanRecord) error {
	panic("TR-10 GREEN pending: Record")
}
