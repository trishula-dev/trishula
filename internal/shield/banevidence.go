package shield

// TR-10 (issue #10): the ban evidence stream (§13.5 + R11). One record per
// enforcement act: the engine's R11 account carried verbatim, plus the
// enforcement deltas the shadow path cannot know (the kernel-clock publish
// instant, the wire reason code, the publish outcome).
//
// JSONLEvidenceSink is append-only JSONL: an in-memory buffer (memory is
// authoritative) with an optional file sink for the lab. Constructed
// kernel-free (MapPublisher handles), so the CI suite runs it host-portably.
import (
	"bufio"
	"encoding/json"
	"os"
	"sync"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

// BanRecord is the §13.5 ban-evidence row for one enforcement act. The R11
// fields (key/score/threshold/events/reasonCodes/bantimeSec) arrive
// verbatim from the engine's BanEvidence; the enforcement deltas are the
// source IP, the wire reason code, the kernel-clock publish instant
// (UntilMS), the centi-score the wire carries and the publish outcome.
type BanRecord struct {
	Key         string                  `json:"key"`
	Mode        string                  `json:"mode"`
	Verdict     string                  `json:"verdict"`
	Tier        string                  `json:"tier"`
	Score       float64                 `json:"score"`
	Threshold   float64                 `json:"threshold"`
	Events      []rateban.EvidenceEvent `json:"events,omitempty"`
	ReasonCodes []string                `json:"reasonCodes,omitempty"`
	AtSec       int64                   `json:"atSec"`
	UntilSec    int64                   `json:"untilSec"`
	Recidivism  int                     `json:"recidivism"`
	BantimeSec  int64                   `json:"bantimeSec"`
	Note        string                  `json:"note,omitempty"`

	// Enforcement deltas (kernel plane).
	SourceIP   string `json:"sourceIP,omitempty"`
	ReasonCode uint16 `json:"reasonCode,omitempty"`
	UntilMS    uint64 `json:"untilMs"`
	ScoreCenti uint16 `json:"scoreCenti"`
	Published  bool   `json:"published"`
	PublishErr string `json:"publishErr,omitempty"`
}

// JSONLEvidenceSink collects one BanRecord per ban. Append-only JSONL in
// memory (memory is authoritative) with an optional file sink for the lab.
type JSONLEvidenceSink struct {
	mu  sync.Mutex
	buf []BanRecord
	w   *bufio.Writer
	f   *os.File
}

// NewJSONLEvidenceSink builds an empty evidence sink.
func NewJSONLEvidenceSink() *JSONLEvidenceSink { return &JSONLEvidenceSink{} }

// Count returns the number of records buffered (memory is authoritative;
// the file is a lab projection).
func (s *JSONLEvidenceSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf)
}

// Records returns the buffered records oldest-first (for OTLP/log wiring
// and tests).
func (s *JSONLEvidenceSink) Records() []BanRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]BanRecord, len(s.buf))
	copy(out, s.buf)
	return out
}

// Record implements EvidenceSink: one record per ban, JSON-line-encoded
// to the file sink when one has been AppendFile'd.
func (s *JSONLEvidenceSink) Record(r BanRecord) error {
	s.mu.Lock()
	s.buf = append(s.buf, r)
	w, f := s.w, s.f
	s.mu.Unlock()
	if w == nil {
		return nil
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if f != nil {
		return f.Sync()
	}
	return nil
}

// AppendFile streams every buffered record as one JSON line to path
// (create/truncate), then flushes each new record on Record().
func (s *JSONLEvidenceSink) AppendFile(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, r := range s.buf {
		line, err := json.Marshal(r)
		if err != nil {
			f.Close()
			return err
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	s.w = w
	s.f = f
	return nil
}
