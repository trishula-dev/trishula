// judge.go carries the T4 async judge contract (§14.2 item 4 + §20.1 R6):
// the expensive/remote classifier seam, its non-blocking submission queue,
// and the verdict delivery/caching shape. The judge is suspicious-only,
// never blocks the request path, and its verdicts are cached (TTL +
// model tag). JudgeVerdict carries no enforcement action on purpose — a
// judge result annotates and evidences, never decides alone (verdicts are
// never LLM-only, §14.2 item 4).
package ml

import (
	"sync/atomic"
	"time"
)

// Judge is the T4 async judge contract's classifier seam (§14.2 item 4):
// Judge answers one semantic verdict over the extracted FeatureView. ID
// names the judge model — it tags both the cache and each verdict.
// Judge runs inside the worker goroutine only; it may block freely (the
// request path never waits on it).
type Judge interface {
	ID() string
	Judge(fv FeatureView) (JudgeVerdict, error)
}

// JudgeVerdict is one judged verdict. It carries NO enforcement action on
// purpose: the type cannot express a decision, so a judge result can
// annotate, never decide (the §14.2 item-4 rule, pinned by the log-only
// fragment test on the S7 stage).
type JudgeVerdict struct {
	// Label is the judge's model-dependent semantic label (a free string:
	// the label vocabulary is the judge model's, not the engine's).
	Label string `json:"label"`
	// ModelID is the judge model tag (stamped by AsyncJudge, the single
	// home for the stamp).
	ModelID string `json:"modelId"`
	// Confidence is the judge's self-reported confidence in [0, 1].
	Confidence float64 `json:"confidence"`
	// Reason is the analyst-loop explanation (§14.2: every ML verdict
	// carries an explanation).
	Reason string `json:"reason,omitempty"`
}

// JudgeRecord is one analyst-loop delivery: the judged submission with its
// aggregate features (never raw payload text — the FeatureView contract)
// and the verdict explanation.
type JudgeRecord struct {
	Signature   string       `json:"signature"`
	FeatureView FeatureView  `json:"featureView"`
	Verdict     JudgeVerdict `json:"verdict"`
	AtSec       int64        `json:"atSec"` // judge clock seconds
}

// JudgeSink receives each delivered verdict record (the §14.2 analyst
// loop; the TR-11 OTel pipeline implements it, tests collect).
type JudgeSink interface {
	Record(JudgeRecord) error
}

// JudgeSinkFunc adapts a func to JudgeSink.
type JudgeSinkFunc func(JudgeRecord) error

// Record implements JudgeSink.
func (f JudgeSinkFunc) Record(r JudgeRecord) error { return f(r) }

// JudgeConfig wires an AsyncJudge (deps injected; no package-side defaults).
type JudgeConfig struct {
	// Judge is the required classifier seam.
	Judge Judge
	// QueueCap is the bounded submission queue size; a full queue drops
	// (never blocks).
	QueueCap int
	// Cache is the required verdict cache (fresh verdicts gate re-judging).
	Cache *VerdictCache
	// Sink is optional: nil = cache-only (verdicts cache, nothing delivers).
	Sink JudgeSink
	// Now is the required judge clock (records stamp it).
	Now func() time.Time
}

// AsyncJudge is the T4 async judge: a single worker draining a bounded
// queue, caching + delivering each verdict. Dropped counts refused
// submissions (§20.1 R6: the async judge never blocks); Failures counts
// judge-call errors; SinkErrors counts failed record deliveries. All
// three are plain counters — the TR-11 exporter owns rates.
type AsyncJudge struct {
	Dropped    atomic.Int64
	Failures   atomic.Int64
	SinkErrors atomic.Int64
}

// NewAsyncJudge builds and starts the judge worker. A nil judge, a
// non-positive queue capacity, a nil cache or a nil clock is a wiring
// error; a nil sink is allowed (cache-only deployment).
func NewAsyncJudge(cfg JudgeConfig) (*AsyncJudge, error) {
	return &AsyncJudge{}, nil // TR-21 RED stub
}

// ID names the judge model (the verdict-cache tag).
func (a *AsyncJudge) ID() string { return "" } // TR-21 RED stub

// Submit queues one suspicious submission NON-BLOCKING (§20.1 R6): a full
// queue drops and counts; a signature already in flight or freshly judged
// is skipped (the §14.2 oracle rate-limit). Judge input is the extracted
// FeatureView + its signature (the cache key), never raw request text.
func (a *AsyncJudge) Submit(fv FeatureView, sig string) {}

// Close stops accepting, drains the queued work, and waits for the worker.
func (a *AsyncJudge) Close() error { return nil } // TR-21 RED stub
