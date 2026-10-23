// judge.go carries the T4 async judge contract (the spec's hand-off item 4 plus risk row R6):
// the expensive/remote classifier seam, its non-blocking submission queue,
// and the verdict delivery/caching shape. The judge is suspicious-only,
// never blocks the request path, and its verdicts are cached (TTL +
// model tag). JudgeVerdict carries no enforcement action on purpose — a
// judge result annotates and evidences, never decides alone (verdicts are
// never LLM-only, the spec's hand-off item 4).
package ml

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Judge is the T4 async judge contract's classifier seam (the spec's hand-off item 4):
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
// annotate, never decide (the spec's item-4 hand-off rule, pinned by the log-only
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
	// Reason is the analyst-loop explanation (the spec's hand-off rule: every ML verdict
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

// JudgeSink receives each delivered verdict record (the spec's analyst
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

// judgeTask is one queued submission: the extracted FeatureView + its
// normalized request signature (the cache key) — never raw request text.
type judgeTask struct {
	fv  FeatureView
	sig string
}

// AsyncJudge is the T4 async judge: a single worker draining a bounded
// queue, caching + delivering each verdict. Dropped counts refused
// submissions (the spec's R6 risk row: the async judge never blocks); Failures counts
// judge-call errors; SinkErrors counts failed record deliveries. All
// three are plain counters — the TR-11 exporter owns rates.
//
// Close stops accepting, drains the queued work, and waits for the
// worker; Submit must not race Close (a send on a closed queue panics —
// the stage wiring owns the lifecycle: submissions stop before Close).
type AsyncJudge struct {
	judge      Judge
	queue      chan judgeTask
	cache      *VerdictCache
	sink       JudgeSink
	now        func() time.Time
	mu         sync.Mutex
	inFlight   map[string]struct{}
	Dropped    atomic.Int64
	Failures   atomic.Int64
	SinkErrors atomic.Int64
	done       chan struct{}
}

// NewAsyncJudge builds and starts the judge worker. A nil judge, a
// non-positive queue capacity, a nil cache or a nil clock is a wiring
// error; a nil sink is allowed (cache-only deployment).
func NewAsyncJudge(cfg JudgeConfig) (*AsyncJudge, error) {
	if cfg.Judge == nil {
		return nil, fmt.Errorf("async judge: nil judge")
	}
	if cfg.QueueCap <= 0 {
		return nil, fmt.Errorf("async judge: queue cap %d must be positive", cfg.QueueCap)
	}
	if cfg.Cache == nil {
		return nil, fmt.Errorf("async judge: nil verdict cache")
	}
	if cfg.Now == nil {
		return nil, fmt.Errorf("async judge: nil clock")
	}
	a := &AsyncJudge{
		judge:    cfg.Judge,
		queue:    make(chan judgeTask, cfg.QueueCap),
		cache:    cfg.Cache,
		sink:     cfg.Sink,
		now:      cfg.Now,
		inFlight: map[string]struct{}{},
		done:     make(chan struct{}),
	}
	go a.worker()
	return a, nil
}

// ID names the judge model (the verdict-cache tag).
func (a *AsyncJudge) ID() string { return a.judge.ID() }

// Submit queues one suspicious submission NON-BLOCKING (the spec's R6 risk row): a full
// queue drops and counts; a signature already in flight or freshly judged
// is skipped (the spec's ML-hand-off oracle rate-limit).
func (a *AsyncJudge) Submit(fv FeatureView, sig string) {
	a.mu.Lock()
	if _, ok := a.inFlight[sig]; ok {
		a.mu.Unlock()
		return // one oracle call per signature at a time
	}
	if _, ok := a.cache.Get(sig, a.judge.ID()); ok {
		a.mu.Unlock()
		return // fresh verdict already judged
	}
	a.inFlight[sig] = struct{}{}
	a.mu.Unlock()
	select {
	case a.queue <- judgeTask{fv: fv, sig: sig}:
	default:
		a.mu.Lock()
		delete(a.inFlight, sig)
		a.mu.Unlock()
		a.Dropped.Add(1) // the spec's R6 risk row: the async judge never blocks
	}
}

// Close stops accepting, drains the queued work, and waits for the worker.
func (a *AsyncJudge) Close() error {
	close(a.queue)
	<-a.done
	return nil
}

// worker drains the queue to the end (range over the closed channel), so
// Close returns only after every accepted submission is judged, cached
// and delivered-or-counted.
func (a *AsyncJudge) worker() {
	defer close(a.done)
	for t := range a.queue {
		v, err := a.judge.Judge(t.fv)
		a.mu.Lock()
		delete(a.inFlight, t.sig)
		a.mu.Unlock()
		if err != nil {
			a.Failures.Add(1)
			continue // nothing cached, nothing delivered: the next fresh request may re-judge
		}
		v.ModelID = a.judge.ID() // the single stamping home
		a.cache.Put(t.sig, v.ModelID, v)
		if a.sink != nil {
			rec := JudgeRecord{Signature: t.sig, FeatureView: t.fv, Verdict: v, AtSec: a.now().Unix()}
			if serr := a.sink.Record(rec); serr != nil {
				a.SinkErrors.Add(1)
			}
		}
	}
}
