package ml

import (
	"sync/atomic"
	"testing"
	"time"
)

// --- fixtures -------------------------------------------------------------

// fakeJudge is the injected classifier seam (timer-free: a blocking judge
// waits on the release channel, so tests never race a wall clock). It
// counts calls, keeps the last judged feature view, and answers with a
// fixed label or the fixture error.
type fakeJudge struct {
	id      string
	release chan struct{} // nil = answer immediately
	entered chan struct{} // nil = no signal; a send inside Judge marks the call entry
	err     error
	label   string

	calls atomic.Int64
	last  atomic.Pointer[FeatureView]
}

func (f *fakeJudge) ID() string { return f.id }

func (f *fakeJudge) Judge(fv FeatureView) (JudgeVerdict, error) {
	f.calls.Add(1)
	cp := fv
	f.last.Store(&cp)
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.release != nil {
		<-f.release
	}
	if f.err != nil {
		return JudgeVerdict{}, f.err
	}
	return JudgeVerdict{Label: f.label, Confidence: 0.8}, nil
}

// countingSink records deliveries and their signatures.
type countingSink struct {
	sigs atomic.Int64 // delivered records
	dups atomic.Int64 // duplicate signature deliveries
	seen map[string]bool
}

func newCountingSink() *countingSink { return &countingSink{seen: map[string]bool{}} }

func (s *countingSink) Record(r JudgeRecord) error {
	if s.seen[r.Signature] {
		s.dups.Add(1)
	}
	s.seen[r.Signature] = true
	s.sigs.Add(1)
	return nil
}

// judgeFixture builds a standard AsyncJudge around the fake seam and
// hands back the cache + sink the tests assert on.
func judgeFixture(t *testing.T, j *fakeJudge, now func() time.Time, cap int) (*AsyncJudge, *VerdictCache, *countingSink) {
	t.Helper()
	sink := newCountingSink()
	cache := mustCache(t, now)
	a, err := NewAsyncJudge(JudgeConfig{Judge: j, QueueCap: cap, Cache: cache, Sink: sink, Now: now})
	if err != nil {
		t.Fatalf("NewAsyncJudge: %v", err)
	}
	return a, cache, sink
}

// --- AsyncJudge tests ------------------------------------------------------

// TestAsyncJudgeNeverBlocks is the §20.1 R6 pin: a full queue refuses the
// submission (counts a drop) and returns without waiting for the worker.
// Sequence is timer-free: the worker consumes the first submission and
// blocks inside Judge (the entered signal proves it), then the queue
// refills and the drop is deterministic.
func TestAsyncJudgeNeverBlocks(t *testing.T) {
	release := make(chan struct{})
	j := &fakeJudge{id: "j1", release: release, entered: make(chan struct{}, 1), label: "benign"}
	now := baseNow
	a, cache, sink := judgeFixture(t, j, fixtureClock(&now), 1)

	a.Submit(FeatureView{Method: "POST"}, "sigB")
	<-j.entered                                   // the worker is now blocked inside Judge: the queue slot is free
	a.Submit(FeatureView{Method: "GET"}, "sigA")  // refills the queue (full)
	a.Submit(FeatureView{Method: "HEAD"}, "sigC") // queue full: dropped
	if got := a.Dropped.Load(); got != 1 {
		t.Errorf("Dropped: got %d, want 1 (the full queue must refuse, never block)", got)
	}
	close(release)
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := j.calls.Load(); got != 2 {
		t.Errorf("judge calls: got %d, want 2 (the dropped task must never judge)", got)
	}
	if got := sink.sigs.Load(); got != 2 {
		t.Errorf("sink records: got %d, want 2", got)
	}
	if _, ok := cache.Get("sigC", "j1"); ok {
		t.Error("cache: the dropped submission must not judge or cache")
	}
}

// TestAsyncJudgeDedupAndDrain pins the oracle rate-limit (§14.2 item 4):
// one in-flight or fresh verdict per signature — duplicates never re-judge
// — and Close drains the queued work before returning.
func TestAsyncJudgeDedupAndDrain(t *testing.T) {
	j := &fakeJudge{id: "j1", label: "prompt-injection"}
	now := baseNow
	a, cache, sink := judgeFixture(t, j, fixtureClock(&now), 8)

	fvA := FeatureView{Method: "POST"}
	fvB := FeatureView{Method: "PUT"}
	a.Submit(fvA, "sigA")
	a.Submit(fvA, "sigA") // in-flight duplicate: skipped
	a.Submit(fvB, "sigB")
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := j.calls.Load(); got != 2 {
		t.Errorf("judge calls: got %d, want 2 (one per distinct signature)", got)
	}
	if got := sink.sigs.Load(); got != 2 {
		t.Errorf("sink records: got %d, want 2", got)
	}
	if got := sink.dups.Load(); got != 0 {
		t.Errorf("sink duplicate deliveries: got %d, want 0", got)
	}
	if j.last.Load() == nil || j.last.Load().Method != "PUT" {
		t.Errorf("judge input: got %+v, want the last queued submission (fvB)", j.last.Load())
	}
	got, ok := cache.Get("sigA", "j1")
	if !ok || got.Label != "prompt-injection" || got.ModelID != "j1" {
		t.Errorf("cache: got %+v ok=%v, want the judged verdict cached and model-stamped", got, ok)
	}
}

// TestAsyncJudgeCachedVerdictSkipsJudge pins the cache-gated rate limit: a
// fresh verdict for the signature means the judge is never called.
func TestAsyncJudgeCachedVerdictSkipsJudge(t *testing.T) {
	j := &fakeJudge{id: "j1", label: "prompt-injection"}
	now := baseNow
	cache := mustCache(t, fixtureClock(&now))
	cache.Put("sigA", "j1", JudgeVerdict{Label: "prompt-injection", ModelID: "j1"})
	a, err := NewAsyncJudge(JudgeConfig{Judge: j, QueueCap: 4, Cache: cache, Now: fixtureClock(&now)})
	if err != nil {
		t.Fatalf("NewAsyncJudge: %v", err)
	}
	a.Submit(FeatureView{Method: "POST"}, "sigA")
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := j.calls.Load(); got != 0 {
		t.Errorf("judge calls: got %d, want 0 (a fresh cached verdict gates the oracle)", got)
	}
}

// TestAsyncJudgeJudgeFailure pins the failure path: a judge error counts,
// caches nothing, and delivers no record.
func TestAsyncJudgeJudgeFailure(t *testing.T) {
	j := &fakeJudge{id: "j1", err: &judgeError{}}
	now := baseNow
	a, cache, sink := judgeFixture(t, j, fixtureClock(&now), 4)
	a.Submit(FeatureView{Method: "POST"}, "sigA")
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := a.Failures.Load(); got != 1 {
		t.Errorf("Failures: got %d, want 1", got)
	}
	if _, ok := cache.Get("sigA", "j1"); ok {
		t.Error("cache: a failed judgement must not cache")
	}
	if got := sink.sigs.Load(); got != 0 {
		t.Errorf("sink records: got %d, want 0", got)
	}
}

// judgeFixture2 wires an error-judge fixture set (cache + sink, no cap).
func judgeFixture2(t *testing.T, j *fakeJudge, now func() time.Time) (*AsyncJudge, *VerdictCache, *countingSink) {
	t.Helper()
	return judgeFixture(t, j, now, 4)
}

// TestAsyncJudgeValidates pins the wiring-error rows (and the allowed
// nil-sink cache-only deployment).
func TestAsyncJudgeValidates(t *testing.T) {
	now := baseNow
	cache := mustCache(t, fixtureClock(&now))
	judge := &fakeJudge{id: "j1"}
	rows := []struct {
		name   string
		cfg    JudgeConfig
		wantOk bool
	}{
		{"nil judge", JudgeConfig{QueueCap: 4, Cache: cache, Now: fixtureClock(&now)}, false},
		{"zero queue cap", JudgeConfig{Judge: judge, Cache: cache, Now: fixtureClock(&now)}, false},
		{"nil cache", JudgeConfig{Judge: judge, QueueCap: 4, Now: fixtureClock(&now)}, false},
		{"nil clock", JudgeConfig{Judge: judge, QueueCap: 4, Cache: cache}, false},
		{"valid, nil sink", JudgeConfig{Judge: judge, QueueCap: 4, Cache: cache, Now: fixtureClock(&now)}, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			a, err := NewAsyncJudge(r.cfg)
			if (err == nil) != r.wantOk {
				t.Errorf("NewAsyncJudge: err=%v, wantOk=%v", err, r.wantOk)
			}
			if err == nil && a.ID() != "j1" {
				t.Errorf("ID: got %q, want the judge's id", a.ID())
			}
		})
	}
}

// judgeError is the fixture judge error.
type judgeError struct{}

func (*judgeError) Error() string { return "judge boom" }

// mustCache builds a valid default cache for fixtures.
func mustCache(t *testing.T, now func() time.Time) *VerdictCache {
	t.Helper()
	c, err := NewVerdictCache(now, 16, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewVerdictCache: %v", err)
	}
	return c
}
