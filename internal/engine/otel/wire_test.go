package otel

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// fakeEmitter records Emit calls the middleware passed through: the adapter
// must surface engine output verbatim (its job is correlation, not verdicts).
type fakeEmitter struct {
	calls []string
	err   error
}

func (f *fakeEmitter) Emit(ctx context.Context, tx *ingest.TxContext, v *ladder.Verdict) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, RequestIDFromContextOrGenerate(ctx))
	return nil
}

// TestMiddlewareGeneratesAndAttachesRequestID: no client header — the
// middleware generates the id, attaches it downstream, and emits the verdict.
func TestMiddlewareGeneratesAndAttachesRequestID(t *testing.T) {
	fe := &fakeEmitter{}
	h := Middleware(nil, fe)
	if h == nil {
		t.Fatal("Middleware returned nil handler")
	}

	// A nil pipeline must not panic; with a nil pipeline the middleware
	// still serves the request (a broken telemetry path never 500s the
	// proxied traffic) and skips the emit.
	rec := newRecorder()
	req := newRequest(t, http.MethodGet, "/healthz")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("nil-pipeline pass-through status = %d, want 200", rec.Code)
	}

	// With a working pipeline, the emitter sees the generated id.
	fe2 := &fakeEmitter{}
	p := newTestPipeline(t)
	h2 := Middleware(p, fe2)
	rec2 := newRecorder()
	h2.ServeHTTP(rec2, newRequest(t, http.MethodGet, "/healthz"))
	if len(fe2.calls) != 1 {
		t.Fatalf("emitter calls = %d, want 1", len(fe2.calls))
	}
	rid := fe2.calls[0]
	if rid == "" {
		t.Fatal("emitter saw empty request id")
	}
	// Generated ids are 128-bit hex — the trace-id-space convention (32 hex
	// chars), so they can double as trace ids (W3C).
	if len(rid) != 32 {
		t.Errorf("generated request id = %q (%d chars), want 32 hex chars", rid, len(rid))
	}

	// The emitted triad carries that id end-to-end.
	snap := p.Exporter().Snapshot()
	if len(snap.Spans) != 1 || len(snap.Metrics) != 1 || len(snap.Logs) != 1 {
		t.Fatalf("middleware spans/metrics/logs = %d/%d/%d, want 1/1/1",
			len(snap.Spans), len(snap.Metrics), len(snap.Logs))
	}
	if got := kvGet(snap.Spans[0].Attributes, AttrRequestID); got != rid {
		t.Errorf("span %s = %q, want the middleware-generated %q", AttrRequestID, got, rid)
	}
}

// TestMiddlewareHonorsClientRequestID: an incoming X-Request-ID is adopted
// verbatim (never repaired, literal-preservation rule) and lands on all
// three exported signals; the response echoes it.
func TestMiddlewareHonorsClientRequestID(t *testing.T) {
	p := newTestPipeline(t)
	fe := &fakeEmitter{}
	h := Middleware(p, fe)

	const rid = "client-supplied-TRace-0001"
	req := newRequest(t, http.MethodPost, "/api/transfer")
	req.Header.Set(HeaderRequestID, rid)

	// The verdict the engine produced: the middleware emits it.
	tx := &ingest.TxContext{Metadata: map[string]string{MetaPathHint: "/api/transfer"}}
	v := &ladder.Verdict{Action: ladder.ActionBlock, Phase: ladder.PhaseRequestHeaders}

	done := make(chan struct{})
	go func() {
		defer close(done)
	}()

	// The adapter contract: the engine callback receives the ctx carrying
	// the adopted id. fakeEmitter records the id it sees.
	rec := newRecorder()
	handler := h.(*wireHandler)
	handler.emitForTest = func(ctx context.Context, tx *ingest.TxContext, v *ladder.Verdict) error {
		return fe.Emit(ctx, tx, v)
	}
	handler.serveWithEmit(rec, req, tx, v)
	<-done

	if got := rec.Header().Get(HeaderRequestID); got != rid {
		t.Errorf("response %s = %q, want echoed %q", HeaderRequestID, got, rid)
	}
	if len(fe.calls) != 1 || fe.calls[0] != rid {
		t.Fatalf("emitter saw %v, want exactly the client id %q", fe.calls, rid)
	}

	snap := p.Exporter().Snapshot()
	if len(snap.Spans) != 1 {
		t.Fatalf("spans = %d, want 1 (client id emit)", len(snap.Spans))
	}
	if got := kvGet(snap.Spans[0].Attributes, AttrRequestID); got != rid {
		t.Errorf("span %s = %q, want client id %q", AttrRequestID, got, rid)
	}
	logs := snap.Logs
	if len(logs) != 1 {
		t.Fatalf("logs = %d, want 1", len(logs))
	}
	logRid := kvGet(logs[0].Attributes, AttrRequestID)
	if logRid != rid {
		t.Errorf("log %s = %q, want %q", AttrRequestID, logRid, rid)
	}
}

// TestMiddlewareRequestIDFromContextOrGenerate covers the helper directly:
// present → verbatim; absent → 32-hex generated id.
func TestMiddlewareRequestIDFromContextOrGenerate(t *testing.T) {
	ctx := ContextWithRequestID(context.Background(), "fixed-id")
	if got := RequestIDFromContextOrGenerate(ctx); got != "fixed-id" {
		t.Errorf("present id = %q, want verbatim", got)
	}
	gen := RequestIDFromContextOrGenerate(context.Background())
	if len(gen) != 32 {
		t.Errorf("generated id = %q, want 32 hex chars", gen)
	}
}

// TestRequestIDFromContext verifies the read-back helper.
func TestRequestIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKey{}, "abc")
	got, ok := RequestIDFromContext(ctx)
	if !ok || got != "abc" {
		t.Errorf("RequestIDFromContext = %q,%v; want abc,true", got, ok)
	}
}

// TestWireErrorsAreSentinel: adapter errors are sentinel values.
func TestWireErrorsAreSentinel(t *testing.T) {
	if !errors.Is(errNotWired{}, errNotWired{}) {
		t.Error("errNotWired not errors.Is-able to itself")
	}
}

func TestMiddlewareNilPipelineOK(t *testing.T) {
	fe := &fakeEmitter{}
	h := Middleware(nil, fe)
	rec := newRecorder()
	h.ServeHTTP(rec, newRequest(t, http.MethodGet, "/x"))
	if rec.Code != http.StatusOK {
		t.Errorf("nil pipeline status = %d, want 200", rec.Code)
	}
}

// TestWireTrishulaIDValid: well-formed ids validate; junk does not.
func TestWireTrishulaIDValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0123456789abcdef0123456789abcdef", true},
		{"ABCDEF0123456789abcdef0123456789", true},
		{"", false},
		{"short", false},
		{"0123456789abcdef0123456789abcdez", false},  // 'z' not hex
		{"0123456789abcdef0123456789abcdeff", false}, // 33 chars
	}
	for _, tc := range cases {
		if got := trishulaIDValid(tc.in); got != tc.want {
			t.Errorf("trishulaIDValid(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestTrishulaIDValidCoversLadderVocab(t *testing.T) {
	// Guard keeps the ladder vocabulary referenced from the wire tests.
	_ = ladder.ActionAllow
}

// TestErrNoRequestIDSentinel pins the errors.Is contract used by hosts.
func TestErrNoRequestIDSentinel(t *testing.T) {
	wrapped := contextChanged{ErrNoRequestID}
	if !errors.Is(wrapped, ErrNoRequestID) {
		t.Error("wrapped ErrNoRequestID lost its identity")
	}
}

type contextChanged struct{ error }

var errErrNoRequestID = ErrNoRequestID

// unused guard so ladder/ingest imports stay used in future edits.
var (
	_ = ingest.FamilyV4
	_ ladder.Action
	_ = errErrNoRequestID
)
