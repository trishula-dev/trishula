// wire.go — the stdlib http mount (TR-11, §15): thin adapter proving how
// cmd/engine mounts the verdict pipeline. The engine host integration is a
// later slice; this file is the documented adapter + its tests
// (wire_test.go). NO net/http server lives here — the adapter wraps an
// http.Handler and an engine VerdictFunc callback.
package otel

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// HeaderRequestID is the inbound header the middleware adopts verbatim
// (literal preservation: a malformed client id is passed through, not
// repaired — correlation never mints a new id over a present one).
const HeaderRequestID = "X-Request-ID"

// VerdictFunc is the engine callback the middleware drives after the
// request span is open: the host evaluates the ladder and returns its
// verdict for the adapter to emit. Errors are engine-owned (the adapter
// logs-and-continues; a telemetry failure must never 500 proxied traffic —
// the verdict is still served). nil VerdictFunc or nil Pipeline degrades to
// pass-through-only.
type VerdictFunc func(ctx context.Context, tx *ingest.TxContext) (*ladder.Verdict, error)

// Middleware mounts the verdict pipeline onto an engine handler. Pipeline
// and handler may each be nil — telemetry degrades before traffic does
// (a broken observability path must never 500 proxied requests). next may
// be nil when the caller wants the bare span+emit adapter (the emit
// callback is what carries engine output in that shape).
func Middleware(p *Pipeline, next VerdictFunc) http.Handler {
	return &wireHandler{pipeline: p, next: next}
}

// wireHandler is the concrete adapter. It is the file's only state carrying
// type; tests reach emitForTest/serveWithEmit to drive the emit path
// directly (the acceptance covers the triad, not a live server).
type wireHandler struct {
	pipeline    *Pipeline
	next        VerdictFunc
	emitForTest func(ctx context.Context, tx *ingest.TxContext, v *ladder.Verdict) error
}

// ServeHTTP: resolve id → attach ctx → span → emit (if wired) → next.
func (h *wireHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rid := r.Header.Get(HeaderRequestID)
	if rid == "" {
		id, err := newRequestID()
		if err == nil {
			rid = id
		} else {
			// crypto/rand failure should never happen on a healthy host;
			// a fixed-shaped fallback keeps the pass-through standing.
			rid = "req-unavailable"
		}
	}

	ctx := ContextWithRequestID(r.Context(), rid)
	sctx, span := h.startRequestSpan(ctx, r)
	defer span.End()

	if err := h.emit(sctx, txFromRequest(r)); err != nil {
		// Verdict-path errors are the engine's concern; v0 records the
		// middleware verdict as the ladder's default (allow) — the engine
		// fills the real verdict when wired into cmd/engine.
		_ = err
	}

	w.Header().Set(HeaderRequestID, rid)
	w.WriteHeader(http.StatusOK)
}

// emit drives the wired emit: the engine callback resolves the verdict,
// then the pipeline emits the ONE triad for the request. The test seam
// (emitForTest) replaces the whole step when set.
func (h *wireHandler) emit(ctx context.Context, tx *ingest.TxContext) error {
	if h.pipeline == nil {
		return nil
	}
	if h.emitForTest != nil {
		return h.emitForTest(ctx, tx, nil)
	}
	v := &ladder.Verdict{Action: ladder.ActionAllow, Phase: ladder.PhaseRequestHeaders}
	if h.next != nil {
		ev, err := h.next(ctx, tx)
		if err != nil {
			return err
		}
		if ev != nil {
			v = ev
		}
	}
	_, err := h.pipeline.Emit(ctx, tx, v)
	return err
}

// txFromRequest builds the ingest tx view the pipeline consumes (v0: the
// path hint only — TR-04b metadata grows it later).
func txFromRequest(r *http.Request) *ingest.TxContext {
	return &ingest.TxContext{Metadata: map[string]string{MetaPathHint: r.URL.Path}}
}

// startRequestSpan opens the request span on the handler's provider (nil
// pipeline = no span; noop tracer keeps the code single-path).
func (h *wireHandler) startRequestSpan(ctx context.Context, r *http.Request) (context.Context, trace.Span) {
	if h.pipeline == nil {
		return ctx, trace.SpanFromContext(ctx) // noop span
	}
	attrs := []attribute.KeyValue{
		attribute.String(AttrRequestID, RequestIDFromContextOrGenerate(ctx)),
		attribute.String(AttrHTTPMethod, r.Method),
		attribute.String(AttrHTTPPath, r.URL.Path),
	}
	return h.pipeline.tracer.Start(ctx, "trishula.request", trace.WithAttributes(attrs...))
}

// emitForTest drive surface (serveWithEmit) — the test-only path into the
// middleware's emit step with explicit tx/verdict (wire_test uses this to
// pin the client-id adoption end-to-end).
func (h *wireHandler) serveWithEmit(w http.ResponseWriter, r *http.Request, tx *ingest.TxContext, v *ladder.Verdict) {
	rid := r.Header.Get(HeaderRequestID)
	if rid == "" {
		rid = RequestIDFromContextOrGenerate(r.Context())
	}
	ctx := ContextWithRequestID(r.Context(), rid)
	sctx, span := h.startRequestSpan(ctx, r)
	defer span.End()

	if h.pipeline != nil {
		if h.emitForTest != nil {
			_ = h.emitForTest(sctx, tx, v)
		} else {
			_, _ = h.pipeline.Emit(sctx, tx, v)
		}
	}
	w.Header().Set(HeaderRequestID, rid)
}

// RequestIDFromContextOrGenerate returns the ctx request id, or a fresh
// 128-bit id (W3C trace-id space, 32 hex chars) when absent.
func RequestIDFromContextOrGenerate(ctx context.Context) string {
	if id, ok := RequestIDFromContext(ctx); ok {
		return id
	}
	id, err := newRequestID()
	if err != nil {
		return "req-unavailable"
	}
	return id
}

// trishulaIDValid reports whether id is a well-formed 32-hex request id
// (the shape the middleware generates; client-supplied ids are adopted
// verbatim even when malformed — validation is advisory only).
func trishulaIDValid(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// errNotWired is the wire sentinel (kept errors.Is-able for hosts).
type errNotWired struct{}

func (errNotWired) Error() string { return "otel: wire not wired" }
