// Package otel implements the §15 verdict observability pipeline v0 (TR-11):
// one call, three correlated signals — a span, a metric datapoint and a log
// record — all keyed by the request id, emitted in-process through the
// OpenTelemetry Go SDK (no collector, no network exporters; the collector
// deployment is TR-08c/TR-23's business and reuses this schema verbatim).
//
// Pipeline shape
//
//	Emit(ctx, tx, verdict) starts the `trishula.verdict` span, feeds the
//	`verdicts_total` counter and emits one INFO log record `trishula.verdict`
//	on the SAME span context — every signal shares the request id + trace id.
//	Signal construction order: span span started → metric + log recorded →
//	span ended (the log record's trace_id is filled by the SDK from ctx while
//	the span is still recording).
//
// Correlation keys (read these before touching the collector config)
//
//   - request.id — present on ALL THREE signals. The per-request correlation
//     key (the TR-11 acceptance). The request id travels in the context:
//     inject with ContextWithRequestID (wire.Middleware does this from the
//     X-Request-ID header, falling back to a generated id).
//   - trace_id / span_id — structural fields (not attributes) on the span and
//     on the log record's TraceContext; the collector renders them as
//     trace_id/span_id on both signal types.
//
// Attribute schema (v0 — names and value shapes are the TR-08c/TR-23
// contract; all values are the literal string forms below):
//
//	Resource (shared by every signal):
//	  service.name = the configured service name (default "trishula-engine")
//
//	Span `trishula.verdict` + same attrs on the log record:
//	  request.id     = string   (the correlation key)
//	  verdict.action = string   → "allow"|"log"|"block"|"challenge"|"ban"
//	                             (ladder.Action vocabulary, §19.1)
//	  verdict.phase  = string   → ladder.Phase ("request_headers", …)
//	  verdict.route  = string   → tx metadata hint key "http.path" (TR-04b),
//	                             "-" when absent
//	  verdict.rules  = string   → ladder Verdict.Rules comma-joined, "" if none
//	  verdict.score  = integer  → ladder Verdict.Score (log record carries the
//	                             same integer; the string form is what the
//	                             test snapshot prints)
//
//	Metric `verdicts_total` (Int64Counter / Sum, monotonic):
//	  request.id     = string   — KEPT in v0 so the acceptance "all three
//	                             signals correlate by request id" holds
//	                             end-to-end; the collector cutover (TR-08c)
//	                             decides whether it moves to exemplars
//	  verdict.action = string   (as above)
//	  verdict.phase  = string   (as above)
//	  verdict.route  = string   (as above)
//
//	Log record `trishula.verdict`:
//	  body           = "verdict <action> request=<request id>" (string)
//	  severity       = INFO (log.SeverityInfo)
//	  event_name     = "trishula.verdict"
//	  attrs          = the same set as the span (request.id, verdict.*)
//
// The middleware span `trishula.request` (wire.go) carries request.id,
// http.method and http.path as string attrs and parents the verdict span.
package otel

import (
	"context"
	"errors"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// Attribute keys (the schema above; the only place these literals live).
const (
	AttrRequestID     = "request.id"
	AttrVerdictAction = "verdict.action"
	AttrVerdictPhase  = "verdict.phase"
	AttrVerdictRoute  = "verdict.route"
	AttrVerdictRules  = "verdict.rules"
	AttrVerdictScore  = "verdict.score"
	AttrHTTPMethod    = "http.method"
	AttrHTTPPath      = "http.path"
	AttrServiceName   = "service.name"
)

// MetaPathHint is the TxContext.Metadata key the pipeline reads the route
// value from (TR-04b fills it on the ingest side).
const MetaPathHint = "http.path"

// DefaultServiceName is the resource service.name when Config leaves it empty.
const DefaultServiceName = "trishula-engine"

// Sentinel errors (errors.Is-able, per the repo's explicit-error convention).
var (
	// ErrNotWired: New has not been given a working pipeline body yet (
	// RED state of TR-11a; the GREEN commit replaces this).
	ErrNotWired = errors.New("otel: verdict pipeline not wired")
	// ErrNoRequestID: Emit called without a request id in the context.
	// Correlation is the pipeline's contract — it refuses to emit signals
	// that cannot be correlated.
	ErrNoRequestID = errors.New("otel: request id absent from context")
	// ErrNilVerdict: Emit called with a nil verdict.
	ErrNilVerdict = errors.New("otel: nil verdict")
	// ErrShutdown: Emit called after Pipeline.Shutdown completed.
	ErrShutdown = errors.New("otel: pipeline shut down")
)

// Config configures the pipeline. Zero value is valid (DefaultServiceName).
type Config struct {
	// ServiceName lands on every signal's resource as service.name.
	ServiceName string
}

// Correlation is what one Emit produced, keyed identically to the emitted
// signals; callers log it, tests assert it.
type Correlation struct {
	RequestID string
	TraceID   string
	SpanID    string
}

// Pipeline emits the three correlated verdict signals per request+verdict
// (§15 v0, in-process SDK only).
type Pipeline struct{}

// New builds the verdict pipeline v0.
func New(Config) (*Pipeline, error) { return nil, ErrNotWired }

// Emit walks one request+verdict through the three-signal triad. The request
// id comes from the context (ContextWithRequestID / wire.Middleware); the
// returned Correlation names exactly the ids the emitted signals carry.
func (p *Pipeline) Emit(ctx context.Context, tx *ingest.TxContext, v *ladder.Verdict) (Correlation, error) {
	return Correlation{}, ErrNotWired
}

// Shutdown flushes and stops all three providers. Emit after Shutdown
// reports ErrShutdown. Safe to call twice (second call is a no-op).
func (p *Pipeline) Shutdown(ctx context.Context) error { return ErrNotWired }

// Exporter returns the pipeline's in-memory exporter (the test surface and
// the v0 "collector output"). Same instance every call.
func (p *Pipeline) Exporter() *Exporter { return nil }

// ctxKey is the unexported context key type for the request id.
type ctxKey struct{}

// ContextWithRequestID attaches the request id to ctx (empty id = detached;
// reads report not-found).
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestIDFromContext reads the request id back (found=false when absent).
func RequestIDFromContext(ctx context.Context) (string, bool) {
	return "", false
}
