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
//	Signal construction order: span started → metric + log recorded →
//	span ended (the log record's trace_id is filled by the SDK from ctx while
//	the span is still recording). Spans and logs stream synchronously through
//	simple processors; the metric reader's one collection point is
//	Pipeline.Shutdown (deterministic — no periodic reader, no sleeps).
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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
	"go.opentelemetry.io/otel/attribute"
	apiLog "go.opentelemetry.io/otel/log"
	apiMetric "go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
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

// Telemetry surface names (signal names carry the trishula. namespace).
const (
	// ScopeName is the instrumentation scope for all three signals.
	ScopeName = "github.com/trishula-dev/trishula/internal/engine/otel"
	// SpanName is the per-verdict span (and the log record's event name).
	SpanName = "trishula.verdict"
	// MetricVerdicts is the verdict counter name.
	MetricVerdicts = "verdicts_total"
)

// DefaultServiceName is the resource service.name when Config leaves it empty.
const DefaultServiceName = "trishula-engine"

// Sentinel errors (errors.Is-able, per the repo's explicit-error convention).
var (
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
// (§15 v0, in-process SDK only): one call, one span + one metric datapoint
// + one log record, all wired to the same in-memory exporter.
type Pipeline struct {
	exp    *Exporter
	tp     *sdktrace.TracerProvider
	mp     *sdkmetric.MeterProvider
	lp     *sdklog.LoggerProvider
	mr     *sdkmetric.ManualReader
	tracer trace.Tracer
	count  apiMetric.Int64Counter
	logr   apiLog.Logger
	conf   Config
	done   bool
	mu     sync.Mutex
}

// New builds the verdict pipeline: three SDK providers over one in-memory
// exporter, one resource (service.name), one scope (this package's name).
func New(conf Config) (*Pipeline, error) {
	if conf.ServiceName == "" {
		conf.ServiceName = DefaultServiceName
	}
	exp := NewExporter()
	res := resource.NewSchemaless(attribute.String(AttrServiceName, conf.ServiceName))

	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp), sdktrace.WithResource(res))
	mr := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(mr), sdkmetric.WithResource(res))
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)), sdklog.WithResource(res))

	tracer := tp.Tracer(ScopeName, trace.WithInstrumentationVersion(version))
	count, err := mp.Meter(ScopeName, apiMetric.WithInstrumentationVersion(version)).
		Int64Counter(MetricVerdicts)
	if err != nil {
		return nil, fmt.Errorf("otel: verdicts_total: %w", err)
	}
	logr := lp.Logger(ScopeName, apiLog.WithInstrumentationVersion(version))

	return &Pipeline{
		exp: exp, tp: tp, mp: mp, lp: lp, mr: mr,
		tracer: tracer, count: count, logr: logr, conf: conf,
	}, nil
}

// Emit walks one request+verdict through the three-signal triad. The request
// id comes from the context (ContextWithRequestID / wire.Middleware); the
// returned Correlation names exactly the ids the emitted signals carry.
//
// Signal order (documented contract): span started → metric + log recorded
// on the span context → span ended (End flushes synchronously through the
// simple span processor, so the Snapshot is complete on return).
func (p *Pipeline) Emit(ctx context.Context, tx *ingest.TxContext, v *ladder.Verdict) (Correlation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return Correlation{}, ErrShutdown
	}
	if v == nil {
		return Correlation{}, ErrNilVerdict
	}
	rid, ok := RequestIDFromContext(ctx)
	if !ok || rid == "" {
		return Correlation{}, ErrNoRequestID
	}

	// request.id rides on every signal (the schema's correlation key — the
	// test asserts its presence on span, metric datapoint and log record);
	// the metric slice additionally carries it because verdicts_total's
	// datapoint set is keyed by request in v0 (see package comment).
	attrs := append(VerdictAttrs(tx, v), attribute.String(AttrRequestID, rid))

	// (a) the span — started, left recording while (b)/(c) emit below.
	sctx, span := p.tracer.Start(ctx, SpanName, trace.WithAttributes(attrs...))
	defer span.End()

	// (b) the metric — one increment with the verdict attributes + the
	// stitch key (trace.id rides as an attr so the shutdown-time collect
	// can pin the datapoint's TraceID; the exporter strips it from the
	// exported KV set and moves it onto the field).
	metricKVs := metricAttrs(attrs)
	metricKVs = append(metricKVs, attribute.String(MetricKeyTraceID, span.SpanContext().TraceID().String()))
	p.count.Add(sctx, 1, apiMetric.WithAttributes(metricKVs...))

	// (c) the log — the SDK stamps TraceID/SpanID from sctx (the span is
	// still recording, so the record correlates structurally).
	rec := apiLog.Record{}
	rec.SetEventName(SpanName)
	rec.SetSeverity(apiLog.SeverityInfo)
	rec.SetBody(attribute.StringValue(logBody(v.Action, rid)))
	rec.AddAttributes(attrs...)
	p.logr.Emit(sctx, rec)

	return Correlation{RequestID: rid, TraceID: span.SpanContext().TraceID().String(), SpanID: span.SpanContext().SpanID().String()}, nil
}

// Shutdown flushes and stops all three providers. Emit after Shutdown
// reports ErrShutdown. Safe to call twice (second call is a no-op). The
// metric reader is collected into the exporter's metric snapshot here
// (shutdown is the one collection point in v0).
func (p *Pipeline) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return nil // documented: double-shutdown is a no-op
	}
	p.done = true
	// Collect the metric pipeline one last time into the in-memory
	// exporter's metric snapshot (the ManualReader is the SDK's surface;
	// Shutdown flushes then closes it).
	rm := metricdata.ResourceMetrics{}
	cctx, cancel := context.WithTimeout(ctx, metricCollectTimeout)
	if err := p.mr.Collect(cctx, &rm); err != nil {
		cancel()
		return fmt.Errorf("otel: metric collect: %w", err)
	}
	cancel()
	p.exp.appendResourceMetrics(rm)
	if err := p.mp.Shutdown(ctx); err != nil {
		return fmt.Errorf("otel: metric provider shutdown: %w", err)
	}
	if err := p.lp.Shutdown(ctx); err != nil {
		return fmt.Errorf("otel: log provider shutdown: %w", err)
	}
	return p.tp.Shutdown(ctx)
}

// Exporter returns the pipeline's in-memory exporter (the test surface and
// the v0 "collector output"). Same instance every call.
func (p *Pipeline) Exporter() *Exporter { return p.exp }

// ctxKey is the unexported context key type for the request id.
type ctxKey struct{}

// ContextWithRequestID attaches the request id to ctx (empty id = detached;
// reads report not-found).
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestIDFromContext reads the request id back (found=false when absent).
func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ctxKey{}).(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// version is the engine's OTLP service.version suffix placeholder (v0).
const version = "v0"

// VerdictAttrs builds the span/log attribute set from the tx + verdict (the
// schema documented in the package comment). Single allocation of the slice;
// values are string-normalised so every signal carries the same shapes.
func VerdictAttrs(tx *ingest.TxContext, v *ladder.Verdict) []attribute.KeyValue {
	route := "-"
	if tx != nil && tx.Metadata != nil {
		if hint, ok := tx.Metadata[MetaPathHint]; ok && hint != "" {
			route = hint
		}
	}
	action := string(ladder.ActionAllow)
	phase := string(ladder.PhaseRequestHeaders)
	score := int64(0)
	var rules []string
	if v != nil {
		if v.Action != "" {
			action = string(v.Action)
		}
		if v.Phase != "" {
			phase = string(v.Phase)
		}
		score = v.Score
		for _, r := range v.Rules {
			rules = append(rules, string(r))
		}
	}
	return []attribute.KeyValue{
		attribute.String(AttrVerdictAction, action),
		attribute.String(AttrVerdictPhase, phase),
		attribute.String(AttrVerdictRoute, route),
		attribute.String(AttrVerdictRules, strings.Join(rules, ",")),
		attribute.Int64(AttrVerdictScore, score),
	}
}

// metricAttrs strips the span-only attrs (rules/score) from the metric set
// (the documented metric attribute schema).
func metricAttrs(attrs []attribute.KeyValue) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(attrs))
	for _, kv := range attrs {
		switch kv.Key {
		case AttrVerdictRules, AttrVerdictScore:
			continue
		default:
			out = append(out, kv)
		}
	}
	return out
}

// logBody renders the log body string (the documented body shape).
func logBody(a ladder.Action, rid string) string {
	return fmt.Sprintf("verdict %s request=%s", string(a), rid)
}

// newRequestID returns a fresh 128-bit request id (32 hex chars, W3C
// trace-id space) — the middleware's fallback when no header came in.
func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("otel: request id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// metricCollectTimeout bounds the shutdown-time metric collect (v0: none of
// the SDK paths here block; the timeout is defensive).
const metricCollectTimeout = 5 * time.Second

// MetricKeyTraceID is the internal metric stitch key (see Emit (b)).
const MetricKeyTraceID = "trace.id"

// init guard: the attribute key is shared with the exporter (exporter.go).
var attrKeyTraceID = attribute.Key(MetricKeyTraceID)
