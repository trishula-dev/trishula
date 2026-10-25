// Package otel implements the spec's verdict observability pipeline v0 (TR-11):
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
//	                             (ladder.Action vocabulary, the reference-implementation sketch)
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
//	DoS signature extension (TR-195, issue #237): when the Verdict carries
//	a DosSig, the span and the log record carry verdict.dos.sig (the
//	DoSSig JSON: class, segs, bytesPerSeg, spanSec, paths). Flow-keyed
//	would-bans emit their own record: event `trishula.ban`, WARN, attrs
//	ban.key / ban.tier / ban.score / ban.reason (+ verdict.dos.sig when
//	the record holds one; no request.id — the key IS the correlation).
//
//	Stage-stamp extension (TR-194, issue #236): the record schema stays
//	trishula.verdict.v1 (additive; the M10 pin). When the verdict carries
//	the ladder's walk rows, the span + the log record carry
//	ladder.rows (the rows JSON: the §3.4 tokens, the v1 row shape
//	{stage, matched, us}, walk order; run stages only — a skipped stage
//	reads absent). When Emit receives correlated shield events
//	(WithEvents), the span gains ONE LINK per event (the link carries the
//	event fields: shield.ts_ns, shield.family, shield.sport, shield.dport,
//	shield.tcp_flags, shield.payload_len, shield.path, shield.stages) and
//	the log record carries shield.stages (the OR over the correlated
//	bitmaps — the union of the kernel's consults, never invented). No
//	correlated event reads NO shield field. The metric's datapoint set
//	stays pinned (no stamp keys on the counter).
//
// The middleware span `trishula.request` (wire.go) carries request.id,
// http.method and http.path as string attrs and parents the verdict span.
package otel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"encoding/json"
	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
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
	// AttrDosSig (TR-195, issue #237): the dynamic signature of a DoS
	// verdict, the DoSSig JSON (class, segs, bytesPerSeg, spanSec, paths).
	// Present on the verdict signals only when the verdict carries a sig;
	// present on ban records always (a ban always carries its sig or nil —
	// nil sig = no attr).
	AttrDosSig = "verdict.dos.sig"
	// TR-194 (issue #236): the stage-stamp fields. ladder.rows carries
	// the walk rows JSON (the record's §7 ladder array);
	// shield.stages carries the OR of the correlated FlowEvent bitmaps
	// (the record's §7 shield object; optional = absence carries no
	// claim). The shield.* link attributes carry one event's fields
	// (the record's §8 list).
	AttrVerdictLadder = "ladder.rows"
	AttrShieldStages  = "shield.stages"
	AttrShieldTSNS    = "shield.ts_ns"
	AttrShieldFamily  = "shield.family"
	AttrShieldSport   = "shield.sport"
	AttrShieldDport   = "shield.dport"
	AttrShieldFlags   = "shield.tcp_flags"
	AttrShieldPayload = "shield.payload_len"
	AttrShieldPath    = "shield.path"
	AttrBanKey        = "ban.key"
	AttrBanTier       = "ban.tier"
	AttrBanScore      = "ban.score"
	AttrBanReason     = "ban.reason"
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

// EmitOption carries optional per-emit context (v0: the correlated shield
// events; TR-194). Zero value is valid.
type EmitOption struct {
	events []*ingest.FlowEvent
}

// WithEvents passes the request's correlated ring events to Emit: the
// verdict span gains one link per event; the record gains shield.stages
// (the OR over the events' bitmaps — the union of what the kernel
// consulted, never invented).
func WithEvents(events []*ingest.FlowEvent) EmitOption {
	return EmitOption{events: events}
}

// Correlation is what one Emit produced, keyed identically to the emitted
// signals; callers log it, tests assert it.
type Correlation struct {
	RequestID string
	TraceID   string
	SpanID    string
}

// Pipeline emits the three correlated verdict signals per request+verdict
// (the spec's observability v0, in-process SDK only): one call, one span + one metric datapoint
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
func (p *Pipeline) Emit(ctx context.Context, tx *ingest.TxContext, v *ladder.Verdict, opts ...EmitOption) (Correlation, error) {
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

	// request.id is present on every signal (the schema's correlation key — the
	// test asserts its presence on span, metric datapoint and log record);
	// the metric slice additionally carries it because verdicts_total's
	// datapoint set is keyed by request in v0 (see package comment).
	attrs := append(VerdictAttrs(tx, v), attribute.String(AttrRequestID, rid))

	// TR-194: the correlated shield events — one span link per event
	// (the record's §8; a link carries a context + attributes, never a
	// span). The events' bitmaps fold into the record's shield.stages
	// (the OR — the union of the kernel's consults, never invented).
	events := emitEvents(opts)
	links := make([]trace.Link, 0, len(events))
	for _, fe := range events {
		links = append(links, trace.Link{
			SpanContext: eventLinkContext(fe),
			Attributes:  eventLinkAttrs(fe),
		})
	}
	startOpts := make([]trace.SpanStartOption, 0, 2)
	startOpts = append(startOpts, trace.WithAttributes(attrs...))
	if len(links) > 0 {
		startOpts = append(startOpts, trace.WithLinks(links...))
	}

	// (a) the span — started, left recording while (b)/(c) emit below.
	sctx, span := p.tracer.Start(ctx, SpanName, startOpts...)
	defer span.End()

	// (b) the metric — one increment with the verdict attributes + the
	// stitch key (trace.id is an attr so the shutdown-time collect
	// can pin the datapoint's TraceID; the exporter strips it from the
	// exported KV set and moves it onto the field).
	metricKVs := metricAttrs(attrs)
	metricKVs = append(metricKVs, attribute.String(MetricKeyTraceID, span.SpanContext().TraceID().String()))
	p.count.Add(sctx, 1, apiMetric.WithAttributes(metricKVs...))

	// (c) the log — the SDK stamps TraceID/SpanID from sctx (the span is
	// still recording, so the record correlates structurally). The
	// record carries the stage-stamp fields additively (TR-194):
	// shield.stages when events correlated, ladder.rows when the walk
	// recorded rows; the metric's set above stays pinned.
	logAttrs := append([]attribute.KeyValue(nil), attrs...)
	if len(events) > 0 {
		logAttrs = append(logAttrs, attribute.Int64(AttrShieldStages, orStages(events)))
	}
	if len(v.Rows) > 0 {
		logAttrs = append(logAttrs, attribute.String(AttrVerdictLadder, ladderRowsJSON(v.Rows)))
	}
	rec := apiLog.Record{}
	rec.SetEventName(SpanName)
	rec.SetSeverity(apiLog.SeverityInfo)
	rec.SetBody(attribute.StringValue(logBody(v.Action, rid)))
	rec.AddAttributes(logAttrs...)
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
	attrs := []attribute.KeyValue{
		attribute.String(AttrVerdictAction, action),
		attribute.String(AttrVerdictPhase, phase),
		attribute.String(AttrVerdictRoute, route),
		attribute.String(AttrVerdictRules, strings.Join(rules, ",")),
		attribute.Int64(AttrVerdictScore, score),
	}
	if v != nil && v.DosSig != nil {
		// TR-195: the verdict record states the dynamic signature (the
		// DoSSig JSON).
		attrs = append(attrs, attribute.String(AttrDosSig, dosSigJSON(*v.DosSig)))
	}
	return attrs
}

// dosSigJSON renders the DoSSig's JSON form for the attribute value (the
// one content, every surface: the cue, the evidence row, the map fact and
// the verdict record cite the same measured facts).
func dosSigJSON(s rateban.DoSSig) string {
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(b)
}

// emitEvents collects the correlated shield events from the options
// (nil events drop; an uncorrelated emit collects none).
func emitEvents(opts []EmitOption) []*ingest.FlowEvent {
	var events []*ingest.FlowEvent
	for _, o := range opts {
		for _, fe := range o.events {
			if fe != nil {
				events = append(events, fe)
			}
		}
	}
	return events
}

// orStages folds the correlated events' bitmaps (the OR: the union of
// what the kernel consulted for the request — no bit ever invents).
func orStages(events []*ingest.FlowEvent) int64 {
	var acc uint64
	for _, fe := range events {
		if fe == nil {
			continue
		}
		acc |= fe.Stages
	}
	return int64(acc)
}

// eventLinkContext derives the link's SpanContext from the event (the
// record's §8: a link carries a context + attributes, never a span). The
// ids hash the event's identity — deterministic, valid, and the event's
// own; the link claims no existing trace (a collector joins on the
// attributes, not on a span lookup).
func eventLinkContext(fe *ingest.FlowEvent) trace.SpanContext {
	h := sha256.New()
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], fe.Timestamp)
	h.Write(be[:])
	h.Write(fe.SrcIP4[:])
	h.Write(fe.SrcIP6[:])
	h.Write(fe.DstIP4[:])
	h.Write(fe.DstIP6[:])
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[:2], fe.SrcPort)
	binary.BigEndian.PutUint16(ports[2:], fe.DstPort)
	h.Write(ports[:])
	h.Write([]byte{fe.TCPFlags, fe.Family})
	var rest [6]byte
	binary.BigEndian.PutUint32(rest[:4], fe.Mark)
	binary.BigEndian.PutUint16(rest[4:], fe.PayloadLen)
	h.Write(rest[:])
	h.Write(fe.PathHint[:])
	var sc trace.SpanContextConfig
	sum := h.Sum(nil)
	copy(sc.SpanID[:], sum[:8])
	copy(sc.TraceID[:], sum[8:24])
	return trace.NewSpanContext(sc)
}

// eventLinkAttrs builds one link's attribute set: the event fields the
// record's §8 names (timestamps, family, ports, TCP flags, payload
// length, path hint, stages integer).
func eventLinkAttrs(fe *ingest.FlowEvent) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Int64(AttrShieldTSNS, int64(fe.Timestamp)),
		attribute.Int(AttrShieldFamily, int(fe.Family)),
		attribute.Int(AttrShieldSport, int(fe.SrcPort)),
		attribute.Int(AttrShieldDport, int(fe.DstPort)),
		attribute.Int(AttrShieldFlags, int(fe.TCPFlags)),
		attribute.Int(AttrShieldPayload, int(fe.PayloadLen)),
		attribute.String(AttrShieldPath, fe.PathString()),
		attribute.Int64(AttrShieldStages, int64(fe.Stages)),
	}
}

// ladderJSONRow is the verdict record's v1 row shape (the stage-stamps
// record §7: {stage, matched, us}; the tokens are the §3.4 names).
type ladderJSONRow struct {
	Stage   string   `json:"stage"`
	Matched []string `json:"matched"`
	US      int64    `json:"us"`
}

// ladderRowsJSON renders the walk rows for the ladder.rows attribute
// (walk order; a row's matched array stays present — nil reads []).
func ladderRowsJSON(rows []ladder.Row) string {
	out := make([]ladderJSONRow, 0, len(rows))
	for _, r := range rows {
		row := ladderJSONRow{Stage: r.Stage.Token(), Matched: []string{}, US: r.US}
		for _, id := range r.Matched {
			row.Matched = append(row.Matched, string(id))
		}
		out = append(out, row)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
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

// SpanBan is the ban log record's event/span name (v0: a flow-keyed ban
// carries no HTTP request, so no request span and no request.id — the
// record keys itself by the ban key).
const SpanBan = "trishula.ban"

// EmitBan publishes one flow-keyed would-ban/ban as a log record (TR-195,
// issue #237). The
// record carries ban.key / ban.tier / ban.score / ban.reason and — when the
// record holds a signature — verdict.dos.sig, the DoSSig JSON. The verdict
// record's own surface (Emit) carries the same sig on the request that
// caused the crossing. Flow-keyed bans ride no request context, so the
// record carries no span: the key IS the correlation (ban.key).
func (p *Pipeline) EmitBan(b rateban.BanEvidence) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return ErrShutdown
	}
	reason := strings.Join(b.ReasonCodes, ",")
	attrs := []attribute.KeyValue{
		attribute.String(AttrBanKey, b.Key),
		attribute.String(AttrBanTier, b.Tier),
		attribute.Float64(AttrBanScore, b.Score),
		attribute.String(AttrBanReason, reason),
	}
	if b.OSig != nil {
		attrs = append(attrs, attribute.String(AttrDosSig, dosSigJSON(*b.OSig)))
	}
	rec := apiLog.Record{}
	rec.SetEventName(SpanBan)
	rec.SetSeverity(apiLog.SeverityWarn)
	rec.SetBody(attribute.StringValue("would-ban " + b.Tier + " " + b.Key))
	rec.AddAttributes(attrs...)
	p.logr.Emit(context.Background(), rec)
	return nil
}
