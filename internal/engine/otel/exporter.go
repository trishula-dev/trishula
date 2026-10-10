// exporter.go — the in-memory exporter (TR-11): the collector-output
// stand-in. It satisfies the SDK's trace.SpanExporter and log.Exporter
// surfaces (spans + log records stream in synchronously through the simple
// processors) and receives metrics from the pipeline's ManualReader collect
// at shutdown. Exported data is inert (string ids, copied attribute
// slices) — no SDK types leak into tests or into the future TR-08c
// collector assertions.
package otel

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	apiLog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// KV is one exported attribute. String values: integer attribute values are
// the literal decimal string (see the package schema).
type KV struct {
	Key   string
	Value string
}

// Span is one exported read-only span.
type Span struct {
	Name         string
	TraceID      string
	SpanID       string
	ParentSpanID string // "" when parentless
	Attributes   []KV
	Resource     []KV
	Events       []string // span event names, order preserved
}

// MetricPoint is one exported metric datapoint. TraceID carries the trace
// context of the request that produced the datapoint — the SDK metric
// datapoint has no trace fields, so the pipeline pins the verdict span's
// trace id onto the increment ("" here would mean uncorrelated; GREEN
// output never carries it).
type MetricPoint struct {
	Name       string
	Value      int64
	Attributes []KV
	Resource   []KV
	TraceID    string
}

// LogRecord is one exported log record.
type LogRecord struct {
	EventName    string
	SeverityText string
	Body         string
	TraceID      string
	SpanID       string
	Attributes   []KV
	Resource     []KV
	ScopeName    string
}

// Snapshot is the collector-output stand-in: the three signal sets as plain
// data. Order within each set is export order (deterministic per test).
type Snapshot struct {
	Spans   []Span
	Metrics []MetricPoint
	Logs    []LogRecord
}

// ErrExporterClosed is returned by exports after Shutdown (errors.Is-able).
var ErrExporterClosed = errors.New("otel: exporter closed")

// Exporter accumulates spans, metric datapoints and log records in memory.
// It satisfies the trace.SpanExporter and log.Exporter SDK surfaces (the
// metric side of this SDK pins unexported Reader method names, so the
// pipeline drives metric export directly through record/collect helpers —
// documented on Pipeline, not faked as an SDK interface).
type Exporter struct {
	mu      sync.Mutex
	closed  bool
	spans   []Span
	metrics []MetricPoint
	logs    []LogRecord
}

// NewExporter returns an empty in-memory exporter.
func NewExporter() *Exporter { return &Exporter{} }

// Snapshot copies the three signal sets (inert copies; safe to hold —
// every KVs slice is duplicated so caller mutation cannot corrupt state).
func (e *Exporter) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := Snapshot{
		Spans:   make([]Span, len(e.spans)),
		Metrics: make([]MetricPoint, len(e.metrics)),
		Logs:    make([]LogRecord, len(e.logs)),
	}
	for i, sp := range e.spans {
		sp.Attributes = copyKVs(sp.Attributes)
		sp.Resource = copyKVs(sp.Resource)
		out.Spans[i] = sp
	}
	for i, dp := range e.metrics {
		dp.Attributes = copyKVs(dp.Attributes)
		dp.Resource = copyKVs(dp.Resource)
		out.Metrics[i] = dp
	}
	for i, lr := range e.logs {
		lr.Attributes = copyKVs(lr.Attributes)
		lr.Resource = copyKVs(lr.Resource)
		out.Logs[i] = lr
	}
	return out
}

// copyKVs duplicates a KVs slice (nil stays nil).
func copyKVs(kvs []KV) []KV {
	if kvs == nil {
		return nil
	}
	out := make([]KV, len(kvs))
	copy(out, kvs)
	return out
}

// Shutdown marks the exporter closed; exports after Shutdown report
// ErrExporterClosed (accumulated signals stay readable — a test shuts the
// pipeline down and then reads its snapshot).
func (e *Exporter) Shutdown(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

// --- trace.SpanExporter ---

// ExportSpans appends ended spans to the span accumulator.
func (e *Exporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrExporterClosed
	}
	for _, s := range spans {
		e.spans = append(e.spans, newSpan(s))
	}
	return nil
}

// --- log.Exporter ---

// Export appends log records (cloned before retention: the processor may
// pool the slice — record mutation after this call is not ours to observe).
func (e *Exporter) Export(_ context.Context, records []log.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrExporterClosed
	}
	for i := range records {
		e.logs = append(e.logs, newLogRecord(&records[i]))
	}
	return nil
}

// ForceFlush is a no-op: the in-memory exporter never holds records back.
func (e *Exporter) ForceFlush(context.Context) error { return nil }

// --- metric surface (collect path; see the type comment) ---

// appendResourceMetrics drains one ResourceMetrics payload into the metric
// accumulator (pipeline-called on Shutdown; integer Sum datapoints only —
// verdicts_total is an Int64Counter, so the v0 snapshot surface is sums).
func (e *Exporter) appendResourceMetrics(rm metricdata.ResourceMetrics) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	res := ksFromResource(rm.Resource)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, p := range sum.DataPoints {
				traceID := traceIDFromMetricAttrs(p.Attributes)
				e.metrics = append(e.metrics, MetricPoint{
					Name:       m.Name,
					Value:      p.Value,
					Attributes: stripKey(ksFromSet(p.Attributes), MetricKeyTraceID),
					Resource:   res,
					TraceID:    traceID,
				})
			}
		}
	}
}

// stripKey removes one key from a KVs slice (order-preserving).
func stripKey(kvs []KV, key string) []KV {
	out := kvs[:0:0]
	for _, kv := range kvs {
		if kv.Key != key {
			out = append(out, kv)
		}
	}
	return out
}

// traceIDFromMetricAttrs reads the stitched trace id the pipeline recorded
// alongside the datapoint ("" when uncorrelated).
func traceIDFromMetricAttrs(set attribute.Set) string {
	v, ok := set.Value(attrKeyTraceID)
	if !ok {
		return ""
	}
	return v.AsString()
}

// --- interface conformance (the GREEN proof the SDK accepts this exporter) ---

var (
	_ sdktrace.SpanExporter = (*Exporter)(nil)
	_ log.Exporter          = (*Exporter)(nil)
)

// --- SDK → inert conversion helpers ---

// newSpan converts an ended SDK span into the inert Span.
func newSpan(s sdktrace.ReadOnlySpan) Span {
	sc := s.SpanContext()
	parent := ""
	if ps := s.Parent(); ps.IsValid() {
		parent = ps.SpanID().String()
	}
	span := Span{
		Name:         s.Name(),
		TraceID:      sc.TraceID().String(),
		SpanID:       sc.SpanID().String(),
		ParentSpanID: parent,
		Attributes:   ksFromKVs(s.Attributes()),
		Resource:     ksFromResource(s.Resource()),
	}
	for _, ev := range s.Events() {
		span.Events = append(span.Events, ev.Name)
	}
	return span
}

// newLogRecord converts an SDK log record into the inert LogRecord.
func newLogRecord(r *log.Record) LogRecord {
	rec := LogRecord{
		EventName:    r.EventName(),
		SeverityText: severityText(r.Severity()),
		TraceID:      r.TraceID().String(),
		SpanID:       r.SpanID().String(),
		Resource:     ksFromResource(r.Resource()),
		ScopeName:    r.InstrumentationScope().Name,
	}
	rec.Body = bodyString(r.Body())
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		rec.Attributes = append(rec.Attributes, kvToKV(kv))
		return true
	})
	return rec
}

// ksFromKVs flattens a []KeyValue into ordered KVs.
func ksFromKVs(kvs []attribute.KeyValue) []KV {
	out := make([]KV, 0, len(kvs))
	for _, kv := range kvs {
		out = append(out, kvToKV(kv))
	}
	return out
}

// ksFromSet flattens an attribute.Set into ordered KVs.
func ksFromSet(set attribute.Set) []KV {
	out := make([]KV, 0, set.Len())
	iter := set.Iter()
	for iter.Next() {
		out = append(out, kvToKV(iter.Attribute()))
	}
	return out
}

// ksFromResource flattens a *resource.Resource (nil-safe).
func ksFromResource(res *resource.Resource) []KV {
	if res == nil {
		return nil
	}
	out := make([]KV, 0, res.Len())
	for _, kv := range res.Attributes() {
		out = append(out, kvToKV(kv))
	}
	return out
}

// kvToKV normalises one attribute to its string form (the package schema).
func kvToKV(kv attribute.KeyValue) KV {
	return KV{Key: string(kv.Key), Value: valueString(kv.Value)}
}

// valueString renders an attribute.Value as its snapshot string form.
func valueString(v attribute.Value) string {
	switch v.Type() {
	case attribute.STRING:
		return v.AsString()
	case attribute.INT64:
		return strconv.FormatInt(v.AsInt64(), 10)
	case attribute.FLOAT64:
		return strconv.FormatFloat(v.AsFloat64(), 'g', -1, 64)
	case attribute.BOOL:
		return strconv.FormatBool(v.AsBool())
	default:
		for _, s := range v.AsStringSlice() {
			return s // first element on unexpected slice types
		}
		return ""
	}
}

// bodyString renders a log body (only string bodies exist in this package).
func bodyString(v attribute.Value) string {
	if v.Type() == attribute.STRING {
		return v.AsString()
	}
	return valueString(v)
}

// severityText renders the otel log severity's text form (the stringer
// emits the OTLP severity names: "INFO", "ERROR", ...).
func severityText(s apiLog.Severity) string {
	if s == 0 {
		return ""
	}
	return s.String()
}
