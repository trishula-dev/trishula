// exporter.go — the in-memory exporter (TR-11): one instance satisfies all
// three SDK exporter interfaces (trace SpanExporter, metric Reader, log
// Exporter) and accumulates every signal as a plain Go struct. Exported
// data is inert (string ids, copied maps): no SDK types leak into tests or
// into the future TR-08c collector assertions.
package otel

import "context"

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

// MetricPoint is one exported metric datapoint. TraceID/ParentSpanID carry
// the trace context of the request that produced the datapoint — the SDK
// metric datapoint has no trace fields, so the pipeline stitches the
// span context on at export time (the Green implementation must do this;
// "" here means uncorrelated and GREEN output never carries it).
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

// Exporter accumulates spans, metric datapoints and log records in memory.
// It satisfies the SDK exporter/reader interfaces; tests read via Snapshot.
type Exporter struct{}

// NewExporter returns an empty in-memory exporter.
func NewExporter() *Exporter { return &Exporter{} }

// Snapshot copies the three signal sets (inert copies; safe to hold).
func (e *Exporter) Snapshot() Snapshot { return Snapshot{} }

// Shutdown marks the exporter closed; export after Shutdown reports
// ErrExporterClosed.
func (e *Exporter) Shutdown(_ context.Context) error { return nil }

// export appends records to the exporter's accumulators. RED state: the
// body is unwired (returns ErrExporterClosed unconditionally) — the GREEN
// commit implements the real accumulate path and the three SDK interfaces.
func (e *Exporter) export(_ context.Context, _ any) error { return ErrExporterClosed }

// ErrExporterClosed is returned by exports after Shutdown.
var ErrExporterClosed = errExporterClosed{}

type errExporterClosed struct{}

func (errExporterClosed) Error() string { return "otel: exporter closed" }
