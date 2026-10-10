package otel

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// kvGet returns the value of key in a KS slice ("" when absent).
func kvGet(kvs []KV, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

// kvHas reports key presence (""-valued keys included).
func kvHas(kvs []KV, key string) bool {
	for _, kv := range kvs {
		if kv.Key == key {
			return true
		}
	}
	return false
}

// kvPairs builds a set literal for attribute-multi-set assertions.
func kvPairs(kvs []KV) map[string]int {
	m := make(map[string]int, len(kvs))
	for _, kv := range kvs {
		m[kv.Key+"\x00"+kv.Value]++
	}
	return m
}

// contains reports whether a KS slice contains exactly one key=value pair.
func containsExactly(kvs []KV, key, value string) bool {
	return kvPairs(kvs)[key+"\x00"+value] == 1
}

// newTestPipeline builds the pipeline the GREEN implementation must satisfy.
// The in-memory test surface: explicit SDK providers, no network, no sleeps.
func newTestPipeline(t *testing.T) *Pipeline {
	t.Helper()
	p, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		if err := p.Shutdown(ctx); err != nil && !errors.Is(err, ErrShutdown) {
			t.Errorf("Shutdown() error: %v", err)
		}
	})
	return p
}

func verdictFixture() *ladder.Verdict {
	return &ladder.Verdict{
		Action: ladder.ActionBlock,
		Rules:  []ladder.RuleID{"crs:942100", "cel:seed-rate-shape"},
		Score:  7,
		Phase:  ladder.PhaseRequestHeaders,
	}
}

func txFixture() *ingest.TxContext {
	return &ingest.TxContext{
		Metadata: map[string]string{MetaPathHint: "/api/login"},
	}
}

// TestEmitCorrelatesThreeSignals is the ONE-request acceptance: a single
// request+verdict through the pipeline must produce exactly the triad —
// 1 span, 1 verdict metric increment, 1 log record — all sharing the
// request id, with the log's trace_id matching the span's.
func TestEmitCorrelatesThreeSignals(t *testing.T) {
	p := newTestPipeline(t)

	rid := "req-req-4f2a"
	ctx := ContextWithRequestID(context.Background(), rid)
	corr, err := p.Emit(ctx, txFixture(), verdictFixture())
	if err != nil {
		t.Fatalf("Emit() error: %v", err)
	}
	if corr.RequestID != rid {
		t.Errorf("Correlation.RequestID = %q, want %q", corr.RequestID, rid)
	}
	if corr.TraceID == "" {
		t.Errorf("Correlation.TraceID empty")
	}

	// Signals must exist BEFORE the shutdown-flush (span End + log Emit are
	// synchronous through simple processors); the shutdown-time metric
	// collect is the one async point.
	pre := p.Exporter().Snapshot()
	if len(pre.Spans) != 1 {
		t.Fatalf("pre-shutdown spans = %d, want 1 (synchronous span End)", len(pre.Spans))
	}
	if len(pre.Logs) != 1 {
		t.Fatalf("pre-shutdown logs = %d, want 1 (synchronous log Emit)", len(pre.Logs))
	}

	// Shutdown flushes the metric reader (the SDK's one collection point).
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	snap := p.Exporter().Snapshot()

	// (a) exactly one span, named trishula.verdict, carrying the request id.
	if len(snap.Spans) != 1 {
		t.Fatalf("spans = %d, want 1", len(snap.Spans))
	}
	span := snap.Spans[0]
	if span.Name != "trishula.verdict" {
		t.Errorf("span name = %q, want trishula.verdict", span.Name)
	}
	if got := kvGet(span.Attributes, AttrRequestID); got != rid {
		t.Errorf("span %s = %q, want %q", AttrRequestID, got, rid)
	}
	if span.TraceID == "" {
		t.Errorf("span TraceID empty")
	}
	if span.SpanID == "" {
		t.Errorf("span SpanID empty")
	}
	if span.TraceID != corr.TraceID {
		t.Errorf("span TraceID = %q, want Correlation's %q", span.TraceID, corr.TraceID)
	}

	// (b) the verdict metric increment: one datapoint for this request with
	// verdict attrs + the shared resource.
	if len(snap.Metrics) != 1 {
		t.Fatalf("metric datapoints = %d, want 1", len(snap.Metrics))
	}
	dp := snap.Metrics[0]
	if dp.Name != "verdicts_total" {
		t.Errorf("metric name = %q, want verdicts_total", dp.Name)
	}
	if dp.Value != 1 {
		t.Errorf("metric value = %d, want 1 (one increment)", dp.Value)
	}
	if got := kvGet(dp.Attributes, AttrRequestID); got != rid {
		t.Errorf("metric %s = %q, want %q", AttrRequestID, got, rid)
	}
	if got := kvGet(dp.Attributes, AttrVerdictAction); got != "block" {
		t.Errorf("metric %s = %q, want block", AttrVerdictAction, got)
	}
	if got := kvGet(dp.Attributes, AttrVerdictRoute); got != "/api/login" {
		t.Errorf("metric %s = %q, want /api/login", AttrVerdictRoute, got)
	}
	if dp.TraceID != span.TraceID {
		t.Errorf("metric TraceID = %q, want span's %q", dp.TraceID, span.TraceID)
	}

	// (c) the log record with trace_id + request id.
	if len(snap.Logs) != 1 {
		t.Fatalf("log records = %d, want 1", len(snap.Logs))
	}
	rec := snap.Logs[0]
	if rec.EventName != "trishula.verdict" {
		t.Errorf("log event name = %q, want trishula.verdict", rec.EventName)
	}
	if rec.TraceID != span.TraceID {
		t.Errorf("log TraceID = %q, want span's %q", rec.TraceID, span.TraceID)
	}
	if rec.SpanID != span.SpanID {
		t.Errorf("log SpanID = %q, want span's %q", rec.SpanID, span.SpanID)
	}
	if got := kvGet(rec.Attributes, AttrRequestID); got != rid {
		t.Errorf("log %s = %q, want %q", AttrRequestID, got, rid)
	}
	if rec.SeverityText != "INFO" {
		t.Errorf("log severity = %q, want INFO", rec.SeverityText)
	}
	if !strings.Contains(rec.Body, rid) {
		t.Errorf("log body %q does not mention the request id", rec.Body)
	}
	if !strings.Contains(rec.Body, "block") {
		t.Errorf("log body %q does not mention the action", rec.Body)
	}

	// Shared resource attrs on all three signals.
	for label, kvs := range map[string][]KV{
		"span":   span.Resource,
		"metric": dp.Resource,
		"log":    rec.Resource,
	} {
		if got := kvGet(kvs, AttrServiceName); got != DefaultServiceName {
			t.Errorf("%s resource service.name = %q, want %q", label, got, DefaultServiceName)
		}
	}

	// Verdict attribute schema on the span (verdict.phase / verdict.rules /
	// verdict.score present with the fixture's values).
	if got := kvGet(span.Attributes, AttrVerdictAction); got != "block" {
		t.Errorf("span %s = %q, want block", AttrVerdictAction, got)
	}
	if got := kvGet(span.Attributes, AttrVerdictPhase); got != string(ladder.PhaseRequestHeaders) {
		t.Errorf("span %s = %q, want %q", AttrVerdictPhase, got, ladder.PhaseRequestHeaders)
	}
	if got := kvGet(span.Attributes, AttrVerdictRules); got != "crs:942100,cel:seed-rate-shape" {
		t.Errorf("span %s = %q, want the comma-joined rules", AttrVerdictRules, got)
	}
	if got := kvGet(span.Attributes, AttrVerdictScore); got != "7" {
		t.Errorf("span %s = %q, want \"7\" (decimal)", AttrVerdictScore, got)
	}
}

// TestSnapshotAfterShutdownReturnsPriorState: Shutdown must not wipe what
// was exported before it; Snapshot works on a closed pipeline.
func TestSnapshotAfterShutdownReturnsPriorState(t *testing.T) {
	p := newTestPipeline(t)

	rid := "req-shutdown-9a"
	ctx := ContextWithRequestID(context.Background(), rid)
	if _, err := p.Emit(ctx, txFixture(), verdictFixture()); err != nil {
		t.Fatalf("Emit() error: %v", err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	snap := p.Exporter().Snapshot()
	if len(snap.Spans) != 1 || len(snap.Metrics) != 1 || len(snap.Logs) != 1 {
		t.Fatalf("post-shutdown snapshot spans/metrics/logs = %d/%d/%d, want 1/1/1",
			len(snap.Spans), len(snap.Metrics), len(snap.Logs))
	}
	if got := kvGet(snap.Spans[0].Attributes, AttrRequestID); got != rid {
		t.Errorf("post-shutdown span %s = %q, want %q", AttrRequestID, got, rid)
	}

	// Double-shutdown is a no-op (documented contract).
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown() error: %v", err)
	}
}

// TestEmitAfterShutdownErrors pins the shutdown discipline.
func TestEmitAfterShutdownErrors(t *testing.T) {
	p := newTestPipeline(t)
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
	if _, err := p.Emit(context.Background(), txFixture(), verdictFixture()); !errors.Is(err, ErrShutdown) {
		t.Errorf("Emit() after Shutdown = %v, want ErrShutdown", err)
	}
}

// TestExportAfterShutdownErrors pins the exporter's closed error.
func TestExportAfterShutdownErrors(t *testing.T) {
	e := NewExporter()
	if err := e.Shutdown(context.Background()); err != nil {
		t.Fatalf("exporter Shutdown() error: %v", err)
	}
	if err := e.Export(context.Background(), nil); !errors.Is(err, ErrExporterClosed) {
		t.Errorf("Export() after Shutdown = %v, want ErrExporterClosed", err)
	}
}

// TestMultipleRequestsCorrelateByID: three requests through one pipeline —
// per id, exactly the triad exists and all three signals share that id;
// signal sets keep export order (deterministic, no sleeps).
func TestMultipleRequestsCorrelateByID(t *testing.T) {
	p := newTestPipeline(t)

	ids := []string{"req-a", "req-b", "req-c"}
	for i, rid := range ids {
		v := &ladder.Verdict{
			Action: ladder.ActionChallenge,
			Rules:  []ladder.RuleID{"shield:ban"},
			Score:  int64(i + 1),
			Phase:  ladder.PhaseRequestBody,
		}
		tx := &ingest.TxContext{Metadata: map[string]string{MetaPathHint: "/pay"}, Packets: 1}
		ctx := ContextWithRequestID(context.Background(), rid)
		corr, err := p.Emit(ctx, tx, v)
		if err != nil {
			t.Fatalf("Emit(%q) error: %v", rid, err)
		}
		if corr.TraceID == "" {
			t.Errorf("Emit(%q) returned empty TraceID", rid)
		}
	}

	// Shutdown flushes the metric reader (all requests' datapoints).
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	snap := p.Exporter().Snapshot()
	if len(snap.Spans) != 3 || len(snap.Metrics) != 3 || len(snap.Logs) != 3 {
		t.Fatalf("3 requests: spans/metrics/logs = %d/%d/%d, want 3/3/3",
			len(snap.Spans), len(snap.Metrics), len(snap.Logs))
	}

	// Cross-signal uniqueness: 3 distinct trace ids — one span per request.
	seen := make(map[string]int)
	for _, s := range snap.Spans {
		seen[s.TraceID]++
	}
	for tid, n := range seen {
		if n != 1 {
			t.Errorf("trace id %s repeated %d times across spans", tid, n)
		}
	}

	// Index the exported sets by request id, then cross-check the triad.
	spansBy := indexSpansByRequestID(t, snap)
	metricsBy := indexMetricsByRequestID(t, snap)
	logsBy := indexLogsByRequestID(t, snap)

	for _, rid := range ids {
		span, ok := spansBy[rid]
		if !ok {
			t.Fatalf("no span carrying request id %q", rid)
		}
		dp, ok := metricsBy[rid]
		if !ok {
			t.Fatalf("no metric datapoint carrying request id %q", rid)
		}
		rec, ok := logsBy[rid]
		if !ok {
			t.Fatalf("no log record carrying request id %q", rid)
		}

		// All three carry THE SAME trace id (the metric datapoint's trace
		// id is stitched onto its exported snapshot entry).
		if span.TraceID != dp.TraceID || dp.TraceID != rec.TraceID {
			t.Errorf("request %q triad trace ids diverge: span=%q metric=%q log=%q",
				rid, span.TraceID, dp.TraceID, rec.TraceID)
		}

		// Verdict attrs agree across the three.
		if want := "challenge"; !containsExactly(span.Attributes, AttrVerdictAction, want) ||
			!containsExactly(dp.Attributes, AttrVerdictAction, want) ||
			!containsExactly(rec.Attributes, AttrVerdictAction, want) {
			t.Errorf("request %q: verdict.action mismatch across the triad", rid)
		}
		wantRoute := "/pay"
		if got := kvGet(dp.Attributes, AttrVerdictRoute); got != wantRoute {
			t.Errorf("request %q: metric route = %q, want %q", rid, got, wantRoute)
		}
		wantPhase := string(ladder.PhaseRequestBody)
		if got := kvGet(span.Attributes, AttrVerdictPhase); got != wantPhase {
			t.Errorf("request %q: span phase = %q, want %q", rid, got, wantPhase)
		}
		if got := kvGet(rec.Attributes, AttrRequestID); got != rid {
			t.Errorf("request %q: log %s = %q", rid, AttrRequestID, got)
		}

		// service.name on at least one signal per request (resource contract).
		if got := kvGet(span.Resource, AttrServiceName); got != DefaultServiceName {
			t.Errorf("request %q: span resource service.name = %q", rid, got)
		}
	}
}

func indexSpansByRequestID(t *testing.T, snap Snapshot) map[string]Span {
	t.Helper()
	m := make(map[string]Span)
	for _, s := range snap.Spans {
		rid := kvGet(s.Attributes, AttrRequestID)
		if rid == "" {
			t.Errorf("span without %s attr", AttrRequestID)
			continue
		}
		if _, dup := m[rid]; dup {
			t.Errorf("two spans carry request id %q", rid)
		}
		m[rid] = s
	}
	return m
}

func indexMetricsByRequestID(t *testing.T, snap Snapshot) map[string]MetricPoint {
	t.Helper()
	m := make(map[string]MetricPoint)
	for _, dp := range snap.Metrics {
		rid := kvGet(dp.Attributes, AttrRequestID)
		if rid == "" {
			t.Errorf("metric datapoint without %s attr", AttrRequestID)
			continue
		}
		m[rid] = dp
	}
	return m
}

func indexLogsByRequestID(t *testing.T, snap Snapshot) map[string]LogRecord {
	t.Helper()
	m := make(map[string]LogRecord)
	for _, r := range snap.Logs {
		rid := kvGet(r.Attributes, AttrRequestID)
		if rid == "" {
			t.Errorf("log record without %s attr", AttrRequestID)
			continue
		}
		m[rid] = r
	}
	return m
}

// TestSnapshotCopiesAreInert: mutable caller edits must not corrupt the
// exporter's state (Snapshot returns inert copies).
func TestSnapshotCopiesAreInert(t *testing.T) {
	p := newTestPipeline(t)

	rid := "req-inert-3b"
	ctx := ContextWithRequestID(context.Background(), rid)
	if _, err := p.Emit(ctx, txFixture(), verdictFixture()); err != nil {
		t.Fatalf("Emit() error: %v", err)
	}

	snap := p.Exporter().Snapshot()
	snap.Spans[0].Attributes[0].Value = "clobbered"

	fresh := p.Exporter().Snapshot()
	for _, kv := range fresh.Spans[0].Attributes {
		if kv.Value == "clobbered" {
			t.Fatalf("Snapshot leaked mutable state: attribute edited via a previous Snapshot")
		}
	}
	if got := kvGet(fresh.Spans[0].Attributes, AttrRequestID); got != rid {
		t.Errorf("Snapshot copy corrupted the request id: got %q, want %q", got, rid)
	}
}

// TestEmitRequiresRequestID: correlation is the contract — no id in the
// context means Emit refuses rather than emitting uncorrelatable signals.
func TestEmitRequiresRequestID(t *testing.T) {
	p := newTestPipeline(t)
	if _, err := p.Emit(context.Background(), txFixture(), verdictFixture()); !errors.Is(err, ErrNoRequestID) {
		t.Errorf("Emit() without request id = %v, want ErrNoRequestID", err)
	}
	if _, ok := RequestIDFromContext(context.Background()); ok {
		t.Errorf("RequestIDFromContext on plain ctx = found, want not-found")
	}
}
