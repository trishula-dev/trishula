package otel

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ingest"
	"github.com/trishula-dev/trishula/internal/engine/ladder"
)

// TR-194 (issue #236): the verdict record's stage-stamp fields. The
// emitted span carries ONE LINK per correlated FlowEvent; the link
// attributes carry the event fields (the record's §8). The emitted log
// record carries the record's §7 extension: ladder.rows (the walk rows,
// the §3.4 tokens, the v1 row shape {stage, matched, us}) and
// shield.stages (the OR over the correlated bitmaps). Absence carries no
// claim: no correlated event reads NO shield key; a zero bitmap reads an
// honest 0. M10 keeps trishula.verdict.v1 schema-valid: the record
// evolves additively, never by a silent break.

// stampFlowEvent builds a correlated FlowEvent for the pipeline tests
// (the decoded view; the wire leg pins byte shapes in ingest).
func stampFlowEvent(ts uint64, stages uint64) *ingest.FlowEvent {
	return &ingest.FlowEvent{
		Timestamp:  ts,
		SrcPort:    4711,
		DstPort:    443,
		PayloadLen: 517,
		HTTPSeen:   1,
		Family:     4,
		Stages:     stages,
		PathHint:   [128]byte{'/', 'v', '1', '/', 'c', 'h', 'a', 't'},
	}
}

// stageRowsFixture returns two walk-order rows (kernel pass + matcher log).
func stageRowsFixture() []ladder.Row {
	return []ladder.Row{
		{Stage: ladder.StageKernel, US: 2},
		{Stage: ladder.StageMatcher, Matched: []ladder.RuleID{"crs:920480"}, US: 12},
	}
}

func TestVerdictRecordCarriesStageStamps(t *testing.T) {
	t.Run("the record + the span carry the stamped fields (GREEN shape)", func(t *testing.T) {
		p := newTestPipeline(t)
		rid := "req-stamps-1"
		ctx := ContextWithRequestID(context.Background(), rid)
		v := &ladder.Verdict{
			Action: ladder.ActionLog,
			Rules:  []ladder.RuleID{"crs:920480"},
			Rows:   stageRowsFixture(),
		}
		evs := []*ingest.FlowEvent{stampFlowEvent(42, 0x70), stampFlowEvent(43, 0x10)}
		if _, err := p.Emit(ctx, txFixture(), v, WithEvents(evs)); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		snap := p.Exporter().Snapshot()

		// (a) the span: one link per correlated event; the link carries
		// the event fields (timestamps, family, ports, TCP flags, payload
		// length, path hint, stages — the record's §8 list).
		var span *Span
		for i := range snap.Spans {
			if snap.Spans[i].Name == SpanName {
				span = &snap.Spans[i]
				break
			}
		}
		if span == nil {
			t.Fatalf("no %q span in the snapshot", SpanName)
		}
		if len(span.Links) != 2 {
			t.Fatalf("span links = %d, want 2 (one link per correlated FlowEvent)", len(span.Links))
		}
		link := span.Links[0]
		if link.TraceID == "" || link.SpanID == "" {
			t.Fatalf("link context empty: %+v", link)
		}
		for _, want := range []string{
			"shield.ts_ns", "shield.family", "shield.sport", "shield.dport",
			"shield.tcp_flags", "shield.payload_len", "shield.path", "shield.stages",
		} {
			if !kvHas(link.Attributes, want) {
				t.Fatalf("link attributes miss %s (the §8 event fields): %v", want, link.Attributes)
			}
		}
		if got := kvGet(link.Attributes, "shield.stages"); got != "112" { // 0x70
			t.Fatalf("link[0] shield.stages = %q, want %q", got, "112")
		}
		if got := kvGet(link.Attributes, "shield.path"); got != "/v1/chat" {
			t.Fatalf("link[0] shield.path = %q, want %q", got, "/v1/chat")
		}
		if got := kvGet(span.Links[1].Attributes, "shield.stages"); got != "16" { // 0x10
			t.Fatalf("link[1] shield.stages = %q, want %q", got, "16")
		}

		// (b) the log record: shield.stages = the OR over the bitmaps;
		// ladder.rows = the walk rows in the v1 row shape.
		var rec *LogRecord
		for i := range snap.Logs {
			if snap.Logs[i].EventName == SpanName {
				rec = &snap.Logs[i]
				break
			}
		}
		if rec == nil {
			t.Fatalf("no %q log record in the snapshot", SpanName)
		}
		if got := kvGet(rec.Attributes, "shield.stages"); got != "112" {
			t.Fatalf("record shield.stages = %q, want %q (the OR: 0x70|0x10 = 0x70)", got, "112")
		}
		rowsRaw := kvGet(rec.Attributes, "ladder.rows")
		if rowsRaw == "" {
			t.Fatal("record misses ladder.rows (the walked stages ride the record)")
		}
		var rows []struct {
			Stage   string   `json:"stage"`
			Matched []string `json:"matched"`
			US      int64    `json:"us"`
		}
		if err := json.Unmarshal([]byte(rowsRaw), &rows); err != nil {
			t.Fatalf("ladder.rows is not the v1 row shape: %v (%s)", err, rowsRaw)
		}
		if len(rows) != 2 {
			t.Fatalf("ladder rows = %d, want 2", len(rows))
		}
		if rows[0].Stage != "kernel" || rows[1].Stage != "matcher" {
			t.Fatalf("row tokens = %q,%q, want the §3.4 walk order kernel then matcher", rows[0].Stage, rows[1].Stage)
		}
		if len(rows[1].Matched) != 1 || rows[1].Matched[0] != "crs:920480" {
			t.Fatalf("row 1 matched = %v, want [crs:920480]", rows[1].Matched)
		}
		if rows[0].US != 2 || rows[1].US != 12 {
			t.Fatalf("row walls = %d,%d, want 2,12", rows[0].US, rows[1].US)
		}

		// (c) the metric stays on the pinned attribute set (the row/stamp
		// fields ride the record + the link; no new datapoint series).
		for _, dp := range snap.Metrics {
			if dp.Name == MetricVerdicts {
				for _, kv := range dp.Attributes {
					if kv.Key == "ladder.rows" || kv.Key == "shield.stages" {
						t.Fatalf("metric carries %s (the datapoint set stays pinned)", kv.Key)
					}
				}
			}
		}
	})

	t.Run("absence carries no claim (no events → no shield key)", func(t *testing.T) {
		p := newTestPipeline(t)
		rid := "req-stamps-2"
		ctx := ContextWithRequestID(context.Background(), rid)
		if _, err := p.Emit(ctx, txFixture(), &ladder.Verdict{Action: ladder.ActionAllow}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		snap := p.Exporter().Snapshot()
		if len(snap.Logs) != 1 {
			t.Fatalf("logs = %d, want 1", len(snap.Logs))
		}
		rec := snap.Logs[0]
		if kvHas(rec.Attributes, "shield.stages") {
			t.Fatalf("no correlated event, but the record carries shield.stages (absence must carry no claim): %v", rec.Attributes)
		}
		if kvHas(rec.Attributes, "ladder.rows") {
			t.Fatalf("no walk rows, but the record carries ladder.rows (absence must carry no claim): %v", rec.Attributes)
		}
		for i := range snap.Spans {
			if snap.Spans[i].Name == SpanName && len(snap.Spans[i].Links) != 0 {
				t.Fatalf("links on an uncorrelated emit: %v", snap.Spans[i].Links)
			}
		}
	})

	t.Run("a zero bitmap on a present event reads an honest 0", func(t *testing.T) {
		p := newTestPipeline(t)
		rid := "req-stamps-3"
		ctx := ContextWithRequestID(context.Background(), rid)
		evs := []*ingest.FlowEvent{stampFlowEvent(9, 0)} // the landed 200-byte class
		if _, err := p.Emit(ctx, txFixture(), &ladder.Verdict{Action: ladder.ActionAllow}, WithEvents(evs)); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		snap := p.Exporter().Snapshot()
		if got := kvGet(snap.Logs[0].Attributes, "shield.stages"); got != "0" {
			t.Fatalf("record shield.stages = %q, want 0 (present event, all-absent bitmap)", got)
		}
	})

	t.Run("M10: the record vocabulary stays pinned (additive extension only)", func(t *testing.T) {
		p := newTestPipeline(t)
		rid := "req-stamps-4"
		ctx := ContextWithRequestID(context.Background(), rid)
		v := &ladder.Verdict{Action: ladder.ActionBlock, Rows: stageRowsFixture()}
		evs := []*ingest.FlowEvent{stampFlowEvent(7, 0x7F)}
		if _, err := p.Emit(ctx, txFixture(), v, WithEvents(evs)); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		snap := p.Exporter().Snapshot()
		// The pinned v0 vocabulary + the TR-194 additive keys. A key
		// outside the vocabulary fails the M10 row (100% schema-valid).
		pinned := map[string]bool{
			AttrRequestID: true, AttrVerdictAction: true, AttrVerdictPhase: true,
			AttrVerdictRoute: true, AttrVerdictRules: true, AttrVerdictScore: true,
			"ladder.rows": true, "shield.stages": true,
		}
		for _, lr := range snap.Logs {
			if lr.EventName != SpanName {
				continue
			}
			for _, kv := range lr.Attributes {
				if !pinned[kv.Key] {
					t.Fatalf("record carries attr %q outside the pinned vocabulary (M10)", kv.Key)
				}
			}
		}
		// The walk-order rows: the tokens stay inside the §3.4 set.
		for _, lr := range snap.Logs {
			if lr.EventName != SpanName {
				continue
			}
			rowsRaw := kvGet(lr.Attributes, "ladder.rows")
			if rowsRaw == "" {
				continue
			}
			var tokens []string
			re := regexp.MustCompile(`"stage":"([a-z_]+)"`)
			for _, m := range re.FindAllStringSubmatch(rowsRaw, -1) {
				tokens = append(tokens, m[1])
			}
			for i, tok := range tokens {
				if got := ladder.Stage(i).Token(); got != tok {
					t.Fatalf("row %d token = %q, want %q (walk order = §3.4 order)", i, tok, got)
				}
			}
		}
	})
}
