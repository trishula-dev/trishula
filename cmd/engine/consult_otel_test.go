package main

// TR-195 leaf 4 (issue #237): the consult decisions emit the verdict
// signals. A ban decision produces the correlated triad — the
// trishula.verdict span/log with verdict.action=ban, the request id, the
// route and verdict.dos.sig (class manual-rule, the request path) — plus
// the trishula.ban record with the ban key and the same sig. A pass
// decision emits a triad with verdict.action=allow and no ban record.
// Nil pipeline = no emit (the transparent proxy shape).
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	otel "github.com/trishula-dev/trishula/internal/engine/otel"
)

func consultPipelineBox(t *testing.T) (*bundleBox, *otel.Pipeline) {
	t.Helper()
	p, err := otel.New(otel.Config{ServiceName: "trishula-test"})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(t.Context()) })
	box := &bundleBox{pipe: p}
	return box, p
}

func TestConsultEmitsVerdictSignals(t *testing.T) {
	box, p := consultPipelineBox(t)
	bundle := compileBanBundle(t)
	e, err := loadBundle(bundle)
	if err != nil {
		t.Fatalf("bundle load: %v", err)
	}
	box.set(bundle, e)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream-body"))
	}))
	defer upstream.Close()
	h := newEngineHandlerWithBox(upstream.URL, "engine", box)

	// The banned request: decision=ban, the verdict span + the ban record.
	req, _ := http.NewRequest(http.MethodGet, "http://engine.local/secret/x", nil)
	req.Header.Set("X-Request-ID", "rid-ban-1")
	req.RemoteAddr = "10.9.9.1:39000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ban probe = %d, want 403", w.Code)
	}

	snap := p.Exporter().Snapshot()
	var vspan *otel.Span
	for i := range snap.Spans {
		if snap.Spans[i].Name == "trishula.verdict" {
			vspan = &snap.Spans[i]
		}
	}
	if vspan == nil {
		t.Fatal("trishula.verdict span missing")
	}
	sawSig := false
	for _, kv := range vspan.Attributes {
		switch kv.Key {
		case "request.id":
			if kv.Value != "rid-ban-1" {
				t.Errorf("request.id = %q, want rid-ban-1", kv.Value)
			}
		case "verdict.action":
			if kv.Value != "ban" {
				t.Errorf("verdict.action = %q, want ban", kv.Value)
			}
		case "verdict.route":
			if kv.Value != "/secret/x" {
				t.Errorf("verdict.route = %q, want /secret/x", kv.Value)
			}
		case "verdict.dos.sig":
			sawSig = true
			var s struct {
				Class string   `json:"class"`
				Paths []string `json:"paths"`
			}
			if err := json.Unmarshal([]byte(kv.Value), &s); err != nil {
				t.Fatalf("dos sig json: %v", err)
			}
			if s.Class != "manual-rule" || len(s.Paths) != 1 || s.Paths[0] != "/secret/x" {
				t.Errorf("dos sig wrong: %+v", s)
			}
		case "verdict.rules":
			if kv.Value != "OPS-BAN-01" {
				t.Errorf("verdict.rules = %q, want OPS-BAN-01", kv.Value)
			}
		}
	}
	if !sawSig {
		t.Error("verdict.dos.sig missing on the ban span")
	}

	// The ban record: ban.key = the request's source, the same sig.
	var banLog *otel.LogRecord
	for i := range snap.Logs {
		if snap.Logs[i].EventName == "trishula.ban" {
			banLog = &snap.Logs[i]
		}
	}
	if banLog == nil {
		t.Fatal("trishula.ban record missing")
	}
	hadKey := false
	for _, kv := range banLog.Attributes {
		if kv.Key == "ban.key" && kv.Value != "" {
			hadKey = true
		}
	}
	if !hadKey {
		t.Error("ban.key missing on the ban record")
	}

	// The pass request: verdict action=allow, no ban record added.
	req2, _ := http.NewRequest(http.MethodGet, "http://engine.local/open", nil)
	req2.Header.Set("X-Request-ID", "rid-pass-1")
	req2.RemoteAddr = "10.9.9.1:39000"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("pass probe = %d, want 200", w2.Code)
	}
	snap2 := p.Exporter().Snapshot()
	bans := 0
	for i := range snap2.Logs {
		if snap2.Logs[i].EventName == "trishula.ban" {
			bans++
		}
	}
	if bans != 1 {
		t.Errorf("ban records after the pass probe = %d, want 1", bans)
	}
	var passSpan *otel.Span
	for i := range snap2.Spans {
		a := ""
		for _, kv := range snap2.Spans[i].Attributes {
			if kv.Key == "request.id" {
				a = kv.Value
			}
		}
		if snap2.Spans[i].Name == "trishula.verdict" && a == "rid-pass-1" {
			passSpan = &snap2.Spans[i]
		}
	}
	if passSpan == nil {
		t.Fatal("the pass probe's verdict span missing")
	}
	for _, kv := range passSpan.Attributes {
		if kv.Key == "verdict.action" && kv.Value != "allow" {
			t.Errorf("pass probe verdict.action = %q, want allow", kv.Value)
		}
		if kv.Key == "verdict.dos.sig" {
			t.Error("a pass verdict carries no dos sig")
		}
	}
}

func TestConsultNilPipeEmitsNothing(t *testing.T) {
	box := &bundleBox{}
	bundle := compileBanBundle(t)
	e, err := loadBundle(bundle)
	if err != nil {
		t.Fatalf("bundle load: %v", err)
	}
	box.set(bundle, e)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	h := newEngineHandlerWithBox(upstream.URL, "engine", box)

	req, _ := http.NewRequest(http.MethodGet, "http://engine.local/secret/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ban probe = %d, want 403", w.Code)
	}
	// no pipe = the transparent-proxy shape: the decision stands, nothing
	// panics, nothing emits (the nil pipe = the no-signal contract).
}

func TestConsultEmitFailureKeepsDecision(t *testing.T) {
	// A closed pipeline = a failing emit surface. The decision must stand,
	// the response must stay the 403, and the failure stays logged.
	p, err := otel.New(otel.Config{ServiceName: "trishula-test"})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	box := &bundleBox{pipe: p}
	bundle := compileBanBundle(t)
	e, err := loadBundle(bundle)
	if err != nil {
		t.Fatalf("bundle load: %v", err)
	}
	box.set(bundle, e)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	h := newEngineHandlerWithBox(upstream.URL, "engine", box)

	if perr := p.Shutdown(t.Context()); perr != nil {
		t.Fatalf("shutdown: %v", perr)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://engine.local/secret/x", nil)
	req.RemoteAddr = "10.9.9.1:39000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ban probe after a pipeline shutdown = %d, want 403 (observability never blocks the request)", w.Code)
	}
	if got := w.Header().Get("X-Trishula-Decision"); got != "ban" {
		t.Errorf("X-Trishula-Decision = %q, want ban", got)
	}
}
