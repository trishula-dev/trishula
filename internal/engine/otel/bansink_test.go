package otel

// TR-195 leaf 3 (issue #237): the ban observability surface.
//
// RED→GREEN: a rateban would-ban that rides BanLogSink lands the
// trishula.ban log record in the exporter snapshot — the ban key, tier,
// score, reasons and (when the record carries one) the dynamic signature
// verdict.dos.sig, the DoSSig JSON verbatim. The verdict signal's own
// attribute set carries the same sig when its Verdict holds one, and no
// dos attr when it does not (the absence carries no claim).
import (
	"encoding/json"
	"testing"

	"github.com/trishula-dev/trishula/internal/engine/ladder"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

func banEvidenceWithSig() rateban.BanEvidence {
	sig := rateban.DoSSig{
		Class:       "slowloris_suspect",
		Segs:        30,
		BytesPerSeg: 8,
		SpanSec:     40,
		Paths:       []string{"/api/login", "/api/health"},
	}
	return rateban.BanEvidence{
		Key:         "10.9.9.1",
		Mode:        "shadow",
		Verdict:     "would-ban",
		Tier:        "scored-window",
		Score:       12.0,
		Threshold:   10.0,
		ReasonCodes: []string{"kernelBurstFlag"},
		AtSec:       1_234_568,
		UntilSec:    1_240_568,
		OSig:        &sig,
	}
}

func TestEmitBanCarriesSigJSON(t *testing.T) {
	p, err := New(Config{ServiceName: "trishula-test"})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	defer p.Shutdown(t.Context())

	b := banEvidenceWithSig()
	if err := p.EmitBan(b); err != nil {
		t.Fatalf("EmitBan: %v", err)
	}
	snap := p.exp.Snapshot()
	if len(snap.Logs) != 1 {
		t.Fatalf("log records = %d, want 1", len(snap.Logs))
	}
	lr := snap.Logs[0]
	if want := "trishula.ban"; lr.EventName != want {
		t.Errorf("event name = %q, want %q", lr.EventName, want)
	}
	var sigJSON string
	var got rateban.DoSSig
	for _, kv := range lr.Attributes {
		switch kv.Key {
		case AttrBanKey:
			if kv.Value != b.Key {
				t.Errorf("ban.key = %q, want %q", kv.Value, b.Key)
			}
		case AttrBanTier:
			if kv.Value != b.Tier {
				t.Errorf("ban.tier = %q, want %q", kv.Value, b.Tier)
			}
		case AttrBanReason:
			if kv.Value != "kernelBurstFlag" {
				t.Errorf("ban.reason = %q, want kernelBurstFlag", kv.Value)
			}
		case AttrDosSig:
			sigJSON = kv.Value

		case AttrRequestID:
			t.Error("a flow-keyed ban carries no request.id (the key IS the correlation)")
		}
	}
	if sigJSON == "" {
		t.Fatal("verdict.dos.sig missing from the ban record")
	}
	if err := json.Unmarshal([]byte(sigJSON), &got); err != nil {
		t.Fatalf("dos sig json: %v", err)
	}
	if got.Class != "slowloris_suspect" || got.Segs != 30 || got.SpanSec != 40 || len(got.Paths) != 2 {
		t.Errorf("dos sig json wrong: %+v", got)
	}
}

func TestEmitBanWithoutSigCarriesNoClaim(t *testing.T) {
	p, err := New(Config{ServiceName: "trishula-test"})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	defer p.Shutdown(t.Context())

	b := banEvidenceWithSig()
	b.OSig = nil
	if err := p.EmitBan(b); err != nil {
		t.Fatalf("EmitBan: %v", err)
	}
	for _, kv := range p.exp.Snapshot().Logs[0].Attributes {
		if kv.Key == AttrDosSig {
			t.Errorf("nil sig must carry no dos attr; got %q", kv.Value)
		}
	}
}

// verdictForTest builds a Verdict carrying (or not carrying) a dos
// signature (the test's builder; the real producers land with the S6
// stage's scored-path wiring).
func verdictForTest(s *rateban.DoSSig) *ladder.Verdict {
	return &ladder.Verdict{Action: ladder.ActionBan, Score: 12, Phase: ladder.PhaseRequestHeaders, DosSig: s}
}

func TestVerdictAttrsCarrySigWhenSet(t *testing.T) {
	sig := rateban.DoSSig{Class: "slowloris_suspect", Segs: 28, BytesPerSeg: 10, SpanSec: 34}
	v := verdictForTest(&sig)
	attrs := VerdictAttrs(nil, v)
	found := false
	for _, kv := range attrs {
		if kv.Key == AttrDosSig {
			found = true
			if json.Unmarshal([]byte(kv.Value.AsString()), &sig) != nil {
				t.Errorf("dos sig json unparseable: %q", kv.Value.AsString())
			}
		}
	}
	if !found {
		t.Error("verdict.dos.sig missing: the verdict record must cite the same sig")
	}
	// Nil sig = no attr (the absence carries no claim).
	attrsNil := VerdictAttrs(nil, verdictForTest(nil))
	for _, kv := range attrsNil {
		if kv.Key == AttrDosSig {
			t.Errorf("nil sig must carry no dos attr; got %q", kv.Value.AsString())
		}
	}
}
