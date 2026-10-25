package rateban

// TR-195 leaf 3 (issue #237): the fanout sink. One record, every receipt:
// the OTel ban record and the engine's own sinks receive the same record;
// one failing sink never hides the others (the errors join; the records
// stay receipts, never enforcement).
import (
	"errors"
	"strings"
	"testing"
)

func TestFanoutDeliversToEverySink(t *testing.T) {
	saw := 0
	ok := EvidenceSinkFunc(func(BanEvidence) error { saw++; return nil })
	boom := EvidenceSinkFunc(func(BanEvidence) error { return errors.New("sink down") })
	rec := BanEvidence{Key: "1.2.3.4", Tier: "scored-window"}
	if err := NewFanoutSink(ok, boom, ok).Record(rec); err == nil || !strings.Contains(err.Error(), "sink down") {
		t.Fatalf("the failing sink's error must join: %v", err)
	}
	if saw != 2 {
		t.Fatalf("good sink saw %d records, want 2 (one bad sink hides nothing)", saw)
	}
}

func TestFanoutSkipsNilSinks(t *testing.T) {
	calls := 0
	ok := EvidenceSinkFunc(func(BanEvidence) error { calls++; return nil })
	if err := NewFanoutSink(nil, ok, nil).Record(BanEvidence{Key: "k"}); err != nil {
		t.Fatalf("nil sinks skip cleanly: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}
