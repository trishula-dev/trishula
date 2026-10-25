package shield

// TR-195 leaf 2 (issue #237): the runner core RED→GREEN. The fake feature
// reader drives the sweep; the fake publisher records the kernel puts.
// The assertions: only the slowloris flow carries the shape, the would-ban
// carries the signature verbatim (the operator's watertight chain), the
// kernel publish lands, and a failed publish surfaces while the records
// ride (the fail-open sweep).
import (
	"testing"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

type fakeFeats struct{ rows []rateban.FlowFeatures }

func (f fakeFeats) Read() ([]rateban.FlowFeatures, []string, error) {
	keys := make([]string, len(f.rows))
	for i := range f.rows {
		keys[i] = "10.9.9.1"
	}
	return f.rows, keys, nil
}

type fakePub struct {
	puts int
	err  error
}

func (p *fakePub) PutBansV4(k BansV4Key, v BansV4Val) error {
	if p.err != nil {
		return p.err
	}
	p.puts++
	return nil
}
func (p *fakePub) DeleteBansV4(k BansV4Key) error { return nil }

func slowFeature() rateban.FlowFeatures {
	f := rateban.FlowFeatures{Segs: 30, Bytes: 30 * 8} // 8 bytes/seg, trickled
	f.FirstNS = uint64(1_000_000_000_000)
	f.LastNS = f.FirstNS + 40*1_000_000_000 // the span = 40 s
	return f
}

type pubErr struct{}

func (e *pubErr) Error() string { return "publish failed (test fixture)" }

func TestSweepSlowlorisPublishesWithSignature(t *testing.T) {
	var sinkRows []rateban.BanEvidence
	rb := rateban.New(func() int64 { return 1_000_000 }, rateban.EvidenceSinkFunc(func(r rateban.BanEvidence) error {
		sinkRows = append(sinkRows, r)
		return nil
	}))
	pub := &fakePub{}
	enf := NewBanEnforcer(pub, NewJSONLEvidenceSink())
	enf.SetClock(func() (uint64, error) { return 1_234_567_890_000, nil })
	r := &DosRunner{
		Feats: fakeFeats{rows: []rateban.FlowFeatures{
			slowFeature(), // cue 1: kernelBurstFlag +3
			slowFeature(), // cue 2: +3 (same key)
			slowFeature(), // cue 3: +3 (same key, 9 = below T)
			slowFeature(), // cue 4: +3 = 12 crosses T = 10
			rateban.FlowFeatures{Segs: 4, Bytes: 4000, FirstNS: 1, LastNS: 2}, // not a suspect
		}},
		Rb:  rb,
		Enf: enf,
	}
	recs, err := r.Sweep()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1 (the key's cues sum past the threshold)", len(recs))
	}
	if pub.puts != 1 {
		t.Fatalf("kernel puts = %d, want 1", pub.puts)
	}
	sig := recs[0].OSig
	if sig == nil || sig.Segs != 30 || sig.BytesPerSeg != 8 || sig.SpanSec != 40 {
		t.Fatalf("signature missing/wrong: %+v", sig)
	}
	if recs[0].Tier != "scored-window" {
		t.Errorf("tier = %q, want scored-window (the sweep rides the score path)", recs[0].Tier)
	}
	if len(sinkRows) > 0 && sinkRows[0].OSig == nil {
		t.Error("the evidence sink must carry the signature too (the watertight chain)")
	}
}

func TestSweepSigFailsOpenOnPublishError(t *testing.T) {
	rb := rateban.New(func() int64 { return 1_000_000 }, rateban.EvidenceSinkFunc(func(rateban.BanEvidence) error {
		return nil
	}))
	pub := &fakePub{err: &pubErr{}}
	enf := NewBanEnforcer(pub, NewJSONLEvidenceSink())
	enf.SetClock(func() (uint64, error) { return 1_234_567_890_000, nil })
	r := &DosRunner{Feats: fakeFeats{rows: []rateban.FlowFeatures{
		slowFeature(), slowFeature(), slowFeature(), slowFeature(), // 4 cues = 12 crosses T
	}}, Rb: rb, Enf: enf}
	re, err := r.Sweep()
	if re == nil || len(re) != 1 {
		t.Fatalf("records must ride on a failed publish: %+v err %v", re, err)
	}
	if err == nil {
		t.Fatal("the publish error must surface (evidenced), never silent")
	}
}
