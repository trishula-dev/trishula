package shield

// dosrunner_linux.go — TR-195 leaf 2 (issue #237): the pinned-map adapters
// for the DoS runner host. The flow_stats map is read with the same key
// and value layouts the ingest collection's reader proves (the C structs'
// Go mirrors; the LE host reads the v4 saddr bytes in network order). The
// bans_v4 map is written through the BansV4Map publisher. The reads and
// the writes fail open: the errors surface per sweep and the packets keep
// passing (the shield's contract; the next sweep retries). The engine's
// clock reads CLOCK_MONOTONIC via NowNS — the same clock the kernel and
// the loader use (the expiry parity).

import (
	"fmt"
	"time"

	ebpf "github.com/cilium/ebpf"
	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

// pinnedFlowKey mirrors struct flow_key (bpf/flow_tc.c): the 16-byte
// address unions the generated reader proves, then the ports and the
// family. The map read needs the same binary shape.
type pinnedFlowKey struct {
	Saddr struct {
		V4 uint32
		_  [12]byte
	}
	Daddr struct {
		V4 uint32
		_  [12]byte
	}
	Sport  uint16
	Dport  uint16
	Family uint8
	_      [3]byte
}

// pinnedFlowStat mirrors struct flow_stat (bpf/flow_tc.c).
type pinnedFlowStat struct {
	SynTs      uint64
	FirstSegTs uint64
	LastSegTs  uint64
	ReqBytes   uint32
	SegCount   uint32
}

// pinnedFeatureReader projects a pinned flow_stats map into the detector
// features (the FeatureReader's kernel adapter).
type pinnedFeatureReader struct{ m *ebpf.Map }

// Read walks the map once; the keys carry the printable offender string
// (the v4 source address in dotted form).
func (r pinnedFeatureReader) Read() ([]rateban.FlowFeatures, []string, error) {
	var (
		feats []rateban.FlowFeatures
		keys  []string
	)
	it := r.m.Iterate()
	var k pinnedFlowKey
	var v pinnedFlowStat
	for it.Next(&k, &v) {
		f := rateban.FlowFeatures{
			Segs:    v.SegCount,
			Bytes:   v.ReqBytes,
			FirstNS: v.FirstSegTs,
			LastNS:  v.LastSegTs,
		}
		feats = append(feats, f)
		keys = append(keys, keyString(k))
	}
	if err := it.Err(); err != nil {
		return nil, nil, fmt.Errorf("flow_stats walk: %w", err)
	}
	return feats, keys, nil
}

// keyString renders the flow key's source address (the offender key the
// evidence reads): the network-order v4 bytes in dotted form.
func keyString(k pinnedFlowKey) string {
	var b [4]byte
	b[0] = byte(k.Saddr.V4)
	b[1] = byte(k.Saddr.V4 >> 8)
	b[2] = byte(k.Saddr.V4 >> 16)
	b[3] = byte(k.Saddr.V4 >> 24)
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

// pinnedBansV4 writes the bans_v4 map through the enforcer's interface
// (add-if-absent publish; the enforcer owns the lifts' deletes).
type pinnedBansV4 struct{ m *ebpf.Map }

func (p pinnedBansV4) PutBansV4(k BansV4Key, v BansV4Val) error {
	return p.m.Update(k, v, ebpf.UpdateNoExist)
}

func (p pinnedBansV4) DeleteBansV4(k BansV4Key) error {
	return p.m.Delete(k)
}

// NewDosRunnerFromPins opens the pinned maps and wires the runner core
// (the features → the cues → the assess → the enforce-records; the
// evidence rides the same JSONL the enforcer writes).
func NewDosRunnerFromPins(flowStatsPin, bansV4Pin string, opts ...RunnerOption) (*DosRunner, error) {
	fs, err := ebpf.LoadPinnedMap(flowStatsPin, nil)
	if err != nil {
		return nil, fmt.Errorf("flow_stats pin: %w", err)
	}
	bv, err := ebpf.LoadPinnedMap(bansV4Pin, nil)
	if err != nil {
		return nil, fmt.Errorf("bans_v4 pin: %w", err)
	}
	l := &Loader{}
	sink := rateban.EvidenceSink(nil)
	ro := runnerOption{}
	for _, o := range opts {
		o(&ro)
	}
	if ro.applyBanSink != nil {
		sink = ro.applyBanSink
	}
	if sink == nil {
		sink = rateban.EvidenceSinkFunc(func(rateban.BanEvidence) error { return nil })
	}
	rb := rateban.New(monotonicSec(l), sink)
	enf := NewBanEnforcer(pinnedBansV4{m: bv}, NewJSONLEvidenceSink())
	return &DosRunner{
		Feats: pinnedFeatureReader{m: fs},
		Rb:    rb,
		Enf:   enf,
	}, nil
}

// runnerOption is one NewDosRunnerFromPins knob (the v0 surface is small;
// the OTel ban sink is the first knob).
type runnerOption struct {
	applyBanSink rateban.EvidenceSink
}

// RunnerOption is the exported knob for NewDosRunnerFromPins.
type RunnerOption func(*runnerOption)

// WithBanSink sets the rateban evidence sink the runner's engine records
// would-bans through (the fanout of the receipts; nil default = the no-op
// sink, the host still reads the records the Sweep returns).
func WithBanSink(s rateban.EvidenceSink) RunnerOption {
	return func(o *runnerOption) {
		if s != nil {
			o.applyBanSink = s
		}
	}
}

// monotonicSec returns a rateban clock over CLOCK_MONOTONIC seconds (the
// Loader's NowNS — the same clock the kernel and the bans_v4 values use;
// the expiry parity).
func monotonicSec(l *Loader) func() int64 {
	return func() int64 {
		ns, err := l.NowNS()
		if err != nil {
			return time.Now().Unix() // the fail-open clock (the walls stay consistent)
		}
		return int64(ns / 1e9)
	}
}
