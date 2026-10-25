package shield

// dosrunner.go — TR-195 leaf 2 (issue #237; the operator's decision): the
// AUTOMATIC DoS leg. The runner sweeps the flow-features projection into
// the ban path: the feature read → the cues → IngestCues (the scored
// evidence) → Assess (the shadow crossing) → BanEnforcer.Record (the
// kernel row + the receipt). The cue note, the evidence record and the
// kernel row state the same signature. Kernel-free core: the FeatureReader
// interface decouples the pinned-map adapter (the linux surface files
// this record's leaf 3).

import (
	"errors"
	"fmt"

	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
)

// FeatureReader projects the shield's per-flow map into detector features.
// Each entry carries the flow key string (the offender key the evidence
// reads) and the measured window. Errors surface per-sweep (the sweep
// continues: fail-open on read failures, the packet passes).
type FeatureReader interface {
	Read() ([]rateban.FlowFeatures, []string, error)
}

// DosRunner runs the automatic DoS loop on the shield side.
type DosRunner struct {
	Feats FeatureReader
	Rb    *rateban.Engine
	Enf   *BanEnforcer
}

// Sweep runs one cycle: the features → the cues → the assess → the
// enforce-records. Returns the would-ban records (the receipts) and the
// joined errors (the sweep never aborts on one flow's cue).
func (r *DosRunner) Sweep() ([]rateban.BanEvidence, error) {
	feats, keys, err := r.Feats.Read()
	if err != nil {
		return nil, err
	}
	cues, errs := cuesFromFeatures(feats, keys)
	recs, err := r.Rb.IngestCues(cues)
	if err != nil {
		errs = append(errs, err)
	}
	for _, rec := range recs {
		if rerr := r.Enf.Record(rec); rerr != nil {
			errs = append(errs, fmt.Errorf("enforce %s: %w", rec.Key, rerr))
		}
	}
	return recs, errors.Join(errs...)
}

// cuesFromFeatures reads the detector shapes: the feature projection → the
// cue (the offender key + the class + the measured signature). The
// slowloris shape drives the first leaf; the rapid-reset shape reads the
// parser counters (the leaf that follows with its transport).
func cuesFromFeatures(feats []rateban.FlowFeatures, keys []string) ([]rateban.Cue, []error) {
	cues := []rateban.Cue{}
	for i, f := range feats {
		if !rateban.SlowlorisSuspect(f) {
			continue
		}
		key := "unknown"
		if i < len(keys) {
			key = keys[i]
		}
		sig := rateban.DoSSig{
			Class:       "slowloris_suspect",
			Segs:        f.Segs,
			BytesPerSeg: bps(f),
			SpanSec:     int64((f.LastNS - f.FirstNS) / 1e9),
		}
		cues = append(cues, rateban.Cue{
			Key:   key,
			Class: rateban.CueSlowloris,
			AtSec: int64(f.LastNS / 1e9),
			Note:  "slowloris_suspect (" + sig.String() + ")",
			Sig:   sig,
		})
	}
	return cues, nil
}

// bps guards the zero divide: a flow with zero counted segments carries no
// bytes-per-segment fact (zero reads absent in the sig).
func bps(f rateban.FlowFeatures) uint32 {
	if f.Segs == 0 {
		return 0
	}
	return f.Bytes / f.Segs
}
