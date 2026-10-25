//go:build linux

// cmd/shield — TR-195 leaf 2 (issue #237): the DoS runner host. The
// shield-side process that reads the flow-features projection and drives
// the automatic ban path: the pinned flow_stats map → the cues (the
// detector shapes) → IngestCues (the scored evidence) → Assess (the
// crossing) → the BanEnforcer (the kernel row + the receipt). The kernel
// row drops the offender at the shield (the replay dies at the NIC);
// fail-open everywhere (a failed read or a failed write never blocks the
// packet path).
//
// The map surfaces arrive pinned (the loader's pin discipline — the
// deployment pins the flow_stats and the bans_v4 maps; the daemonset
// mounts the pin dir):
//
//	shield --flow-stats /sys/fs/bpf/trishula/flow_stats \
//	       --bans-v4  /sys/fs/bpf/trishula/bans_v4
package main

import (
	"flag"
	"log"
	"time"

	otel "github.com/trishula-dev/trishula/internal/engine/otel"
	rateban "github.com/trishula-dev/trishula/internal/engine/rateban"
	"github.com/trishula-dev/trishula/internal/shield"
)

func main() {
	flowStats := flag.String("flow-stats", "", "pinned flow_stats map (required)")
	bansV4 := flag.String("bans-v4", "", "pinned bans_v4 map (required)")
	interval := flag.Duration("interval", 5*time.Second, "sweep interval")

	if *flowStats == "" || *bansV4 == "" {
		log.Fatal("shield: --flow-stats and --bans-v4 are required (the pinned map paths)")
	}

	// The verdict pipeline: the would-bans ride the trishula.ban log
	// record (the operator's watertight-observability receipt). The
	// in-process exporter = the v0 surface; the collector cutover rides
	// TR-08c/TR-23 and reuses the schema verbatim. -no-otel turns the
	// pipeline off (the runner keeps the host-log receipts).
	pipes := flag.Bool("no-otel", false, "disable the verdict pipeline (the ban log records)")
	flag.Parse()

	sinks := []rateban.EvidenceSink{}
	if !*pipes {
		p, err := otel.New(otel.Config{ServiceName: "trishula-shield"})
		if err != nil {
			log.Fatalf("shield: verdict pipeline: %v", err)
		}
		sinks = append(sinks, otel.NewBanLogSink(p))
	}

	// The adapters open the pinned maps in the linux surface
	// (internal/shield/dosrunner_linux.go); the core loop is kernel-free
	// (the Sweep cycle: the features → the cues → the assess → the
	// enforce-records; one sweep = one cycle; the errors log and continue).
	runner, err := shield.NewDosRunnerFromPins(*flowStats, *bansV4, shield.WithBanSink(rateban.NewFanoutSink(sinks...)))
	if err != nil {
		log.Fatalf("shield: %v", err)
	}
	log.Printf("shield: the DoS runner up (flow_stats=%s bans_v4=%s interval=%s otel=%v)", *flowStats, *bansV4, *interval, !*pipes)
	for {
		recs, err := runner.Sweep()
		if err != nil {
			log.Printf("shield: sweep error (the packets pass; the next sweep retries): %v", err)
		}
		for _, r := range recs {
			log.Printf("shield: would-ban %s tier=%s score=%.2f sig=%+v", r.Key, r.Tier, r.Score, r.OSig)
		}
		time.Sleep(*interval)
	}
}
