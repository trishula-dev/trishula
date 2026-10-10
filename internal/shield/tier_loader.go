//go:build linux

package shield

// TR-80 (issue #80) — the loader's visibility-tier face.
//
// The boot sequence this file pins: the loader ATTACHES, runs a small
// burst of probe packets, measures what the kernel actually invoked at
// each altitude, classifies the visibility tier (tier.go), and surfaces
// it — as a VALUE (Loader.ShieldTier) and as the ONCE-AT-BOOT attribute
// trishula.shield.visibility_tier (tier_otel.go) carried on the
// startup evidence the engine's OTel pipeline forwards (§15/TR-11: the
// tier rides the shield startup record as an attribute; the pipeline
// schema is unchanged).
//
// TIER_NONE refuses the boot (fail loudly — TierRefusal): an invisible
// shield is a false sense of security.
//
// The PROBE packet burst here is a UDP loopback-to-iface echo pair
// (netns-raw-socket when the caller provides one — the unit fake):
// the counters decide, the L4 choice is transport detail; ICMP is the
// XDP-reliable form the in-VM e2e uses (the deliverable's E2E runs in
// test/tier with the tag shield_tier_e2e).

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// tierAttach performs the loader's attach and returns the kernel seam
// for the probe counters (the loader's own collection: maps already
// wired — the tier probe reads THROUGH the loader's map handles).
func tierAttach(args tierAttachArgs) (TierHandle, error) {
	return attachTierHandle(args.iface)
}

// ShieldTier runs the visibility probe NOW on iface (the loader path:
// attach → burst → classify) and returns the typed tier + evidence.
// The kernel face needs root (in-VM only); the ROOT-LESS tier unit
// suite drives synthetic seams (tier_test.go, no daemon required).
func ShieldTier(iface string) (DetectResult, error) {
	p := NewProbe(tierAttach, kernelStatsSource(iface))
	return p.Detect(iface, kernelBurstSender{})
}

// RequireVisibleTier is the boot gate: NONE must fail the boot loudly.
func RequireVisibleTier(res DetectResult) error {
	if res.Tier == TierNone {
		return &TierRefusal{Iface: res.Iface}
	}
	return nil
}

// kernelStatsSource reads THIS loader's probe counters (the collection
// the attach produced; the iface arg is the seam key for map resolution).
func kernelStatsSource(iface string) StatsSource {
	return func() (ProbeStats, error) {
		h, err := attachTierHandle(iface)
		if err != nil {
			return ProbeStats{}, err
		}
		defer h.Close()
		return h.Stats()
	}
}

// attachTierHandle resolves the live maps on iface (the loader's
// collection in prod; bpftool-id resolution in the e2e). GREEN wire:
// implemented against the loader collection in the next commit.
func attachTierHandle(iface string) (TierHandle, error) {
	return nil, fmt.Errorf("shield: tier handle for %s: loader wiring pending (TR-80)", iface)
}

// kernelBurstSender sends the probe burst (raw socket from a netns when
// the caller provides one; ICMP echo to the host iface otherwise — the
// reliable invocation signal on OrbStack veths). GREEN wire: the ICMP
// burst lands with the loader wiring commit.
type kernelBurstSender struct{}

func (kernelBurstSender) Send(tierAttachArgs, int) error {
	return fmt.Errorf("shield: tier burst: kernel sender pending (TR-80)")
}

// ensureRoot surfaces the privilege requirement with a clear message
// (the probe plane is a root plane; the unit suite never enters it).
func ensureRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("shield: tier kernel probe needs root (CAP_NET_RAW/BPF/PERFMON)")
	}
	return nil
}

// ifaceExists is the sender-side liveness check (burst → bad iface
// fails cleanly instead of a silent zero-tier guess).
func ifaceExists(name string) bool {
	out, err := exec.Command("ip", "-o", "link", "show", name).CombinedOutput()
	return err == nil && strings.Contains(string(out), name)
}
