// Package shield — TR-80 (issue #80) — the visibility-tier probe and its
// wire/OTel contract, pinned BEFORE the loader C (the repo's
// hypothesis-first standard, contract_test.go posture).
//
// This file's suite drives the probe's CLASSIFICATION and its emitted
// vocabulary through synthetic counters (kernel-free, runs everywhere,
// no root, no daemon). The REAL kernel probe (bpf2go load on Linux,
// netns ICMP burst) is root-gated in test/tier (the shield_tier_e2e tag).
package shield

import "testing"

// The classification contract: given per-burst deltas (packets sent vs
// counters ticked at each altitude) the classifier must return the tier
// named in issue #80's vocabulary. These are the SAME shapes the VM e2e
// measures through probe_stats (kernel-truth evidence).
func TestClassifyTier(t *testing.T) {
	const n = 5
	cases := []struct {
		name   string
		deltas ProbeDelta
		want   Tier
	}{
		{"every packet seen at both altitudes → FULL",
			ProbeDelta{sent: n, xdp: n, tc: n}, TierFull},
		{"TC saw only packet #1 of the connection → FIRST_PACKET",
			ProbeDelta{sent: n, xdp: 0, tc: 1}, TierFirstPacket},
		{"XDP saw only ICMP (netns UDP ignored; TR-04d) → FIRST_PACKET",
			ProbeDelta{sent: n, xdp: 1, tc: 0}, TierFirstPacket},
		{"partial burst (3 of 5 segments visible) → FIRST_PACKET",
			ProbeDelta{sent: n, xdp: 0, tc: 3}, TierFirstPacket},
		{"nothing observed at any altitude → NONE",
			ProbeDelta{sent: n, xdp: 0, tc: 0}, TierNone},
		{"zero packets sent → NONE (not FULL: nothing measured)",
			ProbeDelta{sent: 0, xdp: 0, tc: 0}, TierNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.deltas)
			if got != tc.want {
				t.Fatalf("classify(%+v) = %s, want %s", tc.deltas, got, tc.want)
			}
		})
	}
}

// The tier literal is the OTel attribute value — the emitted metric/attr
// vocabulary is pinned here so the collector (TR-08c/TR-23) can key on it.
func TestTierStringContract(t *testing.T) {
	cases := map[Tier]string{
		TierFull:        "full",
		TierFirstPacket: "first_packet",
		TierNone:        "none",
		TierUnknown:     "unknown",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Fatalf("Tier(%d).String() = %q, want %q", tier, got, want)
		}
		if tier != TierUnknown && tier.Enforcement() == "" {
			t.Fatalf("Tier(%d).Enforcement() empty for known tier", tier)
		}
	}
}

// Detect() through synthetic seams (NO root): a burst of 5 with only the
// first packet reaching TC classifies FIRST_PACKET, evidence intact.
func TestProbeDetectSyntheticFirstPacket(t *testing.T) {
	stats := ProbeStats{XDP: 0, TC: 1}
	pr := NewProbe(
		func(tierAttachArgs) (TierHandle, error) { return fakeHandle{}, nil },
		func() (ProbeStats, error) { return stats, nil },
	)
	res, err := pr.Detect("k8s-pod-veth", fakeSender{})
	if err != nil {
		t.Fatalf("Detect(): %v", err)
	}
	if res.Tier != TierFirstPacket {
		t.Fatalf("tier = %s, want first_packet", res.Tier)
	}
	if res.Iface != "k8s-pod-veth" || res.Ev.Sent != ProbesPerBurst ||
		res.Ev.XDPInvoked != 0 || res.Ev.TCInvoked != 1 {
		t.Fatalf("evidence incomplete: %+v", res)
	}
	if res.Reason == "" {
		t.Fatal("empty reason: the tier must carry its WHY")
	}
}

// Detect() through synthetic seams: a FULL burst classifies FULL.
func TestProbeDetectSyntheticFull(t *testing.T) {
	pr := NewProbe(
		func(tierAttachArgs) (TierHandle, error) { return fakeHandle{}, nil },
		func() (ProbeStats, error) { return ProbeStats{XDP: 5, TC: 5}, nil },
	)
	res, err := pr.Detect("tr04h", fakeSender{})
	if err != nil {
		t.Fatalf("Detect(): %v", err)
	}
	if res.Tier != TierFull {
		t.Fatalf("tier = %s, want full", res.Tier)
	}
}

// A failing sender surfaces as a probe error (the boot refuses on a
// probe that could not run — never on a guessed tier).
func TestProbeDetectSenderError(t *testing.T) {
	pr := NewProbe(
		func(tierAttachArgs) (TierHandle, error) { return fakeHandle{}, nil },
		func() (ProbeStats, error) { return ProbeStats{}, nil },
	)
	if _, err := pr.Detect("x", boomSender{}); err == nil {
		t.Fatal("sender failure must surface, got nil error")
	}
}

// Wiring errors surface (nil seams are boot bugs, not tiers).
func TestProbeWiringErrors(t *testing.T) {
	if _, err := (*Probe)(nil).Detect("x", fakeSender{}); err == nil {
		t.Fatal("nil probe must error")
	}
	if _, err := NewProbe(nil, nil).Detect("x", fakeSender{}); err == nil {
		t.Fatal("nil seams must error")
	}
	if _, err := NewProbe(
		func(tierAttachArgs) (TierHandle, error) { return fakeHandle{}, nil },
		func() (ProbeStats, error) { return ProbeStats{}, nil },
	).Detect("", fakeSender{}); err == nil {
		t.Fatal("empty iface must error")
	}
}

// The e2e gate's per-interface evidence line format (lab/tier-gate.sh
// greps EXACTLY this: TIER(<iface>)=<tier>).
func TestTierEvidenceLine(t *testing.T) {
	if got, want := TierLine("k8s-pod-veth", TierFirstPacket), "TIER(k8s-pod-veth)=first_packet"; got != want {
		t.Fatalf("TierLine = %q, want %q", got, want)
	}
}

// The OTel attribute contract (tier_otel.go): constant key, value =
// the tier literal, iface label carried for the boot emit.
func TestTierOTelAttrContract(t *testing.T) {
	if AttrShieldVisibilityTier != "trishula.shield.visibility_tier" {
		t.Fatalf("attr key = %q, want trishula.shield.visibility_tier", AttrShieldVisibilityTier)
	}
	_kv, err := TierOTelAttr("tr04h", TierFull)
	if err != nil {
		t.Fatalf("TierOTelAttr: %v", err)
	}
	if _kv.Key != "trishula.shield.visibility_tier" || _kv.Value != "full" || _kv.Iface != "tr04h" {
		t.Fatalf("attr = %+v", _kv)
	}
	if _, err := TierOTelAttr("", TierFull); err == nil {
		t.Fatal("empty iface must error")
	}
	if _, err := TierOTelAttr("x", TierUnknown); err == nil {
		t.Fatal("unprobed tier must error (never emit unknown)")
	}
}

// The refusal error type is errors.Is-able (the boot-path contract).
func TestTierRefusal(t *testing.T) {
	err := &TierRefusal{Iface: "eth0"}
	if err.Error() == "" {
		t.Fatal("empty refusal text")
	}
}

// --- synthetic seams (kernel-free; the e2e uses the kernel source) ---

type fakeHandle struct{}

func (fakeHandle) Stats() (ProbeStats, error) { return ProbeStats{}, nil }
func (fakeHandle) Close() error               { return nil }

type fakeSender struct{}

func (fakeSender) Send(tierAttachArgs, int) error { return nil }

type boomSender struct{}

func (boomSender) Send(tierAttachArgs, int) error { return errBoom }

var errBoom = errStr("probe sender: synthetic failure")

type errStr string

func (e errStr) Error() string { return string(e) }
