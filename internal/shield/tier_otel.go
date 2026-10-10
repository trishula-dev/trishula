package shield

// TR-80 (issue #80) — the tier's OTel wire contract. The loader emits
// trishula.shield.visibility_tier ONCE AT BOOT per interface, as an
// attribute on the shield's startup evidence (the engine's OTel pipeline
// is internal/engine/otel — §15/TR-11: one span + one metric + one log
// per verdict; the tier rides the SHIELD's boot path as an attribute, not
// a new pipeline). Collector wire note (TR-08c/TR-23): the attribute key
// below is stable; its value is Tier.String()'s literal
// ("full" | "first_packet" | "none").
//
// Emission wiring: the linux loader path (probe_kernel.go) calls
// TierOTelAttr after Detect classifies and threads the KeyValue into the
// startup record; the CI suite pins the key + value shape HERE
// (kernel-free) — no daemon requirement.

import "fmt"

// AttrShieldVisibilityTier is the attribute key emitted once at boot,
// per interface (the iface travels in the record's label set).
const AttrShieldVisibilityTier = "trishula.shield.visibility_tier"

// TierOTelAttr builds the boot-emit attribute for one interface. The
// value renders as the tier literal via KVValue (the pipeline's exported
// string form — internal/engine/otel.KV.Value is a string).
func TierOTelAttr(iface string, t Tier) (AttrKV, error) {
	if iface == "" {
		return AttrKV{}, fmt.Errorf("shield: tier attr for empty iface")
	}
	if t == TierUnknown {
		return AttrKV{}, fmt.Errorf("shield: tier attr for unprobed tier")
	}
	return AttrKV{Key: AttrShieldVisibilityTier, Value: t.String(), Iface: iface}, nil
}

// TierLine renders the CI-evidence line lab/tier-gate.sh prints and the
// PR asserts: TIER(<iface>)=<tier>.
func TierLine(iface string, t Tier) string {
	return "TIER(" + iface + ")=" + t.String()
}

// AttrKV is one label/value pair for the startup evidence (the plain
// form exported to the engine's pipeline — no SDK types leak here).
type AttrKV struct {
	Key   string
	Value string
	Iface string
}
