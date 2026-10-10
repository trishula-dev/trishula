// Package shield — TR-10 (issue #10): the ScoredWindowBan enforcement leg.
//
// bans_v4 is the ENFORCEMENT plane the rateban engine publishes into: an
// LRU-hash map keyed by the offender's source IPv4 (u32, network byte
// order) whose value is {ban_until_ms u64, score u16, reason_code u16}.
// bpf/ban_xdp.c enforces it BEFORE the TR-03 verdict-cache/ACL verdicts:
// a packet from a banned source is TC_ACT_SHOT'd at XDP (XDP_DROP) and
// expiry auto-lifts the verdict in-kernel (now >= ban_until_ms ⇒ pass).
package shield

import (
	"fmt"
	"net/netip"
)

// Wire reason codes for BansV4Val.reason_code. The §13.4 tier names are
// the reason space at v0 (bans_v4 scores are engine-produced); 0 is the
// TR-03 legacy convention for an unscored ban. Keep in step with
// bpf/ban_xdp.c's comment block — the wire carries the code, the record
// carries the name.
const (
	reasonUnspecified  uint16 = 0
	ReasonScoredWindow uint16 = 1300
)

var reasonCodes = map[string]uint16{
	"scored-window": ReasonScoredWindow,
	"":              reasonUnspecified, // TR-03 legacy: unscored kernel bans
}

// ReasonCode maps a §13.4 ladder tier name to its wire reason code in
// BansV4Val. Unknown tiers are an error: the code space stays a known
// enum (the evidence record carries the name; the wire does not invent).
func ReasonCode(tier string) (uint16, error) {
	code, ok := reasonCodes[tier]
	if !ok {
		return 0, fmt.Errorf("shield: unknown ban reason tier %q", tier)
	}
	return code, nil
}

// BansV4KeyFromIP builds a bans_v4 key: 4-byte network-order saddr +
// family/class loader discipline (the same union prefix the dual-stack
// ban_table keys use, so the enforcement and kernel tables agree).
// IPv6 is refused (bans_v4 is IPv4-keyed; the dual-stack ban_table
// carries v6 bans).
func BansV4KeyFromIP(ip netip.Addr) (BansV4Key, error) {
	ip = ip.Unmap()
	if !ip.Is4() {
		return BansV4Key{}, fmt.Errorf("shield ifaces: bans_v4 is IPv4-keyed, got %s", ip)
	}
	return BansV4Key{
		SAddr:    ip.As4(),
		Family:   FamilyV4,
		KeyClass: KeyClassIP,
	}, nil
}
