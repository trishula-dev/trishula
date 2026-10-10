// Package shield — TR-10 (issue #10): the ScoredWindowBan enforcement leg.
//
// bans_v4 is the ENFORCEMENT plane the rateban engine publishes into: an
// LRU-hash map keyed by the offender's source IPv4 (u32, network byte
// order) whose value is {ban_until_ms u64, score u16, reason_code u16}.
// bpf/ban_xdp.c enforces it BEFORE the TR-03 verdict-cache/ACL verdicts:
// a packet from a banned source is TC_ACT_SHOT'd at XDP (XDP_DROP) and
// expiry auto-lifts the verdict in-kernel.
//
// RED stub — the symbols below are the contract this leg lands; the GREEN
// commit implements them (BanEnforcer publish-on-assess, expiry
// reconcile, JSONL evidence).
package shield

import "net/netip"

// ReasonCode maps a §13.4 ladder tier name to its wire reason code in
// BansV4Val.reason_code. "" (an unscored ban — the TR-03 legacy posture)
// maps to 0.
//
// RED stub — implemented in the GREEN commit.
func ReasonCode(tier string) (uint16, error) {
	panic("TR-10 GREEN pending: ReasonCode")
}

// BansV4KeyFromIP builds a bans_v4 key: 4-byte network-order saddr +
// family/class loader discipline. IPv6 is refused (bans_v4 is IPv4-keyed;
// the dual-stack ban_table carries v6 bans).
//
// RED stub — implemented in the GREEN commit.
func BansV4KeyFromIP(ip netip.Addr) (BansV4Key, error) {
	panic("TR-10 GREEN pending: BansV4KeyFromIP")
}
