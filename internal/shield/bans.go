package shield

import (
	"fmt"
	"net/netip"
)

// Wire contract (internal/shield/banwire_test.go, defect #62 amended):
// keys carry a family-discriminated 16-byte address union — a bare u32
// cannot represent IPv6 (dual-stack: the spec's acl4/acl6 map pair; the /24-vs-/48 ban prefix rule).
//
//   struct ban_key {
//       union { __be32 v4; __u8 v6[16]; } addr;   // network byte order
//       __u8 family;                              // 4 | 6, explicit
//       __u8 key_class;                           // ip | ja4_cluster | prefix
//   };
//   struct ban_val { __u64 until_ts; __u8 tier; __u16 reason_code; };  // +2 pad

// Key family discriminators mirroring the kernel ABI (4 = AF_INET-sized
// address, 6 = AF_INET6). These are wire constants, not Go net.Dial
// network strings.
const (
	FamilyV4 uint8 = 4
	FamilyV6 uint8 = 6
)

// Key classes (the reference-implementation prose); PR #2 grows the set (ja4_cluster, prefix).
const (
	KeyClassIP uint8 = 0
)

// BanKey is the map key on the ban_table (LRU hash). Addr is network byte
// order; v4 occupies only Addr[:4] (the remainder is zero — union
// discipline). Marshals to exactly 18 bytes (banwire_test.go).
type BanKey struct {
	Addr     [16]byte
	Family   uint8
	KeyClass uint8
	_        [2]byte // C u64-alignment tail (bpf_shieldBanKey parity)
}

// validateBanVal is the loader-side check (host-portable, wire-safe).
func validateBanVal(v BanVal) error {
	if v.UntilTS == 0 {
		return fmt.Errorf("ban with zero expiry (infinite bans forbidden)")
	}
	return nil
}

// BanVal's until_ts is absolute CLOCK_MONOTONIC nanoseconds
// (what bpf_ktime_get_ns reads); the loader NEVER writes a zero/absent
// expiry (infinite bans are a TR-10 safety property — banned means timed).
// Marshals to 16 bytes (8 + tier + pad + reason + 4B struct alignment —
// exactly bpf_shieldBanVal in the generated object).
type BanVal struct {
	UntilTS    uint64
	Tier       uint8
	Pad        uint8 // struct alignment (explicit: wire stability)
	ReasonCode uint16
	_          [4]byte // C struct alignment tail
}

// Expired reports whether the ban is over at monotonic-read now:
// expiry semantics are `now >= until` (the ban holds while now < until).
func (v BanVal) Expired(now uint64) bool { return now >= v.UntilTS }

// BanKeyFromIP builds a family-discriminated key from either address
// family. v4 keys zero the upper 12 bytes (aliases cannot collide).
func BanKeyFromIP(ip netip.Addr, class uint8) BanKey {
	ip = ip.Unmap()
	if ip.Is4() {
		return BanKey{
			Addr:     addr4To16(ip.As4()),
			Family:   FamilyV4,
			KeyClass: class,
		}
	}
	return BanKey{
		Addr:     ip.As16(),
		Family:   FamilyV6,
		KeyClass: class,
	}
}

func addr4To16(a4 [4]byte) [16]byte {
	var a [16]byte
	copy(a[:4], a4[:])
	return a
}

// Verdict actions (verdict_cache/ban enforcement ABI; kernel-side mirror in
// bpf/shield_xdp.c enum verdict_action).
const (
	VerdictAllow uint8 = 0
	VerdictDrop  uint8 = 1
)

// ShieldSpec is the compiled-object contract (reference-implementation names/sizes/types).
// Zero-value = the spec pin; a caller may only tighten via tests.
type ShieldSpec struct{}

// MapSpec is one reference-implementation map contract row (name, kind, max_entries).
type MapSpec struct {
	Name       string
	Kind       string // lpm_trie | lru_hash | ringbuf
	MaxEntries uint32
}
