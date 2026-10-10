package shield

// TR-10 (issue #10): the bans_v4 wire. bpf/ban_xdp.c declares the same
// layout in C (its reason block cites these codes):
//
//	struct BansV4Key { __be32 saddr; __u8 family; __u8 key_class; __u16 _pad; };
//	struct BansV4Val { __u64 ban_until_ms; __u16 score; __u16 reason_code; __u32 _pad; };
//
// Key = 8 bytes (be32 + u8 + u8 + u16 pad), value = 16 bytes (u64 + u16 +
// u16 + u32 pad). Go wires fixed-size structs — no dynamic slices.
import "encoding/binary"

// BansV4Key is the map key: the offender's source IPv4 in network byte
// order, with the loader's family/class discipline fields (bans_v4 is
// IPv4-keyed — the dual-stack ban_table carries v6 bans).
type BansV4Key struct {
	SAddr    [4]byte // network byte order (be32)
	Family   uint8   // FamilyV4
	KeyClass uint8   // KeyClassIP
	_        uint16  // C u32-alignment tail (blank: binary skips, size counts)
}

// BansV4Val is the enforcement value: absolute kernel-clock milliseconds
// (CLOCK_MONOTONIC; bpf_ktime_get_ns / 1e6), the §13.3 score at crossing
// as score × 100 (2 decimals), and the wire reason code. Expiry parity
// with the engine/record: now_ms >= BanUntilMs means the ban is over.
type BansV4Val struct {
	BanUntilMs uint64
	Score      uint16
	ReasonCode uint16
	_          uint32 // C struct alignment tail (blank: binary skips, size counts)
}

// Compile-time wire assertions (banenforce_test.go pins the contract).
var _ = [1]struct{}{}[binary.Size(BansV4Key{})-8]
var _ = [1]struct{}{}[binary.Size(BansV4Val{})-16]
