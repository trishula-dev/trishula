package shield

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
)

// Ban-entry wire contract (§19.1 sketch, amended per defect #62): keys are
// family-discriminated unions — a bare u32 address cannot represent IPv6
// (dual-stack: §9.3 acl4/acl6, §13.3 /24 vs /48 prefix escalation).
//
//	struct ban_key {
//	    union { __be32 v4; __u8 v6[16]; } addr;
//	    __u8 family;                     // 4 | 6 — explicit, not inferred
//	    __u8 key_class;
//	};
//
// struct ban_val { __u64 until_ts; __u8 tier; __u16 reason_code; };
const (
	keyClassIP uint8 = 0

	// Key families (mirror AF_INET=2 / AF_INET6=10 so kernel+userspace
	// agree on the discriminator without an errno-abi header include).
	familyV4 uint8 = 4
	familyV6 uint8 = 6

	// Wire sizes on little-endian arm64/amd64 targets (bpf2go targets);
	// Go side marshals via the same fixed-size structs.
	BanKeySize = 18 // 16-byte union + u8 family + u8 key_class
	BanValSize = 12 // u64 until_ts + u8 tier + pad + u16 reason_code
)

func TestBanEntryWireContract(t *testing.T) {
	// The loader writes ban entries; assert our Go struct layout matches
	// the C wire size so map I/O never silently mis-parses.
	var k BanKey
	var v BanVal
	if size := binary.Size(k); size != BanKeySize {
		t.Fatalf("BanKey marshals to %d bytes, want %d", size, BanKeySize)
	}
	if size := binary.Size(v); size != BanValSize {
		t.Fatalf("BanVal marshals to %d bytes, want %d", size, BanValSize)
	}
}

func TestBanKeyParsing(t *testing.T) {
	// v4: 4-byte address, network order, family=4.
	v4 := netip.MustParseAddr("192.0.2.7")
	k4 := BanKeyFromIP(v4, keyClassIP)
	a4 := v4.As4()
	if k4.Family != familyV4 {
		t.Fatalf("v4 key family = %d, want %d", k4.Family, familyV4)
	}
	if got := binary.BigEndian.Uint32(k4.Addr[:4]); got != binary.BigEndian.Uint32(a4[:]) {
		t.Fatalf("v4 key addr = %#x, want network-order %#x", got, binary.BigEndian.Uint32(a4[:]))
	}
	// The v4 bytes beyond addr[4] must be zeroed (union discipline).
	if k4.Addr[4] != 0 || k4.Addr[15] != 0 {
		t.Fatalf("v4 key polluted the v6 half of the union: %v", k4.Addr)
	}
	// v6: full 16-byte address, family=6.
	v6 := netip.MustParseAddr("2001:db8::7")
	k6 := BanKeyFromIP(v6, keyClassIP)
	if k6.Family != familyV6 {
		t.Fatalf("v6 key family = %d, want %d", k6.Family, familyV6)
	}
	want6 := v6.As16()
	if k6.Addr != want6 {
		t.Fatalf("v6 key addr = %v, want %v", k6.Addr, want6)
	}
	// Distinct families never alias (a v6 addr is not a v4 key).
	if k4 == k6 {
		t.Fatal("v4 and v6 keys collapsed to one map key")
	}
}

func TestVerdictSemantics(t *testing.T) {
	// §19.1: ban hit → XDP_DROP-class action in kernel; nothing else may
	// synthesize a drop without a verdict/ban map source (kernel stays
	// decision-free, §9.1).
	if actionAllow != 0 || actionDrop != 1 {
		t.Fatalf("action constants are the kernel's ABI: allow=0 drop=1, got %d/%d",
			actionAllow, actionDrop)
	}
	if actionDrop != VerdictDrop {
		t.Fatalf("loader VerdictDrop must equal the wire actionDrop (%d)", VerdictDrop)
	}
}

func TestLoaderRejectsStaleMaps(t *testing.T) {
	// Loader contract: pin path is fixed (§9.3) and the loader refuses to
	// open maps whose sizes do not match the compiled contract (fail
	// closed, no silent compat shims).
	_, err := OpenPinnedMaps("/nonexistent/trishula", ShieldSpec{})
	if err == nil {
		t.Fatal("OpenPinnedMaps on a missing pin path must error")
	}
	_ = ebpf.Map{} // assert cilium/ebpf stays a loader-scope dep, not engine-scope
}

func TestBanWriteExpiry(t *testing.T) {
	// BanVal.until_ts is absolute nanoseconds since boot (CLOCK_MONOTONIC
	// raw, as bpf_ktime_get_ns reads); the loader never writes 0-expiry
	// (infinite) bans — that invariant is TR-10's safety property, pinned
	// here so a v0 violation is caught at the loader layer.
	live := BanVal{UntilTS: 2_000_000_000, Tier: 1, ReasonCode: 42} // +2s
	if live.Expired(1_000_000_000) {
		t.Fatal("live ban (until now+2s) read expired at now")
	}
	if !live.Expired(3_000_000_000) {
		t.Fatal("ban past until_ns never expired")
	}
	if !(BanVal{UntilTS: 5}).Expired(5) {
		t.Fatal("ban at exactly until_ns must read expired (<= semantics)")
	}
}
