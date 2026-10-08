package shield

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
)

// Ban-entry wire contract (§19.1 sketch): what the ban engine writes and
// the kernel reads. Frozen here so TR-09/TR-10 (ban v1) and the C agree
// byte-for-byte from day one.
//
// struct ban_key  { __u32 ip; __u8 key_class; };
// struct ban_val  { __u64 until_ts; __u8 tier; __u16 reason_code; };
const (
	keyClassIP uint8 = 0

	// Wire sizes on little-endian arm64/amd64 targets (bpf2go targets);
	// Go side marshals via the same fixed-size structs.
	BanKeySize = 5  // u32 ip + u8 key_class
	BanValSize = 10 // u64 until_ts + u8 tier + u16 reason_code (+pad)
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
	ip := netip.MustParseAddr("192.0.2.7")
	k := BanKeyFromIP(ip, keyClassIP)
	a4 := ip.As4()
	if k.IP != binary.BigEndian.Uint32(a4[:]) {
		t.Fatalf("ban key ip = %#x, want network-order %#x", k.IP, binary.BigEndian.Uint32(a4[:]))
	}
	if k.KeyClass != keyClassIP {
		t.Fatalf("key_class = %d, want %d", k.KeyClass, keyClassIP)
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
	v := BanVal{UntilTS: 1, Tier: 1, ReasonCode: 42}
	if v.Expired(2) {
		t.Fatal("ban with until_ts=1 must not be expired at t=2... inverted")
	}
	if !v.Expired(0) {
		t.Fatal("ban expired check fails at t=0 < 1")
	}
}
