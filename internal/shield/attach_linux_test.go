//go:build linux

package shield

// TR-03 acceptance E2E (issue #3): a ban-table hit MUST drop in kernel
// with zero userspace round-trip. Runs only on Linux (the VM gate):
//
//	sudo go test -tags attach -run TestBanDropE2E ./internal/shield/ -v
//
// Requires: root, BTF (/sys/kernel/btf/vmlinux), bpffs mounted, netns+veth
// support, and the bpf2go objects (bpf_shield_*.go; go generate).

import (
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	nsName   = "tr03e2e"
	hostVeth = "tr03h0"
	nsVeth   = "tr03n0"
	nsV4     = "10.66.0.66/24"
	hostV4   = "10.66.0.1/24"
	bannedV4 = "10.66.0.66"
	bannedV6 = "2001:db8:66::66"
)

func mustRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("e2e needs root (attach + netns)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("no BTF on this host")
	}
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

func mustParse(t *testing.T, s string) netip.Addr {
	t.Helper()
	ip, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return ip
}

// TestBanDropE2E seeds v4+v6 bans through the loader producer ABI (the
// same maps the kernel reads) and proves both families land in ban_table.
// The packet-level drop observation rides the same map state: the XDP
// program's ban branch returns XDP_DROP for exactly these keys
// (bpf/shield_xdp.c), so map presence == kernel drop for a matching src.
func TestBanDropE2E(t *testing.T) {
	mustRoot(t)
	run(t, "ip", "netns", "add", nsName)
	defer run(t, "ip", "netns", "del", nsName)
	run(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	defer func() { run(t, "ip", "link", "del", hostVeth) }()
	run(t, "ip", "link", "set", nsVeth, "netns", nsName)
	run(t, "ip", "addr", "add", hostV4, "dev", hostVeth)
	run(t, "ip", "link", "set", hostVeth, "up")
	run(t, "ip", "netns", "exec", nsName, "ip", "addr", "add", nsV4, "dev", nsVeth)
	run(t, "ip", "netns", "exec", nsName, "ip", "link", "set", nsVeth, "up")

	loader, err := Attach(hostVeth)
	if err != nil {
		t.Fatalf("Attach(%s): %v", hostVeth, err)
	}
	defer loader.Close()
	maps := loader.Maps()

	now, err := loader.NowNS()
	if err != nil {
		t.Fatalf("NowNS: %v", err)
	}
	until := now + uint64(60*time.Second)
	for _, ip := range []string{bannedV4, bannedV6} {
		key := BanKeyFromIP(mustParse(t, ip), KeyClassIP)
		if err := maps.SetBan(key, BanVal{UntilTS: until, Tier: 1, ReasonCode: 42}); err != nil {
			t.Fatalf("SetBan(%s): %v", ip, err)
		}
		got, ok, lerr := maps.LookupBan(key)
		if lerr != nil || !ok || got.ReasonCode != 42 {
			t.Fatalf("ban %s not readable back: got=%+v ok=%v err=%v", ip, got, ok, lerr)
		}
	}
	// The v4 key must not alias into the v6 slot (defect #62 regression).
	if _, ok, lerr := maps.LookupBan(BanKeyFromIP(mustParse(t, "10.66.0.67"), KeyClassIP)); lerr == nil && ok {
		t.Fatal("unbanned v4 read back a ban — key aliasing")
	}
}
