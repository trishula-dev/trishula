// Package shield contains the userspace loader for the XDP shield (TR-03).
//
// The kernel contract is frozen by THIS test file before the C lands
// (hypothesis-first standard, issue #42): map names, key/value layouts and
// the XDP action semantics the loader relies on. bpf/shield_xdp.c must
// satisfy it — RED here means the C object does not exist yet, and every
// case fails at compile/load time.
//
// Test contract: tests import ONLY our package API (+ cilium/ebpf types
// for map spec assertions, which is the loader's own dependency) — never
// the generated objects. The attach/VM gate is a separate build-tag'd
// test (attach_linux_test.go); this file runs everywhere.
package shield

import "testing"

// Kernel contract under test (PRD §9.3 + §19.1 sketch):
const (
	// Map names exactly as pinned in the §19.1 sketch.
	mapACL4         = "acl4"
	mapVerdictCache = "verdict_cache"
	mapBanTable     = "ban_table"
	mapFlowStats    = "flow_stats"
	mapEvents       = "events"

	// Verdict actions (XDP "action" values in verdict_cache/ban_table).
	actionAllow uint8 = 0
	actionDrop  uint8 = 1
)

func TestKernelContract(t *testing.T) {
	if testing.Short() {
		t.Skip("kernel contract needs the compiled object; run in VM gate")
	}
	// RED: ShieldSpec() does not exist yet — first GREEN adds it plus the
	// bpf2go object; GREEN here = the compiled object satisfies the
	// §19.1 contract verified by the attach test on Linux.
	spec := MustSpec(t, ShieldSpec{})
	cases := []struct {
		name    string
		mapSpec string
		wantTyp string
		wantMax uint32
	}{
		{"acl4 is LPM trie", mapACL4, "lpm_trie", 1 << 20},
		{"verdict_cache is LRU", mapVerdictCache, "lru_hash", 1 << 20},
		{"ban_table is LRU", mapBanTable, "lru_hash", 1 << 20},
		{"flow_stats is LRU", mapFlowStats, "lru_hash", 1 << 18},
		{"events is ringbuf", mapEvents, "ringbuf", 1 << 24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := spec.Map(t, tc.mapSpec)
			if got := m.Type(); got != tc.wantTyp {
				t.Fatalf("map %s type=%s, want %s (§19.1)", tc.mapSpec, got, tc.wantTyp)
			}
			if m.MaxEntries() != tc.wantMax {
				t.Fatalf("map %s max_entries=%d, want %d (§19.1)", tc.mapSpec, m.MaxEntries(), tc.wantMax)
			}
		})
	}
	t.Run("program entrypoint", func(t *testing.T) {
		if !spec.HasProgram("xdp") {
			t.Fatal("object must expose SEC(xdp) entrypoint shield_xdp")
		}
	})
}
