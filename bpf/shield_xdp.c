// SPDX-License-Identifier: GPL-2.0
// TR-03 (issue #3) — XDP shield PoC, CO-RE per PRD v4 §19.1 + §9.1/§9.3.
//
// Kernel plane (§9.1): bounded, allocation-free, verdict-cheap. L3/L4 ACL,
// verdict-cache and ban-table enforcement. Every packet pays O(1); the
// kernel stays decision-free — it enforces what userspace wrote (§9.5).
//
// v0 scope (TR-02 seed posture): IPv4 XDP ACL + verdict cache + ban table
// with XDP_DROP on ban hit (acceptance: in-kernel drop, zero userspace
// round-trip). IPv6 normalization, SYN-flood tarpits and TC flow
// classification (flow_tc.c) follow in this issue's later PRs.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_UDP 17

/* Ban table: written by the ban engine (TR-09/10) via the shield loader,
 * enforced here at line rate. Dual-stack per defect #62 (amended §19.1):
 * keys carry a family-discriminated 16-byte address union — a bare u32
 * cannot hold an IPv6 address and a /48 prefix would alias its hosts.
 * Wire contract pinned by internal/shield/banwire_test.go:
 *   key: {union {be32 v4 | u8 v6[16]} addr, u8 family, u8 key_class} = 18B
 *   val: {u64 until_ns, u8 tier, pad, u16 reason_code}          = 12B
 */
enum key_class {
	KEY_CLASS_IP = 0,
	KEY_CLASS_JA4_CLUSTER = 1,
	KEY_CLASS_PREFIX = 2,
};

#define KEY_AF_INET 4
#define KEY_AF_INET6 6

struct key_addr {
	union {
		__be32 v4;        /* network byte order; upper 12 bytes zeroed */
		__u8 v6[16];
	};
};

struct ban_key {
	struct key_addr addr;
	__u8 family;            /* KEY_AF_INET / KEY_AF_INET6 — explicit */
	__u8 key_class;
};

struct ban_val {
	__u64 until_ts;
	__u8 tier;
	__u8 _pad;
	__u16 reason_code;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 20);
	__type(key, struct ban_key);
	__type(value, struct ban_val);
} ban_table SEC(".maps");

/* Verdict cache: engine → shield short-circuit decisions (§9.3). */
struct verdict_key {
	struct key_addr addr;
	__u8 family;
	__u16 port_class;
};

struct verdict_val {
	__u8 action; /* 0 = allow, 1 = drop (loader ABI: internal/shield) */
	__u64 until_ts;
};

enum verdict_action {
	VERDICT_ALLOW = 0,
	VERDICT_DROP = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 20);
	__type(key, struct verdict_key);
	__type(value, struct verdict_val);
} verdict_cache SEC(".maps");

/* L3 ACL: operator-compiled prefixes (CRD → bundle → map, §8).
 * v0 = IPv4 (acl4); the acl6 trie lands with the IPv6 slice (§9.2 later
 * slice of TR-03) — keys here use the same #62 family discipline when
 * that lands; LPM v4 key layout stays the kernel's u32-prefixlen form. */
struct acl4_key {
	__u32 prefixlen;
	__be32 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1 << 20);
	__type(key, struct acl4_key);
	/* value: u8 action — VERDICT_ALLOW / VERDICT_DROP */
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} acl4 SEC(".maps");

/* TR-203 L1 (issues #264/#242, leaf 1): the UDP flood leg. The counter
 * map = rate_windows: per-source UDP rate rows, counted here at XDP
 * (the map name = the spec's, section 9.5). v0 = the flat window count;
 * the EWMA refinement = the section 9.5 slice. The rows stay UDP-scoped
 * by construction: only the UDP branch touches the map. The knob row
 * (shield_knobs[0]) arms the leg — the engine-published shape, like the
 * ban and the ACL rows: userspace owns the threshold and the window,
 * the kernel owns the count and the drop. A missing knob row = the leg
 * idle = the fail-open default. The drop = XDP_DROP. The counters never
 * issue a ban (section 9.5); they count and drop the flood in kernel. */

struct rate_key {
	struct key_addr addr;
	__u8 family; /* KEY_AF_INET at v0 (the program stays IPv4-only) */
};

struct rate_val {
	__u64 window_start_ns;
	__u32 count;
	__u32 _pad;
};

struct shield_knob_val {
	__u32 udp_flood_pps; /* the drop threshold per window */
	__u32 _pad;
	__u64 window_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shield_knob_val);
} shield_knobs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 16);
	__type(key, struct rate_key);
	__type(value, struct rate_val);
} rate_windows SEC(".maps");

/* Verdict counters (the flood leg's readback; the e2e + the loader's
 * pollers). TARPIT ticks only on a tarpit drop; UDP_PASS ticks on a
 * datagram that passed the tarpit branch. */
#define SHIELD_STAT_TARPIT_DROP 0
#define SHIELD_STAT_UDP_PASS 1

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} shield_stats SEC(".maps");

static __always_inline void shield_stat_tick(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&shield_stats, &idx);
	if (c)
		*c += 1; /* per-CPU: no atomic needed */
}

static __always_inline int udp_flood_tarpit(__be32 saddr)
{
	__u32 z = 0;
	struct shield_knob_val *knob = bpf_map_lookup_elem(&shield_knobs, &z);
	if (!knob || knob->udp_flood_pps == 0)
		return 0; /* the leg idles without an armed row: pass */

	struct rate_key rk;
	__builtin_memset(&rk, 0, sizeof(rk)); /* the pad byte: zero before compare */
	rk.addr.v4 = saddr;
	rk.family = KEY_AF_INET;
	struct rate_val *rw = bpf_map_lookup_elem(&rate_windows, &rk);
	__u64 now = bpf_ktime_get_ns();
	if (!rw) {
		/* A failed insert fails open: the lost row loses one count. */
		struct rate_val init = {.window_start_ns = now, .count = 1, ._pad = 0};
		bpf_map_update_elem(&rate_windows, &rk, &init, BPF_NOEXIST);
		shield_stat_tick(SHIELD_STAT_UDP_PASS);
		return 0;
	}
	if (now - rw->window_start_ns >= knob->window_ns) {
		/* The window rolls: the fresh count starts at this datagram.
		 * Plain stores: a cross-CPU race loses one count, the
		 * fail-open direction. */
		rw->window_start_ns = now;
		rw->count = 1;
	} else {
		__sync_fetch_and_add(&rw->count, 1);
	}
	if (rw->count > knob->udp_flood_pps) {
		shield_stat_tick(SHIELD_STAT_TARPIT_DROP);
		return 1;
	}
	shield_stat_tick(SHIELD_STAT_UDP_PASS);
	return 0;
}

SEC("xdp")
int shield_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Bounded L2 walk: eth header minimum. */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS; /* IPv6 + non-IP: later slice (§9.2) */

	/* Bounded L3 walk: IPv4 header minimum. */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->ihl < 5)
		return XDP_PASS; /* verifier-safe: no options parsing at v0 */

	/* The 20B key compare reads every byte: the LRU hash compares the
	 * full padded key_size. A brace init of the 16B union fills its
	 * first 4 bytes only — the compiled rest of the union slot reads
	 * stack garbage (the same pad-garbage split the flow path's E2E
	 * proved; the key is memset before use). A garbage byte in the
	 * union pad misses every lookup: the ban row never matches and the
	 * drop never fires. */
	struct ban_key bk;
	__builtin_memset(&bk, 0, sizeof(bk));
	bk.addr.v4 = ip->saddr;
	bk.family = KEY_AF_INET;
	bk.key_class = KEY_CLASS_IP;
	struct ban_val *ban = bpf_map_lookup_elem(&ban_table, &bk);
	if (ban) {
		__u64 now = bpf_ktime_get_ns();
		if (ban->until_ts > now)
			return XDP_DROP; /* the acceptance path: in-kernel drop */
		/* LRU lazily evicts; no delete on miss-by-expiry (allocation-free). */
	}

	/* TR-203 L1: the UDP flood tarpit walks the same enforcement order:
	 * ban first (the ban-table reuse), then the flood count, then the
	 * operator policy (the ACL) and the verdict cache. A live ban drops
	 * UDP flows here; the tarpit counts and drops the flood in kernel. */
	if (ip->protocol == IPPROTO_UDP && udp_flood_tarpit(ip->saddr))
		return XDP_DROP;

	/* ACL match only when no live ban (ban = enforcement, ACL = policy). */
	struct acl4_key ak = {
		.prefixlen = 32,
		.addr = ip->saddr,
	};
	__u8 *acl = bpf_map_lookup_elem(&acl4, &ak);
	if (acl && *acl == VERDICT_DROP)
		return XDP_DROP;
	if (acl && *acl == VERDICT_ALLOW)
		return XDP_PASS;

	/* Verdict cache: engine-written (block wins with expiry). */
	struct verdict_key vk;
	__builtin_memset(&vk, 0, sizeof(vk)); /* the pad byte at offset 17 */
	vk.addr.v4 = ip->saddr;
	vk.family = KEY_AF_INET;
	vk.port_class = 0; /* v0: single class; per-port classes land with §8 bundles */
	struct verdict_val *vc = bpf_map_lookup_elem(&verdict_cache, &vk);
	if (vc) {
		if (vc->until_ts > bpf_ktime_get_ns()) {
			if (vc->action == VERDICT_DROP)
				return XDP_DROP;
			return XDP_PASS;
		}
		/* expired: fall through to pass (v0; eviction is LRU-lazy) */
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
