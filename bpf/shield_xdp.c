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

	struct ban_key bk = {
		.addr = {.v4 = ip->saddr},
		.family = KEY_AF_INET,
		.key_class = KEY_CLASS_IP,
	};
	struct ban_val *ban = bpf_map_lookup_elem(&ban_table, &bk);
	if (ban) {
		__u64 now = bpf_ktime_get_ns();
		if (ban->until_ts > now)
			return XDP_DROP; /* the acceptance path: in-kernel drop */
		/* LRU lazily evicts; no delete on miss-by-expiry (allocation-free). */
	}

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
	struct verdict_key vk = {
		.addr = {.v4 = ip->saddr},
		.family = KEY_AF_INET,
		.port_class = 0, /* v0: single class; per-port classes land with §8 bundles */
	};
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
