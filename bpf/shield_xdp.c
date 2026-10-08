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
 * enforced here at line rate.
 * Wire contract pinned by internal/shield/banwire_test.go:
 *   key: {u32 ip (network order), u8 key_class} = 5 bytes
 *   val: {u64 until_ns, u8 tier, u16 reason_code} + pad = 12 bytes
 */
enum key_class {
	KEY_CLASS_IP = 0,
	KEY_CLASS_JA4_CLUSTER = 1,
	KEY_CLASS_PREFIX = 2,
};

struct ban_key {
	__be32 ip;
	__u8 key_class;
};

struct ban_val {
	__u64 until_ts;
	__u8 tier;
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
	__be32 ip;
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

/* L3/L4 ACL: operator-compiled prefixes (CRD → bundle → map, §8). */
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
		.ip = ip->saddr,
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
		.ip = ip->saddr,
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
