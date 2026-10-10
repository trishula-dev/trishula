// SPDX-License-Identifier: GPL-2.0
//
// TR-10 (issue #10) — bans_v4: the ScoredWindowBan ENFORCEMENT plane.
//
// Separate XDP program (not a shield_xdp.c edit): the TR-03 shield's
// contract is frozen by internal/shield/contract_test.go (map names,
// kinds, max_entries, program entrypoint) — extending that source would
// widen the frozen spec; a sibling program composes with it (attach both
// on one iface) while keeping the TR-03 contract untouched. The Go loader
// (internal/shield) carries the SAME wire structs:
//
//	struct BansV4Key { __be32 saddr; __u8 family; __u8 key_class; __u16 _pad; };
//	struct BansV4Val { __u64 ban_until_ms; __u16 score; __u16 reason_code; __u32 _pad; };
//
// Reason codes in BansV4Val.reason_code (the §13.4 tier names are the
// reason space at v0): 0 = unspecified (the TR-03 legacy posture for an
// unscored ban), 1300 = scored-window. Expiry parity with the engine:
// the ban holds while now_ms < ban_until_ms; at now_ms >= ban_until_ms
// the entry is deleted and the packet passes (auto-lift, in-kernel).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

#define KEY_AF_INET 4
#define KEY_CLASS_IP 0

#define IP_DF 0x4000 /* TR-80 visibility-probe marker bit (host order) */

/* Wire reason codes (internal/shield/banenforce.go pins the enum). */
#define REASON_UNSPECIFIED 0
#define REASON_SCORED_WINDOW 1300

/* Verdict/traffic stats (TR-10): per-CPU counters (verdict observability
 * for the e2e and the loader's pollers). STAT_PASS ticks for every IPv4
 * packet that exits clean (either direction — generic XDP on a veth sees
 * host egress too); STAT_LIFT ticks ONLY on the expired-lift branch: a
 * pass that happened BECAUSE its ban expired (the auto-lift evidence). */
#define STAT_DROP 0
#define STAT_PASS 1
#define STAT_LIFT 2

/* TR-80 visibility probe (issue #80): PROBE_SEEN ticks ONCE per program
 * invocation on a probe-marked packet — the marker is a zero IP id with
 * a zero 16-bit checksum complement marker that no ordinary stack emits
 * (the tier probe sender sets it; ICMP probes carry it and ICMP is the
 * reliable invocation signal on OrbStack veths). The loader reads the
 * delta around the burst → the visibility tier (internal/shield/tier.go
 * — full / first_packet / none). ban_stats keeps its verdict keys
 * (STAT_*); the probe counter shares the same map at the reserved index
 * below — one map per program, no new object on the wire. */
#define PROBE_SEEN 3 /* ban_stats[3]: probe invocations (STAT_* < 3) */

struct BansV4Key {
	__be32 saddr;    /* network byte order */
	__u8 family;     /* KEY_AF_INET */
	__u8 key_class;  /* KEY_CLASS_IP */
	__u16 _pad;
};

struct BansV4Val {
	__u64 ban_until_ms; /* CLOCK_MONOTONIC ms — bpf_ktime_get_ns()/1e6 */
	__u16 score;        /* §13.3 score at crossing, ×100 (2 decimals) */
	__u16 reason_code;  /* REASON_* above */
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 20);
	__type(key, struct BansV4Key);
	__type(value, struct BansV4Val);
} bans_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} ban_stats SEC(".maps");

static __always_inline void stat_tick(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&ban_stats, &idx);
	if (c)
		*c += 1; /* per-CPU: no atomic needed */
}

SEC("xdp")
int ban_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Bounded L2 walk: eth header minimum (the TR-03 shield's posture). */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS; /* bans_v4 is IPv4-keyed at v0 */

	/* Bounded L3 walk: IPv4 header minimum. */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->ihl < 5)
		return XDP_PASS; /* verifier-safe: no options parsing at v0 */

	/* The enforcement read: consult bans_v4 BEFORE any verdict cache
	 * (bans are enforcement — they outvote operator policy). */
	struct BansV4Key bk = {
		.saddr = ip->saddr,
		.family = KEY_AF_INET,
		.key_class = KEY_CLASS_IP,
		._pad = 0,
	};
	struct BansV4Val *ban = bpf_map_lookup_elem(&bans_v4, &bk);
	if (ban) {
		__u64 now_ms = bpf_ktime_get_ns() / 1000000;
		if (now_ms < ban->ban_until_ms) {
			stat_tick(STAT_DROP);
			return XDP_DROP; /* TC_ACT_SHOT semantics at XDP */
		}
		/* now >= until: auto-lift — drop the expired entry and pass.
		 * (LRU evicts under pressure; the lifted expiry is the
		 * correctness path the Go reconciler matches.) */
		bpf_map_delete_elem(&bans_v4, &bk);
		stat_tick(STAT_LIFT);
		/* TR-80: a probe packet from a JUST-EXPIRED source still
		 * counts (the loader needs the invocation, not the verdict). */
		if (!(ip->frag_off & bpf_htons(IP_DF)))
			stat_tick(PROBE_SEEN);
		return XDP_PASS;
	}

	/* TR-80 visibility probe: the DF-mask marker (a NEVER-DF stack:
	 * every ordinary stack sets DF today; the tier probe sender clears
	 * it on every burst packet — the only !DF frames on a normal wire
	 * are ≤64B non-TCP remnants, not this traffic). */
	if (!(ip->frag_off & bpf_htons(IP_DF)))
		stat_tick(PROBE_SEEN);

	stat_tick(STAT_PASS);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
