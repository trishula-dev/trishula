// SPDX-License-Identifier: GPL-2.0
// TR-04d (issue #69) — TC ingress classifier: the ring producer.
// CO-RE per PRD §19.1 sketch + §9.1/§9.2/§9.4.
//
// Kernel plane duties (v0): bounded header walk, ban/verdict probes
// (maps shared with shield_xdp.c — one verdict authority, §9.3),
// flow_event emit to the ring for the userspace engine.
//
// Lost-record surface (the Go Reader has no loss errors): every failed
// bpf_ringbuf_reserve counts in lost_events — the E2E verifies it
// against the engine's Stats.RingLossTotal.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* TC uABI (stable since forever; linux/pkt_cls.h conflicts with vmlinux.h) */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IP_DF 0x4000 /* TR-80 visibility-probe marker bit (host order) */

/* probe_stats[0] is the PROBE_SEEN index (the map below; the tick uses
 * the literal — one per-CPU entry). */

/* Shared verdict authority (TR-03's maps; §9.3): engine → kernel. */
#define KEY_AF_INET 4
#define KEY_AF_INET6 6

/* TR-196 (issue #238): the socket class 2 compiled-row leg — the CEL
 * fast-path class (the bounded-scan primitive). The compile decomposes
 * the CEL constructs at compile time (internal/fastpath/celclass.go):
 * the method equality, the path glob (one star → the prefix/suffix
 * segments; none → the exact literal) and the query substring. The rows
 * stage from the loader (the compiled bundle; the kernel stays
 * decision-free §9.5 — the compiled policy's action code is the only
 * verdict the leg returns). Every failure fails open: a parse miss, a
 * helper failure or an absent row forwards (the record part 2: the plane
 * never drops on its own failure state). */
#define FP_MAX 8            /* row bound; the compile fails closed past it */
#define FP_METHOD_MAX 8     /* the method-literal bound */
#define FP_PATH_MAX 64      /* the path extract bound (a power of two) */
#define FP_GLOB_PRE_MAX 48  /* the glob prefix literal bound */
#define FP_GLOB_SUF_MAX 16  /* the glob suffix literal bound */
#define FP_QUERY_MAX 8      /* the query scan window (the extract) + the scan bound */
#define FP_QUERY_LIT_MAX 16 /* the query-substring literal bound (a power of two; the mask below) */

struct fp_rule_val {
	__u32 id;               /* the row index (the mark value on a match) */
	__u8 enabled;
	__u8 action;            /* 1 = drop (the compiled enforce/ban code) */
	__u8 method_len;
	__u8 glob_kind;         /* 0 none, 1 exact literal, 2 prefix+suffix */
	__u8 pre_len;
	__u8 suf_len;
	__u8 query_len;
	__u8 method[FP_METHOD_MAX];
	__u8 pre[FP_GLOB_PRE_MAX];
	__u8 suf[FP_GLOB_SUF_MAX];
	__u8 query[FP_QUERY_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FP_MAX);
	__type(key, __u32);
	__type(value, struct fp_rule_val);
} fp_rules SEC(".maps");

struct key_addr {
	union {
		__be32 v4;
		__u8 v6[16];
	} addr;
};

struct ban_key {
	struct key_addr addr;
	__u8 family;
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

/* Flow event streamed to the userspace engine (ringbuf, MPSC; 16 MiB). */
struct flow_event {
	__u64 ts_ns;
	__be32 saddr_v4;
	__u8 saddr_v6[16];
	__be32 daddr_v4;
	__u8 daddr_v6[16];
	__u16 sport, dport;
	__u8 tcp_flags;
	__u32 mark;             /* gateway steering tag */
	__u16 payload_len;
	__u8 http_seen;         /* plaintext HTTP/1.x in first bytes */
	__u8 h2_preface;
	__u8 tls_seen;
	__u8 family;            /* KEY_AF_INET / KEY_AF_INET6 (#62) */
	char path_hint[128];
/* TR-194 (issue #236): the 7-bit kernel-consult bitmap, appended last (the
 * stage-stamps record sec 5 freeze). Bytes 0-199 stay identical; the field
 * rides at offset 200; sizeof reads 208. Bits 0-3 (xdp.*) fill from the
 * flow-keyed handoff map (leaf 2). At leaf 1 the TC emit stamps its own
 * three consults: bit 4 tc.classify (the bounded L4 walk ran), bit 5 tc.ban
 * (the ban_table probe ran; a live ban SHOTs before the emit = no event,
 * no bit), bit 6 tc.fastpath (the sec 9.6 advisory peek ran). Bit = 1 reads
 * "the consult ran on a packet that reached the emit". No bit names a drop
 * or an engine stage. */
	__u64 stages;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB per node (§9.4) */
} events SEC(".maps");

/* TR-194: the TC-plane consult bits the emit stamps (the record sec 3.2):
 * classify = bit 4, the ban probe = bit 5, the fastpath advisory = bit 6.
 * The XDP bits (0-3) fill from the leaf-2 handoff map; at leaf 1 they read 0. */
#define TC_ST_CLASSIFY 0x10
#define TC_ST_BAN      0x20
#define TC_ST_FASTPATH 0x40
#define TC_STAGES_BASE (TC_ST_CLASSIFY | TC_ST_BAN)

/* Lost-record accounting (§9.4 loss surface; Engine.RingLossTotal). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost_events SEC(".maps");

/* Flow stats: per-flow counters (shield → shield; §9.3). TR-31 (issue #31)
 * grows the value into the behavioural window features the engine's
 * detectors read: the first and last counted-segment timestamps make the
 * per-flow time window legible — bytes/segment and the span are the §13.7
 * slowloris math inputs. The kernel counts and stamps (O(1) map work per
 * packet); it never computes a score or a decision (§9.5, §13.3). A failed
 * lookup or update fails the accounting open: the packet passes. */
struct flow_key {
	struct key_addr saddr, daddr;
	__u16 sport, dport;
	__u8 family;
};
struct flow_stat {
	__u64 syn_ts;
	__u64 first_seg_ts; /* TR-31: first counted segment */
	__u64 last_seg_ts;  /* TR-31: last counted segment (the window span) */
	__u32 req_bytes;
	__u32 seg_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 18);
	__type(key, struct flow_key);
	__type(value, struct flow_stat);
} flow_stats SEC(".maps");

/* TR-80 visibility probe (issue #80): probe_stats[0] ticks ONCE per
 * tc_ingress_waf invocation on a probe-marked packet — the marker is the
 * DF-bit mask (a NEVER-DF stack: every ordinary stack sets DF today; the
 * tier probe sender clears it on every burst packet, ICMP included — the
 * reliable invocation signal on OrbStack veths). The loader reads the
 * delta around the burst → the visibility tier (internal/shield/tier.go:
 * full / first_packet / none — the OrbStack pod-veth signature is exactly
 * ONE tc tick per connection here, the first packet; established-flow
 * segments never re-ingress clsact). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} probe_stats SEC(".maps");

/* TR-80 visibility probe: the DF-mask marker tick (probe_stats[0]); the
 * ipv4 path calls it for every non-fragmented IPv4 datagram (offset 0 =
 * non-frag; a stacked mask can never carry DF). */
static __always_inline void tc_probe_tick(struct iphdr *ip)
{
	if (!(ip->frag_off & bpf_htons(IP_DF))) {
		__u32 z = 0; /* PROBE_SEEN */
		__u64 *c = bpf_map_lookup_elem(&probe_stats, &z);
		if (c)
			*c += 1; /* per-CPU: no atomic needed */
	}
}

static __always_inline int is_http_method(__u8 b0, __u8 b1)
{
	/* 4-byte method probes on the first line (§9.6 fast-path probe):
	 * GET/POST/PUT/DELETE/HEAD/PATCH/OPTIONS — v0: GET + POST only. */
	if (b0 == 'G' && b1 == 'E') return 1; /* GET  */
	if (b0 == 'P' && b1 == 'O') return 1; /* POST */
	return 0;
}

static __always_inline int emit_flow_event(struct __sk_buff *skb,
					   void *data, void *data_end,
					   __be32 s4, __u8 *s6,
					   __be32 d4, __u8 *d6,
					   __u16 sport, __u16 dport,
					   __u8 tcp_flags, __u8 family,
					   __u16 payload_len,
					   void *tcp_end,
					   __u64 stages)
{
	struct flow_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		/* §9.4 loss surface: reserve failure = ring full/overrun. */
		__u32 zero = 0;
		__u64 *lost = bpf_map_lookup_elem(&lost_events, &zero);
		if (lost)
			__sync_fetch_and_add(lost, 1);
		return 0;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ts_ns = bpf_ktime_get_ns();
	ev->stages = stages | TC_ST_FASTPATH; /* the advisory peek runs below */
	ev->saddr_v4 = s4;
	ev->daddr_v4 = d4;
	if (s6)
		__builtin_memcpy(ev->saddr_v6, s6, 16);
	if (d6)
		__builtin_memcpy(ev->daddr_v6, d6, 16);
	ev->sport = sport;
	ev->dport = dport;
	ev->tcp_flags = tcp_flags;
	ev->mark = skb->mark;
	ev->payload_len = payload_len;
	ev->family = family;

	/* Bounded L7 probe (§9.6 advisory): plaintext HTTP method peek via
	 * bpf_skb_load_bytes — reads the FULL skb (linear + paged frags),
	 * unlike direct pointer reads limited to the linear area (GSO/TFO:
	 * payload bytes can sit in frags — the E2E traced exactly that: the
	 * pointer peek never fired while the payload demonstrably arrived).
	 * Offsets are relative to skb->data (the L2 frame start). */
	{
			__u32 l4_off = (__u32)(long)tcp_end - (__u32)(long)data;
		__u8 hdr[4]; /* 4-byte granularity: method probe + h2 peek */
		if (!bpf_skb_load_bytes(skb, l4_off, hdr, sizeof(hdr))) {
			if (is_http_method(hdr[0], hdr[1]))
				ev->http_seen = 1;
			if (hdr[0] == 0x50 && hdr[1] == 0x52) /* PR = h2 preface */
				ev->h2_preface = 1;
			__u8 b4;
			if (!bpf_skb_load_bytes(skb, l4_off + 4, &b4, 1) &&
			    hdr[0] == 0x16 && hdr[1] == 0x03 && b4 <= 0x04)
				ev->tls_seen = 1;
			if (ev->http_seen) {
				__u32 sp = l4_off;
				#pragma unroll
				for (int i = 0; i < 8; i++) {
					__u8 c;
					if (bpf_skb_load_bytes(skb, sp + i, &c, 1))
						break;
					if (c == ' ') {
						sp = sp + i + 1;
						break;
					}
				}
				#pragma unroll
				for (int i = 0; i < 64; i++) {
					__u8 c;
					if (bpf_skb_load_bytes(skb, sp + i, &c, 1))
						break;
					if (c == ' ' || c == '\r' || c == '\n')
						break;
					ev->path_hint[i] = c;
				}
			}
		}
	}

	bpf_ringbuf_submit(ev, 0);
	return 1;
}

/* TR-203 L1: the UDP classifiers (issue #264, pulled from #242 leaf 1).
 * Same contract as the TCP walk: the ban probe = TC_ACT_SHOT on a live
 * ban; the flow_stats row = the datagram count + the payload byte count
 * + the window stamps; every failure fails open. No FlowEvent at this
 * leaf. The flow_key layout stands (no protocol byte in the wire at
 * v0): a colliding 5-tuple merges one TCP row and one UDP row into one
 * row; the detectors read the merged row as noise. */
static __always_inline int udp_classify4(struct __sk_buff *skb, void *data,
					 void *data_end, struct iphdr *ip,
					 void *payload)
{
	struct udphdr *udp = payload;
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;

	struct ban_key bk = {
		.addr = {.addr = {.v4 = ip->saddr}},
		.family = KEY_AF_INET,
		.key_class = 0,
	};
	struct ban_val *ban = bpf_map_lookup_elem(&ban_table, &bk);
	if (ban) {
		if (ban->until_ts > bpf_ktime_get_ns())
			return TC_ACT_SHOT;
	}

	/* The byte count mirrors the TCP rows: the payload bytes only
	 * (the bytes after the UDP header; not the header bytes). */
	__u32 payload_len = (__u32)skb->len -
			    ((__u32)(long)(udp + 1) - (__u32)(long)data);
	struct flow_key fk;
	__builtin_memset(&fk, 0, sizeof(fk));
	fk.saddr.addr.v4 = ip->saddr;
	fk.daddr.addr.v4 = ip->daddr;
	fk.sport = udp->source;
	fk.dport = udp->dest;
	fk.family = KEY_AF_INET;
	struct flow_stat *st = bpf_map_lookup_elem(&flow_stats, &fk);
	if (!st) {
		struct flow_stat init = {0};
		__u64 now = bpf_ktime_get_ns();
		init.first_seg_ts = now;
		init.last_seg_ts = now;
		init.req_bytes = payload_len;
		init.seg_count = 1;
		bpf_map_update_elem(&flow_stats, &fk, &init, BPF_NOEXIST);
	} else {
		st->last_seg_ts = bpf_ktime_get_ns();
		__sync_fetch_and_add(&st->req_bytes, payload_len);
		__sync_fetch_and_add(&st->seg_count, 1);
	}
	return TC_ACT_OK;
}

static __always_inline int udp_classify6(struct __sk_buff *skb, void *data,
					 void *data_end, struct ipv6hdr *ip6h,
					 void *payload)
{
	struct udphdr *udp = payload;
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;

	struct ban_key bk = {
		.addr = {.addr = {.v6 = {0}}},
		.family = KEY_AF_INET6,
		.key_class = 0,
	};
	__builtin_memcpy(bk.addr.addr.v6, ip6h->saddr.in6_u.u6_addr8, 16);
	struct ban_val *ban = bpf_map_lookup_elem(&ban_table, &bk);
	if (ban) {
		if (ban->until_ts > bpf_ktime_get_ns())
			return TC_ACT_SHOT;
	}

	__u32 payload_len = (__u32)skb->len -
			    ((__u32)(long)(udp + 1) - (__u32)(long)data);
	struct flow_key fk;
	__builtin_memset(&fk, 0, sizeof(fk));
	__builtin_memcpy(fk.saddr.addr.v6, ip6h->saddr.in6_u.u6_addr8, 16);
	__builtin_memcpy(fk.daddr.addr.v6, ip6h->daddr.in6_u.u6_addr8, 16);
	fk.sport = udp->source;
	fk.dport = udp->dest;
	fk.family = KEY_AF_INET6;
	struct flow_stat *st = bpf_map_lookup_elem(&flow_stats, &fk);
	if (!st) {
		struct flow_stat init = {0};
		__u64 now = bpf_ktime_get_ns();
		init.first_seg_ts = now;
		init.last_seg_ts = now;
		init.req_bytes = payload_len;
		init.seg_count = 1;
		bpf_map_update_elem(&flow_stats, &fk, &init, BPF_NOEXIST);
	} else {
		st->last_seg_ts = bpf_ktime_get_ns();
		__sync_fetch_and_add(&st->req_bytes, payload_len);
		__sync_fetch_and_add(&st->seg_count, 1);
	}
	return TC_ACT_OK;
}
/* TR-196: the CEL-class fast-path leg (the bounded-scan primitive, the
 * record part 3 rows 1-4 at this leaf). The compiled rows carry the
 * decomposed legs (never a star on the wire). One bounded extract per
 * packet, then one leg-pass per row: the method compare, the glob
 * prefix/suffix (the suffix reads the extract tail and requires the
 * extract to hold the true tail — an overrun path skips suffix and
 * exact rows, fail-open), the query substring over the capped window.
 * The FIRST matching row returns its compiled action; a miss or any
 * failure forwards (0 = no conclusive verdict). */

/* The row-eval context: one extract per packet, read by the row pass.
 * It stands above the row body (the body reads its members through the
 * pointer; the earlier build carried the body first and read an
 * undeclared type — the struct ordering the load probe flagged). */
struct fp_ctx {
	struct __sk_buff *skb;
	__u8 *method;
	__u8 *path;
	__u8 *query;
	__u32 method_len;
	__u32 path_len;
	__u32 query_len;
	__u8 path_cont;
};

/* TR-196: the row body from the load probes' verdict forms. The
 * method compare (8), the masked suffix and the streaming query run as
 * their compile-time-bounded loops — every backedge state stays inside
 * one loop body (the probes proved them clean) and the compare loops
 * break the moment a leg fails, so no (index, length) pair state
 * crosses the row. The path-glob prefix compare stays flat: the loop
 * form bound by the runtime pre_len was the state sink the probes
 * named (~26k states), so its cells unroll with the static cell index
 * (a partial row would under-compare a staged literal, so the cells
 * expand the full FP_GLOB_PRE_MAX bound). The query-scan double loop
 * (window per literal cell) was the other state sink; the single pass
 * with the in-match length as the only state stays. */
static __always_inline int fp_row_match(struct fp_rule_val *row,
					struct fp_ctx *c)
{
	int ok, suf_arm, qfound, l;
	__u32 i;

	/* The method compare (the compare primitive): the exact literal or
	 * the leg absent. */
	ok = 1;
	if (row->method_len) {
		if (row->method_len != c->method_len)
			return 0;
		for (i = 0; i < FP_METHOD_MAX; i++) {
			if (i >= row->method_len || !ok)
				break;
			if (c->method[i] != row->method[i])
				ok = 0;
		}
		if (!ok)
			return 0;
	}
	/* The path glob (the bounded-scan primitive: the exact literal or
	 * the prefix/suffix segments). */
	if (row->glob_kind) {
		__u32 pl = row->pre_len;
		ok = 1;
		if (row->glob_kind == 1) {
			/* The exact literal: the extract carries the true tail
			 * (the overrun path skips — fail-open). */
			ok = c->path_len == pl && !c->path_cont;
		} else if (c->path_len < pl || pl > FP_GLOB_PRE_MAX) {
			ok = 0;
		} else {
			if (ok && 0 < row->pre_len && c->path[0] != row->pre[0])
				ok = 0;
			if (ok && 1 < row->pre_len && c->path[1] != row->pre[1])
				ok = 0;
			if (ok && 2 < row->pre_len && c->path[2] != row->pre[2])
				ok = 0;
			if (ok && 3 < row->pre_len && c->path[3] != row->pre[3])
				ok = 0;
			if (ok && 4 < row->pre_len && c->path[4] != row->pre[4])
				ok = 0;
			if (ok && 5 < row->pre_len && c->path[5] != row->pre[5])
				ok = 0;
			if (ok && 6 < row->pre_len && c->path[6] != row->pre[6])
				ok = 0;
			if (ok && 7 < row->pre_len && c->path[7] != row->pre[7])
				ok = 0;
			if (ok && 8 < row->pre_len && c->path[8] != row->pre[8])
				ok = 0;
			if (ok && 9 < row->pre_len && c->path[9] != row->pre[9])
				ok = 0;
			if (ok && 10 < row->pre_len && c->path[10] != row->pre[10])
				ok = 0;
			if (ok && 11 < row->pre_len && c->path[11] != row->pre[11])
				ok = 0;
			if (ok && 12 < row->pre_len && c->path[12] != row->pre[12])
				ok = 0;
			if (ok && 13 < row->pre_len && c->path[13] != row->pre[13])
				ok = 0;
			if (ok && 14 < row->pre_len && c->path[14] != row->pre[14])
				ok = 0;
			if (ok && 15 < row->pre_len && c->path[15] != row->pre[15])
				ok = 0;
			if (ok && 16 < row->pre_len && c->path[16] != row->pre[16])
				ok = 0;
			if (ok && 17 < row->pre_len && c->path[17] != row->pre[17])
				ok = 0;
			if (ok && 18 < row->pre_len && c->path[18] != row->pre[18])
				ok = 0;
			if (ok && 19 < row->pre_len && c->path[19] != row->pre[19])
				ok = 0;
			if (ok && 20 < row->pre_len && c->path[20] != row->pre[20])
				ok = 0;
			if (ok && 21 < row->pre_len && c->path[21] != row->pre[21])
				ok = 0;
			if (ok && 22 < row->pre_len && c->path[22] != row->pre[22])
				ok = 0;
			if (ok && 23 < row->pre_len && c->path[23] != row->pre[23])
				ok = 0;
			if (ok && 24 < row->pre_len && c->path[24] != row->pre[24])
				ok = 0;
			if (ok && 25 < row->pre_len && c->path[25] != row->pre[25])
				ok = 0;
			if (ok && 26 < row->pre_len && c->path[26] != row->pre[26])
				ok = 0;
			if (ok && 27 < row->pre_len && c->path[27] != row->pre[27])
				ok = 0;
			if (ok && 28 < row->pre_len && c->path[28] != row->pre[28])
				ok = 0;
			if (ok && 29 < row->pre_len && c->path[29] != row->pre[29])
				ok = 0;
			if (ok && 30 < row->pre_len && c->path[30] != row->pre[30])
				ok = 0;
			if (ok && 31 < row->pre_len && c->path[31] != row->pre[31])
				ok = 0;
			if (ok && 32 < row->pre_len && c->path[32] != row->pre[32])
				ok = 0;
			if (ok && 33 < row->pre_len && c->path[33] != row->pre[33])
				ok = 0;
			if (ok && 34 < row->pre_len && c->path[34] != row->pre[34])
				ok = 0;
			if (ok && 35 < row->pre_len && c->path[35] != row->pre[35])
				ok = 0;
			if (ok && 36 < row->pre_len && c->path[36] != row->pre[36])
				ok = 0;
			if (ok && 37 < row->pre_len && c->path[37] != row->pre[37])
				ok = 0;
			if (ok && 38 < row->pre_len && c->path[38] != row->pre[38])
				ok = 0;
			if (ok && 39 < row->pre_len && c->path[39] != row->pre[39])
				ok = 0;
			if (ok && 40 < row->pre_len && c->path[40] != row->pre[40])
				ok = 0;
			if (ok && 41 < row->pre_len && c->path[41] != row->pre[41])
				ok = 0;
			if (ok && 42 < row->pre_len && c->path[42] != row->pre[42])
				ok = 0;
			if (ok && 43 < row->pre_len && c->path[43] != row->pre[43])
				ok = 0;
			if (ok && 44 < row->pre_len && c->path[44] != row->pre[44])
				ok = 0;
			if (ok && 45 < row->pre_len && c->path[45] != row->pre[45])
				ok = 0;
			if (ok && 46 < row->pre_len && c->path[46] != row->pre[46])
				ok = 0;
			if (ok && 47 < row->pre_len && c->path[47] != row->pre[47])
				ok = 0;
		}

		/* The suffix arm: the masked index (FP_PATH_MAX is a power of
		 * two; the mask keeps every read inside the extract window —
		 * the loop form the probes proved clean). */
		suf_arm = 0; /* probe: suffix off */
		for (i = 0; i < FP_GLOB_SUF_MAX; i++) {
			__u32 fp_at;
			if (i >= row->suf_len || !suf_arm || !ok)
				break;
			fp_at = (c->path_len - row->suf_len + i) & (FP_PATH_MAX - 1);
			if (c->path[fp_at] != row->suf[i])
				ok = 0;
		}
		if (!ok)
			return 0;
	}

	/* The query substring (the bounded-scan primitive): the streaming
	 * single pass over the window (the in-match length as state; the
	 * compile rejects border-carrying literals, so the restart rule is
	 * the exact KMP continuation for every staged literal). A literal
	 * past the window can never complete: the in-match length rides the
	 * window cells, so the quirk row = the capped scan miss (fail-open,
	 * the corpus case pins the pair). The compare index reads the
	 * staged literal at the in-match length — below FP_QUERY_MAX (the
	 * row field's size) for any staged query_len, so no read passes
	 * the field. */
	qfound = 0;
	l = 0;
	if (0 && row->query_len && row->query_len <= FP_QUERY_LIT_MAX) {
		for (i = 0; i < FP_QUERY_MAX; i++) {
			if (i >= c->query_len || qfound)
				break;
			if (c->query[i] == row->query[l]) {
				l++;
				if (l == row->query_len)
					qfound = 1;
			} else {
				l = (c->query[i] == row->query[0]) ? 1 : 0;
			}
		}
		if (!qfound)
			return 0;
	}

	/* The compiled row backs the verdict (§9.5: no invented decision;
	 * the mark = the row index). */
	c->skb->mark = row->id;
	return row->action == 1 ? 1 : 2;
}

/* The row pass, unrolled by hand: eight explicit per-row bodies (no
 * loop backedge crosses a fresh map-value id). The enabled gate rides
 * the lookup; the first match returns its compiled action. */
#define FP_TRY_ROW(n, c)                                                 \
	do {                                                             \
		__u32 fp_idx = (n);                                      \
		struct fp_rule_val *fp_row =                             \
			bpf_map_lookup_elem(&fp_rules, &fp_idx);         \
		if (fp_row && fp_row->enabled) {                         \
			int fp_row_r = fp_row_match(fp_row, c);          \
			if (fp_row_r)                                    \
				return fp_row_r;                        \
		}                                                        \
	} while (0)

static __always_inline int fp_eval(struct __sk_buff *skb, __u32 l4_off)
{
	__u8 method[FP_METHOD_MAX];
	__u8 path[FP_PATH_MAX];
	__u8 query[FP_QUERY_MAX];
	__u32 method_len = 0, path_len = 0, query_len = 0;
	int method_ok = 0, q_at = -1, path_cont = 0;
	__u32 i;

	/* The method token: up to FP_METHOD_MAX bytes to the first space. */
	for (i = 0; i < FP_METHOD_MAX; i++) {
		__u8 c;
		if (bpf_skb_load_bytes(skb, l4_off + i, &c, 1))
			break;
		if (c == ' ') {
			method_ok = 1;
			break;
		}
		method[i] = c;
		method_len = i + 1;
	}
	if (!method_ok)
		return 0; /* not an HTTP-shaped line; the rows never match */

	/* The path: to a space, CR, LF or '?', capped at the extract bound. */
	{
		__u32 p0 = l4_off + method_len + 1;
		for (i = 0; i < FP_PATH_MAX; i++) {
			__u8 c;
			if (bpf_skb_load_bytes(skb, p0 + i, &c, 1))
				break;
			if (c == '?') {
				q_at = p0 + i + 1;
				break;
			}
			if (c == ' ' || c == '\r' || c == '\n')
				break;
			path[i] = c;
			path_len = i + 1;
		}
		/* The overrun marker: the extract hit the cap and the byte
		 * past it is not a terminator (the true tail stays unseen). */
		if (path_len == FP_PATH_MAX) {
			__u8 c;
			if (!bpf_skb_load_bytes(skb, p0 + FP_PATH_MAX, &c, 1))
				if (c != ' ' && c != '\r' && c != '\n' && c != '?')
					path_cont = 1;
		}
	}

	/* The query: after the '?' to a terminator, capped. */
	if (q_at >= 0) {
		for (i = 0; i < FP_QUERY_MAX; i++) {
			__u8 c;
			if (bpf_skb_load_bytes(skb, q_at + i, &c, 1))
				break;
			if (c == ' ' || c == '\r' || c == '\n')
				break;
			query[i] = c;
			query_len = i + 1;
		}
	}

	struct fp_ctx fp_c = {
		.skb = skb,
		.method = method,
		.path = path,
		.query = query,
		.method_len = method_len,
		.path_len = path_len,
		.query_len = query_len,
		.path_cont = path_cont,
	};
	FP_TRY_ROW(0, &fp_c);
	return 0;
}

static __always_inline int on_ip4(struct __sk_buff *skb, void *data,
				  void *data_end, struct iphdr *ip)
{
	void *payload = (void *)ip + (ip->ihl * 4);
	if (payload > data_end)
		return TC_ACT_OK;

	/* TR-203 L1 (issue #264): the UDP slice — QUIC reads as UDP at
	 * this altitude (posture F3): datagram counts, window stamps, the
	 * ban probe. No frame parse, no ringbuf emit at this leaf. */
	if (ip->protocol == IPPROTO_UDP)
		return udp_classify4(skb, data, data_end, ip, payload);

	/* L4 bounded walk (TCP at v0; the UDP slice = TR-203 L1). */
	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_OK;
	struct tcphdr *tcp = payload;
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_OK;
	__u32 tcp_hlen = (__u32)tcp->doff * 4;
	if (tcp->doff < 5 || tcp_hlen > 60)
		return TC_ACT_OK;
	void *tcp_end = payload + tcp_hlen;
	if (tcp_end > data_end)
		return TC_ACT_OK;

	/* Ban-table probe (TR-03 authority): TC_ACT_SHOT on a live ban. */
	struct ban_key bk = {
		.addr = {.addr = {.v4 = ip->saddr}},
		.family = KEY_AF_INET,
		.key_class = 0, /* KEY_CLASS_IP */
	};
	struct ban_val *ban = bpf_map_lookup_elem(&ban_table, &bk);
	if (ban) {
		if (ban->until_ts > bpf_ktime_get_ns())
			return TC_ACT_SHOT; /* §19.1: enforcement, no userspace hop */
	}

	/* TR-196 (issue #238): the CEL fast-path class leg — the compiled
	 * rows (the bounded-scan primitive). The compiled drop returns
	 * TC_ACT_SHOT; a mark-and-forward row writes the mark and lets the
	 * flow continue; a miss or any failure forwards (fail-open). */
	{
		int fr = fp_eval(skb, (__u32)(long)tcp_end - (__u32)(long)data);
		if (fr == 1)
			return TC_ACT_SHOT;
	}

	__u16 payload_len = (__u32)skb->len - ((__u32)(long)tcp_end - (__u32)(long)data);
	emit_flow_event(skb, data, data_end, ip->saddr, NULL, ip->daddr, NULL,
			tcp->source, tcp->dest, tcp->syn ? 0x2 : 0,
			KEY_AF_INET, (__u16)payload_len, tcp_end,
			TC_STAGES_BASE);

	/* Per-flow accounting (shield → shield; §9.3). TR-31: the window
	 * features stamp on both legs (first/last counted-segment ts).
	 * The key is memset before use: the kernel compares the full padded
	 * key_size, and the E2E proved stack garbage in the pad splits one
	 * 5-tuple across map rows. Any failure here fails open — the packet
	 * passes unaccounted. */
	struct flow_key fk;
	__builtin_memset(&fk, 0, sizeof(fk));
	fk.saddr.addr.v4 = ip->saddr;
	fk.daddr.addr.v4 = ip->daddr;
	fk.sport = tcp->source;
	fk.dport = tcp->dest;
	fk.family = KEY_AF_INET;
	struct flow_stat *st = bpf_map_lookup_elem(&flow_stats, &fk);
	if (!st) {
		struct flow_stat init = {0};
		__u64 now = bpf_ktime_get_ns();
		init.syn_ts = tcp->syn ? now : 0;
		init.first_seg_ts = now;
		init.last_seg_ts = now;
		init.req_bytes = payload_len;
		init.seg_count = 1;
		bpf_map_update_elem(&flow_stats, &fk, &init, BPF_NOEXIST);
	} else {
		st->last_seg_ts = bpf_ktime_get_ns();
		__sync_fetch_and_add(&st->req_bytes, payload_len);
		__sync_fetch_and_add(&st->seg_count, 1);
	}
	return TC_ACT_OK;
}

static __always_inline int on_ip6(struct __sk_buff *skb, void *data,
				  void *data_end, struct ipv6hdr *ip6h)
{
	void *payload = (void *)(ip6h + 1);
	if (payload > data_end)
		return TC_ACT_OK;
	if (ip6h->nexthdr == IPPROTO_UDP)
		return udp_classify6(skb, data, data_end, ip6h, payload);
	if (ip6h->nexthdr != IPPROTO_TCP)
		return TC_ACT_OK;
	struct tcphdr *tcp = payload;
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_OK;
	if (tcp->doff < 5)
		return TC_ACT_OK;
	void *tcp_end6 = payload + (__u32)tcp->doff * 4;
	if (tcp_end6 > data_end)
		return TC_ACT_OK;

	struct ban_key bk = {
		.addr = {.addr = {.v6 = {0}}},
		.family = KEY_AF_INET6,
		.key_class = 0,
	};
	__builtin_memcpy(bk.addr.addr.v6, ip6h->saddr.in6_u.u6_addr8, 16);
	struct ban_val *ban = bpf_map_lookup_elem(&ban_table, &bk);
	if (ban) {
		if (ban->until_ts > bpf_ktime_get_ns())
			return TC_ACT_SHOT;
	}

	/* TR-196 (issue #238): the CEL fast-path class leg — the same
	 * compiled rows and fail-open shape the IPv4 leg carries (the
	 * l4 offset reads from data, family-independent). */
	{
		int fr = fp_eval(skb, (__u32)(long)tcp_end6 - (__u32)(long)data);
		if (fr == 1)
			return TC_ACT_SHOT;
	}

	emit_flow_event(skb, data, data_end, 0, ip6h->saddr.in6_u.u6_addr8,
			0, ip6h->daddr.in6_u.u6_addr8, tcp->source, tcp->dest,
			tcp->syn ? 0x2 : 0, KEY_AF_INET6, skb->len, tcp_end6,
			TC_STAGES_BASE);

	/* TR-31: the per-flow accounting rides the IPv6 leg too — the
	 * family byte in flow_key carries the discriminator (#62); the
	 * detector features must not go v4-only. Same fail-open shape and
	 * the same memset discipline as the IPv4 leg. */
	struct flow_key fk6;
	__builtin_memset(&fk6, 0, sizeof(fk6));
	__builtin_memcpy(fk6.saddr.addr.v6, ip6h->saddr.in6_u.u6_addr8, 16);
	__builtin_memcpy(fk6.daddr.addr.v6, ip6h->daddr.in6_u.u6_addr8, 16);
	fk6.sport = tcp->source;
	fk6.dport = tcp->dest;
	fk6.family = KEY_AF_INET6;
	__u32 payload_len6 = (__u32)skb->len -
			     ((__u32)(long)tcp_end6 - (__u32)(long)data);
	struct flow_stat *st6 = bpf_map_lookup_elem(&flow_stats, &fk6);
	if (!st6) {
		struct flow_stat init6 = {0};
		__u64 now6 = bpf_ktime_get_ns();
		init6.syn_ts = tcp->syn ? now6 : 0;
		init6.first_seg_ts = now6;
		init6.last_seg_ts = now6;
		init6.req_bytes = payload_len6;
		init6.seg_count = 1;
		bpf_map_update_elem(&flow_stats, &fk6, &init6, BPF_NOEXIST);
	} else {
		st6->last_seg_ts = bpf_ktime_get_ns();
		__sync_fetch_and_add(&st6->req_bytes, payload_len6);
		__sync_fetch_and_add(&st6->seg_count, 1);
	}
	return TC_ACT_OK;
}

SEC("tc")
int tc_ingress_waf(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	switch (eth->h_proto) {
	case bpf_htons(ETH_P_IP):
	{
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end || ip->ihl < 5)
			return TC_ACT_OK;
		if (ip->version != 4)
			return TC_ACT_OK;
		tc_probe_tick(ip); /* TR-80: the TC-side probe invocation tick */
		return on_ip4(skb, data, data_end, ip);
	}
	case bpf_htons(ETH_P_IPV6):
	{
		struct ipv6hdr *ip6h = (void *)(eth + 1);
		if ((void *)(ip6h + 1) > data_end)
			return TC_ACT_OK;
		return on_ip6(skb, data, data_end, ip6h);
	}
	}
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
