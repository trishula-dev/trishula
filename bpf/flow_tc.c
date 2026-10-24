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
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB per node (§9.4) */
} events SEC(".maps");

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
					   void *tcp_end)
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

static __always_inline int on_ip4(struct __sk_buff *skb, void *data,
				  void *data_end, struct iphdr *ip)
{
	void *payload = (void *)ip + (ip->ihl * 4);
	if (payload > data_end)
		return TC_ACT_OK;

	/* L4 bounded walk (TCP only at v0; UDP slice lands with §12). */
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

	__u16 payload_len = (__u32)skb->len - ((__u32)(long)tcp_end - (__u32)(long)data);
	emit_flow_event(skb, data, data_end, ip->saddr, NULL, ip->daddr, NULL,
			tcp->source, tcp->dest, tcp->syn ? 0x2 : 0,
			KEY_AF_INET, (__u16)payload_len, tcp_end);

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

	emit_flow_event(skb, data, data_end, 0, ip6h->saddr.in6_u.u6_addr8,
			0, ip6h->daddr.in6_u.u6_addr8, tcp->source, tcp->dest,
			tcp->syn ? 0x2 : 0, KEY_AF_INET6, skb->len, tcp_end6);

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
