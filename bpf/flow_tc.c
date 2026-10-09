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

/* Flow stats: per-flow counters (slowloris math later, §12/§13). */
struct flow_key {
	struct key_addr saddr, daddr;
	__u16 sport, dport;
	__u8 family;
};
struct flow_stat { __u64 syn_ts; __u32 req_bytes; __u32 seg_count; };

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 18);
	__type(key, struct flow_key);
	__type(value, struct flow_stat);
} flow_stats SEC(".maps");

static __always_inline int is_http_method(__u8 b0, __u8 b1)
{
	/* 4-byte method probes on the first line (§9.6 fast-path probe):
	 * GET/POST/PUT/DELETE/HEAD/PATCH/OPTIONS — v0: GET + POST only. */
	if (b0 == 'G' && b1 == 'E') return 1; /* GET  */
	if (b0 == 'P' && b1 == 'O') return 1; /* POST */
	return 0;
}

static __always_inline int emit_flow_event(struct __sk_buff *skb,
					   __be32 s4, __u8 *s6,
					   __be32 d4, __u8 *d6,
					   __u16 sport, __u16 dport,
					   __u8 tcp_flags, __u8 family,
					   __u16 payload_len,
					   void *payload, void *data_end)
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

	/* Bounded L7 probe (§9.6 advisory): plaintext HTTP method peek. */
	if (payload + 4 <= data_end) {
		__u8 b0 = *(__u8 *)payload;
		__u8 b1 = *(__u8 *)(payload + 1);
		if (is_http_method(b0, b1))
			ev->http_seen = 1;
		if (b0 == 0x50 && b1 == 0x52) /* "PR" of the h2 preface */
			ev->h2_preface = 1;
		if (payload + 6 <= data_end) {
			__u8 b3 = *(__u8 *)(payload + 3);
			__u8 b4 = *(__u8 *)(payload + 4);
			/* TLS record: 0x16 0x03 [0x00-0x04] size... */
			if (b0 == 0x16 && b1 == 0x03 && b4 <= 0x04)
				ev->tls_seen = 1;
			/* Path hint: after the method token + space. */
			if (ev->http_seen) {
				void *p = payload;
				int off = 0;
				/* find first SP (end of method) */
				#pragma unroll
				for (int i = 0; i < 8; i++) {
					if (p + i + 1 > data_end) break;
					if (*(__u8 *)(p + i) == ' ') { off = i + 1; break; }
				}
				#pragma unroll
				for (int i = 0; i < 64; i++) {
					if (p + off + i + 1 > data_end) break;
					__u8 c = *(__u8 *)(p + off + i);
					if (c == ' ' || c == '\r' || c == '\n') break;
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
	__u32 tcp_hlen = (__u32)tcp->doff * 4;
	if (tcp->doff < 5 || tcp_hlen > 60 || tcp_hlen > skb->len)
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

	__u16 payload_len = skb->len - ((__u32)(long)payload - (__u32)(long)data);
	emit_flow_event(skb, ip->saddr, NULL, ip->daddr, NULL,
			tcp->source, tcp->dest, tcp->syn ? 0x2 : 0,
			KEY_AF_INET, (__u16)payload_len, tcp_end, data_end);

	/* Per-flow accounting (shield → shield; §9.3). */
	struct flow_key fk = {
		.saddr = {.addr = {.v4 = ip->saddr}},
		.daddr = {.addr = {.v4 = ip->daddr}},
		.sport = tcp->source,
		.dport = tcp->dest,
		.family = KEY_AF_INET,
	};
	struct flow_stat *st = bpf_map_lookup_elem(&flow_stats, &fk);
	if (!st) {
		struct flow_stat init = {0};
		init.syn_ts = tcp->syn ? bpf_ktime_get_ns() : 0;
		init.req_bytes = payload_len;
		init.seg_count = 1;
		bpf_map_update_elem(&flow_stats, &fk, &init, BPF_NOEXIST);
	} else {
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

	emit_flow_event(skb, 0, ip6h->saddr.in6_u.u6_addr8, 0,
			ip6h->daddr.in6_u.u6_addr8, tcp->source, tcp->dest,
			tcp->syn ? 0x2 : 0, KEY_AF_INET6, skb->len,
			(void *)(tcp + 1), data_end);
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
