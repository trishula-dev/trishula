// SPDX-License-Identifier: GPL-2.0
// TR-40b (issue #188) — the route-marking template (the census `route`
// class). The template contract (docs/design/socket-plane/
// 4-compiler-census.md §5): one program, no tail calls, compile-time loop
// bounds, fail-open. The compile fills the placeholders from the bundle:
// route_marks rows (prefix, action) staged by the loader, and the
// route_cfg.default_fwd verdict for every miss. Everything outside the
// staged prefixes forwards; the kernel stays decision-free (§9.5).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ROUTE_MAX 8 /* row bound; the compile fails closed past it */
#define ROUTE_PREFIX_MAX 64
#define REQ_SNAP_MAX 96 /* the bounded request-line read */

struct route_key { __u32 prefixlen; __u8 prefix[ROUTE_PREFIX_MAX]; };
struct route_val { __u8 action; __u32 id; }; /* part-1 primitives */
struct route_cfg { __u32 default_fwd; }; /* load-time placeholder */

volatile const struct route_cfg route_cfg = { .default_fwd = TC_ACT_OK };

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, 1); /* BPF_F_NO_PREALLOC */
	__uint(max_entries, ROUTE_MAX);
	__type(key, struct route_key);
	__type(value, struct route_val);
} route_marks SEC(".maps");

SEC("tc")
int route_mark(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(0x0800)) return route_cfg.default_fwd;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->ihl < 5 || ip->protocol != 6) return route_cfg.default_fwd;
	struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
	if ((void *)(tcp + 1) > data_end || tcp->doff < 5) return route_cfg.default_fwd;
	__u32 req_off = sizeof(struct ethhdr) + ip->ihl * 4 + tcp->doff * 4;
	if (skb->len <= req_off)
		return route_cfg.default_fwd;
	__u32 n = skb->len - req_off; /* guarded: at least 1 byte */
	n &= 0xFF; /* bound the size word; the clamps below carry the truth */
	if (n > REQ_SNAP_MAX) n = REQ_SNAP_MAX;
	if (n < 1) return route_cfg.default_fwd; /* the helper needs 1..96 */
	__u8 buf[REQ_SNAP_MAX];
	if (bpf_skb_load_bytes(skb, req_off, buf, n)) return route_cfg.default_fwd;

	/* Scan one: the method end (the space that starts the path). */
	__u32 p0 = 0;
	for (__u32 i = 1; i < REQ_SNAP_MAX; i++) {
		if (i >= n) break;
		if (buf[i] != ' ') continue;
		p0 = i;
		break;
	}
	if (p0 == 0 || p0 >= n) return route_cfg.default_fwd;

	/* Scan two: the path. Copy stops at 64 bytes; the rest forwards. */
	struct route_key key = {};
	__u32 d = 0;
	for (__u32 i = p0 + 1; i < REQ_SNAP_MAX; i++) {
		if (i >= n || d >= ROUTE_PREFIX_MAX) break;
		__u8 c = buf[i];
		if (c == ' ' || c == '\r' || c == '\n') break;
		key.prefix[d++] = c;
	}
	if (d == 0) return route_cfg.default_fwd;

	/* The compile rejects non-printable prefixes, so no copied byte is
	 * NUL: the length reads back to the first zero. A NUL in the wire
	 * path shortens the key — the miss then forwards (fail-open). */
	for (__u32 i = 0; i < ROUTE_PREFIX_MAX; i++) {
		if (key.prefix[i] == 0) break;
		key.prefixlen += 8;
	}
	struct route_val *rv = bpf_map_lookup_elem(&route_marks, &key);
	if (!rv) return route_cfg.default_fwd;
	skb->mark = rv->id; /* the route class mark (row id) */
	if (rv->action == 1 /* ROUTE_ACT_DROP, the part-1 drop primitive */)
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
