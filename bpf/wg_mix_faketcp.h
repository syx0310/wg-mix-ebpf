// SPDX-License-Identifier: MIT
//
// Clean-room FakeTCP wire path. This follows the public architectural idea of
// a TC encoder, pre-GRO XDP decoder and userspace handshake engine, but does
// not contain source copied from third-party implementations.
#ifndef WG_MIX_FAKETCP_H
#define WG_MIX_FAKETCP_H

#define FAKETCP_STATE_IDLE        0
#define FAKETCP_STATE_SYN_SENT    1
#define FAKETCP_STATE_SYN_RECV    2
#define FAKETCP_STATE_ESTABLISHED 3
#define FAKETCP_STATE_CLOSING     4

#define FAKETCP_EVENT_NEED_HANDSHAKE 1
#define FAKETCP_EVENT_SYN            2
#define FAKETCP_EVENT_SYNACK         3
#define FAKETCP_EVENT_ACK            4
#define FAKETCP_EVENT_RST            5
#define FAKETCP_EVENT_FIN            6

#define FAKETCP_FLAG_FIN 0x01
#define FAKETCP_FLAG_SYN 0x02
#define FAKETCP_FLAG_RST 0x04
#define FAKETCP_FLAG_PSH 0x08
#define FAKETCP_FLAG_ACK 0x10

#define FAKETCP_HEADER_DELTA 12
#define FAKETCP_METADATA_MAGIC 0x57474654U

struct faketcp_session_key {
	__u64 generation;
	__be32 local_ipv4;
	__be32 remote_ipv4;
	__u32 underlay_index;
	__u16 local_port;
	__u16 remote_port;
};

struct faketcp_session_value {
	__u64 generation;
	__u64 last_seen_nanos;
	__u32 tx_sequence;
	__u32 rx_sequence;
	__u32 local_isn;
	__u32 remote_isn;
	__u16 window;
	__u8 state;
	__u8 flags;
	__u8 pad[4];
};

struct faketcp_event {
	struct faketcp_session_key key;
	__u64 timestamp_nanos;
	__u32 sequence;
	__u32 acknowledgement;
	__u32 payload_length;
	__u8 type;
	__u8 tcp_flags;
	__u8 pad[2];
};

struct faketcp_metadata {
	__u32 magic;
	__u32 generation_low;
};

struct faketcp_pseudo_tail {
	__u8 zero;
	__u8 protocol;
	__be16 length;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct faketcp_session_key);
	__type(value, struct faketcp_session_value);
} faketcp_session_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} faketcp_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} faketcp_egress_programs SEC(".maps");

static __always_inline int faketcp_emit_event(const struct faketcp_session_key *key,
					       __u8 type, __u8 flags,
					       __u32 seq, __u32 ack,
					       __u32 payload_len)
{
	struct faketcp_event event = {
		.key = *key,
		.timestamp_nanos = bpf_ktime_get_ns(),
		.sequence = seq,
		.acknowledgement = ack,
		.payload_length = payload_len,
		.type = type,
		.tcp_flags = flags,
	};

	if (bpf_ringbuf_output(&faketcp_events, &event, sizeof(event), 0) < 0) {
		inc_stat(STAT_FAKETCP_EVENT_ERROR);
		return -1;
	}
	return 0;
}

static __always_inline int faketcp_tc_key(struct __sk_buff *skb,
					   const struct packet_info *info,
					   __u64 generation,
					   struct faketcp_session_key *key)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;

	if (info->family != FAMILY_IPV4 || (void *)(iph + 1) > data_end)
		return -1;
	key->generation = generation;
	key->local_ipv4 = iph->saddr;
	key->remote_ipv4 = iph->daddr;
	key->underlay_index = skb->ifindex;
	key->local_port = info->src_port;
	key->remote_port = info->dst_port;
	return 0;
}

static __always_inline int faketcp_tcp_checksum_from_udp(const struct iphdr *iph,
						  struct udphdr old_udp,
						  struct tcphdr *tcp,
						  __u16 udp_len)
{
	struct faketcp_pseudo_tail old_pseudo = {
		.protocol = IPPROTO_UDP,
		.length = bpf_htons(udp_len),
	};
	struct faketcp_pseudo_tail new_pseudo = {
		.protocol = IPPROTO_TCP,
		.length = bpf_htons(udp_len + FAKETCP_HEADER_DELTA),
	};
	__u16 old_checksum = bpf_ntohs(old_udp.check);
	__s64 sum;

	(void)iph;
	if (old_checksum == 0)
		return -1;
	old_udp.check = 0;
	tcp->check = 0;
	sum = (~old_checksum) & 0xffff;
	sum = bpf_csum_diff((__be32 *)&old_pseudo, sizeof(old_pseudo),
			     (__be32 *)&new_pseudo, sizeof(new_pseudo), sum);
	if (sum < 0)
		return -1;
	sum = bpf_csum_diff((__be32 *)&old_udp, sizeof(old_udp),
			     (__be32 *)tcp, sizeof(*tcp), sum);
	if (sum < 0)
		return -1;
	tcp->check = bpf_htons(fold_csum(sum));
	if (tcp->check == 0)
		tcp->check = bpf_htons(0xffff);
	return 0;
}

// faketcp_encode_established is the single encoder used by both the direct
// type-word path and the XOR tail-call continuation.
static __always_inline int faketcp_encode_established(struct __sk_buff *skb,
						       struct packet_info *info,
						       struct egress_rule_value *rule,
						       __u64 generation)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct udphdr *udp = data + info->udp_off;
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct udphdr old_udp;
	struct tcphdr tcp = {};
	__u8 head[FAKETCP_HEADER_DELTA] = {};
	__u16 old_total_len, new_total_len, udp_len;
	__u32 seq;

	if (rule->transport_mode != TRANSPORT_FAKETCP || info->family != FAMILY_IPV4 ||
	    info->payload_len < FAKETCP_HEADER_DELTA || (info->payload_len & 1) ||
	    (void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end) {
		inc_stat(STAT_FAKETCP_BAD_PACKET);
		return TC_ACT_SHOT;
	}
	if (skb->gso_segs || skb->gso_size) {
		inc_stat(STAT_FAKETCP_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	if (faketcp_tc_key(skb, info, generation, &key) < 0) {
		inc_stat(STAT_FAKETCP_BAD_PACKET);
		return TC_ACT_SHOT;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (!session || session->generation != generation) {
		inc_stat(STAT_FAKETCP_SESSION_MISS);
		faketcp_emit_event(&key, FAKETCP_EVENT_NEED_HANDSHAKE, 0, 0, 0,
				   info->payload_len);
		return TC_ACT_SHOT;
	}
	if (session->state != FAKETCP_STATE_ESTABLISHED) {
		inc_stat(STAT_FAKETCP_BAD_STATE);
		return TC_ACT_SHOT;
	}
	old_udp = *udp;
	udp_len = bpf_ntohs(old_udp.len);
	old_total_len = bpf_ntohs(iph->tot_len);
	if (udp_len != info->payload_len + sizeof(old_udp) ||
	    old_total_len > 0xffff - FAKETCP_HEADER_DELTA) {
		inc_stat(STAT_FAKETCP_BAD_PACKET);
		return TC_ACT_SHOT;
	}
	if (bpf_skb_load_bytes(skb, info->payload_off, head, sizeof(head)) < 0) {
		inc_stat(STAT_SKB_LOAD_ERROR);
		return TC_ACT_SHOT;
	}
	if (bpf_skb_change_tail(skb, skb->len + FAKETCP_HEADER_DELTA, 0) < 0) {
		inc_stat(STAT_SKB_STORE_ERROR);
		return TC_ACT_SHOT;
	}
	if (bpf_skb_store_bytes(skb, skb->len - FAKETCP_HEADER_DELTA,
				head, sizeof(head), BPF_F_INVALIDATE_HASH) < 0) {
		inc_stat(STAT_SKB_STORE_ERROR);
		return TC_ACT_SHOT;
	}

	seq = __sync_fetch_and_add(&session->tx_sequence, info->payload_len);
	session->last_seen_nanos = bpf_ktime_get_ns();
	tcp.source = old_udp.source;
	tcp.dest = old_udp.dest;
	tcp.seq = bpf_htonl(seq);
	tcp.ack_seq = bpf_htonl(session->rx_sequence);
	tcp.doff = 5;
	tcp.ack = 1;
	tcp.psh = 1;
	tcp.window = bpf_htons(session->window ? session->window : 65535);
	if (faketcp_tcp_checksum_from_udp(iph, old_udp, &tcp, udp_len) < 0) {
		inc_stat(STAT_FAKETCP_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}
	if (bpf_skb_store_bytes(skb, info->udp_off, &tcp, sizeof(tcp),
				BPF_F_INVALIDATE_HASH) < 0) {
		inc_stat(STAT_SKB_STORE_ERROR);
		return TC_ACT_SHOT;
	}
	new_total_len = old_total_len + FAKETCP_HEADER_DELTA;
	if (bpf_l3_csum_replace(skb, info->ip_off + offsetof(struct iphdr, check),
				bpf_htons(old_total_len), bpf_htons(new_total_len), 2) < 0 ||
	    bpf_skb_store_bytes(skb, info->ip_off + offsetof(struct iphdr, tot_len),
				&(__be16){bpf_htons(new_total_len)}, sizeof(__be16),
				BPF_F_INVALIDATE_HASH) < 0 ||
	    update_ipv4_protocol(skb, info->ip_off, IPPROTO_UDP, IPPROTO_TCP) < 0) {
		inc_stat(STAT_FAKETCP_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}

	// Loading this path is gated until a reviewed kfunc can update
	// CHECKSUM_PARTIAL csum_offset. Do not weaken that loader gate merely
	// because fully materialized packet tests pass.
	inc_stat(STAT_EGRESS_REWRITE_OK);
	inc_stat(STAT_FAKETCP_EGRESS_OK);
	return TC_ACT_OK;
}

static __always_inline int faketcp_continue_egress(struct __sk_buff *skb)
{
	struct packet_info info = {};
	struct egress_rule_key key = {};
	struct egress_rule_value *rule;
	__u64 generation = 0;

	if (!active_generation(&generation) || parse_packet(skb, &info, generation) != PARSE_OK)
		return TC_ACT_SHOT;
	key.generation = generation;
	key.fwmark = skb->mark;
	key.underlay_index = skb->ifindex;
	key.source_port = info.src_port;
	key.family = info.family;
	rule = bpf_map_lookup_elem(&egress_rule_map, &key);
	if (!rule || rule->generation != generation) {
		key.underlay_index = UNDERLAY_WILDCARD;
		rule = bpf_map_lookup_elem(&egress_rule_map, &key);
	}
	if (!rule || rule->generation != generation ||
	    rule->transport_mode != TRANSPORT_FAKETCP) {
		inc_stat(STAT_FAKETCP_BAD_STATE);
		return TC_ACT_SHOT;
	}
	return faketcp_encode_established(skb, &info, rule, generation);
}

SEC("classifier/faketcp_egress")
int wg_faketcp_egress(struct __sk_buff *skb)
{
	return faketcp_continue_egress(skb);
}

static __always_inline int faketcp_metadata_valid(struct __sk_buff *skb,
						   __u64 generation)
{
	void *data = (void *)(long)skb->data;
	void *meta = (void *)(long)skb->data_meta;
	struct faketcp_metadata *value = meta;

	if (meta + sizeof(*value) > data)
		return 0;
	return value->magic == FAKETCP_METADATA_MAGIC &&
	       value->generation_low == (__u32)generation;
}

static __always_inline int faketcp_xdp_listener(__u32 ifindex, __u16 port,
						 __u64 generation,
						 struct ingress_listener_value **out)
{
	struct ingress_listener_key key = {
		.generation = generation,
		.underlay_index = ifindex,
		.destination_port = port,
		.family = FAMILY_IPV4,
	};
	struct ingress_listener_value *listener;

	listener = bpf_map_lookup_elem(&ingress_listener_map, &key);
	if (!listener || listener->generation != generation) {
		key.underlay_index = UNDERLAY_WILDCARD;
		listener = bpf_map_lookup_elem(&ingress_listener_map, &key);
	}
	if (!listener || listener->generation != generation ||
	    listener->transport_mode != TRANSPORT_FAKETCP)
		return 0;
	*out = listener;
	return 1;
}

static __always_inline __u8 faketcp_tcp_flags(const struct tcphdr *tcp)
{
	const __u8 *raw = (const __u8 *)tcp;
	return raw[13];
}

static __always_inline __u8 faketcp_event_type(__u8 flags)
{
	if (flags & FAKETCP_FLAG_RST)
		return FAKETCP_EVENT_RST;
	if (flags & FAKETCP_FLAG_FIN)
		return FAKETCP_EVENT_FIN;
	if ((flags & (FAKETCP_FLAG_SYN | FAKETCP_FLAG_ACK)) ==
	    (FAKETCP_FLAG_SYN | FAKETCP_FLAG_ACK))
		return FAKETCP_EVENT_SYNACK;
	if (flags & FAKETCP_FLAG_SYN)
		return FAKETCP_EVENT_SYN;
	return FAKETCP_EVENT_ACK;
}

SEC("xdp")
int wg_mix_faketcp_ingress(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	__u64 off = sizeof(struct ethhdr);
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct ingress_listener_value *listener = 0;
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct faketcp_metadata *metadata;
	struct faketcp_pseudo_tail old_pseudo, new_pseudo;
	struct tcphdr old_tcp;
	struct udphdr udp = {};
	__u8 tail[FAKETCP_HEADER_DELTA] = {};
	__u8 flags;
	__u16 total_len, tcp_len, payload_len, new_total_len;
	__u32 seq, next_seq;
	__u64 generation = 0;
	__s64 sum;

	if (!active_generation(&generation))
		return XDP_PASS;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_8021Q) ||
	    eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		struct wg_vlan_hdr *vlan = data + off;
		if ((void *)(vlan + 1) > data_end)
			return XDP_PASS;
		if (vlan->h_vlan_encapsulated_proto != bpf_htons(ETH_P_IP))
			return XDP_PASS;
		off += sizeof(*vlan);
	} else if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}
	iph = data + off;
	if ((void *)(iph + 1) > data_end || iph->version != 4 || iph->ihl != 5 ||
	    iph->protocol != IPPROTO_TCP || (bpf_ntohs(iph->frag_off) & (IP_MF | IP_OFFSET)))
		return XDP_PASS;
	tcp = data + off + sizeof(*iph);
	if ((void *)(tcp + 1) > data_end || tcp->doff != 5)
		return XDP_PASS;
	if (!faketcp_xdp_listener(xdp->ingress_ifindex, bpf_ntohs(tcp->dest),
				   generation, &listener))
		return XDP_PASS;
	if (listener->action != ACTION_REWRITE)
		return XDP_DROP;
	total_len = bpf_ntohs(iph->tot_len);
	if (total_len < sizeof(*iph) + sizeof(*tcp) || data + off + total_len > data_end)
		return XDP_DROP;
	tcp_len = total_len - sizeof(*iph);
	payload_len = tcp_len - sizeof(*tcp);
	flags = faketcp_tcp_flags(tcp);
	seq = bpf_ntohl(tcp->seq);
	key.generation = generation;
	key.local_ipv4 = iph->daddr;
	key.remote_ipv4 = iph->saddr;
	key.underlay_index = xdp->ingress_ifindex;
	key.local_port = bpf_ntohs(tcp->dest);
	key.remote_port = bpf_ntohs(tcp->source);
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (!session || session->generation != generation ||
	    session->state != FAKETCP_STATE_ESTABLISHED) {
		faketcp_emit_event(&key, faketcp_event_type(flags), flags, seq,
				   bpf_ntohl(tcp->ack_seq), payload_len);
		return XDP_DROP;
	}
	if ((flags & (FAKETCP_FLAG_SYN | FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN)) ||
	    !(flags & FAKETCP_FLAG_ACK) || payload_len < FAKETCP_HEADER_DELTA ||
	    (payload_len & 1)) {
		inc_stat(STAT_FAKETCP_BAD_PACKET);
		return XDP_DROP;
	}
	old_tcp = *tcp;
	if (old_tcp.check == 0 ||
	    bpf_xdp_load_bytes(xdp, off + total_len - FAKETCP_HEADER_DELTA,
			       tail, sizeof(tail)) < 0) {
		inc_stat(STAT_FAKETCP_CHECKSUM_ERROR);
		return XDP_DROP;
	}
	udp.source = old_tcp.source;
	udp.dest = old_tcp.dest;
	udp.len = bpf_htons(payload_len + sizeof(udp));
	udp.check = 0;
	old_pseudo = (struct faketcp_pseudo_tail){
		.protocol = IPPROTO_TCP,
		.length = bpf_htons(tcp_len),
	};
	new_pseudo = (struct faketcp_pseudo_tail){
		.protocol = IPPROTO_UDP,
		.length = udp.len,
	};
	sum = (~bpf_ntohs(old_tcp.check)) & 0xffff;
	old_tcp.check = 0;
	sum = bpf_csum_diff((__be32 *)&old_pseudo, sizeof(old_pseudo),
			     (__be32 *)&new_pseudo, sizeof(new_pseudo), sum);
	if (sum < 0)
		return XDP_DROP;
	sum = bpf_csum_diff((__be32 *)&old_tcp, sizeof(old_tcp),
			     (__be32 *)&udp, sizeof(udp), sum);
	if (sum < 0)
		return XDP_DROP;
	udp.check = bpf_htons(fold_csum(sum));
	if (udp.check == 0)
		udp.check = bpf_htons(0xffff);

	new_total_len = total_len - FAKETCP_HEADER_DELTA;
	if (bpf_xdp_adjust_meta(xdp, -(int)sizeof(struct faketcp_metadata)) < 0)
		return XDP_DROP;
	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;
	metadata = (void *)(long)xdp->data_meta;
	if ((void *)(metadata + 1) > data)
		return XDP_DROP;
	metadata->magic = FAKETCP_METADATA_MAGIC;
	metadata->generation_low = (__u32)generation;
	if (bpf_xdp_store_bytes(xdp, off + sizeof(*iph), &udp, sizeof(udp)) < 0 ||
	    bpf_xdp_store_bytes(xdp, off + sizeof(*iph) + sizeof(udp), tail,
			       sizeof(tail)) < 0)
		return XDP_DROP;

	// This first slice accepts only a fixed 20-byte IPv4 header, so a full
	// header recomputation is bounded and avoids XDP checksum-helper gaps.
	iph = data + off;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;
	struct iphdr new_ip = *iph;
	new_ip.protocol = IPPROTO_UDP;
	new_ip.tot_len = bpf_htons(new_total_len);
	new_ip.check = 0;
	sum = bpf_csum_diff(0, 0, (__be32 *)&new_ip, sizeof(new_ip), 0);
	if (sum < 0)
		return XDP_DROP;
	new_ip.check = bpf_htons(fold_csum(sum));
	if (bpf_xdp_store_bytes(xdp, off, &new_ip, sizeof(new_ip)) < 0 ||
	    bpf_xdp_adjust_tail(xdp, -FAKETCP_HEADER_DELTA) < 0)
		return XDP_DROP;

	next_seq = seq + payload_len;
	if ((__s32)(next_seq - session->rx_sequence) > 0)
		__sync_val_compare_and_swap(&session->rx_sequence,
					    session->rx_sequence, next_seq);
	session->last_seen_nanos = bpf_ktime_get_ns();
	inc_stat(STAT_FAKETCP_INGRESS_OK);
	return XDP_PASS;
}

#endif
