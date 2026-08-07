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
#define FAKETCP_MAX_CAPTURED_PACKET 2304

enum faketcp_stat_id {
	FAKETCP_STAT_EGRESS_OK = 0,
	FAKETCP_STAT_INGRESS_OK,
	FAKETCP_STAT_SESSION_MISS,
	FAKETCP_STAT_BAD_STATE,
	FAKETCP_STAT_BAD_PACKET,
	FAKETCP_STAT_GSO_REJECT,
	FAKETCP_STAT_CHECKSUM_ERROR,
	FAKETCP_STAT_METADATA_ERROR,
	FAKETCP_STAT_EVENT_ERROR,
	FAKETCP_STAT_MAX,
};

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
	__u32 fwmark;
	__u32 wg_id;
	__u16 packet_length;
	__u8 type;
	__u8 tcp_flags;
};

struct faketcp_packet_event {
	struct faketcp_event event;
	__u8 packet[FAKETCP_MAX_CAPTURED_PACKET];
};

_Static_assert(sizeof(struct faketcp_event) == 56, "faketcp event ABI drift");
_Static_assert(sizeof(struct faketcp_packet_event) == 2360,
	       "faketcp packet event ABI drift");

struct faketcp_metadata {
	__u32 magic;
	__u32 generation_low;
};

struct faketcp_pseudo_tail {
	__u8 zero;
	__u8 protocol;
	__be16 length;
};

// These policy maps are populated for every concrete XDP attachment before
// the link becomes reachable. They deliberately duplicate the small listener
// projection needed at XDP: the baseline ingress map permits wildcard
// interfaces and cannot classify non-initial fragments that have no port.
// Keeping an exact per-interface marker makes every ambiguous TCP fragment or
// truncated header fail closed instead of reaching the host TCP stack.
struct faketcp_managed_if_key {
	__u64 generation;
	__u32 underlay_index;
	__u32 pad;
};

struct faketcp_managed_port_key {
	__u64 generation;
	__u32 underlay_index;
	__u16 destination_port;
	__u16 pad;
};

struct faketcp_managed_port_value {
	__u64 generation;
	__u32 wg_id;
	__u8 action;
	__u8 pad[3];
};

struct faketcp_ipv6_extension {
	__u8 next_header;
	__u8 header_length;
};

struct faketcp_ipv6_fragment {
	__u8 next_header;
	__u8 reserved;
	__be16 fragment_offset;
	__be32 identification;
};

struct {
	// Only established sessions enter this map. A bounded userspace half-open
	// table absorbs SYN pressure, and HASH insertion fails at capacity instead
	// of evicting an active established flow as LRU_HASH would.
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct faketcp_session_key);
	__type(value, struct faketcp_session_value);
} faketcp_session_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct faketcp_managed_if_key);
	__type(value, __u64);
} faketcp_managed_if_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct faketcp_managed_port_key);
	__type(value, struct faketcp_managed_port_value);
} faketcp_managed_port_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} faketcp_events SEC(".maps");

// bpf_ringbuf_output accepts a verifier-bounded variable record size whereas
// bpf_ringbuf_reserve requires a constant size. A per-CPU staging record lets
// us emit only the initialized event header and captured packet bytes, never
// the unused tail of the fixed upper bound.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct faketcp_packet_event);
} faketcp_capture_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} faketcp_egress_programs SEC(".maps");

// Experimental counters stay outside the version-10 canonical pinned stats
// map. This preserves ordinary UDP/ICMP reload compatibility while FakeTCP is
// hard-gated; the loader can expose this map together with the controller when
// the feature is ready for activation.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FAKETCP_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} faketcp_stats_map SEC(".maps");

static __always_inline void inc_faketcp_stat(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&faketcp_stats_map, &key);

	if (value)
		*value += 1;
}

static __always_inline int faketcp_emit_event(const struct faketcp_session_key *key,
					       __u8 type, __u8 flags,
					       __u32 seq, __u32 ack,
					       __u32 payload_len,
					       __u32 fwmark, __u32 wg_id)
{
	struct faketcp_event event = {
		.key = *key,
		.timestamp_nanos = bpf_ktime_get_ns(),
		.sequence = seq,
		.acknowledgement = ack,
		.payload_length = payload_len,
		.fwmark = fwmark,
		.wg_id = wg_id,
		.type = type,
		.tcp_flags = flags,
	};

	if (bpf_ringbuf_output(&faketcp_events, &event, sizeof(event), 0) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
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

	if (info->family != FAMILY_IPV4 || (void *)(iph + 1) > data_end ||
	    iph->version != 4 || iph->ihl != 5)
		return -1;
	key->generation = generation;
	key->local_ipv4 = iph->saddr;
	key->remote_ipv4 = iph->daddr;
	key->underlay_index = skb->ifindex;
	key->local_port = info->src_port;
	key->remote_port = info->dst_port;
	return 0;
}

// Capture happens before type-word and XOR mutation. The userspace release
// path can therefore re-inject this exact IPv4 packet once and let the normal
// egress pipeline apply every transform in the required order.
static __always_inline int faketcp_capture_first_packet(struct __sk_buff *skb,
						 const struct packet_info *info,
						 const struct egress_rule_value *rule,
						 const struct faketcp_session_key *key)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct faketcp_packet_event *record;
	__u32 zero = 0;
	__u64 record_len;
	__u16 packet_len;

	if ((void *)(iph + 1) > data_end)
		return -1;
	packet_len = bpf_ntohs(iph->tot_len);
	if (packet_len < sizeof(*iph) + sizeof(struct udphdr) ||
	    packet_len > FAKETCP_MAX_CAPTURED_PACKET)
		return -1;
	record = bpf_map_lookup_elem(&faketcp_capture_scratch, &zero);
	if (!record)
		return -1;
	record->event = (struct faketcp_event){
		.key = *key,
		.timestamp_nanos = bpf_ktime_get_ns(),
		.payload_length = info->payload_len,
		.fwmark = skb->mark,
		.wg_id = rule->wg_id,
		.packet_length = packet_len,
		.type = FAKETCP_EVENT_NEED_HANDSHAKE,
	};
	if (bpf_skb_load_bytes(skb, info->ip_off, record->packet, packet_len) < 0)
		return -1;
	record_len = sizeof(record->event) + packet_len;
	if (bpf_ringbuf_output(&faketcp_events, record, record_len, 0) < 0)
		return -1;
	return 0;
}

static __always_inline int faketcp_preflight_egress(struct __sk_buff *skb,
						     const struct packet_info *info,
						     const struct egress_rule_value *rule,
						     __u64 generation)
{
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;

	if (faketcp_tc_key(skb, info, generation, &key) < 0)
		return -1;
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (session && session->generation == generation &&
	    session->state == FAKETCP_STATE_ESTABLISHED)
		return 0;
	if (skb->gso_segs || skb->gso_size) {
		// Dropping is only a development fail-safe, not GSO support. The
		// activation gate requires a verified per-segment transform and real
		// offload acceptance before this object can be attached.
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return -1;
	}
	if (session)
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
	else
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
	if (faketcp_capture_first_packet(skb, info, rule, &key) < 0)
		inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
	return -1;
}

static __always_inline __s64 faketcp_rotation_checksum(const __u8 head[FAKETCP_HEADER_DELTA],
							__s64 seed, int inverse)
{
	__u8 aligned[16] = {};
	__u8 shifted[16] = {};

#pragma unroll
	for (int i = 0; i < FAKETCP_HEADER_DELTA; i++) {
		aligned[i] = head[i];
		shifted[i + 1] = head[i];
	}
	if (inverse)
		return bpf_csum_diff((__be32 *)shifted, sizeof(shifted),
				     (__be32 *)aligned, sizeof(aligned), seed);
	return bpf_csum_diff((__be32 *)aligned, sizeof(aligned),
			     (__be32 *)shifted, sizeof(shifted), seed);
}

// This packet-level prototype accepts only a fully materialized UDP checksum.
// Activation remains blocked until the kernel path can identify ip_summed,
// materialize/complete every CHECKSUM_PARTIAL seed, and reset checksum offset
// plus skb checksum metadata after the UDP-to-TCP header-size change. Merely
// rewriting csum_offset is not a valid completion strategy.
static __always_inline int faketcp_tcp_checksum_from_materialized_udp(
						  struct udphdr old_udp,
						  struct tcphdr *tcp,
						  __u16 udp_len,
						  const __u8 head[FAKETCP_HEADER_DELTA],
						  __u16 payload_len)
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
	if (payload_len & 1) {
		sum = faketcp_rotation_checksum(head, sum, 0);
		if (sum < 0)
			return -1;
	}
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
	    info->payload_len < FAKETCP_HEADER_DELTA ||
	    (void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return TC_ACT_SHOT;
	}
	if (skb->gso_segs || skb->gso_size) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	if (faketcp_tc_key(skb, info, generation, &key) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return TC_ACT_SHOT;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (!session || session->generation != generation) {
		// The preflight hook is the only place allowed to emit the handshake request
		// because it still owns the unmodified first packet. A map eviction in
		// this narrow post-transform race is a deliberate drop; WireGuard/QUIC
		// retransmission re-enters preflight with a capturable packet.
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
		return TC_ACT_SHOT;
	}
	if (session->state != FAKETCP_STATE_ESTABLISHED) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return TC_ACT_SHOT;
	}
	old_udp = *udp;
	udp_len = bpf_ntohs(old_udp.len);
	old_total_len = bpf_ntohs(iph->tot_len);
	if (udp_len != info->payload_len + sizeof(old_udp) ||
	    old_total_len > 0xffff - FAKETCP_HEADER_DELTA) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
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
	if (faketcp_tcp_checksum_from_materialized_udp(old_udp, &tcp, udp_len,
						      head, info->payload_len) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
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
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}

	// Loading this path is gated until CHECKSUM_PARTIAL inspection,
	// materialization/completion and checksum-metadata reset all pass the real
	// NIC offload matrix. Do not weaken that gate merely because fully
	// materialized packet tests pass.
	inc_stat(STAT_EGRESS_REWRITE_OK);
	inc_faketcp_stat(FAKETCP_STAT_EGRESS_OK);
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
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
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

static __always_inline int faketcp_xdp_managed_interface(__u32 ifindex,
						  __u64 generation)
{
	struct faketcp_managed_if_key key = {
		.generation = generation,
		.underlay_index = ifindex,
	};
	__u64 *value = bpf_map_lookup_elem(&faketcp_managed_if_map, &key);

	return value && *value == generation;
}

static __always_inline struct faketcp_managed_port_value *
faketcp_xdp_managed_port(__u32 ifindex, __u16 port, __u64 generation)
{
	struct faketcp_managed_port_key key = {
		.generation = generation,
		.underlay_index = ifindex,
		.destination_port = port,
	};
	struct faketcp_managed_port_value *value;

	value = bpf_map_lookup_elem(&faketcp_managed_port_map, &key);
	if (!value || value->generation != generation)
		return 0;
	return value;
}

static __always_inline int faketcp_xdp_ipv6_policy(void *data, void *data_end,
						    __u64 off, __u32 ifindex,
						    __u64 generation,
						    int managed_interface)
{
	struct ipv6hdr *ip6 = data + off;
	__u8 next_header;

	if ((void *)(ip6 + 1) > data_end || ip6->version != 6)
		return managed_interface ? XDP_DROP : XDP_PASS;
	next_header = ip6->nexthdr;
	off += sizeof(*ip6);

#pragma unroll
	for (int depth = 0; depth < 4; depth++) {
		if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
			struct udphdr *ports = data + off;

			if ((void *)(ports + 1) > data_end)
				return managed_interface ? XDP_DROP : XDP_PASS;
			return faketcp_xdp_managed_port(ifindex,
							 bpf_ntohs(ports->dest),
							 generation) ? XDP_DROP : XDP_PASS;
		}
		if (next_header == NEXTHDR_FRAGMENT) {
			struct faketcp_ipv6_fragment *fragment = data + off;

			if ((void *)(fragment + 1) > data_end)
				return managed_interface ? XDP_DROP : XDP_PASS;
			// Non-initial fragments have no trustworthy destination port.
			if (bpf_ntohs(fragment->fragment_offset) & 0xfff8)
				return managed_interface ? XDP_DROP : XDP_PASS;
			next_header = fragment->next_header;
			off += sizeof(*fragment);
			continue;
		}
		if (next_header == NEXTHDR_HOP || next_header == NEXTHDR_ROUTING ||
		    next_header == NEXTHDR_DEST) {
			struct faketcp_ipv6_extension *extension = data + off;
			__u64 extension_length;

			if ((void *)(extension + 1) > data_end)
				return managed_interface ? XDP_DROP : XDP_PASS;
			extension_length = ((__u64)extension->header_length + 1) * 8;
			if (extension_length < 8 || data + off + extension_length > data_end)
				return managed_interface ? XDP_DROP : XDP_PASS;
			next_header = extension->next_header;
			off += extension_length;
			continue;
		}
		if (next_header == IPPROTO_ICMPV6 || next_header == NEXTHDR_NONE)
			return XDP_PASS;
		// AH, ESP and unknown extension/transport values cannot prove that
		// a managed TCP/UDP destination is absent. Never leak them to the
		// host stack on a managed interface.
		return managed_interface ? XDP_DROP : XDP_PASS;
	}
	// An extension chain deeper than the verifier-bounded parser is
	// ambiguous on a managed interface and must never reach the host stack.
	return managed_interface ? XDP_DROP : XDP_PASS;
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
	__be16 protocol;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct udphdr *wire_ports;
	struct faketcp_managed_port_value *listener = 0;
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
	__u16 fragment_offset;
	__u32 ipv4_header_length;
	int managed_interface;

	if (!active_generation(&generation))
		return XDP_PASS;
	managed_interface = faketcp_xdp_managed_interface(xdp->ingress_ifindex,
							 generation);
	if ((void *)(eth + 1) > data_end)
		return managed_interface ? XDP_DROP : XDP_PASS;
	protocol = eth->h_proto;
#pragma unroll
	for (int vlan_depth = 0; vlan_depth < 2; vlan_depth++) {
		if (protocol != bpf_htons(ETH_P_8021Q) &&
		    protocol != bpf_htons(ETH_P_8021AD))
			break;
		struct wg_vlan_hdr *vlan = data + off;
		if ((void *)(vlan + 1) > data_end)
			return managed_interface ? XDP_DROP : XDP_PASS;
		protocol = vlan->h_vlan_encapsulated_proto;
		off += sizeof(*vlan);
	}
	if (protocol == bpf_htons(ETH_P_8021Q) ||
	    protocol == bpf_htons(ETH_P_8021AD))
		return managed_interface ? XDP_DROP : XDP_PASS;
	if (protocol == bpf_htons(ETH_P_IPV6))
		return faketcp_xdp_ipv6_policy(data, data_end, off,
						 xdp->ingress_ifindex, generation,
						 managed_interface);
	if (protocol != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	iph = data + off;
	if ((void *)(iph + 1) > data_end || iph->version != 4 || iph->ihl < 5)
		return managed_interface ? XDP_DROP : XDP_PASS;
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return XDP_PASS;
	fragment_offset = bpf_ntohs(iph->frag_off);
	if (fragment_offset & IP_OFFSET)
		return managed_interface ? XDP_DROP : XDP_PASS;
	ipv4_header_length = (__u32)iph->ihl * 4;
	if (data + off + ipv4_header_length > data_end)
		return managed_interface ? XDP_DROP : XDP_PASS;
	wire_ports = data + off + ipv4_header_length;
	if ((void *)(wire_ports + 1) > data_end)
		return managed_interface ? XDP_DROP : XDP_PASS;
	listener = faketcp_xdp_managed_port(xdp->ingress_ifindex,
						    bpf_ntohs(wire_ports->dest), generation);
	if (!listener)
		return XDP_PASS;
	// Native UDP to a FakeTCP port is a transport-bypass attempt. Decoded
	// packets do not re-enter XDP, so this cannot catch the valid TCP-to-UDP
	// result produced later by this program.
	if (iph->protocol == IPPROTO_UDP)
		return XDP_DROP;
	tcp = (struct tcphdr *)wire_ports;
	if ((void *)(tcp + 1) > data_end)
		return XDP_DROP;
	// The policy lookup deliberately precedes all unsupported-header checks.
	// A managed packet can only PASS after successful FakeTCP decoding.
	if ((fragment_offset & IP_MF) || iph->ihl != 5 || tcp->doff != 5)
		return XDP_DROP;
	if (listener->action != ACTION_REWRITE)
		return XDP_DROP;
	total_len = bpf_ntohs(iph->tot_len);
	if (total_len < sizeof(*iph) + sizeof(*tcp) || data + off + total_len > data_end)
		return XDP_DROP;
	tcp_len = total_len - sizeof(*iph);
	payload_len = tcp_len - sizeof(*tcp);
	flags = faketcp_tcp_flags(tcp);
	seq = bpf_ntohl(tcp->seq);
	// The current ring ABI does not carry the complete TCP packet, so
	// userspace cannot independently prove checksum and receive-window state.
	// Until the BPF validator capability is implemented, close controls must
	// never be emitted as session-deletion authority.
	if (flags & (FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return XDP_DROP;
	}
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
				   bpf_ntohl(tcp->ack_seq), payload_len, 0,
				   listener->wg_id);
		return XDP_DROP;
	}
	if (flags & (FAKETCP_FLAG_SYN | FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN)) {
		faketcp_emit_event(&key, faketcp_event_type(flags), flags, seq,
				   bpf_ntohl(tcp->ack_seq), payload_len, 0,
				   listener->wg_id);
		return XDP_DROP;
	}
	if (payload_len == 0 && flags == FAKETCP_FLAG_ACK) {
		// A userspace keepalive has no UDP image. Consume it before GRO and
		// refresh only the peer session's idle clock.
		session->last_seen_nanos = bpf_ktime_get_ns();
		return XDP_DROP;
	}
	if (!(flags & FAKETCP_FLAG_ACK) || payload_len < FAKETCP_HEADER_DELTA) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return XDP_DROP;
	}
	old_tcp = *tcp;
	if (bpf_xdp_load_bytes(xdp, off + total_len - FAKETCP_HEADER_DELTA,
			       tail, sizeof(tail)) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
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
	if (payload_len & 1) {
		sum = faketcp_rotation_checksum(tail, sum, 1);
		if (sum < 0)
			return XDP_DROP;
	}
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
	inc_faketcp_stat(FAKETCP_STAT_INGRESS_OK);
	return XDP_PASS;
}

#endif
