// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
#include <linux/tcp.h>
#endif
#include <linux/udp.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ABI_VERSION 10

#define FAMILY_ANY  0
#define FAMILY_IPV4 4
#define FAMILY_IPV6 6

#define ACTION_PASS    1
#define ACTION_DROP    2
#define ACTION_REWRITE 3

#define CONTROL_KEY_GLOBAL 0
#define UNDERLAY_WILDCARD 0

#define PARSER_AUTO     0
#define PARSER_ETHERNET 1
#define PARSER_L3       2

#define TRANSPORT_UDP     0
#define TRANSPORT_ICMP    1
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
#define TRANSPORT_FAKETCP 2
#endif

#define ICMP_ROLE_NONE   0
#define ICMP_ROLE_CLIENT 1
#define ICMP_ROLE_SERVER 2

#define ICMP_LISTENER_F_WILDCARD_ID (1U << 0)

#define CIPHER_MODE_NONE 0
#define CIPHER_MODE_XOR  1
#define CIPHER_F_PREFIX  (1U << 0)
#define XOR_ERR_KEY      -6

#define MAX_XOR_BYTES 2048
#define XOR_SEGMENT_BYTES 256
#define XOR_SEGMENT_COUNT (MAX_XOR_BYTES / XOR_SEGMENT_BYTES)
#define XOR_PROGRAM_BANKS 2
#define XOR_PROGRAM_COUNT (XOR_SEGMENT_COUNT * XOR_PROGRAM_BANKS)
#define XOR_STORE_CHUNK_SIZE 64
#define XOR_DIFF_CHUNK_SIZE 32
#define XOR_CSUM_NONE 0
#define XOR_CSUM_RECOMPUTE 1
#define XOR_CSUM_MANUAL 2
#define XOR_CONTEXT_MAGIC 0x584f0000U
#define XOR_CONTEXT_MAGIC_MASK 0xffff0000U
#define XOR_CONTEXT_TARGET_MASK 0x00000fffU
#define XOR_CONTEXT_MODE_SHIFT 12
#define XOR_CONTEXT_MODE_MASK 0x00003000U
#define XOR_CONTEXT_RESERVED_MASK 0x0000c000U
#define XOR_CONTEXT_F_FAKETCP (1U << 14)
#define XOR_CONTEXT_FORBIDDEN_MASK (1U << 15)

#define ICMP_ECHOREPLY 0
#define ICMP_ECHO      8
#define MAX_ICMP_CSUM_BYTES 256
#define ICMP_CSUM_CHUNK_SIZE 16

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif

#ifndef NEXTHDR_FRAGMENT
#define NEXTHDR_FRAGMENT 44
#endif

#ifndef NEXTHDR_HOP
#define NEXTHDR_HOP 0
#endif

#ifndef NEXTHDR_ROUTING
#define NEXTHDR_ROUTING 43
#endif

#ifndef NEXTHDR_DEST
#define NEXTHDR_DEST 60
#endif

#ifndef NEXTHDR_NONE
#define NEXTHDR_NONE 59
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define wg_le32_to_cpu(x) (x)
#define wg_cpu_to_le32(x) (x)
#else
#define wg_le32_to_cpu(x) __builtin_bswap32(x)
#define wg_cpu_to_le32(x) __builtin_bswap32(x)
#endif

#define PARSE_OK 0
#define PARSE_SHORT 1
#define PARSE_NOT_UDP 2
#define PARSE_FRAGMENT 3
#define PARSE_IPV6_EXT 4
#define PARSE_IPV4_FIRST_FRAGMENT 5
#define PARSE_IPV4_NON_FIRST_FRAGMENT 6
#define PARSE_IPV6_EXT_UDP 7
#define PARSE_IPV6_FRAGMENT_FIRST 8
#define PARSE_IPV6_FRAGMENT_NON_FIRST 9
#define PARSE_BAD_CSUM 10
#define PARSE_IPV6_EXT_TOO_DEEP 11

struct wg_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct wg_ipv6_opt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
};

struct wg_ipv6_frag_hdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 identification;
};

struct control_value {
	__u64 active_generation;
	__u32 abi_version;
	__u32 flags;
};

struct owner_value {
	__u32 version;
	__u32 flags;
	__u8 resource_digest[32];
	__u8 token[32];
};

struct profile_value {
	__u64 generation;
	__u32 standard_to_mixed[4];
	__u32 mixed_to_standard[4];
	__u32 policy_flags;
	__u32 pad;
};

struct profile_key {
	__u64 generation;
	__u32 profile_id;
	__u32 pad;
};

struct cipher_key {
	__u64 generation;
	__u32 cipher_id;
	__u32 pad;
};

struct cipher_value {
	__u64 generation;
	__u8 key[256];
	__u32 key_len;
	__u32 key_mask;
	__u32 max_bytes;
	__u32 flags;
	__u8 mode;
	__u8 pad[7];
};

struct managed_fwmark_key {
	__u64 generation;
	__u32 fwmark;
	__u32 underlay_index;
};

struct underlay_config_key {
	__u64 generation;
	__u32 underlay_index;
	__u32 pad;
};

struct underlay_config_value {
	__u64 generation;
	__u8 parser_mode;
	__u8 pad[7];
};

struct managed_fwmark_value {
	__u64 generation;
	__u8 action_on_miss;
	__u8 pad[7];
};

struct egress_rule_key {
	__u64 generation;
	__u32 fwmark;
	__u32 underlay_index;
	__u16 source_port;
	__u8 family;
	__u8 pad[5];
};

struct egress_rule_value {
	__u64 generation;
	__u32 profile_id;
	__u32 wg_id;
	__u32 cipher_id;
	__u16 icmp_id;
	__u8 action;
	__u8 transport_mode;
	__u8 icmp_role;
	__u8 pad[7];
};

struct ingress_listener_key {
	__u64 generation;
	__u32 underlay_index;
	__u16 destination_port;
	__u8 family;
	__u8 pad;
};

struct ingress_listener_value {
	__u64 generation;
	__u32 profile_id;
	__u32 wg_id;
	__u32 cipher_id;
	__u8 action;
	__u8 transport_mode;
	__u8 pad[2];
};

struct icmp_listener_key {
	__u64 generation;
	__u32 underlay_index;
	__u16 icmp_id;
	__u8 family;
	__u8 icmp_type;
};

struct icmp_listener_value {
	__u64 generation;
	__u32 profile_id;
	__u32 wg_id;
	__u16 listen_port;
	__u8 action;
	__u8 role;
	__u32 flags;
};

struct icmp_seq_key {
	__u64 generation;
	__u32 remote_ipv4;
	__u32 underlay_index;
	__u32 wg_id;
	__u16 icmp_id;
	__u16 pad;
};

struct icmp_seq_value {
	__u64 generation;
	__u16 sequence;
	__u16 pad[3];
};

struct packet_info {
	__u32 family;
	__u32 ip_off;
	__u32 udp_off;
	__u32 payload_off;
	__u32 payload_len;
	__u16 src_port;
	__u16 dst_port;
	__u8 ipv4_udp_csum_zero;
};

struct xor_context {
	__u64 generation;
	__u64 admission_nonce;
	__u32 cipher_id;
	__u32 payload_off;
	__u32 target;
	__u8 checksum_mode;
	__u8 continue_faketcp;
};

struct xor_ingress_metadata {
	__u32 wire;
	__u32 target;
};

struct icmp_packet_info {
	__u32 family;
	__u32 ip_off;
	__u32 icmp_off;
	__u32 payload_off;
	__u32 payload_len;
	__u32 src_ipv4;
	__u16 id;
	__u16 sequence;
	__u8 type;
	__u8 code;
};

struct wg_icmphdr {
	__u8 type;
	__u8 code;
	__be16 checksum;
	__be16 id;
	__be16 sequence;
};

enum stat_id {
	STAT_EGRESS_REWRITE_OK = 0,
	STAT_EGRESS_RULE_MISS,
	STAT_EGRESS_BAD_TYPE,
	STAT_EGRESS_BAD_LENGTH,
	STAT_EGRESS_FRAGMENT,
	STAT_EGRESS_IPV6_EXT,
	STAT_INGRESS_REWRITE_OK,
	STAT_INGRESS_RULE_MISS,
	STAT_INGRESS_BAD_TYPE,
	STAT_INGRESS_BAD_LENGTH,
	STAT_INGRESS_FRAGMENT,
	STAT_INGRESS_IPV6_EXT,
	STAT_CHECKSUM_ERROR,
	STAT_SKB_LOAD_ERROR,
	STAT_SKB_STORE_ERROR,
	STAT_EGRESS_GSO_SEEN,
	STAT_EGRESS_GSO_MANAGED_SEEN,
	STAT_EGRESS_GSO_REWRITE_OK,
	STAT_INGRESS_GSO_SEEN,
	STAT_INGRESS_GSO_LISTENER_HIT,
	STAT_INGRESS_GSO_REWRITE_OK,
	STAT_ICMP_EGRESS_REWRITE_OK,
	STAT_ICMP_INGRESS_REWRITE_OK,
	STAT_ICMP_CHECKSUM_ERROR,
	STAT_XOR_EGRESS_OK,
	STAT_XOR_INGRESS_OK,
	STAT_XOR_KEY_MISSING,
	STAT_XOR_LEN_OVERFLOW,
	STAT_XOR_BAD_TYPE_AFTER_DECRYPT,
	STAT_XOR_LOAD_ERROR,
	STAT_XOR_STORE_ERROR,
	STAT_XOR_CSUM_ERROR,
	STAT_INGRESS_BAD_CHECKSUM,
	STAT_EGRESS_BAD_CHECKSUM,
	STAT_XOR_EGRESS_DISPATCH_ERROR,
	STAT_XOR_INGRESS_DISPATCH_ERROR,
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct control_value);
} control_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct owner_value);
} owner_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct profile_key);
	__type(value, struct profile_value);
} profile_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct cipher_key);
	__type(value, struct cipher_value);
} cipher_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct underlay_config_key);
	__type(value, struct underlay_config_value);
} underlay_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct managed_fwmark_key);
	__type(value, struct managed_fwmark_value);
} managed_fwmark_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct egress_rule_key);
	__type(value, struct egress_rule_value);
} egress_rule_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct ingress_listener_key);
	__type(value, struct ingress_listener_value);
} ingress_listener_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct icmp_listener_key);
	__type(value, struct icmp_listener_value);
} icmp_listener_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, struct icmp_seq_key);
	__type(value, struct icmp_seq_value);
} icmp_seq_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, XOR_PROGRAM_COUNT);
	__type(key, __u32);
	__type(value, __u32);
} xor_egress_programs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, XOR_PROGRAM_COUNT);
	__type(key, __u32);
	__type(value, __u32);
} xor_ingress_programs SEC(".maps");

static __always_inline void inc_stat(__u32 key)
{
	__u64 *value;

	value = bpf_map_lookup_elem(&stats_map, &key);
	if (value)
		*value += 1;
}

static __always_inline struct control_value *active_control(void)
{
	__u32 key = CONTROL_KEY_GLOBAL;
	return bpf_map_lookup_elem(&control_map, &key);
}

static __always_inline int active_generation(__u64 *generation)
{
	struct control_value *control = active_control();

	if (!control || control->abi_version != ABI_VERSION || control->active_generation == 0)
		return 0;
	*generation = control->active_generation;
	return 1;
}

static __always_inline __u8 lookup_parser_mode(__u32 ifindex, __u64 generation)
{
	struct underlay_config_key key = {
		.generation = generation,
		.underlay_index = ifindex,
	};
	struct underlay_config_value *value;

	value = bpf_map_lookup_elem(&underlay_config_map, &key);
	if (value && value->generation == generation)
		return value->parser_mode;
	key.underlay_index = UNDERLAY_WILDCARD;
	value = bpf_map_lookup_elem(&underlay_config_map, &key);
	if (value && value->generation == generation)
		return value->parser_mode;
	return PARSER_AUTO;
}

static __always_inline int parse_l3_link(struct __sk_buff *skb, __u64 *off, __u16 *proto)
{
	__u16 skb_proto = skb->protocol;

	if (skb_proto == bpf_htons(ETH_P_IP) || skb_proto == bpf_htons(ETH_P_IPV6)) {
		*off = 0;
		*proto = skb_proto;
		return PARSE_OK;
	}
	return PARSE_NOT_UDP;
}

static __always_inline int parse_ethernet_link(void *data, void *data_end, __u64 *off,
					       __u16 *proto)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) <= data_end) {
		*off = sizeof(*eth);
		*proto = eth->h_proto;

		if (*proto == bpf_htons(ETH_P_IP) || *proto == bpf_htons(ETH_P_IPV6) ||
		    *proto == bpf_htons(ETH_P_8021Q) || *proto == bpf_htons(ETH_P_8021AD)) {
#pragma unroll
			for (int i = 0; i < 2; i++) {
				struct wg_vlan_hdr *vh;

				if (*proto != bpf_htons(ETH_P_8021Q) &&
				    *proto != bpf_htons(ETH_P_8021AD))
					break;
				vh = data + *off;
				if ((void *)(vh + 1) > data_end)
					return PARSE_SHORT;
				*proto = vh->h_vlan_encapsulated_proto;
				*off += sizeof(*vh);
			}
			return PARSE_OK;
		}
	}
	return PARSE_NOT_UDP;
}

static __always_inline int parse_link(struct __sk_buff *skb, void *data, void *data_end,
				      __u64 *off, __u16 *proto, __u64 generation)
{
	__u8 parser_mode = lookup_parser_mode(skb->ifindex, generation);
	int rc;

	if (parser_mode == PARSER_L3)
		return parse_l3_link(skb, off, proto);
	if (parser_mode == PARSER_ETHERNET)
		return parse_ethernet_link(data, data_end, off, proto);

	rc = parse_ethernet_link(data, data_end, off, proto);
	if (rc == PARSE_OK)
		return rc;
	return parse_l3_link(skb, off, proto);
}

static __always_inline int parse_udp_at(void *data, void *data_end, struct packet_info *info,
					__u32 family, __u32 ip_off, __u32 udp_off,
					int require_payload_word)
{
	struct udphdr *udp = data + udp_off;
	__u16 udp_len;

	if ((void *)(udp + 1) > data_end)
		return PARSE_SHORT;
	udp_len = bpf_ntohs(udp->len);
	if (udp_len < sizeof(*udp))
		return PARSE_SHORT;
	info->family = family;
	info->ip_off = ip_off;
	info->udp_off = udp_off;
	info->payload_off = udp_off + sizeof(*udp);
	info->payload_len = udp_len - sizeof(*udp);
	info->src_port = bpf_ntohs(udp->source);
	info->dst_port = bpf_ntohs(udp->dest);
	info->ipv4_udp_csum_zero = family == FAMILY_IPV4 && udp->check == 0;
	if (family == FAMILY_IPV6 && udp->check == 0)
		return PARSE_BAD_CSUM;
	if (require_payload_word && info->payload_len < 4)
		return PARSE_SHORT;
	return PARSE_OK;
}

static __always_inline int is_ipv6_option_header(__u8 nexthdr)
{
	return nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING || nexthdr == NEXTHDR_DEST;
}

static __always_inline int parse_packet(struct __sk_buff *skb, struct packet_info *info,
					__u64 generation)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u64 off = 0;
	__u16 proto = 0;
	int rc;

	__builtin_memset(info, 0, sizeof(*info));
	rc = parse_link(skb, data, data_end, &off, &proto, generation);
	if (rc != PARSE_OK)
		return rc;

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + off;
		__u32 ihl;
		__u16 frag;
		__u16 frag_off;

		if ((void *)(iph + 1) > data_end)
			return PARSE_SHORT;
		ihl = iph->ihl * 4;
		if (ihl < sizeof(*iph) || data + off + ihl > data_end)
			return PARSE_SHORT;
		if (iph->protocol != IPPROTO_UDP)
			return PARSE_NOT_UDP;
		frag = bpf_ntohs(iph->frag_off);
		frag_off = frag & IP_OFFSET;
		if (frag_off != 0)
			return PARSE_IPV4_NON_FIRST_FRAGMENT;
		rc = parse_udp_at(data, data_end, info, FAMILY_IPV4, off, off + ihl, !(frag & IP_MF));
		if (rc != PARSE_OK)
			return rc;
		if (frag & IP_MF)
			return PARSE_IPV4_FIRST_FRAGMENT;
		return rc;
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + off;
		__u32 hdr_off = off + sizeof(*ip6h);
		__u8 nexthdr;
		__u8 saw_ext = 0;
		__u8 saw_frag = 0;

		if ((void *)(ip6h + 1) > data_end)
			return PARSE_SHORT;
		nexthdr = ip6h->nexthdr;

#pragma unroll
		for (int i = 0; i < 8; i++) {
			if (nexthdr == IPPROTO_UDP) {
				rc = parse_udp_at(data, data_end, info, FAMILY_IPV6, off, hdr_off,
						  !(saw_ext || saw_frag));
				if (rc != PARSE_OK)
					return rc;
				if (saw_frag)
					return PARSE_IPV6_FRAGMENT_FIRST;
				if (saw_ext)
					return PARSE_IPV6_EXT_UDP;
				return PARSE_OK;
			}
			if (nexthdr == NEXTHDR_FRAGMENT) {
				struct wg_ipv6_frag_hdr *fh = data + hdr_off;
				__u16 frag;

				if ((void *)(fh + 1) > data_end)
					return PARSE_SHORT;
				frag = bpf_ntohs(fh->frag_off);
				if (frag & 0xfff8)
					return PARSE_IPV6_FRAGMENT_NON_FIRST;
				saw_frag = 1;
				nexthdr = fh->nexthdr;
				hdr_off += sizeof(*fh);
				continue;
			}
			if (is_ipv6_option_header(nexthdr)) {
				struct wg_ipv6_opt_hdr *oh = data + hdr_off;
				__u32 len;

				if ((void *)(oh + 1) > data_end)
					return PARSE_SHORT;
				len = ((__u32)oh->hdrlen + 1) * 8;
				if (len < 8 || hdr_off + len < hdr_off)
					return PARSE_IPV6_EXT_TOO_DEEP;
				saw_ext = 1;
				nexthdr = oh->nexthdr;
				hdr_off += len;
				if (hdr_off > off + sizeof(*ip6h) + 512)
					return PARSE_IPV6_EXT_TOO_DEEP;
				continue;
			}
			if (nexthdr == NEXTHDR_NONE)
				return PARSE_NOT_UDP;
			return PARSE_IPV6_EXT;
		}
		return PARSE_IPV6_EXT_TOO_DEEP;
	}

	return PARSE_NOT_UDP;
}

static __always_inline int parse_icmp_packet(struct __sk_buff *skb,
					     struct icmp_packet_info *info,
					     __u64 generation)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u64 off = 0;
	__u16 proto = 0;
	struct iphdr *iph;
	struct wg_icmphdr *icmp;
	__u32 ihl;
	__u16 frag;
	__u16 frag_off;
	__u16 total_len;
	int rc;

	__builtin_memset(info, 0, sizeof(*info));
	rc = parse_link(skb, data, data_end, &off, &proto, generation);
	if (rc != PARSE_OK)
		return rc;
	if (proto != bpf_htons(ETH_P_IP))
		return PARSE_NOT_UDP;
	iph = data + off;
	if ((void *)(iph + 1) > data_end)
		return PARSE_SHORT;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph) || data + off + ihl > data_end)
		return PARSE_SHORT;
	if (iph->protocol != IPPROTO_ICMP)
		return PARSE_NOT_UDP;
	frag = bpf_ntohs(iph->frag_off);
	frag_off = frag & IP_OFFSET;
	if (frag_off != 0)
		return PARSE_IPV4_NON_FIRST_FRAGMENT;
	if (frag & IP_MF)
		return PARSE_IPV4_FIRST_FRAGMENT;
	total_len = bpf_ntohs(iph->tot_len);
	if (total_len < ihl + sizeof(*icmp))
		return PARSE_SHORT;
	icmp = data + off + ihl;
	if ((void *)(icmp + 1) > data_end)
		return PARSE_SHORT;
	info->family = FAMILY_IPV4;
	info->ip_off = off;
	info->icmp_off = off + ihl;
	info->payload_off = info->icmp_off + sizeof(*icmp);
	info->payload_len = total_len - ihl - sizeof(*icmp);
	info->src_ipv4 = iph->saddr;
	info->type = icmp->type;
	info->code = icmp->code;
	info->id = bpf_ntohs(icmp->id);
	info->sequence = bpf_ntohs(icmp->sequence);
	return PARSE_OK;
}

static __always_inline __u16 fold_csum(__u64 sum)
{
#pragma unroll
	for (int i = 0; i < 4; i++)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~((__u16)sum);
}

static __always_inline void csum_add_word(__u64 *sum, __u16 word)
{
	*sum += word;
}

static __always_inline void csum_sub_word(__u64 *sum, __u16 word)
{
	*sum += (~word) & 0xffff;
}

static __always_inline void csum_sub_ipv4(__u64 *sum, __be32 addr)
{
	__u32 host = bpf_ntohl(addr);

	csum_sub_word(sum, host >> 16);
	csum_sub_word(sum, host & 0xffff);
}

static __always_inline void csum_add_type_word(__u64 *sum, __u32 wire)
{
	__u32 host = bpf_ntohl(wire);

	csum_add_word(sum, host >> 16);
	csum_add_word(sum, host & 0xffff);
}

static __always_inline void csum_sub_type_word(__u64 *sum, __u32 wire)
{
	__u32 host = bpf_ntohl(wire);

	csum_sub_word(sum, host >> 16);
	csum_sub_word(sum, host & 0xffff);
}

static __always_inline int compute_icmp_checksum_small(struct __sk_buff *skb,
						       __u32 off,
						       __u32 len,
						       __u16 *out)
{
	__u8 chunk[ICMP_CSUM_CHUNK_SIZE] = {};
	__u32 word = 0;
	__u32 processed = 0;
	__s64 sum = 0;

	if (len == 0 || len > MAX_ICMP_CSUM_BYTES || (len & 3))
		return -1;

#pragma unroll
	for (int i = 0; i < MAX_ICMP_CSUM_BYTES / ICMP_CSUM_CHUNK_SIZE; i++) {
		if (processed + ICMP_CSUM_CHUNK_SIZE > len)
			break;
		if (bpf_skb_load_bytes(skb, off + processed, chunk, sizeof(chunk)) < 0)
			return -1;
		sum = bpf_csum_diff(0, 0, (__be32 *)chunk, sizeof(chunk), (__wsum)sum);
		if (sum < 0)
			return -1;
		processed += ICMP_CSUM_CHUNK_SIZE;
	}

#pragma unroll
	for (int i = 0; i < (ICMP_CSUM_CHUNK_SIZE / sizeof(word)) - 1; i++) {
		if (processed + sizeof(word) > len)
			break;
		if (bpf_skb_load_bytes(skb, off + processed, &word, sizeof(word)) < 0)
			return -1;
		sum = bpf_csum_diff(0, 0, (__be32 *)&word, sizeof(word), (__wsum)sum);
		if (sum < 0)
			return -1;
		processed += sizeof(word);
	}
	if (processed != len)
		return -1;

	*out = fold_csum(sum);
	return 0;
}

static __always_inline int derive_icmp_checksum_from_udp(struct __sk_buff *skb,
							 struct packet_info *info,
							 __u8 icmp_type,
							 __u16 icmp_id,
							 __u16 icmp_sequence,
							 __u32 old_wire,
							 __u32 new_wire,
							 __u16 *out)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct udphdr *udp = data + info->udp_off;
	__u16 udp_check;
	__u16 udp_len;
	__u64 sum;

	if ((void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end)
		return -1;
	udp_check = bpf_ntohs(udp->check);
	if (udp_check == 0)
		return -1;
	udp_len = bpf_ntohs(udp->len);
	sum = (~udp_check) & 0xffff;

	csum_sub_ipv4(&sum, iph->saddr);
	csum_sub_ipv4(&sum, iph->daddr);
	csum_sub_word(&sum, IPPROTO_UDP);
	csum_sub_word(&sum, udp_len);
	csum_sub_word(&sum, info->src_port);
	csum_sub_word(&sum, info->dst_port);
	csum_sub_word(&sum, udp_len);
	csum_sub_type_word(&sum, old_wire);

	csum_add_word(&sum, ((__u16)icmp_type) << 8);
	csum_add_word(&sum, icmp_id);
	csum_add_word(&sum, icmp_sequence);
	csum_add_type_word(&sum, new_wire);

	*out = bpf_htons(fold_csum(sum));
	return 0;
}

static __always_inline __u16 lookup_icmp_sequence(struct __sk_buff *skb,
						  struct packet_info *info,
						  struct egress_rule_value *rule,
						  __u16 icmp_id)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct icmp_seq_key key = {
		.generation = rule->generation,
		.underlay_index = skb->ifindex,
		.wg_id = rule->wg_id,
		.icmp_id = icmp_id,
	};
	struct icmp_seq_value *value;

	if ((void *)(iph + 1) > data_end)
		return 0;
	key.remote_ipv4 = iph->daddr;
	value = bpf_map_lookup_elem(&icmp_seq_map, &key);
	if (!value || value->generation != rule->generation)
		return 0;
	return value->sequence;
}

static __always_inline void remember_icmp_sequence(struct __sk_buff *skb,
						   struct icmp_packet_info *info,
						   struct icmp_listener_value *listener)
{
	struct icmp_seq_key key = {
		.generation = listener->generation,
		.remote_ipv4 = info->src_ipv4,
		.underlay_index = skb->ifindex,
		.wg_id = listener->wg_id,
		.icmp_id = info->id,
	};
	struct icmp_seq_value value = {
		.generation = listener->generation,
		.sequence = info->sequence,
	};

	bpf_map_update_elem(&icmp_seq_map, &key, &value, BPF_ANY);
}

static __always_inline int kind_from_standard(__u32 type_word)
{
	switch (type_word) {
	case 1:
		return 0;
	case 2:
		return 1;
	case 3:
		return 2;
	case 4:
		return 3;
	default:
		return -1;
	}
}

static __always_inline int validate_len(int kind, __u32 payload_len)
{
	if (kind == 0)
		return payload_len == 148;
	if (kind == 1)
		return payload_len == 92;
	if (kind == 2)
		return payload_len == 64;
	if (kind == 3)
		return payload_len >= 32;
	return 0;
}

static __always_inline int update_type_word(struct __sk_buff *skb, struct packet_info *info,
					    __u32 old_wire, __u32 new_wire,
					    int recompute_checksum)
{
	__u64 store_flags = BPF_F_INVALIDATE_HASH;
	__u64 csum_flags = BPF_F_MARK_MANGLED_0;
	__u32 csum_off = info->udp_off + offsetof(struct udphdr, check);
	__s64 diff;

	if (recompute_checksum && info->family != FAMILY_IPV6) {
		if (!(info->family == FAMILY_IPV4 && info->ipv4_udp_csum_zero))
			store_flags |= BPF_F_RECOMPUTE_CSUM;
	} else if (!(info->family == FAMILY_IPV4 && info->ipv4_udp_csum_zero)) {
		diff = bpf_csum_diff((__be32 *)&old_wire, sizeof(old_wire),
				     (__be32 *)&new_wire, sizeof(new_wire), 0);
		if (diff < 0)
			return -1;
		if (bpf_l4_csum_replace(skb, csum_off, 0, diff, csum_flags) < 0)
			return -1;
	}
	if (bpf_skb_store_bytes(skb, info->payload_off, &new_wire, sizeof(new_wire),
				store_flags) < 0)
		return -2;
	return 0;
}

static __always_inline struct cipher_value *lookup_cipher(__u32 cipher_id, __u64 generation)
{
	struct cipher_key key = {
		.generation = generation,
		.cipher_id = cipher_id,
	};
	struct cipher_value *cipher;

	if (cipher_id == 0)
		return 0;
	cipher = bpf_map_lookup_elem(&cipher_map, &key);
	if (cipher && cipher->generation == generation && cipher->mode == CIPHER_MODE_XOR)
		return cipher;
	return 0;
}

static __always_inline __u8 xor_key_byte(struct cipher_value *cipher, __u32 off)
{
	return cipher->key[off & 255];
}

static __always_inline __u32 xor_type_word_copy(__u32 wire, struct cipher_value *cipher)
{
	__u8 *bytes = (__u8 *)&wire;

#pragma unroll
	for (int i = 0; i < 4; i++)
		bytes[i] ^= xor_key_byte(cipher, i);
	return wire;
}

static __always_inline int xor_payload_target(struct packet_info *info,
					      struct cipher_value *cipher,
					      __u32 *target)
{
	__u32 value = info->payload_len;

	if (!cipher)
		return -1;
	if (cipher->max_bytes == 0 || cipher->max_bytes > MAX_XOR_BYTES)
		return -4;
	if (value > cipher->max_bytes) {
		if (cipher->flags & CIPHER_F_PREFIX)
			value = cipher->max_bytes;
		else
			return -4;
	}
	if (value == 0 || value > MAX_XOR_BYTES)
		return -4;
	*target = value;
	return 0;
}

static __always_inline int xor_segment_bounds(__u32 target,
					      __u32 segment,
					      __u32 start_offset,
					      __u32 *processed,
					      __u32 *segment_target,
					      __u8 *has_more)
{
	__u32 segment_start;
	__u32 segment_end;

	if (segment >= XOR_SEGMENT_COUNT)
		return -4;
	segment_start = segment * XOR_SEGMENT_BYTES;
	segment_end = segment_start + XOR_SEGMENT_BYTES;
	if (target <= segment_start)
		return -4;
	*processed = segment_start;
	if (*processed < start_offset)
		*processed = start_offset;
	if (target < *processed)
		return -4;
	if (target < segment_end)
		*segment_target = target;
	else
		*segment_target = segment_end;
	*has_more = target > segment_end;
	return 0;
}

static __always_inline int xor_load_partial_word(struct __sk_buff *skb,
						  __u32 off,
						  __u32 len,
						  __u32 *word)
{
	if (len == 1)
		return bpf_skb_load_bytes(skb, off, word, 1) < 0 ? -5 : 0;
	if (len == 2)
		return bpf_skb_load_bytes(skb, off, word, 2) < 0 ? -5 : 0;
	if (len == 3)
		return bpf_skb_load_bytes(skb, off, word, 3) < 0 ? -5 : 0;
	return -4;
}

static __always_inline int xor_store_partial_word(struct __sk_buff *skb,
						   __u32 off,
						   __u32 len,
						   __u32 *word,
						   __u64 flags)
{
	if (len == 1)
		return bpf_skb_store_bytes(skb, off, word, 1, flags) < 0 ? -2 : 0;
	if (len == 2)
		return bpf_skb_store_bytes(skb, off, word, 2, flags) < 0 ? -2 : 0;
	if (len == 3)
		return bpf_skb_store_bytes(skb, off, word, 3, flags) < 0 ? -2 : 0;
	return -4;
}

static __always_inline void xor_partial_word(struct cipher_value *cipher,
					      __u32 processed,
					      __u32 len,
					      __u32 old_word,
					      __u32 *new_word)
{
	__u8 *old_bytes = (__u8 *)&old_word;
	__u8 *new_bytes = (__u8 *)new_word;

	*new_word = 0;
	new_bytes[0] = old_bytes[0] ^ xor_key_byte(cipher, processed);
	if (len > 1)
		new_bytes[1] = old_bytes[1] ^ xor_key_byte(cipher, processed + 1);
	if (len > 2)
		new_bytes[2] = old_bytes[2] ^ xor_key_byte(cipher, processed + 2);
}

static __always_inline int xor_segment_store_only(struct __sk_buff *skb,
						  struct cipher_value *cipher,
						  __u32 payload_off,
						  __u32 target,
						  __u32 segment,
						  __u32 start_offset,
						  __u64 store_flags)
{
	__u32 processed = 0;
	__u32 segment_target = 0;
	__u8 has_more = 0;
	__u8 old_chunk[XOR_STORE_CHUNK_SIZE] = {};
	__u8 new_chunk[XOR_STORE_CHUNK_SIZE] = {};
	__u32 old_word = 0;
	__u32 new_word = 0;
	__u32 tail_len;
	int rc;

	rc = xor_segment_bounds(target, segment, start_offset, &processed,
				&segment_target, &has_more);
	if (rc < 0)
		return rc;
	if (processed == segment_target)
		return has_more ? 1 : 0;

#pragma unroll
	for (int i = 0; i < XOR_SEGMENT_BYTES / XOR_STORE_CHUNK_SIZE; i++) {
		if (processed + XOR_STORE_CHUNK_SIZE > segment_target)
			break;
		if (bpf_skb_load_bytes(skb, payload_off + processed, old_chunk,
				       sizeof(old_chunk)) < 0)
			return -5;
#pragma unroll
		for (int j = 0; j < XOR_STORE_CHUNK_SIZE; j++)
			new_chunk[j] = old_chunk[j] ^ xor_key_byte(cipher, processed + j);
		if (bpf_skb_store_bytes(skb, payload_off + processed, new_chunk,
					sizeof(new_chunk), store_flags) < 0)
			return -2;
		processed += XOR_STORE_CHUNK_SIZE;
	}

#pragma unroll
	for (int i = 0; i < (XOR_STORE_CHUNK_SIZE / 4) - 1; i++) {
		__u8 *old_bytes = (__u8 *)&old_word;
		__u8 *new_bytes = (__u8 *)&new_word;

		if (processed + 4 > segment_target)
			break;
		if (bpf_skb_load_bytes(skb, payload_off + processed, &old_word,
				       sizeof(old_word)) < 0)
			return -5;
		new_word = old_word;
#pragma unroll
		for (int j = 0; j < 4; j++)
			new_bytes[j] = old_bytes[j] ^ xor_key_byte(cipher, processed + j);
		if (bpf_skb_store_bytes(skb, payload_off + processed, &new_word,
					sizeof(new_word), store_flags) < 0)
			return -2;
		processed += 4;
	}
	if (processed < segment_target) {
		tail_len = segment_target - processed;
		old_word = 0;
		rc = xor_load_partial_word(skb, payload_off + processed, tail_len,
					   &old_word);
		if (rc < 0)
			return rc;
		xor_partial_word(cipher, processed, tail_len, old_word, &new_word);
		rc = xor_store_partial_word(skb, payload_off + processed, tail_len,
					    &new_word, store_flags);
		if (rc < 0)
			return rc;
		processed += tail_len;
	}
	if (processed != segment_target)
		return -4;
	return has_more ? 1 : 0;
}

static __always_inline int xor_segment_manual_diff(struct __sk_buff *skb,
						   struct cipher_value *cipher,
						   __u32 payload_off,
						   __u32 target,
						   __u32 segment,
						   __u32 start_offset)
{
	__u32 processed = 0;
	__u32 segment_target = 0;
	__u8 has_more = 0;
	__u8 old_chunk[XOR_DIFF_CHUNK_SIZE] = {};
	__u8 new_chunk[XOR_DIFF_CHUNK_SIZE] = {};
	__u32 old_word = 0;
	__u32 new_word = 0;
	__u32 tail_len;
	__s64 csum_diff = 0;
	__s64 diff;
	int rc;

	rc = xor_segment_bounds(target, segment, start_offset, &processed,
				&segment_target, &has_more);
	if (rc < 0)
		return rc;
	if (processed == segment_target)
		return has_more ? 1 : 0;

#pragma unroll
	for (int i = 0; i < XOR_SEGMENT_BYTES / XOR_DIFF_CHUNK_SIZE; i++) {
		if (processed + XOR_DIFF_CHUNK_SIZE > segment_target)
			break;
		if (bpf_skb_load_bytes(skb, payload_off + processed, old_chunk,
				       sizeof(old_chunk)) < 0)
			return -5;
#pragma unroll
		for (int j = 0; j < XOR_DIFF_CHUNK_SIZE; j++)
			new_chunk[j] = old_chunk[j] ^ xor_key_byte(cipher, processed + j);
		diff = bpf_csum_diff((__be32 *)old_chunk, sizeof(old_chunk),
				     (__be32 *)new_chunk, sizeof(new_chunk),
				     (__wsum)csum_diff);
		if (diff < 0)
			return -3;
		csum_diff = diff;
		if (bpf_skb_store_bytes(skb, payload_off + processed, new_chunk,
					sizeof(new_chunk), BPF_F_INVALIDATE_HASH) < 0)
			return -2;
		processed += XOR_DIFF_CHUNK_SIZE;
	}

#pragma unroll
	for (int i = 0; i < (XOR_DIFF_CHUNK_SIZE / 4) - 1; i++) {
		__u8 *old_bytes = (__u8 *)&old_word;
		__u8 *new_bytes = (__u8 *)&new_word;

		if (processed + 4 > segment_target)
			break;
		if (bpf_skb_load_bytes(skb, payload_off + processed, &old_word,
				       sizeof(old_word)) < 0)
			return -5;
		new_word = old_word;
#pragma unroll
		for (int j = 0; j < 4; j++)
			new_bytes[j] = old_bytes[j] ^ xor_key_byte(cipher, processed + j);
		diff = bpf_csum_diff((__be32 *)&old_word, sizeof(old_word),
				     (__be32 *)&new_word, sizeof(new_word),
				     (__wsum)csum_diff);
		if (diff < 0)
			return -3;
		csum_diff = diff;
		if (bpf_skb_store_bytes(skb, payload_off + processed, &new_word,
					sizeof(new_word), BPF_F_INVALIDATE_HASH) < 0)
			return -2;
		processed += 4;
	}
	if (processed < segment_target) {
		tail_len = segment_target - processed;
		old_word = 0;
		rc = xor_load_partial_word(skb, payload_off + processed, tail_len,
					   &old_word);
		if (rc < 0)
			return rc;
		xor_partial_word(cipher, processed, tail_len, old_word, &new_word);
		/*
		 * The UDP payload starts on a four-byte checksum boundary and all
		 * preceding chunks are multiples of four. Zero-padding this final
		 * word therefore matches Internet-checksum padding while avoiding
		 * any read or write beyond the UDP payload.
		 */
		diff = bpf_csum_diff((__be32 *)&old_word, sizeof(old_word),
				     (__be32 *)&new_word, sizeof(new_word),
				     (__wsum)csum_diff);
		if (diff < 0)
			return -3;
		csum_diff = diff;
		rc = xor_store_partial_word(skb, payload_off + processed, tail_len,
					    &new_word, BPF_F_INVALIDATE_HASH);
		if (rc < 0)
			return rc;
		processed += tail_len;
	}
	if (processed != segment_target)
		return -4;
	if (bpf_l4_csum_replace(skb, payload_off - sizeof(struct udphdr) +
				offsetof(struct udphdr, check),
				0, csum_diff, BPF_F_MARK_MANGLED_0) < 0)
		return -3;
	return has_more ? 1 : 0;
}

static __noinline int load_xor_ingress_metadata(struct packet_info *info,
						 __u32 wire,
						 __u32 cipher_id,
						 __u64 generation,
						 struct xor_ingress_metadata *metadata)
{
	struct cipher_value *cipher;
	int rc;

	if (info->payload_off < sizeof(struct udphdr))
		return -4;
	cipher = lookup_cipher(cipher_id, generation);
	if (!cipher)
		return XOR_ERR_KEY;
	rc = xor_payload_target(info, cipher, &metadata->target);
	if (rc < 0)
		return rc;
	metadata->wire = xor_type_word_copy(wire, cipher);
	return 0;
}

static __always_inline int update_ipv4_protocol(struct __sk_buff *skb, __u32 ip_off,
						__u8 old_proto, __u8 new_proto)
{
	__u8 proto = new_proto;
	__u32 csum_off = ip_off + offsetof(struct iphdr, check);
	__u32 proto_off = ip_off + offsetof(struct iphdr, protocol);

	if (bpf_l3_csum_replace(skb, csum_off, bpf_htons(old_proto),
				bpf_htons(new_proto), 2) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, proto_off, &proto, sizeof(proto),
				BPF_F_INVALIDATE_HASH) < 0)
		return -2;
	return 0;
}

static __always_inline int rewrite_udp_to_icmp(struct __sk_buff *skb,
					       struct packet_info *info,
					       struct egress_rule_value *rule,
					       __u32 old_wire,
					       __u32 new_wire)
{
	struct wg_icmphdr icmp = {};
	__u16 checksum = 0;
	__u16 icmp_id = rule->icmp_id;
	__u32 icmp_len = info->payload_len + sizeof(icmp);
	__u16 icmp_sequence = 0;
	__u8 icmp_type = ICMP_ECHO;
	int rc;
	int small_checksum = icmp_len <= MAX_ICMP_CSUM_BYTES;

	if (info->family != FAMILY_IPV4)
		return -1;
	if (rule->icmp_role == ICMP_ROLE_SERVER) {
		icmp_type = ICMP_ECHOREPLY;
		if (info->dst_port != 0)
			icmp_id = info->dst_port;
		icmp_sequence = lookup_icmp_sequence(skb, info, rule, icmp_id);
	}
	icmp.type = icmp_type;
	icmp.code = 0;
	icmp.checksum = 0;
	icmp.id = bpf_htons(icmp_id);
	icmp.sequence = bpf_htons(icmp_sequence);

	if (!small_checksum) {
		if (derive_icmp_checksum_from_udp(skb, info, icmp_type, icmp_id,
						  icmp_sequence, old_wire, new_wire,
						  &checksum) < 0)
			return -3;
		icmp.checksum = checksum;
	}
	if (bpf_skb_store_bytes(skb, info->payload_off, &new_wire, sizeof(new_wire),
				BPF_F_INVALIDATE_HASH) < 0)
		return -2;
	if (bpf_skb_store_bytes(skb, info->udp_off, &icmp, sizeof(icmp),
				BPF_F_INVALIDATE_HASH) < 0)
		return -2;
	rc = update_ipv4_protocol(skb, info->ip_off, IPPROTO_UDP, IPPROTO_ICMP);
	if (rc < 0)
		return rc == -1 ? -3 : rc;
	if (small_checksum) {
		if (compute_icmp_checksum_small(skb, info->udp_off, icmp_len, &checksum) < 0)
			return -3;
		if (bpf_skb_store_bytes(skb,
					info->udp_off + offsetof(struct wg_icmphdr, checksum),
					&checksum, sizeof(checksum), BPF_F_INVALIDATE_HASH) < 0)
			return -2;
	}
	return 0;
}

static __always_inline int rewrite_icmp_to_udp(struct __sk_buff *skb,
					       struct icmp_packet_info *info,
					       struct icmp_listener_value *listener,
					       __u32 new_wire)
{
	struct udphdr udp = {};
	__u16 source_port = info->id;
	int rc;

	if (source_port == 0)
		source_port = 1;
	udp.source = bpf_htons(source_port);
	udp.dest = bpf_htons(listener->listen_port);
	udp.len = bpf_htons(info->payload_len + sizeof(udp));
	udp.check = 0;

	if (listener->role == ICMP_ROLE_SERVER && info->type == ICMP_ECHO)
		remember_icmp_sequence(skb, info, listener);
	if (bpf_skb_store_bytes(skb, info->payload_off, &new_wire, sizeof(new_wire),
				BPF_F_INVALIDATE_HASH) < 0)
		return -2;
	if (bpf_skb_store_bytes(skb, info->icmp_off, &udp, sizeof(udp),
				BPF_F_INVALIDATE_HASH) < 0)
		return -2;
	rc = update_ipv4_protocol(skb, info->ip_off, IPPROTO_ICMP, IPPROTO_UDP);
	if (rc < 0)
		return rc == -1 ? -3 : rc;
	return 0;
}

static __always_inline struct managed_fwmark_value *lookup_managed_fwmark(__u32 mark, __u32 ifindex,
									  __u64 generation)
{
	struct managed_fwmark_key key = {
		.generation = generation,
		.fwmark = mark,
		.underlay_index = ifindex,
	};
	struct managed_fwmark_value *value;

	value = bpf_map_lookup_elem(&managed_fwmark_map, &key);
	if (value && value->generation == generation)
		return value;

	key.underlay_index = UNDERLAY_WILDCARD;
	value = bpf_map_lookup_elem(&managed_fwmark_map, &key);
	if (value && value->generation == generation)
		return value;
	return 0;
}

static __always_inline int managed_miss_action(__u32 stat, struct managed_fwmark_value *managed)
{
	if (!managed)
		return TC_ACT_OK;
	inc_stat(stat);
	if (managed->action_on_miss == ACTION_DROP)
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int parse_result_is_fragment(int rc)
{
	return rc == PARSE_FRAGMENT || rc == PARSE_IPV4_FIRST_FRAGMENT ||
	       rc == PARSE_IPV4_NON_FIRST_FRAGMENT || rc == PARSE_IPV6_FRAGMENT_FIRST ||
	       rc == PARSE_IPV6_FRAGMENT_NON_FIRST;
}

static __always_inline int parse_result_is_ipv6_ext(int rc)
{
	return rc == PARSE_IPV6_EXT || rc == PARSE_IPV6_EXT_UDP ||
	       rc == PARSE_IPV6_EXT_TOO_DEEP;
}

static __always_inline int parse_result_has_ingress_port(int rc)
{
	return rc == PARSE_OK || rc == PARSE_IPV4_FIRST_FRAGMENT ||
	       rc == PARSE_IPV6_EXT_UDP || rc == PARSE_IPV6_FRAGMENT_FIRST ||
	       rc == PARSE_BAD_CSUM;
}

static __always_inline struct ingress_listener_value *lookup_ingress_listener(__u32 ifindex,
									      __u16 dst_port,
									      __u8 family,
									      __u64 generation)
{
	struct ingress_listener_key key = {
		.generation = generation,
		.underlay_index = ifindex,
		.destination_port = dst_port,
		.family = family,
	};
	struct ingress_listener_value *listener;

	listener = bpf_map_lookup_elem(&ingress_listener_map, &key);
	if (listener && listener->generation == generation)
		return listener;
	key.underlay_index = UNDERLAY_WILDCARD;
	listener = bpf_map_lookup_elem(&ingress_listener_map, &key);
	if (listener && listener->generation == generation)
		return listener;
	return 0;
}

static __always_inline struct icmp_listener_value *lookup_icmp_listener(__u32 ifindex,
									__u16 icmp_id,
									__u8 icmp_type,
									__u8 family,
									__u64 generation,
									__u8 *wildcard_id)
{
	struct icmp_listener_key key = {
		.generation = generation,
		.underlay_index = ifindex,
		.icmp_id = icmp_id,
		.family = family,
		.icmp_type = icmp_type,
	};
	struct icmp_listener_value *listener;

	*wildcard_id = 0;
	listener = bpf_map_lookup_elem(&icmp_listener_map, &key);
	if (listener && listener->generation == generation) {
		if (listener->flags & ICMP_LISTENER_F_WILDCARD_ID)
			*wildcard_id = 1;
		return listener;
	}
	key.underlay_index = UNDERLAY_WILDCARD;
	listener = bpf_map_lookup_elem(&icmp_listener_map, &key);
	if (listener && listener->generation == generation) {
		if (listener->flags & ICMP_LISTENER_F_WILDCARD_ID)
			*wildcard_id = 1;
		return listener;
	}
	if (icmp_id != 0) {
		key.underlay_index = ifindex;
		key.icmp_id = 0;
		listener = bpf_map_lookup_elem(&icmp_listener_map, &key);
		if (listener && listener->generation == generation &&
		    (listener->flags & ICMP_LISTENER_F_WILDCARD_ID)) {
			*wildcard_id = 1;
			return listener;
		}
		key.underlay_index = UNDERLAY_WILDCARD;
		listener = bpf_map_lookup_elem(&icmp_listener_map, &key);
		if (listener && listener->generation == generation &&
		    (listener->flags & ICMP_LISTENER_F_WILDCARD_ID)) {
			*wildcard_id = 1;
			return listener;
		}
	}
	return 0;
}

static __always_inline int icmp_bad_ingress_action(__u32 stat, __u8 wildcard_id)
{
	inc_stat(stat);
	if (wildcard_id)
		return TC_ACT_OK;
	return TC_ACT_SHOT;
}

static __always_inline void inc_xor_error(int rc)
{
	if (rc == -2)
		inc_stat(STAT_XOR_STORE_ERROR);
	else if (rc == -3)
		inc_stat(STAT_XOR_CSUM_ERROR);
	else if (rc == -4)
		inc_stat(STAT_XOR_LEN_OVERFLOW);
	else if (rc == -5)
		inc_stat(STAT_XOR_LOAD_ERROR);
	else
		inc_stat(STAT_XOR_KEY_MISSING);
}

static __always_inline __u32 xor_program_index(__u64 generation, __u32 segment)
{
	return ((__u32)generation & 1) * XOR_SEGMENT_COUNT + segment;
}

static __always_inline void set_xor_context(struct __sk_buff *skb,
					    __u64 generation,
					    __u32 cipher_id,
					    __u32 payload_off,
					    __u32 target,
					    __u8 checksum_mode)
{
	skb->cb[0] = (__u32)generation;
	skb->cb[1] = (__u32)(generation >> 32);
	skb->cb[2] = cipher_id;
	skb->cb[3] = payload_off;
	skb->cb[4] = XOR_CONTEXT_MAGIC |
		     ((__u32)checksum_mode << XOR_CONTEXT_MODE_SHIFT) |
		     target;
}

static __always_inline void set_faketcp_xor_context(struct __sk_buff *skb,
						     __u64 nonce)
{
	// A FakeTCP continuation never trusts XOR geometry from skb->cb. The
	// collection-local token is the only source for those fields.
	skb->cb[0] = (__u32)nonce;
	skb->cb[1] = (__u32)(nonce >> 32);
	skb->cb[2] = 0;
	skb->cb[3] = 0;
	skb->cb[4] = XOR_CONTEXT_MAGIC | XOR_CONTEXT_F_FAKETCP;
}

static __always_inline int load_xor_context(struct __sk_buff *skb,
					    struct xor_context *context)
{
	__u32 metadata = skb->cb[4];

	context->admission_nonce = ((__u64)skb->cb[1] << 32) | skb->cb[0];
	context->continue_faketcp = !!(metadata & XOR_CONTEXT_F_FAKETCP);
	if ((metadata & XOR_CONTEXT_MAGIC_MASK) != XOR_CONTEXT_MAGIC ||
	    (metadata & XOR_CONTEXT_FORBIDDEN_MASK))
		return -1;
	if (context->continue_faketcp) {
		if (context->admission_nonce == 0 || skb->cb[2] != 0 ||
		    skb->cb[3] != 0 ||
		    metadata != (XOR_CONTEXT_MAGIC | XOR_CONTEXT_F_FAKETCP))
			return -1;
		return 0;
	}
	context->generation = ((__u64)skb->cb[1] << 32) | skb->cb[0];
	context->cipher_id = skb->cb[2];
	context->payload_off = skb->cb[3];
	context->target = metadata & XOR_CONTEXT_TARGET_MASK;
	context->checksum_mode = (metadata & XOR_CONTEXT_MODE_MASK) >>
				 XOR_CONTEXT_MODE_SHIFT;
	if (context->generation == 0 || context->cipher_id == 0 ||
	    context->payload_off < sizeof(struct udphdr) ||
	    context->payload_off + context->target < context->payload_off ||
	    context->target < 4 || context->target > MAX_XOR_BYTES ||
	    context->checksum_mode > XOR_CSUM_MANUAL)
		return -1;
	return 0;
}

static __noinline void clear_xor_context(struct __sk_buff *skb)
{
	skb->cb[0] = 0;
	skb->cb[1] = 0;
	skb->cb[2] = 0;
	skb->cb[3] = 0;
	skb->cb[4] = 0;
}

static __always_inline int xor_dispatch_fail(struct __sk_buff *skb, __u32 stat)
{
	clear_xor_context(skb);
	inc_stat(stat);
	return TC_ACT_SHOT;
}

static __always_inline int prepare_xor_context_by_id(struct __sk_buff *skb,
						      struct packet_info *info,
						      __u32 cipher_id,
						      __u64 generation,
						      __u8 checksum_mode)
{
	struct cipher_value *cipher;
	__u32 target = 0;
	int rc;

	if (checksum_mode > XOR_CSUM_MANUAL ||
	    info->payload_off < sizeof(struct udphdr))
		return -4;
	cipher = lookup_cipher(cipher_id, generation);
	if (!cipher)
		return XOR_ERR_KEY;
	rc = xor_payload_target(info, cipher, &target);
	if (rc < 0)
		return rc;
	set_xor_context(skb, generation, cipher_id, info->payload_off, target,
			checksum_mode);
	return 0;
}

#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
#include "wg_mix_faketcp.h"
#endif

static __always_inline int run_xor_egress_segment(struct __sk_buff *skb, __u32 segment)
{
	struct xor_context context = {};
	struct cipher_value *cipher;
	int rc;

	if (load_xor_context(skb, &context) < 0) {
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
		faketcp_consume_egress_admission(context.admission_nonce, 0);
#endif
		return xor_dispatch_fail(skb, STAT_XOR_EGRESS_DISPATCH_ERROR);
	}
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
	if (context.continue_faketcp &&
	    faketcp_bind_egress_xor_progress(&context) < 0) {
		faketcp_consume_egress_admission(context.admission_nonce, 0);
		return xor_dispatch_fail(skb, STAT_XOR_EGRESS_DISPATCH_ERROR);
	}
#endif
	cipher = lookup_cipher(context.cipher_id, context.generation);
	if (!cipher) {
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
		if (context.continue_faketcp)
			faketcp_consume_egress_admission(
				context.admission_nonce, 0);
#endif
		return xor_dispatch_fail(skb, STAT_XOR_KEY_MISSING);
	}

	if (context.checksum_mode == XOR_CSUM_NONE)
		rc = xor_segment_store_only(skb, cipher, context.payload_off,
					    context.target, segment, 0,
					    BPF_F_INVALIDATE_HASH);
	else if (context.checksum_mode == XOR_CSUM_RECOMPUTE)
		rc = xor_segment_store_only(skb, cipher, context.payload_off,
					    context.target, segment, 0,
					    BPF_F_INVALIDATE_HASH |
					    BPF_F_RECOMPUTE_CSUM);
	else
		rc = xor_segment_manual_diff(skb, cipher, context.payload_off,
					     context.target, segment, 0);
	if (rc < 0) {
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
		if (context.continue_faketcp)
			faketcp_consume_egress_admission(
				context.admission_nonce, 0);
#endif
		clear_xor_context(skb);
		inc_xor_error(rc);
		return TC_ACT_SHOT;
	}
	if (rc > 0) {
		bpf_tail_call(skb, &xor_egress_programs,
			      xor_program_index(context.generation, segment + 1));
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
		if (context.continue_faketcp)
			faketcp_consume_egress_admission(
				context.admission_nonce, 0);
#endif
		return xor_dispatch_fail(skb, STAT_XOR_EGRESS_DISPATCH_ERROR);
	}

	inc_stat(STAT_XOR_EGRESS_OK);
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
	if (context.continue_faketcp) {
		if (faketcp_complete_egress_xor(context.admission_nonce) < 0) {
			faketcp_consume_egress_admission(
				context.admission_nonce, 0);
			return xor_dispatch_fail(
				skb, STAT_XOR_EGRESS_DISPATCH_ERROR);
		}
		bpf_tail_call(skb, &faketcp_egress_programs,
			      (__u32)context.generation & 1);
		faketcp_consume_egress_admission(context.admission_nonce, 0);
		return xor_dispatch_fail(skb, STAT_XOR_EGRESS_DISPATCH_ERROR);
	}
#endif
	clear_xor_context(skb);
	inc_stat(STAT_EGRESS_REWRITE_OK);
	if (skb->gso_segs || skb->gso_size)
		inc_stat(STAT_EGRESS_GSO_REWRITE_OK);
	return TC_ACT_OK;
}

static __always_inline int run_xor_ingress_segment(struct __sk_buff *skb, __u32 segment)
{
	struct xor_context context = {};
	struct cipher_value *cipher;
	int rc;

	if (load_xor_context(skb, &context) < 0 ||
	    context.checksum_mode == XOR_CSUM_RECOMPUTE)
		return xor_dispatch_fail(skb, STAT_XOR_INGRESS_DISPATCH_ERROR);
	cipher = lookup_cipher(context.cipher_id, context.generation);
	if (!cipher)
		return xor_dispatch_fail(skb, STAT_XOR_KEY_MISSING);

	if (context.checksum_mode == XOR_CSUM_NONE)
		rc = xor_segment_store_only(skb, cipher, context.payload_off,
					    context.target, segment, 4,
					    BPF_F_INVALIDATE_HASH);
	else
		rc = xor_segment_manual_diff(skb, cipher, context.payload_off,
					     context.target, segment, 4);
	if (rc < 0) {
		clear_xor_context(skb);
		inc_xor_error(rc);
		return TC_ACT_SHOT;
	}
	if (rc > 0) {
		bpf_tail_call(skb, &xor_ingress_programs,
			      xor_program_index(context.generation, segment + 1));
		return xor_dispatch_fail(skb, STAT_XOR_INGRESS_DISPATCH_ERROR);
	}

	clear_xor_context(skb);
	inc_stat(STAT_INGRESS_REWRITE_OK);
	inc_stat(STAT_XOR_INGRESS_OK);
	if (skb->gso_segs || skb->gso_size)
		inc_stat(STAT_INGRESS_GSO_REWRITE_OK);
	return TC_ACT_OK;
}

#define DEFINE_XOR_EGRESS_SEGMENT(index)                \
	SEC("classifier/xor_egress/" #index)            \
	int wg_xor_eg_##index(struct __sk_buff *skb)     \
	{                                                \
		return run_xor_egress_segment(skb, index); \
	}

#define DEFINE_XOR_INGRESS_SEGMENT(index)                \
	SEC("classifier/xor_ingress/" #index)            \
	int wg_xor_in_##index(struct __sk_buff *skb)     \
	{                                                \
		return run_xor_ingress_segment(skb, index); \
	}

DEFINE_XOR_EGRESS_SEGMENT(0)
DEFINE_XOR_EGRESS_SEGMENT(1)
DEFINE_XOR_EGRESS_SEGMENT(2)
DEFINE_XOR_EGRESS_SEGMENT(3)
DEFINE_XOR_EGRESS_SEGMENT(4)
DEFINE_XOR_EGRESS_SEGMENT(5)
DEFINE_XOR_EGRESS_SEGMENT(6)
DEFINE_XOR_EGRESS_SEGMENT(7)

DEFINE_XOR_INGRESS_SEGMENT(0)
DEFINE_XOR_INGRESS_SEGMENT(1)
DEFINE_XOR_INGRESS_SEGMENT(2)
DEFINE_XOR_INGRESS_SEGMENT(3)
DEFINE_XOR_INGRESS_SEGMENT(4)
DEFINE_XOR_INGRESS_SEGMENT(5)
DEFINE_XOR_INGRESS_SEGMENT(6)
DEFINE_XOR_INGRESS_SEGMENT(7)

SEC("classifier/egress")
int wg_mix_egress(struct __sk_buff *skb)
{
	struct packet_info info;
	struct egress_rule_key key = {};
	struct egress_rule_value *rule;
	struct managed_fwmark_value *managed;
	struct profile_key profile_key = {};
	struct profile_value *profile;
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
	struct faketcp_egress_admission faketcp_admission = {};
#endif
	__u64 generation = 0;
	__u32 old_wire = 0;
	__u32 old_type = 0;
	__u32 new_wire = 0;
	__u32 cipher_id = 0;
	__u8 gso_seen = 0;
	__u8 xor_checksum_mode = XOR_CSUM_NONE;
	int rc, kind;

	if (!active_generation(&generation))
		return TC_ACT_OK;
	if (skb->gso_segs || skb->gso_size) {
		gso_seen = 1;
		inc_stat(STAT_EGRESS_GSO_SEEN);
	}

	managed = lookup_managed_fwmark(skb->mark, skb->ifindex, generation);
	if (!managed)
		return TC_ACT_OK;
	if (gso_seen)
		inc_stat(STAT_EGRESS_GSO_MANAGED_SEEN);
	rc = parse_packet(skb, &info, generation);
	if (parse_result_is_fragment(rc)) {
		inc_stat(STAT_EGRESS_FRAGMENT);
		return TC_ACT_SHOT;
	}
	if (parse_result_is_ipv6_ext(rc)) {
		inc_stat(STAT_EGRESS_IPV6_EXT);
		return TC_ACT_SHOT;
	}
	if (rc == PARSE_BAD_CSUM)
		return managed_miss_action(STAT_EGRESS_BAD_CHECKSUM, managed);
	if (rc != PARSE_OK)
		return managed_miss_action(STAT_EGRESS_RULE_MISS, managed);

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
	if (!rule || rule->generation != generation)
		return managed_miss_action(STAT_EGRESS_RULE_MISS, managed);
	if (rule->action == ACTION_DROP)
		return TC_ACT_SHOT;
	if (rule->action != ACTION_REWRITE)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, info.payload_off, &old_wire, sizeof(old_wire)) < 0) {
		inc_stat(STAT_SKB_LOAD_ERROR);
		return TC_ACT_SHOT;
	}
	old_type = wg_le32_to_cpu(old_wire);
	kind = kind_from_standard(old_type);
	if (kind < 0) {
		inc_stat(STAT_EGRESS_BAD_TYPE);
		return TC_ACT_SHOT;
	}
	if (!validate_len(kind, info.payload_len)) {
		inc_stat(STAT_EGRESS_BAD_LENGTH);
		return TC_ACT_SHOT;
	}
	profile_key.generation = generation;
	profile_key.profile_id = rule->profile_id;
	profile = bpf_map_lookup_elem(&profile_map, &profile_key);
	if (!profile || profile->generation != generation) {
		inc_stat(STAT_EGRESS_RULE_MISS);
		return TC_ACT_SHOT;
	}
	cipher_id = rule->cipher_id;
	if (cipher_id != 0) {
		if (rule->transport_mode != TRANSPORT_UDP
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
		    && rule->transport_mode != TRANSPORT_FAKETCP
#endif
		) {
			inc_stat(STAT_XOR_KEY_MISSING);
			return TC_ACT_SHOT;
		}
	}
	new_wire = wg_cpu_to_le32(profile->standard_to_mixed[kind]);
	if (cipher_id != 0) {
		if (info.family == FAMILY_IPV4) {
			if (!info.ipv4_udp_csum_zero)
				xor_checksum_mode = XOR_CSUM_RECOMPUTE;
		} else {
			xor_checksum_mode = XOR_CSUM_MANUAL;
		}
	}
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
	// The single admission checkpoint validates the unmodified packet and the
	// complete managed type-word/XOR/FakeTCP composition. Checksum metadata is
	// normalized only after that proof and still before any packet-byte write.
	if (rule->transport_mode == TRANSPORT_FAKETCP) {
		if (faketcp_egress_admission_checkpoint(
			    skb, &info, managed, rule, profile, generation, rc,
			    kind, old_wire, new_wire, xor_checksum_mode,
			    &faketcp_admission) != FAKETCP_ADMISSION_TRANSFORM)
			return TC_ACT_SHOT;
		if (faketcp_inspect_and_reset_udp_checksum(
			    skb, info.ip_off, info.udp_off,
			    info.payload_len + sizeof(struct udphdr)) < 0) {
			faketcp_consume_egress_admission(
				faketcp_admission.nonce, 0);
			return TC_ACT_SHOT;
		}
		if (cipher_id != 0) {
			set_faketcp_xor_context(skb, faketcp_admission.nonce);
			rc = update_type_word(skb, &info, old_wire, new_wire, 1);
			if (rc < 0) {
				faketcp_consume_egress_admission(
					faketcp_admission.nonce, 0);
				clear_xor_context(skb);
				inc_stat(rc == -2 ? STAT_XOR_STORE_ERROR :
						    STAT_CHECKSUM_ERROR);
				return TC_ACT_SHOT;
			}
			bpf_tail_call(skb, &xor_egress_programs,
				      xor_program_index(generation, 0));
			faketcp_consume_egress_admission(
				faketcp_admission.nonce, 0);
			return xor_dispatch_fail(
				skb, STAT_XOR_EGRESS_DISPATCH_ERROR);
		}
		if (faketcp_consume_egress_admission(
			    faketcp_admission.nonce, &faketcp_admission) < 0 ||
		    !faketcp_egress_admission_matches(
			    skb, &info, managed, rule, profile, generation,
			    FAKETCP_TOKEN_ARMED, &faketcp_admission)) {
			inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
			return TC_ACT_SHOT;
		}
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT);
		rc = update_type_word(skb, &info, old_wire, new_wire, 1);
		if (rc < 0) {
			inc_stat(rc == -2 ? STAT_SKB_STORE_ERROR :
					    STAT_CHECKSUM_ERROR);
			return TC_ACT_SHOT;
		}
		return faketcp_encode_established(skb, &info, rule, generation,
						  &faketcp_admission);
	}
#endif
	if (rule->transport_mode == TRANSPORT_ICMP) {
		rc = rewrite_udp_to_icmp(skb, &info, rule, old_wire, new_wire);
	} else if (cipher_id != 0) {
		rc = prepare_xor_context_by_id(skb, &info, cipher_id, generation,
					       xor_checksum_mode);
		if (rc < 0) {
			inc_xor_error(rc);
			return TC_ACT_SHOT;
		}
		rc = update_type_word(skb, &info, old_wire, new_wire, 1);
		if (rc < 0) {
			clear_xor_context(skb);
			if (rc == -2)
				inc_stat(STAT_XOR_STORE_ERROR);
			else
				inc_stat(STAT_CHECKSUM_ERROR);
			return TC_ACT_SHOT;
		}
		bpf_tail_call(skb, &xor_egress_programs,
			      xor_program_index(generation, 0));
		return xor_dispatch_fail(skb, STAT_XOR_EGRESS_DISPATCH_ERROR);
	} else {
		rc = update_type_word(skb, &info, old_wire, new_wire, 1);
	}
	if (rc < 0) {
		if (rc == -2)
			inc_stat(cipher_id != 0 ? STAT_XOR_STORE_ERROR :
				 STAT_SKB_STORE_ERROR);
		else if (rc == -3)
			inc_stat(cipher_id != 0 ? STAT_XOR_CSUM_ERROR :
				 STAT_ICMP_CHECKSUM_ERROR);
		else if (rc == -4)
			inc_stat(STAT_XOR_LEN_OVERFLOW);
		else if (rc == -5)
			inc_stat(STAT_XOR_LOAD_ERROR);
		else if (rc == XOR_ERR_KEY)
			inc_stat(STAT_XOR_KEY_MISSING);
		else
			inc_stat(STAT_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}
	inc_stat(STAT_EGRESS_REWRITE_OK);
	if (rule->transport_mode == TRANSPORT_ICMP)
		inc_stat(STAT_ICMP_EGRESS_REWRITE_OK);
	if (gso_seen)
		inc_stat(STAT_EGRESS_GSO_REWRITE_OK);
	return TC_ACT_OK;
}

SEC("classifier/ingress")
int wg_mix_ingress(struct __sk_buff *skb)
{
	struct packet_info info;
	struct icmp_packet_info icmp_info;
	struct ingress_listener_value *listener;
	struct icmp_listener_value *icmp_listener;
	struct profile_key profile_key = {};
	struct profile_value *profile;
	struct xor_ingress_metadata xor_metadata = {};
	__u64 generation = 0;
	__u32 old_wire = 0;
	__u32 encrypted_wire = 0;
	__u32 old_type = 0;
	__u32 new_wire = 0;
	__u32 cipher_id = 0;
	__u8 gso_seen = 0;
	__u8 icmp_wildcard_id = 0;
	__u8 xor_checksum_mode = XOR_CSUM_NONE;
	int rc, kind = -1;

	if (!active_generation(&generation))
		return TC_ACT_OK;
	if (skb->gso_segs || skb->gso_size) {
		gso_seen = 1;
		inc_stat(STAT_INGRESS_GSO_SEEN);
	}

	rc = parse_icmp_packet(skb, &icmp_info, generation);
	if (rc == PARSE_OK && icmp_info.code == 0 &&
	    (icmp_info.type == ICMP_ECHO || icmp_info.type == ICMP_ECHOREPLY)) {
		icmp_listener = lookup_icmp_listener(skb->ifindex, icmp_info.id, icmp_info.type,
						     icmp_info.family, generation,
						     &icmp_wildcard_id);
		if (!icmp_listener)
			return TC_ACT_OK;
		if (gso_seen)
			inc_stat(STAT_INGRESS_GSO_LISTENER_HIT);
		if (icmp_listener->action == ACTION_DROP)
			return TC_ACT_SHOT;
		if (icmp_listener->action != ACTION_REWRITE)
			return TC_ACT_OK;

		profile_key.generation = generation;
		profile_key.profile_id = icmp_listener->profile_id;
		profile = bpf_map_lookup_elem(&profile_map, &profile_key);
		if (!profile || profile->generation != generation) {
			inc_stat(STAT_INGRESS_RULE_MISS);
			return TC_ACT_SHOT;
		}
		if (icmp_info.payload_len < sizeof(old_wire))
			return icmp_bad_ingress_action(STAT_INGRESS_BAD_LENGTH,
						       icmp_wildcard_id);
		if (bpf_skb_load_bytes(skb, icmp_info.payload_off, &old_wire,
				       sizeof(old_wire)) < 0) {
			inc_stat(STAT_SKB_LOAD_ERROR);
			return TC_ACT_SHOT;
		}
		old_type = wg_le32_to_cpu(old_wire);
		kind = -1;
#pragma unroll
		for (int i = 0; i < 4; i++) {
			if (profile->standard_to_mixed[i] == old_type) {
				kind = i;
				break;
			}
		}
		if (kind < 0) {
			return icmp_bad_ingress_action(STAT_INGRESS_BAD_TYPE,
						       icmp_wildcard_id);
		}
		if (!validate_len(kind, icmp_info.payload_len)) {
			return icmp_bad_ingress_action(STAT_INGRESS_BAD_LENGTH,
						       icmp_wildcard_id);
		}
		new_wire = wg_cpu_to_le32(profile->mixed_to_standard[kind]);
		rc = rewrite_icmp_to_udp(skb, &icmp_info, icmp_listener, new_wire);
		if (rc < 0) {
			if (rc == -2)
				inc_stat(STAT_SKB_STORE_ERROR);
			else if (rc == -3)
				inc_stat(STAT_ICMP_CHECKSUM_ERROR);
			else
				inc_stat(STAT_CHECKSUM_ERROR);
			return TC_ACT_SHOT;
		}
		inc_stat(STAT_INGRESS_REWRITE_OK);
		inc_stat(STAT_ICMP_INGRESS_REWRITE_OK);
		if (gso_seen)
			inc_stat(STAT_INGRESS_GSO_REWRITE_OK);
		return TC_ACT_OK;
	}

	rc = parse_packet(skb, &info, generation);
	if (!parse_result_has_ingress_port(rc)) {
		if (parse_result_is_fragment(rc))
			inc_stat(STAT_INGRESS_FRAGMENT);
		if (parse_result_is_ipv6_ext(rc))
			inc_stat(STAT_INGRESS_IPV6_EXT);
		return TC_ACT_OK;
	}

	listener = lookup_ingress_listener(skb->ifindex, info.dst_port, info.family, generation);
	if (!listener) {
		inc_stat(STAT_INGRESS_RULE_MISS);
		return TC_ACT_OK;
	}
	if (gso_seen)
		inc_stat(STAT_INGRESS_GSO_LISTENER_HIT);
	if (parse_result_is_fragment(rc)) {
		inc_stat(STAT_INGRESS_FRAGMENT);
		return TC_ACT_SHOT;
	}
	if (rc == PARSE_BAD_CSUM) {
		inc_stat(STAT_INGRESS_BAD_CHECKSUM);
		return TC_ACT_SHOT;
	}
	if (parse_result_is_ipv6_ext(rc)) {
		inc_stat(STAT_INGRESS_IPV6_EXT);
		return TC_ACT_SHOT;
	}
	if (rc != PARSE_OK)
		return TC_ACT_OK;

	if (listener->action == ACTION_DROP)
		return TC_ACT_SHOT;
	if (listener->action != ACTION_REWRITE)
		return TC_ACT_OK;

	profile_key.generation = generation;
	profile_key.profile_id = listener->profile_id;
	profile = bpf_map_lookup_elem(&profile_map, &profile_key);
	if (!profile || profile->generation != generation) {
		inc_stat(STAT_INGRESS_RULE_MISS);
		return TC_ACT_SHOT;
	}
#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
	if (listener->transport_mode == TRANSPORT_FAKETCP &&
	    faketcp_consume_ingress_admission(skb, &info, listener, profile,
					      generation) < 0)
		return TC_ACT_SHOT;
#endif
	cipher_id = listener->cipher_id;
	if (bpf_skb_load_bytes(skb, info.payload_off, &old_wire, sizeof(old_wire)) < 0) {
		inc_stat(STAT_SKB_LOAD_ERROR);
		return TC_ACT_SHOT;
	}
	encrypted_wire = old_wire;
	if (cipher_id != 0) {
		rc = load_xor_ingress_metadata(&info, old_wire, cipher_id, generation,
					       &xor_metadata);
		if (rc < 0) {
			inc_xor_error(rc);
			return TC_ACT_SHOT;
		}
		old_wire = xor_metadata.wire;
	}
	old_type = wg_le32_to_cpu(old_wire);

#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (profile->standard_to_mixed[i] == old_type) {
			kind = i;
			break;
		}
	}
	if (kind < 0) {
		inc_stat(cipher_id != 0 ? STAT_XOR_BAD_TYPE_AFTER_DECRYPT :
			 STAT_INGRESS_BAD_TYPE);
		return TC_ACT_SHOT;
	}
	if (!validate_len(kind, info.payload_len)) {
		inc_stat(STAT_INGRESS_BAD_LENGTH);
		return TC_ACT_SHOT;
	}
	new_wire = wg_cpu_to_le32(profile->mixed_to_standard[kind]);
	if (cipher_id != 0) {
		if (!(info.family == FAMILY_IPV4 && info.ipv4_udp_csum_zero))
			xor_checksum_mode = XOR_CSUM_MANUAL;
		set_xor_context(skb, generation, cipher_id, info.payload_off,
				xor_metadata.target,
				xor_checksum_mode);
		rc = update_type_word(skb, &info, encrypted_wire, new_wire, 0);
		if (rc < 0) {
			clear_xor_context(skb);
			if (rc == -2)
				inc_stat(STAT_XOR_STORE_ERROR);
			else
				inc_stat(STAT_CHECKSUM_ERROR);
			return TC_ACT_SHOT;
		}
		bpf_tail_call(skb, &xor_ingress_programs,
			      xor_program_index(generation, 0));
		return xor_dispatch_fail(skb, STAT_XOR_INGRESS_DISPATCH_ERROR);
	} else {
		rc = update_type_word(skb, &info, old_wire, new_wire, 0);
	}
	if (rc < 0) {
		if (rc == -2)
			inc_stat(cipher_id != 0 ? STAT_XOR_STORE_ERROR :
				 STAT_SKB_STORE_ERROR);
		else if (rc == -3)
			inc_stat(STAT_XOR_CSUM_ERROR);
		else if (rc == -4)
			inc_stat(STAT_XOR_LEN_OVERFLOW);
		else if (rc == -5)
			inc_stat(STAT_XOR_LOAD_ERROR);
		else if (rc == XOR_ERR_KEY)
			inc_stat(STAT_XOR_KEY_MISSING);
		else
			inc_stat(STAT_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}
	inc_stat(STAT_INGRESS_REWRITE_OK);
	if (gso_seen)
		inc_stat(STAT_INGRESS_GSO_REWRITE_OK);
	return TC_ACT_OK;
}

#ifdef WG_MIX_EXPERIMENTAL_FAKETCP
// Kernel kfunc callers must use a GPL-compatible BPF license. This applies
// only to the separately built experimental object; the baseline stays MIT.
char LICENSE[] SEC("license") = "GPL";
#else
char LICENSE[] SEC("license") = "MIT";
#endif
