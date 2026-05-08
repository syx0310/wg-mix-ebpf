// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ABI_VERSION 3

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
	__u8 action;
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
	__u8 action;
	__u8 pad[7];
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
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct control_value);
} control_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct profile_key);
	__type(value, struct profile_value);
} profile_map SEC(".maps");

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
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

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
	if (require_payload_word && data + info->payload_off + 4 > data_end)
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
		return payload_len >= 32 && ((payload_len - 32) & 15) == 0;
	return 0;
}

static __always_inline int update_type_word(struct __sk_buff *skb, struct packet_info *info,
					    __u32 old_wire, __u32 new_wire)
{
	__u32 csum_off = info->udp_off + offsetof(struct udphdr, check);
	__s64 diff;

	if (!(info->family == FAMILY_IPV4 && info->ipv4_udp_csum_zero)) {
		diff = bpf_csum_diff((__be32 *)&old_wire, sizeof(old_wire),
				     (__be32 *)&new_wire, sizeof(new_wire), 0);
		if (diff < 0)
			return -1;
		if (bpf_l4_csum_replace(skb, csum_off, 0, diff, 0) < 0)
			return -1;
	}
	if (bpf_skb_store_bytes(skb, info->payload_off, &new_wire, sizeof(new_wire), 0) < 0)
		return -1;
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

SEC("tc/egress")
int wg_mix_egress(struct __sk_buff *skb)
{
	struct packet_info info;
	struct egress_rule_key key = {};
	struct egress_rule_value *rule;
	struct managed_fwmark_value *managed;
	struct profile_key profile_key = {};
	struct profile_value *profile;
	__u64 generation = 0;
	__u32 old_wire = 0;
	__u32 old_type = 0;
	__u32 new_wire = 0;
	int rc, kind;

	if (!active_generation(&generation))
		return TC_ACT_OK;

	rc = parse_packet(skb, &info, generation);
	managed = lookup_managed_fwmark(skb->mark, skb->ifindex, generation);
	if (parse_result_is_fragment(rc)) {
		if (managed) {
			inc_stat(STAT_EGRESS_FRAGMENT);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}
	if (parse_result_is_ipv6_ext(rc)) {
		if (managed) {
			inc_stat(STAT_EGRESS_IPV6_EXT);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}
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

	if (bpf_skb_load_bytes(skb, info.payload_off, &old_wire, sizeof(old_wire)) < 0)
		return TC_ACT_SHOT;
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
	new_wire = wg_cpu_to_le32(profile->standard_to_mixed[kind]);
	if (update_type_word(skb, &info, old_wire, new_wire) < 0) {
		inc_stat(STAT_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}
	inc_stat(STAT_EGRESS_REWRITE_OK);
	return TC_ACT_OK;
}

SEC("tc/ingress")
int wg_mix_ingress(struct __sk_buff *skb)
{
	struct packet_info info;
	struct ingress_listener_value *listener;
	struct profile_key profile_key = {};
	struct profile_value *profile;
	__u64 generation = 0;
	__u32 old_wire = 0;
	__u32 old_type = 0;
	__u32 new_wire = 0;
	int rc, kind = -1;

	if (!active_generation(&generation))
		return TC_ACT_OK;

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
	if (parse_result_is_fragment(rc)) {
		inc_stat(STAT_INGRESS_FRAGMENT);
		return TC_ACT_SHOT;
	}
	if (parse_result_is_ipv6_ext(rc) || rc == PARSE_BAD_CSUM) {
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
	if (bpf_skb_load_bytes(skb, info.payload_off, &old_wire, sizeof(old_wire)) < 0)
		return TC_ACT_SHOT;
	old_type = wg_le32_to_cpu(old_wire);

#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (profile->standard_to_mixed[i] == old_type) {
			kind = i;
			break;
		}
	}
	if (kind < 0) {
		inc_stat(STAT_INGRESS_BAD_TYPE);
		return TC_ACT_SHOT;
	}
	if (!validate_len(kind, info.payload_len)) {
		inc_stat(STAT_INGRESS_BAD_LENGTH);
		return TC_ACT_SHOT;
	}
	new_wire = wg_cpu_to_le32(profile->mixed_to_standard[kind]);
	if (update_type_word(skb, &info, old_wire, new_wire) < 0) {
		inc_stat(STAT_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}
	inc_stat(STAT_INGRESS_REWRITE_OK);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "MIT";
