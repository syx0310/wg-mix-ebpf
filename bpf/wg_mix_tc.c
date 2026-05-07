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

#define ABI_VERSION 1

#define FAMILY_ANY  0
#define FAMILY_IPV4 4
#define FAMILY_IPV6 6

#define ACTION_PASS    1
#define ACTION_DROP    2
#define ACTION_REWRITE 3

#define CONTROL_KEY_GLOBAL 0
#define UNDERLAY_WILDCARD 0

#define PARSE_OK 0
#define PARSE_SHORT 1
#define PARSE_NOT_UDP 2
#define PARSE_FRAGMENT 3
#define PARSE_IPV6_EXT 4

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

struct managed_fwmark_key {
	__u32 fwmark;
	__u32 underlay_index;
};

struct managed_fwmark_value {
	__u64 generation;
	__u8 action_on_miss;
	__u8 pad[7];
};

struct egress_rule_key {
	__u32 fwmark;
	__u32 underlay_index;
	__u16 source_port;
	__u8 family;
	__u8 pad;
};

struct egress_rule_value {
	__u64 generation;
	__u32 profile_id;
	__u32 wg_id;
	__u8 action;
	__u8 pad[7];
};

struct ingress_listener_key {
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
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct profile_value);
} profile_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct managed_fwmark_key);
	__type(value, struct managed_fwmark_value);
} managed_fwmark_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct egress_rule_key);
	__type(value, struct egress_rule_value);
} egress_rule_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
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

static __always_inline int same_generation(__u64 generation)
{
	struct control_value *control = active_control();

	if (!control || control->abi_version != ABI_VERSION)
		return 0;
	return generation == control->active_generation;
}

static __always_inline int parse_eth_or_l3(void *data, void *data_end, __u64 *off, __u16 *proto)
{
	struct ethhdr *eth = data;
	__u8 first;

	if (data + 1 > data_end)
		return PARSE_SHORT;

	first = *(__u8 *)data;
	if ((first >> 4) == 4) {
		*off = 0;
		*proto = bpf_htons(ETH_P_IP);
		return PARSE_OK;
	}
	if ((first >> 4) == 6) {
		*off = 0;
		*proto = bpf_htons(ETH_P_IPV6);
		return PARSE_OK;
	}

	if ((void *)(eth + 1) > data_end)
		return PARSE_SHORT;

	*off = sizeof(*eth);
	*proto = eth->h_proto;

#pragma unroll
	for (int i = 0; i < 2; i++) {
		struct vlan_hdr *vh;

		if (*proto != bpf_htons(ETH_P_8021Q) && *proto != bpf_htons(ETH_P_8021AD))
			break;
		vh = data + *off;
		if ((void *)(vh + 1) > data_end)
			return PARSE_SHORT;
		*proto = vh->h_vlan_encapsulated_proto;
		*off += sizeof(*vh);
	}
	return PARSE_OK;
}

static __always_inline int parse_packet(struct __sk_buff *skb, struct packet_info *info)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u64 off = 0;
	__u16 proto = 0;
	int rc;

	__builtin_memset(info, 0, sizeof(*info));
	rc = parse_eth_or_l3(data, data_end, &off, &proto);
	if (rc != PARSE_OK)
		return rc;

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + off;
		__u32 ihl;
		__u16 frag;
		struct udphdr *udp;
		__u16 udp_len;

		if ((void *)(iph + 1) > data_end)
			return PARSE_SHORT;
		ihl = iph->ihl * 4;
		if (ihl < sizeof(*iph) || data + off + ihl > data_end)
			return PARSE_SHORT;
		frag = bpf_ntohs(iph->frag_off);
		if (frag & (IP_MF | IP_OFFSET))
			return PARSE_FRAGMENT;
		if (iph->protocol != IPPROTO_UDP)
			return PARSE_NOT_UDP;
		udp = data + off + ihl;
		if ((void *)(udp + 1) > data_end)
			return PARSE_SHORT;
		udp_len = bpf_ntohs(udp->len);
		if (udp_len < sizeof(*udp))
			return PARSE_SHORT;
		info->family = FAMILY_IPV4;
		info->ip_off = off;
		info->udp_off = off + ihl;
		info->payload_off = info->udp_off + sizeof(*udp);
		info->payload_len = udp_len - sizeof(*udp);
		info->src_port = bpf_ntohs(udp->source);
		info->dst_port = bpf_ntohs(udp->dest);
		info->ipv4_udp_csum_zero = udp->check == 0;
		if (data + info->payload_off + 4 > data_end)
			return PARSE_SHORT;
		return PARSE_OK;
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + off;
		struct udphdr *udp;
		__u16 udp_len;

		if ((void *)(ip6h + 1) > data_end)
			return PARSE_SHORT;
		if (ip6h->nexthdr == NEXTHDR_FRAGMENT)
			return PARSE_FRAGMENT;
		if (ip6h->nexthdr != IPPROTO_UDP)
			return PARSE_IPV6_EXT;
		udp = data + off + sizeof(*ip6h);
		if ((void *)(udp + 1) > data_end)
			return PARSE_SHORT;
		udp_len = bpf_ntohs(udp->len);
		if (udp_len < sizeof(*udp))
			return PARSE_SHORT;
		if (udp->check == 0)
			return PARSE_SHORT;
		info->family = FAMILY_IPV6;
		info->ip_off = off;
		info->udp_off = off + sizeof(*ip6h);
		info->payload_off = info->udp_off + sizeof(*udp);
		info->payload_len = udp_len - sizeof(*udp);
		info->src_port = bpf_ntohs(udp->source);
		info->dst_port = bpf_ntohs(udp->dest);
		if (data + info->payload_off + 4 > data_end)
			return PARSE_SHORT;
		return PARSE_OK;
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

static __always_inline struct managed_fwmark_value *lookup_managed_fwmark(__u32 mark, __u32 ifindex)
{
	struct managed_fwmark_key key = {
		.fwmark = mark,
		.underlay_index = ifindex,
	};
	struct managed_fwmark_value *value;

	value = bpf_map_lookup_elem(&managed_fwmark_map, &key);
	if (value && same_generation(value->generation))
		return value;

	key.underlay_index = UNDERLAY_WILDCARD;
	value = bpf_map_lookup_elem(&managed_fwmark_map, &key);
	if (value && same_generation(value->generation))
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

SEC("tc/egress")
int wg_mix_egress(struct __sk_buff *skb)
{
	struct packet_info info;
	struct egress_rule_key key = {};
	struct egress_rule_value *rule;
	struct managed_fwmark_value *managed;
	struct profile_value *profile;
	__u32 old_wire = 0;
	__u32 old_type = 0;
	__u32 new_wire = 0;
	int rc, kind;

	rc = parse_packet(skb, &info);
	managed = lookup_managed_fwmark(skb->mark, skb->ifindex);
	if (rc == PARSE_FRAGMENT) {
		if (managed) {
			inc_stat(STAT_EGRESS_FRAGMENT);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}
	if (rc == PARSE_IPV6_EXT) {
		if (managed) {
			inc_stat(STAT_EGRESS_IPV6_EXT);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}
	if (rc != PARSE_OK)
		return managed_miss_action(STAT_EGRESS_RULE_MISS, managed);

	key.fwmark = skb->mark;
	key.underlay_index = skb->ifindex;
	key.source_port = info.src_port;
	key.family = info.family;
	rule = bpf_map_lookup_elem(&egress_rule_map, &key);
	if (!rule || !same_generation(rule->generation)) {
		key.underlay_index = UNDERLAY_WILDCARD;
		rule = bpf_map_lookup_elem(&egress_rule_map, &key);
	}
	if (!rule || !same_generation(rule->generation))
		return managed_miss_action(STAT_EGRESS_RULE_MISS, managed);
	if (rule->action == ACTION_DROP)
		return TC_ACT_SHOT;
	if (rule->action != ACTION_REWRITE)
		return TC_ACT_OK;

	if (bpf_skb_load_bytes(skb, info.payload_off, &old_wire, sizeof(old_wire)) < 0)
		return TC_ACT_SHOT;
	old_type = bpf_le32_to_cpu(old_wire);
	kind = kind_from_standard(old_type);
	if (kind < 0) {
		inc_stat(STAT_EGRESS_BAD_TYPE);
		return TC_ACT_SHOT;
	}
	if (!validate_len(kind, info.payload_len)) {
		inc_stat(STAT_EGRESS_BAD_LENGTH);
		return TC_ACT_SHOT;
	}
	profile = bpf_map_lookup_elem(&profile_map, &rule->profile_id);
	if (!profile || !same_generation(profile->generation))
		return managed_miss_action(STAT_EGRESS_RULE_MISS, managed);
	new_wire = bpf_cpu_to_le32(profile->standard_to_mixed[kind]);
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
	struct ingress_listener_key key = {};
	struct ingress_listener_value *listener;
	struct profile_value *profile;
	__u32 old_wire = 0;
	__u32 old_type = 0;
	__u32 new_wire = 0;
	int rc, kind = -1;

	rc = parse_packet(skb, &info);
	if (rc == PARSE_FRAGMENT) {
		inc_stat(STAT_INGRESS_FRAGMENT);
		return TC_ACT_OK;
	}
	if (rc == PARSE_IPV6_EXT) {
		inc_stat(STAT_INGRESS_IPV6_EXT);
		return TC_ACT_OK;
	}
	if (rc != PARSE_OK)
		return TC_ACT_OK;

	key.underlay_index = skb->ifindex;
	key.destination_port = info.dst_port;
	key.family = info.family;
	listener = bpf_map_lookup_elem(&ingress_listener_map, &key);
	if (!listener || !same_generation(listener->generation)) {
		key.underlay_index = UNDERLAY_WILDCARD;
		listener = bpf_map_lookup_elem(&ingress_listener_map, &key);
	}
	if (!listener || !same_generation(listener->generation)) {
		inc_stat(STAT_INGRESS_RULE_MISS);
		return TC_ACT_OK;
	}
	if (listener->action == ACTION_DROP)
		return TC_ACT_SHOT;
	if (listener->action != ACTION_REWRITE)
		return TC_ACT_OK;

	profile = bpf_map_lookup_elem(&profile_map, &listener->profile_id);
	if (!profile || !same_generation(profile->generation)) {
		inc_stat(STAT_INGRESS_RULE_MISS);
		return TC_ACT_OK;
	}
	if (bpf_skb_load_bytes(skb, info.payload_off, &old_wire, sizeof(old_wire)) < 0)
		return TC_ACT_SHOT;
	old_type = bpf_le32_to_cpu(old_wire);

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
	new_wire = bpf_cpu_to_le32(profile->mixed_to_standard[kind]);
	if (update_type_word(skb, &info, old_wire, new_wire) < 0) {
		inc_stat(STAT_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}
	inc_stat(STAT_INGRESS_REWRITE_OK);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "MIT";
