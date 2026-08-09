// SPDX-License-Identifier: MIT
#ifndef WG_MIX_FAKETCP_L3_H
#define WG_MIX_FAKETCP_L3_H

// Only FAKETCP_L3_OK authorizes transport-port access or mutation.
// SAFE_BYPASS proves a non-TCP/UDP protocol; every error result fails closed.
#define FAKETCP_L3_OK 0
#define FAKETCP_L3_SAFE_BYPASS 1
#define FAKETCP_L3_TRUNCATED 2
#define FAKETCP_L3_MALFORMED 3
#define FAKETCP_L3_UNSUPPORTED 4
#define FAKETCP_L3_FIRST_FRAGMENT 5
#define FAKETCP_L3_NONINITIAL_FRAGMENT 6
#define FAKETCP_L3_EXTENSION_TOO_DEEP 7

#define FAKETCP_L3_MAX_EXTENSION_HEADERS 8
#define FAKETCP_L3_MAX_EXTENSION_BYTES 512

#define FAKETCP_L3_F_IPV4_OPTIONS (1U << 0)
#define FAKETCP_L3_F_IPV4_DF (1U << 1)
#define FAKETCP_L3_F_MORE_FRAGMENTS (1U << 2)
#define FAKETCP_L3_F_IPV6_EXTENSIONS (1U << 3)
#define FAKETCP_L3_F_FRAGMENT (1U << 4)

#ifndef IP_RESERVED
#define IP_RESERVED 0x8000
#endif

#ifndef IP_DF
#define IP_DF 0x4000
#endif

#ifndef NEXTHDR_AUTH
#define NEXTHDR_AUTH 51
#endif

struct faketcp_l3_info {
	__u32 l3_off;
	__u32 l3_len;
	__u32 l4_off;
	__u32 l4_len;
	__u16 l3_header_len;
	__u16 l4_header_len;
	__u16 fragment_offset_bytes;
	__u8 family;
	__u8 transport_protocol;
	__u8 extension_count;
	__u8 flags;
};

_Static_assert(sizeof(struct faketcp_l3_info) == 28,
	       "faketcp L3 descriptor layout drift");

struct faketcp_l3_ipv6_extension {
	__u8 next_header;
	__u8 header_length;
};

struct faketcp_l3_ipv6_fragment {
	__u8 next_header;
	__u8 reserved;
	__be16 fragment_offset;
	__be32 identification;
};

static __always_inline int
faketcp_l3_validate_transport(void *data, void *data_end, __u32 frame_len,
			       struct faketcp_l3_info *info)
{
	__u64 l4_end = (__u64)info->l4_off + info->l4_len;

	if (info->l4_off > frame_len || l4_end > frame_len)
		return FAKETCP_L3_TRUNCATED;
	if (info->transport_protocol == IPPROTO_UDP) {
		struct udphdr *udp;
		__u16 udp_len;

		if (info->l4_len < sizeof(*udp))
			return FAKETCP_L3_MALFORMED;
		udp = data + info->l4_off;
		if ((void *)(udp + 1) > data_end)
			return FAKETCP_L3_TRUNCATED;
		udp_len = bpf_ntohs(udp->len);
		if (udp_len < sizeof(*udp) || udp_len != info->l4_len)
			return FAKETCP_L3_MALFORMED;
		info->l4_header_len = sizeof(*udp);
		return FAKETCP_L3_OK;
	}
	if (info->transport_protocol == IPPROTO_TCP) {
		struct tcphdr *tcp;
		__u16 tcp_header_len;

		if (info->l4_len < sizeof(*tcp))
			return FAKETCP_L3_MALFORMED;
		tcp = data + info->l4_off;
		if ((void *)(tcp + 1) > data_end)
			return FAKETCP_L3_TRUNCATED;
		tcp_header_len = (__u16)tcp->doff * 4;
		if (tcp_header_len < sizeof(*tcp) || tcp_header_len > info->l4_len)
			return FAKETCP_L3_MALFORMED;
		if (data + info->l4_off + tcp_header_len > data_end)
			return FAKETCP_L3_TRUNCATED;
		info->l4_header_len = tcp_header_len;
		return FAKETCP_L3_OK;
	}
	return FAKETCP_L3_UNSUPPORTED;
}

static __always_inline int
faketcp_parse_ipv4_l3(void *data, void *data_end, __u32 frame_len,
		       __u32 l3_off, struct faketcp_l3_info *info)
{
	struct iphdr *iph;
	__u32 ihl;
	__u16 total_len;
	__u16 fragment;
	__u16 fragment_offset;

	info->family = FAMILY_IPV4;
	if (l3_off > frame_len)
		return FAKETCP_L3_TRUNCATED;
	iph = data + l3_off;
	if ((void *)(iph + 1) > data_end)
		return FAKETCP_L3_TRUNCATED;
	if (iph->version != 4)
		return FAKETCP_L3_MALFORMED;
	ihl = (__u32)iph->ihl * 4;
	if (ihl < sizeof(*iph))
		return FAKETCP_L3_MALFORMED;
	if (ihl > frame_len - l3_off || data + l3_off + ihl > data_end)
		return FAKETCP_L3_TRUNCATED;
	total_len = bpf_ntohs(iph->tot_len);
	if (total_len < ihl)
		return FAKETCP_L3_MALFORMED;
	if (total_len > frame_len - l3_off)
		return FAKETCP_L3_TRUNCATED;

	info->l3_len = total_len;
	info->l3_header_len = ihl;
	info->l4_off = l3_off + ihl;
	info->l4_len = total_len - ihl;
	info->transport_protocol = iph->protocol;
	if (ihl > sizeof(*iph))
		info->flags |= FAKETCP_L3_F_IPV4_OPTIONS;

	fragment = bpf_ntohs(iph->frag_off);
	if (fragment & IP_RESERVED)
		return FAKETCP_L3_MALFORMED;
	if (fragment & IP_DF)
		info->flags |= FAKETCP_L3_F_IPV4_DF;
	if ((fragment & IP_DF) && (fragment & (IP_MF | IP_OFFSET)))
		return FAKETCP_L3_MALFORMED;
	if (fragment & IP_MF)
		info->flags |= FAKETCP_L3_F_MORE_FRAGMENTS |
			       FAKETCP_L3_F_FRAGMENT;
	fragment_offset = fragment & IP_OFFSET;
	info->fragment_offset_bytes = fragment_offset * 8;
	if (fragment_offset) {
		info->flags |= FAKETCP_L3_F_FRAGMENT;
		return FAKETCP_L3_NONINITIAL_FRAGMENT;
	}
	if (fragment & IP_MF)
		return FAKETCP_L3_FIRST_FRAGMENT;
	if (iph->protocol == IPPROTO_ICMP)
		return FAKETCP_L3_SAFE_BYPASS;
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return FAKETCP_L3_UNSUPPORTED;
	return faketcp_l3_validate_transport(data, data_end, frame_len, info);
}

static __always_inline int
faketcp_parse_ipv6_l3(void *data, void *data_end, __u32 frame_len,
		       __u32 l3_off, struct faketcp_l3_info *info)
{
	struct ipv6hdr *ip6;
	__u32 total_len;
	__u32 header_off;
	__u32 extension_bytes = 0;
	__u16 payload_len;
	__u8 next_header;

	info->family = FAMILY_IPV6;
	if (l3_off > frame_len)
		return FAKETCP_L3_TRUNCATED;
	ip6 = data + l3_off;
	if ((void *)(ip6 + 1) > data_end)
		return FAKETCP_L3_TRUNCATED;
	if (ip6->version != 6)
		return FAKETCP_L3_MALFORMED;
	payload_len = bpf_ntohs(ip6->payload_len);
	total_len = sizeof(*ip6) + payload_len;
	if (total_len > frame_len - l3_off)
		return FAKETCP_L3_TRUNCATED;
	info->l3_len = total_len;
	info->l3_header_len = sizeof(*ip6);
	next_header = ip6->nexthdr;
	if (payload_len == 0) {
		info->transport_protocol = next_header;
		return next_header == NEXTHDR_NONE ? FAKETCP_L3_SAFE_BYPASS :
					       FAKETCP_L3_UNSUPPORTED;
	}
	header_off = l3_off + sizeof(*ip6);

#pragma unroll
	for (int depth = 0; depth <= FAKETCP_L3_MAX_EXTENSION_HEADERS; depth++) {
		if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
			info->l4_off = header_off;
			info->l4_len = l3_off + total_len - header_off;
			info->transport_protocol = next_header;
			return faketcp_l3_validate_transport(data, data_end,
						       frame_len, info);
		}
		if (next_header == IPPROTO_ICMPV6 || next_header == NEXTHDR_NONE) {
			info->l4_off = header_off;
			info->l4_len = l3_off + total_len - header_off;
			info->transport_protocol = next_header;
			return FAKETCP_L3_SAFE_BYPASS;
		}
		if (next_header == NEXTHDR_FRAGMENT) {
			struct faketcp_l3_ipv6_fragment *fragment;
			__u16 raw_fragment;

			if (depth == FAKETCP_L3_MAX_EXTENSION_HEADERS)
				return FAKETCP_L3_EXTENSION_TOO_DEEP;
			if (header_off > l3_off + total_len ||
			    sizeof(*fragment) > l3_off + total_len - header_off)
				return FAKETCP_L3_MALFORMED;
			fragment = data + header_off;
			if ((void *)(fragment + 1) > data_end)
				return FAKETCP_L3_TRUNCATED;
			raw_fragment = bpf_ntohs(fragment->fragment_offset);
			if (fragment->reserved || (raw_fragment & 0x0006))
				return FAKETCP_L3_MALFORMED;
			info->flags |= FAKETCP_L3_F_IPV6_EXTENSIONS |
				       FAKETCP_L3_F_FRAGMENT;
			info->extension_count++;
			info->transport_protocol = fragment->next_header;
			info->fragment_offset_bytes = raw_fragment & 0xfff8;
			if (raw_fragment & 1)
				info->flags |= FAKETCP_L3_F_MORE_FRAGMENTS;
			return info->fragment_offset_bytes ?
			       FAKETCP_L3_NONINITIAL_FRAGMENT :
			       FAKETCP_L3_FIRST_FRAGMENT;
		}
		if (next_header == NEXTHDR_HOP || next_header == NEXTHDR_ROUTING ||
		    next_header == NEXTHDR_DEST) {
			struct faketcp_l3_ipv6_extension *extension;
			__u32 extension_len;

			if (depth == FAKETCP_L3_MAX_EXTENSION_HEADERS)
				return FAKETCP_L3_EXTENSION_TOO_DEEP;
			if (next_header == NEXTHDR_HOP && depth != 0)
				return FAKETCP_L3_MALFORMED;
			if (header_off > l3_off + total_len ||
			    sizeof(*extension) > l3_off + total_len - header_off)
				return FAKETCP_L3_MALFORMED;
			extension = data + header_off;
			if ((void *)(extension + 1) > data_end)
				return FAKETCP_L3_TRUNCATED;
			extension_len = ((__u32)extension->header_length + 1) * 8;
			if (extension_len < 8 ||
			    extension_len > l3_off + total_len - header_off)
				return FAKETCP_L3_MALFORMED;
			if (data + header_off + extension_len > data_end)
				return FAKETCP_L3_TRUNCATED;
			extension_bytes += extension_len;
			if (extension_bytes > FAKETCP_L3_MAX_EXTENSION_BYTES)
				return FAKETCP_L3_EXTENSION_TOO_DEEP;
			info->flags |= FAKETCP_L3_F_IPV6_EXTENSIONS;
			info->extension_count++;
			next_header = extension->next_header;
			header_off += extension_len;
			continue;
		}
		if (next_header == NEXTHDR_AUTH) {
			struct faketcp_l3_ipv6_extension *auth;
			__u32 auth_len;

			if (depth == FAKETCP_L3_MAX_EXTENSION_HEADERS)
				return FAKETCP_L3_EXTENSION_TOO_DEEP;
			if (header_off > l3_off + total_len ||
			    sizeof(*auth) > l3_off + total_len - header_off)
				return FAKETCP_L3_MALFORMED;
			auth = data + header_off;
			if ((void *)(auth + 1) > data_end)
				return FAKETCP_L3_TRUNCATED;
			auth_len = ((__u32)auth->header_length + 2) * 4;
			if (auth_len < 12 || auth_len > l3_off + total_len - header_off)
				return FAKETCP_L3_MALFORMED;
			info->flags |= FAKETCP_L3_F_IPV6_EXTENSIONS;
			info->extension_count++;
			info->transport_protocol = next_header;
			return FAKETCP_L3_UNSUPPORTED;
		}
		// ESP, nested IP and every unrecognized next-header value are opaque
		// to this parser and therefore share one unsupported result.
		info->transport_protocol = next_header;
		return FAKETCP_L3_UNSUPPORTED;
	}
	return FAKETCP_L3_EXTENSION_TOO_DEEP;
}

static __always_inline int
faketcp_parse_l3(void *data, void *data_end, __u32 frame_len, __u32 l3_off,
		 __u8 family, struct faketcp_l3_info *info)
{
	__builtin_memset(info, 0, sizeof(*info));
	info->l3_off = l3_off;
	if (family == FAMILY_IPV4)
		return faketcp_parse_ipv4_l3(data, data_end, frame_len, l3_off, info);
	if (family == FAMILY_IPV6)
		return faketcp_parse_ipv6_l3(data, data_end, frame_len, l3_off, info);
	return FAKETCP_L3_MALFORMED;
}

#endif
