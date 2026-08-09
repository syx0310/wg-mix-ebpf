// SPDX-License-Identifier: MIT
#ifndef WG_MIX_FAKETCP_MTU_H
#define WG_MIX_FAKETCP_MTU_H

#include <linux/version.h>

#define FAKETCP_FIB_AF_INET  2
#define FAKETCP_FIB_AF_INET6 10

// These two orthogonal axes mirror internal/faketcp.MTUError. The array key is
// reason * FAKETCP_MTU_BOUNDARY_MAX + boundary, so operators can distinguish
// route/device failures without multiplying the reason taxonomy.
enum faketcp_mtu_reason {
	FAKETCP_MTU_INVALID_INPUT = 0,
	FAKETCP_MTU_ARITHMETIC_OVERFLOW,
	FAKETCP_MTU_FRAGMENTATION_REJECTED,
	FAKETCP_MTU_UNKNOWN,
	FAKETCP_MTU_EXCEEDED,
	FAKETCP_MTU_REASON_MAX,
};

enum faketcp_mtu_boundary {
	FAKETCP_MTU_BOUNDARY_INPUT = 0,
	FAKETCP_MTU_BOUNDARY_DEVICE,
	FAKETCP_MTU_BOUNDARY_ROUTE,
	FAKETCP_MTU_BOUNDARY_MAX,
};

#define FAKETCP_MTU_F_IPV4_DF       (1U << 0)
#define FAKETCP_MTU_F_IPV4_MF       (1U << 1)
#define FAKETCP_MTU_F_NONINITIAL    (1U << 2)
#define FAKETCP_MTU_F_IPV6_FRAGMENT (1U << 3)
#define FAKETCP_MTU_F_GSO           (1U << 4)
#define FAKETCP_MTU_F_MASK           ((1U << 5) - 1)

struct faketcp_mtu_request {
	__u32 input_l3_len;
	__u32 input_segment_l3_len;
	__u32 ifindex;
	__u32 mark;
	__be16 source_port;
	__be16 destination_port;
	__u8 family;
	__u8 flags;
	__u8 tos;
	__u8 pad;
	__be32 flowinfo;
	union {
		struct {
			__be32 source;
			__be32 destination;
		} ipv4;
		struct {
			__u32 source[4];
			__u32 destination[4];
		} ipv6;
	} addresses;
};

_Static_assert(sizeof(struct faketcp_mtu_request) == 60,
	       "faketcp MTU request layout drift");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FAKETCP_MTU_REASON_MAX * FAKETCP_MTU_BOUNDARY_MAX);
	__type(key, __u32);
	__type(value, __u64);
} faketcp_mtu_audit_map SEC(".maps");

static __always_inline int faketcp_mtu_reject(__u32 reason, __u32 boundary)
{
	__u32 key;
	__u64 *counter;

	if (reason >= FAKETCP_MTU_REASON_MAX ||
	    boundary >= FAKETCP_MTU_BOUNDARY_MAX)
		return 0;
	key = reason * FAKETCP_MTU_BOUNDARY_MAX + boundary;
	counter = bpf_map_lookup_elem(&faketcp_mtu_audit_map, &key);
	if (counter)
		*counter += 1;
	inc_faketcp_stat(FAKETCP_STAT_MTU_REJECT);
	return 0;
}

// One admission function owns every MTU decision. Callers pass the largest
// pre-transform wire segment: the complete L3 length for non-GSO and the
// maximum future segment L3 length for GSO. Both device and marked-route
// checks use the exact post-transform segment length; FakeTCP never falls back
// to IP fragmentation.
static __always_inline int
faketcp_mtu_admit(struct __sk_buff *skb,
		  const struct faketcp_mtu_request *request)
{
	struct bpf_fib_lookup fib = {};
	__u32 planned_l3_len;
	__u32 device_mtu;
	__u32 fib_flags = BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_SKIP_NEIGH;
	long rc;

	if (!request || request->ifindex == 0 || request->ifindex != skb->ifindex ||
	    request->flags & ~FAKETCP_MTU_F_MASK)
		return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	if (request->family == FAMILY_IPV4) {
		if (request->flags & FAKETCP_MTU_F_IPV6_FRAGMENT)
			return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
						   FAKETCP_MTU_BOUNDARY_INPUT);
		if (request->input_segment_l3_len < sizeof(struct iphdr) +
						       sizeof(struct udphdr))
			return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
						   FAKETCP_MTU_BOUNDARY_INPUT);
	} else if (request->family == FAMILY_IPV6) {
		if (request->flags & (FAKETCP_MTU_F_IPV4_DF |
				      FAKETCP_MTU_F_IPV4_MF))
			return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
						   FAKETCP_MTU_BOUNDARY_INPUT);
		if (request->input_segment_l3_len < sizeof(struct ipv6hdr) +
						       sizeof(struct udphdr))
			return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
						   FAKETCP_MTU_BOUNDARY_INPUT);
	} else {
		return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	}
	if (request->flags & (FAKETCP_MTU_F_IPV4_MF |
			      FAKETCP_MTU_F_NONINITIAL |
			      FAKETCP_MTU_F_IPV6_FRAGMENT))
		return faketcp_mtu_reject(FAKETCP_MTU_FRAGMENTATION_REJECTED,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	if (request->flags & FAKETCP_MTU_F_GSO) {
		if (!skb->gso_size || !skb->gso_segs ||
		    request->input_segment_l3_len > request->input_l3_len)
			return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
						   FAKETCP_MTU_BOUNDARY_INPUT);
	} else if (skb->gso_size || skb->gso_segs ||
		   request->input_segment_l3_len != request->input_l3_len) {
		return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	}
	if (request->input_segment_l3_len > 0xffffffffU -
						    FAKETCP_HEADER_DELTA)
		return faketcp_mtu_reject(FAKETCP_MTU_ARITHMETIC_OVERFLOW,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	if (request->input_l3_len > 0xffffU)
		return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	planned_l3_len = request->input_segment_l3_len + FAKETCP_HEADER_DELTA;
	if (planned_l3_len > 0xffffU)
		return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
					   FAKETCP_MTU_BOUNDARY_INPUT);

	// Passing the explicit largest future segment avoids treating the GSO
	// aggregate length as a wire packet. A negative result or a zero returned
	// MTU means the device limit is unknown and is never guessed.
	device_mtu = planned_l3_len;
	rc = bpf_check_mtu(skb, request->ifindex, &device_mtu, 0, 0);
	if (rc == BPF_MTU_CHK_RET_FRAG_NEEDED ||
	    rc == BPF_MTU_CHK_RET_SEGS_TOOBIG ||
	    (rc == BPF_MTU_CHK_RET_SUCCESS && planned_l3_len > device_mtu))
		return faketcp_mtu_reject(FAKETCP_MTU_EXCEEDED,
					   FAKETCP_MTU_BOUNDARY_DEVICE);
	if (rc != BPF_MTU_CHK_RET_SUCCESS || device_mtu == 0)
		return faketcp_mtu_reject(FAKETCP_MTU_UNKNOWN,
					   FAKETCP_MTU_BOUNDARY_DEVICE);

	fib.family = request->family == FAMILY_IPV4 ?
		     FAKETCP_FIB_AF_INET : FAKETCP_FIB_AF_INET6;
	fib.l4_protocol = IPPROTO_TCP;
	fib.sport = request->source_port;
	fib.dport = request->destination_port;
	fib.tot_len = (__u16)planned_l3_len;
	fib.ifindex = request->ifindex;
	if (request->family == FAMILY_IPV4) {
		fib.tos = request->tos;
		fib.ipv4_src = request->addresses.ipv4.source;
		fib.ipv4_dst = request->addresses.ipv4.destination;
	} else {
		fib.flowinfo = request->flowinfo;
#pragma unroll
		for (int i = 0; i < 4; i++) {
			fib.ipv6_src[i] = request->addresses.ipv6.source[i];
			fib.ipv6_dst[i] = request->addresses.ipv6.destination[i];
		}
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
	// BPF_FIB_LOOKUP_MARK and the input mark field entered the UAPI together.
	// The full lookup must observe the same policy-routing mark as the skb.
	fib.mark = request->mark;
	fib_flags |= BPF_FIB_LOOKUP_MARK;
#else
	// An older build header cannot express marked policy routing. Refusing a
	// marked packet is the only non-ambiguous behavior; the capability remains
	// evidence-gated on the Linux 7.0 target build.
	if (request->mark != 0)
		return faketcp_mtu_reject(FAKETCP_MTU_UNKNOWN,
					   FAKETCP_MTU_BOUNDARY_ROUTE);
#endif

	rc = bpf_fib_lookup(skb, &fib, sizeof(fib), fib_flags);
	if (rc == BPF_FIB_LKUP_RET_FRAG_NEEDED)
		return faketcp_mtu_reject(FAKETCP_MTU_EXCEEDED,
					   FAKETCP_MTU_BOUNDARY_ROUTE);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS || fib.ifindex != request->ifindex)
		return faketcp_mtu_reject(FAKETCP_MTU_UNKNOWN,
					   FAKETCP_MTU_BOUNDARY_ROUTE);
	return 1;
}

#endif
