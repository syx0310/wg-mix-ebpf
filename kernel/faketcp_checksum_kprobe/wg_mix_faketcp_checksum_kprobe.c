// SPDX-License-Identifier: GPL-2.0-only
/*
 * Legacy FakeTCP checksum, PMTU and GSO bridge.
 *
 * Linux 5.15 predates sched_cls kfunc registration on several production
 * distributions.  This module exposes the same deliberately narrow packet
 * contract as wg_mix_faketcp_checksum through two kretprobes.  The BPF object
 * invokes helper inputs that the upstream helpers reject before changing the
 * skb; only an exact magic, a live per-open cookie and a complete descriptor
 * allow the return handler to replace that rejection with a bridge result.
 */
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/build_bug.h>
#include <linux/compat.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "wg_mix_faketcp_checksum_kprobe_uapi.h"

/* The first production compatibility gate is intentionally x86_64 Linux
 * 5.15.  Do not silently build an unvalidated calling-convention decoder on
 * another architecture.  KPROBES/KRETPROBES are hard module prerequisites,
 * not capabilities that may disappear after the device lease is issued.
 */
#if !defined(CONFIG_X86_64)
#error "wg_mix_faketcp_checksum_kprobe requires the validated x86_64 ABI"
#endif
#if !defined(CONFIG_KPROBES) || !defined(CONFIG_KRETPROBES) || \
	!defined(CONFIG_KALLSYMS)
#error "wg_mix_faketcp_checksum_kprobe requires KPROBES, KRETPROBES and KALLSYMS"
#endif

#define WG_MIX_FAKETCP_HEADER_DELTA 12U
#define WG_MIX_FAKETCP_MIN_SEGMENT_PAYLOAD 32U
#define WG_MIX_FAKETCP_MAX_INPUT_TOTAL_LEN \
	(U16_MAX - WG_MIX_FAKETCP_HEADER_DELTA)
#define WG_MIX_FAKETCP_KPROBE_MAX_LEASES 64U
#define WG_MIX_FAKETCP_KPROBE_COOKIE_ATTEMPTS 128U
#define WG_MIX_FAKETCP_KPROBE_MAXACTIVE 256

/* Stable result ABI shared with both FakeTCP BPF artifacts. */
enum wg_mix_faketcp_prepare_result {
	WG_MIX_FAKETCP_PREPARE_ACCEPT_NONE = 0,
	WG_MIX_FAKETCP_PREPARE_ACCEPT_PARTIAL_RESET = 1,
	WG_MIX_FAKETCP_PREPARE_ACCEPT_GSO = 2,
	WG_MIX_FAKETCP_PREPARE_REJECT_PACKET = -1,
	WG_MIX_FAKETCP_PREPARE_REJECT_STATE = -2,
	WG_MIX_FAKETCP_PREPARE_REJECT_METADATA = -3,
	WG_MIX_FAKETCP_PREPARE_REJECT_GSO_TYPE = -4,
	WG_MIX_FAKETCP_PREPARE_REJECT_GSO_GEOMETRY = -5,
	WG_MIX_FAKETCP_PREPARE_REJECT_WRITABLE = -6,
	WG_MIX_FAKETCP_PREPARE_REJECT_TRUNCATED = -7,
	WG_MIX_FAKETCP_PREPARE_REJECT_MTU_INVALID_INPUT = -8,
	WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ARITHMETIC_OVERFLOW = -9,
	WG_MIX_FAKETCP_PREPARE_REJECT_MTU_FRAGMENTATION_REJECTED = -10,
	WG_MIX_FAKETCP_PREPARE_REJECT_MTU_DEVICE_UNKNOWN = -11,
	WG_MIX_FAKETCP_PREPARE_REJECT_MTU_DEVICE_EXCEEDED = -12,
	WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ROUTE_UNKNOWN = -13,
	WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ROUTE_EXCEEDED = -14,
};

struct wg_mix_faketcp_udp_view {
	struct iphdr ip;
	u32 udp_length;
	u32 payload_length;
};

struct wg_mix_faketcp_kprobe_lease {
	u64 cookie;
	u64 errors_baseline;
	u64 nmissed_baseline;
	u32 slot;
};

struct wg_mix_faketcp_kprobe_descriptor {
	u64 cookie;
	u32 network_offset;
	u32 transport_offset;
	u32 value;
	u32 raw_cb[5];
};

static DEFINE_SPINLOCK(wg_mix_faketcp_lease_lock);
static u64 wg_mix_faketcp_active_cookies[WG_MIX_FAKETCP_KPROBE_MAX_LEASES];
static atomic64_t wg_mix_faketcp_prepare_hits = ATOMIC64_INIT(0);
static atomic64_t wg_mix_faketcp_commit_hits = ATOMIC64_INIT(0);
static atomic64_t wg_mix_faketcp_errors = ATOMIC64_INIT(0);
static bool wg_mix_faketcp_probes_ready;

static int wg_mix_faketcp_validate_udp_packet(
	struct sk_buff *skb, u32 network_offset, u32 transport_offset,
	u32 udp_length, struct wg_mix_faketcp_udp_view *view)
{
	struct iphdr ip_storage;
	struct udphdr udp_storage;
	const struct iphdr *ip;
	const struct udphdr *udp;
	int actual_network_offset;

	if (skb->protocol != htons(ETH_P_IP))
		return WG_MIX_FAKETCP_PREPARE_REJECT_PACKET;

	actual_network_offset = skb_network_offset(skb);
	if (actual_network_offset < 0 || network_offset != actual_network_offset)
		return WG_MIX_FAKETCP_PREPARE_REJECT_PACKET;
	if (network_offset > skb->len || transport_offset < network_offset ||
	    transport_offset > skb->len ||
	    transport_offset - network_offset != sizeof(struct iphdr) ||
	    udp_length < sizeof(struct udphdr) || udp_length > U16_MAX ||
	    udp_length != skb->len - transport_offset)
		return WG_MIX_FAKETCP_PREPARE_REJECT_TRUNCATED;

	ip = skb_header_pointer(skb, network_offset, sizeof(ip_storage),
				&ip_storage);
	udp = skb_header_pointer(skb, transport_offset, sizeof(udp_storage),
				 &udp_storage);
	if (!ip || !udp)
		return WG_MIX_FAKETCP_PREPARE_REJECT_TRUNCATED;
	if (ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_UDP ||
	    ntohs(ip->tot_len) != sizeof(*ip) + udp_length ||
	    ntohs(ip->tot_len) != skb->len - network_offset ||
	    ntohs(udp->len) != udp_length)
		return WG_MIX_FAKETCP_PREPARE_REJECT_PACKET;
	if (ip->frag_off & htons(IP_MF | IP_OFFSET))
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_FRAGMENTATION_REJECTED;
	if (ntohs(ip->tot_len) > WG_MIX_FAKETCP_MAX_INPUT_TOTAL_LEN)
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ARITHMETIC_OVERFLOW;

	view->ip = *ip;
	view->udp_length = udp_length;
	view->payload_length = udp_length - sizeof(*udp);
	return 0;
}

static int wg_mix_faketcp_validate_udp_checksum(
	struct sk_buff *skb, u32 transport_offset,
	const struct wg_mix_faketcp_udp_view *view)
{
	int actual_transport_offset;

	if (skb_is_gso(skb) || skb_shinfo(skb)->gso_type ||
	    skb_shinfo(skb)->gso_segs)
		return WG_MIX_FAKETCP_PREPARE_REJECT_GSO_TYPE;

	switch (skb->ip_summed) {
	case CHECKSUM_NONE:
		return WG_MIX_FAKETCP_PREPARE_ACCEPT_NONE;
	case CHECKSUM_PARTIAL:
		break;
	default:
		return WG_MIX_FAKETCP_PREPARE_REJECT_STATE;
	}
	if (!skb_transport_header_was_set(skb))
		return WG_MIX_FAKETCP_PREPARE_REJECT_METADATA;
	actual_transport_offset = skb_transport_offset(skb);
	if (actual_transport_offset < 0 ||
	    transport_offset != actual_transport_offset ||
	    skb_csum_is_sctp(skb) ||
	    skb_checksum_start_offset(skb) != transport_offset ||
	    skb->csum_offset != offsetof(struct udphdr, check) ||
	    skb->csum_offset > view->udp_length - sizeof(__sum16))
		return WG_MIX_FAKETCP_PREPARE_REJECT_METADATA;

	return WG_MIX_FAKETCP_PREPARE_ACCEPT_PARTIAL_RESET;
}

static int wg_mix_faketcp_admit_pmtu(struct sk_buff *skb,
				      u32 planned_l3_length)
{
	struct net_device *device = READ_ONCE(skb->dev);
	struct dst_entry *dst;
	u32 device_mtu;
	u32 route_mtu;

	if (planned_l3_length < sizeof(struct iphdr) + sizeof(struct tcphdr) ||
	    planned_l3_length > U16_MAX)
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_INVALID_INPUT;
	if (!device)
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_DEVICE_UNKNOWN;
	device_mtu = READ_ONCE(device->mtu);
	if (!device_mtu)
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_DEVICE_UNKNOWN;
	if (planned_l3_length > device_mtu)
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_DEVICE_EXCEEDED;

	if (!skb_valid_dst(skb))
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ROUTE_UNKNOWN;
	dst = skb_dst(skb);
	if (READ_ONCE(dst->dev) != device)
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ROUTE_UNKNOWN;
	route_mtu = dst_mtu(dst);
	if (!route_mtu)
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ROUTE_UNKNOWN;
	if (planned_l3_length > route_mtu)
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ROUTE_EXCEEDED;
	return 0;
}

static int wg_mix_faketcp_validate_udp_gso(
	struct sk_buff *skb, u32 transport_offset,
	const struct wg_mix_faketcp_udp_view *view,
	bool allow_dodgy_zero_segments)
{
	const unsigned int allowed_gso_type = SKB_GSO_UDP_L4 | SKB_GSO_DODGY;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	u32 expected_segments;
	int actual_transport_offset;

	if (!skb_is_gso(skb) || skb->encapsulation || shinfo->frag_list ||
	    !(shinfo->gso_type & SKB_GSO_UDP_L4) ||
	    shinfo->gso_type & ~allowed_gso_type)
		return WG_MIX_FAKETCP_PREPARE_REJECT_GSO_TYPE;

	if (!skb_transport_header_was_set(skb))
		return WG_MIX_FAKETCP_PREPARE_REJECT_METADATA;
	actual_transport_offset = skb_transport_offset(skb);
	if (actual_transport_offset < 0 ||
	    transport_offset != actual_transport_offset)
		return WG_MIX_FAKETCP_PREPARE_REJECT_METADATA;

	if (view->payload_length <= shinfo->gso_size ||
	    shinfo->gso_size < WG_MIX_FAKETCP_MIN_SEGMENT_PAYLOAD)
		return WG_MIX_FAKETCP_PREPARE_REJECT_GSO_GEOMETRY;
	expected_segments = DIV_ROUND_UP(view->payload_length, shinfo->gso_size);
	if ((shinfo->gso_segs != expected_segments &&
	     !(allow_dodgy_zero_segments && !shinfo->gso_segs &&
	       (shinfo->gso_type & SKB_GSO_DODGY))) ||
	    view->payload_length - (expected_segments - 1) * shinfo->gso_size <
		    WG_MIX_FAKETCP_MIN_SEGMENT_PAYLOAD)
		return WG_MIX_FAKETCP_PREPARE_REJECT_GSO_GEOMETRY;

	if (skb->ip_summed != CHECKSUM_PARTIAL || skb_csum_is_sctp(skb) ||
	    skb_checksum_start_offset(skb) != transport_offset ||
	    skb->csum_offset != offsetof(struct udphdr, check) ||
	    skb->csum_offset > view->udp_length - sizeof(__sum16))
		return WG_MIX_FAKETCP_PREPARE_REJECT_METADATA;

	return WG_MIX_FAKETCP_PREPARE_ACCEPT_GSO;
}

static void wg_mix_faketcp_rotate_gso_payload(struct sk_buff *skb,
					      u32 payload_offset,
					      u32 payload_length,
					      u32 gso_size)
{
	u8 saved[WG_MIX_FAKETCP_HEADER_DELTA];
	u8 *payload = skb->data + payload_offset;
	u32 processed = 0;

	while (processed < payload_length) {
		u32 segment_length = min(gso_size, payload_length - processed);
		u8 *segment = payload + processed;

		memcpy(saved, segment, sizeof(saved));
		memmove(segment, segment + sizeof(saved),
			segment_length - sizeof(saved));
		memcpy(segment + segment_length - sizeof(saved), saved,
		       sizeof(saved));
		processed += segment_length;
	}
}

static int wg_mix_faketcp_prepare_udp(struct sk_buff *skb,
				       u32 network_offset,
				       u32 transport_offset,
				       u32 udp_length)
{
	struct wg_mix_faketcp_udp_view view;
	u32 planned_l3_length;
	int admission;
	int ret;

	ret = wg_mix_faketcp_validate_udp_packet(skb, network_offset,
						 transport_offset, udp_length, &view);
	if (ret < 0)
		return ret;

	if (!skb_is_gso(skb)) {
		ret = wg_mix_faketcp_validate_udp_checksum(skb, transport_offset,
						     &view);
		if (ret < 0)
			return ret;
		if (ntohs(view.ip.tot_len) >
		    U16_MAX - WG_MIX_FAKETCP_HEADER_DELTA)
			return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ARITHMETIC_OVERFLOW;
		planned_l3_length = ntohs(view.ip.tot_len) +
				    WG_MIX_FAKETCP_HEADER_DELTA;
		admission = wg_mix_faketcp_admit_pmtu(skb,
						       planned_l3_length);
		if (admission < 0)
			return admission;
		if (ret == WG_MIX_FAKETCP_PREPARE_ACCEPT_NONE)
			return ret;

		skb->csum = 0;
		skb->csum_valid = 0;
		skb->csum_complete_sw = 0;
		skb->csum_level = 0;
		/* skb_reset_csum_not_inet() is newer than Linux 5.15. */
		skb->csum_not_inet = 0;
		skb->ip_summed = CHECKSUM_NONE;
		return WG_MIX_FAKETCP_PREPARE_ACCEPT_PARTIAL_RESET;
	}

	ret = wg_mix_faketcp_validate_udp_gso(skb, transport_offset, &view,
					       true);
	if (ret != WG_MIX_FAKETCP_PREPARE_ACCEPT_GSO)
		return ret;
	if (skb_shinfo(skb)->gso_size >
	    U16_MAX - sizeof(struct iphdr) - sizeof(struct tcphdr))
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ARITHMETIC_OVERFLOW;
	planned_l3_length = sizeof(struct iphdr) + sizeof(struct tcphdr) +
			    skb_shinfo(skb)->gso_size;
	admission = wg_mix_faketcp_admit_pmtu(skb, planned_l3_length);
	if (admission < 0)
		return admission;
	if (skb_shared(skb))
		return WG_MIX_FAKETCP_PREPARE_REJECT_WRITABLE;
	if (skb_linearize_cow(skb) < 0)
		return WG_MIX_FAKETCP_PREPARE_REJECT_WRITABLE;
	if (skb_cow_head(skb, WG_MIX_FAKETCP_HEADER_DELTA) < 0 ||
	    skb_headroom(skb) < WG_MIX_FAKETCP_HEADER_DELTA ||
	    skb_is_nonlinear(skb))
		return WG_MIX_FAKETCP_PREPARE_REJECT_WRITABLE;

	ret = wg_mix_faketcp_validate_udp_packet(skb, network_offset,
						 transport_offset, udp_length, &view);
	if (ret < 0)
		return ret;
	ret = wg_mix_faketcp_validate_udp_gso(skb, transport_offset, &view,
					       true);
	if (ret != WG_MIX_FAKETCP_PREPARE_ACCEPT_GSO)
		return ret;
	skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(
		view.payload_length, skb_shinfo(skb)->gso_size);
	return WG_MIX_FAKETCP_PREPARE_ACCEPT_GSO;
}

static int wg_mix_faketcp_commit_udp_gso(struct sk_buff *skb,
					  u32 network_offset,
					  u32 transport_offset,
					  u32 sequence,
					  u64 ack_window)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	struct wg_mix_faketcp_udp_view view;
	struct udphdr old_udp;
	struct iphdr *ip;
	struct tcphdr *tcp;
	u32 udp_length;
	u32 payload_length;
	u32 header_length;
	u32 gso_size;
	u32 gso_modifier;
	u32 acknowledgement = (u32)ack_window;
	u16 window = (u16)(ack_window >> 32);
	int ret;

	if (transport_offset > skb->len ||
	    skb->len - transport_offset > U16_MAX)
		return WG_MIX_FAKETCP_PREPARE_REJECT_TRUNCATED;
	udp_length = skb->len - transport_offset;
	ret = wg_mix_faketcp_validate_udp_packet(skb, network_offset,
						 transport_offset, udp_length, &view);
	if (ret < 0)
		return ret;
	ret = wg_mix_faketcp_validate_udp_gso(skb, transport_offset, &view,
					       false);
	if (ret != WG_MIX_FAKETCP_PREPARE_ACCEPT_GSO)
		return ret;
	if (skb_shared(skb) || skb_cloned(skb) || skb_header_cloned(skb) ||
	    skb_is_nonlinear(skb) ||
	    skb_headroom(skb) < WG_MIX_FAKETCP_HEADER_DELTA)
		return WG_MIX_FAKETCP_PREPARE_REJECT_WRITABLE;

	header_length = transport_offset + sizeof(old_udp);
	payload_length = view.payload_length;
	gso_size = shinfo->gso_size;
	gso_modifier = shinfo->gso_type & SKB_GSO_DODGY;
	memcpy(&old_udp, skb->data + transport_offset, sizeof(old_udp));
	wg_mix_faketcp_rotate_gso_payload(skb, header_length, payload_length,
					    gso_size);

	skb_push(skb, WG_MIX_FAKETCP_HEADER_DELTA);
	memmove(skb->data, skb->data + WG_MIX_FAKETCP_HEADER_DELTA,
		header_length);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, network_offset);
	skb_set_transport_header(skb, transport_offset);
	skb_reset_mac_len(skb);

	ip = ip_hdr(skb);
	tcp = tcp_hdr(skb);
	memset(tcp, 0, sizeof(*tcp));
	tcp->source = old_udp.source;
	tcp->dest = old_udp.dest;
	tcp->seq = htonl(sequence);
	tcp->ack_seq = htonl(acknowledgement);
	tcp->doff = sizeof(*tcp) / sizeof(u32);
	tcp->ack = 1;
	tcp->psh = 1;
	tcp->window = htons(window ? window : U16_MAX);

	ip->protocol = IPPROTO_TCP;
	ip->tot_len = htons(ntohs(ip->tot_len) + WG_MIX_FAKETCP_HEADER_DELTA);
	ip_send_check(ip);

	skb->csum = 0;
	skb->csum_valid = 0;
	skb->csum_complete_sw = 0;
	skb->csum_level = 0;
	skb->csum_not_inet = 0;
	skb->ip_summed = CHECKSUM_PARTIAL;
	tcp->check = ~tcp_v4_check(sizeof(*tcp) + payload_length,
				  ip->saddr, ip->daddr, 0);
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);

	shinfo = skb_shinfo(skb);
	shinfo->gso_type = SKB_GSO_TCPV4 | gso_modifier;
	shinfo->gso_size = gso_size;
	shinfo->gso_segs = DIV_ROUND_UP(payload_length, gso_size);
	skb_clear_hash(skb);
	return 0;
}

static void wg_mix_faketcp_snapshot_descriptor(
	struct sk_buff *skb, struct wg_mix_faketcp_kprobe_descriptor *descriptor)
{
	/* TC exposes __sk_buff.cb through qdisc_skb_cb(skb)->data.  The 5.15
	 * bpf_skb_cb() accessor is the sole supported bridge to that region;
	 * struct sk_buff::cb is qdisc-private storage with a different layout.
	 */
	u8 *cb = bpf_skb_cb(skb);

	memcpy(descriptor->raw_cb, cb, sizeof(descriptor->raw_cb));
	memcpy(&descriptor->cookie,
	       (u8 *)descriptor->raw_cb +
		WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_COOKIE_OFFSET,
	       sizeof(descriptor->cookie));
	memcpy(&descriptor->network_offset,
	       (u8 *)descriptor->raw_cb +
		WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_NETWORK_OFFSET,
	       sizeof(descriptor->network_offset));
	memcpy(&descriptor->transport_offset,
	       (u8 *)descriptor->raw_cb +
		WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_TRANSPORT_OFFSET,
	       sizeof(descriptor->transport_offset));
	memcpy(&descriptor->value,
	       (u8 *)descriptor->raw_cb +
		WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_VALUE_OFFSET,
	       sizeof(descriptor->value));
}

static bool wg_mix_faketcp_descriptor_unchanged(
	struct sk_buff *skb,
	const struct wg_mix_faketcp_kprobe_descriptor *descriptor)
{
	return !memcmp(bpf_skb_cb(skb), descriptor->raw_cb,
		       sizeof(descriptor->raw_cb));
}

static void wg_mix_faketcp_clear_descriptor(struct sk_buff *skb)
{
	memset(bpf_skb_cb(skb), 0,
	       WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_SIZE);
}

static bool wg_mix_faketcp_cookie_active(u64 cookie)
{
	unsigned long irq_flags;
	u32 index;
	bool found = false;

	if (!cookie)
		return false;
	spin_lock_irqsave(&wg_mix_faketcp_lease_lock, irq_flags);
	for (index = 0; index < WG_MIX_FAKETCP_KPROBE_MAX_LEASES; index++) {
		if (wg_mix_faketcp_active_cookies[index] == cookie) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&wg_mix_faketcp_lease_lock, irq_flags);
	return found;
}

struct wg_mix_faketcp_change_type_parameters {
	struct sk_buff *skb;
	u32 type;
	struct wg_mix_faketcp_kprobe_descriptor descriptor;
};

static int wg_mix_faketcp_change_type_entry(struct kretprobe_instance *ri,
					     struct pt_regs *regs)
{
	struct wg_mix_faketcp_change_type_parameters *parameters = ri->data;

	parameters->skb = (struct sk_buff *)regs_get_kernel_argument(regs, 0);
	parameters->type = (u32)regs_get_kernel_argument(regs, 1);
	/* A non-zero entry return skips this instance's return handler.  Do that
	 * for every unrelated helper invocation so the bridge never interprets or
	 * mutates it as one of our trigger calls.
	 */
	if (!parameters->skb ||
	    parameters->type != WG_MIX_FAKETCP_KPROBE_PREPARE_MAGIC)
		return 1;
	wg_mix_faketcp_snapshot_descriptor(parameters->skb,
					    &parameters->descriptor);
	if (!wg_mix_faketcp_cookie_active(parameters->descriptor.cookie))
		return 1;
	return 0;
}
NOKPROBE_SYMBOL(wg_mix_faketcp_change_type_entry);

static int wg_mix_faketcp_change_type_return(struct kretprobe_instance *ri,
					      struct pt_regs *regs)
{
	struct wg_mix_faketcp_change_type_parameters *parameters = ri->data;
	int result;

	/* Linux 5.15 bpf_skb_change_type rejects an invalid pkt_type with
	 * -EINVAL before assigning skb->pkt_type.  Never take over another result.
	 */
	if ((long)regs_return_value(regs) != -EINVAL || !parameters->skb ||
	    parameters->type != WG_MIX_FAKETCP_KPROBE_PREPARE_MAGIC)
		return 0;
	if (!wg_mix_faketcp_descriptor_unchanged(parameters->skb,
						 &parameters->descriptor) ||
	    !wg_mix_faketcp_cookie_active(parameters->descriptor.cookie)) {
		atomic64_inc(&wg_mix_faketcp_errors);
		return 0;
	}

	/* Consume the short-lived capability before any packet mutation.  The BPF
	 * caller also clears cb unconditionally after the helper returns, including
	 * the missed-probe path.
	 */
	wg_mix_faketcp_clear_descriptor(parameters->skb);
	result = wg_mix_faketcp_prepare_udp(
		parameters->skb, parameters->descriptor.network_offset,
		parameters->descriptor.transport_offset,
		parameters->descriptor.value);
	atomic64_inc(&wg_mix_faketcp_prepare_hits);
	regs_set_return_value(regs, (unsigned long)result);
	return 0;
}
NOKPROBE_SYMBOL(wg_mix_faketcp_change_type_return);

struct wg_mix_faketcp_change_proto_parameters {
	struct sk_buff *skb;
	__be16 proto;
	u64 flags;
	struct wg_mix_faketcp_kprobe_descriptor descriptor;
};

static int wg_mix_faketcp_change_proto_entry(struct kretprobe_instance *ri,
					      struct pt_regs *regs)
{
	struct wg_mix_faketcp_change_proto_parameters *parameters = ri->data;

	parameters->skb = (struct sk_buff *)regs_get_kernel_argument(regs, 0);
	parameters->proto = (__be16)regs_get_kernel_argument(regs, 1);
	parameters->flags = (u64)regs_get_kernel_argument(regs, 2);
	if (!parameters->skb ||
	    parameters->proto !=
		(__be16)WG_MIX_FAKETCP_KPROBE_COMMIT_PROTO_MAGIC ||
	    !parameters->flags)
		return 1;
	wg_mix_faketcp_snapshot_descriptor(parameters->skb,
					    &parameters->descriptor);
	if (!wg_mix_faketcp_cookie_active(parameters->descriptor.cookie))
		return 1;
	return 0;
}
NOKPROBE_SYMBOL(wg_mix_faketcp_change_proto_entry);

static int wg_mix_faketcp_change_proto_return(struct kretprobe_instance *ri,
					       struct pt_regs *regs)
{
	struct wg_mix_faketcp_change_proto_parameters *parameters = ri->data;
	int result;

	/* Linux 5.15 bpf_skb_change_proto checks non-zero flags first and returns
	 * -EINVAL before protocol translation or bpf_compute_data_pointers().
	 * ack_window always contains a non-zero 16-bit window in bits 32..47.
	 */
	if ((long)regs_return_value(regs) != -EINVAL || !parameters->skb ||
	    parameters->proto !=
		(__be16)WG_MIX_FAKETCP_KPROBE_COMMIT_PROTO_MAGIC ||
	    !parameters->flags)
		return 0;
	if (!wg_mix_faketcp_descriptor_unchanged(parameters->skb,
						 &parameters->descriptor) ||
	    !wg_mix_faketcp_cookie_active(parameters->descriptor.cookie)) {
		atomic64_inc(&wg_mix_faketcp_errors);
		return 0;
	}

	wg_mix_faketcp_clear_descriptor(parameters->skb);
	result = wg_mix_faketcp_commit_udp_gso(
		parameters->skb, parameters->descriptor.network_offset,
		parameters->descriptor.transport_offset,
		parameters->descriptor.value, parameters->flags);
	atomic64_inc(&wg_mix_faketcp_commit_hits);
	regs_set_return_value(regs, (unsigned long)result);
	return 0;
}
NOKPROBE_SYMBOL(wg_mix_faketcp_change_proto_return);

static struct kretprobe wg_mix_faketcp_change_type_probe = {
	.kp.symbol_name = "bpf_skb_change_type",
	.entry_handler = wg_mix_faketcp_change_type_entry,
	.handler = wg_mix_faketcp_change_type_return,
	.data_size = sizeof(struct wg_mix_faketcp_change_type_parameters),
};

static struct kretprobe wg_mix_faketcp_change_proto_probe = {
	.kp.symbol_name = "bpf_skb_change_proto",
	.entry_handler = wg_mix_faketcp_change_proto_entry,
	.handler = wg_mix_faketcp_change_proto_return,
	.data_size = sizeof(struct wg_mix_faketcp_change_proto_parameters),
};

static struct kretprobe *wg_mix_faketcp_probes[] = {
	&wg_mix_faketcp_change_type_probe,
	&wg_mix_faketcp_change_proto_probe,
};

static u64 wg_mix_faketcp_nmissed(void)
{
	return (u64)READ_ONCE(wg_mix_faketcp_change_type_probe.nmissed) +
	       (u64)READ_ONCE(wg_mix_faketcp_change_proto_probe.nmissed);
}

static u64 wg_mix_faketcp_counter_delta(u64 current, u64 baseline)
{
	/* The counters are monotonic for the complete module lifetime.  Report an
	 * impossible regression as maximally unhealthy instead of wrapping to a
	 * deceptively small delta.
	 */
	if (current < baseline)
		return U64_MAX;
	return current - baseline;
}

static int wg_mix_faketcp_configure_maxactive(void)
{
	/* nr_cpu_ids is fixed after SMP bring-up and is a constant on UP builds;
	 * a plain read therefore works for both Linux 5.15 definitions.
	 */
	unsigned int cpu_ids = nr_cpu_ids;
	unsigned int maxactive;

	if (cpu_ids > INT_MAX / 2U)
		return -EOVERFLOW;
	maxactive = max_t(unsigned int, WG_MIX_FAKETCP_KPROBE_MAXACTIVE,
			 2U * cpu_ids);
	if (maxactive > INT_MAX)
		return -EOVERFLOW;
	wg_mix_faketcp_change_type_probe.maxactive = (int)maxactive;
	wg_mix_faketcp_change_proto_probe.maxactive = (int)maxactive;
	return 0;
}

static int wg_mix_faketcp_insert_cookie(struct wg_mix_faketcp_kprobe_lease *lease)
{
	unsigned long irq_flags;
	u32 attempt;

	for (attempt = 0; attempt < WG_MIX_FAKETCP_KPROBE_COOKIE_ATTEMPTS;
	     attempt++) {
		u64 cookie = get_random_u64();
		u32 free_slot = WG_MIX_FAKETCP_KPROBE_MAX_LEASES;
		u32 index;
		bool duplicate = false;

		if (!cookie)
			continue;
		spin_lock_irqsave(&wg_mix_faketcp_lease_lock, irq_flags);
		for (index = 0; index < WG_MIX_FAKETCP_KPROBE_MAX_LEASES;
		     index++) {
			if (wg_mix_faketcp_active_cookies[index] == cookie) {
				duplicate = true;
				break;
			}
			if (!wg_mix_faketcp_active_cookies[index] &&
			    free_slot == WG_MIX_FAKETCP_KPROBE_MAX_LEASES)
				free_slot = index;
		}
		if (!duplicate && free_slot < WG_MIX_FAKETCP_KPROBE_MAX_LEASES) {
			wg_mix_faketcp_active_cookies[free_slot] = cookie;
			lease->cookie = cookie;
			lease->slot = free_slot;
			spin_unlock_irqrestore(&wg_mix_faketcp_lease_lock,
					       irq_flags);
			return 0;
		}
		spin_unlock_irqrestore(&wg_mix_faketcp_lease_lock, irq_flags);
		if (!duplicate)
			return -EMFILE;
	}
	return -EAGAIN;
}

static int wg_mix_faketcp_device_open(struct inode *inode, struct file *file)
{
	struct wg_mix_faketcp_kprobe_lease *lease;
	int ret;

	lease = kzalloc(sizeof(*lease), GFP_KERNEL);
	if (!lease)
		return -ENOMEM;
	ret = wg_mix_faketcp_insert_cookie(lease);
	if (ret) {
		kfree(lease);
		return ret;
	}
	/* A newly issued cookie cannot be used until this open file description
	 * returns it via GET_STATUS and userspace installs it into its BPF map.
	 * Snapshot after insertion so the first status is relative to this lease,
	 * while global prepare/commit hit counters remain observable.
	 */
	lease->errors_baseline = atomic64_read(&wg_mix_faketcp_errors);
	lease->nmissed_baseline = wg_mix_faketcp_nmissed();
	file->private_data = lease;
	return 0;
}

static int wg_mix_faketcp_device_release(struct inode *inode,
					 struct file *file)
{
	struct wg_mix_faketcp_kprobe_lease *lease = file->private_data;
	unsigned long irq_flags;

	if (!lease)
		return 0;
	spin_lock_irqsave(&wg_mix_faketcp_lease_lock, irq_flags);
	if (lease->slot < WG_MIX_FAKETCP_KPROBE_MAX_LEASES &&
	    wg_mix_faketcp_active_cookies[lease->slot] == lease->cookie)
		wg_mix_faketcp_active_cookies[lease->slot] = 0;
	else
		atomic64_inc(&wg_mix_faketcp_errors);
	spin_unlock_irqrestore(&wg_mix_faketcp_lease_lock, irq_flags);
	file->private_data = NULL;
	memzero_explicit(lease, sizeof(*lease));
	kfree(lease);
	return 0;
}

static long wg_mix_faketcp_device_ioctl(struct file *file, unsigned int command,
					unsigned long argument)
{
	struct wg_mix_faketcp_kprobe_lease *lease = file->private_data;
	struct wg_mix_faketcp_checksum_kprobe_status_v1 status = { };
	u64 nmissed;
	u64 errors;

	if (command != WG_MIX_FAKETCP_CHECKSUM_KPROBE_GET_STATUS)
		return -ENOTTY;
	if (!lease || !wg_mix_faketcp_cookie_active(lease->cookie))
		return -ENXIO;

	nmissed = wg_mix_faketcp_counter_delta(
		wg_mix_faketcp_nmissed(), lease->nmissed_baseline);
	errors = wg_mix_faketcp_counter_delta(
		atomic64_read(&wg_mix_faketcp_errors), lease->errors_baseline);
	status.abi_version = WG_MIX_FAKETCP_CHECKSUM_KPROBE_ABI_VERSION;
	status.struct_size = sizeof(status);
	status.capabilities = WG_MIX_FAKETCP_KPROBE_CAP_CHECKSUM_STATE |
		WG_MIX_FAKETCP_KPROBE_CAP_PARTIAL_RESET |
		WG_MIX_FAKETCP_KPROBE_CAP_PMTU |
		WG_MIX_FAKETCP_KPROBE_CAP_UDP_GSO_TO_TCP |
		WG_MIX_FAKETCP_KPROBE_CAP_FAIL_CLOSED |
		WG_MIX_FAKETCP_KPROBE_CAP_MULTI_LEASE;
	status.cookie = lease->cookie;
	status.hits_prepare = atomic64_read(&wg_mix_faketcp_prepare_hits);
	status.hits_commit = atomic64_read(&wg_mix_faketcp_commit_hits);
	status.errors = errors;
	status.nmissed = nmissed;
	status.flags = WG_MIX_FAKETCP_KPROBE_STATUS_F_LEASE_ACTIVE;
	if (READ_ONCE(wg_mix_faketcp_probes_ready))
		status.flags |= WG_MIX_FAKETCP_KPROBE_STATUS_F_PROBES_READY;
	if (READ_ONCE(wg_mix_faketcp_probes_ready) && !nmissed && !errors)
		status.flags |= WG_MIX_FAKETCP_KPROBE_STATUS_F_HEALTHY;

	if (copy_to_user((void __user *)argument, &status, sizeof(status)))
		return -EFAULT;
	return 0;
}

#ifdef CONFIG_COMPAT
static long wg_mix_faketcp_device_compat_ioctl(struct file *file,
					       unsigned int command,
					       unsigned long argument)
{
	return wg_mix_faketcp_device_ioctl(
		file, command, (unsigned long)compat_ptr(argument));
}
#endif

static const struct file_operations wg_mix_faketcp_device_operations = {
	.owner = THIS_MODULE,
	.open = wg_mix_faketcp_device_open,
	.release = wg_mix_faketcp_device_release,
	.unlocked_ioctl = wg_mix_faketcp_device_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = wg_mix_faketcp_device_compat_ioctl,
#endif
	.llseek = no_llseek,
};

static struct miscdevice wg_mix_faketcp_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = WG_MIX_FAKETCP_CHECKSUM_KPROBE_DEVICE_NAME,
	.fops = &wg_mix_faketcp_device_operations,
	.mode = 0600,
};

static int __init wg_mix_faketcp_checksum_kprobe_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct wg_mix_faketcp_checksum_kprobe_status_v1) !=
		     64);
	BUILD_BUG_ON(WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_SIZE != 5 * sizeof(u32));
	BUILD_BUG_ON(WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_SIZE > BPF_SKB_CB_LEN);
	BUILD_BUG_ON(WG_MIX_FAKETCP_KPROBE_PREPARE_MAGIC <= PACKET_OTHERHOST);

	ret = wg_mix_faketcp_configure_maxactive();
	if (ret)
		return ret;
	ret = register_kretprobes(wg_mix_faketcp_probes,
				  ARRAY_SIZE(wg_mix_faketcp_probes));
	if (ret)
		return ret;
	WRITE_ONCE(wg_mix_faketcp_probes_ready, true);
	ret = misc_register(&wg_mix_faketcp_device);
	if (ret) {
		WRITE_ONCE(wg_mix_faketcp_probes_ready, false);
		unregister_kretprobes(wg_mix_faketcp_probes,
				      ARRAY_SIZE(wg_mix_faketcp_probes));
		return ret;
	}
	return 0;
}

static void __exit wg_mix_faketcp_checksum_kprobe_exit(void)
{
	misc_deregister(&wg_mix_faketcp_device);
	WRITE_ONCE(wg_mix_faketcp_probes_ready, false);
	unregister_kretprobes(wg_mix_faketcp_probes,
				      ARRAY_SIZE(wg_mix_faketcp_probes));
}

module_init(wg_mix_faketcp_checksum_kprobe_init);
module_exit(wg_mix_faketcp_checksum_kprobe_exit);

MODULE_DESCRIPTION("wg-mix-ebpf legacy FakeTCP checksum, PMTU and GSO bridge");
MODULE_LICENSE("GPL");
