// SPDX-License-Identifier: GPL-2.0-only
/*
 * Narrow checksum, PMTU and GSO bridge for the experimental FakeTCP TC
 * encoder.
 *
 * The TC UAPI context intentionally does not expose ip_summed, csum_start or
 * csum_offset. This kfunc validates the one packet shape the encoder supports
 * before admitting a materialized CHECKSUM_NONE packet or discarding a UDP
 * CHECKSUM_PARTIAL request whose checksum field will be replaced by a TCP
 * checksum. The GSO path additionally admits one exact UDP_L4 shape, prepares
 * writable storage and commits it as TCPv4 GSO. It is not a general skb
 * metadata write primitive.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <net/ip.h>
#include <net/tcp.h>

#define WG_MIX_FAKETCP_HEADER_DELTA 12U
#define WG_MIX_FAKETCP_MIN_SEGMENT_PAYLOAD 32U
#define WG_MIX_FAKETCP_MAX_INPUT_TOTAL_LEN \
	(U16_MAX - WG_MIX_FAKETCP_HEADER_DELTA)

/* Stable result ABI shared with the experimental BPF object. */
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
	WG_MIX_FAKETCP_PREPARE_REJECT_MTU_FRAGMENTATION = -10,
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
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_FRAGMENTATION;
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
		/* Raw/IP_HDRINCL reinjection already carries materialized bytes. */
		return WG_MIX_FAKETCP_PREPARE_ACCEPT_NONE;
	case CHECKSUM_PARTIAL:
		break;
	default:
		return WG_MIX_FAKETCP_PREPARE_REJECT_STATE;
	}
	/* CHECKSUM_NONE is byte-validated above; PARTIAL also needs exact metadata. */
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

	/* A metadata dst is non-NULL but does not prove a live route. Never fall
	 * back to the device MTU, or admit a route resolved for another device. */
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

/*
 * Deliberately narrow transform contract.  This is not a generic GSO
 * converter: only one non-encapsulated IPv4 SKB_GSO_UDP_L4 aggregate is
 * accepted.  SKB_GSO_DODGY is the sole modifier because packet sockets and
 * other untrusted producers use it to request complete header validation.
 * GRO fraglists, UFO, tunnels, partial GSO and every other type fail here.
 */
static int wg_mix_faketcp_validate_udp_gso(
	struct sk_buff *skb, u32 transport_offset,
	const struct wg_mix_faketcp_udp_view *view,
	bool allow_dodgy_zero_segments)
{
	const unsigned int allowed_gso_type = SKB_GSO_UDP_L4 | SKB_GSO_DODGY;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	u32 expected_segments;
	int actual_transport_offset;

	if (!skb_is_gso(skb) || skb->encapsulation ||
	    shinfo->frag_list ||
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

	if (skb->ip_summed != CHECKSUM_PARTIAL ||
	    skb_csum_is_sctp(skb) ||
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

__bpf_kfunc_start_defs();

/*
 * Single admission boundary for both supported UDP inputs. Packet shape,
 * checksum state and device/route PMTU are read from the skb rather than from
 * caller-provided descriptors. Non-GSO CHECKSUM_PARTIAL is normalized to
 * CHECKSUM_NONE. GSO is made writable and publishes an exact segment count;
 * packet bytes and GSO type remain unchanged until commit.
 */
__bpf_kfunc int
wg_mix_faketcp_skb_prepare_udp(struct __sk_buff *ctx,
				       u32 network_offset,
				       u32 transport_offset,
				       u32 udp_length)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
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

		/* csum aliases csum_start/csum_offset. No UDP pseudo-header seed
		 * may survive the transport-header size change. */
		skb->csum = 0;
		skb->csum_valid = 0;
		skb->csum_complete_sw = 0;
		skb->csum_level = 0;
		skb_reset_csum_not_inet(skb);
		skb->ip_summed = CHECKSUM_NONE;
		return WG_MIX_FAKETCP_PREPARE_ACCEPT_PARTIAL_RESET;
	}

	ret = wg_mix_faketcp_validate_udp_gso(skb, transport_offset, &view,
					       true);
	if (ret != WG_MIX_FAKETCP_PREPARE_ACCEPT_GSO)
		return ret;
	/* payload_length > gso_size proves at least one full future segment;
	 * the separately checked last segment may be shorter. UDP_L4 gso_size is
	 * the UDP payload size and becomes the TCP payload MSS. */
	if (skb_shinfo(skb)->gso_size >
	    U16_MAX - sizeof(struct iphdr) - sizeof(struct tcphdr))
		return WG_MIX_FAKETCP_PREPARE_REJECT_MTU_ARITHMETIC_OVERFLOW;
	planned_l3_length = sizeof(struct iphdr) + sizeof(struct tcphdr) +
			    skb_shinfo(skb)->gso_size;
	admission = wg_mix_faketcp_admit_pmtu(skb, planned_l3_length);
	if (admission < 0)
		return admission;
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
	/* Virtio and packet sockets publish DODGY GSO with a zero segment count
	 * after marking the header for validation. Publish the validated count at
	 * this one preparation boundary; commit never accepts zero. */
	skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(
		view.payload_length, skb_shinfo(skb)->gso_size);
	return WG_MIX_FAKETCP_PREPARE_ACCEPT_GSO;
}

/*
 * Commit the already validated aggregate.  The BPF side passes host-order
 * sequence/acknowledgement numbers and packs the host-order window into the
 * high 16 bits of ack_window.  gso_size remains the UDP payload size and is
 * therefore also the resulting TCP payload MSS.  TCP GSO owns per-segment
 * sequence, IPv4 length/checksum, PSH placement and TCP checksum completion.
 */
__bpf_kfunc int
wg_mix_faketcp_skb_commit_udp_gso(struct __sk_buff *ctx,
					  u32 network_offset,
					  u32 transport_offset,
					  u32 sequence,
					  u64 ack_window)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
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
	if (skb_is_nonlinear(skb) ||
	    skb_headroom(skb) < WG_MIX_FAKETCP_HEADER_DELTA)
		return WG_MIX_FAKETCP_PREPARE_REJECT_WRITABLE;

	header_length = transport_offset + sizeof(old_udp);
	payload_length = view.payload_length;
	gso_size = shinfo->gso_size;
	gso_modifier = shinfo->gso_type & SKB_GSO_DODGY;
	memcpy(&old_udp, skb->data + transport_offset, sizeof(old_udp));
	/* Validation proves every segment is at least 32 bytes. No mutation below
	 * this point can fail, so a rejected skb is never left half-committed. */
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
	skb_reset_csum_not_inet(skb);
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

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(wg_mix_faketcp_checksum_kfunc_ids)
BTF_ID_FLAGS(func, wg_mix_faketcp_skb_prepare_udp)
BTF_ID_FLAGS(func, wg_mix_faketcp_skb_commit_udp_gso)
BTF_KFUNCS_END(wg_mix_faketcp_checksum_kfunc_ids)

static const struct btf_kfunc_id_set wg_mix_faketcp_checksum_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &wg_mix_faketcp_checksum_kfunc_ids,
};

static int __init wg_mix_faketcp_checksum_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					 &wg_mix_faketcp_checksum_kfunc_set);
}

static void __exit wg_mix_faketcp_checksum_exit(void)
{
}

module_init(wg_mix_faketcp_checksum_init);
module_exit(wg_mix_faketcp_checksum_exit);

MODULE_DESCRIPTION("wg-mix-ebpf experimental FakeTCP checksum, PMTU and GSO bridge");
MODULE_LICENSE("GPL");
