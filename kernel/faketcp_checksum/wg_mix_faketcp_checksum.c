// SPDX-License-Identifier: GPL-2.0-only
/*
 * Narrow checksum-metadata bridge for the experimental FakeTCP TC encoder.
 *
 * The TC UAPI context intentionally does not expose ip_summed, csum_start or
 * csum_offset. This kfunc validates the one packet shape the encoder supports
 * before admitting a materialized CHECKSUM_NONE packet or discarding a UDP
 * CHECKSUM_PARTIAL request whose checksum field will be replaced by a fully
 * materialized TCP checksum. It is not a general skb metadata write primitive.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <net/ip.h>

/*
 * Stable return values consumed by the experimental BPF object.  Do not use
 * errno here: the caller must be able to account packet shape, checksum state,
 * checksum metadata and GSO failures independently without guessing which
 * validation produced a shared errno.
 */
enum wg_mix_faketcp_checksum_result {
	WG_MIX_FAKETCP_CSUM_ACCEPT_NONE = 0,
	WG_MIX_FAKETCP_CSUM_ACCEPT_PARTIAL_RESET = 1,
	WG_MIX_FAKETCP_CSUM_REJECT_PACKET = -1,
	WG_MIX_FAKETCP_CSUM_REJECT_STATE = -2,
	WG_MIX_FAKETCP_CSUM_REJECT_METADATA = -3,
	WG_MIX_FAKETCP_CSUM_REJECT_GSO = -4,
};

static int wg_mix_faketcp_validate_udp_checksum(struct sk_buff *skb,
						  u32 network_offset,
						  u32 transport_offset,
						  u32 udp_length)
{
	struct iphdr ip_storage;
	struct udphdr udp_storage;
	const struct iphdr *ip;
	const struct udphdr *udp;
	int actual_network_offset;
	int actual_transport_offset;

	if (skb_is_gso(skb))
		return WG_MIX_FAKETCP_CSUM_REJECT_GSO;
	if (skb->protocol != htons(ETH_P_IP))
		return WG_MIX_FAKETCP_CSUM_REJECT_PACKET;

	actual_network_offset = skb_network_offset(skb);
	if (actual_network_offset < 0 || network_offset != actual_network_offset)
		return WG_MIX_FAKETCP_CSUM_REJECT_PACKET;
	if (network_offset > skb->len || transport_offset > skb->len ||
	    transport_offset - network_offset != sizeof(struct iphdr) ||
	    udp_length < sizeof(struct udphdr) || udp_length > U16_MAX ||
	    udp_length != skb->len - transport_offset)
		return WG_MIX_FAKETCP_CSUM_REJECT_PACKET;

	ip = skb_header_pointer(skb, network_offset, sizeof(ip_storage),
				&ip_storage);
	udp = skb_header_pointer(skb, transport_offset, sizeof(udp_storage),
				 &udp_storage);
	if (!ip || !udp)
		return WG_MIX_FAKETCP_CSUM_REJECT_PACKET;
	if (ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_UDP ||
	    ip->frag_off & htons(IP_MF | IP_OFFSET))
		return WG_MIX_FAKETCP_CSUM_REJECT_PACKET;
	if (ntohs(ip->tot_len) != sizeof(*ip) + udp_length ||
	    network_offset + ntohs(ip->tot_len) != skb->len ||
	    ntohs(udp->len) != udp_length)
		return WG_MIX_FAKETCP_CSUM_REJECT_PACKET;

	switch (skb->ip_summed) {
	case CHECKSUM_NONE:
		/* Raw/IP_HDRINCL reinjection already carries materialized bytes. */
		return WG_MIX_FAKETCP_CSUM_ACCEPT_NONE;
	case CHECKSUM_PARTIAL:
		break;
	default:
		return WG_MIX_FAKETCP_CSUM_REJECT_STATE;
	}
	/* CHECKSUM_NONE is byte-validated above; PARTIAL also needs exact metadata. */
	if (!skb_transport_header_was_set(skb))
		return WG_MIX_FAKETCP_CSUM_REJECT_METADATA;
	actual_transport_offset = skb_transport_offset(skb);
	if (actual_transport_offset < 0 ||
	    transport_offset != actual_transport_offset)
		return WG_MIX_FAKETCP_CSUM_REJECT_METADATA;
	if (skb_csum_is_sctp(skb))
		return WG_MIX_FAKETCP_CSUM_REJECT_METADATA;
	if (skb_checksum_start_offset(skb) != transport_offset ||
	    skb->csum_offset != offsetof(struct udphdr, check))
		return WG_MIX_FAKETCP_CSUM_REJECT_METADATA;
	if (skb->csum_offset > udp_length - sizeof(__sum16))
		return WG_MIX_FAKETCP_CSUM_REJECT_METADATA;

	return WG_MIX_FAKETCP_CSUM_ACCEPT_PARTIAL_RESET;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int
wg_mix_faketcp_skb_normalize_udp_csum(struct __sk_buff *ctx,
					      u32 network_offset,
					      u32 transport_offset,
					      u32 udp_length)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	int ret;

	ret = wg_mix_faketcp_validate_udp_checksum(skb, network_offset,
						   transport_offset, udp_length);
	if (ret < 0)
		return ret;
	if (ret == WG_MIX_FAKETCP_CSUM_ACCEPT_NONE)
		return ret;
	if (ret != WG_MIX_FAKETCP_CSUM_ACCEPT_PARTIAL_RESET)
		return WG_MIX_FAKETCP_CSUM_REJECT_STATE;

	/*
	 * csum aliases csum_start/csum_offset.  Clear both words and every
	 * checksum-validity field before publishing CHECKSUM_NONE.  The BPF
	 * encoder subsequently materializes the complete TCP checksum from packet
	 * bytes; no UDP pseudo-header seed survives the header-size change.
	 */
	skb->csum = 0;
	skb->csum_valid = 0;
	skb->csum_complete_sw = 0;
	skb->csum_level = 0;
	skb_reset_csum_not_inet(skb);
	skb->ip_summed = CHECKSUM_NONE;
	return WG_MIX_FAKETCP_CSUM_ACCEPT_PARTIAL_RESET;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(wg_mix_faketcp_checksum_kfunc_ids)
BTF_ID_FLAGS(func, wg_mix_faketcp_skb_normalize_udp_csum)
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

MODULE_DESCRIPTION("wg-mix-ebpf experimental FakeTCP checksum metadata bridge");
MODULE_LICENSE("GPL");
