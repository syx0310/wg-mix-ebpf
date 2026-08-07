// SPDX-License-Identifier: GPL-2.0-only
/*
 * Narrow checksum-metadata bridge for the experimental FakeTCP TC encoder.
 *
 * The TC UAPI context intentionally does not expose ip_summed, csum_start or
 * csum_offset. This kfunc validates the one packet shape the encoder supports
 * before discarding a UDP CHECKSUM_PARTIAL request whose checksum field will
 * be replaced by a fully materialized TCP checksum. It is not a general skb
 * metadata write primitive.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

static int wg_mix_faketcp_validate_udp_partial(struct sk_buff *skb,
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
		return -EOPNOTSUPP;
	if (skb->protocol != htons(ETH_P_IP))
		return -EPROTONOSUPPORT;
	if (!skb_transport_header_was_set(skb))
		return -EPROTO;

	actual_network_offset = skb_network_offset(skb);
	actual_transport_offset = skb_transport_offset(skb);
	if (actual_network_offset < 0 || actual_transport_offset < 0 ||
	    network_offset != actual_network_offset ||
	    transport_offset != actual_transport_offset)
		return -EPROTO;
	if (network_offset > skb->len || transport_offset > skb->len ||
	    transport_offset - network_offset != sizeof(struct iphdr) ||
	    udp_length < sizeof(struct udphdr) || udp_length > U16_MAX ||
	    udp_length != skb->len - transport_offset)
		return -EMSGSIZE;

	ip = skb_header_pointer(skb, network_offset, sizeof(ip_storage),
				&ip_storage);
	udp = skb_header_pointer(skb, transport_offset, sizeof(udp_storage),
				 &udp_storage);
	if (!ip || !udp)
		return -EMSGSIZE;
	if (ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_UDP ||
	    ip->frag_off & htons(IP_MF | IP_OFFSET))
		return -EPROTO;
	if (ntohs(ip->tot_len) != sizeof(*ip) + udp_length ||
	    network_offset + ntohs(ip->tot_len) != skb->len ||
	    ntohs(udp->len) != udp_length)
		return -EMSGSIZE;

	if (skb->ip_summed != CHECKSUM_PARTIAL || skb_csum_is_sctp(skb))
		return -EPROTO;
	if (skb_checksum_start_offset(skb) != transport_offset ||
	    skb->csum_offset != offsetof(struct udphdr, check))
		return -EPROTO;
	if (skb->csum_offset > udp_length - sizeof(__sum16))
		return -EMSGSIZE;

	return 0;
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

	ret = wg_mix_faketcp_validate_udp_partial(skb, network_offset,
						  transport_offset, udp_length);
	if (ret)
		return ret;

	/* csum aliases csum_start/csum_offset, so clear the validated request. */
	skb->csum = 0;
	skb->csum_valid = 0;
	skb->csum_complete_sw = 0;
	skb->csum_level = 0;
	skb_reset_csum_not_inet(skb);
	return 0;
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
