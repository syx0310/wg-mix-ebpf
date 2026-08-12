/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef WG_MIX_FAKETCP_CHECKSUM_KPROBE_ABI_H
#define WG_MIX_FAKETCP_CHECKSUM_KPROBE_ABI_H

/*
 * Shared legacy BPF/module bridge ABI.  Keep this header independent of
 * libc and kernel headers so the BPF translation unit can include it.
 */
#define WG_MIX_FAKETCP_CHECKSUM_KPROBE_ABI_VERSION 1U

/* Both trigger values are rejected by the underlying helpers before they
 * mutate the skb.  The kretprobe handlers only inspect calls whose original
 * return value is -EINVAL and whose trigger exactly matches these constants.
 */
#define WG_MIX_FAKETCP_KPROBE_PREPARE_MAGIC 0x57475031U
#define WG_MIX_FAKETCP_KPROBE_COMMIT_PROTO_MAGIC 0x5747U

/* struct __sk_buff::cb is exactly five u32 words (20 bytes). */
#define WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_SIZE 20U
#define WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_COOKIE_OFFSET 0U
#define WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_NETWORK_OFFSET 8U
#define WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_TRANSPORT_OFFSET 12U
#define WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_VALUE_OFFSET 16U

/* prepare descriptor: cookie, network_offset, transport_offset, udp_length.
 * commit descriptor: cookie, network_offset, transport_offset, sequence.
 * acknowledgement/window stay in bpf_skb_change_proto's u64 flags argument.
 */

/* The BPF runtime-cookie array value is independently ABI-checked by the
 * loader: cookie@0, abi_version@8, reserved@12, sizeof == 16.
 */
#define WG_MIX_FAKETCP_KPROBE_RUNTIME_COOKIE_SIZE 16U
#define WG_MIX_FAKETCP_KPROBE_RUNTIME_COOKIE_COOKIE_OFFSET 0U
#define WG_MIX_FAKETCP_KPROBE_RUNTIME_COOKIE_ABI_OFFSET 8U
#define WG_MIX_FAKETCP_KPROBE_RUNTIME_COOKIE_RESERVED_OFFSET 12U

#endif /* WG_MIX_FAKETCP_CHECKSUM_KPROBE_ABI_H */
