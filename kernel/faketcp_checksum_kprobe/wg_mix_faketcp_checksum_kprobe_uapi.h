/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef WG_MIX_FAKETCP_CHECKSUM_KPROBE_UAPI_H
#define WG_MIX_FAKETCP_CHECKSUM_KPROBE_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include "wg_mix_faketcp_checksum_kprobe_abi.h"

#define WG_MIX_FAKETCP_CHECKSUM_KPROBE_DEVICE_NAME \
	"wg_mix_faketcp_checksum_kprobe"
#define WG_MIX_FAKETCP_CHECKSUM_KPROBE_DEVICE_PATH \
	"/dev/" WG_MIX_FAKETCP_CHECKSUM_KPROBE_DEVICE_NAME

#define WG_MIX_FAKETCP_KPROBE_CAP_CHECKSUM_STATE (1ULL << 0)
#define WG_MIX_FAKETCP_KPROBE_CAP_PARTIAL_RESET  (1ULL << 1)
#define WG_MIX_FAKETCP_KPROBE_CAP_PMTU           (1ULL << 2)
#define WG_MIX_FAKETCP_KPROBE_CAP_UDP_GSO_TO_TCP (1ULL << 3)
#define WG_MIX_FAKETCP_KPROBE_CAP_FAIL_CLOSED    (1ULL << 4)
#define WG_MIX_FAKETCP_KPROBE_CAP_MULTI_LEASE    (1ULL << 5)

#define WG_MIX_FAKETCP_KPROBE_STATUS_F_LEASE_ACTIVE (1U << 0)
#define WG_MIX_FAKETCP_KPROBE_STATUS_F_PROBES_READY (1U << 1)
#define WG_MIX_FAKETCP_KPROBE_STATUS_F_HEALTHY      (1U << 2)

/*
 * Fixed-width native Linux UAPI. All integer fields use host byte order.
 * cookie is scoped to the calling open file description and must never be
 * logged. Prepare/commit hits are module-wide monotonic snapshots. Errors and
 * nmissed are deltas since this open file description acquired its lease, so
 * a historical failure cannot poison a newly opened daemon.
 *
 * Layout (bytes): abi_version@0, struct_size@4, capabilities@8, cookie@16,
 * hits_prepare@24, hits_commit@32, errors@40, nmissed@48, flags@56,
 * reserved@60; sizeof == 64.
 */
struct wg_mix_faketcp_checksum_kprobe_status_v1 {
	__u32 abi_version;
	__u32 struct_size;
	__u64 capabilities;
	__u64 cookie;
	__u64 hits_prepare;
	__u64 hits_commit;
	__u64 errors;
	__u64 nmissed;
	__u32 flags;
	__u32 reserved;
};

#define WG_MIX_FAKETCP_CHECKSUM_KPROBE_IOCTL_MAGIC 'W'
#define WG_MIX_FAKETCP_CHECKSUM_KPROBE_GET_STATUS \
	_IOR(WG_MIX_FAKETCP_CHECKSUM_KPROBE_IOCTL_MAGIC, 0x01, \
	     struct wg_mix_faketcp_checksum_kprobe_status_v1)

#endif /* WG_MIX_FAKETCP_CHECKSUM_KPROBE_UAPI_H */
