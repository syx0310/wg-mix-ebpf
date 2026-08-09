// SPDX-License-Identifier: MIT
//
// Clean-room FakeTCP wire path. This follows the public architectural idea of
// a TC encoder, pre-GRO XDP decoder and userspace handshake engine, but does
// not contain source copied from third-party implementations.
#ifndef WG_MIX_FAKETCP_H
#define WG_MIX_FAKETCP_H

#define FAKETCP_STATE_IDLE        0
#define FAKETCP_STATE_SYN_SENT    1
#define FAKETCP_STATE_SYN_RECV    2
#define FAKETCP_STATE_ESTABLISHED 3
#define FAKETCP_STATE_CLOSING     4

#define FAKETCP_EVENT_NEED_HANDSHAKE 1
#define FAKETCP_EVENT_SYN            2
#define FAKETCP_EVENT_SYNACK         3
#define FAKETCP_EVENT_ACK            4
#define FAKETCP_EVENT_RST            5
#define FAKETCP_EVENT_FIN            6
#define FAKETCP_EVENT_ABI_VERSION    1

#define FAKETCP_FLAG_FIN 0x01
#define FAKETCP_FLAG_SYN 0x02
#define FAKETCP_FLAG_RST 0x04
#define FAKETCP_FLAG_PSH 0x08
#define FAKETCP_FLAG_ACK 0x10

#define FAKETCP_HEADER_DELTA 12
#define FAKETCP_MAX_CAPTURED_PACKET 2304
#define FAKETCP_MAX_IPV4_TOTAL_LEN 2304
#define FAKETCP_GSO_MAX_PAYLOAD \
	(0xffffU - sizeof(struct iphdr) - sizeof(struct udphdr) - \
	 FAKETCP_HEADER_DELTA)
#define FAKETCP_CHECKSUM_CHUNK_BYTES 32
#define FAKETCP_CHECKSUM_CHUNK_COUNT \
	((FAKETCP_MAX_IPV4_TOTAL_LEN + FAKETCP_CHECKSUM_CHUNK_BYTES - 1) / \
	 FAKETCP_CHECKSUM_CHUNK_BYTES)
#define FAKETCP_METADATA_MAGIC 0x57474654U
#define FAKETCP_CONTROL_MIN_INTERVAL_NANOS 10000000ULL
#define FAKETCP_CONTROL_MAX_INTERVAL_NANOS 10000000000ULL
#define FAKETCP_CONTROL_MAX_BURST 4096U
#define FAKETCP_CONTROL_CAS_ATTEMPTS 4

// Required, non-weak module kfunc. The experimental object cannot be linked or
// verifier-loaded unless wg_mix_faketcp_checksum is loaded with this exact BTF
// function. The baseline object never sees this declaration or relocation.
extern int wg_mix_faketcp_skb_prepare_udp(struct __sk_buff *skb,
					   __u32 network_offset,
					   __u32 transport_offset,
					   __u32 udp_length) __ksym;
extern int wg_mix_faketcp_skb_commit_udp_gso(struct __sk_buff *skb,
					      __u32 network_offset,
					      __u32 transport_offset,
					      __u32 sequence,
					      __u64 ack_window) __ksym;

// Stable result ABI shared with kernel/faketcp_checksum. Each accepted input
// has one exact positive mode; every failure has one mutually exclusive class.
#define FAKETCP_PREPARE_ACCEPT_NONE                    0
#define FAKETCP_PREPARE_ACCEPT_PARTIAL_RESET           1
#define FAKETCP_PREPARE_ACCEPT_GSO                     2
#define FAKETCP_PREPARE_REJECT_PACKET                 -1
#define FAKETCP_PREPARE_REJECT_STATE                  -2
#define FAKETCP_PREPARE_REJECT_METADATA               -3
#define FAKETCP_PREPARE_REJECT_GSO_TYPE               -4
#define FAKETCP_PREPARE_REJECT_GSO_GEOMETRY           -5
#define FAKETCP_PREPARE_REJECT_WRITABLE               -6
#define FAKETCP_PREPARE_REJECT_TRUNCATED              -7
#define FAKETCP_PREPARE_REJECT_MTU_INVALID_INPUT      -8
#define FAKETCP_PREPARE_REJECT_MTU_ARITHMETIC_OVERFLOW -9
#define FAKETCP_PREPARE_REJECT_MTU_FRAGMENTATION_REJECTED -10
#define FAKETCP_PREPARE_REJECT_MTU_DEVICE_UNKNOWN    -11
#define FAKETCP_PREPARE_REJECT_MTU_DEVICE_EXCEEDED   -12
#define FAKETCP_PREPARE_REJECT_MTU_ROUTE_UNKNOWN     -13
#define FAKETCP_PREPARE_REJECT_MTU_ROUTE_EXCEEDED    -14

#define FAKETCP_GSO_COMMIT_ACCEPT          0
#define FAKETCP_GSO_XOR_CHUNK_BYTES       32

// The reason and boundary axes are shared verbatim with internal/faketcp's
// userspace audit schema. Keys are reason * BOUNDARY_MAX + boundary.
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

enum faketcp_stat_id {
	FAKETCP_STAT_EGRESS_OK = 0,
	FAKETCP_STAT_INGRESS_OK,
	FAKETCP_STAT_SESSION_MISS,
	FAKETCP_STAT_BAD_STATE,
	FAKETCP_STAT_BAD_PACKET,
	FAKETCP_STAT_GSO_REJECT,
	FAKETCP_STAT_CHECKSUM_ERROR,
	FAKETCP_STAT_METADATA_ERROR,
	FAKETCP_STAT_EVENT_ERROR,
	FAKETCP_STAT_CONTROL_COALESCED,
	FAKETCP_STAT_CONTROL_RATE_LIMITED,
	FAKETCP_STAT_CONTROL_POLICY_MISS,
	FAKETCP_STAT_CAPTURE_ID_ERROR,
	FAKETCP_STAT_CHECKSUM_NONE_ACCEPTED,
	FAKETCP_STAT_CHECKSUM_PARTIAL_RESET,
	FAKETCP_STAT_CHECKSUM_STATE_REJECT,
	FAKETCP_STAT_MTU_REJECT,
	FAKETCP_STAT_MAX,
};

struct faketcp_session_key {
	__u64 generation;
	__be32 local_ipv4;
	__be32 remote_ipv4;
	__u32 underlay_index;
	__u16 local_port;
	__u16 remote_port;
};

struct faketcp_session_value {
	__u64 generation;
	__u64 last_seen_nanos;
	__u32 tx_sequence;
	__u32 rx_sequence;
	__u32 local_isn;
	__u32 remote_isn;
	__u16 window;
	__u8 state;
	__u8 flags;
	__u8 pad[4];
};

_Static_assert(sizeof(struct faketcp_session_key) == 24,
	       "faketcp session key ABI drift");
_Static_assert(sizeof(struct faketcp_session_value) == 40,
	       "faketcp session value ABI drift");

struct faketcp_event {
	struct faketcp_session_key key;
	__u64 timestamp_nanos;
	__u8 runtime_incarnation[16];
	__u64 capture_sequence;
	__u32 capture_cpu;
	__u32 sequence;
	__u32 acknowledgement;
	__u32 payload_length;
	__u32 fwmark;
	__u32 wg_id;
	__u16 packet_length;
	__u16 event_abi_version;
	__u8 type;
	__u8 tcp_flags;
	__u8 pad[2];
};

struct faketcp_packet_event {
	struct faketcp_event event;
	__u8 packet[FAKETCP_MAX_CAPTURED_PACKET];
};

_Static_assert(sizeof(struct faketcp_event) == 88, "faketcp event ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, runtime_incarnation) == 32,
	       "faketcp runtime incarnation ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, capture_sequence) == 48,
	       "faketcp capture sequence ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, capture_cpu) == 56,
	       "faketcp capture CPU ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, event_abi_version) == 82,
	       "faketcp event version ABI drift");
_Static_assert(sizeof(struct faketcp_packet_event) == 2392,
	       "faketcp packet event ABI drift");

struct faketcp_runtime_identity_value {
	__u64 generation;
	__u8 incarnation[16];
	__u16 event_abi_version;
	__u8 pad[6];
};

_Static_assert(sizeof(struct faketcp_runtime_identity_value) == 32,
	       "faketcp runtime identity ABI drift");

struct faketcp_metadata {
	__u32 magic;
	__u32 generation_low;
};

struct faketcp_pseudo_tail {
	__u8 zero;
	__u8 protocol;
	__be16 length;
};

struct faketcp_ipv4_pseudo_header {
	__be32 source;
	__be32 destination;
	__u8 zero;
	__u8 protocol;
	__be16 length;
};

_Static_assert(sizeof(struct faketcp_ipv4_pseudo_header) == 12,
	       "faketcp IPv4 pseudo-header ABI drift");

// These policy maps are populated for every concrete XDP attachment before
// the link becomes reachable. They deliberately duplicate the small listener
// projection needed at XDP: the baseline ingress map permits wildcard
// interfaces and cannot classify non-initial fragments that have no port.
// Keeping an exact per-interface marker makes every ambiguous TCP fragment or
// truncated header fail closed instead of reaching the host TCP stack.
struct faketcp_managed_if_key {
	__u64 generation;
	__u32 underlay_index;
	__u32 pad;
};

struct faketcp_managed_port_key {
	__u64 generation;
	__u32 underlay_index;
	__u16 destination_port;
	__u16 pad;
};

struct faketcp_managed_port_value {
	__u64 generation;
	__u32 wg_id;
	__u8 action;
	__u8 pad[3];
};

// The controller creates one policy value per managed WireGuard and staged
// generation before an XDP link can become reachable. virtual_time_nanos is a
// BPF-owned GCRA cursor: zero starts with no immediately spendable budget, so
// reloading or recreating this unpinned experimental map cannot mint a burst.
struct faketcp_control_policy_key {
	__u64 generation;
	__u32 wg_id;
	__u32 pad;
};

struct faketcp_control_policy_value {
	__u64 generation;
	__u64 virtual_time_nanos;
	__u64 interval_nanos;
	__u32 burst;
	__u32 pad;
};

// Repeated control packets are coalesced by managed policy, generation, flow
// and event type. This cache may evict old coalescing hints, but it never owns
// established session state; the policy budget remains the strict event cap.
struct faketcp_control_flow_key {
	struct faketcp_session_key session;
	__u32 wg_id;
	__u8 event_type;
	__u8 pad[3];
};

struct faketcp_control_flow_value {
	__u64 generation;
	__u64 last_event_nanos;
};

_Static_assert(sizeof(struct faketcp_control_policy_key) == 16,
	       "faketcp control policy key ABI drift");
_Static_assert(sizeof(struct faketcp_control_policy_value) == 32,
	       "faketcp control policy value ABI drift");
_Static_assert(sizeof(struct faketcp_control_flow_key) == 32,
	       "faketcp control flow key ABI drift");
_Static_assert(sizeof(struct faketcp_control_flow_value) == 16,
	       "faketcp control flow value ABI drift");

#include "wg_mix_faketcp_l3.h"

struct {
	// Only established sessions enter this map. A bounded userspace half-open
	// table absorbs SYN pressure, and HASH insertion fails at capacity instead
	// of evicting an active established flow as LRU_HASH would.
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct faketcp_session_key);
	__type(value, struct faketcp_session_value);
} faketcp_session_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct faketcp_managed_if_key);
	__type(value, __u64);
} faketcp_managed_if_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct faketcp_managed_port_key);
	__type(value, struct faketcp_managed_port_value);
} faketcp_managed_port_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct faketcp_control_policy_key);
	__type(value, struct faketcp_control_policy_value);
} faketcp_control_policy_map SEC(".maps");

struct {
	// Only an admitted event can update this LRU. Once a policy budget is
	// exhausted, a unique-flow SYN flood performs lookups but cannot amplify
	// into map writes. Eviction can reduce coalescing, never bypass the policy
	// cursor that caps ring-buffer output.
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct faketcp_control_flow_key);
	__type(value, struct faketcp_control_flow_value);
} faketcp_control_flow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} faketcp_events SEC(".maps");

// bpf_ringbuf_output accepts a verifier-bounded variable record size whereas
// bpf_ringbuf_reserve requires a constant size. A per-CPU staging record lets
// us emit only the initialized event header and captured packet bytes, never
// the unused tail of the fixed upper bound.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct faketcp_packet_event);
} faketcp_capture_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct faketcp_runtime_identity_value);
} faketcp_rt_id SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} faketcp_cap_seq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} faketcp_egress_programs SEC(".maps");

// Experimental counters stay outside the version-10 canonical pinned stats
// map. This preserves ordinary UDP/ICMP reload compatibility while FakeTCP is
// hard-gated; the loader can expose this map together with the controller when
// the feature is ready for activation.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FAKETCP_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} faketcp_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FAKETCP_MTU_REASON_MAX * FAKETCP_MTU_BOUNDARY_MAX);
	__type(key, __u32);
	__type(value, __u64);
} faketcp_mtu_audit_map SEC(".maps");

static __always_inline void inc_faketcp_stat(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&faketcp_stats_map, &key);

	if (value)
		*value += 1;
}

static __always_inline int faketcp_mtu_reject(__u32 reason, __u32 boundary)
{
	__u32 key;
	__u64 *counter;

	if (reason >= FAKETCP_MTU_REASON_MAX ||
	    boundary >= FAKETCP_MTU_BOUNDARY_MAX)
		return -1;
	key = reason * FAKETCP_MTU_BOUNDARY_MAX + boundary;
	counter = bpf_map_lookup_elem(&faketcp_mtu_audit_map, &key);
	if (counter)
		*counter += 1;
	inc_faketcp_stat(FAKETCP_STAT_MTU_REJECT);
	return -1;
}

static __always_inline int
faketcp_prepare_udp(struct __sk_buff *skb, __u32 network_offset,
		    __u32 transport_offset, __u32 udp_length, int expect_gso)
{
	int result;

	result = wg_mix_faketcp_skb_prepare_udp(
		skb, network_offset, transport_offset, udp_length);
	if (expect_gso) {
		if (result == FAKETCP_PREPARE_ACCEPT_GSO)
			return 0;
	} else {
		switch (result) {
		case FAKETCP_PREPARE_ACCEPT_NONE:
			inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_NONE_ACCEPTED);
			return 0;
		case FAKETCP_PREPARE_ACCEPT_PARTIAL_RESET:
			inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_PARTIAL_RESET);
			return 0;
		}
	}
	switch (result) {
	case FAKETCP_PREPARE_REJECT_GSO_TYPE:
	case FAKETCP_PREPARE_REJECT_GSO_GEOMETRY:
	case FAKETCP_PREPARE_REJECT_WRITABLE:
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return -1;
	case FAKETCP_PREPARE_REJECT_PACKET:
	case FAKETCP_PREPARE_REJECT_TRUNCATED:
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return -1;
	case FAKETCP_PREPARE_REJECT_STATE:
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_STATE_REJECT);
		return -1;
	case FAKETCP_PREPARE_REJECT_METADATA:
		inc_faketcp_stat(FAKETCP_STAT_METADATA_ERROR);
		return -1;
	case FAKETCP_PREPARE_REJECT_MTU_INVALID_INPUT:
		return faketcp_mtu_reject(FAKETCP_MTU_INVALID_INPUT,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	case FAKETCP_PREPARE_REJECT_MTU_ARITHMETIC_OVERFLOW:
		return faketcp_mtu_reject(FAKETCP_MTU_ARITHMETIC_OVERFLOW,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	case FAKETCP_PREPARE_REJECT_MTU_FRAGMENTATION_REJECTED:
		return faketcp_mtu_reject(FAKETCP_MTU_FRAGMENTATION_REJECTED,
					   FAKETCP_MTU_BOUNDARY_INPUT);
	case FAKETCP_PREPARE_REJECT_MTU_DEVICE_UNKNOWN:
		return faketcp_mtu_reject(FAKETCP_MTU_UNKNOWN,
					   FAKETCP_MTU_BOUNDARY_DEVICE);
	case FAKETCP_PREPARE_REJECT_MTU_DEVICE_EXCEEDED:
		return faketcp_mtu_reject(FAKETCP_MTU_EXCEEDED,
					   FAKETCP_MTU_BOUNDARY_DEVICE);
	case FAKETCP_PREPARE_REJECT_MTU_ROUTE_UNKNOWN:
		return faketcp_mtu_reject(FAKETCP_MTU_UNKNOWN,
					   FAKETCP_MTU_BOUNDARY_ROUTE);
	case FAKETCP_PREPARE_REJECT_MTU_ROUTE_EXCEEDED:
		return faketcp_mtu_reject(FAKETCP_MTU_EXCEEDED,
					   FAKETCP_MTU_BOUNDARY_ROUTE);
	default:
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
		return -1;
	}
}

static __always_inline int
faketcp_bind_runtime_identity(const struct faketcp_session_key *key,
			      struct faketcp_event *event)
{
	__u32 zero = 0;
	struct faketcp_runtime_identity_value *identity;
	__u8 nonzero = 0;

	identity = bpf_map_lookup_elem(&faketcp_rt_id, &zero);
	if (!identity || identity->generation != key->generation ||
	    identity->event_abi_version != FAKETCP_EVENT_ABI_VERSION)
		return -1;
#pragma unroll
	for (int i = 0; i < 16; i++)
		nonzero |= identity->incarnation[i];
	if (!nonzero)
		return -1;
	__builtin_memcpy(event->runtime_incarnation, identity->incarnation,
			 sizeof(event->runtime_incarnation));
	event->event_abi_version = FAKETCP_EVENT_ABI_VERSION;
	return 0;
}

static __always_inline int
faketcp_assign_capture_sequence(struct faketcp_event *event)
{
	__u32 zero = 0;
	__u64 *sequence = bpf_map_lookup_elem(&faketcp_cap_seq, &zero);

	// Zero is reserved for non-capture events. Saturation is permanent for
	// this per-CPU map/runtime and requires a fresh runtime incarnation/map;
	// never wrap and alias an earlier capture.
	if (!sequence || *sequence == ~0ULL)
		return -1;
	*sequence += 1;
	event->capture_sequence = *sequence;
	event->capture_cpu = bpf_get_smp_processor_id();
	return 0;
}

// Allocate one event slot from a per-WireGuard, per-generation GCRA cursor.
// Every retry bound is a compile-time constant. Under contention this helper
// rejects after four failed compare-and-swaps instead of doing attacker-sized
// work. interval/burst bounds also make every multiplication verifier-safe.
static __always_inline int
faketcp_take_control_budget(struct faketcp_control_policy_value *policy,
			    __u64 now)
{
	__u64 interval = policy->interval_nanos;
	__u32 burst = policy->burst;
	__u64 window;

	if (interval < FAKETCP_CONTROL_MIN_INTERVAL_NANOS ||
	    interval > FAKETCP_CONTROL_MAX_INTERVAL_NANOS || burst == 0 ||
	    burst > FAKETCP_CONTROL_MAX_BURST)
		return 0;
	window = interval * (__u64)burst;
	if (now > ~0ULL - window)
		return 0;

#pragma unroll
	for (int attempt = 0; attempt < FAKETCP_CONTROL_CAS_ATTEMPTS; attempt++) {
		__u64 old = policy->virtual_time_nanos;
		__u64 base, candidate, limit = now + window;

		if (old == 0) {
			// The first packet establishes the zero-budget epoch. Exactly one
			// token becomes available after one configured interval.
			if (__sync_val_compare_and_swap(&policy->virtual_time_nanos,
						old, limit) == old)
				return 0;
			continue;
		}
		base = old > now ? old : now;
		if (base > ~0ULL - interval)
			return 0;
		candidate = base + interval;
		if (candidate > limit)
			return 0;
		if (__sync_val_compare_and_swap(&policy->virtual_time_nanos,
						old, candidate) == old)
			return 1;
	}
	return 0;
}

static __always_inline int
faketcp_admit_control_event(const struct faketcp_session_key *session,
			    __u32 wg_id, __u8 event_type, __u64 now)
{
	struct faketcp_control_policy_key policy_key = {
		.generation = session->generation,
		.wg_id = wg_id,
	};
	struct faketcp_control_flow_key flow_key = {
		.session = *session,
		.wg_id = wg_id,
		.event_type = event_type,
	};
	struct faketcp_control_policy_value *policy;
	struct faketcp_control_flow_value *previous;
	struct faketcp_control_flow_value next = {
		.generation = session->generation,
		.last_event_nanos = now,
	};

	// Policy identity validation and lookup are first and fail-closed. No
	// packet can allocate its own policy budget, and generations/WireGuards
	// never share a cursor.
	if (session->generation == 0 || wg_id == 0 ||
	    event_type < FAKETCP_EVENT_NEED_HANDSHAKE ||
	    event_type > FAKETCP_EVENT_FIN) {
		inc_faketcp_stat(FAKETCP_STAT_CONTROL_POLICY_MISS);
		return 0;
	}
	policy = bpf_map_lookup_elem(&faketcp_control_policy_map, &policy_key);
	if (!policy || policy->generation != session->generation ||
	    policy->interval_nanos < FAKETCP_CONTROL_MIN_INTERVAL_NANOS ||
	    policy->interval_nanos > FAKETCP_CONTROL_MAX_INTERVAL_NANOS ||
	    policy->burst == 0 || policy->burst > FAKETCP_CONTROL_MAX_BURST) {
		inc_faketcp_stat(FAKETCP_STAT_CONTROL_POLICY_MISS);
		return 0;
	}
	previous = bpf_map_lookup_elem(&faketcp_control_flow_map, &flow_key);
	if (previous && previous->generation == session->generation &&
	    previous->last_event_nanos != 0 &&
	    (now <= previous->last_event_nanos ||
	     now - previous->last_event_nanos < policy->interval_nanos)) {
		inc_faketcp_stat(FAKETCP_STAT_CONTROL_COALESCED);
		return 0;
	}
	if (!faketcp_take_control_budget(policy, now)) {
		inc_faketcp_stat(FAKETCP_STAT_CONTROL_RATE_LIMITED);
		return 0;
	}
	// This is the only attacker-keyed write, and only a policy-admitted event
	// reaches it. A failed hint update does not remove the strict policy cap.
	if (bpf_map_update_elem(&faketcp_control_flow_map, &flow_key, &next,
				BPF_ANY) < 0)
		inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
	return 1;
}

static __always_inline int faketcp_emit_event(const struct faketcp_session_key *key,
					       __u8 type, __u8 flags,
					       __u32 seq, __u32 ack,
					       __u32 payload_len,
					       __u32 fwmark, __u32 wg_id)
{
	__u64 now = bpf_ktime_get_ns();
	struct faketcp_event event;

	if (!faketcp_admit_control_event(key, wg_id, type, now))
		return 0;
	event = (struct faketcp_event){
		.key = *key,
		.timestamp_nanos = now,
		.sequence = seq,
		.acknowledgement = ack,
		.payload_length = payload_len,
		.fwmark = fwmark,
		.wg_id = wg_id,
		.type = type,
		.tcp_flags = flags,
	};
	if (faketcp_bind_runtime_identity(key, &event) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_CAPTURE_ID_ERROR);
		return -1;
	}

	if (bpf_ringbuf_output(&faketcp_events, &event, sizeof(event), 0) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
		return -1;
	}
	return 0;
}

static __always_inline int faketcp_tc_key(struct __sk_buff *skb,
					   const struct packet_info *info,
					   const struct faketcp_l3_info *l3,
					   __u64 generation,
					   struct faketcp_session_key *key)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + l3->l3_off;

	// faketcp_parse_tc_l3 already applied the sole fixed-header IPv4 gate.
	// Keep only descriptor/source-parser coherence and verifier bounds here.
	if (l3->l3_off != info->ip_off || l3->l4_off != info->udp_off ||
	    (void *)(iph + 1) > data_end)
		return -1;
	key->generation = generation;
	key->local_ipv4 = iph->saddr;
	key->remote_ipv4 = iph->daddr;
	key->underlay_index = skb->ifindex;
	key->local_port = info->src_port;
	key->remote_port = info->dst_port;
	return 0;
}

static __always_inline int faketcp_parse_tc_l3(struct __sk_buff *skb,
						const struct packet_info *info,
						struct faketcp_l3_info *l3)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	int rc;

	rc = faketcp_parse_l3(data, data_end, skb->len, info->ip_off,
			      info->family, l3);
	if (rc != FAKETCP_L3_OK)
		return rc;
	rc = faketcp_managed_transform_status(l3, IPPROTO_UDP);
	if (rc != FAKETCP_L3_OK)
		return rc;
	if (l3->l4_off != info->udp_off ||
	    l3->l4_len != sizeof(struct udphdr) + info->payload_len)
		return FAKETCP_L3_MALFORMED;
	return FAKETCP_L3_OK;
}

// Capture happens before type-word and XOR mutation. The userspace release
// path can therefore re-inject this exact IPv4 packet once and let the normal
// egress pipeline apply every transform in the required order.
static __always_inline int faketcp_capture_first_packet(struct __sk_buff *skb,
						 const struct packet_info *info,
						 const struct faketcp_l3_info *l3,
						 const struct egress_rule_value *rule,
						 const struct faketcp_session_key *key)
{
	struct faketcp_packet_event *record;
	__u32 zero = 0;
	__u64 record_len;
	__u64 now;
	__u16 packet_len;

	packet_len = l3->l3_len;
	if (packet_len < sizeof(struct iphdr) + sizeof(struct udphdr) ||
	    packet_len > FAKETCP_MAX_CAPTURED_PACKET ||
	    (__u32)packet_len != sizeof(struct iphdr) + sizeof(struct udphdr) +
				 info->payload_len ||
	    info->ip_off > skb->len || packet_len > skb->len - info->ip_off)
		return -1;
	record = bpf_map_lookup_elem(&faketcp_capture_scratch, &zero);
	if (!record)
		return -1;
	// Cheap packet-shape and scratch-availability failures do not spend a
	// control token. Admission still precedes every scratch write and the
	// attacker-sized packet copy. A later copy/output failure deliberately
	// burns its token: fail closed instead of letting a failing path retry at
	// unlimited rate. The same timestamp is carried into the emitted record.
	now = bpf_ktime_get_ns();
	if (!faketcp_admit_control_event(key, rule->wg_id,
					 FAKETCP_EVENT_NEED_HANDSHAKE, now))
		return 0;
	record->event = (struct faketcp_event){
		.key = *key,
		.timestamp_nanos = now,
		.payload_length = info->payload_len,
		.fwmark = skb->mark,
		.wg_id = rule->wg_id,
		.packet_length = packet_len,
		.type = FAKETCP_EVENT_NEED_HANDSHAKE,
	};
	if (faketcp_bind_runtime_identity(key, &record->event) < 0 ||
	    faketcp_assign_capture_sequence(&record->event) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_CAPTURE_ID_ERROR);
		return -1;
	}
	if (bpf_skb_load_bytes(skb, info->ip_off, record->packet, packet_len) < 0)
		return -1;
	record_len = sizeof(record->event) + packet_len;
	if (bpf_ringbuf_output(&faketcp_events, record, record_len, 0) < 0)
		return -1;
	return 0;
}

static __always_inline int faketcp_preflight_egress(struct __sk_buff *skb,
						     const struct packet_info *info,
						     const struct egress_rule_value *rule,
						     __u64 generation)
{
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct faketcp_l3_info l3;
	__u32 old_total_len;

	// The egress entry point dispatches supported UDP_L4 GSO aggregates to the
	// per-segment transformer before this single-packet preflight. Keep this
	// rejection as a defence against accidental aggregate entry through the
	// non-GSO continuation.
	if (skb->gso_segs || skb->gso_size) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return -1;
	}
	if (faketcp_parse_tc_l3(skb, info, &l3) != FAKETCP_L3_OK ||
	    info->payload_len > FAKETCP_MAX_IPV4_TOTAL_LEN -
				 sizeof(struct iphdr) - sizeof(struct udphdr)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return -1;
	}
	old_total_len = sizeof(struct iphdr) + sizeof(struct udphdr) +
			info->payload_len;
	if (info->ip_off > skb->len || old_total_len != skb->len - info->ip_off) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return -1;
	}
	if (faketcp_tc_key(skb, info, &l3, generation, &key) < 0)
		return -1;
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (session && session->generation == generation &&
	    session->state == FAKETCP_STATE_ESTABLISHED) {
		if (faketcp_prepare_udp(skb, info->ip_off, info->udp_off,
					 info->payload_len + sizeof(struct udphdr),
					 0) < 0)
			return -1;
		return 0;
	}
	if (session)
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
	else
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
	if (faketcp_capture_first_packet(skb, info, &l3, rule, &key) < 0)
		inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
	return -1;
}

struct faketcp_gso_loop_context {
	struct __sk_buff *skb;
	struct cipher_value *cipher;
	__u32 mixed_type[4];
	__u32 payload_offset;
	__u32 payload_length;
	__u32 gso_size;
	__u32 gso_segments;
	__u32 xor_chunks_per_segment;
	int error;
};

static __always_inline __u32
faketcp_gso_segment_length(const struct faketcp_gso_loop_context *context,
			   __u32 index)
{
	__u32 offset = index * context->gso_size;
	__u32 remaining = context->payload_length - offset;

	return remaining < context->gso_size ? remaining : context->gso_size;
}

static long faketcp_gso_validate_segment(__u32 index, void *opaque)
{
	struct faketcp_gso_loop_context *context = opaque;
	__u32 segment_offset;
	__u32 segment_length;
	__u32 wire_type;
	int kind;

	if (index >= context->gso_segments) {
		context->error = -1;
		return 1;
	}
	segment_offset = index * context->gso_size;
	segment_length = faketcp_gso_segment_length(context, index);
	if (segment_length < FAKETCP_HEADER_DELTA ||
	    bpf_skb_load_bytes(context->skb,
			       context->payload_offset + segment_offset,
			       &wire_type, sizeof(wire_type)) < 0) {
		context->error = -1;
		return 1;
	}
	kind = kind_from_standard(wg_le32_to_cpu(wire_type));
	if (kind < 0 || !validate_len(kind, segment_length)) {
		context->error = -1;
		return 1;
	}
	if (context->cipher && segment_length > context->cipher->max_bytes &&
	    !(context->cipher->flags & CIPHER_F_PREFIX)) {
		context->error = -1;
		return 1;
	}
	return 0;
}

static long faketcp_gso_rewrite_type(__u32 index, void *opaque)
{
	struct faketcp_gso_loop_context *context = opaque;
	__u32 segment_offset = index * context->gso_size;
	__u32 old_wire;
	__u32 new_wire;
	int kind;

	if (index >= context->gso_segments ||
	    bpf_skb_load_bytes(context->skb,
			       context->payload_offset + segment_offset,
			       &old_wire, sizeof(old_wire)) < 0) {
		context->error = -1;
		return 1;
	}
	kind = kind_from_standard(wg_le32_to_cpu(old_wire));
	if (kind < 0) {
		context->error = -1;
		return 1;
	}
	new_wire = wg_cpu_to_le32(context->mixed_type[kind]);
	if (bpf_skb_store_bytes(context->skb,
				context->payload_offset + segment_offset,
				&new_wire, sizeof(new_wire),
				BPF_F_INVALIDATE_HASH) < 0) {
		context->error = -1;
		return 1;
	}
	return 0;
}

static long faketcp_gso_xor_chunk(__u32 index, void *opaque)
{
	struct faketcp_gso_loop_context *context = opaque;
	__u8 chunk[FAKETCP_GSO_XOR_CHUNK_BYTES] = {};
	__u32 segment_index;
	__u32 segment_offset;
	__u32 segment_length;
	__u32 chunk_offset;
	__u32 target_length;
	__u32 chunk_length;

	if (!context->cipher || !context->xor_chunks_per_segment) {
		context->error = -1;
		return 1;
	}
	segment_index = index / context->xor_chunks_per_segment;
	if (segment_index >= context->gso_segments) {
		context->error = -1;
		return 1;
	}
	segment_offset = segment_index * context->gso_size;
	segment_length = faketcp_gso_segment_length(context, segment_index);
	chunk_offset = (index % context->xor_chunks_per_segment) *
		       FAKETCP_GSO_XOR_CHUNK_BYTES;
	target_length = segment_length < context->cipher->max_bytes ?
			segment_length : context->cipher->max_bytes;
	if (chunk_offset >= target_length)
		return 0;
	chunk_length = target_length - chunk_offset;
	if (chunk_length > sizeof(chunk))
		chunk_length = sizeof(chunk);
	if (bpf_skb_load_bytes(context->skb,
			       context->payload_offset + segment_offset +
				       chunk_offset,
			       chunk, chunk_length) < 0) {
		context->error = -1;
		return 1;
	}
#pragma unroll
	for (int byte = 0; byte < FAKETCP_GSO_XOR_CHUNK_BYTES; byte++) {
		if (byte >= chunk_length)
			break;
		chunk[byte] ^= xor_key_byte(context->cipher, chunk_offset + byte);
	}
	if (bpf_skb_store_bytes(context->skb,
				context->payload_offset + segment_offset +
					chunk_offset,
				chunk, chunk_length,
				BPF_F_INVALIDATE_HASH) < 0) {
		context->error = -1;
		return 1;
	}
	return 0;
}

// The only supported aggregate is the exact observable fixed-IHL IPv4
// SKB_GSO_UDP_L4 shape. Non-fraglist aggregates are source-neutral because skb
// metadata cannot reliably distinguish transmit GSO from a compatible GRO
// image. The module prepares exclusive writable storage; every logical UDP
// payload is then independently checked, retagged and XORed before the single
// UDP-GSO -> TCPv4-GSO commit. No other GSO type has a fallback path.
static __always_inline int
faketcp_encode_gso_segments(struct __sk_buff *skb,
			    const struct packet_info *info,
			    const struct egress_rule_value *rule,
			    __u64 generation)
{
	struct faketcp_gso_loop_context context = {
		.skb = skb,
		.payload_offset = info->payload_off,
		.payload_length = info->payload_len,
		.gso_size = skb->gso_size,
	};
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct faketcp_l3_info l3;
	struct profile_key profile_key = {
		.generation = generation,
		.profile_id = rule->profile_id,
	};
	struct profile_value *profile;
	__u32 expected_segments;
	__u32 xor_chunks;
	__u32 xor_segment_bytes;
	__u32 sequence;
	__u64 ack_window;
	int result;

	if (rule->transport_mode != TRANSPORT_FAKETCP ||
	    faketcp_parse_tc_l3(skb, info, &l3) != FAKETCP_L3_OK ||
	    info->payload_len <= skb->gso_size ||
	    info->payload_len > FAKETCP_GSO_MAX_PAYLOAD ||
	    skb->gso_size < 32 ||
	    info->payload_off > skb->len ||
	    info->payload_len > skb->len - info->payload_off) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	expected_segments = (info->payload_len + skb->gso_size - 1) /
			    skb->gso_size;
	if ((skb->gso_segs && expected_segments != skb->gso_segs) ||
	    info->payload_len - (expected_segments - 1) * skb->gso_size < 32) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	context.gso_segments = expected_segments;
	if (faketcp_tc_key(skb, info, &l3, generation, &key) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (!session || session->generation != generation ||
	    session->state != FAKETCP_STATE_ESTABLISHED) {
		inc_faketcp_stat(session ? FAKETCP_STAT_BAD_STATE :
					    FAKETCP_STAT_SESSION_MISS);
		return TC_ACT_SHOT;
	}
	profile = bpf_map_lookup_elem(&profile_map, &profile_key);
	if (!profile || profile->generation != generation) {
		inc_stat(STAT_EGRESS_RULE_MISS);
		return TC_ACT_SHOT;
	}

#pragma unroll
	for (int kind = 0; kind < 4; kind++)
		context.mixed_type[kind] = profile->standard_to_mixed[kind];
	if (rule->cipher_id) {
		context.cipher = lookup_cipher(rule->cipher_id, generation);
		if (!context.cipher) {
			inc_stat(STAT_XOR_KEY_MISSING);
			return TC_ACT_SHOT;
		}
		if (!context.cipher->max_bytes ||
		    context.cipher->max_bytes > MAX_XOR_BYTES) {
			inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
			return TC_ACT_SHOT;
		}
	}
	context.error = 0;
	if (bpf_loop(context.gso_segments, faketcp_gso_validate_segment,
		     &context, 0) != context.gso_segments || context.error) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}

	if (faketcp_prepare_udp(skb, info->ip_off, info->udp_off,
				 info->payload_len + sizeof(struct udphdr), 1) < 0)
		return TC_ACT_SHOT;
	context.error = 0;
	if (bpf_loop(context.gso_segments, faketcp_gso_rewrite_type,
		     &context, 0) != context.gso_segments || context.error) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	if (context.cipher) {
		xor_segment_bytes = context.gso_size < context.cipher->max_bytes ?
				    context.gso_size : context.cipher->max_bytes;
		context.xor_chunks_per_segment =
			(xor_segment_bytes + FAKETCP_GSO_XOR_CHUNK_BYTES - 1) /
			FAKETCP_GSO_XOR_CHUNK_BYTES;
		xor_chunks = context.xor_chunks_per_segment * context.gso_segments;
		context.error = 0;
		if (bpf_loop(xor_chunks, faketcp_gso_xor_chunk, &context, 0) !=
			    xor_chunks || context.error) {
			inc_stat(STAT_XOR_STORE_ERROR);
			return TC_ACT_SHOT;
		}
		inc_stat(STAT_XOR_EGRESS_OK);
	}

	// prepare_udp completed the fallible allocation boundary. Commit performs
	// one final contract check before its first mutation and cannot allocate.
	sequence = __sync_fetch_and_add(&session->tx_sequence,
					context.payload_length);
	ack_window = session->rx_sequence |
		     ((__u64)(session->window ? session->window : 65535) << 32);
	result = wg_mix_faketcp_skb_commit_udp_gso(
		skb, info->ip_off, info->udp_off, sequence, ack_window);
	if (result != FAKETCP_GSO_COMMIT_ACCEPT) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	session->last_seen_nanos = bpf_ktime_get_ns();
	inc_stat(STAT_EGRESS_REWRITE_OK);
	inc_stat(STAT_EGRESS_GSO_REWRITE_OK);
	inc_faketcp_stat(FAKETCP_STAT_EGRESS_OK);
	return TC_ACT_OK;
}

static __always_inline __s64 faketcp_rotation_checksum(const __u8 head[FAKETCP_HEADER_DELTA],
							__s64 seed, int inverse)
{
	__u8 aligned[16] = {};
	__u8 shifted[16] = {};

#pragma unroll
	for (int i = 0; i < FAKETCP_HEADER_DELTA; i++) {
		aligned[i] = head[i];
		shifted[i + 1] = head[i];
	}
	if (inverse)
		return bpf_csum_diff((__be32 *)shifted, sizeof(shifted),
				     (__be32 *)aligned, sizeof(aligned), seed);
	return bpf_csum_diff((__be32 *)aligned, sizeof(aligned),
			     (__be32 *)shifted, sizeof(shifted), seed);
}

// TC's public __sk_buff ABI does not expose ip_summed, csum_start or
// csum_offset, skb_dst or route PMTU. The prepare kfunc validates those hidden
// fields once, admits the exact planned L3 wire size and normalizes non-GSO
// CHECKSUM_PARTIAL before any type-word/XOR mutation. Its stable result is
// classified by faketcp_prepare_udp, so failures never collapse into a
// fallback path.
// The old UDP checksum is deliberately ignored because it is only a
// pseudo-header seed.
// This helper materializes a new TCP checksum from the IPv4 pseudo-header,
// constructed TCP header and complete final payload.
//
// Every read is bounded by the previously validated fixed-IHL IPv4 total
// length and FAKETCP_MAX_IPV4_TOTAL_LEN. bpf_skb_load_bytes handles a packet
// that was non-linear before change_tail. The final short chunk is zero padded,
// which is the Internet-checksum rule for odd-length payloads.
static __always_inline int faketcp_materialize_tcp_checksum(
						 struct __sk_buff *skb,
						 __be32 source,
						 __be32 destination,
						 struct tcphdr *tcp,
						 __u32 payload_off,
						 __u16 payload_len)
{
	struct faketcp_ipv4_pseudo_header pseudo = {
		.source = source,
		.destination = destination,
		.protocol = IPPROTO_TCP,
		.length = bpf_htons(sizeof(*tcp) + payload_len),
	};
	__u8 chunk[FAKETCP_CHECKSUM_CHUNK_BYTES] = {};
	__u32 processed = 0;
	__u32 remaining;
	__s64 sum;

	if (payload_len > FAKETCP_MAX_IPV4_TOTAL_LEN - sizeof(struct iphdr) -
			  sizeof(struct udphdr))
		return -1;
	tcp->check = 0;
	sum = bpf_csum_diff(0, 0, (__be32 *)&pseudo, sizeof(pseudo), 0);
	if (sum < 0)
		return -1;
	sum = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp), (__wsum)sum);
	if (sum < 0)
		return -1;

#pragma unroll
	for (int i = 0; i < FAKETCP_CHECKSUM_CHUNK_COUNT; i++) {
		if (processed + FAKETCP_CHECKSUM_CHUNK_BYTES > payload_len)
			break;
		if (bpf_skb_load_bytes(skb, payload_off + processed, chunk,
				       sizeof(chunk)) < 0)
			return -1;
		sum = bpf_csum_diff(0, 0, (__be32 *)chunk, sizeof(chunk),
				     (__wsum)sum);
		if (sum < 0)
			return -1;
		processed += FAKETCP_CHECKSUM_CHUNK_BYTES;
	}
	if (processed < payload_len) {
		remaining = payload_len - processed;
		if (remaining == 0 || remaining > sizeof(chunk))
			return -1;
		__builtin_memset(chunk, 0, sizeof(chunk));
		if (bpf_skb_load_bytes(skb, payload_off + processed, chunk,
				       remaining) < 0)
			return -1;
		sum = bpf_csum_diff(0, 0, (__be32 *)chunk, sizeof(chunk),
				     (__wsum)sum);
		if (sum < 0)
			return -1;
		processed += remaining;
	}
	if (processed != payload_len)
		return -1;
	tcp->check = bpf_htons(fold_csum(sum));
	if (tcp->check == 0)
		tcp->check = bpf_htons(0xffff);
	return 0;
}

// faketcp_encode_established is the single encoder used by both the direct
// type-word path and the XOR tail-call continuation.
static __always_inline int faketcp_encode_established(struct __sk_buff *skb,
						       struct packet_info *info,
						       struct egress_rule_value *rule,
						       __u64 generation)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct udphdr *udp = data + info->udp_off;
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct faketcp_l3_info l3;
	struct udphdr old_udp;
	struct tcphdr tcp = {};
	__u8 head[FAKETCP_HEADER_DELTA] = {};
	__u16 old_total_len, new_total_len, udp_len;
	__be32 source_ipv4, destination_ipv4;
	__u32 seq;

	if (rule->transport_mode != TRANSPORT_FAKETCP ||
	    faketcp_parse_tc_l3(skb, info, &l3) != FAKETCP_L3_OK ||
	    info->payload_len < FAKETCP_HEADER_DELTA ||
	    (void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return TC_ACT_SHOT;
	}
	if (skb->gso_segs || skb->gso_size) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	if (faketcp_tc_key(skb, info, &l3, generation, &key) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return TC_ACT_SHOT;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (!session || session->generation != generation) {
		// The preflight hook is the only place allowed to emit the handshake request
		// because it still owns the unmodified first packet. A map eviction in
		// this narrow post-transform race is a deliberate drop; WireGuard/QUIC
		// retransmission re-enters preflight with a capturable packet.
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
		return TC_ACT_SHOT;
	}
	if (session->state != FAKETCP_STATE_ESTABLISHED) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return TC_ACT_SHOT;
	}
	old_udp = *udp;
	udp_len = bpf_ntohs(old_udp.len);
	old_total_len = bpf_ntohs(iph->tot_len);
	if (udp_len != info->payload_len + sizeof(old_udp) ||
	    old_total_len != sizeof(*iph) + udp_len ||
	    old_total_len > FAKETCP_MAX_IPV4_TOTAL_LEN ||
	    old_total_len > 0xffff - FAKETCP_HEADER_DELTA ||
	    info->ip_off > skb->len || old_total_len != skb->len - info->ip_off ||
	    skb->len > 0xffffffffU - FAKETCP_HEADER_DELTA) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return TC_ACT_SHOT;
	}
	source_ipv4 = iph->saddr;
	destination_ipv4 = iph->daddr;
	if (bpf_skb_load_bytes(skb, info->payload_off, head, sizeof(head)) < 0) {
		inc_stat(STAT_SKB_LOAD_ERROR);
		return TC_ACT_SHOT;
	}
	// The kfunc admitted CHECKSUM_NONE or normalized validated CHECKSUM_PARTIAL
	// metadata to CHECKSUM_NONE. change_tail only grows/linearizes the skb;
	// old_udp.check is never treated as the final TCP checksum.
	if (bpf_skb_change_tail(skb, skb->len + FAKETCP_HEADER_DELTA, 0) < 0) {
		inc_stat(STAT_SKB_STORE_ERROR);
		return TC_ACT_SHOT;
	}
	if (bpf_skb_store_bytes(skb, skb->len - FAKETCP_HEADER_DELTA,
				head, sizeof(head), BPF_F_INVALIDATE_HASH) < 0) {
		inc_stat(STAT_SKB_STORE_ERROR);
		return TC_ACT_SHOT;
	}

	seq = __sync_fetch_and_add(&session->tx_sequence, info->payload_len);
	session->last_seen_nanos = bpf_ktime_get_ns();
	tcp.source = old_udp.source;
	tcp.dest = old_udp.dest;
	tcp.seq = bpf_htonl(seq);
	tcp.ack_seq = bpf_htonl(session->rx_sequence);
	tcp.doff = 5;
	tcp.ack = 1;
	tcp.psh = 1;
	tcp.window = bpf_htons(session->window ? session->window : 65535);
	if (faketcp_materialize_tcp_checksum(skb, source_ipv4, destination_ipv4,
					       &tcp,
					       info->udp_off + sizeof(tcp),
					       info->payload_len) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}
	if (bpf_skb_store_bytes(skb, info->udp_off, &tcp, sizeof(tcp),
				BPF_F_INVALIDATE_HASH) < 0) {
		inc_stat(STAT_SKB_STORE_ERROR);
		return TC_ACT_SHOT;
	}
	new_total_len = old_total_len + FAKETCP_HEADER_DELTA;
	if (bpf_l3_csum_replace(skb, info->ip_off + offsetof(struct iphdr, check),
				bpf_htons(old_total_len), bpf_htons(new_total_len), 2) < 0 ||
	    bpf_skb_store_bytes(skb, info->ip_off + offsetof(struct iphdr, tot_len),
				&(__be16){bpf_htons(new_total_len)}, sizeof(__be16),
				BPF_F_INVALIDATE_HASH) < 0 ||
	    update_ipv4_protocol(skb, info->ip_off, IPPROTO_UDP, IPPROTO_TCP) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
		return TC_ACT_SHOT;
	}

	// This encoder is deliberately non-GSO; supported aggregates were handled
	// by the per-segment transformer before reaching this continuation.
	inc_stat(STAT_EGRESS_REWRITE_OK);
	inc_faketcp_stat(FAKETCP_STAT_EGRESS_OK);
	return TC_ACT_OK;
}

static __always_inline int faketcp_continue_egress(struct __sk_buff *skb)
{
	struct packet_info info = {};
	struct egress_rule_key key = {};
	struct egress_rule_value *rule;
	__u64 generation = 0;

	if (!active_generation(&generation) || parse_packet(skb, &info, generation) != PARSE_OK)
		return TC_ACT_SHOT;
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
	if (!rule || rule->generation != generation ||
	    rule->transport_mode != TRANSPORT_FAKETCP) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return TC_ACT_SHOT;
	}
	return faketcp_encode_established(skb, &info, rule, generation);
}

SEC("classifier/faketcp_egress")
int wg_faketcp_egress(struct __sk_buff *skb)
{
	return faketcp_continue_egress(skb);
}

static __always_inline int faketcp_metadata_valid(struct __sk_buff *skb,
						   __u64 generation)
{
	void *data = (void *)(long)skb->data;
	void *meta = (void *)(long)skb->data_meta;
	struct faketcp_metadata *value = meta;

	if (meta + sizeof(*value) > data)
		return 0;
	return value->magic == FAKETCP_METADATA_MAGIC &&
	       value->generation_low == (__u32)generation;
}

static __always_inline int faketcp_xdp_managed_interface(__u32 ifindex,
						  __u64 generation)
{
	struct faketcp_managed_if_key key = {
		.generation = generation,
		.underlay_index = ifindex,
	};
	__u64 *value = bpf_map_lookup_elem(&faketcp_managed_if_map, &key);

	return value && *value == generation;
}

static __always_inline struct faketcp_managed_port_value *
faketcp_xdp_managed_port(__u32 ifindex, __u16 port, __u64 generation)
{
	struct faketcp_managed_port_key key = {
		.generation = generation,
		.underlay_index = ifindex,
		.destination_port = port,
	};
	struct faketcp_managed_port_value *value;

	value = bpf_map_lookup_elem(&faketcp_managed_port_map, &key);
	if (!value || value->generation != generation)
		return 0;
	return value;
}

static __always_inline int faketcp_xdp_l3_start(void *data, void *data_end,
						 __u8 parser_mode, __u32 *l3_off,
						 __u8 *family)
{
	__u32 off = sizeof(struct ethhdr);
	struct ethhdr *eth;
	__be16 protocol;

	if (parser_mode == PARSER_L3) {
		__u8 *first = data;

		if ((void *)(first + 1) > data_end)
			return FAKETCP_L3_TRUNCATED;
		*l3_off = 0;
		if ((*first >> 4) == 4) {
			*family = FAMILY_IPV4;
			return FAKETCP_L3_OK;
		}
		if ((*first >> 4) == 6) {
			*family = FAMILY_IPV6;
			return FAKETCP_L3_OK;
		}
		return FAKETCP_L3_MALFORMED;
	}
	// FakeTCP refuses parser:auto at state construction. Do not recreate an
	// ambiguous Ethernet/L3 fallback in the XDP hook.
	if (parser_mode != PARSER_ETHERNET)
		return FAKETCP_L3_UNSUPPORTED;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return FAKETCP_L3_TRUNCATED;
	protocol = eth->h_proto;
#pragma unroll
	for (int depth = 0; depth < 2; depth++) {
		struct wg_vlan_hdr *vlan;

		if (protocol != bpf_htons(ETH_P_8021Q) &&
		    protocol != bpf_htons(ETH_P_8021AD))
			break;
		vlan = data + off;
		if ((void *)(vlan + 1) > data_end)
			return FAKETCP_L3_TRUNCATED;
		protocol = vlan->h_vlan_encapsulated_proto;
		off += sizeof(*vlan);
	}
	if (protocol == bpf_htons(ETH_P_8021Q) ||
	    protocol == bpf_htons(ETH_P_8021AD))
		return FAKETCP_L3_UNSUPPORTED;
	*l3_off = off;
	if (protocol == bpf_htons(ETH_P_IP)) {
		*family = FAMILY_IPV4;
		return FAKETCP_L3_OK;
	}
	if (protocol == bpf_htons(ETH_P_IPV6)) {
		*family = FAMILY_IPV6;
		return FAKETCP_L3_OK;
	}
	return FAKETCP_L3_SAFE_BYPASS;
}

static __always_inline __u8 faketcp_tcp_flags(const struct tcphdr *tcp)
{
	const __u8 *raw = (const __u8 *)tcp;
	return raw[13];
}

static __always_inline __u8 faketcp_event_type(__u8 flags)
{
	if (flags & FAKETCP_FLAG_RST)
		return FAKETCP_EVENT_RST;
	if (flags & FAKETCP_FLAG_FIN)
		return FAKETCP_EVENT_FIN;
	if ((flags & (FAKETCP_FLAG_SYN | FAKETCP_FLAG_ACK)) ==
	    (FAKETCP_FLAG_SYN | FAKETCP_FLAG_ACK))
		return FAKETCP_EVENT_SYNACK;
	if (flags & FAKETCP_FLAG_SYN)
		return FAKETCP_EVENT_SYN;
	return FAKETCP_EVENT_ACK;
}

SEC("xdp")
int wg_mix_faketcp_ingress(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct udphdr *wire_ports;
	struct faketcp_l3_info l3;
	struct faketcp_managed_port_value *listener = 0;
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct faketcp_metadata *metadata;
	struct faketcp_pseudo_tail old_pseudo, new_pseudo;
	struct iphdr new_ip;
	struct tcphdr old_tcp;
	struct udphdr udp = {};
	__u8 tail[FAKETCP_HEADER_DELTA] = {};
	__u8 flags;
	__u8 family = 0;
	__u8 parser_mode;
	__u16 total_len, tcp_len, payload_len, new_total_len;
	__u32 frame_len, l3_off = 0, seq, next_seq;
	__u64 generation = 0;
	__s64 sum;
	int managed_interface, parse_rc;

	if (!active_generation(&generation))
		return XDP_PASS;
	managed_interface = faketcp_xdp_managed_interface(xdp->ingress_ifindex,
							 generation);
	frame_len = (__u32)((long)data_end - (long)data);
	parser_mode = lookup_parser_mode(xdp->ingress_ifindex, generation);
	parse_rc = faketcp_xdp_l3_start(data, data_end, parser_mode, &l3_off,
					       &family);
	if (parse_rc != FAKETCP_L3_OK)
		return parse_rc == FAKETCP_L3_SAFE_BYPASS ? XDP_PASS :
		       (managed_interface ? XDP_DROP : XDP_PASS);
	parse_rc = faketcp_parse_l3(data, data_end, frame_len, l3_off, family, &l3);
	if (parse_rc != FAKETCP_L3_OK)
		return parse_rc == FAKETCP_L3_SAFE_BYPASS ? XDP_PASS :
		       (managed_interface ? XDP_DROP : XDP_PASS);
	wire_ports = data + l3.l4_off;
	if ((void *)(wire_ports + 1) > data_end)
		return managed_interface ? XDP_DROP : XDP_PASS;
	listener = faketcp_xdp_managed_port(xdp->ingress_ifindex,
						    bpf_ntohs(wire_ports->dest), generation);
	if (!listener)
		return XDP_PASS;
	// ParseL3 can classify IPv4 options, IPv6 and TCP options, but the current
	// checksum/session ABI transforms only fixed-header IPv4. Reject once,
	// before native-UDP handling, event capture or any packet mutation.
	if (faketcp_managed_transform_status(&l3, l3.transport_protocol) !=
	    FAKETCP_L3_OK)
		return XDP_DROP;
	// Native UDP to a FakeTCP port is a transport-bypass attempt. Decoded
	// packets do not re-enter XDP, so this cannot catch the valid TCP-to-UDP
	// result produced later by this program.
	if (l3.transport_protocol == IPPROTO_UDP)
		return XDP_DROP;
	tcp = (struct tcphdr *)wire_ports;
	if ((void *)(tcp + 1) > data_end)
		return XDP_DROP;
	if (listener->action != ACTION_REWRITE)
		return XDP_DROP;
	iph = data + l3.l3_off;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;
	total_len = l3.l3_len;
	tcp_len = l3.l4_len;
	payload_len = tcp_len - sizeof(*tcp);
	flags = faketcp_tcp_flags(tcp);
	seq = bpf_ntohl(tcp->seq);
	// The current ring ABI does not carry the complete TCP packet, so
	// userspace cannot independently prove checksum and receive-window state.
	// Until the BPF validator capability is implemented, close controls must
	// never be emitted as session-deletion authority.
	if (flags & (FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return XDP_DROP;
	}
	key.generation = generation;
	key.local_ipv4 = iph->daddr;
	key.remote_ipv4 = iph->saddr;
	key.underlay_index = xdp->ingress_ifindex;
	key.local_port = bpf_ntohs(tcp->dest);
	key.remote_port = bpf_ntohs(tcp->source);
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (!session || session->generation != generation ||
	    session->state != FAKETCP_STATE_ESTABLISHED) {
		faketcp_emit_event(&key, faketcp_event_type(flags), flags, seq,
				   bpf_ntohl(tcp->ack_seq), payload_len, 0,
				   listener->wg_id);
		return XDP_DROP;
	}
	if (flags & (FAKETCP_FLAG_SYN | FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN)) {
		faketcp_emit_event(&key, faketcp_event_type(flags), flags, seq,
				   bpf_ntohl(tcp->ack_seq), payload_len, 0,
				   listener->wg_id);
		return XDP_DROP;
	}
	if (payload_len == 0 && flags == FAKETCP_FLAG_ACK) {
		// A userspace keepalive has no UDP image. Consume it before GRO and
		// refresh only the peer session's idle clock.
		session->last_seen_nanos = bpf_ktime_get_ns();
		return XDP_DROP;
	}
	if (!(flags & FAKETCP_FLAG_ACK) || payload_len < FAKETCP_HEADER_DELTA) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return XDP_DROP;
	}
	old_tcp = *tcp;
	if (bpf_xdp_load_bytes(xdp, l3.l3_off + total_len - FAKETCP_HEADER_DELTA,
			       tail, sizeof(tail)) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
		return XDP_DROP;
	}
	udp.source = old_tcp.source;
	udp.dest = old_tcp.dest;
	udp.len = bpf_htons(payload_len + sizeof(udp));
	udp.check = 0;
	old_pseudo = (struct faketcp_pseudo_tail){
		.protocol = IPPROTO_TCP,
		.length = bpf_htons(tcp_len),
	};
	new_pseudo = (struct faketcp_pseudo_tail){
		.protocol = IPPROTO_UDP,
		.length = udp.len,
	};
	sum = (~bpf_ntohs(old_tcp.check)) & 0xffff;
	old_tcp.check = 0;
	sum = bpf_csum_diff((__be32 *)&old_pseudo, sizeof(old_pseudo),
			     (__be32 *)&new_pseudo, sizeof(new_pseudo), sum);
	if (sum < 0)
		return XDP_DROP;
	sum = bpf_csum_diff((__be32 *)&old_tcp, sizeof(old_tcp),
			     (__be32 *)&udp, sizeof(udp), sum);
	if (sum < 0)
		return XDP_DROP;
	if (payload_len & 1) {
		sum = faketcp_rotation_checksum(tail, sum, 1);
		if (sum < 0)
			return XDP_DROP;
	}
	udp.check = bpf_htons(fold_csum(sum));
	if (udp.check == 0)
		udp.check = bpf_htons(0xffff);

	new_total_len = total_len - FAKETCP_HEADER_DELTA;
	if (bpf_xdp_adjust_meta(xdp, -(int)sizeof(struct faketcp_metadata)) < 0)
		return XDP_DROP;
	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;
	metadata = (void *)(long)xdp->data_meta;
	if ((void *)(metadata + 1) > data)
		return XDP_DROP;
	metadata->magic = FAKETCP_METADATA_MAGIC;
	metadata->generation_low = (__u32)generation;
	if (bpf_xdp_store_bytes(xdp, l3.l4_off, &udp, sizeof(udp)) < 0 ||
	    bpf_xdp_store_bytes(xdp, l3.l4_off + sizeof(udp), tail,
			       sizeof(tail)) < 0)
		return XDP_DROP;

	// The integration gate accepts only a fixed 20-byte IPv4 header, so one
	// bounded full-header checksum recomputation covers every transformed byte.
	iph = data + l3.l3_off;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;
	new_ip = *iph;
	new_ip.protocol = IPPROTO_UDP;
	new_ip.tot_len = bpf_htons(new_total_len);
	new_ip.check = 0;
	sum = bpf_csum_diff(0, 0, (__be32 *)&new_ip, sizeof(new_ip), 0);
	if (sum < 0)
		return XDP_DROP;
	new_ip.check = bpf_htons(fold_csum(sum));
	if (bpf_xdp_store_bytes(xdp, l3.l3_off, &new_ip, sizeof(new_ip)) < 0 ||
	    bpf_xdp_adjust_tail(xdp, -FAKETCP_HEADER_DELTA) < 0)
		return XDP_DROP;

	next_seq = seq + payload_len;
	if ((__s32)(next_seq - session->rx_sequence) > 0)
		__sync_val_compare_and_swap(&session->rx_sequence,
					    session->rx_sequence, next_seq);
	session->last_seen_nanos = bpf_ktime_get_ns();
	inc_faketcp_stat(FAKETCP_STAT_INGRESS_OK);
	return XDP_PASS;
}

#endif
