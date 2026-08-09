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
extern int wg_mix_faketcp_skb_normalize_udp_csum(struct __sk_buff *skb,
						  __u32 network_offset,
						  __u32 transport_offset,
						  __u32 udp_length) __ksym;

// Stable result ABI shared with kernel/faketcp_checksum.  Positive results
// identify the admitted checksum state; negative results classify a failure
// before the packet can be mutated.
#define FAKETCP_CSUM_ACCEPT_NONE           0
#define FAKETCP_CSUM_ACCEPT_PARTIAL_RESET  1
#define FAKETCP_CSUM_REJECT_PACKET        -1
#define FAKETCP_CSUM_REJECT_STATE         -2
#define FAKETCP_CSUM_REJECT_METADATA      -3
#define FAKETCP_CSUM_REJECT_GSO           -4

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
	FAKETCP_STAT_ADMISSION_ACCEPT,
	FAKETCP_STAT_ADMISSION_BYPASS_REJECT,
	FAKETCP_STAT_MAX,
};

#define FAKETCP_ADMISSION_F_TYPE_WORD      (1U << 0)
#define FAKETCP_ADMISSION_F_XOR            (1U << 1)
#define FAKETCP_ADMISSION_F_HEADER_REWRITE (1U << 2)
#define FAKETCP_ADMISSION_F_WIRE           (1U << 3)
#define FAKETCP_ADMISSION_REQUIRED_FEATURES \
	(FAKETCP_ADMISSION_F_TYPE_WORD | FAKETCP_ADMISSION_F_HEADER_REWRITE | \
	 FAKETCP_ADMISSION_F_WIRE)

#define FAKETCP_TOKEN_FREE         0
#define FAKETCP_TOKEN_ARMED        1
#define FAKETCP_TOKEN_XOR_COMPLETE 2

enum faketcp_admission_decision {
	FAKETCP_ADMISSION_DROP = 0,
	FAKETCP_ADMISSION_TRANSFORM = 1,
	FAKETCP_ADMISSION_CONTROL = 2,
	FAKETCP_ADMISSION_KEEPALIVE = 3,
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

// This projection is produced once from the unmodified packet. Direct egress
// consumes it in the same TC program; the XOR path stores it in a fresh
// per-CPU token slot and carries only its nonce through skb->cb.
struct faketcp_egress_admission {
	struct faketcp_session_key key;
	__u64 nonce;
	__u8 runtime_incarnation[16];
	__u32 fwmark;
	__u32 wg_id;
	__u32 profile_id;
	__u32 cipher_id;
	__u32 feature_mask;
	__u32 network_off;
	__u32 transport_off;
	__u32 payload_off;
	__u32 payload_len;
	__u32 ip_total_len;
	__u32 wire_len;
	__u32 skb_len;
	__u32 standard_wire;
	__u32 mixed_wire;
	__u32 profile_policy_flags;
	__u32 session_local_isn;
	__u32 session_remote_isn;
	__u32 xor_target;
	__u32 token_state;
	__u16 session_window;
	__u8 managed_action;
	__u8 rule_action;
	__u8 transport_mode;
	__u8 direction;
	__u8 session_state;
	__u8 session_flags;
	__u8 xor_checksum_mode;
	__u8 type_kind;
	__u8 pad[2];
};

struct faketcp_egress_admission_slot {
	// next_nonce survives consumption. Exhaustion fails closed rather than
	// reusing a nonce within this collection/CPU lifetime.
	__u64 next_nonce;
	struct faketcp_egress_admission active;
};

struct faketcp_ingress_admission {
	struct faketcp_session_key key;
	__u8 runtime_incarnation[16];
	__u32 wg_id;
	__u32 profile_id;
	__u32 cipher_id;
	__u32 feature_mask;
	__u32 profile_policy_flags;
	__u32 sequence;
	__u32 acknowledgement;
	__u32 payload_len;
	__u32 decoded_total_len;
	__u32 wire_total_len;
	__u32 network_off;
	__u32 transport_off;
	__u32 payload_off;
	__u32 xor_target;
	__u32 session_local_isn;
	__u32 session_remote_isn;
	__u32 input_wire;
	__u32 mixed_wire;
	__u32 standard_wire;
	__u16 session_window;
	__u8 tcp_flags;
	__u8 session_state;
	__u8 session_flags;
	__u8 type_kind;
	__u8 pad[6];
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

#define FAKETCP_DIRECTION_EGRESS 1
#define FAKETCP_DIRECTION_INGRESS 2
#define FAKETCP_ADMISSION_XDP_FEATURES \
	FAKETCP_ADMISSION_REQUIRED_FEATURES

struct faketcp_metadata {
	__u32 magic;
	__u8 direction;
	__u8 pad[3];
	struct faketcp_ingress_admission admission;
};

_Static_assert(sizeof(struct faketcp_egress_admission) == 136,
	       "faketcp egress admission ABI drift");
_Static_assert(sizeof(struct faketcp_egress_admission_slot) == 144,
	       "faketcp egress admission slot ABI drift");
_Static_assert(sizeof(struct faketcp_ingress_admission) == 128,
	       "faketcp ingress admission ABI drift");
_Static_assert(sizeof(struct faketcp_metadata) == 136,
	       "faketcp metadata ABI drift");

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

struct faketcp_ipv6_extension {
	__u8 next_header;
	__u8 header_length;
};

struct faketcp_ipv6_fragment {
	__u8 next_header;
	__u8 reserved;
	__be16 fragment_offset;
	__be32 identification;
};

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

// This collection-local slot is writable only by BPF. One networking program
// and its synchronous tail-call chain stay on the same CPU, so a per-CPU slot
// cannot be observed by another packet between ARMED and consume. PinNone
// gives each collection a fresh nonce domain; the syscall-side BPF_F_RDONLY
// flag prevents userspace from manufacturing an active proof.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(map_flags, BPF_F_RDONLY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct faketcp_egress_admission_slot);
} faketcp_egress_admission_map SEC(".maps");

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

static __always_inline void inc_faketcp_stat(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&faketcp_stats_map, &key);

	if (value)
		*value += 1;
}

static __always_inline int
faketcp_inspect_and_reset_udp_checksum(struct __sk_buff *skb,
					       __u32 network_offset,
					       __u32 transport_offset,
					       __u32 udp_length)
{
	int result;

	result = wg_mix_faketcp_skb_normalize_udp_csum(
		skb, network_offset, transport_offset, udp_length);
	switch (result) {
	case FAKETCP_CSUM_ACCEPT_NONE:
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_NONE_ACCEPTED);
		return 0;
	case FAKETCP_CSUM_ACCEPT_PARTIAL_RESET:
		// The module has cleared CHECKSUM_PARTIAL and its offsets.  The
		// encoder below completes the operation by materializing the final
		// TCP checksum from the transformed bytes.
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_PARTIAL_RESET);
		return 0;
	case FAKETCP_CSUM_REJECT_GSO:
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return -1;
	case FAKETCP_CSUM_REJECT_PACKET:
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return -1;
	case FAKETCP_CSUM_REJECT_STATE:
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_STATE_REJECT);
		return -1;
	case FAKETCP_CSUM_REJECT_METADATA:
		inc_faketcp_stat(FAKETCP_STAT_METADATA_ERROR);
		return -1;
	default:
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
		return -1;
	}
}

static __always_inline struct faketcp_runtime_identity_value *
faketcp_runtime_identity(__u64 generation)
{
	__u32 zero = 0;
	struct faketcp_runtime_identity_value *identity;
	__u8 nonzero = 0;

	identity = bpf_map_lookup_elem(&faketcp_rt_id, &zero);
	if (!identity || identity->generation != generation ||
	    identity->event_abi_version != FAKETCP_EVENT_ABI_VERSION)
		return 0;
#pragma unroll
	for (int i = 0; i < 16; i++)
		nonzero |= identity->incarnation[i];
	if (!nonzero)
		return 0;
	return identity;
}

static __always_inline int
faketcp_bind_runtime_identity(const struct faketcp_session_key *key,
			      struct faketcp_event *event)
{
	struct faketcp_runtime_identity_value *identity;

	identity = faketcp_runtime_identity(key->generation);
	if (!identity)
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
					   __u64 generation,
					   struct faketcp_session_key *key)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;

	if (info->family != FAMILY_IPV4 || (void *)(iph + 1) > data_end ||
	    iph->version != 4 || iph->ihl != 5)
		return -1;
	key->generation = generation;
	key->local_ipv4 = iph->saddr;
	key->remote_ipv4 = iph->daddr;
	key->underlay_index = skb->ifindex;
	key->local_port = info->src_port;
	key->remote_port = info->dst_port;
	return 0;
}

// Capture happens before type-word and XOR mutation. The userspace release
// path can therefore re-inject this exact IPv4 packet once and let the normal
// egress pipeline apply every transform in the required order.
static __always_inline int faketcp_capture_first_packet(struct __sk_buff *skb,
						 const struct packet_info *info,
						 const struct egress_rule_value *rule,
						 const struct faketcp_session_key *key)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct faketcp_packet_event *record;
	__u32 zero = 0;
	__u64 record_len;
	__u64 now;
	__u16 packet_len;

	if ((void *)(iph + 1) > data_end)
		return -1;
	packet_len = bpf_ntohs(iph->tot_len);
	if (packet_len < sizeof(*iph) + sizeof(struct udphdr) ||
	    packet_len > FAKETCP_MAX_CAPTURED_PACKET ||
	    (__u32)packet_len != sizeof(*iph) + sizeof(struct udphdr) +
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

static __always_inline struct faketcp_egress_admission *
faketcp_active_egress_admission(__u64 nonce)
{
	__u32 zero = 0;
	struct faketcp_egress_admission_slot *slot;

	if (nonce == 0)
		return 0;
	slot = bpf_map_lookup_elem(&faketcp_egress_admission_map, &zero);
	if (!slot || slot->active.nonce != nonce)
		return 0;
	return &slot->active;
}

// The only token consume primitive. It copies the active projection before
// clearing it, and it clears only active: the monotonic counter never moves
// backwards. A wrong or stale nonce still invalidates the current slot so a
// residual skb->cb can only fail closed.
static __always_inline int faketcp_consume_egress_admission(
	__u64 nonce, struct faketcp_egress_admission *consumed)
{
	__u32 zero = 0;
	struct faketcp_egress_admission_slot *slot;
	__u64 active_nonce;

	slot = bpf_map_lookup_elem(&faketcp_egress_admission_map, &zero);
	if (!slot)
		return -1;
	active_nonce = slot->active.nonce;
	if (consumed)
		*consumed = slot->active;
	__builtin_memset(&slot->active, 0, sizeof(slot->active));
	return nonce != 0 && active_nonce == nonce ? 0 : -1;
}

static __always_inline int faketcp_complete_egress_xor(__u64 nonce)
{
	struct faketcp_egress_admission *active;
	__u32 previous;

	active = faketcp_active_egress_admission(nonce);
	if (!active ||
	    active->feature_mask !=
		(FAKETCP_ADMISSION_REQUIRED_FEATURES | FAKETCP_ADMISSION_F_XOR) ||
	    active->cipher_id == 0 || active->xor_target == 0)
		return -1;
	previous = __sync_val_compare_and_swap(&active->token_state,
					       FAKETCP_TOKEN_ARMED,
					       FAKETCP_TOKEN_XOR_COMPLETE);
	return previous == FAKETCP_TOKEN_ARMED ? 0 : -1;
}

static __always_inline int faketcp_bind_egress_xor_progress(
	struct xor_context *context)
{
	struct faketcp_egress_admission *active;

	active = faketcp_active_egress_admission(context->admission_nonce);
	if (!active || active->token_state != FAKETCP_TOKEN_ARMED ||
	    active->feature_mask !=
		(FAKETCP_ADMISSION_REQUIRED_FEATURES | FAKETCP_ADMISSION_F_XOR) ||
	    active->key.generation == 0 || active->cipher_id == 0 ||
	    active->payload_off < sizeof(struct udphdr) ||
	    active->xor_target < 4 || active->xor_target > MAX_XOR_BYTES ||
	    active->xor_checksum_mode > XOR_CSUM_MANUAL)
		return -1;
	context->generation = active->key.generation;
	context->cipher_id = active->cipher_id;
	context->payload_off = active->payload_off;
	context->target = active->xor_target;
	context->checksum_mode = active->xor_checksum_mode;
	return 0;
}

static __always_inline int faketcp_runtime_incarnation_matches(
	__u64 generation, const __u8 expected[16])
{
	struct faketcp_runtime_identity_value *identity;
	__u8 different = 0;

	identity = faketcp_runtime_identity(generation);
	if (!identity)
		return 0;
#pragma unroll
	for (int i = 0; i < 16; i++)
		different |= identity->incarnation[i] ^ expected[i];
	return different == 0;
}

static __always_inline int faketcp_egress_admission_matches(
	struct __sk_buff *skb,
	const struct packet_info *info,
	const struct managed_fwmark_value *managed,
	const struct egress_rule_value *rule,
	const struct profile_value *profile,
	__u64 generation,
	__u32 required_state,
	const struct faketcp_egress_admission *admission)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct udphdr *udp = data + info->udp_off;
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct cipher_value *cipher = 0;
	__u32 xor_target = 0;
	__u32 required_features;
	__u32 current_wire = 0;
	__u32 expected_standard;
	__u32 ip_total_len;
	__u32 wire_len;

	if (!admission || !managed || !rule || !profile ||
	    required_state == FAKETCP_TOKEN_FREE ||
	    (void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end)
		return 0;
	required_features = FAKETCP_ADMISSION_REQUIRED_FEATURES |
			    (rule->cipher_id ? FAKETCP_ADMISSION_F_XOR : 0);
	if ((required_state == FAKETCP_TOKEN_XOR_COMPLETE) !=
	    (rule->cipher_id != 0) ||
	    bpf_skb_load_bytes(skb, info->payload_off, &current_wire,
			       sizeof(current_wire)) < 0)
		return 0;
	ip_total_len = bpf_ntohs(iph->tot_len);
	wire_len = bpf_ntohs(udp->len);
	if (admission->nonce == 0 || admission->token_state != required_state ||
	    admission->key.generation != generation ||
	    admission->direction != FAKETCP_DIRECTION_EGRESS ||
	    admission->feature_mask != required_features ||
	    admission->fwmark != skb->mark || admission->skb_len != skb->len ||
	    admission->network_off != info->ip_off ||
	    admission->transport_off != info->udp_off ||
	    admission->payload_off != info->payload_off ||
	    admission->payload_len != info->payload_len ||
	    admission->ip_total_len != ip_total_len ||
	    admission->wire_len != wire_len ||
	    admission->managed_action != managed->action_on_miss ||
	    admission->rule_action != rule->action ||
	    admission->transport_mode != rule->transport_mode ||
	    admission->wg_id != rule->wg_id ||
	    admission->profile_id != rule->profile_id ||
	    admission->cipher_id != rule->cipher_id ||
	    admission->profile_policy_flags != profile->policy_flags ||
	    admission->type_kind >= 4)
		return 0;
	expected_standard = wg_cpu_to_le32((__u32)admission->type_kind + 1);
	if (admission->standard_wire != expected_standard ||
	    admission->mixed_wire !=
		wg_cpu_to_le32(profile->standard_to_mixed[admission->type_kind]) ||
	    managed->generation != generation || rule->generation != generation ||
	    profile->generation != generation || rule->action != ACTION_REWRITE ||
	    rule->transport_mode != TRANSPORT_FAKETCP ||
	    !faketcp_runtime_incarnation_matches(
		generation, admission->runtime_incarnation))
		return 0;
	if (faketcp_tc_key(skb, info, generation, &key) < 0 ||
	    key.local_ipv4 != admission->key.local_ipv4 ||
	    key.remote_ipv4 != admission->key.remote_ipv4 ||
	    key.underlay_index != admission->key.underlay_index ||
	    key.local_port != admission->key.local_port ||
	    key.remote_port != admission->key.remote_port)
		return 0;
	if (rule->cipher_id != 0) {
		cipher = lookup_cipher(rule->cipher_id, generation);
		if (!cipher || xor_payload_target((struct packet_info *)info, cipher,
					       &xor_target) < 0 ||
		    xor_target != admission->xor_target ||
		    xor_type_word_copy(current_wire, cipher) != admission->mixed_wire)
			return 0;
	} else if (current_wire != admission->standard_wire ||
		   admission->xor_target != 0 ||
		   admission->xor_checksum_mode != XOR_CSUM_NONE) {
		return 0;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (!session || session->generation != generation ||
	    session->state != FAKETCP_STATE_ESTABLISHED ||
	    session->state != admission->session_state ||
	    session->flags != admission->session_flags ||
	    session->local_isn != admission->session_local_isn ||
	    session->remote_isn != admission->session_remote_isn ||
	    session->window != admission->session_window)
		return 0;
	return 1;
}

// This is the only TC egress admission checkpoint. It is deliberately pure
// with respect to packet bytes and checksum metadata: policy, parser output,
// direction, exact flow generation, bounds and the complete transform
// composition are proven before checksum normalization, capture, type-word,
// XOR or FakeTCP header mutation. A missing session may emit one bounded
// pre-transform capture, but the packet itself is always dropped unchanged.
static __always_inline int faketcp_egress_admission_checkpoint(
	struct __sk_buff *skb,
	const struct packet_info *info,
	const struct managed_fwmark_value *managed,
	const struct egress_rule_value *rule,
	const struct profile_value *profile,
	__u64 generation,
	int parser_classification,
	int type_kind,
	__u32 standard_wire,
	__u32 mixed_wire,
	__u8 xor_checksum_mode,
	struct faketcp_egress_admission *admission)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct udphdr *udp = data + info->udp_off;
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct faketcp_runtime_identity_value *identity;
	struct faketcp_egress_admission_slot *slot;
	struct cipher_value *cipher;
	__u32 zero = 0;
	__u32 feature_mask = FAKETCP_ADMISSION_REQUIRED_FEATURES;
	__u32 xor_target = 0;
	__u32 old_total_len;
	__u16 udp_len;

	__builtin_memset(admission, 0, sizeof(*admission));
	if (parser_classification != PARSE_OK || info->family != FAMILY_IPV4 ||
	    (void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end ||
	    iph->version != 4 || iph->ihl != 5 || iph->protocol != IPPROTO_UDP) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	if (!managed || !rule || !profile || generation == 0 ||
	    managed->generation != generation || rule->generation != generation ||
	    profile->generation != generation || rule->action != ACTION_REWRITE ||
	    rule->transport_mode != TRANSPORT_FAKETCP || type_kind < 0 ||
	    type_kind >= 4 ||
	    standard_wire != wg_cpu_to_le32((__u32)type_kind + 1) ||
	    mixed_wire != wg_cpu_to_le32(profile->standard_to_mixed[type_kind])) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return FAKETCP_ADMISSION_DROP;
	}
	if (rule->cipher_id != 0) {
		cipher = lookup_cipher(rule->cipher_id, generation);
		if (!cipher || xor_payload_target((struct packet_info *)info, cipher,
					       &xor_target) < 0) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
			return FAKETCP_ADMISSION_DROP;
		}
		feature_mask |= FAKETCP_ADMISSION_F_XOR;
	}

	// A UDP GSO skb represents several future wire packets, but this hook is
	// invoked only once for the aggregate. One header insertion cannot provide
	// a distinct TCP header, sequence number and checksum for every segment,
	// and the TC context cannot safely retag UDP GSO as TCP GSO. Reject before
	// type-word/XOR mutation or slow-path capture; this is a hard capability
	// gate, not an implementation of per-segment FakeTCP.
	if (skb->gso_segs || skb->gso_size) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return FAKETCP_ADMISSION_DROP;
	}
	if (info->payload_len < FAKETCP_HEADER_DELTA ||
	    info->payload_len > FAKETCP_MAX_IPV4_TOTAL_LEN -
				 sizeof(struct iphdr) - sizeof(struct udphdr)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	old_total_len = sizeof(struct iphdr) + sizeof(struct udphdr) +
			info->payload_len;
	udp_len = bpf_ntohs(udp->len);
	if (info->ip_off > skb->len || old_total_len != skb->len - info->ip_off ||
	    bpf_ntohs(iph->tot_len) != old_total_len ||
	    udp_len != sizeof(*udp) + info->payload_len) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	if (faketcp_tc_key(skb, info, generation, &key) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (session && session->generation == generation &&
	    session->state == FAKETCP_STATE_ESTABLISHED) {
		identity = faketcp_runtime_identity(generation);
		slot = bpf_map_lookup_elem(&faketcp_egress_admission_map, &zero);
		if (!identity || !slot || slot->active.nonce != 0 ||
		    slot->next_nonce == ~0ULL) {
			if (slot && slot->active.nonce != 0)
				faketcp_consume_egress_admission(
					slot->active.nonce, 0);
			inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
			return FAKETCP_ADMISSION_DROP;
		}
		slot->next_nonce++;
		if (slot->next_nonce == 0) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
			return FAKETCP_ADMISSION_DROP;
		}
		*admission = (struct faketcp_egress_admission){
			.key = key,
			.nonce = slot->next_nonce,
			.fwmark = skb->mark,
			.wg_id = rule->wg_id,
			.profile_id = rule->profile_id,
			.cipher_id = rule->cipher_id,
			.feature_mask = feature_mask,
			.network_off = info->ip_off,
			.transport_off = info->udp_off,
			.payload_off = info->payload_off,
			.payload_len = info->payload_len,
			.ip_total_len = old_total_len,
			.wire_len = udp_len,
			.skb_len = skb->len,
			.standard_wire = standard_wire,
			.mixed_wire = mixed_wire,
			.profile_policy_flags = profile->policy_flags,
			.session_local_isn = session->local_isn,
			.session_remote_isn = session->remote_isn,
			.xor_target = xor_target,
			.token_state = FAKETCP_TOKEN_ARMED,
			.session_window = session->window,
			.managed_action = managed->action_on_miss,
			.rule_action = rule->action,
			.transport_mode = rule->transport_mode,
			.direction = FAKETCP_DIRECTION_EGRESS,
			.session_state = session->state,
			.session_flags = session->flags,
			.xor_checksum_mode = rule->cipher_id ?
					     xor_checksum_mode : XOR_CSUM_NONE,
			.type_kind = type_kind,
		};
		__builtin_memcpy(admission->runtime_incarnation,
				 identity->incarnation,
				 sizeof(admission->runtime_incarnation));
		slot->active = *admission;
		return FAKETCP_ADMISSION_TRANSFORM;
	}
	if (session) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return FAKETCP_ADMISSION_DROP;
	} else {
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
	}
	if (faketcp_capture_first_packet(skb, info, rule, &key) < 0)
		inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
	return FAKETCP_ADMISSION_DROP;
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

// bpf_check_mtu interprets a non-zero mtu_len input as an L3 packet length.
// Asking about the planned +12 byte transport-header growth gives the exact
// pre-transform boundary: an input IPv4 packet must be no larger than the
// current underlay MTU minus FAKETCP_HEADER_DELTA. Route-specific PMTU is not
// exposed by this helper, so the activation gate still requires real-host PMTU
// acceptance rather than claiming that this interface-MTU check is sufficient.
static __always_inline int faketcp_mtu_allows_growth(struct __sk_buff *skb,
						      __u16 old_total_len)
{
	__u32 mtu_len = old_total_len;
	long rc;

	rc = bpf_check_mtu(skb, 0, &mtu_len, FAKETCP_HEADER_DELTA, 0);
	if (rc != 0 || mtu_len < FAKETCP_HEADER_DELTA ||
	    old_total_len > mtu_len - FAKETCP_HEADER_DELTA) {
		inc_faketcp_stat(FAKETCP_STAT_MTU_REJECT);
		return 0;
	}
	return 1;
}

// TC's public __sk_buff ABI does not expose ip_summed, csum_start or
// csum_offset. The required module kfunc accepts an already materialized
// CHECKSUM_NONE skb or validates and clears exactly one non-GSO UDP
// CHECKSUM_PARTIAL request before any type-word/XOR mutation. Its stable
// result is classified by faketcp_inspect_and_reset_udp_checksum, so a state,
// metadata, GSO or packet-shape failure never collapses into a generic counter.
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
						       __u64 generation,
						       const struct faketcp_egress_admission *admission)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data + info->ip_off;
	struct udphdr *udp = data + info->udp_off;
	struct faketcp_session_value *session;
	struct udphdr old_udp;
	struct tcphdr tcp = {};
	__u8 head[FAKETCP_HEADER_DELTA] = {};
	__u16 old_total_len, new_total_len, udp_len;
	__be32 source_ipv4, destination_ipv4;
	__u32 seq;

	if (!admission || admission->key.generation != generation ||
	    admission->direction != FAKETCP_DIRECTION_EGRESS ||
	    admission->cipher_id != rule->cipher_id ||
	    admission->payload_len != info->payload_len ||
	    admission->feature_mask !=
		(FAKETCP_ADMISSION_REQUIRED_FEATURES |
		 (admission->cipher_id ? FAKETCP_ADMISSION_F_XOR : 0)) ||
	    (void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &admission->key);
	if (!session || session->generation != generation) {
		// The checkpoint is the only place allowed to emit the handshake request
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
	if (!faketcp_mtu_allows_growth(skb, old_total_len))
		return TC_ACT_SHOT;
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

	// Aggregate GSO remains unsupported. Keep activation gated until the real
	// TC CHECKSUM_PARTIAL/metadata and NIC matrices prove this module boundary.
	inc_stat(STAT_EGRESS_REWRITE_OK);
	inc_faketcp_stat(FAKETCP_STAT_EGRESS_OK);
	return TC_ACT_OK;
}

static __always_inline int faketcp_continue_egress(struct __sk_buff *skb)
{
	struct packet_info info = {};
	struct egress_rule_key key = {};
	struct egress_rule_value *rule;
	struct managed_fwmark_value *managed;
	struct profile_key profile_key = {};
	struct profile_value *profile;
	struct faketcp_egress_admission admission = {};
	struct xor_context progress = {};
	__u64 generation = 0;
	int context_ok;
	int consume_rc;

	context_ok = load_xor_context(skb, &progress) == 0 &&
		     progress.continue_faketcp;
	// Consume is deliberately first. It copies then clears the per-CPU active
	// token before cb cleanup, parsing, lookup or comparison, so an independent
	// call and every malformed/residual cb path are single-use failures.
	consume_rc = faketcp_consume_egress_admission(
		progress.admission_nonce, &admission);
	clear_xor_context(skb);
	if (!context_ok || consume_rc < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	if (!active_generation(&generation) || parse_packet(skb, &info, generation) != PARSE_OK) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	managed = lookup_managed_fwmark(skb->mark, skb->ifindex, generation);
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
	if (!managed || !rule || rule->generation != generation) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	profile_key.generation = generation;
	profile_key.profile_id = rule->profile_id;
	profile = bpf_map_lookup_elem(&profile_map, &profile_key);
	if (!profile ||
	    !faketcp_egress_admission_matches(
		    skb, &info, managed, rule, profile, generation,
		    FAKETCP_TOKEN_XOR_COMPLETE, &admission)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT);
	return faketcp_encode_established(skb, &info, rule, generation,
					  &admission);
}

SEC("classifier/faketcp_egress")
int wg_faketcp_egress(struct __sk_buff *skb)
{
	return faketcp_continue_egress(skb);
}

static __always_inline int faketcp_consume_ingress_admission(
	struct __sk_buff *skb,
	const struct packet_info *info,
	const struct ingress_listener_value *listener,
	const struct profile_value *profile,
	__u64 generation)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	void *meta = (void *)(long)skb->data_meta;
	struct faketcp_metadata *metadata = meta;
	struct faketcp_metadata consumed = {};
	const struct faketcp_ingress_admission *admission = &consumed.admission;
	struct faketcp_session_value *session;
	struct cipher_value *cipher = 0;
	struct iphdr *iph = data + info->ip_off;
	__u32 xor_target = 0;
	__u32 feature_mask;
	__u32 next_sequence;
	__u32 decoded_total_len;
	__u32 input_wire = 0;
	__u32 mixed_wire;
	__u32 standard_wire;

	if (meta + sizeof(*metadata) > data) {
		inc_faketcp_stat(FAKETCP_STAT_METADATA_ERROR);
		return -1;
	}
	// The metadata is single-use even when malformed: copy every field needed by
	// this consumer, then clear magic before the first policy/GSO comparison.
	consumed = *metadata;
	metadata->magic = 0;
	if (consumed.magic != FAKETCP_METADATA_MAGIC ||
	    consumed.direction != FAKETCP_DIRECTION_INGRESS ||
	    consumed.pad[0] != 0 || consumed.pad[1] != 0 || consumed.pad[2] != 0) {
		inc_faketcp_stat(FAKETCP_STAT_METADATA_ERROR);
		return -1;
	}
	// Until a separately reviewed per-segment path exists, both GSO and GRO
	// coalescing are one capability failure with one counter classification.
	if (skb->gso_segs || skb->gso_size) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return -1;
	}
	if (!listener || !profile || (void *)(iph + 1) > data_end ||
	    listener->generation != generation ||
	    listener->transport_mode != TRANSPORT_FAKETCP ||
	    listener->action != ACTION_REWRITE ||
	    profile->generation != generation) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	feature_mask = FAKETCP_ADMISSION_XDP_FEATURES |
		       (listener->cipher_id ? FAKETCP_ADMISSION_F_XOR : 0);
	decoded_total_len = bpf_ntohs(iph->tot_len);
	if (bpf_skb_load_bytes(skb, info->payload_off, &input_wire,
			       sizeof(input_wire)) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	if (admission->key.generation != generation ||
	    admission->key.local_ipv4 != iph->daddr ||
	    admission->key.remote_ipv4 != iph->saddr ||
	    admission->key.underlay_index != skb->ifindex ||
	    admission->key.local_port != info->dst_port ||
	    admission->key.remote_port != info->src_port ||
	    admission->wg_id != listener->wg_id ||
	    admission->profile_id != listener->profile_id ||
	    admission->cipher_id != listener->cipher_id ||
	    admission->feature_mask != feature_mask ||
	    admission->profile_policy_flags != profile->policy_flags ||
	    admission->payload_len != info->payload_len ||
	    admission->decoded_total_len != decoded_total_len ||
	    admission->wire_total_len !=
		decoded_total_len + FAKETCP_HEADER_DELTA ||
	    admission->network_off != info->ip_off ||
	    admission->transport_off != info->udp_off ||
	    admission->payload_off != info->payload_off ||
	    admission->input_wire != input_wire || admission->type_kind >= 4 ||
	    admission->tcp_flags != (FAKETCP_FLAG_ACK | FAKETCP_FLAG_PSH) ||
	    admission->pad[0] != 0 || admission->pad[1] != 0 ||
	    admission->pad[2] != 0 || admission->pad[3] != 0 ||
	    admission->pad[4] != 0 || admission->pad[5] != 0 ||
	    !faketcp_runtime_incarnation_matches(
		generation, admission->runtime_incarnation)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	if (listener->cipher_id != 0) {
		cipher = lookup_cipher(listener->cipher_id, generation);
		if (!cipher || xor_payload_target((struct packet_info *)info, cipher,
					       &xor_target) < 0 ||
		    xor_target != admission->xor_target) {
			inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
			return -1;
		}
	} else if (admission->xor_target != 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	mixed_wire = input_wire;
	if (cipher)
		mixed_wire = xor_type_word_copy(mixed_wire, cipher);
	standard_wire = wg_cpu_to_le32((__u32)admission->type_kind + 1);
	if (admission->mixed_wire != mixed_wire ||
	    admission->standard_wire != standard_wire ||
	    profile->standard_to_mixed[admission->type_kind] !=
		wg_le32_to_cpu(mixed_wire) ||
	    !validate_len(admission->type_kind, admission->payload_len)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &admission->key);
	next_sequence = admission->sequence + admission->payload_len;
	if (!session || session->generation != generation ||
	    session->state != FAKETCP_STATE_ESTABLISHED ||
	    session->state != admission->session_state ||
	    session->flags != admission->session_flags ||
	    session->local_isn != admission->session_local_isn ||
	    session->remote_isn != admission->session_remote_isn ||
	    session->window != admission->session_window ||
	    (__s32)(session->rx_sequence - next_sequence) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT);
	return 0;
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

static __always_inline int faketcp_xdp_ipv6_policy(void *data, void *data_end,
						    __u64 off, __u32 ifindex,
						    __u64 generation,
						    int managed_interface)
{
	struct ipv6hdr *ip6 = data + off;
	__u8 next_header;

	if ((void *)(ip6 + 1) > data_end || ip6->version != 6)
		return managed_interface ? XDP_DROP : XDP_PASS;
	next_header = ip6->nexthdr;
	off += sizeof(*ip6);

#pragma unroll
	for (int depth = 0; depth < 4; depth++) {
		if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
			struct udphdr *ports = data + off;

			if ((void *)(ports + 1) > data_end)
				return managed_interface ? XDP_DROP : XDP_PASS;
			return faketcp_xdp_managed_port(ifindex,
							 bpf_ntohs(ports->dest),
							 generation) ? XDP_DROP : XDP_PASS;
		}
		if (next_header == NEXTHDR_FRAGMENT) {
			struct faketcp_ipv6_fragment *fragment = data + off;

			if ((void *)(fragment + 1) > data_end)
				return managed_interface ? XDP_DROP : XDP_PASS;
			// Non-initial fragments have no trustworthy destination port.
			if (bpf_ntohs(fragment->fragment_offset) & 0xfff8)
				return managed_interface ? XDP_DROP : XDP_PASS;
			next_header = fragment->next_header;
			off += sizeof(*fragment);
			continue;
		}
		if (next_header == NEXTHDR_HOP || next_header == NEXTHDR_ROUTING ||
		    next_header == NEXTHDR_DEST) {
			struct faketcp_ipv6_extension *extension = data + off;
			__u64 extension_length;

			if ((void *)(extension + 1) > data_end)
				return managed_interface ? XDP_DROP : XDP_PASS;
			extension_length = ((__u64)extension->header_length + 1) * 8;
			if (extension_length < 8 || data + off + extension_length > data_end)
				return managed_interface ? XDP_DROP : XDP_PASS;
			next_header = extension->next_header;
			off += extension_length;
			continue;
		}
		if (next_header == IPPROTO_ICMPV6 || next_header == NEXTHDR_NONE)
			return XDP_PASS;
		// AH, ESP and unknown extension/transport values cannot prove that
		// a managed TCP/UDP destination is absent. Never leak them to the
		// host stack on a managed interface.
		return managed_interface ? XDP_DROP : XDP_PASS;
	}
	// An extension chain deeper than the verifier-bounded parser is
	// ambiguous on a managed interface and must never reach the host stack.
	return managed_interface ? XDP_DROP : XDP_PASS;
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

// All managed FakeTCP wire packets reach this one bounded classifier before
// xdp metadata, header, payload, checksum or tail adjustment. Non-managed
// traffic has already taken the explicit XDP_PASS branch; every failure after
// a managed-port match is an explicit XDP_DROP.
static __always_inline int faketcp_xdp_admission_checkpoint(
	struct xdp_md *xdp,
	void *data,
	void *data_end,
	__u64 ip_off,
	struct iphdr *iph,
	struct tcphdr *tcp,
	const struct faketcp_managed_port_value *managed_listener,
	const struct ingress_listener_value *policy_listener,
	int managed_interface,
	__u64 generation,
	struct faketcp_ingress_admission *admission,
	struct faketcp_session_value **established_session)
{
	struct faketcp_session_value *session;
	struct faketcp_runtime_identity_value *identity;
	struct profile_key profile_key = {};
	struct profile_value *profile;
	struct cipher_value *cipher = 0;
	struct packet_info xor_info = {};
	__u32 feature_mask = FAKETCP_ADMISSION_XDP_FEATURES;
	__u32 xor_target = 0;
	__u32 input_wire = 0;
	__u32 mixed_wire = 0;
	__u16 fragment_offset;
	__u16 tcp_len;
	__u8 flags;
	int type_kind = -1;

	__builtin_memset(admission, 0, sizeof(*admission));
	*established_session = 0;
	if (!managed_interface || !managed_listener || !policy_listener ||
	    managed_listener->generation != generation ||
	    managed_listener->wg_id == 0 ||
	    managed_listener->action != ACTION_REWRITE ||
	    policy_listener->generation != generation ||
	    policy_listener->wg_id != managed_listener->wg_id ||
	    policy_listener->profile_id == 0 ||
	    policy_listener->action != ACTION_REWRITE ||
	    policy_listener->transport_mode != TRANSPORT_FAKETCP) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return FAKETCP_ADMISSION_DROP;
	}
	profile_key.generation = generation;
	profile_key.profile_id = policy_listener->profile_id;
	profile = bpf_map_lookup_elem(&profile_map, &profile_key);
	if (!profile || profile->generation != generation) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return FAKETCP_ADMISSION_DROP;
	}
	if ((void *)(iph + 1) > data_end || (void *)(tcp + 1) > data_end) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	fragment_offset = bpf_ntohs(iph->frag_off);
	if (iph->version != 4 || iph->ihl != 5 || iph->protocol != IPPROTO_TCP ||
	    (fragment_offset & (IP_MF | IP_OFFSET)) || tcp->doff != 5) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	admission->wire_total_len = bpf_ntohs(iph->tot_len);
	if (admission->wire_total_len < sizeof(*iph) + sizeof(*tcp) ||
	    admission->wire_total_len > FAKETCP_MAX_IPV4_TOTAL_LEN +
				   FAKETCP_HEADER_DELTA ||
	    data + ip_off + admission->wire_total_len > data_end) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	tcp_len = admission->wire_total_len - sizeof(*iph);
	admission->payload_len = tcp_len - sizeof(*tcp);
	admission->decoded_total_len =
		admission->wire_total_len - FAKETCP_HEADER_DELTA;
	admission->network_off = ip_off;
	admission->transport_off = ip_off + sizeof(*iph);
	admission->payload_off = admission->transport_off + sizeof(struct udphdr);
	flags = faketcp_tcp_flags(tcp);
	admission->tcp_flags = flags;
	admission->sequence = bpf_ntohl(tcp->seq);
	admission->acknowledgement = bpf_ntohl(tcp->ack_seq);
	admission->key = (struct faketcp_session_key){
		.generation = generation,
		.local_ipv4 = iph->daddr,
		.remote_ipv4 = iph->saddr,
		.underlay_index = xdp->ingress_ifindex,
		.local_port = bpf_ntohs(tcp->dest),
		.remote_port = bpf_ntohs(tcp->source),
	};
	if (admission->key.local_port == 0 || admission->key.remote_port == 0 ||
	    admission->key.underlay_index == 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	// Close-control authority is intentionally owned by the separate validated
	// close topic. Until that proof lands, these flags never reach a mutation.
	if (flags & (FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	if (policy_listener->cipher_id != 0) {
		xor_info.payload_off = admission->payload_off;
		xor_info.payload_len = admission->payload_len;
		cipher = lookup_cipher(policy_listener->cipher_id, generation);
		if (!cipher || xor_payload_target(&xor_info, cipher, &xor_target) < 0) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
			return FAKETCP_ADMISSION_DROP;
		}
		feature_mask |= FAKETCP_ADMISSION_F_XOR;
	}
	admission->wg_id = policy_listener->wg_id;
	admission->profile_id = policy_listener->profile_id;
	admission->cipher_id = policy_listener->cipher_id;
	admission->feature_mask = feature_mask;
	admission->profile_policy_flags = profile->policy_flags;
	admission->xor_target = xor_target;
	session = bpf_map_lookup_elem(&faketcp_session_map, &admission->key);
	if (!session || session->generation != generation ||
	    session->state != FAKETCP_STATE_ESTABLISHED) {
		if (session)
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		else
			inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
		return FAKETCP_ADMISSION_CONTROL;
	}
	identity = faketcp_runtime_identity(generation);
	if (!identity) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return FAKETCP_ADMISSION_DROP;
	}
	__builtin_memcpy(admission->runtime_incarnation, identity->incarnation,
			 sizeof(admission->runtime_incarnation));
	admission->session_local_isn = session->local_isn;
	admission->session_remote_isn = session->remote_isn;
	admission->session_window = session->window;
	admission->session_state = session->state;
	admission->session_flags = session->flags;
	*established_session = session;
	if (flags & FAKETCP_FLAG_SYN)
		return FAKETCP_ADMISSION_CONTROL;
	if (admission->payload_len == 0 && flags == FAKETCP_FLAG_ACK)
		return FAKETCP_ADMISSION_KEEPALIVE;
	if ((flags & ~(FAKETCP_FLAG_ACK | FAKETCP_FLAG_PSH)) != 0 ||
	    !(flags & FAKETCP_FLAG_ACK) ||
	    admission->payload_len < FAKETCP_HEADER_DELTA) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	if (bpf_xdp_load_bytes(xdp,
			       ip_off + sizeof(*iph) + sizeof(*tcp),
			       &input_wire, sizeof(input_wire)) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	mixed_wire = input_wire;
	if (cipher)
		mixed_wire = xor_type_word_copy(mixed_wire, cipher);
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (profile->standard_to_mixed[i] == wg_le32_to_cpu(mixed_wire)) {
			type_kind = i;
			break;
		}
	}
	if (type_kind < 0 || !validate_len(type_kind, admission->payload_len)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	admission->input_wire = input_wire;
	admission->mixed_wire = mixed_wire;
	admission->standard_wire = wg_cpu_to_le32((__u32)type_kind + 1);
	admission->type_kind = type_kind;
	return FAKETCP_ADMISSION_TRANSFORM;
}

SEC("xdp")
int wg_mix_faketcp_ingress(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	__u64 off = sizeof(struct ethhdr);
	struct ethhdr *eth = data;
	__be16 protocol;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct udphdr *wire_ports;
	struct faketcp_managed_port_value *managed_listener = 0;
	struct ingress_listener_value *policy_listener = 0;
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct faketcp_ingress_admission admission = {};
	struct faketcp_metadata *metadata;
	struct faketcp_pseudo_tail old_pseudo, new_pseudo;
	struct tcphdr old_tcp;
	struct udphdr udp = {};
	__u8 tail[FAKETCP_HEADER_DELTA] = {};
	__u8 flags;
	__u16 total_len, tcp_len, payload_len, new_total_len;
	__u32 seq, next_seq;
	__u64 generation = 0;
	__s64 sum;
	__u16 fragment_offset;
	__u32 ipv4_header_length;
	int managed_interface;
	int admission_decision;

	if (!active_generation(&generation))
		return XDP_PASS;
	managed_interface = faketcp_xdp_managed_interface(xdp->ingress_ifindex,
							 generation);
	if ((void *)(eth + 1) > data_end)
		return managed_interface ? XDP_DROP : XDP_PASS;
	protocol = eth->h_proto;
#pragma unroll
	for (int vlan_depth = 0; vlan_depth < 2; vlan_depth++) {
		if (protocol != bpf_htons(ETH_P_8021Q) &&
		    protocol != bpf_htons(ETH_P_8021AD))
			break;
		struct wg_vlan_hdr *vlan = data + off;
		if ((void *)(vlan + 1) > data_end)
			return managed_interface ? XDP_DROP : XDP_PASS;
		protocol = vlan->h_vlan_encapsulated_proto;
		off += sizeof(*vlan);
	}
	if (protocol == bpf_htons(ETH_P_8021Q) ||
	    protocol == bpf_htons(ETH_P_8021AD))
		return managed_interface ? XDP_DROP : XDP_PASS;
	if (protocol == bpf_htons(ETH_P_IPV6))
		return faketcp_xdp_ipv6_policy(data, data_end, off,
						 xdp->ingress_ifindex, generation,
						 managed_interface);
	if (protocol != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	iph = data + off;
	if ((void *)(iph + 1) > data_end || iph->version != 4 || iph->ihl < 5)
		return managed_interface ? XDP_DROP : XDP_PASS;
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		if (iph->protocol == IPPROTO_ICMP)
			return XDP_PASS;
		// AH, ESP, IP-in-IP, IPv6 encapsulation and unknown protocols can
		// carry a managed inner destination that this bounded parser cannot
		// classify. Match the IPv6 policy and fail closed on managed links.
		return managed_interface ? XDP_DROP : XDP_PASS;
	}
	fragment_offset = bpf_ntohs(iph->frag_off);
	if (fragment_offset & IP_OFFSET)
		return managed_interface ? XDP_DROP : XDP_PASS;
	ipv4_header_length = (__u32)iph->ihl * 4;
	if (data + off + ipv4_header_length > data_end)
		return managed_interface ? XDP_DROP : XDP_PASS;
	wire_ports = data + off + ipv4_header_length;
	if ((void *)(wire_ports + 1) > data_end)
		return managed_interface ? XDP_DROP : XDP_PASS;
	managed_listener = faketcp_xdp_managed_port(
		xdp->ingress_ifindex, bpf_ntohs(wire_ports->dest), generation);
	if (!managed_listener)
		return XDP_PASS;
	// Native UDP to a FakeTCP port is a transport-bypass attempt. Decoded
	// packets do not re-enter XDP, so this cannot catch the valid TCP-to-UDP
	// result produced later by this program.
	if (iph->protocol == IPPROTO_UDP)
		return XDP_DROP;
	tcp = (struct tcphdr *)wire_ports;
	if ((void *)(tcp + 1) > data_end)
		return XDP_DROP;
	policy_listener = lookup_ingress_listener(
		xdp->ingress_ifindex, bpf_ntohs(tcp->dest), FAMILY_IPV4,
		generation);
	// The policy lookup deliberately precedes the single admission checkpoint.
	// A managed packet can only PASS after that checkpoint and full decoding.
	admission_decision = faketcp_xdp_admission_checkpoint(
		xdp, data, data_end, off, iph, tcp, managed_listener,
		policy_listener, managed_interface, generation, &admission,
		&session);
	if (admission_decision == FAKETCP_ADMISSION_DROP)
		return XDP_DROP;
	key = admission.key;
	total_len = admission.wire_total_len;
	tcp_len = total_len - sizeof(*iph);
	payload_len = admission.payload_len;
	flags = admission.tcp_flags;
	seq = admission.sequence;
	if (admission_decision == FAKETCP_ADMISSION_CONTROL) {
		faketcp_emit_event(&key, faketcp_event_type(flags), flags, seq,
				   admission.acknowledgement, payload_len, 0,
				   managed_listener->wg_id);
		return XDP_DROP;
	}
	if (!session) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return XDP_DROP;
	}
	if (admission_decision == FAKETCP_ADMISSION_KEEPALIVE) {
		// A userspace keepalive has no UDP image. Consume it before GRO and
		// refresh only the peer session's idle clock.
		session->last_seen_nanos = bpf_ktime_get_ns();
		return XDP_DROP;
	}
	if (admission_decision != FAKETCP_ADMISSION_TRANSFORM) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return XDP_DROP;
	}
	old_tcp = *tcp;
	if (bpf_xdp_load_bytes(xdp, off + total_len - FAKETCP_HEADER_DELTA,
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
	metadata->direction = FAKETCP_DIRECTION_INGRESS;
	metadata->pad[0] = 0;
	metadata->pad[1] = 0;
	metadata->pad[2] = 0;
	metadata->admission = admission;
	if (bpf_xdp_store_bytes(xdp, off + sizeof(*iph), &udp, sizeof(udp)) < 0 ||
	    bpf_xdp_store_bytes(xdp, off + sizeof(*iph) + sizeof(udp), tail,
			       sizeof(tail)) < 0)
		return XDP_DROP;

	// This first slice accepts only a fixed 20-byte IPv4 header, so a full
	// header recomputation is bounded and avoids XDP checksum-helper gaps.
	iph = data + off;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;
	struct iphdr new_ip = *iph;
	new_ip.protocol = IPPROTO_UDP;
	new_ip.tot_len = bpf_htons(new_total_len);
	new_ip.check = 0;
	sum = bpf_csum_diff(0, 0, (__be32 *)&new_ip, sizeof(new_ip), 0);
	if (sum < 0)
		return XDP_DROP;
	new_ip.check = bpf_htons(fold_csum(sum));
	if (bpf_xdp_store_bytes(xdp, off, &new_ip, sizeof(new_ip)) < 0 ||
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
