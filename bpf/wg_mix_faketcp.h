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
#define FAKETCP_STATE_DELETE_CLAIMED 4

#define FAKETCP_CLAIM_MALFORMED 0
#define FAKETCP_CLAIM_ABSENT    1
#define FAKETCP_CLAIM_DIFFERENT 2
#define FAKETCP_CLAIMED         3

#define FAKETCP_SESSION_MUTATE_TX    1
#define FAKETCP_SESSION_MUTATE_RX    2
#define FAKETCP_SESSION_MUTATE_TOUCH 3

#define FAKETCP_EVENT_NEED_HANDSHAKE 1
#define FAKETCP_EVENT_SYN            2
#define FAKETCP_EVENT_SYNACK         3
#define FAKETCP_EVENT_ACK            4
#define FAKETCP_EVENT_RST            5
#define FAKETCP_EVENT_FIN            6
#define FAKETCP_EVENT_ABI_VERSION    2

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
	FAKETCP_STAT_ADMISSION_ACCEPT,
	FAKETCP_STAT_ADMISSION_BYPASS_REJECT,
	FAKETCP_STAT_MAX,
};

#define FAKETCP_ADMISSION_F_TYPE_WORD      (1U << 0)
#define FAKETCP_ADMISSION_F_XOR            (1U << 1)
#define FAKETCP_ADMISSION_F_HEADER_REWRITE (1U << 2)
#define FAKETCP_ADMISSION_F_WIRE           (1U << 3)
#define FAKETCP_ADMISSION_F_GSO            (1U << 4)
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
	FAKETCP_ADMISSION_CLOSE = 4,
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
	// This lock is deliberately embedded in each hash value: unrelated
	// sessions never share a serialisation point. Every packet-path read which
	// admits work, every mutable writer, and the userspace-triggered delete
	// claim use this exact lock.
	struct bpf_spin_lock lock;
	__u32 kernel_reserved;
	__u64 revision;
	__u64 session_id;
	__u8 runtime_incarnation[16];
};

// A claim request has the exact userspace value layout, but represents the
// kernel lock as an ordinary zero word: struct bpf_spin_lock is forbidden on
// the BPF stack. All other bytes participate in the comparison.
struct faketcp_session_expected_value {
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
	__u32 kernel_lock;
	__u32 kernel_reserved;
	__u64 revision;
	__u64 session_id;
	__u8 runtime_incarnation[16];
};

struct faketcp_session_claim_request {
	struct faketcp_session_key key;
	struct faketcp_session_expected_value expected;
};

struct faketcp_session_mutation_result {
	__u32 sequence;
	__u32 acknowledgement;
	__u16 window;
};

// Admission carries this stable lifetime authority between its checkpoint and
// final consumer. Mutable revision/sequence fields are deliberately excluded:
// concurrent packets in one session serialize at the final writer instead of
// rejecting one another as stale.
struct faketcp_session_authority {
	__u64 session_id;
	__u8 runtime_incarnation[16];
};

// These session-shape fields are immutable for one lifetime and bind the
// packet projection without turning the mutable revision into admission
// authority.
struct faketcp_session_projection {
	__u32 local_isn;
	__u32 remote_isn;
	__u16 window;
	__u8 state;
	__u8 flags;
};

// A locked internal snapshot retains mutable authority for the close decision.
// Ordinary transform admission projects only lifetime authority and never
// compares revision or sequences across programs or packet stages.
struct faketcp_session_snapshot {
	struct faketcp_session_authority authority;
	struct faketcp_session_projection projection;
	__u64 revision;
	__u32 tx_sequence;
	__u32 rx_sequence;
};

struct faketcp_ingress_transform_projection {
	__u32 xor_target;
	__u32 input_wire;
	__u32 mixed_wire;
	__u32 standard_wire;
};

struct faketcp_ingress_close_projection {
	__u64 session_revision;
	__u32 tx_sequence;
	__u32 rx_sequence;
};

// CLOSE terminates in XDP, while TRANSFORM is copied to TC metadata. Their
// mutually exclusive projection keeps the hot-path admission ABI at 136 bytes.
union faketcp_ingress_decision_projection {
	struct faketcp_ingress_transform_projection transform;
	struct faketcp_ingress_close_projection close;
};

// GSO admission binds both raw skb metadata and the normalized logical
// geometry. segment_contract is recomputed from every segment's index, length,
// input/output type word and XOR target before the single token is consumed.
struct faketcp_gso_projection {
	__u64 segment_contract;
	__u32 gso_size;
	__u32 raw_gso_segs;
	__u32 logical_segments;
	__u32 pad;
};

// This projection is produced once from the unmodified packet. Direct egress
// consumes it in the same TC program; the XOR path stores it in a fresh
// per-CPU token slot and carries only its nonce through skb->cb.
struct faketcp_egress_admission {
	struct faketcp_session_key key;
	__u64 nonce;
	struct faketcp_session_authority session_authority;
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
	__u32 xor_target;
	__u32 token_state;
	struct faketcp_gso_projection gso;
	struct faketcp_session_projection session_projection;
	__u8 managed_action;
	__u8 rule_action;
	__u8 transport_mode;
	__u8 direction;
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
	struct faketcp_session_authority session_authority;
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
	union faketcp_ingress_decision_projection decision;
	__u32 payload_off;
	struct faketcp_session_projection session_projection;
	__u8 tcp_flags;
	__u8 type_kind;
	__u8 pad[6];
};

_Static_assert(sizeof(struct faketcp_session_key) == 24,
	       "faketcp session key ABI drift");
_Static_assert(sizeof(struct faketcp_session_value) == 80,
	       "faketcp session value ABI drift");
_Static_assert(sizeof(struct faketcp_session_expected_value) == 80,
	       "faketcp expected session value ABI drift");
_Static_assert(sizeof(struct faketcp_session_claim_request) == 104,
	       "faketcp session claim request ABI drift");
_Static_assert(sizeof(struct faketcp_session_mutation_result) == 12,
	       "faketcp session mutation result drift");
_Static_assert(sizeof(struct faketcp_session_authority) == 24,
	       "faketcp session authority drift");
_Static_assert(sizeof(struct faketcp_session_projection) == 12,
	       "faketcp session projection drift");
_Static_assert(sizeof(struct faketcp_session_snapshot) == 56,
	       "faketcp session snapshot drift");
_Static_assert(__builtin_offsetof(struct faketcp_session_snapshot,
				    revision) == 40,
	       "faketcp session snapshot revision drift");
_Static_assert(__builtin_offsetof(struct faketcp_session_snapshot,
				    tx_sequence) == 48,
	       "faketcp session snapshot TX drift");
_Static_assert(__builtin_offsetof(struct faketcp_session_snapshot,
				    rx_sequence) == 52,
	       "faketcp session snapshot RX drift");
_Static_assert(sizeof(struct faketcp_ingress_transform_projection) == 16,
	       "faketcp ingress transform projection drift");
_Static_assert(sizeof(struct faketcp_ingress_close_projection) == 16,
	       "faketcp ingress close projection drift");
_Static_assert(sizeof(union faketcp_ingress_decision_projection) == 16,
	       "faketcp ingress decision projection drift");
_Static_assert(__builtin_offsetof(struct faketcp_ingress_admission,
				    decision) == 96,
	       "faketcp ingress decision projection offset drift");
_Static_assert(sizeof(struct faketcp_gso_projection) == 24,
	       "faketcp GSO projection drift");

struct faketcp_event {
	struct faketcp_session_key key;
	__u64 timestamp_nanos;
	__u8 runtime_incarnation[16];
	__u64 capture_sequence;
	__u64 session_revision;
	__u64 session_id;
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

_Static_assert(sizeof(struct faketcp_event) == 104, "faketcp event ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, runtime_incarnation) == 32,
	       "faketcp runtime incarnation ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, capture_sequence) == 48,
	       "faketcp capture sequence ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, session_revision) == 56,
	       "faketcp session revision ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, session_id) == 64,
	       "faketcp session ID ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, capture_cpu) == 72,
	       "faketcp capture CPU ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, event_abi_version) == 98,
	       "faketcp event version ABI drift");
_Static_assert(sizeof(struct faketcp_packet_event) == 2408,
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

_Static_assert(sizeof(struct faketcp_egress_admission) == 168,
	       "faketcp egress admission ABI drift");
_Static_assert(sizeof(struct faketcp_egress_admission_slot) == 176,
	       "faketcp egress admission slot ABI drift");
_Static_assert(sizeof(struct faketcp_ingress_admission) == 136,
	       "faketcp ingress admission ABI drift");
_Static_assert(sizeof(struct faketcp_metadata) == 144,
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

static __always_inline int faketcp_nonzero_incarnation(const __u8 incarnation[16])
{
	__u8 aggregate = 0;

#pragma unroll
	for (int i = 0; i < 16; i++)
		aggregate |= incarnation[i];
	return aggregate != 0;
}

static __always_inline int faketcp_session_metadata_valid_locked(
	const struct faketcp_session_value *session, __u64 generation)
{
	__u8 pad = 0;

#pragma unroll
	for (int i = 0; i < 4; i++)
		pad |= session->pad[i];
	return session->generation == generation &&
	       session->state == FAKETCP_STATE_ESTABLISHED &&
	       session->flags == 0 && pad == 0 &&
	       session->kernel_reserved == 0 && session->revision != 0 &&
	       session->session_id != 0 &&
	       faketcp_nonzero_incarnation(session->runtime_incarnation);
}

static __always_inline void faketcp_session_snapshot_locked(
	const struct faketcp_session_value *session,
	struct faketcp_session_snapshot *snapshot)
{
	snapshot->revision = session->revision;
	snapshot->authority.session_id = session->session_id;
	__builtin_memcpy(snapshot->authority.runtime_incarnation,
			 session->runtime_incarnation,
			 sizeof(snapshot->authority.runtime_incarnation));
	snapshot->projection.local_isn = session->local_isn;
	snapshot->projection.remote_isn = session->remote_isn;
	snapshot->projection.window = session->window;
	snapshot->projection.state = session->state;
	snapshot->projection.flags = session->flags;
	snapshot->tx_sequence = session->tx_sequence;
	snapshot->rx_sequence = session->rx_sequence;
}

static __always_inline int faketcp_session_authority_matches_locked(
	const struct faketcp_session_value *session, __u64 generation,
	const struct faketcp_session_authority *expected_authority,
	const struct faketcp_session_projection *expected_projection)
{
	__u8 difference = 0;

	if (!expected_authority || !expected_projection ||
	    !faketcp_session_metadata_valid_locked(session, generation) ||
	    session->session_id != expected_authority->session_id ||
	    session->local_isn != expected_projection->local_isn ||
	    session->remote_isn != expected_projection->remote_isn ||
	    session->window != expected_projection->window ||
	    session->state != expected_projection->state ||
	    session->flags != expected_projection->flags)
		return 0;
#pragma unroll
	for (int i = 0; i < 16; i++)
		difference |= session->runtime_incarnation[i] ^
			      expected_authority->runtime_incarnation[i];
	return difference == 0;
}

// A successful snapshot is the read-side linearisation point. Transform code
// carries authority plus the immutable projection; mutable fields are reserved
// for the close decision and never become ordinary admission equality.
static __always_inline int faketcp_session_snapshot_established(
	struct faketcp_session_value *session, __u64 generation,
	struct faketcp_session_snapshot *snapshot)
{
	int admitted;

	if (!session || !snapshot)
		return 0;
	__builtin_memset(snapshot, 0, sizeof(*snapshot));

	bpf_spin_lock(&session->lock);
	admitted = faketcp_session_metadata_valid_locked(session, generation);
	if (admitted)
		faketcp_session_snapshot_locked(session, snapshot);
	bpf_spin_unlock(&session->lock);
	return admitted;
}

static __always_inline int faketcp_session_authority_matches(
	struct faketcp_session_value *session, __u64 generation,
	const struct faketcp_session_authority *expected_authority,
	const struct faketcp_session_projection *expected_projection)
{
	int matched;

	if (!session || !expected_authority || !expected_projection)
		return 0;
	bpf_spin_lock(&session->lock);
	matched = faketcp_session_authority_matches_locked(
		session, generation, expected_authority, expected_projection);
	bpf_spin_unlock(&session->lock);
	return matched;
}

// Every mutable TC/XDP path converges here. Packet work and time helpers run
// before this function; the per-session lock covers only state revalidation,
// the required field update, one revision increment, and the tiny TX snapshot.
static __always_inline int faketcp_session_mutate(
	struct faketcp_session_value *session, __u64 generation, __u64 now,
	__u32 operation, __u32 argument,
	const struct faketcp_session_authority *expected_authority,
	const struct faketcp_session_projection *expected_projection,
	struct faketcp_session_mutation_result *result)
{
	int admitted;

	if (!session || operation < FAKETCP_SESSION_MUTATE_TX ||
	    operation > FAKETCP_SESSION_MUTATE_TOUCH ||
	    !expected_authority || !expected_projection ||
	    (operation == FAKETCP_SESSION_MUTATE_TX && !result))
		return 0;
	if (result)
		__builtin_memset(result, 0, sizeof(*result));
	bpf_spin_lock(&session->lock);
	admitted = faketcp_session_authority_matches_locked(
			session, generation, expected_authority,
			expected_projection) &&
		   session->revision != ~0ULL;
	if (admitted) {
		if (operation == FAKETCP_SESSION_MUTATE_TX) {
			result->sequence = session->tx_sequence;
			result->acknowledgement = session->rx_sequence;
			result->window = session->window;
			session->tx_sequence += argument;
		} else if (operation == FAKETCP_SESSION_MUTATE_RX &&
			   (__s32)(argument - session->rx_sequence) > 0) {
			session->rx_sequence = argument;
		}
		if (now > session->last_seen_nanos)
			session->last_seen_nanos = now;
		session->revision++;
	}
	bpf_spin_unlock(&session->lock);
	return admitted;
}

static __always_inline int faketcp_session_matches_expected_locked(
	const struct faketcp_session_value *session,
	const struct faketcp_session_expected_value *expected,
	int permit_claimed_state)
{
	__u8 difference = 0;

	if (session->generation != expected->generation ||
	    session->last_seen_nanos != expected->last_seen_nanos ||
	    session->tx_sequence != expected->tx_sequence ||
	    session->rx_sequence != expected->rx_sequence ||
	    session->local_isn != expected->local_isn ||
	    session->remote_isn != expected->remote_isn ||
	    session->window != expected->window ||
	    session->flags != expected->flags ||
	    session->kernel_reserved != expected->kernel_reserved ||
	    session->revision != expected->revision ||
	    session->session_id != expected->session_id)
		return 0;
	if (session->state != expected->state &&
	    !(permit_claimed_state &&
	      session->state == FAKETCP_STATE_DELETE_CLAIMED &&
	      expected->state == FAKETCP_STATE_ESTABLISHED))
		return 0;
#pragma unroll
	for (int i = 0; i < 4; i++)
		difference |= session->pad[i] ^ expected->pad[i];
#pragma unroll
	for (int i = 0; i < 16; i++)
		difference |= session->runtime_incarnation[i] ^
			      expected->runtime_incarnation[i];
	return difference == 0;
}

static __always_inline int faketcp_claim_request_valid(
	const struct faketcp_session_claim_request *request)
{
	const struct faketcp_session_expected_value *expected = &request->expected;
	__u8 pad = 0;

#pragma unroll
	for (int i = 0; i < 4; i++)
		pad |= expected->pad[i];
	return request->key.generation != 0 &&
	       request->key.generation == expected->generation &&
	       expected->state == FAKETCP_STATE_ESTABLISHED &&
	       expected->flags == 0 && pad == 0 && expected->kernel_lock == 0 &&
	       expected->kernel_reserved == 0 && expected->revision != 0 &&
	       expected->session_id != 0 &&
	       faketcp_nonzero_incarnation(expected->runtime_incarnation);
}

// This program is never attached. Userspace invokes it with BPF_PROG_TEST_RUN
// after proving from ProgramInfo.MapIDs that its sole map is the exact session
// map bound to the store. ESTABLISHED -> DELETE_CLAIMED under the per-session
// lock is the compare-delete linearisation point. Repeating the same complete
// expected value after a crash between claim and delete is idempotent; a
// different revision/incarnation/value never inherits that authority.
SEC("classifier/faketcp_session_claim")
int wg_faketcp_session_claim(struct __sk_buff *skb)
{
	struct faketcp_session_claim_request request = {};
	struct faketcp_session_value *session;
	int result = FAKETCP_CLAIM_DIFFERENT;

	if (skb->len != sizeof(request) ||
	    bpf_skb_load_bytes(skb, 0, &request, sizeof(request)) < 0 ||
	    !faketcp_claim_request_valid(&request))
		return FAKETCP_CLAIM_MALFORMED;
	session = bpf_map_lookup_elem(&faketcp_session_map, &request.key);
	if (!session)
		return FAKETCP_CLAIM_ABSENT;

	bpf_spin_lock(&session->lock);
	if (faketcp_session_matches_expected_locked(session, &request.expected, 1)) {
		if (session->state == FAKETCP_STATE_ESTABLISHED)
			session->state = FAKETCP_STATE_DELETE_CLAIMED;
		result = FAKETCP_CLAIMED;
	}
	bpf_spin_unlock(&session->lock);
	return result;
}

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

static __always_inline int
faketcp_output_packet_event(struct faketcp_packet_event *record,
			    __u16 packet_len)
{
	__u64 record_len;

	if (packet_len == 0 || packet_len > FAKETCP_MAX_CAPTURED_PACKET)
		return -1;
	record_len = sizeof(record->event) + packet_len;
	return bpf_ringbuf_output(&faketcp_events, record, record_len, 0);
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

	// The authoritative TC descriptor already applied the sole fixed-header
	// IPv4 gate. Keep only descriptor coherence and verifier bounds here.
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

// One descriptor owns both the generic rule-lookup result and the stricter
// FakeTCP projection. The observation and L3 views share storage because the
// latter is derived immediately from scalar fields loaded by the sole parser.
union faketcp_tc_packet_shape {
	struct packet_parse_observation observation;
	struct faketcp_l3_info l3;
};

struct faketcp_tc_packet_descriptor {
	union faketcp_tc_packet_shape shape;
	struct packet_info info;
	int generic_status;
	int faketcp_status;
};

_Static_assert(sizeof(struct faketcp_tc_packet_descriptor) == 64,
	       "FakeTCP TC packet descriptor layout drift");

static __always_inline int
faketcp_tc_status_from_generic(int status)
{
	switch (status) {
	case PARSE_SHORT:
		return FAKETCP_L3_TRUNCATED;
	case PARSE_IPV4_FIRST_FRAGMENT:
	case PARSE_IPV6_FRAGMENT_FIRST:
		return FAKETCP_L3_FIRST_FRAGMENT;
	case PARSE_IPV4_NON_FIRST_FRAGMENT:
	case PARSE_IPV6_FRAGMENT_NON_FIRST:
		return FAKETCP_L3_NONINITIAL_FRAGMENT;
	case PARSE_IPV6_EXT_TOO_DEEP:
		return FAKETCP_L3_EXTENSION_TOO_DEEP;
	case PARSE_BAD_CSUM:
		return FAKETCP_L3_MALFORMED;
	default:
		return FAKETCP_L3_UNSUPPORTED;
	}
}

static __always_inline int
faketcp_tc_project_ipv4_udp(struct faketcp_tc_packet_descriptor *packet)
{
	__u32 frame_len = packet->shape.observation.frame_len;
	__u32 total_len = packet->shape.observation.ipv4_total_len;
	__u16 header_len = packet->shape.observation.ipv4_header_len;
	__u16 fragment = packet->shape.observation.ipv4_fragment;
	__u16 udp_len = packet->shape.observation.udp_len;
	__u8 version = packet->shape.observation.ip_version;
	__u8 protocol = packet->shape.observation.ip_protocol;
	struct faketcp_l3_info *l3 = &packet->shape.l3;

	__builtin_memset(l3, 0, sizeof(*l3));
	l3->l3_off = packet->info.ip_off;
	l3->family = packet->info.family;
	if (packet->info.family != FAMILY_IPV4)
		return FAKETCP_L3_UNSUPPORTED;
	if (version != 4 || header_len < sizeof(struct iphdr))
		return FAKETCP_L3_MALFORMED;
	if (packet->info.ip_off > frame_len ||
	    total_len > frame_len - packet->info.ip_off)
		return FAKETCP_L3_TRUNCATED;
	if (total_len < header_len)
		return FAKETCP_L3_MALFORMED;

	l3->l3_len = total_len;
	l3->l3_header_len = header_len;
	l3->l4_off = packet->info.ip_off + header_len;
	l3->l4_len = total_len - header_len;
	l3->transport_protocol = protocol;
	if (header_len > sizeof(struct iphdr))
		l3->flags |= FAKETCP_L3_F_IPV4_OPTIONS;
	if (fragment & IP_RESERVED)
		return FAKETCP_L3_MALFORMED;
	if (fragment & IP_DF)
		l3->flags |= FAKETCP_L3_F_IPV4_DF;
	if ((fragment & IP_DF) && (fragment & (IP_MF | IP_OFFSET)))
		return FAKETCP_L3_MALFORMED;
	if (fragment & IP_OFFSET)
		return FAKETCP_L3_NONINITIAL_FRAGMENT;
	if (fragment & IP_MF)
		return FAKETCP_L3_FIRST_FRAGMENT;
	if (protocol != IPPROTO_UDP)
		return FAKETCP_L3_UNSUPPORTED;
	if (udp_len < sizeof(struct udphdr) || udp_len != l3->l4_len)
		return FAKETCP_L3_MALFORMED;
	l3->l4_header_len = sizeof(struct udphdr);
	return FAKETCP_L3_OK;
}

static __always_inline int
faketcp_parse_tc_egress_packet(struct __sk_buff *skb, __u64 generation,
				struct faketcp_tc_packet_descriptor *packet)
{
	__builtin_memset(packet, 0, sizeof(*packet));
	packet->generic_status = parse_packet_observed(
		skb, &packet->info, &packet->shape.observation, generation);
	if (packet->generic_status == PARSE_OK)
		packet->faketcp_status = faketcp_tc_project_ipv4_udp(packet);
	else {
		packet->faketcp_status =
			faketcp_tc_status_from_generic(packet->generic_status);
		__builtin_memset(&packet->shape.l3, 0,
				 sizeof(packet->shape.l3));
	}
	return packet->generic_status;
}

static __always_inline int faketcp_tc_fixed_udp_status(
	const struct faketcp_tc_packet_descriptor *packet)
{
	if (packet->faketcp_status != FAKETCP_L3_OK)
		return packet->faketcp_status;
	if (faketcp_managed_transform_status(&packet->shape.l3, IPPROTO_UDP) !=
	    FAKETCP_L3_OK)
		return FAKETCP_L3_UNSUPPORTED;
	if (packet->shape.l3.l3_off != packet->info.ip_off ||
	    packet->shape.l3.l4_off != packet->info.udp_off ||
	    packet->shape.l3.l4_len !=
		    sizeof(struct udphdr) + packet->info.payload_len)
		return FAKETCP_L3_MALFORMED;
	return FAKETCP_L3_OK;
}

// XOR may mutate payload bytes and the UDP checksum, but it must not alter the
// admitted fixed IPv4/UDP envelope. Re-read only those fixed header scalars
// before trusting the projection; this is deliberately not an L3 parser.
static __always_inline int faketcp_tc_current_admission_coherent(
	struct __sk_buff *skb, const struct faketcp_egress_admission *admission)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph;
	struct udphdr *udp;
	__u16 fragment;

	if (!admission || admission->network_off > skb->len ||
	    admission->transport_off < admission->network_off ||
	    admission->payload_off < admission->transport_off ||
	    admission->transport_off - admission->network_off !=
		    sizeof(struct iphdr) ||
	    admission->payload_off - admission->transport_off !=
		    sizeof(struct udphdr) ||
	    admission->wire_len < sizeof(struct udphdr) ||
	    admission->wire_len - sizeof(struct udphdr) !=
		    admission->payload_len ||
	    admission->ip_total_len < sizeof(struct iphdr) ||
	    admission->ip_total_len - sizeof(struct iphdr) !=
		    admission->wire_len ||
	    admission->skb_len != skb->len ||
	    admission->ip_total_len != skb->len - admission->network_off ||
	    admission->cipher_id == 0 ||
	    admission->xor_checksum_mode > XOR_CSUM_RECOMPUTE)
		return -1;
	iph = data + admission->network_off;
	udp = data + admission->transport_off;
	if ((void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end)
		return -1;
	fragment = bpf_ntohs(iph->frag_off);
	if (iph->version != 4 || iph->ihl != sizeof(*iph) / 4 ||
	    iph->protocol != IPPROTO_UDP ||
	    (fragment & (IP_RESERVED | IP_MF | IP_OFFSET)) ||
	    bpf_ntohs(iph->tot_len) != admission->ip_total_len ||
	    bpf_ntohs(udp->len) != admission->wire_len ||
	    bpf_ntohs(udp->source) != admission->key.local_port ||
	    bpf_ntohs(udp->dest) != admission->key.remote_port ||
	    ((udp->check == 0) !=
	     (admission->xor_checksum_mode == XOR_CSUM_NONE)))
		return -1;
	return 0;
}

static __always_inline void faketcp_tc_descriptor_from_admission(
	const struct faketcp_egress_admission *admission,
	struct faketcp_tc_packet_descriptor *packet)
{
	__builtin_memset(packet, 0, sizeof(*packet));
	packet->shape.l3 = (struct faketcp_l3_info){
		.l3_off = admission->network_off,
		.l3_len = admission->ip_total_len,
		.l4_off = admission->transport_off,
		.l4_len = admission->wire_len,
		.l3_header_len = sizeof(struct iphdr),
		.l4_header_len = sizeof(struct udphdr),
		.family = FAMILY_IPV4,
		.transport_protocol = IPPROTO_UDP,
	};
	packet->info = (struct packet_info){
		.family = FAMILY_IPV4,
		.ip_off = admission->network_off,
		.udp_off = admission->transport_off,
		.payload_off = admission->payload_off,
		.payload_len = admission->payload_len,
		.src_port = admission->key.local_port,
		.dst_port = admission->key.remote_port,
		.ipv4_udp_csum_zero =
			admission->xor_checksum_mode == XOR_CSUM_NONE,
	};
	packet->generic_status = PARSE_OK;
	packet->faketcp_status = FAKETCP_L3_OK;
}

// TC ingress receives an XDP-decoded packet, so it deliberately revalidates
// that independent program boundary. Egress must use the single descriptor
// above and never call this helper.
static __always_inline int faketcp_revalidate_tc_ingress_l3(
	struct __sk_buff *skb, const struct packet_info *info,
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
	if (faketcp_output_packet_event(record, packet_len) < 0)
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

static __always_inline int faketcp_incarnations_equal(
	const __u8 left[16], const __u8 right[16])
{
	__u8 different = 0;

#pragma unroll
	for (int i = 0; i < 16; i++)
		different |= left[i] ^ right[i];
	return different == 0;
}

static __always_inline int faketcp_runtime_incarnation_matches(
	__u64 generation, const __u8 expected[16])
{
	struct faketcp_runtime_identity_value *identity;

	identity = faketcp_runtime_identity(generation);
	return identity && faketcp_incarnations_equal(identity->incarnation,
						 expected);
}

static __always_inline int faketcp_gso_build_projection(
	struct __sk_buff *skb, const struct packet_info *info,
	const struct profile_value *profile, struct cipher_value *cipher,
	struct faketcp_gso_projection *projection, __u32 *max_xor_target);

static __always_inline int faketcp_gso_projection_matches(
	const struct faketcp_gso_projection *left,
	const struct faketcp_gso_projection *right)
{
	return left->segment_contract == right->segment_contract &&
	       left->gso_size == right->gso_size &&
	       left->raw_gso_segs == right->raw_gso_segs &&
	       left->logical_segments == right->logical_segments &&
	       left->pad == 0 && right->pad == 0;
}

static __always_inline int faketcp_egress_admission_matches(
	struct __sk_buff *skb,
	const struct packet_info *info,
	const struct faketcp_l3_info *l3,
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
	struct faketcp_gso_projection observed_gso = {};
	struct cipher_value *cipher = 0;
	__u32 xor_target = 0;
	__u32 required_features;
	__u32 current_wire = 0;
	__u32 expected_standard;
	__u32 ip_total_len;
	__u32 wire_len;
	__u8 expected_xor_checksum_mode = XOR_CSUM_NONE;
	int is_gso = skb->gso_segs || skb->gso_size;

	if (!l3 || faketcp_managed_transform_status(l3, IPPROTO_UDP) !=
			   FAKETCP_L3_OK ||
	    l3->l3_off != info->ip_off || l3->l4_off != info->udp_off ||
	    l3->l4_len != sizeof(struct udphdr) + info->payload_len ||
	    !admission || !managed || !rule || !profile ||
	    required_state == FAKETCP_TOKEN_FREE ||
	    (void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end)
		return 0;
	required_features = FAKETCP_ADMISSION_REQUIRED_FEATURES |
			    (rule->cipher_id ? FAKETCP_ADMISSION_F_XOR : 0) |
			    (is_gso ? FAKETCP_ADMISSION_F_GSO : 0);
	if ((is_gso && required_state != FAKETCP_TOKEN_ARMED) ||
	    (!is_gso &&
	     ((required_state == FAKETCP_TOKEN_XOR_COMPLETE) !=
	      (rule->cipher_id != 0))) ||
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
		generation,
		admission->session_authority.runtime_incarnation))
		return 0;
	if (faketcp_tc_key(skb, info, l3, generation, &key) < 0 ||
	    key.local_ipv4 != admission->key.local_ipv4 ||
	    key.remote_ipv4 != admission->key.remote_ipv4 ||
	    key.underlay_index != admission->key.underlay_index ||
	    key.local_port != admission->key.local_port ||
	    key.remote_port != admission->key.remote_port)
		return 0;
	if (rule->cipher_id != 0) {
		cipher = lookup_cipher(rule->cipher_id, generation);
		if (!cipher)
			return 0;
	}
	if (is_gso) {
		if (faketcp_gso_build_projection(skb, info, profile, cipher,
						 &observed_gso, &xor_target) < 0 ||
		    !faketcp_gso_projection_matches(&admission->gso,
						     &observed_gso) ||
		    current_wire != admission->standard_wire ||
		    xor_target != admission->xor_target ||
		    admission->xor_checksum_mode != XOR_CSUM_NONE)
			return 0;
	} else {
		if (!validate_len(admission->type_kind, admission->payload_len) ||
		    admission->gso.segment_contract != 0 ||
		    admission->gso.gso_size != 0 ||
		    admission->gso.raw_gso_segs != 0 ||
		    admission->gso.logical_segments != 0 ||
		    admission->gso.pad != 0)
			return 0;
		if (cipher) {
			if (xor_payload_target((struct packet_info *)info, cipher,
						       &xor_target) < 0 ||
			    xor_target != admission->xor_target ||
			    xor_type_word_copy(current_wire, cipher) !=
				admission->mixed_wire)
				return 0;
			if (info->family == FAMILY_IPV4 &&
			    !info->ipv4_udp_csum_zero)
				expected_xor_checksum_mode = XOR_CSUM_RECOMPUTE;
			else if (info->family == FAMILY_IPV6)
				expected_xor_checksum_mode = XOR_CSUM_MANUAL;
		} else if (current_wire != admission->standard_wire ||
			   admission->xor_target != 0) {
			return 0;
		}
		if (admission->xor_checksum_mode != expected_xor_checksum_mode)
			return 0;
	}
	if (admission->session_authority.session_id == 0 ||
	    admission->session_projection.state != FAKETCP_STATE_ESTABLISHED ||
	    admission->session_projection.flags != 0 || admission->pad[0] != 0 ||
	    admission->pad[1] != 0)
		return 0;
	return 1;
}

// This is the only TC egress admission checkpoint. The shared fixed-IPv4 gate
// and the unified skb prepare run first; prepare may normalize checksum/GSO
// metadata but never packet bytes. Policy, exact flow/lifetime, aggregate
// geometry and the complete type/XOR/header composition are then projected
// into one single-use token before capture or packet-byte mutation.
static __always_inline int faketcp_egress_admission_checkpoint(
	struct __sk_buff *skb,
	const struct packet_info *info,
	const struct faketcp_l3_info *l3,
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
	struct faketcp_gso_projection gso = {};
	struct faketcp_session_value *session;
	struct faketcp_session_snapshot session_snapshot = {};
	struct faketcp_runtime_identity_value *identity;
	struct faketcp_egress_admission_slot *slot;
	struct cipher_value *cipher = 0;
	__u32 zero = 0;
	__u32 feature_mask = FAKETCP_ADMISSION_REQUIRED_FEATURES;
	__u32 xor_target = 0;
	__u32 old_total_len;
	__u16 udp_len;
	int is_gso = skb->gso_segs || skb->gso_size;

	__builtin_memset(admission, 0, sizeof(*admission));
	if (parser_classification != PARSE_OK || !l3 ||
	    l3->l3_off != info->ip_off || l3->l4_off != info->udp_off ||
	    l3->l4_len != sizeof(struct udphdr) + info->payload_len ||
	    info->family != FAMILY_IPV4 ||
	    (void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end) {
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
		if (!cipher) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
			return FAKETCP_ADMISSION_DROP;
		}
		feature_mask |= FAKETCP_ADMISSION_F_XOR;
	}
	if (is_gso) {
		feature_mask |= FAKETCP_ADMISSION_F_GSO;
		if (xor_checksum_mode != XOR_CSUM_NONE ||
		    faketcp_gso_build_projection(skb, info, profile, cipher,
						 &gso, &xor_target) < 0) {
			inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
			return FAKETCP_ADMISSION_DROP;
		}
	} else if ((rule->cipher_id != 0 &&
		    xor_payload_target((struct packet_info *)info, cipher,
					       &xor_target) < 0) ||
		   !validate_len(type_kind, info->payload_len)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	if (info->payload_len < FAKETCP_HEADER_DELTA ||
	    info->payload_len > (is_gso ?
				 FAKETCP_GSO_MAX_PAYLOAD :
				 FAKETCP_MAX_IPV4_TOTAL_LEN -
				 sizeof(struct iphdr) - sizeof(struct udphdr))) {
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
	if (faketcp_tc_key(skb, info, l3, generation, &key) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &key);
	if (faketcp_session_snapshot_established(
		    session, generation, &session_snapshot)) {
		identity = faketcp_runtime_identity(generation);
		slot = bpf_map_lookup_elem(&faketcp_egress_admission_map, &zero);
		if (!identity ||
		    !faketcp_incarnations_equal(identity->incarnation,
					       session_snapshot.authority.runtime_incarnation) ||
		    !slot || slot->active.nonce != 0 ||
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
			.session_authority = session_snapshot.authority,
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
			.xor_target = xor_target,
			.token_state = FAKETCP_TOKEN_ARMED,
			.gso = gso,
			.session_projection = session_snapshot.projection,
			.managed_action = managed->action_on_miss,
			.rule_action = rule->action,
			.transport_mode = rule->transport_mode,
			.direction = FAKETCP_DIRECTION_EGRESS,
			.xor_checksum_mode = rule->cipher_id && !is_gso ?
					     xor_checksum_mode : XOR_CSUM_NONE,
			.type_kind = type_kind,
		};
		slot->active = *admission;
		return FAKETCP_ADMISSION_TRANSFORM;
	}
	if (session) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return FAKETCP_ADMISSION_DROP;
	} else {
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
	}
	if (is_gso)
		return FAKETCP_ADMISSION_DROP;
	if (faketcp_capture_first_packet(skb, info, l3, rule, &key) < 0)
		inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
	return FAKETCP_ADMISSION_DROP;
}

struct faketcp_gso_loop_context {
	struct __sk_buff *skb;
	struct cipher_value *cipher;
	__u64 segment_contract;
	__u32 mixed_type[4];
	__u32 payload_offset;
	__u32 payload_length;
	__u32 gso_size;
	__u32 gso_segments;
	__u32 xor_chunks_per_segment;
	__u32 max_xor_target;
	int error;
};

static __always_inline __u64 faketcp_gso_contract_word(__u64 contract,
							__u32 word)
{
	return (contract ^ word) * 1099511628211ULL;
}

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
	__u32 mixed_wire;
	__u32 xor_target = 0;
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
	if (context->cipher) {
		xor_target = segment_length < context->cipher->max_bytes ?
			     segment_length : context->cipher->max_bytes;
		if (xor_target > context->max_xor_target)
			context->max_xor_target = xor_target;
	}
	mixed_wire = wg_cpu_to_le32(context->mixed_type[kind]);
	context->segment_contract = faketcp_gso_contract_word(
		context->segment_contract, index);
	context->segment_contract = faketcp_gso_contract_word(
		context->segment_contract, segment_length);
	context->segment_contract = faketcp_gso_contract_word(
		context->segment_contract, wire_type);
	context->segment_contract = faketcp_gso_contract_word(
		context->segment_contract, mixed_wire);
	context->segment_contract = faketcp_gso_contract_word(
		context->segment_contract, xor_target);
	return 0;
}

static __always_inline int faketcp_gso_build_projection(
	struct __sk_buff *skb, const struct packet_info *info,
	const struct profile_value *profile, struct cipher_value *cipher,
	struct faketcp_gso_projection *projection, __u32 *max_xor_target)
{
	struct faketcp_gso_loop_context context = {
		.skb = skb,
		.cipher = cipher,
		.segment_contract = 1469598103934665603ULL,
		.payload_offset = info->payload_off,
		.payload_length = info->payload_len,
		.gso_size = skb->gso_size,
	};
	__u32 expected_segments;

	if (!profile || !projection || !max_xor_target ||
	    info->payload_len > FAKETCP_GSO_MAX_PAYLOAD ||
	    info->payload_len <= skb->gso_size || skb->gso_size < 32 ||
	    info->payload_off > skb->len ||
	    info->payload_len > skb->len - info->payload_off ||
	    (cipher && (!cipher->max_bytes ||
			cipher->max_bytes > MAX_XOR_BYTES)))
		return -1;
	expected_segments = (info->payload_len + skb->gso_size - 1) /
			    skb->gso_size;
	if (expected_segments < 2 || skb->gso_segs != expected_segments ||
	    info->payload_len - (expected_segments - 1) * skb->gso_size < 32)
		return -1;
	context.gso_segments = expected_segments;
#pragma unroll
	for (int kind = 0; kind < 4; kind++)
		context.mixed_type[kind] = profile->standard_to_mixed[kind];
	if (bpf_loop(context.gso_segments, faketcp_gso_validate_segment,
		     &context, 0) != context.gso_segments || context.error)
		return -1;
	*projection = (struct faketcp_gso_projection){
		.segment_contract = context.segment_contract,
		.gso_size = context.gso_size,
		.raw_gso_segs = skb->gso_segs,
		.logical_segments = context.gso_segments,
	};
	*max_xor_target = context.max_xor_target;
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
			    const struct faketcp_l3_info *l3,
			    const struct managed_fwmark_value *managed,
			    const struct egress_rule_value *rule,
			    const struct profile_value *profile,
			    __u64 generation, int parser_classification,
			    int type_kind, __u32 standard_wire,
			    __u32 mixed_wire)
{
	struct faketcp_gso_loop_context context = {
		.skb = skb,
		.payload_offset = info->payload_off,
		.payload_length = info->payload_len,
		.gso_size = skb->gso_size,
	};
	struct faketcp_egress_admission admission = {};
	struct faketcp_session_value *session;
	struct faketcp_session_mutation_result mutation = {};
	__u32 xor_chunks;
	__u32 xor_segment_bytes;
	__u64 now;
	__u64 ack_window;
	int result;

	if (!l3 || !managed || !rule || !profile ||
	    rule->transport_mode != TRANSPORT_FAKETCP ||
	    info->payload_len <= skb->gso_size ||
	    info->payload_len > FAKETCP_GSO_MAX_PAYLOAD ||
	    skb->gso_size < 32 ||
	    info->payload_off > skb->len ||
	    info->payload_len > skb->len - info->payload_off) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
	// Unified prepare is the sole checksum/GSO/PMTU/writability admission and
	// runs exactly once before the proof is formed or any packet byte changes.
	if (faketcp_prepare_udp(skb, info->ip_off, info->udp_off,
				 info->payload_len + sizeof(struct udphdr), 1) < 0)
		return TC_ACT_SHOT;
	if (faketcp_egress_admission_checkpoint(
		    skb, info, l3, managed, rule, profile, generation,
		    parser_classification, type_kind, standard_wire, mixed_wire,
		    XOR_CSUM_NONE, &admission) != FAKETCP_ADMISSION_TRANSFORM)
		return TC_ACT_SHOT;
	if (faketcp_consume_egress_admission(admission.nonce, &admission) < 0 ||
	    !faketcp_egress_admission_matches(
		    skb, info, l3, managed, rule, profile, generation,
		    FAKETCP_TOKEN_ARMED, &admission)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	context.gso_size = admission.gso.gso_size;
	context.gso_segments = admission.gso.logical_segments;
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
	session = bpf_map_lookup_elem(&faketcp_session_map, &admission.key);
	if (!session) {
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
		return TC_ACT_SHOT;
	}

	// Packet validation, allocation and every per-segment rewrite stay outside
	// the value lock. This sole mutation revalidates ESTABLISHED, advances the
	// aggregate sequence once, publishes revision/last_seen and snapshots every
	// header field consumed by commit.
	now = bpf_ktime_get_ns();
	if (!faketcp_session_mutate(session, generation, now,
				    FAKETCP_SESSION_MUTATE_TX,
				    context.payload_length,
				    &admission.session_authority,
				    &admission.session_projection,
				    &mutation)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return TC_ACT_SHOT;
	}
	inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT);
	ack_window = mutation.acknowledgement |
		     ((__u64)(mutation.window ? mutation.window : 65535) << 32);
	result = wg_mix_faketcp_skb_commit_udp_gso(
		skb, info->ip_off, info->udp_off, mutation.sequence, ack_window);
	if (result != FAKETCP_GSO_COMMIT_ACCEPT) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return TC_ACT_SHOT;
	}
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
	__u64 now;
	struct faketcp_session_mutation_result mutation = {};

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
	if (!session) {
		// The checkpoint is the only place allowed to emit the handshake request
		// because it still owns the unmodified first packet. A map eviction in
		// this narrow post-transform race is a deliberate drop; WireGuard/QUIC
		// retransmission re-enters preflight with a capturable packet.
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
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

	// No session field is consumed before this call. Helpers and packet rewrite
	// stay outside the critical section; this single short region both admits
	// the established value and linearises its update. A delete claim which
	// wins the same per-session lock drops the rewritten skb before emission.
	now = bpf_ktime_get_ns();
	if (!faketcp_session_mutate(session, generation, now,
				    FAKETCP_SESSION_MUTATE_TX,
				    info->payload_len,
				    &admission->session_authority,
				    &admission->session_projection,
				    &mutation)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return TC_ACT_SHOT;
	}
	inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT);
	tcp.source = old_udp.source;
	tcp.dest = old_udp.dest;
	tcp.seq = bpf_htonl(mutation.sequence);
	tcp.ack_seq = bpf_htonl(mutation.acknowledgement);
	tcp.doff = 5;
	tcp.ack = 1;
	tcp.psh = 1;
	tcp.window = bpf_htons(mutation.window ? mutation.window : 65535);
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
	struct faketcp_tc_packet_descriptor packet = {};
	struct packet_info *info = &packet.info;
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
	// token before cb cleanup, projection, lookup or comparison, so an independent
	// call and every malformed/residual cb path are single-use failures.
	consume_rc = faketcp_consume_egress_admission(
		progress.admission_nonce, &admission);
	clear_xor_context(skb);
	if (!context_ok || consume_rc < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	if (!active_generation(&generation) ||
	    faketcp_tc_current_admission_coherent(skb, &admission) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	faketcp_tc_descriptor_from_admission(&admission, &packet);
	managed = lookup_managed_fwmark(skb->mark, skb->ifindex, generation);
	key.generation = generation;
	key.fwmark = skb->mark;
	key.underlay_index = skb->ifindex;
	key.source_port = info->src_port;
	key.family = info->family;
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
		    skb, info, &packet.shape.l3, managed, rule, profile, generation,
		    FAKETCP_TOKEN_XOR_COMPLETE, &admission)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	return faketcp_encode_established(skb, info, rule, generation,
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
	    admission->decision.transform.input_wire != input_wire ||
	    admission->type_kind >= 4 ||
	    admission->tcp_flags != (FAKETCP_FLAG_ACK | FAKETCP_FLAG_PSH) ||
	    admission->pad[0] != 0 || admission->pad[1] != 0 ||
	    admission->pad[2] != 0 || admission->pad[3] != 0 ||
	    admission->pad[4] != 0 || admission->pad[5] != 0 ||
	    !faketcp_runtime_incarnation_matches(
		generation,
		admission->session_authority.runtime_incarnation)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	if (listener->cipher_id != 0) {
		cipher = lookup_cipher(listener->cipher_id, generation);
		if (!cipher || xor_payload_target((struct packet_info *)info, cipher,
					       &xor_target) < 0 ||
		    xor_target != admission->decision.transform.xor_target) {
			inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
			return -1;
		}
	} else if (admission->decision.transform.xor_target != 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	mixed_wire = input_wire;
	if (cipher)
		mixed_wire = xor_type_word_copy(mixed_wire, cipher);
	standard_wire = wg_cpu_to_le32((__u32)admission->type_kind + 1);
	if (admission->decision.transform.mixed_wire != mixed_wire ||
	    admission->decision.transform.standard_wire != standard_wire ||
	    profile->standard_to_mixed[admission->type_kind] !=
		wg_le32_to_cpu(mixed_wire) ||
	    !validate_len(admission->type_kind, admission->payload_len)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &admission->key);
	if (!faketcp_session_authority_matches(
		    session, generation, &admission->session_authority,
		    &admission->session_projection)) {
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

// Close controls are deliberately canonical and payload-free. Validate both
// checksums in XDP before spending control-event budget; userspace repeats the
// validation against a fresh complete-value snapshot before teardown
// authority is granted. A mathematically valid zero TCP checksum field is
// accepted because only the complete one's-complement residual is authoritative.
static __always_inline int
faketcp_close_checksums_valid(const struct iphdr *iph,
			      const struct tcphdr *tcp)
{
	struct faketcp_ipv4_pseudo_header pseudo = {
		.source = iph->saddr,
		.destination = iph->daddr,
		.protocol = IPPROTO_TCP,
		.length = bpf_htons(sizeof(*tcp)),
	};
	__s64 sum;

	sum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), 0);
	if (sum < 0 || fold_csum(sum) != 0)
		return 0;
	sum = bpf_csum_diff(0, 0, (__be32 *)&pseudo, sizeof(pseudo), 0);
	if (sum < 0)
		return 0;
	sum = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(*tcp), (__wsum)sum);
	return sum >= 0 && fold_csum(sum) == 0;
}

static __always_inline int
faketcp_capture_close_packet(struct xdp_md *xdp, __u32 packet_off,
			     __u16 packet_len,
			     const struct faketcp_ingress_admission *admission)
{
	struct faketcp_packet_event *record;
	__u32 zero = 0;
	__u64 now;
	__u8 event_type;

	if (packet_len != sizeof(struct iphdr) + sizeof(struct tcphdr) ||
	    !admission)
		return -1;
	event_type = faketcp_event_type(admission->tcp_flags);
	record = bpf_map_lookup_elem(&faketcp_capture_scratch, &zero);
	if (!record)
		return -1;
	now = bpf_ktime_get_ns();
	if (!faketcp_admit_control_event(&admission->key, admission->wg_id,
					 event_type, now))
		return 0;
	record->event = (struct faketcp_event){
		.key = admission->key,
		.timestamp_nanos = now,
		.session_revision = admission->decision.close.session_revision,
		.session_id = admission->session_authority.session_id,
		.sequence = admission->decision.close.rx_sequence,
		.acknowledgement = admission->decision.close.tx_sequence,
		.wg_id = admission->wg_id,
		.packet_length = packet_len,
		.event_abi_version = FAKETCP_EVENT_ABI_VERSION,
		.type = event_type,
		.tcp_flags = admission->tcp_flags,
	};
#pragma unroll
	for (int i = 0; i < 16; i++)
		record->event.runtime_incarnation[i] =
			admission->session_authority.runtime_incarnation[i];
	if (bpf_xdp_load_bytes(xdp, packet_off, record->packet, packet_len) < 0)
		return -1;
	if (faketcp_output_packet_event(record, packet_len) < 0)
		return -1;
	return 0;
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
	const struct faketcp_l3_info *l3,
	const struct faketcp_managed_port_value *managed_listener,
	const struct ingress_listener_value *policy_listener,
	int managed_interface,
	__u64 generation,
	struct faketcp_ingress_admission *admission,
	struct faketcp_session_value **established_session)
{
	struct faketcp_session_value *session;
	struct faketcp_session_snapshot session_snapshot = {};
	struct faketcp_runtime_identity_value *identity;
	struct profile_key profile_key = {};
	struct profile_value *profile;
	struct cipher_value *cipher = 0;
	struct packet_info xor_info = {};
	__u32 feature_mask = FAKETCP_ADMISSION_XDP_FEATURES;
	__u32 xor_target = 0;
	__u32 input_wire = 0;
	__u32 mixed_wire = 0;
	__u16 tcp_len;
	__u8 flags;
	__u8 close_control;
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
	if (!l3 ||
	    faketcp_managed_transform_status(l3, IPPROTO_TCP) != FAKETCP_L3_OK ||
	    l3->l3_off != ip_off || l3->l4_off != ip_off + sizeof(*iph) ||
	    (void *)(iph + 1) > data_end || (void *)(tcp + 1) > data_end) {
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
	close_control = flags & (FAKETCP_FLAG_RST | FAKETCP_FLAG_FIN);
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
	if (!close_control && policy_listener->cipher_id != 0) {
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
	admission->decision.transform.xor_target = xor_target;
	session = bpf_map_lookup_elem(&faketcp_session_map, &admission->key);
	if (!faketcp_session_snapshot_established(
		    session, generation, &session_snapshot)) {
		if (session)
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		else
			inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
		return close_control ? FAKETCP_ADMISSION_DROP :
				       FAKETCP_ADMISSION_CONTROL;
	}
	identity = faketcp_runtime_identity(generation);
	if (!identity ||
	    !faketcp_incarnations_equal(identity->incarnation,
				       session_snapshot.authority.runtime_incarnation)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return FAKETCP_ADMISSION_DROP;
	}
	admission->session_authority = session_snapshot.authority;
	admission->session_projection = session_snapshot.projection;
	*established_session = session;
	if (close_control) {
		admission->decision.close.session_revision = session_snapshot.revision;
		admission->decision.close.tx_sequence = session_snapshot.tx_sequence;
		admission->decision.close.rx_sequence = session_snapshot.rx_sequence;
		return FAKETCP_ADMISSION_CLOSE;
	}
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
	admission->decision.transform.input_wire = input_wire;
	admission->decision.transform.mixed_wire = mixed_wire;
	admission->decision.transform.standard_wire =
		wg_cpu_to_le32((__u32)type_kind + 1);
	admission->type_kind = type_kind;
	return FAKETCP_ADMISSION_TRANSFORM;
}

// ParseL3 is the sole authority for traffic whose port is not yet proven.
// A managed interface therefore has one mutually exclusive early-drop
// classification: malformed/truncated input is BAD_PACKET; every other
// unsupported managed shape is an admission-bypass rejection.
static __always_inline int faketcp_xdp_l3_action(int parse_rc,
						 int managed_interface)
{
	if (parse_rc == FAKETCP_L3_OK)
		return 0;
	if (parse_rc == FAKETCP_L3_SAFE_BYPASS || !managed_interface)
		return XDP_PASS;
	inc_faketcp_stat(parse_rc == FAKETCP_L3_TRUNCATED ||
			  parse_rc == FAKETCP_L3_MALFORMED ?
			  FAKETCP_STAT_BAD_PACKET :
			  FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
	return XDP_DROP;
}

static __always_inline int faketcp_xdp_reject(__u32 stat)
{
	inc_faketcp_stat(stat);
	return XDP_DROP;
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
	struct faketcp_managed_port_value *managed_listener = 0;
	struct ingress_listener_value *policy_listener = 0;
	struct faketcp_session_key key = {};
	struct faketcp_session_value *session;
	struct faketcp_ingress_admission admission = {};
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
	__u64 now;
	__u64 generation = 0;
	__s64 sum;
	int managed_interface, parse_rc, parse_action, admission_decision;

	if (!active_generation(&generation))
		return XDP_PASS;
	managed_interface = faketcp_xdp_managed_interface(xdp->ingress_ifindex,
							 generation);
	frame_len = (__u32)((long)data_end - (long)data);
	parser_mode = lookup_parser_mode(xdp->ingress_ifindex, generation);
	parse_rc = faketcp_xdp_l3_start(data, data_end, parser_mode, &l3_off,
					       &family);
	parse_action = faketcp_xdp_l3_action(parse_rc, managed_interface);
	if (parse_action)
		return parse_action;
	parse_rc = faketcp_parse_l3(data, data_end, frame_len, l3_off, family, &l3);
	parse_action = faketcp_xdp_l3_action(parse_rc, managed_interface);
	if (parse_action)
		return parse_action;
	wire_ports = data + l3.l4_off;
	if ((void *)(wire_ports + 1) > data_end)
		return managed_interface ?
		       faketcp_xdp_reject(FAKETCP_STAT_BAD_PACKET) : XDP_PASS;
	managed_listener = faketcp_xdp_managed_port(
		xdp->ingress_ifindex, bpf_ntohs(wire_ports->dest), generation);
	if (!managed_listener)
		return XDP_PASS;
	// ParseL3 can classify IPv4 options, IPv6 and TCP options, but the current
	// checksum/session ABI transforms only fixed-header IPv4. Reject once,
	// before native-UDP handling, event capture or any packet mutation.
	if (faketcp_managed_transform_status(&l3, l3.transport_protocol) !=
	    FAKETCP_L3_OK)
		return faketcp_xdp_reject(
			FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
	// Native UDP to a FakeTCP port is a transport-bypass attempt. Decoded
	// packets do not re-enter XDP, so this cannot catch the valid TCP-to-UDP
	// result produced later by this program.
	if (l3.transport_protocol == IPPROTO_UDP)
		return faketcp_xdp_reject(
			FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
	tcp = (struct tcphdr *)wire_ports;
	if ((void *)(tcp + 1) > data_end)
		return faketcp_xdp_reject(FAKETCP_STAT_BAD_PACKET);
	iph = data + l3.l3_off;
	if ((void *)(iph + 1) > data_end)
		return faketcp_xdp_reject(FAKETCP_STAT_BAD_PACKET);
	policy_listener = lookup_ingress_listener(
		xdp->ingress_ifindex, bpf_ntohs(tcp->dest), FAMILY_IPV4,
		generation);
	// The policy lookup deliberately precedes the single admission checkpoint.
	// A managed packet can only PASS after that checkpoint and full decoding.
	admission_decision = faketcp_xdp_admission_checkpoint(
		xdp, data, data_end, l3.l3_off, iph, tcp, &l3, managed_listener,
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
	if (admission_decision == FAKETCP_ADMISSION_CLOSE) {
		const __u8 *raw_tcp = (const __u8 *)tcp;

		if (admission.session_projection.window == 0) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
			return XDP_DROP;
		}
		if (total_len != sizeof(*iph) + sizeof(*tcp) || payload_len != 0 ||
		    raw_tcp[12] != (sizeof(*tcp) / 4) << 4 ||
		    (flags != (FAKETCP_FLAG_RST | FAKETCP_FLAG_ACK) &&
		     flags != (FAKETCP_FLAG_FIN | FAKETCP_FLAG_ACK)) ||
		    seq != admission.decision.close.rx_sequence ||
		    admission.acknowledgement !=
			admission.decision.close.tx_sequence ||
		    bpf_ntohs(tcp->window) != admission.session_projection.window ||
		    tcp->urg_ptr != 0) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
			return XDP_DROP;
		}
		if (!faketcp_close_checksums_valid(iph, tcp)) {
			inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
			return XDP_DROP;
		}
		if (faketcp_capture_close_packet(
			    xdp, l3.l3_off, total_len, &admission) < 0)
			inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
		return XDP_DROP;
	}
	if (admission_decision == FAKETCP_ADMISSION_KEEPALIVE) {
		// A userspace keepalive has no UDP image. Consume it before GRO and
		// refresh only the peer session's idle clock.
		now = bpf_ktime_get_ns();
		if (!faketcp_session_mutate(session, generation, now,
					    FAKETCP_SESSION_MUTATE_TOUCH, 0,
					    &admission.session_authority,
					    &admission.session_projection, 0)) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
			return XDP_DROP;
		}
		return XDP_DROP;
	}
	if (admission_decision != FAKETCP_ADMISSION_TRANSFORM) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
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
	metadata->direction = FAKETCP_DIRECTION_INGRESS;
	metadata->pad[0] = 0;
	metadata->pad[1] = 0;
	metadata->pad[2] = 0;
	metadata->admission = admission;
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
	now = bpf_ktime_get_ns();
	if (!faketcp_session_mutate(session, generation, now,
				    FAKETCP_SESSION_MUTATE_RX, next_seq,
				    &admission.session_authority,
				    &admission.session_projection, 0)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return XDP_DROP;
	}
	inc_faketcp_stat(FAKETCP_STAT_INGRESS_OK);
	return XDP_PASS;
}

#endif
