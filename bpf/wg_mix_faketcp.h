// SPDX-License-Identifier: MIT
//
// Clean-room FakeTCP wire path. This follows the public architectural idea of
// a TC encoder, pre-GRO XDP decoder and userspace handshake engine, but does
// not contain source copied from third-party implementations.
#ifndef WG_MIX_FAKETCP_H
#define WG_MIX_FAKETCP_H

#ifdef WG_MIX_FAKETCP_LEGACY_515
#include "../kernel/faketcp_checksum_kprobe/wg_mix_faketcp_checksum_kprobe_abi.h"
#endif

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
#define FAKETCP_EVENT_ABI_VERSION    3

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
#ifdef WG_MIX_FAKETCP_LEGACY_515
// Linux 5.15 predates bpf_loop but supports bpf_for_each_map_elem. Keep the
// full modern GSO contract with an exact legacy-only array iterator instead of
// an open-coded loop whose 2046/4096 paths exceed the old verifier's 8192-jump
// sequence ceiling. Every admitted logical segment is at least 32 bytes, so
// 2046 is the exact segment ceiling for the maximum IPv4 aggregate. Across
// that same geometry, the maximum number of 32-byte XOR chunks is 3968
// (gso_size=33); 4096 leaves a power-of-two bound without reducing the accepted
// wire domain. The extra array entry is the mandatory fail-closed stop sentinel.
#define FAKETCP_LEGACY_515_FULL_GSO_CAPABILITY 1
#define FAKETCP_LEGACY_515_GSO_MAX_SEGMENTS \
	(FAKETCP_GSO_MAX_PAYLOAD / 32U)
#define FAKETCP_LEGACY_515_GSO_MAX_XOR_CHUNKS 4096U
#define FAKETCP_LEGACY_515_ITERATION_MAP_ENTRIES \
	(FAKETCP_LEGACY_515_GSO_MAX_XOR_CHUNKS + 1U)
#endif
#define FAKETCP_CHECKSUM_CHUNK_BYTES 32
#define FAKETCP_CHECKSUM_CHUNK_COUNT \
	((FAKETCP_MAX_IPV4_TOTAL_LEN + FAKETCP_CHECKSUM_CHUNK_BYTES - 1) / \
	 FAKETCP_CHECKSUM_CHUNK_BYTES)
#define FAKETCP_METADATA_MAGIC 0x57474654U
#define FAKETCP_CONTROL_MIN_INTERVAL_NANOS 10000000ULL
#define FAKETCP_CONTROL_MAX_INTERVAL_NANOS 10000000000ULL
#define FAKETCP_CONTROL_MAX_BURST 4096U
#define FAKETCP_CONTROL_CAS_ATTEMPTS 4

#define FAKETCP_GENERATION_OPEN       (1ULL << 63)
#define FAKETCP_GENERATION_SEALED     (1ULL << 62)
#define FAKETCP_GENERATION_POISON     (1ULL << 61)
#define FAKETCP_GENERATION_WAKE_ARMED (1ULL << 60)
#define FAKETCP_GENERATION_INFLIGHT_MASK \
	(FAKETCP_GENERATION_WAKE_ARMED - 1)
#define FAKETCP_GENERATION_CAS_ATTEMPTS 8

#define FAKETCP_GENERATION_CONTROL_ASSERT_CLOSED 1
#define FAKETCP_GENERATION_CONTROL_OPEN          2
#define FAKETCP_GENERATION_CONTROL_CLOSE         3

#define FAKETCP_GENERATION_RESULT_MALFORMED 0
#define FAKETCP_GENERATION_RESULT_IDLE      1
#define FAKETCP_GENERATION_RESULT_OPEN      2
#define FAKETCP_GENERATION_RESULT_WAIT      3
#define FAKETCP_GENERATION_RESULT_POISON    4
#define FAKETCP_GENERATION_RESULT_MISMATCH  5

// Required, non-weak module kfunc. The modern object cannot be linked or
// verifier-loaded unless wg_mix_faketcp_checksum is loaded with this exact BTF
// function. The baseline and legacy objects never see these declarations or
// relocations.
#ifndef WG_MIX_FAKETCP_LEGACY_515
extern int wg_mix_faketcp_skb_prepare_udp(struct __sk_buff *skb,
					   __u32 network_offset,
					   __u32 transport_offset,
					   __u32 udp_length) __ksym;
extern int wg_mix_faketcp_skb_commit_udp_gso(struct __sk_buff *skb,
					      __u32 network_offset,
					      __u32 transport_offset,
					      __u32 sequence,
					      __u64 ack_window) __ksym;
#endif

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
	__u32 wg_id;
	__u8 pad[4];
};

struct faketcp_session_value {
	__u64 generation;
	// Peer-liveness clock. Local egress, including WireGuard PersistentKeepalive,
	// must not refresh it; only admitted peer data or a peer FakeTCP keepalive may.
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
// mutually exclusive projection keeps the hot-path admission ABI at 144 bytes.
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
	// BPF supports compare-and-swap on naturally aligned 64-bit words. Keep the
	// single-use proof state in that native width instead of relying on a
	// compiler-specific 32-bit atomic lowering.
	__u64 token_state;
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

_Static_assert(sizeof(struct faketcp_session_key) == 32,
	       "faketcp session key ABI drift");
_Static_assert(sizeof(struct faketcp_session_value) == 80,
	       "faketcp session value ABI drift");
_Static_assert(sizeof(struct faketcp_session_expected_value) == 80,
	       "faketcp expected session value ABI drift");
_Static_assert(sizeof(struct faketcp_session_claim_request) == 112,
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
				    decision) == 104,
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

_Static_assert(sizeof(struct faketcp_event) == 112, "faketcp event ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, runtime_incarnation) == 40,
	       "faketcp runtime incarnation ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, capture_sequence) == 56,
	       "faketcp capture sequence ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, session_revision) == 64,
	       "faketcp session revision ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, session_id) == 72,
	       "faketcp session ID ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, capture_cpu) == 80,
	       "faketcp capture CPU ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_event, event_abi_version) == 106,
	       "faketcp event version ABI drift");
_Static_assert(sizeof(struct faketcp_packet_event) == 2416,
	       "faketcp packet event ABI drift");

struct faketcp_runtime_identity_value {
	__u64 generation;
	__u8 incarnation[16];
	__u16 event_abi_version;
	__u8 pad[6];
};

_Static_assert(sizeof(struct faketcp_runtime_identity_value) == 32,
	       "faketcp runtime identity ABI drift");

struct faketcp_generation_gate_value {
	__u64 generation;
	__u64 state;
};

struct faketcp_generation_control_request {
	__u64 generation;
	__u8 incarnation[16];
	__u32 operation;
	__u32 reserved;
};

struct faketcp_generation_wake {
	__u64 generation;
	__u8 incarnation[16];
	__u64 state;
};

_Static_assert(sizeof(struct faketcp_generation_gate_value) == 16,
	       "faketcp generation gate ABI drift");
_Static_assert(__builtin_offsetof(struct faketcp_generation_gate_value, state) == 8,
	       "faketcp generation state alignment drift");
_Static_assert(sizeof(struct faketcp_generation_control_request) == 32,
	       "faketcp generation control request ABI drift");
_Static_assert(sizeof(struct faketcp_generation_wake) == 32,
	       "faketcp generation wake ABI drift");

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

_Static_assert(sizeof(struct faketcp_egress_admission) == 184,
	       "faketcp egress admission ABI drift");
_Static_assert(sizeof(struct faketcp_egress_admission_slot) == 192,
	       "faketcp egress admission slot ABI drift");
_Static_assert(sizeof(struct faketcp_ingress_admission) == 144,
	       "faketcp ingress admission ABI drift");
_Static_assert(sizeof(struct faketcp_metadata) == 152,
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
_Static_assert(sizeof(struct faketcp_control_flow_key) == 40,
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

static __always_inline int
faketcp_session_key_valid(const struct faketcp_session_key *key)
{
	__u8 pad = 0;

	if (!key || key->generation == 0 || key->local_ipv4 == 0 ||
	    key->remote_ipv4 == 0 || key->underlay_index == 0 ||
	    key->local_port == 0 || key->remote_port == 0 || key->wg_id == 0)
		return 0;
#pragma unroll
	for (int i = 0; i < 4; i++)
		pad |= key->pad[i];
	return pad == 0;
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
		// TX proves only that this host produced traffic. Treating it as peer
		// activity would let a local WireGuard PersistentKeepalive keep a dead
		// peer's session alive forever and prevent a fresh SYN from reconnecting.
		if (operation != FAKETCP_SESSION_MUTATE_TX &&
		    now > session->last_seen_nanos)
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
	return faketcp_session_key_valid(&request->key) &&
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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_RDONLY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct faketcp_generation_gate_value);
} faketcp_gen_gt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} faketcp_gen_wk SEC(".maps");

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

#ifdef WG_MIX_FAKETCP_LEGACY_515
// Each legacy collection has one userspace-populated lease identity.  The
// program may read but cannot modify it; a zero/malformed value fails closed
// before either public helper trigger.  Separate collection maps allow
// simultaneous resident runtimes to authenticate distinct module leases.
struct faketcp_kprobe_runtime_value {
	__u64 cookie;
	__u32 abi_version;
	__u32 reserved;
};

_Static_assert(sizeof(struct faketcp_kprobe_runtime_value) == 16,
	       "FakeTCP kprobe runtime value ABI drift");
_Static_assert(sizeof(struct faketcp_kprobe_runtime_value) ==
	       WG_MIX_FAKETCP_KPROBE_RUNTIME_COOKIE_SIZE,
	       "FakeTCP kprobe runtime shared size drift");
_Static_assert(__builtin_offsetof(struct faketcp_kprobe_runtime_value,
				    cookie) ==
	       WG_MIX_FAKETCP_KPROBE_RUNTIME_COOKIE_COOKIE_OFFSET,
	       "FakeTCP kprobe cookie offset drift");
_Static_assert(__builtin_offsetof(struct faketcp_kprobe_runtime_value,
				    abi_version) ==
	       WG_MIX_FAKETCP_KPROBE_RUNTIME_COOKIE_ABI_OFFSET,
	       "FakeTCP kprobe ABI offset drift");
_Static_assert(__builtin_offsetof(struct faketcp_kprobe_runtime_value,
				    reserved) ==
	       WG_MIX_FAKETCP_KPROBE_RUNTIME_COOKIE_RESERVED_OFFSET,
	       "FakeTCP kprobe reserved offset drift");
_Static_assert(sizeof(((struct __sk_buff *)0)->cb) ==
	       WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_SIZE,
	       "FakeTCP kprobe skb descriptor size drift");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct faketcp_kprobe_runtime_value);
} faketcp_kprobe_runtime_map SEC(".maps");

// Contents are deliberately irrelevant: Linux 5.15's
// bpf_for_each_array_elem() supplies array keys in ascending order and counts
// the stop element before returning. Entry 4096 is therefore a stop sentinel,
// so every accepted limit has a representable limit+1 traversal proof.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__uint(max_entries, FAKETCP_LEGACY_515_ITERATION_MAP_ENTRIES);
	__type(key, __u32);
	__type(value, __u32);
} faketcp_legacy_515_iteration_map SEC(".maps");
#endif

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

#ifdef WG_MIX_FAKETCP_LEGACY_515
// bpf_skb_change_proto() marks the caller's ctx register as modified on
// Linux 5.15.  Keep descriptor cleanup in a separate subprogram so its ctx
// argument is verified afresh instead of dereferencing that modified caller
// register.  This is deliberately fixed-size and stackless: cb is exactly
// the kprobe descriptor, and cleanup must still run after a rejected trigger.
static __noinline void
faketcp_clear_kprobe_descriptor(struct __sk_buff *skb)
{
	skb->cb[0] = 0;
	skb->cb[1] = 0;
	skb->cb[2] = 0;
	skb->cb[3] = 0;
	skb->cb[4] = 0;
}
#endif

static __always_inline int
faketcp_prepare_udp(struct __sk_buff *skb, __u32 network_offset,
		    __u32 transport_offset, __u32 udp_length, int expect_gso)
{
	int result;

#ifdef WG_MIX_FAKETCP_LEGACY_515
	__u32 zero = 0;
	struct faketcp_kprobe_runtime_value *runtime;

	runtime = bpf_map_lookup_elem(&faketcp_kprobe_runtime_map, &zero);
	if (!runtime || runtime->cookie == 0 ||
	    runtime->abi_version !=
		WG_MIX_FAKETCP_CHECKSUM_KPROBE_ABI_VERSION ||
	    runtime->reserved != 0)
		result = FAKETCP_PREPARE_REJECT_STATE;
	else {
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_COOKIE_OFFSET /
			sizeof(__u32)] =
			(__u32)runtime->cookie;
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_COOKIE_OFFSET /
			sizeof(__u32) + 1] =
			(__u32)(runtime->cookie >> 32);
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_NETWORK_OFFSET /
			sizeof(__u32)] =
			network_offset;
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_TRANSPORT_OFFSET /
			sizeof(__u32)] =
			transport_offset;
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_VALUE_OFFSET /
			sizeof(__u32)] =
			udp_length;
		result = bpf_skb_change_type(
			skb, WG_MIX_FAKETCP_KPROBE_PREPARE_MAGIC);
	}
	// The descriptor is valid only during the synchronous helper/kretprobe
	// call.  Clearing is unconditional so a miss or rejection cannot leak
	// lease identity into the later XOR tail-call protocol.
	faketcp_clear_kprobe_descriptor(skb);
	// The module may have linearized or COW-reallocated skb storage even though
	// the verifier models change_type as a non-data-changing helper.  Refresh
	// verifier packet-pointer state immediately after the synchronous trigger;
	// callers retain only scalar/map-backed descriptors across this boundary.
	if (bpf_skb_pull_data(skb, 0) < 0)
		result = FAKETCP_PREPARE_REJECT_WRITABLE;
#else
	result = wg_mix_faketcp_skb_prepare_udp(
		skb, network_offset, transport_offset, udp_length);
#endif
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
faketcp_commit_udp_gso(struct __sk_buff *skb, __u32 network_offset,
		       __u32 transport_offset, __u32 sequence,
		       __u64 ack_window)
{
#ifdef WG_MIX_FAKETCP_LEGACY_515
	__u32 zero = 0;
	struct faketcp_kprobe_runtime_value *runtime;
	int result;

	runtime = bpf_map_lookup_elem(&faketcp_kprobe_runtime_map, &zero);
	if (!runtime || runtime->cookie == 0 ||
	    runtime->abi_version !=
		WG_MIX_FAKETCP_CHECKSUM_KPROBE_ABI_VERSION ||
	    runtime->reserved != 0 || ack_window == 0)
		result = FAKETCP_PREPARE_REJECT_STATE;
	else {
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_COOKIE_OFFSET /
			sizeof(__u32)] =
			(__u32)runtime->cookie;
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_COOKIE_OFFSET /
			sizeof(__u32) + 1] =
			(__u32)(runtime->cookie >> 32);
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_NETWORK_OFFSET /
			sizeof(__u32)] =
			network_offset;
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_TRANSPORT_OFFSET /
			sizeof(__u32)] =
			transport_offset;
		skb->cb[WG_MIX_FAKETCP_KPROBE_DESCRIPTOR_VALUE_OFFSET /
			sizeof(__u32)] = sequence;
		result = bpf_skb_change_proto(
			skb, WG_MIX_FAKETCP_KPROBE_COMMIT_PROTO_MAGIC,
			ack_window);
	}
	// This must stay unconditional: failed helper dispatches must not leave a
	// stale descriptor for the later XOR tail-call protocol.  The noinline
	// subprogram is also the verifier boundary required after change_proto.
	faketcp_clear_kprobe_descriptor(skb);
	return result;
#else
	return wg_mix_faketcp_skb_commit_udp_gso(
		skb, network_offset, transport_offset, sequence, ack_window);
#endif
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
faketcp_generation_poison(struct faketcp_generation_gate_value *gate)
{
	__sync_fetch_and_or(&gate->state, FAKETCP_GENERATION_POISON);
	return FAKETCP_GENERATION_RESULT_POISON;
}

static __always_inline int faketcp_generation_enter(__u64 generation)
{
	__u32 zero = 0;
	struct faketcp_generation_gate_value *gate;

	gate = bpf_map_lookup_elem(&faketcp_gen_gt, &zero);
	if (!gate || generation == 0)
		return -1;
	if (gate->generation != generation) {
		if (gate->generation != 0 || gate->state != 0)
			faketcp_generation_poison(gate);
		return -1;
	}

#pragma unroll
	for (int attempt = 0; attempt < FAKETCP_GENERATION_CAS_ATTEMPTS; attempt++) {
		__u64 old = gate->state;
		__u64 count = old & FAKETCP_GENERATION_INFLIGHT_MASK;
		__u64 flags = old & ~FAKETCP_GENERATION_INFLIGHT_MASK;

		if (flags & FAKETCP_GENERATION_POISON)
			return -1;
		if ((flags == 0 && count == 0) ||
		    (flags == FAKETCP_GENERATION_SEALED && count == 0) ||
		    flags == (FAKETCP_GENERATION_SEALED |
			      FAKETCP_GENERATION_WAKE_ARMED))
			return -1;
		if (flags != FAKETCP_GENERATION_OPEN) {
			faketcp_generation_poison(gate);
			return -1;
		}
		if (count == FAKETCP_GENERATION_INFLIGHT_MASK) {
			faketcp_generation_poison(gate);
			return -1;
		}
		if (__sync_val_compare_and_swap(&gate->state, old, old + 1) == old)
			return 0;
	}
	return -1;
}

static __always_inline void faketcp_generation_exit(__u64 generation)
{
	__u32 zero = 0;
	struct faketcp_generation_gate_value *gate;
	struct faketcp_runtime_identity_value *identity;
	struct faketcp_generation_wake wake = {};
	__u64 old, count, flags;

	gate = bpf_map_lookup_elem(&faketcp_gen_gt, &zero);
	if (!gate)
		return;
	old = __sync_fetch_and_sub(&gate->state, 1);
	count = old & FAKETCP_GENERATION_INFLIGHT_MASK;
	flags = old & ~FAKETCP_GENERATION_INFLIGHT_MASK;
	if (count == 0 || gate->generation != generation) {
		faketcp_generation_poison(gate);
		return;
	}
	if (flags & FAKETCP_GENERATION_POISON)
		return;
	if (flags != FAKETCP_GENERATION_OPEN &&
	    flags != (FAKETCP_GENERATION_SEALED |
		      FAKETCP_GENERATION_WAKE_ARMED)) {
		faketcp_generation_poison(gate);
		return;
	}
	if (count != 1 || flags != (FAKETCP_GENERATION_SEALED |
				    FAKETCP_GENERATION_WAKE_ARMED))
		return;

	identity = faketcp_runtime_identity(generation);
	if (!identity) {
		faketcp_generation_poison(gate);
		return;
	}
	wake.generation = generation;
	__builtin_memcpy(wake.incarnation, identity->incarnation,
			 sizeof(wake.incarnation));
	wake.state = FAKETCP_GENERATION_SEALED |
		     FAKETCP_GENERATION_WAKE_ARMED;
	if (bpf_ringbuf_output(&faketcp_gen_wk, &wake,
			       sizeof(wake), 0) == 0)
		__sync_val_compare_and_swap(
			&gate->state,
			FAKETCP_GENERATION_SEALED |
				FAKETCP_GENERATION_WAKE_ARMED,
			FAKETCP_GENERATION_SEALED);
}

static __always_inline int
faketcp_generation_open(struct faketcp_generation_gate_value *gate,
			__u64 generation)
{
	__u64 bound;

	bound = __sync_val_compare_and_swap(&gate->generation, 0, generation);
	if (bound != 0 && bound != generation)
		return faketcp_generation_poison(gate);

#pragma unroll
	for (int attempt = 0; attempt < FAKETCP_GENERATION_CAS_ATTEMPTS; attempt++) {
		__u64 old = gate->state;
		__u64 count = old & FAKETCP_GENERATION_INFLIGHT_MASK;
		__u64 flags = old & ~FAKETCP_GENERATION_INFLIGHT_MASK;

		if (flags & FAKETCP_GENERATION_POISON)
			return FAKETCP_GENERATION_RESULT_POISON;
		if (flags == FAKETCP_GENERATION_OPEN)
			return FAKETCP_GENERATION_RESULT_OPEN;
		if ((flags == FAKETCP_GENERATION_SEALED && count == 0) ||
		    flags == (FAKETCP_GENERATION_SEALED |
			      FAKETCP_GENERATION_WAKE_ARMED))
			return FAKETCP_GENERATION_RESULT_MISMATCH;
		if (old != 0)
			return faketcp_generation_poison(gate);
		if (__sync_val_compare_and_swap(&gate->state, 0,
						FAKETCP_GENERATION_OPEN) == 0)
			return FAKETCP_GENERATION_RESULT_OPEN;
	}
	return FAKETCP_GENERATION_RESULT_MISMATCH;
}

static __always_inline int
faketcp_generation_close(struct faketcp_generation_gate_value *gate,
			 __u64 generation)
{
	__u64 bound;

	bound = __sync_val_compare_and_swap(&gate->generation, 0, generation);
	if (bound != 0 && bound != generation)
		return faketcp_generation_poison(gate);

#pragma unroll
	for (int attempt = 0; attempt < FAKETCP_GENERATION_CAS_ATTEMPTS; attempt++) {
		__u64 old = gate->state;
		__u64 count = old & FAKETCP_GENERATION_INFLIGHT_MASK;
		__u64 flags = old & ~FAKETCP_GENERATION_INFLIGHT_MASK;
		__u64 next;

		if (flags & FAKETCP_GENERATION_POISON)
			return FAKETCP_GENERATION_RESULT_POISON;
		if (old == 0) {
			if (__sync_val_compare_and_swap(
				    &gate->state, 0,
				    FAKETCP_GENERATION_SEALED) == 0)
				return FAKETCP_GENERATION_RESULT_IDLE;
			continue;
		}
		if (flags == FAKETCP_GENERATION_OPEN) {
			next = FAKETCP_GENERATION_SEALED | count;
			if (count != 0)
				next |= FAKETCP_GENERATION_WAKE_ARMED;
			if (__sync_val_compare_and_swap(&gate->state, old, next) != old)
				continue;
			return count == 0 ? FAKETCP_GENERATION_RESULT_IDLE :
				FAKETCP_GENERATION_RESULT_WAIT;
		}
		if (flags == FAKETCP_GENERATION_SEALED && count == 0)
			return FAKETCP_GENERATION_RESULT_IDLE;
		if (flags == (FAKETCP_GENERATION_SEALED |
			      FAKETCP_GENERATION_WAKE_ARMED)) {
			if (count != 0)
				return FAKETCP_GENERATION_RESULT_WAIT;
			if (__sync_val_compare_and_swap(
				    &gate->state, old,
				    FAKETCP_GENERATION_SEALED) == old)
				return FAKETCP_GENERATION_RESULT_IDLE;
			continue;
		}
		return faketcp_generation_poison(gate);
	}
	return FAKETCP_GENERATION_RESULT_MISMATCH;
}

SEC("classifier/faketcp_generation_control")
int wg_faketcp_generation_control(struct __sk_buff *skb)
{
	struct faketcp_generation_control_request request = {};
	struct faketcp_generation_gate_value *gate;
	struct faketcp_runtime_identity_value *identity;
	__u32 zero = 0;
	__u8 difference = 0;
	__u64 state, count, flags, bound;

	if (skb->len != sizeof(request) ||
	    bpf_skb_load_bytes(skb, 0, &request, sizeof(request)) < 0 ||
	    bpf_ringbuf_query(&faketcp_gen_wk, BPF_RB_RING_SIZE) != 4096 ||
	    request.generation == 0 || request.reserved != 0 ||
	    request.operation < FAKETCP_GENERATION_CONTROL_ASSERT_CLOSED ||
	    request.operation > FAKETCP_GENERATION_CONTROL_CLOSE)
		return FAKETCP_GENERATION_RESULT_MALFORMED;
	identity = faketcp_runtime_identity(request.generation);
	if (!identity)
		return FAKETCP_GENERATION_RESULT_MALFORMED;
#pragma unroll
	for (int i = 0; i < 16; i++)
		difference |= request.incarnation[i] ^ identity->incarnation[i];
	if (difference != 0)
		return FAKETCP_GENERATION_RESULT_MALFORMED;
	gate = bpf_map_lookup_elem(&faketcp_gen_gt, &zero);
	if (!gate)
		return FAKETCP_GENERATION_RESULT_MALFORMED;
	switch (request.operation) {
	case FAKETCP_GENERATION_CONTROL_ASSERT_CLOSED:
		bound = gate->generation;
		state = gate->state;
		count = state & FAKETCP_GENERATION_INFLIGHT_MASK;
		flags = state & ~FAKETCP_GENERATION_INFLIGHT_MASK;
		if (flags & FAKETCP_GENERATION_POISON)
			return FAKETCP_GENERATION_RESULT_POISON;
		if (bound != 0 && bound != request.generation)
			return faketcp_generation_poison(gate);
		if (state == 0)
			return FAKETCP_GENERATION_RESULT_IDLE;
		if (flags == FAKETCP_GENERATION_OPEN ||
		    (flags == FAKETCP_GENERATION_SEALED && count == 0) ||
		    flags == (FAKETCP_GENERATION_SEALED |
			      FAKETCP_GENERATION_WAKE_ARMED))
			return FAKETCP_GENERATION_RESULT_MISMATCH;
		return faketcp_generation_poison(gate);
	case FAKETCP_GENERATION_CONTROL_OPEN:
		return faketcp_generation_open(gate, request.generation);
	case FAKETCP_GENERATION_CONTROL_CLOSE:
		return faketcp_generation_close(gate, request.generation);
	default:
		return FAKETCP_GENERATION_RESULT_MALFORMED;
	}
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
			// A fresh generation starts with its explicitly configured burst.
			// Charging the first token at now+interval preserves the GCRA
			// ceiling while allowing the first WireGuard handshake immediately.
			candidate = now + interval;
			if (__sync_val_compare_and_swap(&policy->virtual_time_nanos,
						old, candidate) == old)
				return 1;
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
faketcp_admit_control_event_inner(const struct faketcp_session_key *session,
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
	if (!faketcp_session_key_valid(session) || session->wg_id != wg_id ||
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

static __always_inline int
faketcp_admit_control_event(const struct faketcp_session_key *session,
			    __u32 wg_id, __u8 event_type, __u64 now)
{
	int admitted;

	if (faketcp_generation_enter(session->generation) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_CONTROL_POLICY_MISS);
		return 0;
	}
	admitted = faketcp_admit_control_event_inner(
		session, wg_id, event_type, now);
	faketcp_generation_exit(session->generation);
	return admitted;
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

// TC helpers can invalidate the verifier's direct packet-pointer range even
// when they do not change packet bytes. Load the complete fixed IPv4/UDP
// envelope through one helper into the runtime's per-CPU scratch. Consumers
// immediately project the fields they need into scalars, so no 28-byte local
// compounds into the inlined BPF stack. The fixed-header admission gate makes
// both headers contiguous.
struct faketcp_tc_ipv4_udp_snapshot {
	struct iphdr ip;
	struct udphdr udp;
};

_Static_assert(sizeof(struct faketcp_tc_ipv4_udp_snapshot) == 28,
	       "FakeTCP TC header snapshot layout drift");

// The managed XDP gate admits only adjacent fixed IPv4/TCP headers. Keeping
// them in one object lets modern kernels perform one fixed-size helper copy and
// gives the legacy direct-copy backend the same contiguous destination.
struct faketcp_xdp_ipv4_tcp_snapshot {
	struct iphdr ip;
	struct tcphdr tcp;
};

_Static_assert(offsetof(struct faketcp_xdp_ipv4_tcp_snapshot, tcp) == 20,
	       "FakeTCP XDP transport snapshot offset drift");
_Static_assert(sizeof(struct faketcp_xdp_ipv4_tcp_snapshot) == 40,
	       "FakeTCP XDP header snapshot layout drift");

static __always_inline int faketcp_tc_load_ipv4_udp_snapshot(
	struct __sk_buff *skb, __u32 network_off, __u32 transport_off,
	__u32 payload_off, struct faketcp_tc_ipv4_udp_snapshot *snapshot)
{
	if (!snapshot || transport_off < network_off || payload_off < transport_off ||
	    transport_off - network_off != sizeof(struct iphdr) ||
	    payload_off - transport_off != sizeof(struct udphdr) ||
	    network_off > skb->len || sizeof(*snapshot) > skb->len - network_off)
		return -1;
	__builtin_memset(snapshot, 0, sizeof(*snapshot));
	return bpf_skb_load_bytes(skb, network_off, snapshot, sizeof(*snapshot));
}

static __always_inline int faketcp_tc_key(
	struct __sk_buff *skb, const struct packet_info *info,
	const struct faketcp_l3_info *l3, __be32 local_ipv4,
	__be32 remote_ipv4, __u64 generation, __u32 wg_id,
	struct faketcp_session_key *key)
{
	// The authoritative TC descriptor already applied the sole fixed-header
	// IPv4 gate. Header bytes were projected into scalars before any
	// policy/session helper, so this function never reconstructs or retains a
	// packet/header pointer.
	if (l3->l3_off != info->ip_off || l3->l4_off != info->udp_off)
		return -1;
	key->generation = generation;
	key->local_ipv4 = local_ipv4;
	key->remote_ipv4 = remote_ipv4;
	key->underlay_index = skb->ifindex;
	key->local_port = info->src_port;
	key->remote_port = info->dst_port;
	key->wg_id = wg_id;
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

// Large packet proofs must not share the 512-byte BPF stack with the parser,
// session and checksum state in the same program. Networking programs execute
// to completion on one CPU, so this collection-local per-CPU slot safely owns
// the one live proof for the current invocation. The TC pair coexists because
// the packet descriptor is still needed while its admission is consumed; the
// ingress variants are mutually exclusive program stages and share storage.
struct faketcp_runtime_scratch {
	union {
		struct {
			struct faketcp_tc_packet_descriptor packet;
			struct faketcp_egress_admission admission;
			struct faketcp_session_key key;
			struct faketcp_gso_projection gso;
			struct faketcp_session_snapshot session_snapshot;
		} tc;
		struct {
			struct faketcp_ingress_admission admission;
			struct faketcp_session_snapshot session_snapshot;
			struct packet_info xor_info;
			struct faketcp_l3_info l3;
			struct faketcp_xdp_ipv4_tcp_snapshot headers;
			struct udphdr udp;
			__u8 tail[FAKETCP_HEADER_DELTA];
			struct faketcp_pseudo_tail old_pseudo;
			struct faketcp_pseudo_tail new_pseudo;
		} ingress;
		struct faketcp_metadata metadata;
	};
	// A dedicated slot outside the variant union keeps fixed helper buffers off
	// the 512-byte BPF stack without aliasing packet/admission or ingress
	// metadata. TC header validation and GSO XOR execute in disjoint phases, so
	// they may safely share these final 32 bytes.
	union {
		struct faketcp_tc_ipv4_udp_snapshot tc_headers;
		__u8 gso_xor_chunk[FAKETCP_GSO_XOR_CHUNK_BYTES];
	};
};

_Static_assert(offsetof(struct faketcp_runtime_scratch, tc_headers) == 360,
	       "FakeTCP runtime header scratch offset drift");
_Static_assert(offsetof(struct faketcp_runtime_scratch, gso_xor_chunk) == 360,
	       "FakeTCP runtime GSO XOR scratch offset drift");
_Static_assert(sizeof(struct faketcp_runtime_scratch) == 392,
	       "FakeTCP runtime scratch layout drift");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct faketcp_runtime_scratch);
} faketcp_runtime_scratch_map SEC(".maps");

static __always_inline struct faketcp_runtime_scratch *
faketcp_runtime_scratch(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&faketcp_runtime_scratch_map, &zero);
}

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
	struct __sk_buff *skb, struct faketcp_runtime_scratch *scratch,
	const struct faketcp_egress_admission *admission)
{
	struct faketcp_tc_ipv4_udp_snapshot *headers;
	__u16 fragment;

	if (!scratch || !admission || admission->network_off > skb->len ||
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
	headers = &scratch->tc_headers;
	if (faketcp_tc_load_ipv4_udp_snapshot(
		    skb, admission->network_off, admission->transport_off,
		    admission->payload_off, headers) < 0)
		return -1;
	fragment = bpf_ntohs(headers->ip.frag_off);
	if (headers->ip.version != 4 ||
	    headers->ip.ihl != sizeof(headers->ip) / 4 ||
	    headers->ip.protocol != IPPROTO_UDP ||
	    (fragment & (IP_RESERVED | IP_MF | IP_OFFSET)) ||
	    bpf_ntohs(headers->ip.tot_len) != admission->ip_total_len ||
	    bpf_ntohs(headers->udp.len) != admission->wire_len ||
	    bpf_ntohs(headers->udp.source) != admission->key.local_port ||
	    bpf_ntohs(headers->udp.dest) != admission->key.remote_port ||
	    ((headers->udp.check == 0) !=
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
	__u64 previous;

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
	struct faketcp_runtime_scratch *scratch,
	const struct faketcp_egress_admission *admission)
{
	struct faketcp_tc_ipv4_udp_snapshot *headers;
	struct faketcp_session_key *key;
	struct faketcp_gso_projection *observed_gso;
	struct cipher_value *cipher = 0;
	__u32 xor_target = 0;
	__u32 required_features;
	__u32 current_wire = 0;
	__u32 expected_mixed;
	__u32 expected_standard;
	__u32 ip_total_len;
	__u32 wire_len;
	__be32 local_ipv4;
	__be32 remote_ipv4;
	__u8 expected_xor_checksum_mode = XOR_CSUM_NONE;
	int is_gso = skb->gso_size != 0;

	if (!info || !l3 || faketcp_managed_transform_status(l3, IPPROTO_UDP) !=
				   FAKETCP_L3_OK ||
	    l3->l3_off != info->ip_off || l3->l4_off != info->udp_off ||
	    l3->l4_len != sizeof(struct udphdr) + info->payload_len ||
	    !admission || !managed || !rule || !profile ||
	    !scratch || required_state == FAKETCP_TOKEN_FREE)
		return 0;
	headers = &scratch->tc_headers;
	if (faketcp_tc_load_ipv4_udp_snapshot(
		    skb, info->ip_off, info->udp_off, info->payload_off,
		    headers) < 0)
		return 0;
	ip_total_len = bpf_ntohs(headers->ip.tot_len);
	wire_len = bpf_ntohs(headers->udp.len);
	local_ipv4 = headers->ip.saddr;
	remote_ipv4 = headers->ip.daddr;
	key = &scratch->tc.key;
	observed_gso = &scratch->tc.gso;
	__builtin_memset(key, 0, sizeof(*key));
	__builtin_memset(observed_gso, 0, sizeof(*observed_gso));
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
	if (profile_mixed_from_kind(profile, admission->type_kind,
				    &expected_mixed) < 0)
		return 0;
	expected_standard = wg_cpu_to_le32((__u32)admission->type_kind + 1);
	if (admission->standard_wire != expected_standard ||
	    admission->mixed_wire != wg_cpu_to_le32(expected_mixed) ||
	    managed->generation != generation || rule->generation != generation ||
	    profile->generation != generation || rule->action != ACTION_REWRITE ||
	    rule->transport_mode != TRANSPORT_FAKETCP ||
	    !faketcp_runtime_incarnation_matches(
		generation,
		admission->session_authority.runtime_incarnation))
		return 0;
	if (faketcp_tc_key(skb, info, l3, local_ipv4, remote_ipv4, generation,
			   rule->wg_id, key) < 0 ||
	    key->local_ipv4 != admission->key.local_ipv4 ||
	    key->remote_ipv4 != admission->key.remote_ipv4 ||
	    key->underlay_index != admission->key.underlay_index ||
	    key->local_port != admission->key.local_port ||
	    key->remote_port != admission->key.remote_port ||
	    key->wg_id != admission->key.wg_id)
		return 0;
	if (rule->cipher_id != 0) {
		cipher = lookup_cipher(rule->cipher_id, generation);
		if (!cipher)
			return 0;
	}
	if (is_gso) {
		if (faketcp_gso_build_projection(skb, info, profile, cipher,
						 observed_gso, &xor_target) < 0 ||
		    !faketcp_gso_projection_matches(&admission->gso,
						     observed_gso) ||
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
	struct faketcp_runtime_scratch *scratch,
	struct faketcp_egress_admission *admission)
{
	struct faketcp_tc_ipv4_udp_snapshot *headers;
	struct faketcp_session_key *key;
	struct faketcp_gso_projection *gso;
	struct faketcp_session_value *session;
	struct faketcp_session_snapshot *session_snapshot;
	struct faketcp_runtime_identity_value *identity;
	struct faketcp_egress_admission_slot *slot;
	struct cipher_value *cipher = 0;
	__u32 zero = 0;
	__u32 feature_mask = FAKETCP_ADMISSION_REQUIRED_FEATURES;
	__u32 xor_target = 0;
	__u32 old_total_len;
	__u32 observed_total_len;
	__u32 expected_mixed;
	__u16 udp_len;
	__be32 local_ipv4;
	__be32 remote_ipv4;
	int is_gso = skb->gso_size != 0;

	if (!scratch || !info || parser_classification != PARSE_OK || !l3 ||
	    l3->l3_off != info->ip_off || l3->l4_off != info->udp_off ||
	    l3->l4_len != sizeof(struct udphdr) + info->payload_len ||
	    info->family != FAMILY_IPV4) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	key = &scratch->tc.key;
	gso = &scratch->tc.gso;
	session_snapshot = &scratch->tc.session_snapshot;
	__builtin_memset(key, 0, sizeof(*key));
	__builtin_memset(gso, 0, sizeof(*gso));
	__builtin_memset(session_snapshot, 0, sizeof(*session_snapshot));
	__builtin_memset(admission, 0, sizeof(*admission));
	headers = &scratch->tc_headers;
	if (faketcp_tc_load_ipv4_udp_snapshot(
		    skb, info->ip_off, info->udp_off, info->payload_off,
		    headers) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	observed_total_len = bpf_ntohs(headers->ip.tot_len);
	udp_len = bpf_ntohs(headers->udp.len);
	local_ipv4 = headers->ip.saddr;
	remote_ipv4 = headers->ip.daddr;
	if (!managed || !rule || !profile || generation == 0 || rule->wg_id == 0 ||
	    managed->generation != generation || rule->generation != generation ||
	    profile->generation != generation || rule->action != ACTION_REWRITE ||
	    rule->transport_mode != TRANSPORT_FAKETCP || type_kind < 0 ||
	    type_kind >= 4 ||
	    standard_wire != wg_cpu_to_le32((__u32)type_kind + 1) ||
	    profile_mixed_from_kind(profile, type_kind, &expected_mixed) < 0 ||
	    mixed_wire != wg_cpu_to_le32(expected_mixed)) {
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
						 gso, &xor_target) < 0) {
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
	if (info->ip_off > skb->len || old_total_len != skb->len - info->ip_off ||
	    observed_total_len != old_total_len ||
	    udp_len != sizeof(struct udphdr) + info->payload_len) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	if (faketcp_tc_key(skb, info, l3, local_ipv4, remote_ipv4, generation,
			   rule->wg_id, key) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, key);
	if (faketcp_session_snapshot_established(
		    session, generation, session_snapshot)) {
		identity = faketcp_runtime_identity(generation);
		slot = bpf_map_lookup_elem(&faketcp_egress_admission_map, &zero);
		if (!identity ||
		    !faketcp_incarnations_equal(identity->incarnation,
					       session_snapshot->authority.runtime_incarnation) ||
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
		// Populate the map-backed admission in place. A whole-struct compound
		// literal makes Clang materialise a second 184-byte copy on the BPF
		// stack even though the destination already lives in per-CPU scratch.
		admission->key = *key;
		admission->nonce = slot->next_nonce;
		admission->session_authority = session_snapshot->authority;
		admission->fwmark = skb->mark;
		admission->wg_id = rule->wg_id;
		admission->profile_id = rule->profile_id;
		admission->cipher_id = rule->cipher_id;
		admission->feature_mask = feature_mask;
		admission->network_off = info->ip_off;
		admission->transport_off = info->udp_off;
		admission->payload_off = info->payload_off;
		admission->payload_len = info->payload_len;
		admission->ip_total_len = old_total_len;
		admission->wire_len = udp_len;
		admission->skb_len = skb->len;
		admission->standard_wire = standard_wire;
		admission->mixed_wire = mixed_wire;
		admission->profile_policy_flags = profile->policy_flags;
		admission->xor_target = xor_target;
		admission->token_state = FAKETCP_TOKEN_ARMED;
		admission->gso = *gso;
		admission->session_projection = session_snapshot->projection;
		admission->managed_action = managed->action_on_miss;
		admission->rule_action = rule->action;
		admission->transport_mode = rule->transport_mode;
		admission->direction = FAKETCP_DIRECTION_EGRESS;
		admission->xor_checksum_mode = rule->cipher_id && !is_gso ?
					       xor_checksum_mode : XOR_CSUM_NONE;
		admission->type_kind = type_kind;
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
	if (faketcp_capture_first_packet(skb, info, l3, rule, key) < 0)
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
	// Admission validation records the maximum XOR target; the later encoder
	// records chunks per segment. Those phases never overlap, so one stack slot
	// keeps the bpf_loop caller frame below the aggregate 512-byte limit.
	union {
		__u32 xor_chunks_per_segment;
		__u32 max_xor_target;
	};
	int error;
};

_Static_assert(sizeof(struct faketcp_gso_loop_context) == 64,
	       "FakeTCP GSO loop context stack layout drift");

static __always_inline int faketcp_gso_mixed_from_kind(
	const struct faketcp_gso_loop_context *context, int kind, __u32 *mixed)
{
	if (!context || !mixed)
		return -1;
	switch (kind) {
	case 0:
		*mixed = context->mixed_type[0];
		return 0;
	case 1:
		*mixed = context->mixed_type[1];
		return 0;
	case 2:
		*mixed = context->mixed_type[2];
		return 0;
	case 3:
		*mixed = context->mixed_type[3];
		return 0;
	default:
		return -1;
	}
}

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

#ifdef WG_MIX_FAKETCP_LEGACY_515
static __noinline long faketcp_gso_validate_segment(
	void *map, const __u32 *key, void *value, void *opaque)
#else
static __noinline long faketcp_gso_validate_segment(__u32 index, void *opaque)
#endif
{
	struct faketcp_gso_loop_context *context = opaque;
	__u32 segment_offset;
	__u32 segment_length;
	__u32 wire_type;
	__u32 mixed_wire;
	__u32 xor_target = 0;
	int kind;

#ifdef WG_MIX_FAKETCP_LEGACY_515
	__u32 index;

	(void)map;
	(void)value;
	if (!context || !key)
		return 1;
	index = *key;
	// Stopping at the first key outside the work domain is success only when
	// the helper reports exactly limit+1 visited entries to the caller.
	if (index >= context->gso_segments)
		return 1;
	// Linux 5.15 does not derive a scalar range from the array iterator key.
	// Make the compile-time geometry bound explicit before packet arithmetic.
	if (index >= FAKETCP_LEGACY_515_GSO_MAX_SEGMENTS) {
		context->error = -1;
		return 1;
	}
#endif
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
	if (kind < 0 || !validate_len(kind, segment_length) ||
	    faketcp_gso_mixed_from_kind(context, kind, &mixed_wire) < 0) {
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
	mixed_wire = wg_cpu_to_le32(mixed_wire);
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

#ifdef WG_MIX_FAKETCP_LEGACY_515
static __always_inline int faketcp_legacy_515_validate_gso_segments(
	struct faketcp_gso_loop_context *context)
{
	if (!context || context->gso_segments < 2 ||
	    context->gso_segments > FAKETCP_LEGACY_515_GSO_MAX_SEGMENTS)
		return -1;
	if (bpf_for_each_map_elem(&faketcp_legacy_515_iteration_map,
				  faketcp_gso_validate_segment, context, 0) !=
	    context->gso_segments + 1U || context->error)
		return -1;
	return 0;
}
#endif

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
	context.mixed_type[0] = profile->standard_to_mixed[0];
	context.mixed_type[1] = profile->standard_to_mixed[1];
	context.mixed_type[2] = profile->standard_to_mixed[2];
	context.mixed_type[3] = profile->standard_to_mixed[3];
#ifdef WG_MIX_FAKETCP_LEGACY_515
	if (faketcp_legacy_515_validate_gso_segments(&context) < 0)
#else
	if (bpf_loop(context.gso_segments, faketcp_gso_validate_segment,
		     &context, 0) != context.gso_segments || context.error)
#endif
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

#ifdef WG_MIX_FAKETCP_LEGACY_515
static __noinline long faketcp_gso_rewrite_type(
	void *map, const __u32 *key, void *value, void *opaque)
#else
static __noinline long faketcp_gso_rewrite_type(__u32 index, void *opaque)
#endif
{
	struct faketcp_gso_loop_context *context = opaque;
#ifdef WG_MIX_FAKETCP_LEGACY_515
	__u32 segment_offset;
#else
	__u32 segment_offset = index * context->gso_size;
#endif
	__u32 old_wire;
	__u32 new_wire;
	int kind;

#ifdef WG_MIX_FAKETCP_LEGACY_515
	__u32 index;

	(void)map;
	(void)value;
	if (!context || !key)
		return 1;
	index = *key;
	if (index >= context->gso_segments)
		return 1;
	if (index >= FAKETCP_LEGACY_515_GSO_MAX_SEGMENTS) {
		context->error = -1;
		return 1;
	}
	segment_offset = index * context->gso_size;
#endif
	if (index >= context->gso_segments ||
	    bpf_skb_load_bytes(context->skb,
			       context->payload_offset + segment_offset,
			       &old_wire, sizeof(old_wire)) < 0) {
		context->error = -1;
		return 1;
	}
	kind = kind_from_standard(wg_le32_to_cpu(old_wire));
	if (kind < 0 ||
	    faketcp_gso_mixed_from_kind(context, kind, &new_wire) < 0) {
		context->error = -1;
		return 1;
	}
	new_wire = wg_cpu_to_le32(new_wire);
	if (bpf_skb_store_bytes(context->skb,
				context->payload_offset + segment_offset,
				&new_wire, sizeof(new_wire),
				BPF_F_INVALIDATE_HASH) < 0) {
		context->error = -1;
		return 1;
	}
	return 0;
}

#ifdef WG_MIX_FAKETCP_LEGACY_515
static __noinline long faketcp_gso_xor_chunk(
	void *map, const __u32 *key, void *value, void *opaque)
#else
static __noinline long faketcp_gso_xor_chunk(__u32 index, void *opaque)
#endif
{
	struct faketcp_gso_loop_context *context = opaque;
	struct faketcp_runtime_scratch *scratch;
	__u8 *chunk;
	__u32 *word_buffer;
	__u32 segment_index;
	__u32 segment_offset;
	__u32 segment_length;
	__u32 chunk_offset;
	__u32 target_length;
	__u32 chunk_length;
	__u32 processed = 0;
	__u32 tail_length;
	__u32 packet_offset;
	int rc;

#ifdef WG_MIX_FAKETCP_LEGACY_515
	__u32 index;
	__u32 xor_chunks;

	(void)map;
	(void)value;
	if (!context || !key || !context->xor_chunks_per_segment ||
	    context->gso_segments >
		FAKETCP_LEGACY_515_GSO_MAX_XOR_CHUNKS /
		context->xor_chunks_per_segment) {
		if (context)
			context->error = -1;
		return 1;
	}
	xor_chunks = context->gso_segments * context->xor_chunks_per_segment;
	index = *key;
	if (index >= xor_chunks)
		return 1;
	if (index >= FAKETCP_LEGACY_515_GSO_MAX_XOR_CHUNKS) {
		context->error = -1;
		return 1;
	}
#endif
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
	if (chunk_length > FAKETCP_GSO_XOR_CHUNK_BYTES)
		chunk_length = FAKETCP_GSO_XOR_CHUNK_BYTES;
	// Older verifiers retain a zero lower bound for the subtraction above even
	// after chunk_offset < target_length. Never pass that scalar as a helper
	// size. Full chunks retain the one-load/one-store fast path; the sole short
	// chunk in a segment is decomposed into fixed four-byte words plus an exact
	// 1/2/3-byte dispatch.
	if (chunk_length == 0 || chunk_length > FAKETCP_GSO_XOR_CHUNK_BYTES) {
		context->error = -1;
		return 1;
	}
	scratch = faketcp_runtime_scratch();
	if (!scratch) {
		context->error = -1;
		return 1;
	}
	chunk = scratch->gso_xor_chunk;
	word_buffer = (__u32 *)chunk;
	packet_offset = context->payload_offset + segment_offset + chunk_offset;
	if (chunk_length == FAKETCP_GSO_XOR_CHUNK_BYTES) {
		if (bpf_skb_load_bytes(context->skb, packet_offset, chunk,
				       FAKETCP_GSO_XOR_CHUNK_BYTES) < 0) {
			context->error = -1;
			return 1;
		}
#pragma unroll
		for (int byte = 0; byte < FAKETCP_GSO_XOR_CHUNK_BYTES; byte++)
			chunk[byte] ^=
				xor_key_byte(context->cipher, chunk_offset + byte);
		if (bpf_skb_store_bytes(context->skb, packet_offset, chunk,
					FAKETCP_GSO_XOR_CHUNK_BYTES,
					BPF_F_INVALIDATE_HASH) < 0) {
			context->error = -1;
			return 1;
		}
		return 0;
	}

#pragma unroll
	for (int word_index = 0;
	     word_index < FAKETCP_GSO_XOR_CHUNK_BYTES / 4; word_index++) {
		if (processed + sizeof(__u32) > chunk_length)
			break;
		*word_buffer = 0;
		if (bpf_skb_load_bytes(context->skb, packet_offset + processed,
				       word_buffer, sizeof(*word_buffer)) < 0) {
			context->error = -1;
			return 1;
		}
#pragma unroll
		for (int byte = 0; byte < 4; byte++)
			chunk[byte] ^=
				xor_key_byte(context->cipher,
					     chunk_offset + processed + byte);
		if (bpf_skb_store_bytes(context->skb, packet_offset + processed,
					word_buffer, sizeof(*word_buffer),
					BPF_F_INVALIDATE_HASH) < 0) {
			context->error = -1;
			return 1;
		}
		processed += sizeof(__u32);
	}
	if (processed < chunk_length) {
		tail_length = chunk_length - processed;
		if (tail_length == 0 || tail_length > 3) {
			context->error = -1;
			return 1;
		}
		*word_buffer = 0;
		rc = xor_load_partial_word(context->skb, packet_offset + processed,
					   tail_length, word_buffer);
		if (rc < 0) {
			context->error = -1;
			return 1;
		}
		chunk[0] ^=
			xor_key_byte(context->cipher, chunk_offset + processed);
		if (tail_length >= 2)
			chunk[1] ^=
				xor_key_byte(context->cipher,
					     chunk_offset + processed + 1);
		if (tail_length == 3)
			chunk[2] ^=
				xor_key_byte(context->cipher,
					     chunk_offset + processed + 2);
		rc = xor_store_partial_word(context->skb, packet_offset + processed,
					    tail_length, word_buffer,
					    BPF_F_INVALIDATE_HASH);
		if (rc < 0) {
			context->error = -1;
			return 1;
		}
		processed += tail_length;
	}
	if (processed != chunk_length) {
		context->error = -1;
		return 1;
	}
	return 0;
}

#ifdef WG_MIX_FAKETCP_LEGACY_515
static __always_inline int faketcp_legacy_515_rewrite_gso_types(
	struct faketcp_gso_loop_context *context)
{
	if (!context || context->gso_segments < 2 ||
	    context->gso_segments > FAKETCP_LEGACY_515_GSO_MAX_SEGMENTS)
		return -1;
	if (bpf_for_each_map_elem(&faketcp_legacy_515_iteration_map,
				  faketcp_gso_rewrite_type, context, 0) !=
	    context->gso_segments + 1U || context->error)
		return -1;
	return 0;
}

static __always_inline int faketcp_legacy_515_xor_gso_chunks(
	struct faketcp_gso_loop_context *context, __u32 xor_chunks)
{
	if (!context || !xor_chunks ||
	    xor_chunks > FAKETCP_LEGACY_515_GSO_MAX_XOR_CHUNKS)
		return -1;
	if (bpf_for_each_map_elem(&faketcp_legacy_515_iteration_map,
				  faketcp_gso_xor_chunk, context, 0) !=
	    xor_chunks + 1U || context->error)
		return -1;
	return 0;
}
#endif

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
	struct faketcp_runtime_scratch *scratch;
	struct faketcp_egress_admission *admission;
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
	scratch = faketcp_runtime_scratch();
	if (!scratch)
		return TC_ACT_SHOT;
	admission = &scratch->tc.admission;
	// Unified prepare is the sole checksum/GSO/PMTU/writability admission and
	// runs exactly once before the proof is formed or any packet byte changes.
	if (faketcp_prepare_udp(skb, info->ip_off, info->udp_off,
				 info->payload_len + sizeof(struct udphdr), 1) < 0)
		return TC_ACT_SHOT;
	if (faketcp_egress_admission_checkpoint(
		    skb, info, l3, managed, rule, profile, generation,
		    parser_classification, type_kind, standard_wire, mixed_wire,
		    XOR_CSUM_NONE, scratch, admission) !=
	    FAKETCP_ADMISSION_TRANSFORM)
		return TC_ACT_SHOT;
	if (faketcp_consume_egress_admission(admission->nonce, admission) < 0 ||
	    !faketcp_egress_admission_matches(
		    skb, info, l3, managed, rule, profile, generation,
		    FAKETCP_TOKEN_ARMED, scratch, admission)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	context.gso_size = admission->gso.gso_size;
	context.gso_segments = admission->gso.logical_segments;
	context.mixed_type[0] = profile->standard_to_mixed[0];
	context.mixed_type[1] = profile->standard_to_mixed[1];
	context.mixed_type[2] = profile->standard_to_mixed[2];
	context.mixed_type[3] = profile->standard_to_mixed[3];
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
#ifdef WG_MIX_FAKETCP_LEGACY_515
	if (faketcp_legacy_515_rewrite_gso_types(&context) < 0) {
#else
	if (bpf_loop(context.gso_segments, faketcp_gso_rewrite_type,
		     &context, 0) != context.gso_segments || context.error) {
#endif
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
#ifdef WG_MIX_FAKETCP_LEGACY_515
		if (faketcp_legacy_515_xor_gso_chunks(&context, xor_chunks) < 0) {
#else
		if (bpf_loop(xor_chunks, faketcp_gso_xor_chunk, &context, 0) !=
			    xor_chunks || context.error) {
#endif
			inc_stat(STAT_XOR_STORE_ERROR);
			return TC_ACT_SHOT;
		}
		inc_stat(STAT_XOR_EGRESS_OK);
	}
	session = bpf_map_lookup_elem(&faketcp_session_map, &admission->key);
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
				    &admission->session_authority,
				    &admission->session_projection,
				    &mutation)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return TC_ACT_SHOT;
	}
	inc_faketcp_stat(FAKETCP_STAT_ADMISSION_ACCEPT);
	ack_window = mutation.acknowledgement |
		     ((__u64)(mutation.window ? mutation.window : 65535) << 32);
	result = faketcp_commit_udp_gso(
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
	/* bpf_csum_diff returns a checksum-native __wsum. fold_csum therefore
	 * already has the __be16 representation expected by the wire field; an
	 * extra bpf_htons would byte-swap every materialized TCP checksum. */
	tcp->check = fold_csum(sum);
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
						       struct faketcp_runtime_scratch *scratch,
						       const struct faketcp_egress_admission *admission)
{
	struct faketcp_tc_ipv4_udp_snapshot *headers;
	struct faketcp_session_value *session;
	struct udphdr old_udp;
	struct tcphdr tcp = {};
	__u8 head[FAKETCP_HEADER_DELTA] = {};
	__u16 old_total_len, new_total_len, udp_len;
	__be32 source_ipv4, destination_ipv4;
	__u64 now;
	struct faketcp_session_mutation_result mutation = {};

	if (!scratch || !admission || admission->key.generation != generation ||
	    admission->direction != FAKETCP_DIRECTION_EGRESS ||
	    admission->cipher_id != rule->cipher_id ||
	    admission->payload_len != info->payload_len ||
	    admission->feature_mask !=
		(FAKETCP_ADMISSION_REQUIRED_FEATURES |
		 (admission->cipher_id ? FAKETCP_ADMISSION_F_XOR : 0))) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	headers = &scratch->tc_headers;
	if (faketcp_tc_load_ipv4_udp_snapshot(
		    skb, info->ip_off, info->udp_off, info->payload_off,
		    headers) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	old_udp = headers->udp;
	udp_len = bpf_ntohs(old_udp.len);
	old_total_len = bpf_ntohs(headers->ip.tot_len);
	source_ipv4 = headers->ip.saddr;
	destination_ipv4 = headers->ip.daddr;
	session = bpf_map_lookup_elem(&faketcp_session_map, &admission->key);
	if (!session) {
		// The checkpoint is the only place allowed to emit the handshake request
		// because it still owns the unmodified first packet. A map eviction in
		// this narrow post-transform race is a deliberate drop; WireGuard/QUIC
		// retransmission re-enters preflight with a capturable packet.
		inc_faketcp_stat(FAKETCP_STAT_SESSION_MISS);
		return TC_ACT_SHOT;
	}
	if (udp_len != info->payload_len + sizeof(old_udp) ||
	    old_total_len != sizeof(struct iphdr) + udp_len ||
	    old_total_len > FAKETCP_MAX_IPV4_TOTAL_LEN ||
	    old_total_len > 0xffff - FAKETCP_HEADER_DELTA ||
	    info->ip_off > skb->len || old_total_len != skb->len - info->ip_off ||
	    skb->len > 0xffffffffU - FAKETCP_HEADER_DELTA) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return TC_ACT_SHOT;
	}
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
	struct faketcp_runtime_scratch *scratch;
	struct faketcp_tc_packet_descriptor *packet;
	struct packet_info *info;
	struct egress_rule_key key = {};
	struct egress_rule_value *rule;
	struct managed_fwmark_value *managed;
	struct profile_key profile_key = {};
	struct profile_value *profile;
	struct faketcp_egress_admission *admission;
	struct xor_context progress = {};
	__u64 generation = 0;
	int context_ok;
	int consume_rc;

	scratch = faketcp_runtime_scratch();
	if (!scratch)
		return TC_ACT_SHOT;
	packet = &scratch->tc.packet;
	admission = &scratch->tc.admission;
	info = &packet->info;
	__builtin_memset(packet, 0, sizeof(*packet));
	context_ok = load_xor_context(skb, &progress) == 0 &&
		     progress.continue_faketcp;
	// Consume is deliberately first. It copies then clears the per-CPU active
	// token before cb cleanup, projection, lookup or comparison, so an independent
	// call and every malformed/residual cb path are single-use failures.
	consume_rc = faketcp_consume_egress_admission(
		progress.admission_nonce, admission);
	clear_xor_context(skb);
	if (!context_ok || consume_rc < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	if (!active_generation(&generation) ||
	    faketcp_tc_current_admission_coherent(skb, scratch, admission) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	faketcp_tc_descriptor_from_admission(admission, packet);
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
		    skb, info, &packet->shape.l3, managed, rule, profile, generation,
		    FAKETCP_TOKEN_XOR_COMPLETE, scratch, admission)) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return TC_ACT_SHOT;
	}
	return faketcp_encode_established(skb, info, rule, generation, scratch,
					  admission);
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
	void *data;
	void *meta;
	struct faketcp_metadata *metadata;
	struct faketcp_tc_ipv4_udp_snapshot *headers;
	struct faketcp_runtime_scratch *scratch;
	struct faketcp_metadata *consumed;
	const struct faketcp_ingress_admission *admission;
	struct faketcp_session_value *session;
	struct cipher_value *cipher = 0;
	__u32 xor_target = 0;
	__u32 feature_mask;
	__u32 decoded_total_len;
	__u32 input_wire = 0;
	__u32 mixed_wire;
	__u32 expected_mixed;
	__u32 standard_wire;
	__be32 local_ipv4;
	__be32 remote_ipv4;

	scratch = faketcp_runtime_scratch();
	if (!scratch)
		return -1;
	// Establish the data/data_meta proof only after the scratch-map helper, then
	// consume metadata before the next helper boundary.
	data = (void *)(long)skb->data;
	meta = (void *)(long)skb->data_meta;
	metadata = meta;
	if (meta + sizeof(*metadata) > data) {
		inc_faketcp_stat(FAKETCP_STAT_METADATA_ERROR);
		return -1;
	}
	consumed = &scratch->metadata;
	headers = &scratch->tc_headers;
	admission = &consumed->admission;
	// The metadata is single-use even when malformed: copy every field needed by
	// this consumer, then clear magic before the first policy/GSO comparison.
	*consumed = *metadata;
	metadata->magic = 0;
	if (consumed->magic != FAKETCP_METADATA_MAGIC ||
	    consumed->direction != FAKETCP_DIRECTION_INGRESS ||
	    consumed->pad[0] != 0 || consumed->pad[1] != 0 ||
	    consumed->pad[2] != 0) {
		inc_faketcp_stat(FAKETCP_STAT_METADATA_ERROR);
		return -1;
	}
	// Until a separately reviewed per-segment path exists, both GSO and GRO
	// coalescing are one capability failure with one counter classification.
	if (skb->gso_size) {
		inc_faketcp_stat(FAKETCP_STAT_GSO_REJECT);
		return -1;
	}
	if (!listener || !profile ||
	    listener->generation != generation ||
	    listener->transport_mode != TRANSPORT_FAKETCP ||
	    listener->action != ACTION_REWRITE ||
	    profile->generation != generation ||
	    faketcp_tc_load_ipv4_udp_snapshot(
		    skb, info->ip_off, info->udp_off, info->payload_off,
		    headers) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	feature_mask = FAKETCP_ADMISSION_XDP_FEATURES |
		       (listener->cipher_id ? FAKETCP_ADMISSION_F_XOR : 0);
	decoded_total_len = bpf_ntohs(headers->ip.tot_len);
	local_ipv4 = headers->ip.daddr;
	remote_ipv4 = headers->ip.saddr;
	if (bpf_skb_load_bytes(skb, info->payload_off, &input_wire,
			       sizeof(input_wire)) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	if (admission->key.generation != generation ||
	    admission->key.local_ipv4 != local_ipv4 ||
	    admission->key.remote_ipv4 != remote_ipv4 ||
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
	if (profile_mixed_from_kind(profile, admission->type_kind,
				    &expected_mixed) < 0) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return -1;
	}
	standard_wire = wg_cpu_to_le32((__u32)admission->type_kind + 1);
	if (admission->decision.transform.mixed_wire != mixed_wire ||
	    admission->decision.transform.standard_wire != standard_wire ||
	    expected_mixed != wg_le32_to_cpu(mixed_wire) ||
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

// FakeTCP controls are deliberately canonical and payload-free. Validate both
// checksums before XDP spends control-event budget and before TC lets an exact
// userspace-generated control packet bypass the managed UDP transform. A
// mathematically valid zero TCP checksum field is accepted because only the
// complete one's-complement residual is authoritative. Userspace independently
// repeats this validation against a fresh complete-value snapshot before
// teardown authority is granted.
static __always_inline int
faketcp_ipv4_tcp_control_checksums_valid(const struct iphdr *iph,
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

#ifdef WG_MIX_FAKETCP_LEGACY_515
// bpf_xdp_load_bytes/store_bytes were added after Linux 5.15. The legacy
// object uses fixed-size direct packet access instead. The parser admits only
// L3 mode or Ethernet with at most two VLAN headers, and the FakeTCP gate caps
// the IPv4 wire length before any helper below is reached. Keeping that exact
// scalar bound visible avoids turning a packet-derived offset into an
// unbounded packet pointer on the 5.15 verifier.
#define FAKETCP_LEGACY_515_XDP_MAX_OFFSET \
	(sizeof(struct ethhdr) + 2U * sizeof(struct wg_vlan_hdr) + \
	 FAKETCP_MAX_IPV4_TOTAL_LEN + FAKETCP_HEADER_DELTA)

static __always_inline int faketcp_legacy_515_xdp_load_close_packet(
	struct xdp_md *xdp, __u32 offset,
	__u8 destination[sizeof(struct iphdr) + sizeof(struct tcphdr)])
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	__u8 *source;

	if (offset > FAKETCP_LEGACY_515_XDP_MAX_OFFSET)
		return -1;
	source = data + offset;
	if ((void *)(source + sizeof(struct iphdr) + sizeof(struct tcphdr)) >
	    data_end)
		return -1;
#pragma unroll
	for (__u32 i = 0; i < sizeof(struct iphdr) + sizeof(struct tcphdr); i++)
		destination[i] = source[i];
	return 0;
}

static __always_inline int faketcp_legacy_515_xdp_load_word(
	struct xdp_md *xdp, __u32 offset, __u32 *destination)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	__u8 *source;
	__u8 *output = (__u8 *)destination;

	if (offset > FAKETCP_LEGACY_515_XDP_MAX_OFFSET)
		return -1;
	source = data + offset;
	if ((void *)(source + sizeof(*destination)) > data_end)
		return -1;
#pragma unroll
	for (__u32 i = 0; i < sizeof(*destination); i++)
		output[i] = source[i];
	return 0;
}

static __always_inline int faketcp_legacy_515_xdp_load_tail(
	struct xdp_md *xdp, __u32 offset,
	__u8 destination[FAKETCP_HEADER_DELTA])
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	__u8 *source;

	if (offset > FAKETCP_LEGACY_515_XDP_MAX_OFFSET)
		return -1;
	source = data + offset;
	if ((void *)(source + FAKETCP_HEADER_DELTA) > data_end)
		return -1;
#pragma unroll
	for (__u32 i = 0; i < FAKETCP_HEADER_DELTA; i++)
		destination[i] = source[i];
	return 0;
}

static __always_inline int faketcp_legacy_515_xdp_store_udp(
	struct xdp_md *xdp, __u32 offset, const struct udphdr *source)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	__u8 *destination;
	const __u8 *input = (const __u8 *)source;

	if (offset > FAKETCP_LEGACY_515_XDP_MAX_OFFSET)
		return -1;
	destination = data + offset;
	if ((void *)(destination + sizeof(*source)) > data_end)
		return -1;
#pragma unroll
	for (__u32 i = 0; i < sizeof(*source); i++)
		destination[i] = input[i];
	return 0;
}

static __always_inline int faketcp_legacy_515_xdp_store_tail(
	struct xdp_md *xdp, __u32 offset,
	const __u8 source[FAKETCP_HEADER_DELTA])
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	__u8 *destination;

	if (offset > FAKETCP_LEGACY_515_XDP_MAX_OFFSET)
		return -1;
	destination = data + offset;
	if ((void *)(destination + FAKETCP_HEADER_DELTA) > data_end)
		return -1;
#pragma unroll
	for (__u32 i = 0; i < FAKETCP_HEADER_DELTA; i++)
		destination[i] = source[i];
	return 0;
}

static __always_inline int faketcp_legacy_515_xdp_store_ipv4(
	struct xdp_md *xdp, __u32 offset, const struct iphdr *source)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	__u8 *destination;
	const __u8 *input = (const __u8 *)source;

	if (offset > FAKETCP_LEGACY_515_XDP_MAX_OFFSET)
		return -1;
	destination = data + offset;
	if ((void *)(destination + sizeof(*source)) > data_end)
		return -1;
#pragma unroll
	for (__u32 i = 0; i < sizeof(*source); i++)
		destination[i] = input[i];
	return 0;
}
#endif

static __always_inline int faketcp_xdp_load_ipv4_tcp_snapshot(
	struct xdp_md *xdp, __u32 network_off, __u32 transport_off,
	struct faketcp_xdp_ipv4_tcp_snapshot *snapshot)
{
	if (!snapshot || transport_off < network_off ||
	    transport_off - network_off != sizeof(struct iphdr))
		return -1;
#ifdef WG_MIX_FAKETCP_LEGACY_515
	return faketcp_legacy_515_xdp_load_close_packet(
		xdp, network_off, (__u8 *)snapshot);
#else
	return bpf_xdp_load_bytes(xdp, network_off, snapshot,
				  sizeof(*snapshot));
#endif
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
#ifdef WG_MIX_FAKETCP_LEGACY_515
	if (faketcp_legacy_515_xdp_load_close_packet(
		    xdp, packet_off, record->packet) < 0)
#else
	if (bpf_xdp_load_bytes(xdp, packet_off, record->packet,
			       sizeof(struct iphdr) + sizeof(struct tcphdr)) < 0)
#endif
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
	__u64 ip_off,
	const struct iphdr *iph,
	const struct tcphdr *tcp,
	const struct faketcp_l3_info *l3,
	const struct faketcp_managed_port_value *managed_listener,
	const struct ingress_listener_value *policy_listener,
	int managed_interface,
	__u64 generation,
	struct faketcp_ingress_admission *admission,
	struct faketcp_session_value **established_session)
{
	struct faketcp_runtime_scratch *scratch;
	struct faketcp_session_value *session;
	struct faketcp_session_snapshot *session_snapshot;
	struct faketcp_runtime_identity_value *identity;
	struct profile_key profile_key = {};
	struct profile_value *profile;
	struct cipher_value *cipher = 0;
	struct packet_info *xor_info;
	__u32 feature_mask = FAKETCP_ADMISSION_XDP_FEATURES;
	__u32 xor_target = 0;
	__u32 input_wire = 0;
	__u32 mixed_wire = 0;
	__u32 decoded_standard = 0;
	__u16 tcp_len;
	__u8 flags;
	__u8 close_control;
	int type_kind = -1;

	scratch = faketcp_runtime_scratch();
	if (!scratch)
		return FAKETCP_ADMISSION_DROP;
	session_snapshot = &scratch->ingress.session_snapshot;
	xor_info = &scratch->ingress.xor_info;
	__builtin_memset(xor_info, 0, sizeof(*xor_info));
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
	if (!l3 || !iph || !tcp ||
	    faketcp_managed_transform_status(l3, IPPROTO_TCP) != FAKETCP_L3_OK ||
	    l3->l3_off != ip_off || l3->l4_off != ip_off + sizeof(*iph)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	admission->wire_total_len = bpf_ntohs(iph->tot_len);
	if (admission->wire_total_len < sizeof(*iph) + sizeof(*tcp) ||
	    admission->wire_total_len > FAKETCP_MAX_IPV4_TOTAL_LEN +
				   FAKETCP_HEADER_DELTA ||
	    admission->wire_total_len != l3->l3_len) {
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
		.wg_id = policy_listener->wg_id,
	};
	if (admission->key.local_port == 0 || admission->key.remote_port == 0 ||
	    admission->key.underlay_index == 0) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	if (!close_control && policy_listener->cipher_id != 0) {
		xor_info->payload_off = admission->payload_off;
		xor_info->payload_len = admission->payload_len;
		cipher = lookup_cipher(policy_listener->cipher_id, generation);
		if (!cipher || xor_payload_target(xor_info, cipher, &xor_target) < 0) {
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
		    session, generation, session_snapshot)) {
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
				       session_snapshot->authority.runtime_incarnation)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return FAKETCP_ADMISSION_DROP;
	}
	admission->session_authority = session_snapshot->authority;
	admission->session_projection = session_snapshot->projection;
	*established_session = session;
	if (close_control) {
		admission->decision.close.session_revision = session_snapshot->revision;
		admission->decision.close.tx_sequence = session_snapshot->tx_sequence;
		admission->decision.close.rx_sequence = session_snapshot->rx_sequence;
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
	// The encoder moves the first 12 UDP payload bytes to the TCP wire tail.
	// Bind the word that inverse rotation restores at the UDP payload start.
#ifdef WG_MIX_FAKETCP_LEGACY_515
	if (faketcp_legacy_515_xdp_load_word(
		    xdp,
		    ip_off + admission->wire_total_len - FAKETCP_HEADER_DELTA,
		    &input_wire) < 0) {
#else
	if (bpf_xdp_load_bytes(xdp,
			       ip_off + admission->wire_total_len -
				       FAKETCP_HEADER_DELTA,
			       &input_wire, sizeof(input_wire)) < 0) {
#endif
		inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
		return FAKETCP_ADMISSION_DROP;
	}
	mixed_wire = input_wire;
	if (cipher)
		mixed_wire = xor_type_word_copy(mixed_wire, cipher);
	if (profile_decode_mixed(profile, wg_le32_to_cpu(mixed_wire),
				 &type_kind, &decoded_standard) < 0 ||
	    decoded_standard != (__u32)type_kind + 1 ||
	    !validate_len(type_kind, admission->payload_len)) {
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

static __always_inline int
faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)
{
	void *data;
	void *data_end;
	struct udphdr *wire_ports;
	struct faketcp_l3_info *l3;
	struct faketcp_managed_port_value *managed_listener = 0;
	struct ingress_listener_value *policy_listener = 0;
	struct faketcp_session_value *session;
	struct faketcp_runtime_scratch *scratch;
	struct faketcp_ingress_admission *admission;
	struct faketcp_metadata *metadata;
	struct faketcp_pseudo_tail *old_pseudo;
	struct faketcp_pseudo_tail *new_pseudo;
	struct faketcp_xdp_ipv4_tcp_snapshot *headers;
	struct iphdr *new_ip;
	struct tcphdr *old_tcp;
	struct udphdr *udp;
	__u8 *tail;
	__u8 flags;
	__u8 family = 0;
	__u8 parser_mode;
	__u16 total_len, tcp_len, payload_len, new_total_len;
	__u16 destination_port;
	__u32 frame_len, l3_off = 0, seq, next_seq;
	__u64 now;
	__s64 sum;
	int managed_interface, parse_rc, parse_action, admission_decision;

	scratch = faketcp_runtime_scratch();
	if (!scratch)
		return XDP_DROP;
	admission = &scratch->ingress.admission;
	l3 = &scratch->ingress.l3;
	headers = &scratch->ingress.headers;
	new_ip = &headers->ip;
	old_tcp = &headers->tcp;
	udp = &scratch->ingress.udp;
	tail = scratch->ingress.tail;
	old_pseudo = &scratch->ingress.old_pseudo;
	new_pseudo = &scratch->ingress.new_pseudo;
	__builtin_memset(l3, 0, sizeof(*l3));
	__builtin_memset(udp, 0, sizeof(*udp));
	__builtin_memset(tail, 0, FAKETCP_HEADER_DELTA);
	managed_interface = faketcp_xdp_managed_interface(xdp->ingress_ifindex,
							 generation);
	parser_mode = lookup_parser_mode(xdp->ingress_ifindex, generation);
	// Establish packet pointers only after the initial map helpers. Every later
	// helper boundary either consumes a scalar/header snapshot or is followed by
	// a fresh data/data_end load before direct packet access resumes.
	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;
	frame_len = (__u32)((long)data_end - (long)data);
	parse_rc = faketcp_xdp_l3_start(data, data_end, parser_mode, &l3_off,
					       &family);
	parse_action = faketcp_xdp_l3_action(parse_rc, managed_interface);
	if (parse_action)
		return parse_action;
	parse_rc = faketcp_parse_l3(data, data_end, frame_len, l3_off, family, l3);
	parse_action = faketcp_xdp_l3_action(parse_rc, managed_interface);
	if (parse_action)
		return parse_action;
	wire_ports = data + l3->l4_off;
	if ((void *)(wire_ports + 1) > data_end)
		return managed_interface ?
		       faketcp_xdp_reject(FAKETCP_STAT_BAD_PACKET) : XDP_PASS;
	// Read the common source/destination prefix while the immediately preceding
	// packet bound is still the verifier's active proof. Do not dereference this
	// packet pointer again after the first map helper.
	destination_port = bpf_ntohs(wire_ports->dest);
	managed_listener = faketcp_xdp_managed_port(
		xdp->ingress_ifindex, destination_port, generation);
	if (!managed_listener)
		return XDP_PASS;
	// ParseL3 can classify IPv4 options, IPv6 and TCP options, but the current
	// checksum/session ABI transforms only fixed-header IPv4. Reject once,
	// before native-UDP handling, event capture or any packet mutation.
	if (faketcp_managed_transform_status(l3, l3->transport_protocol) !=
	    FAKETCP_L3_OK)
		return faketcp_xdp_reject(
			FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
	// Native UDP to a FakeTCP port is a transport-bypass attempt. Decoded
	// packets do not re-enter XDP, so this cannot catch the valid TCP-to-UDP
	// result produced later by this program.
	if (l3->transport_protocol == IPPROTO_UDP)
		return faketcp_xdp_reject(
			FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
	// The managed-port lookup is a helper boundary. Copy the adjacent fixed
	// IPv4/TCP envelope with one verifier-safe fixed-size operation instead of
	// rebuilding a dynamic-offset packet pointer. All admission, checksum and
	// close decisions below consume only this map-backed snapshot.
	if (faketcp_xdp_load_ipv4_tcp_snapshot(
		    xdp, l3->l3_off, l3->l4_off, headers) < 0)
		return faketcp_xdp_reject(FAKETCP_STAT_BAD_PACKET);
	policy_listener = lookup_ingress_listener(
		xdp->ingress_ifindex, destination_port, FAMILY_IPV4,
		generation);
	// The policy lookup deliberately precedes the single admission checkpoint.
	// A managed packet can only PASS after that checkpoint and full decoding.
	admission_decision = faketcp_xdp_admission_checkpoint(
		xdp, l3->l3_off, new_ip, old_tcp, l3, managed_listener,
		policy_listener, managed_interface, generation, admission,
		&session);
	if (admission_decision == FAKETCP_ADMISSION_DROP)
		return XDP_DROP;
	total_len = admission->wire_total_len;
	tcp_len = total_len - sizeof(*new_ip);
	payload_len = admission->payload_len;
	flags = admission->tcp_flags;
	seq = admission->sequence;
	if (admission_decision == FAKETCP_ADMISSION_CONTROL) {
		faketcp_emit_event(&admission->key, faketcp_event_type(flags), flags, seq,
				   admission->acknowledgement, payload_len, 0,
				   managed_listener->wg_id);
		return XDP_DROP;
	}
	if (!session) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return XDP_DROP;
	}
	if (admission_decision == FAKETCP_ADMISSION_CLOSE) {
		const __u8 *raw_tcp = (const __u8 *)old_tcp;

		if (admission->session_projection.window == 0) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
			return XDP_DROP;
		}
		if (total_len != sizeof(*new_ip) + sizeof(*old_tcp) || payload_len != 0 ||
		    raw_tcp[12] != (sizeof(*old_tcp) / 4) << 4 ||
		    (flags != (FAKETCP_FLAG_RST | FAKETCP_FLAG_ACK) &&
		     flags != (FAKETCP_FLAG_FIN | FAKETCP_FLAG_ACK)) ||
		    seq != admission->decision.close.rx_sequence ||
		    admission->acknowledgement !=
			admission->decision.close.tx_sequence ||
		    bpf_ntohs(old_tcp->window) != admission->session_projection.window ||
		    old_tcp->urg_ptr != 0) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_PACKET);
			return XDP_DROP;
		}
		if (!faketcp_ipv4_tcp_control_checksums_valid(new_ip, old_tcp)) {
			inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
			return XDP_DROP;
		}
		if (faketcp_capture_close_packet(
			    xdp, l3->l3_off, total_len, admission) < 0)
			inc_faketcp_stat(FAKETCP_STAT_EVENT_ERROR);
		return XDP_DROP;
	}
	if (admission_decision == FAKETCP_ADMISSION_KEEPALIVE) {
		// A userspace keepalive has no UDP image. Consume it before GRO and
		// refresh only the peer session's idle clock.
		now = bpf_ktime_get_ns();
		if (!faketcp_session_mutate(session, generation, now,
					    FAKETCP_SESSION_MUTATE_TOUCH, 0,
					    &admission->session_authority,
					    &admission->session_projection, 0)) {
			inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
			return XDP_DROP;
		}
		return XDP_DROP;
	}
	if (admission_decision != FAKETCP_ADMISSION_TRANSFORM) {
		inc_faketcp_stat(FAKETCP_STAT_ADMISSION_BYPASS_REJECT);
		return XDP_DROP;
	}
#ifdef WG_MIX_FAKETCP_LEGACY_515
	if (faketcp_legacy_515_xdp_load_tail(
		    xdp, l3->l3_off + total_len - FAKETCP_HEADER_DELTA,
		    tail) < 0) {
#else
	if (bpf_xdp_load_bytes(xdp,
			       l3->l3_off + total_len - FAKETCP_HEADER_DELTA,
			       tail, FAKETCP_HEADER_DELTA) < 0) {
#endif
		inc_faketcp_stat(FAKETCP_STAT_CHECKSUM_ERROR);
		return XDP_DROP;
	}
	udp->source = old_tcp->source;
	udp->dest = old_tcp->dest;
	udp->len = bpf_htons(payload_len + sizeof(*udp));
	udp->check = 0;
	*old_pseudo = (struct faketcp_pseudo_tail){
		.protocol = IPPROTO_TCP,
		.length = bpf_htons(tcp_len),
	};
	*new_pseudo = (struct faketcp_pseudo_tail){
		.protocol = IPPROTO_UDP,
		.length = udp->len,
	};
	/* Keep the complete TCP checksum seed and every bpf_csum_diff result in
	 * checksum-native order. Converting the seed to host order would make it
	 * incompatible with the helper's __wsum accumulator. */
	sum = (~old_tcp->check) & 0xffff;
	old_tcp->check = 0;
	sum = bpf_csum_diff((__be32 *)old_pseudo, sizeof(*old_pseudo),
			     (__be32 *)new_pseudo, sizeof(*new_pseudo), sum);
	if (sum < 0)
		return XDP_DROP;
	sum = bpf_csum_diff((__be32 *)old_tcp, sizeof(*old_tcp),
			     (__be32 *)udp, sizeof(*udp), sum);
	if (sum < 0)
		return XDP_DROP;
	if (payload_len & 1) {
		sum = faketcp_rotation_checksum(tail, sum, 1);
		if (sum < 0)
			return XDP_DROP;
	}
	udp->check = fold_csum(sum);
	if (udp->check == 0)
		udp->check = bpf_htons(0xffff);

	new_total_len = total_len - FAKETCP_HEADER_DELTA;
	if (bpf_xdp_adjust_meta(xdp, -(int)sizeof(struct faketcp_metadata)) < 0)
		return XDP_DROP;
	data = (void *)(long)xdp->data;
	metadata = (void *)(long)xdp->data_meta;
	if ((void *)(metadata + 1) > data)
		return XDP_DROP;
	metadata->magic = FAKETCP_METADATA_MAGIC;
	metadata->direction = FAKETCP_DIRECTION_INGRESS;
	metadata->pad[0] = 0;
	metadata->pad[1] = 0;
	metadata->pad[2] = 0;
	metadata->admission = *admission;
#ifdef WG_MIX_FAKETCP_LEGACY_515
	if (faketcp_legacy_515_xdp_store_udp(xdp, l3->l4_off, udp) < 0 ||
	    faketcp_legacy_515_xdp_store_tail(
		    xdp, l3->l4_off + sizeof(*udp), tail) < 0)
#else
	if (bpf_xdp_store_bytes(xdp, l3->l4_off, udp, sizeof(*udp)) < 0 ||
	    bpf_xdp_store_bytes(xdp, l3->l4_off + sizeof(*udp), tail,
			       FAKETCP_HEADER_DELTA) < 0)
#endif
		return XDP_DROP;

	// The integration gate accepts only a fixed 20-byte IPv4 header, so one
	// bounded full-header checksum recomputation covers every transformed byte.
	new_ip->protocol = IPPROTO_UDP;
	new_ip->tot_len = bpf_htons(new_total_len);
	new_ip->check = 0;
	sum = bpf_csum_diff(0, 0, (__be32 *)new_ip, sizeof(*new_ip), 0);
	if (sum < 0)
		return XDP_DROP;
	new_ip->check = fold_csum(sum);
#ifdef WG_MIX_FAKETCP_LEGACY_515
	if (faketcp_legacy_515_xdp_store_ipv4(xdp, l3->l3_off, new_ip) < 0 ||
	    bpf_xdp_adjust_tail(xdp, -FAKETCP_HEADER_DELTA) < 0)
#else
	if (bpf_xdp_store_bytes(xdp, l3->l3_off, new_ip, sizeof(*new_ip)) < 0 ||
	    bpf_xdp_adjust_tail(xdp, -FAKETCP_HEADER_DELTA) < 0)
#endif
		return XDP_DROP;

	next_seq = seq + payload_len;
	now = bpf_ktime_get_ns();
	if (!faketcp_session_mutate(session, generation, now,
				    FAKETCP_SESSION_MUTATE_RX, next_seq,
				    &admission->session_authority,
				    &admission->session_projection, 0)) {
		inc_faketcp_stat(FAKETCP_STAT_BAD_STATE);
		return XDP_DROP;
	}
	inc_faketcp_stat(FAKETCP_STAT_INGRESS_OK);
	return XDP_PASS;
}

SEC("xdp")
int wg_mix_faketcp_ingress(struct xdp_md *xdp)
{
	__u64 generation = 0;
	int action;

	if (!active_generation(&generation))
		return XDP_PASS;
	if (faketcp_generation_enter(generation) < 0)
		return XDP_DROP;
	action = faketcp_xdp_ingress_body(xdp, generation);
	faketcp_generation_exit(generation);
	return action;
}

#endif
