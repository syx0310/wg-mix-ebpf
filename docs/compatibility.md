# Compatibility

This document describes the expected compatibility surface for the current MVP implementation.

## WireGuard Interoperability

Supported topology:

```text
standard kernel WireGuard + wg-mix-ebpf
  <-> network
  <-> standard kernel WireGuard + wg-mix-ebpf
```

Unsupported topologies:

```text
standard kernel WireGuard + wg-mix-ebpf <-> native standard WireGuard
standard kernel WireGuard + wg-mix-ebpf <-> native wireguard-mix
```

Both endpoints must use the same transform profile. The built-in `wireguard-mix-wire-values-v1` preset only reuses fixed on-wire type-word values; it does not provide direct native `wireguard-mix` interoperability.

## Packet Scope

The dataplane only rewrites the first four bytes of the WireGuard UDP payload:

```text
standard type_word <-> mixed type_word
```

It does not rewrite IP addresses, UDP ports, WireGuard indexes, counters, MACs, ciphertext, peer endpoints, routes, DNS, or DDNS state.

## Transport Modes

Supported transport modes:

```text
udp
icmp
faketcp
```

`udp` is the default and is the original transparent type-word mode.

UDP and FakeTCP transports can optionally enable the XOR cipher layer. XOR runs after type-word mixing on egress and before type-word unmixing on ingress. It obfuscates the WireGuard payload but does not add authentication, replay protection, length hiding, or udp2raw wire compatibility.

XOR compatibility requirements:

```text
both endpoints must enable the same cipher definition
the same XOR key material must be configured on both endpoints
UDP and FakeTCP transports are supported
ICMP + XOR is rejected
current XOR is not mux/multiplex and does not merge multiple flows
```

`icmp` is an experimental IPv4-only raw transport mode. It changes the outer IPv4 protocol from UDP to ICMP and replaces the 8-byte UDP header with an 8-byte ICMP Echo header. The WireGuard payload is still protected by WireGuard and still uses the same mixed type-word profile.

ICMP mode roles:

```text
client:
  emits Echo Request
  accepts Echo Reply
  requires a nonzero 16-bit icmp.id

server:
  accepts Echo Request
  emits Echo Reply
  requires transport.icmp.id to be omitted or zero in config
  uses wildcard ingress id to tolerate NAT ICMP id rewriting
  wildcard id is intended for mixed WireGuard Echo payloads, not ordinary ping traffic
  passes wildcard-id Echo Requests that fail only mixed type-word or WireGuard length checks
  preserves NAT-rewritten Echo sequence values with runtime kernel state
```

Ordinary ICMP Echo traffic with a non-WireGuard payload should pass through a server wildcard listener. Raw UDP WireGuard packets sent directly to an ICMP-managed `ListenPort` are not a compatibility fallback and should be dropped so they cannot bypass ICMP mode.

MVP ICMP limitations:

```text
experimental
IPv4 only
single client profile per server listener unless ids are made unique
no udp2raw wire compatibility
no extra encryption/auth/anti-replay beyond WireGuard itself
no ICMPv6
no outer fragmentation support
checksum and offload behavior requires target validation; small WG packets use bounded full ICMP checksum, larger packets use a UDP-checksum-derived fast path
```

Large ICMP packets use the UDP-checksum-derived fast path instead of a verifier-bounded full ICMP checksum recompute. This path depends on the original UDP checksum; an IPv4 UDP packet with checksum zero causes large ICMP checksum derivation to fail and is reported through `icmp_checksum_error`.

`faketcp` is the production IPv4 TCP-shaped transport. It is packet-oriented,
not a TCP byte stream, and supports exactly one FakeTCP WireGuard per daemon.
The production attachment contract is TCX egress/ingress plus direct generic
XDP ingress on every attachable underlay. Existing XDP programs, libxdp
dispatcher chaining, XDP replacement/fallback, and `classic_tc` are rejected
before mutation. The runtime is process-owned and therefore must run in the
long-lived daemon; one-shot `reload` and `run --once` are rejected. The
administrator must provision the matching `wg_mix_faketcp_checksum` kfunc
module. A fixed non-zero WireGuard `ListenPort`, the nft temporary startup
guard, and fail-closed managed-flow policy are mandatory; the guard is removed
only after the process-owned maps and every TCX/XDP attachment pass their final
health check. `faketcp-lite` remains unsupported.

Netns regression entry points:

```bash
sudo make test-netns-smoke
sudo make test-netns-xor-smoke
sudo make test-netns-xor-full-smoke
sudo make test-netns-icmp-smoke
sudo make test-netns-tcp
sudo make test-netns-tcp-pmtu-positive
sudo make test-netns-tcp-outer-gso-observe
sudo make test-netns-full
sudo NEGATIVE_CHECKS=xfail scripts/smoke-netns-icmp.sh
sudo NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh
```

The default XOR smoke exercises the recommended `wg-payload-prefix` scope with
`max_bytes: 128`; the explicit full smoke covers `wg-payload-full` with
`max_bytes: 2048`. `test-netns-full` covers UDP IPv4/IPv6, XOR prefix
IPv4/IPv6, XOR full IPv4/IPv6 (including multi-segment parity-bank
coverage), IPv6 computed-zero UDP checksum mangling in native and full-XOR
paths, ICMP IPv4, and the TCP MTU matrix.

The TCP matrix is opt-in so the lightweight smoke targets do not require
`iperf3`. `test-netns-tcp` runs type-word-only UDP, XOR prefix, and XOR full
modes. In each mode it runs 1, 4, and 16 TCP flows in forward, reverse, and
simultaneous bidirectional directions at WireGuard MTUs 1419, 1420, 1421, and
1422. These four values are the XOR tail-alignment matrix, not a physical-link
PMTU claim. `test-netns-tcp-pmtu-positive` uses a 1500-byte underlay and checks
the positive IPv4 WireGuard MTUs 1439/1440 and IPv6 MTUs 1419/1420. Every
receiver stream in every direction must transfer at least 1 MiB.
The iperf summary must match the per-stream records, retransmits must remain
zero, multi-flow Jain fairness must be at least 0.90, and both peers' WireGuard
receive and transmit counters must increase for every tested MTU. Dataplane
type, length, fragment, IPv6 extension, checksum, load/store, rule-miss, and
XOR error counters must remain unchanged. These are the correctness gates.

GSO evidence is deliberately split from correctness. The matrix records the
inner TCP GSO capabilities advertised by both `wg0` devices, and separately
records the outer UDP GSO/GRO capabilities and dataplane counter deltas on the
underlay path. Linux WireGuard can segment an inner TCP GSO skb before
encryption, so a valid TCP-over-WireGuard run does not necessarily present an
outer UDP GSO skb to the underlay TC programs. Consequently, a missing outer
GSO observation is reported as `not-covered` (or `unsupported` when the link
capabilities are absent), never as a correctness pass or failure. The focused
`test-netns-tcp-outer-gso-observe` target runs 16 simultaneous bidirectional
flows for 30 seconds to maximize the opportunity to observe those counters on
the Linux 7.0 test host. It remains an observation target, not proof of outer
GSO coverage. A dedicated outer-UDP `UDP_SEGMENT` sender and GRO receiver must
be validated separately before outer GSO/GRO can be marked passed.

The TCP load starts only after the initial packet-capture validation finishes.
Every MTU, stream-count, and direction cell has separate router-side captures
for `ra0` and `rb0`.
Each capture is limited to 4096 packets with a 192-byte snap length and a
timeout derived from that cell's duration. The checker validates each
interface and expected underlay flow independently. A bidirectional cell must
show both A-to-B and B-to-A transport packets in both `ra0` and `rb0` captures,
so one interface, one direction, or an earlier cell cannot satisfy another
cell's transport type-word requirement.

Direct script callers can select the same gate and tune it for slower test
hosts:

```bash
sudo TCP_CHECKS=enforce \
  TCP_MTUS="1419 1420 1421 1422" \
  TCP_STREAMS="1 4 16" \
  TCP_DIRECTIONS="forward reverse bidir" \
  TCP_DURATION=2 \
  TCP_MIN_BYTES=1048576 \
  TCP_MAX_RETRANSMITS=0 \
  TCP_MIN_FAIRNESS=0.90 \
  TCP_INNER_GSO_CHECKS=report \
  TCP_OUTER_GSO_CHECKS=observe \
  TCP_CAPTURE_PACKETS=4096 \
  scripts/smoke-netns-wg.sh
```

`TCP_MIN_BYTES` is a per-receiver-stream and per-direction threshold.
`TCP_CHECKS=off` is the default. MTUs 1419 through 1422 cover four adjacent
XOR byte-tail alignments. They run over a deliberately larger 2200-byte
underlay; use the positive PMTU target for the 1500-byte boundary.
`iperf3` is checked as a dependency only when the TCP gate is enabled.
`TCP_INNER_GSO_CHECKS` accepts `off`, `report`, or `enforce`; only the explicit
`enforce` value makes missing `wg0` TX checksum, scatter-gather, TCP
segmentation, or generic segmentation capability fail the run.
`TCP_OUTER_GSO_CHECKS` accepts `off` or `observe`. Observation mode records TX
checksum, scatter-gather, GSO, GRO, and UDP segmentation capability on
`under0`, `ra0`, and `rb0`, then classifies actual managed/listener GSO counter
deltas without changing the correctness exit status. A missing or malformed
observation counter is reported as `not-covered`; it does not silently turn
into either a pass or a correctness failure. Successful runs end with separate
machine-readable `summary=inner-tcp-gso`, `summary=outer-udp-gso`, and
`summary=correctness` records; only the last record reports TCP correctness.

The ICMP smoke test is IPv4-only. Its pcap check requires ICMP Echo Request and
Reply records, valid ICMP checksums, mixed initiation/response/transport payload
type words, and zero standard type-word leaks. The Make target enforces ordinary
ping pass-through and raw IPv4/IPv6 UDP bypass protection; direct script callers
may still select `skip` or `xfail` while developing a dataplane change.

## Linux Platform Support

Tier 1 for the MVP:

```text
Linux x86_64
Linux aarch64
```

The public CI currently builds and tests on Linux amd64. arm64 builds are expected to work from a suitable Linux build host, but live TC/eBPF and WireGuard validation should be performed on controlled arm64 hardware before relying on it in production.

Not supported by the current MVP:

```text
32-bit Linux targets
OpenWrt mips32 / armv7
non-Linux operating systems
cross-netns or moved WireGuard socket setups
```

The Go binary is built with `CGO_ENABLED=0`. The BPF object is compiled during packaging and embedded into the binary, so target machines do not need clang or kernel headers for normal use.

## Kernel And Runtime Requirements

Runtime requirements:

```text
root privileges
WireGuard kernel support
BPF syscall support
TC clsact / sched_cls support
bpffs mounted at /sys/fs/bpf
wg command for runtime WireGuard state
tc command for attach/status inspection
nft command for startup-guard application and fixed-table cleanup
```

`startup_guard.mode: none` disables guard application for UDP/ICMP, but is
rejected for FakeTCP. Stop/uninstall still use `nft` to check and remove the
fixed owned table in case an earlier configuration left it behind.

## OpenWrt

OpenWrt x86_64 and aarch64 are intended targets when the required kernel modules and tools are available. The resolver supports:

```text
type: netdev
type: openwrt-interface
```

Known OpenWrt limitations:

```text
Do not configure both an OpenWrt logical interface and its lower carrier netdev as transform underlays.
PPPoE/VLAN/bridge paths require target-specific validation.
Hotplug integration writes a separate `runtime.request` event so it cannot
overwrite acknowledged CLI stop/reload requests; the daemon still performs a
poll fallback.
Legacy `reload.request` reload notifications remain accepted, but legacy
`stop:` notifications are intentionally ignored because they cannot target a
specific daemon instance.
```

## Offload, GSO, And GRO

The dataplane uses skb helpers for type-word load/store and direction-specific checksum handling to support common checksum offload, GSO, and GRO paths.

Expected validation before production:

```text
TX/RX checksum offload on/off
GSO/GRO on/off
veth / virtio / physical NIC
OpenWrt bridge and WAN paths
```

For ICMP mode, the TX checksum offload, GSO, and NIC matrix still needs target-specific validation, especially for large packets that use the UDP-checksum-derived ICMP checksum fast path.

For XOR mode, the dataplane rewrites the managed UDP payload in bounded chunks and updates the UDP checksum from the accumulated payload diff. The netns smoke target validates both IPv4 and IPv6 UDP underlay. Production validation should include at least one receiver-side pcap check with `scripts/check-wg-pcap.py --xor-udp2raw-password ... --require-xor-mixed ... --forbid-plain-standard --forbid-plain-mixed`.

The default XOR scope is `wg-payload-prefix` with `max_bytes: 128`. For performance-sensitive deployments, keep that default or lower it to `64` after validating the target path. Larger values scale linearly with the number of processed chunks; full-payload XOR should be benchmarked on the target path before use.

TX-side packet captures can show invalid UDP checksums when hardware or virtio checksum offload is enabled. Receiver-side captures and dataplane counters are more useful for checksum validation.

ICMP mode has a narrower validation surface in the MVP: ICMP checksum handling is implemented for the current skb shapes, but large packets and offload/GSO/GRO combinations still require target-specific testing. Keep ICMP-mode WireGuard MTU conservative until the target path has been validated.

## IPv6

The parser supports ordinary IPv6 UDP and has netns-level validation. Production use with IPv6 underlay should still be validated on the target network path, especially when extension headers or fragments are possible.

ICMP transport does not support IPv6/ICMPv6 in the MVP.

MVP behavior:

```text
ordinary IPv6 UDP: transform
IPv6 Fragment Header on managed listener: drop
unsupported IPv6 extension on managed egress: drop
unsupported IPv6 extension on ingress: targeted policy/counter behavior
```

## Fragmentation

Outer WireGuard UDP or ICMP fragmentation is not supported as a transform path. Configure WireGuard MTU and underlay MTU so outer packets are not fragmented.

MVP behavior is fail-closed when the packet can be identified as managed, and conservative pass/counter behavior when a non-first fragment cannot be tied to a managed listener without risking unrelated traffic.

## FwMark Requirement

Managed WireGuard interfaces must have a nonzero `FwMark`.

Accepted expected-mark sources:

```text
[Interface] FwMark = 0x...
PostUp = wg set %i fwmark 0x...
```

The live WireGuard runtime `FirewallMark` must match the expected config value by default. `require_nonzero_fwmark=false` and zero-mark fallback are reserved and intentionally rejected by the MVP.
