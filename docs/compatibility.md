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
```

`udp` is the default and is the original transparent type-word mode.

UDP transport can optionally enable the experimental XOR cipher layer. XOR runs after type-word mixing on egress and before type-word unmixing on ingress. It obfuscates the WireGuard UDP payload but does not add authentication, replay protection, length hiding, or udp2raw wire compatibility.

XOR compatibility requirements:

```text
both endpoints must enable the same cipher definition
the same XOR key material must be configured on both endpoints
only UDP transport is supported in the MVP
ICMP + XOR and fakeTCP + XOR are rejected
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
no fakeTCP
no udp2raw wire compatibility
no extra encryption/auth/anti-replay beyond WireGuard itself
no ICMPv6
no outer fragmentation support
checksum and offload behavior requires target validation; small WG packets use bounded full ICMP checksum, larger packets use a UDP-checksum-derived fast path
```

Large ICMP packets use the UDP-checksum-derived fast path instead of a verifier-bounded full ICMP checksum recompute. This path depends on the original UDP checksum; an IPv4 UDP packet with checksum zero causes large ICMP checksum derivation to fail and is reported through `icmp_checksum_error`.

`faketcp` and `faketcp-lite` are reserved names and are rejected by config validation in this version.

Netns regression entry points:

```bash
sudo make test-netns-smoke
sudo make test-netns-xor-smoke
sudo make test-netns-icmp-smoke
sudo NEGATIVE_CHECKS=xfail scripts/smoke-netns-icmp.sh
sudo NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh
```

The ICMP smoke test is IPv4-only. Its pcap check requires ICMP Echo Request and Reply records, mixed initiation/response/transport payload type words, and zero standard type-word leaks. The negative hooks are optional by default because ordinary ping pass-through and raw UDP bypass protection can be developed on separate core dataplane branches.

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
nft command when startup_guard.mode is nft-temporary-drop
```

If `startup_guard.mode: none` is used, missing `nft` is tolerated for stop/uninstall guard cleanup because there is no guard table to remove.

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
Hotplug integration writes reload requests; the daemon still performs a poll fallback.
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
