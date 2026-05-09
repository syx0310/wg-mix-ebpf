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

TX-side packet captures can show invalid UDP checksums when hardware or virtio checksum offload is enabled. Receiver-side captures and dataplane counters are more useful for checksum validation.

## IPv6

The parser supports ordinary IPv6 UDP and has netns-level validation. Production use with IPv6 underlay should still be validated on the target network path, especially when extension headers or fragments are possible.

MVP behavior:

```text
ordinary IPv6 UDP: transform
IPv6 Fragment Header on managed listener: drop
unsupported IPv6 extension on managed egress: drop
unsupported IPv6 extension on ingress: targeted policy/counter behavior
```

## Fragmentation

Outer WireGuard UDP fragmentation is not supported as a transform path. Configure WireGuard MTU and underlay MTU so outer packets are not fragmented.

MVP behavior is fail-closed when the packet can be identified as managed, and conservative pass/counter behavior when a non-first fragment cannot be tied to a managed listener without risking unrelated traffic.

## FwMark Requirement

Managed WireGuard interfaces must have a nonzero `FwMark`.

Accepted expected-mark sources:

```text
[Interface] FwMark = 0x...
PostUp = wg set %i fwmark 0x...
```

The live WireGuard runtime `FirewallMark` must match the expected config value by default. `require_nonzero_fwmark=false` and zero-mark fallback are reserved and intentionally rejected by the MVP.

