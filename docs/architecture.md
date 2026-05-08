# Architecture

`wg-mix-ebpf` is a transparent WireGuard packet transform. It runs as a userspace control plane plus TC/eBPF dataplane programs attached to selected underlay interfaces.

## Boundary

The dataplane only rewrites the first four bytes of the WireGuard UDP payload:

```text
egress: standard type_word -> mixed type_word
ingress: mixed type_word -> standard type_word
```

It does not rewrite:

```text
outer IP addresses
outer UDP source or destination ports
WireGuard sender_index or receiver_index
WireGuard counters
WireGuard MACs
WireGuard ciphertext
peer endpoints
routes
DNS or DDNS records
```

Both WireGuard endpoints must run standard kernel WireGuard plus this transparent transform layer.

## Interoperability

Supported:

```text
standard kernel WireGuard + wg-mix-ebpf
  <-> network
  <-> standard kernel WireGuard + wg-mix-ebpf
```

Not supported:

```text
standard kernel WireGuard + wg-mix-ebpf <-> native standard WireGuard
standard kernel WireGuard + wg-mix-ebpf <-> native wireguard-mix
```

The `wireguard-mix-wire-values-v1` preset only reuses fixed on-wire type-word values. It does not provide direct native `wireguard-mix` interoperability because WireGuard handshake MACs cover the message type and reserved bytes.

## Components

```text
cmd/wg-mix-ebpf
  CLI entrypoint.

internal/config
  Agent config schema, defaults, and static validation.

internal/wgconfig
  WireGuard config parsing for ListenPort and FwMark expectations.

internal/runtime
  Live WireGuard runtime reader.

internal/underlay
  Underlay resolver for Linux netdev and OpenWrt logical interfaces.

internal/control
  Desired state builder that combines config, wg config, runtime state, and underlay state.

internal/abi
  Stable Go-side ABI snapshot for BPF maps.

internal/dataplane
  Linux TC/eBPF loader, pinned-map handling, generation commit, status, and detach.

internal/guard
  nft startup guard generation and execution.

bpf/wg_mix_tc.c
  TC ingress and egress dataplane program.
```

## Packet Flow

Egress:

```text
WireGuard sends standard UDP packet
  -> TC egress on underlay
  -> match runtime FirewallMark + runtime ListenPort + underlay ifindex
  -> validate WireGuard packet shape
  -> rewrite type_word to mixed value
  -> update UDP checksum
  -> pass packet unchanged otherwise
```

Ingress:

```text
network receives mixed UDP packet
  -> TC ingress on underlay
  -> match runtime ListenPort + underlay ifindex
  -> validate WireGuard packet shape
  -> rewrite type_word to standard value
  -> update UDP checksum
  -> standard kernel WireGuard receives packet
```

Peer endpoint changes, NAT source-port changes, and DDNS changes do not alter BPF maps because endpoints are not part of dataplane matching.

## BPF Maps

The MVP dataplane uses pinned maps so reloads and status commands can share kernel state.

Important map groups:

```text
control_map
  Active generation and ABI version.

profile_map
  Generation-scoped type_word mappings.

egress_rule_map
  Generation-scoped egress match rules.

ingress_listener_map
  Generation-scoped ingress listener rules.

managed_fwmark_map
  Egress fail-closed guard for managed marks.

underlay_config_map
  Parser mode per underlay ifindex.

stats_map
  Per-CPU dataplane counters.
```

Rule keys include generation. Reload prepares new generation entries first, then commits `active_generation`, then cleans stale entries. This avoids overwriting live generation entries before commit.

## Startup Guard

The optional nft startup guard reduces the window where WireGuard could send standard type words before TC programs and BPF maps are ready.

Default behavior:

```text
egress guard: drop managed WireGuard fwmark
ingress guard: drop configured ListenPort if present
random ListenPort ingress: best-effort only
```

If dataplane reload fails after the guard is applied, the guard is intentionally left in place for fail-closed behavior.

## Build Model

The Go binary is built with cgo disabled by default.

The TC/eBPF object is compiled separately with:

```text
clang -target bpf
```

and embedded into the Go binary by the standard build targets. Runtime machines do not need clang or kernel headers when using packaged binaries.

## Test Boundary

Public CI only runs unit tests, BPF compilation, binary build, and offline validation.

These tests require controlled external Linux/OpenWrt machines and are intentionally not part of public CI:

```text
BPF load on target kernel
TC attach/detach
network namespace WireGuard smoke
OpenWrt underlay tests
PPPoE/VLAN tests
offload/GSO/GRO tests
public-internet WireGuard tests
performance and soak tests
```
