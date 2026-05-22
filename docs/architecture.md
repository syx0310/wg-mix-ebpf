# Architecture

`wg-mix-ebpf` is a transparent WireGuard packet transform. It runs as a userspace control plane plus TC/eBPF dataplane programs attached to selected underlay interfaces.

## Boundary

The default UDP transport only rewrites the first four bytes of the WireGuard UDP payload:

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

The experimental ICMP transport keeps the same WireGuard payload transform, but also replaces the fixed-size outer UDP header with an ICMP Echo header on IPv4. UDP and ICMP Echo headers are both 8 bytes, so packet length is unchanged.

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

internal/reconcile
  Shared validate/status/reload/detach workflow used by CLI and daemon.

internal/daemon
  Runtime reconcile loop, status file writer, reload-request handling, and stop-request handling.

internal/install
  Systemd/OpenWrt install and uninstall helpers.

internal/abi
  Stable Go-side ABI snapshot for BPF maps.

internal/dataplane
  Linux TC/eBPF loader, pinned-map handling, generation commit, status, and detach.

internal/guard
  nft startup guard generation and execution.

internal/lockfile
  Process-wide file lock used to serialize reload, detach, daemon stop, and uninstall cleanup.

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

ICMP transport egress:

```text
WireGuard sends standard UDP packet
  -> TC egress on underlay
  -> match runtime FirewallMark + runtime ListenPort + underlay ifindex
  -> validate WireGuard packet shape
  -> rewrite type_word to mixed value
  -> IPv4 protocol UDP -> ICMP
  -> UDP header -> ICMP Echo Request/Reply header
  -> recompute IPv4 header checksum and ICMP checksum
```

ICMP transport ingress:

```text
network receives ICMP Echo packet
  -> TC ingress on underlay
  -> match ICMP role/type/id rule
  -> validate mixed WireGuard payload shape
  -> rewrite type_word to standard value
  -> IPv4 protocol ICMP -> UDP
  -> ICMP Echo header -> UDP header with local runtime ListenPort
  -> standard kernel WireGuard receives packet
```

ICMP server listeners use an explicit wildcard-id flag for the `id=0` fallback entry. Exact-id listener hits still fail closed on bad mixed type words or invalid WireGuard lengths. Wildcard-id fallback hits pass packets that fail only the mixed type-word or WireGuard length checks, while still incrementing the ingress bad-type or bad-length counter, so ordinary Echo Request traffic is not dropped merely because its payload is not a managed WireGuard packet. Profile misses and generation mismatches still drop.

For ICMP server mode, ingress uses the observed Echo `id` as the synthetic UDP source port. WireGuard then naturally carries that value in the return packet destination port, allowing egress to emit an Echo Reply with the same `id`.

Some NAT devices rewrite the ICMP Echo `sequence` field while keeping the Echo `id`. ICMP server ingress records the observed `generation + underlay ifindex + wg_id + remote IPv4 + Echo id -> sequence` in a small kernel LRU map. Server egress uses that value when emitting Echo Replies, so the return packet matches the NAT-created ICMP state without sharing sequence state across reloads, underlays, or WireGuard interfaces.

## Checksums And Offload

The dataplane reads and writes the WireGuard type word with skb helpers rather than requiring the UDP payload to be in the direct-access linear skb area. This is required on hosts where TX checksum offload, GSO, or GRO changes skb layout.

Checksum handling is direction-specific:

```text
egress:
  bpf_skb_store_bytes(..., BPF_F_RECOMPUTE_CSUM)

ingress:
  bpf_l4_csum_replace(...)
  bpf_skb_store_bytes(..., BPF_F_INVALIDATE_HASH)

ICMP egress:
  bounded full ICMP checksum for small WG packets
  UDP-checksum-derived ICMP checksum for larger WG packets

ICMP ingress:
  IPv4 UDP checksum 0 after ICMP -> UDP conversion
```

Status exposes load/store/checksum errors and direction-specific GSO counters:

```text
skb_load_error
skb_store_error
checksum_error
icmp_checksum_error
egress_gso_seen
egress_gso_managed_seen
egress_gso_rewrite_ok
ingress_gso_seen
ingress_gso_listener_hit
ingress_gso_rewrite_ok
```

TX-side tcpdump captures may show invalid UDP checksums when checksum offload is enabled. Receiver-side captures and dataplane error counters are the useful evidence for checksum correctness.

IPv6 outer UDP is supported by the parser and netns smoke tests, but real multi-host IPv6 underlay validation is still required for release-level confidence.

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

icmp_listener_map
  Generation-scoped ICMP Echo listener rules for IPv4 ICMP transport.

icmp_seq_map
  Runtime LRU state keyed by generation, underlay ifindex, wg_id, remote IPv4, and Echo id for ICMP server replies when an upstream NAT rewrites Echo sequence.

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

For nftables compatibility, guard cleanup is executed separately from guard creation. Cleanup uses `delete table` as a best-effort operation and ignores missing-table errors before applying the add-table rules. This avoids aborting startup guard creation on older nftables versions that reject `destroy table` or fail a combined script when the table does not already exist.

The startup guard is generated from config-only state before runtime WireGuard state is required. That allows egress fwmark guard rules to be installed even when the WireGuard interface has not appeared yet.

## Service And Reconcile Model

The user-facing commands are intentionally small:

```text
doctor
install
init
profile
reload
status
uninstall
```

The daemon entrypoint is:

```text
run
```

`install` only installs the binary, config directory, state directories, and systemd/OpenWrt service files. It does not start, enable, reload, attach TC, or mutate WireGuard.

The daemon performs:

```text
startup reconcile
low-frequency poll reconcile
manual reload request handling
OpenWrt hotplug reload request handling
manual stop request handling
status file updates under /run/wg-mix-ebpf
```

Poll reconcile intentionally ignores peer endpoint, handshake, and transfer counter changes. Those values are status-only metadata and do not enter dataplane maps.

Poll reconcile also treats config file changes as operator-controlled changes. If the daemon notices that the config file content changed during a poll/runtime event, it records `config_changed` / `need_reload` in daemon status and waits for explicit `wg-mix-ebpf reload` or service reload. This avoids accidentally applying profile or underlay changes while the operator is still editing the file.

The daemon does not:

```text
modify WireGuard config
execute wg set or wg syncconf
resolve DDNS
update dataplane maps when only peer endpoint/handshake/counters change
```

`systemctl stop wg-mix-ebpf` or OpenWrt service stop detaches this agent's TC filters. If WireGuard keeps running after that, it may send standard WireGuard type words.

Service stop is routed through `wg-mix-ebpf stop`. If the daemon is running, the command asks the daemon to acquire the shared lock, stop polling/reloading, detach dataplane, remove the nft startup guard table, write stopped status, and exit. If the daemon is not running, it performs one-shot stop cleanup.

Successful dataplane reload writes persistent attach metadata to `/var/lib/wg-mix-ebpf/attach-state.json`. Stop, detach, and uninstall use this file first, so cleanup does not depend on the WireGuard interface still existing. Reload also compares the previous attach state with the current desired state and detaches stale underlay ifindexes that disappeared from config or changed after reconnect.

`uninstall` stops the service, detaches this agent's dataplane using attach-state when available, removes BPF pins, removes the nft guard table, and removes runtime/state/service files. It keeps `/etc/wg-mix-ebpf/config.yaml` by default; `--purge` removes the config directory. It does not delete the binary or WireGuard configuration.

`uninstall --purge` only removes the owned config directory. It refuses to purge arbitrary parent directories from custom `--config` paths.

Poll no-op optimization checks desired state and dataplane health. If pinned maps or expected TC filters are missing, the daemon forces reconcile instead of reporting active from desired state alone.

Manual reload and stop requests sent to a running daemon must target the daemon's active config path. If a user passes `--config` for a different file, the request is rejected instead of silently reloading the daemon's original config.

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
