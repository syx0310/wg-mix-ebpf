# Architecture

`wg-mix-ebpf` is a transparent WireGuard packet transform. It runs as a userspace control plane plus TC/eBPF dataplane programs attached to selected underlay interfaces.

## Boundary

The default UDP transport only rewrites the first four bytes of the WireGuard UDP payload:

```text
egress: standard type_word -> mixed type_word
ingress: mixed type_word -> standard type_word
```

With optional UDP XOR enabled, the UDP payload pipeline is:

```text
egress: standard type_word -> mixed type_word -> XOR WireGuard payload
ingress: XOR WireGuard payload -> mixed type_word -> standard type_word
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
  It derives configured XOR cipher keys and redacts key bytes from status and ABI JSON.

internal/reconcile
  Shared validate/status/reload/detach workflow used by CLI and daemon.

internal/daemon
  Runtime reconcile loop, global daemon lifecycle lease, status file writer,
  durable instance-bound request acknowledgements, hardened control-file
  reads, and bounded stop handling.

internal/install
  Systemd/OpenWrt install and uninstall helpers.

internal/abi
  Stable Go-side ABI snapshot for BPF maps.

internal/dataplane
  Linux TC/eBPF loader, pinned-map handling, generation commit, status, and detach.

internal/guard
  nft startup guard generation and execution.

internal/lockfile
  Global lifecycle lease plus the separate short-lived operation lock used to
  serialize reload, detach, daemon stop, and uninstall cleanup.

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
  -> optionally XOR the WireGuard payload for UDP cipher mode
  -> update UDP checksum
  -> pass packet unchanged otherwise
```

Ingress:

```text
network receives mixed UDP packet
  -> TC ingress on underlay
  -> match runtime ListenPort + underlay ifindex
  -> validate WireGuard packet shape
  -> optionally undo UDP XOR cipher mode
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
  IPv4: bpf_skb_store_bytes(..., BPF_F_RECOMPUTE_CSUM)
  IPv6: bpf_csum_diff(...) + bpf_l4_csum_replace(...)
        then bpf_skb_store_bytes(..., BPF_F_INVALIDATE_HASH)

ingress:
  bpf_l4_csum_replace(...)
  bpf_skb_store_bytes(..., BPF_F_INVALIDATE_HASH)

ICMP egress:
  bounded full ICMP checksum for small WG packets
  UDP-checksum-derived ICMP checksum for larger WG packets

ICMP ingress:
  IPv4 UDP checksum 0 after ICMP -> UDP conversion

UDP XOR cipher:
  chunked skb load/store of managed WireGuard UDP payload
  IPv4 egress uses the offload-friendly recompute checksum path
  IPv6 egress updates UDP checksum from chunk diffs before writing payload bytes
  ingress accumulates chunk checksum diffs and updates UDP checksum once per
  tail-call segment
```

For payload-only UDP checksum updates, the L4 checksum helper is used in diff
mode with no additional L4 checksum flags. Passing `BPF_F_IPV6` in this
payload-only diff path caused TC egress helper failures in the IPv6 netns
regression.

XOR cost scales with `max_bytes`. `wg-payload-prefix` with a small bounded prefix
is the preferred performance mode; `wg-payload-full` is available for stronger
payload obfuscation but costs one chunked load/store and checksum-diff sequence
per processed chunk.

The current XOR layer is not a mux/multiplex implementation. It does not merge
multiple WireGuard interfaces or peer flows, does not change the outer UDP
tuple, and is only valid with UDP transport. Config validation rejects
ICMP+XOR and fakeTCP+XOR in the MVP.

Status exposes load/store/checksum errors and direction-specific GSO counters:

```text
skb_load_error
skb_store_error
checksum_error
icmp_checksum_error
xor_egress_ok
xor_ingress_ok
xor_key_missing
xor_len_overflow
xor_bad_type_after_decrypt
xor_load_error
xor_store_error
xor_csum_error
xor_egress_dispatch_error
xor_ingress_dispatch_error
egress_gso_seen
egress_gso_managed_seen
egress_gso_rewrite_ok
ingress_gso_seen
ingress_gso_listener_hit
ingress_gso_rewrite_ok
```

TX-side tcpdump captures may show invalid UDP checksums when checksum offload is enabled. Receiver-side captures and dataplane error counters are the useful evidence for checksum correctness.

IPv6 outer UDP is supported by the parser, but real IPv6 underlay validation is still required for release-level confidence, especially when optional payload ciphers are enabled.

## BPF Maps

The MVP dataplane uses pinned maps so reloads and status commands can share kernel state.

Important map groups:

```text
control_map
  Active generation and ABI version.

profile_map
  Generation-scoped type_word mappings.

cipher_map
  Generation-scoped XOR cipher keys and limits. ABI version 10 repeats shorter key periods across the fixed 256-byte key storage so the dataplane can use one verifier-bounded index. Raw key bytes are not emitted in status or `dump-abi` JSON.

xor_egress_programs / xor_ingress_programs
  Pinned ProgramArray maps for the verifier-safe 8 x 256-byte XOR tail-call
  chain. Each map has two generation-parity banks. Reload populates the next
  bank before committing the generation; a missing segment fails closed and
  increments the matching dispatch-error counter.

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

Replacing an existing guard uses one nft batch containing `delete table` followed by the complete replacement table. nft commits the batch atomically; a validation or rule-creation failure therefore rolls back the delete and preserves the old guard. A missing-table error is the only condition that triggers a second, create-only batch.

Each reload reads the main configuration once and memoizes each parsed WireGuard configuration for both guard and runtime state construction. The startup guard is first generated from this config-only snapshot, which allows it to be installed before the WireGuard interface appears. Reload then samples every configured runtime device, atomically expands the guard to cover the union of configured and observed runtime fwmarks, and uses that same runtime snapshot for full state validation. A strict fwmark mismatch on any interface therefore leaves all marks observed during the reload guarded while reload returns an error.

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

Before it reconciles a mutating dataplane, the daemon acquires
`/run/wg-mix-ebpf/daemon.lease` and holds it through final shutdown status
persistence. The lease location is not derived from `--run-dir`, so alternate
status/request directories cannot create multiple owners of the process-global
BPF pins, TC filters, nftables guard table, or attach state. The lease and the
runtime-directory operation lock have separate file descriptions and purposes:
the lifecycle lease establishes one owner, while the operation lock serializes
individual mutations.

All non-dry-run reconcile mutation entrypoints acquire the same lifecycle lease
when the caller does not supply a valid already-held lease token. The daemon
passes its unforgeable held token into reload and stop, avoiding recursive
acquisition while keeping one-shot CLI and uninstall paths on the same ownership
boundary. Both lifecycle and operation lock opens use no-follow semantics and
reject files with multiple hard links.

Non-dry-run install follows the same global-then-runtime lock ordering before
replacing files. Uninstall first asks the service manager to stop the owner,
then acquires both locks for detach and artifact cleanup.

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

Service stop is routed through `wg-mix-ebpf stop`. CLI stop/reload requests use
per-request JSON files and matching per-request ack files rather than inferring
completion from status timestamps. Requests carry the random daemon instance ID
from status; a later daemon acknowledges but never executes a request targeting
an exited instance. The daemon scans queued requests immediately after startup
and on its request interval; a stop in the current batch supersedes reloads in
that batch, with an ack for every request ID.
Admission uses a dedicated queue lock and a bounded request count. Consumed acks
are removed only after their requests disappear; retained acks are capped by
pruning the oldest entries that are no longer needed for crash deduplication.
Request and ack reads use no-follow opens and reject non-regular or
multiply-linked control files.
The legacy `reload.request` compatibility path accepts reload notifications but
never stop notifications, which lack an instance ID. Legacy reload/runtime
files use the same bounded safe reader; invalid inputs are persisted as an
ignored-notification status error while the reconcile loop continues.

If the daemon is running, stop asks it to acquire the shared operation lock,
stop polling/reloading, detach dataplane, remove the nft startup guard table,
write stopped status, and exit. Cleanup has a 10-second deadline by default plus
a fixed 25-millisecond completion-arbitration window. It runs with a duplicated
lifecycle lease descriptor so a timed-out, context-ignoring cleanup worker
retains global ownership after the main daemon loop returns. Cleanup, concurrent
deadline, and final status-write failures are joined and returned as a non-zero
daemon exit. The first termination signal also restores default signal handling
so a second signal can force termination. If the daemon is not running, `stop`
performs one-shot cleanup after acquiring the global lease.

Successful dataplane reload writes persistent attach metadata to `/var/lib/wg-mix-ebpf/attach-state.json`. Stop, detach, and uninstall use this file first, so cleanup does not depend on the WireGuard interface still existing. Reload also compares the previous attach state with the current desired state and detaches stale underlay ifindexes that disappeared from config or changed after reconnect.

Guard cleanup targets the fixed owned table independently of the current configuration mode. This prevents a newer `startup_guard.mode: none` configuration, or a missing configuration with valid attach-state, from falsely reporting that a table left by an earlier reload was removed.

`uninstall` stops the service, acquires the global lifecycle lease, detaches this
agent's dataplane using attach-state when available, and removes BPF pins, the
nft guard table, and runtime/state/service artifacts. It preserves the global
lease inode and parent directory to avoid an unlink/recreate ownership race. It
keeps `/etc/wg-mix-ebpf/config.yaml` by default; `--purge` removes the config
directory. It does not delete the binary or WireGuard configuration.

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
