# Configuration

The default config path is:

```text
/etc/wg-mix-ebpf/config.yaml
```

The config format version is currently `1`.

Configuration parsing is strict. Unknown fields, duplicate mapping keys, and multiple YAML documents are rejected so misspelled safety options cannot be silently ignored.

An installed but uninitialized config may be an idle template:

```yaml
version: 1
mode: transparent-typeword
underlays: []
wireguards: []
profiles:
  default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none
```

This template is valid and has no network effect because it manages no WireGuard interface.

## Complete Example

```yaml
version: 1
mode: transparent-typeword

underlays:
  - name: eth0
    type: netdev

wireguards:
  - name: wg0
    config: /etc/wireguard/wg0.conf
    profile: mix-default
    cipher: xor-home
    transport:
      mode: udp

profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none

ciphers:
  xor-home:
    mode: xor
    auth: none
    scope: wg-payload-prefix
    key_derivation: udp2raw-md5-key1
    password: "change-me"
    max_bytes: 128

fwmark_policy:
  mode: config-required

runtime:
  poll_interval: 5s
  attachment_backend: auto
  require_nonzero_fwmark: true
  strict_runtime_fwmark: true
  allow_zero_fwmark_fallback: false

startup_guard:
  mode: nft-temporary-drop
  egress:
    match: fwmark
  ingress:
    match: config-listen-port-if-present
    random_listen_port_behavior: best-effort

underlay_overlap_policy: reject

policy:
  non_managed_udp: pass
  managed_egress_map_miss: drop
  managed_egress_bad_type: drop
  managed_egress_bad_length: drop
  egress_managed_ipv6_ext_header: drop
  managed_ingress_map_miss: pass
  managed_ingress_bad_type: drop
  managed_ingress_bad_length: drop
  ingress_managed_ipv6_ext_header: drop
  ipv4_first_fragment: drop
  ipv4_non_first_fragment:
    ingress: pass
    egress_if_managed_fwmark: drop
    optional_drop_all_on_underlay: false
  ipv6_fragment: drop
  startup_fail_mode: fail_closed_for_managed_flows
```

## `version`

Supported value:

```yaml
version: 1
```

Other versions are rejected.

## `mode`

Supported value:

```yaml
mode: transparent-typeword
```

This mode only rewrites the WireGuard UDP payload `type_word`.

## `underlays`

`underlays` defines where TC programs are attached.

Supported underlay types:

```text
netdev
openwrt-interface
```

Linux netdev example:

```yaml
underlays:
  - name: eth0
    type: netdev
```

OpenWrt logical interface example:

```yaml
underlays:
  - name: wan
    type: openwrt-interface
```

Optional parser override:

```yaml
underlays:
  - name: eth0
    type: netdev
    parser: ethernet
```

Supported parser values:

```text
auto
ethernet
l3
```

Default behavior is equivalent to `auto`. Use explicit parser settings only when validating a known platform path.

## `wireguards`

Each entry binds one WireGuard interface to one transform profile.

```yaml
wireguards:
  - name: wg0
    config: /etc/wireguard/wg0.conf
    profile: mix-default
```

If `config` is omitted, the default is:

```text
/etc/wireguard/<name>.conf
```

MVP netns support is root namespace only:

```yaml
wireguards:
  - name: wg0
    netns: root
```

Cross-netns and moved WireGuard socket setups are not supported by the MVP.

### `cipher`

Each WireGuard entry can optionally select an outer payload obfuscation cipher:

```yaml
wireguards:
  - name: wg0
    profile: mix-default
    cipher: xor-home
    transport:
      mode: udp
```

The XOR cipher is implemented with `transport.mode: udp` and
`transport.mode: faketcp`. ICMP + XOR is rejected.

### `transport`

Each WireGuard entry can select an outer transport. The default is the original UDP type-word transform:

```yaml
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: udp
```

Experimental IPv4 ICMP mode:

```yaml
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: icmp
      icmp:
        role: client
        id: 0x5301
```

Public/server side:

```yaml
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: icmp
      icmp:
        role: server
```

ICMP mode notes:

```text
ICMP mode is experimental
IPv4 only; ICMPv6 is not implemented
client emits Echo Request and accepts Echo Reply
server accepts Echo Request and emits Echo Reply
client id must be nonzero and should be unique per client/profile
server uses wildcard Echo id; leave server icmp.id unset or zero
server config with a nonzero transport.icmp.id is rejected
server wildcard matching is intended for mixed WireGuard Echo payloads, not ordinary ping traffic
server wildcard-id listener passes only bad type-word or bad length misses; valid managed ICMP WireGuard packets are still rewritten
server preserves NAT-rewritten Echo sequence values with runtime kernel state
raw UDP WireGuard packets to an ICMP-managed ListenPort are not a fallback path and should be dropped
outer IP fragmentation is unsupported; keep WireGuard MTU below the underlay fragmentation threshold
large-packet ICMP checksum handling depends on the current skb checksum/offload shape and needs target validation
```

Production IPv4 FakeTCP mode:

```yaml
wireguards:
  - name: wg0
    profile: mix-default
    transport:
      mode: faketcp
      faketcp:
        checksum_mode: partial-complete-reset-required
        ingress_mode: xdp-generic-exact

runtime:
  attachment_backend: auto
  checksum_backend: auto
```

FakeTCP keeps WireGuard packet boundaries and presents a TCP-shaped outer wire
image; it is not a TCP stream. Multiple WireGuard entries may select FakeTCP;
their policy, session, event and slow-path routing state is isolated by WGID.
It is IPv4-only and must run in the resident daemon. The TC stage supports
`tcx` and `classic_tc`, while every combination keeps direct generic XDP with
exact selected-mode ownership and no replace, fallback, or libxdp chaining.
The checksum bridge supports `kfunc` and the legacy-compatible `kprobe`
backend. The deprecated `experimental` field is parsed and ignored, and legacy
`xdp-required` is normalized to `xdp-generic-exact`.

Backend selection is independent:

```yaml
runtime:
  # auto | tcx | classic_tc
  attachment_backend: auto
  # auto | kfunc | kprobe
  checksum_backend: auto
```

`attachment_backend: auto` prefers exact TCX when the kernel supports it and
otherwise resolves to classic TC before any network mutation. A validated
durable FakeTCP classic owner remains sticky during recovery. Probe errors
other than an explicit unsupported result fail without falling back.

`checksum_backend: auto` prefers the matching kfunc module/object. It may use
kprobe only when kfunc is explicitly unsupported and the complete kprobe
module lease, trigger, health and artifact contract is available. An explicit
`kfunc` or `kprobe` value never falls back to the other backend. The resolved
backend does not change while a resident generation is active.

The released kprobe module currently targets Linux x86_64. On arm64, select
`kfunc` (or let `auto` select it); `kprobe` remains unavailable until its
architecture-specific kernel calling convention is separately validated.

The kfunc path requires administrator-provisioned
`wg_mix_faketcp_checksum`. The kprobe path requires
`wg_mix_faketcp_checksum_kprobe` and a per-runtime FD lease. The module accepts
multiple simultaneous leases and issues a distinct fixed cookie to each
runtime; a runtime may use only the cookie bound to its retained FD and cannot
fall back after activation. Both paths retain the complete checksum, PMTU and
UDP-GSO-to-TCP-GSO contract; a reduced `faketcp-lite` path is not selected
automatically.

FakeTCP startup is always fail-closed. Its WireGuard file must configure a
fixed non-zero `ListenPort`, `startup_guard.mode` must be
`nft-temporary-drop`, and `policy.startup_fail_mode` must be
`fail_closed_for_managed_flows`. These are validation errors rather than
best-effort recommendations: the same fixed port is guarded as both UDP and
TCP until the complete resident runtime passes its final health check.

Multiple FakeTCP WireGuard entries use one shared set of TC and XDP programs
per underlay. Every entry must have a distinct, fixed non-zero `ListenPort` in
its WireGuard configuration. An ambiguous managed port, fwmark, or WGID route
is rejected before attachment; the error identifies the conflicting entries.

Regression entry points:

```bash
sudo make test-netns-icmp-smoke
sudo NEGATIVE_CHECKS=xfail scripts/smoke-netns-icmp.sh
sudo NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh
```

`test-netns-icmp-smoke` validates the positive ICMP client/server path and requires ICMP Echo Request/Reply pcaps with mixed initiation, response, and transport type words and zero standard type-word leaks. `NEGATIVE_CHECKS=xfail` exercises the negative hooks without failing the run on branches that do not yet include the core pass/drop logic; `NEGATIVE_CHECKS=enforce` makes ordinary ping pass-through and raw UDP bypass protection mandatory.

## `ciphers`

`ciphers` defines optional WireGuard payload obfuscation layers. The first implemented mode is XOR:

```yaml
ciphers:
  xor-home:
    mode: xor
    auth: none
    scope: wg-payload-prefix
    key_derivation: udp2raw-md5-key1
    password: "example-passphrase"
    max_bytes: 128
```

MVP UDP processing order:

```text
egress:
  standard type_word -> mixed type_word -> XOR WireGuard payload

ingress:
  XOR WireGuard payload -> mixed type_word -> standard type_word
```

Current XOR is not multiplexing. It does not combine multiple WireGuard
interfaces or flows into one outer flow, and it does not implement udp2raw
framing. It is a UDP-only payload transform layered on top of the type-word
rewrite. Config validation rejects ICMP + XOR; UDP and FakeTCP accept XOR.

Supported fields:

```text
mode:
  xor

auth:
  none

scope:
  wg-payload-full
  wg-payload-prefix

key_derivation:
  wgmx-hkdf256-v1
  udp2raw-md5-key1

key_len:
  16, 32, 64, or 256

max_bytes:
  non-zero multiple of 4 up to 2048
```

Default values:

```text
scope: wg-payload-prefix
max_bytes: 128
auth: none
key_derivation: wgmx-hkdf256-v1
key_len: 256
```

`wg-payload-full` XORs the whole WireGuard UDP payload and drops managed packets larger than `max_bytes`. `wg-payload-prefix` XORs only the first `max_bytes` bytes.

`wg-payload-prefix` is the recommended default for performance-sensitive UDP mode. The dataplane processes XOR in bounded chunks, so CPU cost scales with the number of bytes XORed. A prefix of `4` only hides the mixed type word; `64` or `128` hides more of the WireGuard header and early ciphertext while keeping helper calls low. Use `wg-payload-full` only when full payload XOR is required and the target path has been benchmarked.

`udp2raw-md5-key1` derives the XOR key as `MD5(password + "key1")`. This only reuses udp2raw's lightweight XOR key style; it is not udp2raw wire-compatible and does not implement udp2raw framing, auth, anti-replay, or raw modes.

`wgmx-hkdf256-v1` derives a symmetric project key from `secret` or `secret_file`:

```yaml
ciphers:
  xor-home:
    mode: xor
    auth: none
    scope: wg-payload-prefix
    key_derivation: wgmx-hkdf256-v1
    secret_file: /etc/wg-mix-ebpf/xor-home.key
    key_len: 256
    max_bytes: 128
```

Secret material is derived in userspace and written to the BPF cipher map as fixed key bytes. For key lengths shorter than 256 bytes, userspace repeats the configured key period across the map's 256-byte key storage; the ABI snapshot rejects inconsistent `key_len`/`key_mask` values before map population, and the dataplane uses a fixed 8-bit index. This representation is part of BPF ABI version 10. Configure exactly one of `secret`, `secret_file`, or `password`; empty decoded/file content is rejected. `status` and `dump-abi` hide the actual key.

Regression entry point:

```bash
sudo make test-netns-xor-smoke
sudo make test-netns-xor-full-smoke
```

The full-payload target sends a 1900-byte no-fragment probe through segment 7,
exercises both ProgramArray parity banks across generations, removes one active
egress and ingress segment to verify fail-closed dispatch counters, and reloads
to confirm recovery.

## WireGuard Config Requirements

The agent reads the expected `FwMark` from the WireGuard config. The live runtime `FirewallMark` is read from WireGuard runtime state and must match by default.

Preferred form:

```ini
[Interface]
FwMark = 0x10000001
```

Compatible `PostUp` form:

```ini
[Interface]
PostUp = wg set %i fwmark 0x10000001
```

The `PostUp` form is useful for launch modes where the config parser can see the expected mark but another tool applies it at interface startup.

For UDP and ICMP, `ListenPort` may be present or omitted in the WireGuard
config and the dataplane uses the runtime value. FakeTCP is stricter: it
requires the static config value to be present and non-zero, and the live
WireGuard interface must report that exact same port. The daemon rejects a
mismatch before the dataplane loader can detach or attach anything, so the
startup guard always covers the exact UDP and TCP wire port:

```ini
[Interface]
ListenPort = 52000
```

For UDP and ICMP only, if WireGuard chooses a random listen port, run
`wg-mix-ebpf reload` after the interface is up so the agent can read the
runtime value. FakeTCP does not permit a random or externally changed live
port; update the WireGuard interface to the configured fixed port first.

For NAT-side peers, configure WireGuard persistent keepalive in the WireGuard config or with your WireGuard management tool. `wg-mix-ebpf` does not modify peer settings, but a NAT-side peer normally needs keepalive to keep its endpoint reachable:

```ini
[Peer]
Endpoint = public.example.net:52000
PersistentKeepalive = 25
```

For short-lived tests, a lower keepalive such as `5` seconds can make endpoint learning deterministic. Production deployments should use the normal WireGuard value appropriate for the NAT path.

## `profiles`

Recommended profile:

```yaml
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none
```

Profiles can be managed with the CLI:

```bash
wg-mix-ebpf profile list
wg-mix-ebpf profile add home
wg-mix-ebpf profile add home --preset wireguard-mix-wire-values-v1
wg-mix-ebpf profile add home --token 'wgmix1....'
wg-mix-ebpf profile token home
wg-mix-ebpf profile check 'wgmix1....'
wg-mix-ebpf profile remove home
wg-mix-ebpf profile remove home --force
```

`profile add <name>` without `--preset` or `--token` creates a random fixed-size type-word profile.

Profile tokens are only an anti-typo transport format. They are not encrypted and not signed. Use the same token on both endpoints when creating a matching profile.

If a profile is still referenced by a WireGuard entry, `profile remove` refuses by default. With `--force`, the profile is removed and the referencing WireGuard entries are removed from the agent config, so the agent no longer manages those interfaces. The WireGuard config and interface are not modified.

`index.mode: none` means sender and receiver indexes are not modified.

Explicit type-word profile:

```yaml
profiles:
  custom:
    type_word:
      initiation: 0xf658c2e6
      response: 0x0686b1d0
      cookie_reply: 0x8ebd4e3d
      transport_data: 0x13dff06b
    index:
      mode: none
```

Rules:

```text
standard type words are fixed as 1, 2, 3, 4
mixed type words must be unique within a profile
mixed type words must not equal standard values unless passthrough is explicitly allowed
sender_index and receiver_index are not rewritten by the MVP
```

## `fwmark_policy`

Supported value:

```yaml
fwmark_policy:
  mode: config-required
```

Reserved but not implemented:

```yaml
fwmark_policy:
  mode: runtime-accepted
```

```yaml
fwmark_policy:
  mode: openwrt-uci
```

The MVP requires the expected mark to be discoverable from the WireGuard config or supported `PostUp` command.

## `runtime`

Default runtime settings:

```yaml
runtime:
  poll_interval: 5s
  require_nonzero_fwmark: true
  strict_runtime_fwmark: true
  allow_zero_fwmark_fallback: false
```

`poll_interval` controls the daemon's low-frequency runtime reconcile loop and must be at least `100ms`. Manual commands still rebuild state when invoked.

The daemon does not automatically apply config file content changes observed by the poll loop. It marks status as `config_changed` / `need_reload` and waits for explicit `wg-mix-ebpf reload` or service reload. Local runtime changes such as WireGuard ListenPort, FirewallMark, and underlay ifindex remain automatically reconciled.

`require_nonzero_fwmark: true` rejects managed interfaces with config or runtime `FwMark = 0/off`.

`require_nonzero_fwmark: false` is reserved but not implemented by the MVP. Managed WireGuard interfaces must use nonzero marks so egress fail-closed logic does not treat ordinary `mark=0` UDP traffic as managed WireGuard traffic.

`strict_runtime_fwmark: true` requires the WireGuard config mark and runtime mark to match.

`allow_zero_fwmark_fallback: true` is reserved but not implemented by the MVP.

## Capacity Limits

Reload keeps the active generation while staging the next one, so the supported per-generation limits are half of the fixed BPF map capacities:

```text
profiles: 64
ciphers: 64
underlays: 256
managed fwmark rules: 256
egress rules: 1024
ingress listeners: 1024
ICMP listeners: 1024
```

Static validation rejects configurations that could exceed these limits during a later reload instead of allowing the first load to succeed and the next generation to fail.

## `startup_guard`

Default:

```yaml
startup_guard:
  mode: nft-temporary-drop
  egress:
    match: fwmark
  ingress:
    match: config-listen-port-if-present
    random_listen_port_behavior: best-effort
```

Supported modes:

```text
nft-temporary-drop
none
```

`nft-temporary-drop` installs temporary nft rules before dataplane reload and removes them after successful reload. If reload fails after the guard is applied, the guard remains in place.

`wg-mix-ebpf stop`, service stop, and uninstall remove the nft guard table as part of network-impact cleanup. `guard-cleanup` can be used to remove a leftover guard explicitly.

When a guard table already exists, reload submits its deletion and the complete replacement table in one nft batch. nft validates and commits that batch atomically, so an invalid replacement leaves the previous guard in place. If the batch reports that the old table is absent, reload retries with a create-only script. Other replacement errors do not trigger that fallback.

The first guard plan uses the configured fwmarks, before runtime state is required. Reload then samples every configured WireGuard runtime device and atomically expands the plan to the union of configured and observed runtime fwmarks before full state validation or dataplane apply. The same runtime snapshot is used for validation. If strict fwmark validation rejects a mismatch, all runtime marks observed during that reload remain guarded.

Stop cleanup always attempts to delete the fixed `inet wg_mix_ebpf_guard` table, even when the current config says `startup_guard.mode: none` or the config file is unavailable but attach-state exists. A missing table is idempotent; a missing `nft` binary or any other cleanup error is reported, and cleanup is not reported as successful.

`none` disables startup guard and is intended for development, controlled tests, or minimal systems without nft. In this mode, egress fail-closed behavior only starts after the TC/eBPF dataplane is attached and maps are populated.

## `underlay_overlap_policy`

Supported value:

```yaml
underlay_overlap_policy: reject
```

`runtime.attachment_backend` accepts `auto`, `tcx`, or `classic_tc`. `auto`
performs a read-only TCX query on every attachable underlay and falls back to
classic TC only when the kernel reports that TCX is unsupported. Permission,
malformed-query, or ownership errors do not trigger fallback. With no
attachable underlay and no durable owner, `auto` is an idle no-op and does not
persist an unprobed owner schema. Once an owner exists, `auto` remains on that
owner's schema-v3 classic or schema-v4 TCX backend across reloads and kernel
upgrades. Select a different backend explicitly only after detaching the old
owner.

FakeTCP, UDP and ICMP can use either TCX or classic TC. FakeTCP additionally
retains exact generic XDP regardless of which TC backend is selected. A
validated durable FakeTCP classic owner keeps `auto` sticky to classic during
recovery; an explicit backend never switches silently.

This rejects duplicate underlay names. More advanced path-overlap detection is platform-specific and must be validated externally.

## `policy`

Default policy:

```yaml
policy:
  non_managed_udp: pass
  managed_egress_map_miss: drop
  managed_egress_bad_type: drop
  managed_egress_bad_length: drop
  egress_managed_ipv6_ext_header: drop
  managed_ingress_map_miss: pass
  managed_ingress_bad_type: drop
  managed_ingress_bad_length: drop
  ingress_managed_ipv6_ext_header: drop
  ipv4_first_fragment: drop
  ipv4_non_first_fragment:
    ingress: pass
    egress_if_managed_fwmark: drop
    optional_drop_all_on_underlay: false
  ipv6_fragment: drop
  startup_fail_mode: fail_closed_for_managed_flows
```

The MVP only implements the shown values. Other values are rejected by static validation.

`best_effort` remains accepted for UDP/ICMP compatibility, but it is rejected
when any WireGuard selects FakeTCP. FakeTCP likewise rejects
`startup_guard.mode: none`.

Egress is fail-closed for managed WireGuard packets. Ingress only drops packets that match a managed listener or a managed fragment policy.

Outer IP fragmentation is not supported. Configure WireGuard MTU and underlay MTU to avoid outer UDP or ICMP fragmentation.

## Baseline And NAT Notes

Standard WireGuard connectivity is useful as an environment reference, but it is not a hard validation gate for this transparent transform. On a public/NAT pair, standard WireGuard may fail to handshake if the public side has not learned the NAT-side endpoint yet, even when the same pair works after keepalive or after traffic from the NAT side.

Validate `wg-mix-ebpf` by checking:

```text
both endpoints run the transparent transform
inner WireGuard ping succeeds in both directions
pcap shows mixed initiation/response/transport type words
pcap shows zero standard type words on managed egress
ICMP mode pcap shows Echo Request and Echo Reply with mixed payload type words
status shows checksum_error=0, skb_load_error=0, skb_store_error=0
```

## Useful Commands

Static validation:

```bash
wg-mix-ebpf validate --config /etc/wg-mix-ebpf/config.yaml --offline
```

Runtime validation:

```bash
wg-mix-ebpf validate --config /etc/wg-mix-ebpf/config.yaml
```

Inspect desired and dataplane state:

```bash
wg-mix-ebpf status --config /etc/wg-mix-ebpf/config.yaml
```

Apply dataplane:

```bash
wg-mix-ebpf reload --config /etc/wg-mix-ebpf/config.yaml
```

Detach dataplane:

```bash
wg-mix-ebpf detach --config /etc/wg-mix-ebpf/config.yaml
```
