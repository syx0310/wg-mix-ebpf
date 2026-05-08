# Configuration

The default config path is:

```text
/etc/wg-mix-ebpf/config.yaml
```

The config format version is currently `1`.

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

profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none

fwmark_policy:
  mode: config-required

runtime:
  poll_interval: 5s
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

`ListenPort` may be present or omitted in the WireGuard config. The dataplane uses the runtime listen port, not the static config value:

```ini
[Interface]
ListenPort = 52000
```

If WireGuard chooses a random listen port, run `wg-mix-ebpf reload` after the interface is up so the agent can read the runtime value.

## `profiles`

Recommended profile:

```yaml
profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none
```

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

`poll_interval` is reserved for future long-running reconcile behavior. The current CLI commands rebuild state when invoked.

`require_nonzero_fwmark: true` rejects managed interfaces with runtime `FirewallMark = 0`.

`strict_runtime_fwmark: true` requires the WireGuard config mark and runtime mark to match.

`allow_zero_fwmark_fallback: true` is reserved but not implemented by the MVP.

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

`none` disables startup guard and is intended for development or controlled tests.

## `underlay_overlap_policy`

Supported value:

```yaml
underlay_overlap_policy: reject
```

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

Egress is fail-closed for managed WireGuard packets. Ingress only drops packets that match a managed listener or a managed fragment policy.

Outer IP fragmentation is not supported. Configure WireGuard MTU and underlay MTU to avoid outer UDP fragmentation.

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
