# Configuration

The default config path is:

```text
/etc/wg-mix-ebpf/config.yaml
```

The config format version is currently `1`.

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

`poll_interval` controls the daemon's low-frequency runtime reconcile loop. Manual commands still rebuild state when invoked.

The daemon does not automatically apply config file content changes observed by the poll loop. It marks status as `config_changed` / `need_reload` and waits for explicit `wg-mix-ebpf reload` or service reload. Local runtime changes such as WireGuard ListenPort, FirewallMark, and underlay ifindex remain automatically reconciled.

`require_nonzero_fwmark: true` rejects managed interfaces with config or runtime `FwMark = 0/off`.

`require_nonzero_fwmark: false` is reserved but not implemented by the MVP. Managed WireGuard interfaces must use nonzero marks so egress fail-closed logic does not treat ordinary `mark=0` UDP traffic as managed WireGuard traffic.

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

`wg-mix-ebpf stop`, service stop, and uninstall remove the nft guard table as part of network-impact cleanup. `guard-cleanup` can be used to remove a leftover guard explicitly.

The nft cleanup step is best effort and runs separately from rule creation. Missing guard tables are ignored so older nftables versions do not abort startup guard creation before dataplane attach.

`none` disables startup guard and is intended for development, controlled tests, or minimal systems without nft. In this mode, egress fail-closed behavior only starts after the TC/eBPF dataplane is attached and maps are populated.

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

## Baseline And NAT Notes

Standard WireGuard connectivity is useful as an environment reference, but it is not a hard validation gate for this transparent transform. On a public/NAT pair, standard WireGuard may fail to handshake if the public side has not learned the NAT-side endpoint yet, even when the same pair works after keepalive or after traffic from the NAT side.

Validate `wg-mix-ebpf` by checking:

```text
both endpoints run the transparent transform
inner WireGuard ping succeeds in both directions
pcap shows mixed initiation/response/transport type words
pcap shows zero standard type words on managed egress
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
