# 2026-05-09 Real Host Hardening Validation

## Scope

Validated commit `b4dd77b` on controlled Linux/OpenWrt hosts after control-plane hardening.

Hosts:

- Build host: `192.168.10.28`, Ubuntu x86_64.
- OpenWrt host: `10.191.3.3`, ImmortalWrt x86_64, underlay `br-lan`.
- Public host: `47.116.202.155`, Ubuntu x86_64, underlay `eth0`, WireGuard UDP `52000`.
- NAT-side host: `172.16.8.134`, Debian x86_64, underlay `eth0`, WireGuard UDP `52000`.

No source code was copied to public/NAT/OpenWrt test endpoints. Only temporary binaries, temporary configs, keys, helper scripts, and pcaps were placed under `/tmp/wme-hardening-test`.

## Build Host Validation

Built on `192.168.10.28` from a sanitized source sync:

```text
go test ./...: pass
make build-linux-amd64: pass
bpf-load-test: pass
scripts/smoke-netns-wg.sh: pass
```

Linux amd64 binary:

```text
sha256: b366f49cbf3915a24aa9bbd4ad0fb193c9562b800df384e2b8c17237fb95a148
```

Netns smoke pcap summary:

```text
udp_packets=12
mixed_type_words=12
standard_type_words=0
mixed initiation=2 response=2 transport=8
```

## OpenWrt wg-quick-op To Public

`wg-quick-op v0.4.1` was built on the build host and copied temporarily to OpenWrt.

Temporary wg-quick-op binary:

```text
sha256: a792fd8d0a83565185579a72b3fcb3999a0127ada3cb1058cdaf9b02cd83b457
```

### Standard WireGuard Baseline

OpenWrt started `wmeop` through `wg-quick-op`.

Result:

```text
OpenWrt -> public ping: 4/4 received, avg 9.917 ms
Public -> OpenWrt ping: 0/4, OpenWrt returned Destination Port Unreachable
WireGuard latest handshake: recent on both sides
```

This matches the previous OpenWrt firewall/ICMP behavior: the tunnel can handshake and OpenWrt-to-public traffic works, while public-to-OpenWrt ICMP is rejected by the OpenWrt side.

### eBPF Clean Flow

For strict eBPF validation, both endpoints were first created without peers, `wg-mix-ebpf reload` was run, then peers were added.

Result:

```text
OpenWrt -> public ping: 6/6 received, avg 10.004 ms
Public -> OpenWrt ping: still rejected with Destination Port Unreachable
```

Public dataplane stats included:

```text
egress_rewrite_ok=8
ingress_rewrite_ok=10
checksum_error=0
skb_load_error=0
skb_store_error=0
ingress_bad_type=0
```

OpenWrt dataplane stats included:

```text
egress_rewrite_ok=15
ingress_rewrite_ok=12
checksum_error=0
skb_load_error=0
skb_store_error=0
ingress_bad_type=0
```

Public post-reload pcap:

```text
udp_packets=8
mixed_type_words=8
standard_type_words=0
mixed transport=8
udp_checksum_valid=4
udp_checksum_invalid=4
```

The invalid checksums were public host TX-side captures with offload; received packets were checksum-valid.

### wg-quick-op Practical Startup Path

OpenWrt was then started with `wg-quick-op up wmeop`, confirming `PostUp = wg set %i fwmark ...` applied:

```text
listening port: 52120
fwmark: 0x10005303
```

When `wg-quick-op up` is used before dataplane reload, the first initiation can leave before eBPF is attached. The first ping run showed transient loss while the tunnel recovered. A post-reload run was stable:

```text
OpenWrt -> public ping: 6/6 received, avg 10.001 ms
post-reload pcap udp_packets=12
mixed_type_words=12
standard_type_words=0
mixed transport=12
```

This validates compatibility with wg-quick-op runtime state and also confirms the startup-order caveat.

## NAT 172 To Public

### Standard WireGuard Baseline

Result:

```text
NAT -> public ping: 0/6
Public -> NAT ping: 0/6
NAT wg show: outbound transfer only, 0 B received
```

This matches the known environment caveat that standard WireGuard between this NAT host and public host may fail.

### eBPF Clean Flow

Clean sequence:

```text
1. Create WireGuard interfaces with no peers.
2. Reload wg-mix-ebpf on both endpoints.
3. Add peers with PersistentKeepalive=5.
4. Run bidirectional ping.
```

Initial public-to-NAT traffic recovered after endpoint learning. Stable retry results:

```text
NAT -> public ping: 8/8 received, avg 9.301 ms
NAT -> public pcap run: 6/6 received, avg 8.712 ms
Public -> NAT pcap run: 6/6 received, avg 9.504 ms
```

NAT dataplane stats included:

```text
egress_rewrite_ok=22
ingress_rewrite_ok=17
checksum_error=0
skb_load_error=0
skb_store_error=0
ingress_bad_type=0
```

Public dataplane stats included:

```text
egress_rewrite_ok=25
ingress_rewrite_ok=27
checksum_error=0
skb_load_error=0
skb_store_error=0
ingress_bad_type=0
```

Public pcap:

```text
udp_packets=25
mixed_type_words=25
standard_type_words=0
mixed transport=25
udp_checksum_valid=13
udp_checksum_invalid=12
```

Again, invalid checksum entries were public host TX-side offload captures.

## Stop And Uninstall Hardening Checks

`wg-mix-ebpf stop` was tested on OpenWrt and public host:

```text
dataplane detached
```

Post-stop checks showed no `wg_mix_*` TC filters and no `/sys/fs/bpf/wg-mix-ebpf` pins.

`uninstall --dry-run --yes --system unknown` was tested on OpenWrt, public, and NAT hosts. It printed the expected plan including the binary removal hint.

`uninstall --dry-run --purge --yes` with custom `/tmp/wme-hardening-test/*.yaml` config paths was rejected on all three hosts:

```text
refuse to purge non-owned config directory /tmp/wme-hardening-test; only /etc/wg-mix-ebpf is managed by uninstall --purge
```

## Cleanup

After tests:

- Removed temporary `wme0` and `wmeop` interfaces.
- Detached this agent's TC filters.
- Removed `/sys/fs/bpf/wg-mix-ebpf`.
- Removed nft guard tables.
- Removed `/run/wg-mix-ebpf`.
- Removed `/tmp/wme-hardening-test` from public, NAT, and OpenWrt hosts.
- Removed temporary `/etc/wireguard/wmeop.conf` and `/etc/wg-quick-op.toml` from OpenWrt.
- Existing unrelated public-host WireGuard interfaces were left untouched.
