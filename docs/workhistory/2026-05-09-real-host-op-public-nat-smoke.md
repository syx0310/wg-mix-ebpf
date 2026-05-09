# 2026-05-09 Real Host OpenWrt/Public/NAT Smoke

## Scope

Validated the new control-plane/daemon/profile command changes and the current dataplane binary on real hosts:

- OpenWrt x86_64: `10.191.3.3`, underlay `br-lan`.
- Public Ubuntu x86_64: `47.116.202.155`, underlay `eth0`, WireGuard UDP `52000`.
- NAT-side Debian x86_64: `172.16.8.134`, underlay `eth0`, WireGuard UDP `52000`.
- Build host: `192.168.10.28`.
- Test tunnel: `10.191.65.0/30` using `/32 peer` addressing.

Only the compiled binary and helper scripts were copied to test hosts. Source code was not copied to public/NAT/OpenWrt test endpoints.

## Build

Built on `192.168.10.28`:

```text
go test ./...: pass
make build-linux-amd64: pass
binary sha256: 7d15dd46dd4d786f903c817b064a5245539ac021fdca4dcc05b5e8e3ba72331f
```

## Findings Fixed During Test

### nft `destroy table` Compatibility

Public Ubuntu has nftables `v1.0.2`, which rejects:

```text
destroy table inet wg_mix_ebpf_guard
```

This caused reload to fail before TC/eBPF attach on the public endpoint.

Fix:

- Changed cleanup script to `delete table inet wg_mix_ebpf_guard`.
- Changed apply flow to run cleanup separately and ignore cleanup errors before applying the add-table script.
- Removed table deletion from the `nft -f` apply script so missing-table cleanup does not abort startup guard creation.

After rebuilding, public reload succeeded.

## OpenWrt -> Public

### Standard WireGuard Baseline

Started OpenWrt with `wg-quick-op v0.4.1` and public endpoint with raw `ip link + wg set`.

Result:

```text
OpenWrt -> public ping: 4/4 received, 0% loss, avg 9.230 ms
Public -> OpenWrt ping: 0/4; OpenWrt returned Destination Port Unreachable
WireGuard handshake: recent on both sides
```

The one-way ping behavior is attributed to OpenWrt-side firewall/ICMP handling. The WireGuard tunnel itself handshook and OpenWrt-to-public traffic worked.

### eBPF Transform

After loading `wg-mix-ebpf` on both endpoints:

```text
OpenWrt -> public ping: 6/6 received, 0% loss, avg 9.300 ms
Public -> OpenWrt ping: 0/6; OpenWrt returned Destination Port Unreachable
```

Dataplane stats:

```text
public:
  egress_rewrite_ok=12
  ingress_rewrite_ok=12
  checksum_error=0
  skb_load_error=0
  skb_store_error=0
  ingress_bad_type=0

openwrt:
  egress_rewrite_ok=12
  ingress_rewrite_ok=12
  checksum_error=0
  skb_load_error=0
  skb_store_error=0
  ingress_bad_type=0
```

The pcap capture was started before dataplane reload and therefore contains four standard handshake/empty-data packets from the pre-transform window. After reload, transport packets are mixed and the tunnel works. Future evidence scripts should start capture after reload or split pre/post captures.

## NAT 172 -> Public

### Standard WireGuard Baseline

Result:

```text
NAT -> public ping: 0/6
Public -> NAT ping: 0/6
NAT wg show: outbound transfer only, 0 B received
```

This matches the known environment caveat: standard WireGuard between `172.16.8.134` and `47.116.202.155` may fail.

### eBPF Transform Clean Flow

Used the clean sequence:

```text
1. Create WireGuard interfaces with no peers.
2. Reload wg-mix-ebpf on both endpoints.
3. Add peers with PersistentKeepalive=5.
4. Run bidirectional ping.
```

Result:

```text
NAT -> public ping: 8/8 received, 0% loss, avg 9.018 ms
Public -> NAT ping: 8/8 received, 0% loss, avg 8.866 ms
```

Dataplane stats:

```text
nat:
  egress_rewrite_ok=18
  ingress_rewrite_ok=18
  checksum_error=0
  skb_load_error=0
  skb_store_error=0
  ingress_bad_type=0

public:
  egress_rewrite_ok=18
  ingress_rewrite_ok=18
  checksum_error=0
  skb_load_error=0
  skb_store_error=0
  ingress_bad_type=0
```

Pcap on public endpoint:

```text
udp_packets=23
mixed_type_words=23
standard_type_words=0
mixed initiation=1
mixed response=1
mixed transport=21
udp_checksum_valid=11
udp_checksum_invalid=12
```

The invalid checksums are TX-side captures with checksum offload; receive-side packets are valid and dataplane checksum/load/store errors remain zero.

## Command Practical Checks

On `172.16.8.134`:

```text
wg-mix-ebpf profile list --config /tmp/wme-real/agent.yaml: printed home
wg-mix-ebpf profile token home: token prefix wgmix1
wg-mix-ebpf profile check <token>: ok
wg-mix-ebpf init --profile-token <token> ...: wrote /tmp/wme-real/init.yaml
wg-mix-ebpf validate --config /tmp/wme-real/init.yaml --offline: ok
wg-mix-ebpf uninstall --config /tmp/wme-real/agent.yaml --system unknown --dry-run --yes: printed expected plan
```

## Cleanup

After tests:

- Deleted temporary `wme0` / `wmeop` interfaces.
- Detached this agent's TC filters.
- Removed `/sys/fs/bpf/wg-mix-ebpf`.
- Removed nft guard tables.
- Removed temporary configs, keys, pcaps, helper scripts, and binaries under `/tmp/wme-real`.
- Removed temporary OpenWrt `/etc/wireguard/wmeop.conf` and `/etc/wg-quick-op.toml`.

Existing public-host WireGuard interfaces unrelated to the test were left untouched.
