# 2026-05-08 IPv6 Netns and Keepalive Public Regression

## Scope

Follow-up hardening after the offload checksum fix:

- Split the GSO/offload counters by direction and rewrite stage.
- Bumped the BPF map ABI to `4`.
- Kept cgo disabled for the Go binary build.
- Added `PersistentKeepalive = 5s` to both sides of the public/NAT regression setup.
- Re-tested on the Ubuntu development machine and the public/NAT host pair.

The public/NAT host pair was used only with built binaries and temporary test config/scripts. Source code was not copied to those endpoints.

## Implementation Changes

### GSO counters

Replaced the single `gso_seen` stat with more specific counters:

```text
egress_gso_seen
egress_gso_managed_seen
egress_gso_rewrite_ok
ingress_gso_seen
ingress_gso_listener_hit
ingress_gso_rewrite_ok
```

This makes status output more useful when debugging whether offload-shaped skbs were seen before parsing, matched as managed traffic, or successfully rewritten.

### Checksum helper flags

The type-word write path now keeps store flags separate from checksum helper behavior:

- `bpf_skb_store_bytes()` only receives store-compatible flags such as `BPF_F_INVALIDATE_HASH` and, on egress, `BPF_F_RECOMPUTE_CSUM`.
- `bpf_l4_csum_replace()` is used on ingress with the payload diff and no store-only flags.

This avoids passing IPv6-specific checksum flags to `bpf_skb_store_bytes()`.

## Ubuntu Development Machine Validation

Host:

```text
192.168.10.28
```

Commands completed successfully:

```text
go test ./...
make GO=/usr/local/go/bin/go build
sudo ./bin/wg-mix-ebpf bpf-load-test
sudo env GO=/usr/local/go/bin/go OUTER_FAMILY=ipv4 make test-netns-smoke
sudo env GO=/usr/local/go/bin/go OUTER_FAMILY=ipv6 make test-netns-smoke
```

IPv4 netns smoke:

```text
mixed initiation=2
mixed response=2
mixed transport=10
standard initiation/response/transport=0
```

IPv6 netns smoke:

```text
mixed initiation=3
mixed response=2
mixed transport=16
standard initiation/response/transport=0
```

Both IPv4 and IPv6 netns runs completed WireGuard handshake and ping through the tunnel. The pcap checker still reports invalid UDP checksums in the router-side veth captures. This is treated as a capture/checksum-offload artifact for IPv4 and as a known limitation for the current two-sided IPv6 transparent transform until a receiver-side real IPv6 environment is available.

## Public/NAT Regression

Hosts:

```text
public: 47.116.202.155
nat:    172.16.8.134
port:   52000
tunnel: 10.191.65.1/32 peer 10.191.65.2/32
```

The test flow was adjusted to avoid baseline handshake state contaminating eBPF evidence:

```text
1. Create both WireGuard interfaces.
2. Remove peers.
3. Load eBPF dataplane.
4. Start tcpdump on both endpoints.
5. Add peers back with persistent keepalive on both sides.
6. Run NAT -> public ping.
7. Run public -> NAT ping.
8. Collect status, wg show, and pcaps.
9. Cleanup both endpoints.
```

Public-side peer setup now includes:

```text
persistent-keepalive 5
```

NAT-side peer setup already used:

```text
persistent-keepalive 5
```

Latest eBPF-only result with the current binary:

```text
NAT -> public: 8/8 received, 0% loss, avg RTT 8.806 ms
public -> NAT: 8/8 received, 0% loss, avg RTT 8.733 ms
```

Dataplane stats:

```text
nat:
  egress_rewrite_ok=18
  ingress_rewrite_ok=20
  egress_rule_miss=0
  checksum_error=0
  skb_load_error=0
  skb_store_error=0
  egress_gso_seen=148
  ingress_gso_seen=4

public:
  egress_rewrite_ok=19
  ingress_rewrite_ok=18
  egress_rule_miss=0
  checksum_error=0
  skb_load_error=0
  skb_store_error=0
  egress_gso_seen=141
  ingress_gso_seen=4
```

Pcap checks:

```text
public capture:
  mixed initiation=1
  mixed response=1
  mixed transport=35
  standard type_words=0

nat capture:
  mixed initiation=1
  mixed response=1
  mixed transport=35
  standard type_words=0
```

TX-side packets still show invalid UDP checksums in tcpdump while receive-side packets show valid checksums. This matches the expected TX checksum offload capture behavior. Dataplane `checksum_error`, `skb_load_error`, and `skb_store_error` stayed at zero.

## Baseline Note

The standard WireGuard baseline between `172.16.8.134` and `47.116.202.155` is environment-dependent. In some runs it handshakes; in others the public endpoint does not learn the NAT-side endpoint in time. Treat it as an environment reference only, not as a hard implementation gate.

## Cleanup

After the final public/NAT run:

- Deleted temporary `wme0` interfaces.
- Detached TC/eBPF programs.
- Removed `/sys/fs/bpf/wg-mix-ebpf`.
- Removed `/tmp/wme-public-test`.
- Removed temporary uploaded binaries and scripts.

## Remaining Work

- Real IPv6 underlay testing on separate machines is still pending.
- Fragment and IPv6 extension-header managed/unmanaged tests are still pending.
- OpenWrt PPPoE/VLAN/underlay-overlap tests are still pending.
