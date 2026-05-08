# 2026-05-08 Public Internet Smoke

## Scope

- Public endpoint: `47.116.202.155`, underlay `eth0`, WireGuard listen port `52000`.
- NAT-side endpoint: `172.16.8.134`, underlay `eth0`, WireGuard listen port `52000`.
- Tunnel test addresses: `10.191.65.1/32 peer 10.191.65.2/32`.
- Build host: `192.168.10.28`; only the built binary and temporary test config were copied to test hosts.

## Baseline Standard WireGuard

Standard WireGuard without eBPF did not establish a tunnel.

Observed:

- NAT-side `wg show` reported repeated outbound transfer and `0 B received`.
- NAT-side `tcpdump` saw standard WireGuard initiation packets leaving `172.16.8.134:52000 -> 47.116.202.155:52000`.
- Public endpoint `tcpdump -i eth0 udp port 52000` saw no WireGuard initiation packets.
- A controlled UDP diagnostic from source port `52000` showed that raw UDP, standard `type_word`, and mixed `type_word` payloads could reach the public endpoint. This indicates the path is not simply dropping all UDP/52000 traffic or all standard-looking first four bytes.

## eBPF Transform

With eBPF enabled on both endpoints and NAT-side checksum/GSO/GRO offloads disabled for the test, the tunnel worked.

Clean rebuild sequence:

- Deleted both WireGuard interfaces.
- Detached eBPF and removed pinned maps.
- Recreated WireGuard interfaces.
- Loaded eBPF dataplane before setting the interfaces up.
- Captured traffic on both endpoints.

Results:

- NAT -> public ping: `8/8` received, `0%` packet loss, average RTT `10.436 ms`.
- Public -> NAT ping: `8/8` received, `0%` packet loss, average RTT `8.363 ms`.
- `wg show` on both endpoints reported recent handshakes and bidirectional transfer.
- `pcap.check` over clean captures reported:

```text
udp_packets=72
mixed_type_words=72
standard_type_words=0
mixed initiation=1
mixed response=1
mixed transport=70
standard initiation=0
standard response=0
standard transport=0
```

Stats after the clean run:

```text
public:
  egress_rewrite_ok=21
  ingress_rewrite_ok=19
  egress_rule_miss=0
  checksum_error=0

nat:
  egress_rewrite_ok=19
  ingress_rewrite_ok=21
  egress_rule_miss=0
  checksum_error=0
```

## Offload Finding

On `172.16.8.134`, the first eBPF attempt with TX/RX checksum offload and GSO/GRO enabled did not establish the tunnel. NAT-side captures showed mixed initiation packets leaving, but the public endpoint did not receive them. After disabling `tx`, `rx`, `tso`, `gso`, and `gro` with `ethtool -K eth0 ... off`, the same eBPF setup established the tunnel.

This should be tracked as a dataplane/offload compatibility issue. The positive smoke result is valid only with NAT-side offloads disabled.

## Cleanup

After testing:

- Removed WireGuard interfaces from both endpoints.
- Detached eBPF programs.
- Removed `/sys/fs/bpf/wg-mix-ebpf`.
- Removed `/tmp/wme-public-test`.
- Restored NAT-side offloads as far as `ethtool` allowed.

Local evidence directory:

```text
/tmp/wme-public-results
```
