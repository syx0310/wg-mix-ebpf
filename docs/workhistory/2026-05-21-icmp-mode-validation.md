# 2026-05-21 ICMP Mode Implementation And Validation

## Summary

Implemented experimental IPv4 ICMP Echo transport mode for the transparent type-word dataplane. fakeTCP remains intentionally unimplemented.

The ICMP mode keeps the WireGuard payload transform unchanged and converts the fixed 8-byte outer UDP header to an 8-byte ICMP Echo header on IPv4. It supports:

- client role: UDP -> Echo Request, Echo Reply -> UDP
- server role: Echo Request -> UDP, UDP -> Echo Reply
- generation-scoped ICMP listener rules
- runtime ICMP sequence preservation for NATs that rewrite Echo sequence values

## Dev28 Validation

Environment: dev28 Linux amd64.

Passed:

- `make build-bpf`
- `go test ./...`
- `make build-linux-amd64`
- `bpf-load-test`
- existing UDP netns smoke
- ICMP netns smoke

ICMP netns smoke evidence:

```text
ping A -> B: 3/3 received
ping B -> A: 3/3 received
icmp_mixed_type_words=32
icmp_standard_type_words=0
icmp_egress_rewrite_ok=8
icmp_ingress_rewrite_ok=8
```

Performance comparison used the existing netns benchmark with `iperf3 -M 1200` to avoid the MVP unsupported outer fragmentation/GSO path:

```text
mode    Mbps    retransmits  ping_ms
native  889.97  0            0.445
udp     821.70  0            0.404
icmp    780.15  0            0.390
```

Additional udp2raw comparison on the same dev28 netns topology used udp2raw commit `4208db6` and `--raw-mode icmp`. The benchmark kept the same `iperf3 -M 1200` constraint so the result compares transport overhead instead of unsupported outer fragmentation behavior:

```text
mode                  Mbps    retransmits  ping_ms
native                866.72  0            0.455
ebpf-udp              815.71  0            0.401
ebpf-icmp             771.04  0            0.442
udp2raw-icmp-none     331.20  221          0.769
udp2raw-icmp-default  205.10  325          0.805
```

`udp2raw-icmp-none` used `--cipher-mode none --auth-mode none`; `udp2raw-icmp-default` used udp2raw defaults. The result shows the in-kernel ICMP transport path is substantially faster than a user-space udp2raw tunnel in this test setup.

## Public/NAT Validation

Endpoints:

- NAT side: `172.16.8.134`
- public side: `47.116.202.155`
- WG test subnet: `10.191.65.0/30`
- public WG port: `52000`

Baseline standard WireGuard:

```text
NAT -> public ping: 4 transmitted, 0 received, 100% loss
```

ICMP mode:

```text
NAT -> public ping: 4 transmitted, 4 received, 0% loss
public -> NAT ping: 4 transmitted, 4 received, 0% loss
```

Observed behavior:

- public side received ICMP Echo Request and emitted Echo Reply
- NAT rewrote the Echo sequence to `65535`
- server-side BPF recorded and reused the rewritten sequence
- WireGuard latest-handshake appeared on both sides
- both dataplanes showed ICMP ingress/egress rewrite counters increasing

Temporary interfaces, BPF pins, scripts, and binaries were removed from both public/NAT endpoints after validation.

## Remaining Limitations

- ICMP mode is IPv4 only.
- ICMPv6 is not implemented.
- fakeTCP/fakeTCP-lite are reserved and rejected by config validation.
- Outer fragmentation remains unsupported.
- Large-packet ICMP checksum handling uses a UDP-checksum-derived fast path and still needs broader offload/NIC matrix validation.
