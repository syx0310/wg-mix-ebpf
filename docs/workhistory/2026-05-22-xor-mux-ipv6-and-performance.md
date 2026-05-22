# 2026-05-22 XOR Mux IPv6 And Performance Validation

## IPv6 Failure

The IPv6 netns smoke failed before the fix with only initiation attempts and no
WireGuard response. Dataplane stats showed managed egress failing before any
rewrite reached the underlay pcap.

Root cause:

```text
bpf_l4_csum_replace(..., BPF_F_IPV6)
```

was being used for WireGuard UDP payload-only checksum diffs. In this dataplane
path the helper is used in diff mode for a payload change, not for a
pseudo-header change. Passing `BPF_F_IPV6` in this payload-only diff path
caused TC egress helper failures on dev28's IPv6 netns/veth path.

Fix:

```text
IPv4 egress:
  keep bpf_skb_store_bytes(..., BPF_F_RECOMPUTE_CSUM)

IPv6 egress:
  bpf_csum_diff(...)
  bpf_l4_csum_replace(..., flags=0)
  bpf_skb_store_bytes(..., BPF_F_INVALIDATE_HASH)

Ingress:
  same payload-diff checksum update path
```

The BPF stats now also split IPv6 UDP checksum-zero drops into
`ingress_bad_checksum` / `egress_bad_checksum` instead of grouping them under
IPv6 extension-header counters.

The BPF map ABI was bumped to `8` because `stats_map` gained two counter slots.

## Dev28 Regression

Host:

```text
192.168.10.28
```

Passed:

```text
go test ./...
make bpf-load-test
make test-netns-smoke
make test-netns-xor-smoke
OUTER_FAMILY=ipv6 make test-netns-smoke
OUTER_FAMILY=ipv6 make test-netns-xor-smoke
```

IPv6 type-word smoke:

```text
mixed initiation=2
mixed response=2
mixed transport=8
standard initiation/response/transport=0
```

IPv6 XOR smoke:

```text
xor_mixed initiation=2
xor_mixed response=2
xor_mixed transport=8
xor_standard initiation/response/transport=0
```

Router-side veth pcaps still show invalid UDP checksums because they are
captured on offload-shaped veth traffic. WireGuard handshake, transport, ping,
and dataplane zero-error stats are the acceptance signal for this netns target.

## Initial Full-Payload Performance Comparison

The dev28 benchmark used the same two-netns/veth topology and WireGuard
parameters for all modes:

```text
WireGuard inner IPs: 10.77.0.1/24 <-> 10.77.0.2/24
underlay: 192.0.2.1/24 <-> 192.0.2.2/24
WireGuard MTU: 1380
iperf3: TCP, 30s, 1 stream, MSS 1200, fq-rate 700M
udp2raw: --raw-mode udp --cipher-mode xor --auth-mode none --disable-bpf
```

Round 1:

```text
mode                    Mbps    retransmits  ping_avg_ms
native                  699.44  0            0.422
ebpf-udp                699.89  0            0.429
ebpf-xor                332.92  0            0.503
udp2raw-udp-xor-none    329.89  931          0.810
```

Round 2:

```text
mode                    Mbps    retransmits  ping_avg_ms
native                  699.83  0            0.361
ebpf-udp                699.94  0            0.448
ebpf-xor                336.42  0            0.440
udp2raw-udp-xor-none    328.16  1001         0.819
```

Interpretation before the checksum-diff accumulation optimization:

```text
ebpf-udp type-word-only overhead is negligible at the 700M paced test rate.
full-payload ebpf-xor and udp2raw UDP+xor+none were close in throughput in this topology.
udp2raw showed significantly more TCP retransmits in both rounds.
```

## XOR Length Matrix

The next benchmark kept the same topology and iperf settings, then varied the
XOR scope and `max_bytes`. These values are after the checksum-diff accumulation
optimization.

```text
mode                    Mbps    retransmits  ping_avg_ms
native                  699.96  0            0.549
ebpf-udp                699.92  0            0.428
xor-prefix-4            697.40  0            0.402
xor-prefix-16           699.93  0            0.506
xor-prefix-64           699.93  0            0.444
xor-prefix-128          699.94  0            0.448
xor-prefix-256          699.77  0            0.414
xor-prefix-512          576.90  0            0.465
xor-full-2048           378.40  0            0.691
udp2raw-udp-xor-none    339.39  1039         0.818
```

Result:

```text
prefix 4/16/64/128/256 stayed at or near the 700M paced ceiling.
prefix 512 dropped to about 577M.
full 2048 improved from about 334M to about 378M after checksum-diff accumulation.
udp2raw UDP+xor+none stayed around 339M and showed significant retransmits.
```

## Loop Optimization Attempts

The implemented loop optimization keeps the verifier-safe 16-byte chunk but
reduces manual checksum helper calls. For ingress and IPv6 egress, chunk
checksum diffs are accumulated with `bpf_csum_diff()` and applied with one final
`bpf_l4_csum_replace()` instead of one L4 checksum helper call per chunk.

Larger stack chunks were tested to reduce load/store helper calls:

```text
64-byte chunk:
  clang rejected the object because the inlined BPF stack exceeded 512 bytes.

32-byte chunk:
  compiled, but verifier hit the 1,000,001 processed instruction limit.

24-byte and 20-byte chunks:
  also hit the verifier instruction limit.

bounded outer loop:
  increased verifier path complexity and was rejected.
```

The safe operational optimization remains: use `wg-payload-prefix` and keep
`max_bytes` small. Documentation and example config now recommend `max_bytes:
128` for UDP XOR mode. A future implementation can revisit larger chunk sizes
with a per-CPU scratch map, but that should be a separate ABI/loader change and
needs its own verifier matrix.

## Follow-up Validation Changes

Config validation now rejects ICMP server mode when `transport.icmp.id` is
nonzero. Server mode intentionally uses a wildcard Echo id listener so NAT
rewrites of ICMP id can be tolerated; a configured nonzero id would imply exact
matching that the current server dataplane does not implement.

XOR defaults were normalized to:

```text
scope: wg-payload-prefix
max_bytes: 128
```

The docs explicitly call out that current XOR is not mux/multiplex, is only
implemented for UDP transport, and is rejected with ICMP or fakeTCP transport.
