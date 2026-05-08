# 2026-05-08 Offload Checksum Fix

## Scope

Validated and fixed the TC/eBPF dataplane against the public/NAT test pair:

- Public endpoint: `47.116.202.155`, underlay `eth0`, WireGuard UDP port `52000`.
- NAT-side endpoint: `172.16.8.134`, underlay `eth0`, WireGuard UDP port `52000`.
- Tunnel addresses: `10.191.65.1/32 peer 10.191.65.2/32`.
- Build host: `192.168.10.28`.

Only the built Linux amd64 binary and temporary test scripts/configs were copied to the test hosts. Source was not copied to the two test endpoints.

## Fixes

Changed BPF dataplane behavior:

- Removed the requirement that the WireGuard payload type word must be in the direct-access linear skb area.
- Kept `bpf_skb_load_bytes()` / `bpf_skb_store_bytes()` for the type-word read/write path so non-linear skb layouts can be handled by helpers.
- Added stats counters for `skb_load_error`, `skb_store_error`, and `gso_seen`.
- Added `BPF_F_INVALIDATE_HASH` for payload writes.
- Split checksum update strategy:
  - egress uses `bpf_skb_store_bytes(..., BPF_F_RECOMPUTE_CSUM)` to handle TX checksum offload / CHECKSUM_PARTIAL safely.
  - ingress uses explicit `bpf_l4_csum_replace()` because received packets have complete checksums and must be corrected before the standard WireGuard stack sees them.
  - IPv6 manual checksum path sets `BPF_F_IPV6`.

## Build Validation

On local macOS workspace:

```text
go test ./... passed
```

On Ubuntu build host `192.168.10.28`:

```text
go test ./... passed
make build-linux-amd64 passed
sudo ./bin/wg-mix-ebpf-linux-amd64 bpf-load-test passed
```

## Public Internet Validation

Baseline standard WireGuard without eBPF still failed, matching earlier observations:

```text
NAT -> public: 5/5 lost
NAT wg show: transmitted, 0 B received
public tcpdump: no UDP/52000 packets captured during baseline window
```

### eBPF, offload on

Both hosts had checksum/GSO/GRO enabled.

NAT -> public:

```text
8 packets transmitted, 8 received, 0% packet loss
rtt avg 9.195 ms
```

Public -> NAT:

```text
8 packets transmitted, 8 received, 0% packet loss
rtt avg 8.930 ms
```

Stats after offload-on run:

```text
nat:
  egress_rewrite_ok=8
  ingress_rewrite_ok=8
  gso_seen=16
  checksum_error=0
  skb_load_error=0
  skb_store_error=0

public:
  egress_rewrite_ok=17
  ingress_rewrite_ok=18
  gso_seen=24
  checksum_error=0
  skb_load_error=0
  skb_store_error=0
```

The non-zero `gso_seen` counters confirm the run covered GSO/offload-shaped skbs.

### eBPF, offload off regression

After disabling TX/GSO/GRO on the public side and TX/RX/GSO/GRO on the NAT side, the tunnel still worked. One NAT-to-public run showed initial transient loss after interface recreation, but public-to-NAT was clean and both dataplanes reported successful ingress/egress rewrites with no checksum/load/store errors.

## Evidence

Local evidence archive directory:

```text
/tmp/wme-current-results
```

Final host evidence archives:

```text
/tmp/wme-current-results/final-public.tgz
/tmp/wme-current-results/final-nat.tgz
```

## Cleanup

After testing, both endpoints were cleaned:

- Detached eBPF dataplane.
- Deleted temporary `wme0` WireGuard interfaces.
- Removed `/sys/fs/bpf/wg-mix-ebpf`.
- Removed `/tmp/wme-public-test`.
- Removed temporary uploaded binary and scripts.
- Restored NAT-side offload flags to on.
