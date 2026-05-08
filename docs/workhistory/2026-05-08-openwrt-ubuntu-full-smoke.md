# 2026-05-08 OpenWrt/Ubuntu full smoke validation

## Scope

Validated the transparent WireGuard `type_word` transform after adding a reusable pcap checker. The remote validation used:

- OpenWrt x86 endpoint: `10.191.3.3`, underlay `br-lan`.
- Ubuntu x86 endpoint: `192.168.10.28`, underlay `ens33`, public endpoint `dxhy.siyx.net:52000`.
- WireGuard tunnel address range: `10.191.65.0/30`.
- Modes: raw `ip link + wg setconf`, official `wg-quick`, and `wg-quick-op` with `PostUp = wg set %i fwmark ...`.

The 10.191.3.1 router node was kept read-only. Final pcap evidence uses the Ubuntu receive-side capture as the primary source because it provides valid checksums for OpenWrt-to-Ubuntu packets after NAT.

## Code changes

- Added `scripts/check-wg-pcap.py`, a dependency-free pcap checker for Ethernet/raw/SLL pcaps.
- The checker reports standard/mixed `type_word` counts, WireGuard packet-kind counts, length validation, IPv4 header checksum, and UDP checksum.
- Updated `scripts/smoke-netns-wg.sh` to require mixed initiation, response, and transport packets and to forbid standard `type_word` leakage.

## Local and Ubuntu VM tests

- `go test ./...`: pass locally.
- Ubuntu remote `go test ./...`: pass.
- Ubuntu remote `make GO=/usr/local/go/bin/go build-linux-amd64`: pass; BPF object embedded into Go binary.
- Ubuntu remote `sudo ./bin/wg-mix-ebpf-linux-amd64 bpf-load-test`: pass; embedded object loaded successfully.
- Ubuntu remote `make test-netns-smoke`: pass; pcap saw 28 mixed packets, 0 standard packets, with initiation/response/transport all present.

## OpenWrt/Ubuntu smoke results

All three modes completed handshake and transport. Ubuntu-to-OpenWrt ping succeeded with 0% loss in all modes. OpenWrt immediate ping also succeeded in the final run after a warmup delay and temporary OpenWrt test-interface firewall accept rules.

| Mode | OpenWrt -> Ubuntu pcap | Ubuntu -> OpenWrt pcap | Ubuntu ping | Notes |
| --- | --- | --- | --- | --- |
| raw | 16 mixed, 0 standard; initiation + transport; UDP checksum valid 16/16 | 16 mixed, 0 standard; response + transport | 4/4 | raw `wg setconf` |
| wg-quick | 15 mixed, 0 standard; initiation + transport; UDP checksum valid 15/15 | 14 mixed, 0 standard; response + transport | 4/4 | official `wg-quick` |
| wg-quick-op | 15 mixed, 0 standard; initiation + transport; UDP checksum valid 15/15 | 16 mixed, 0 standard; response + transport | 4/4 | `PostUp` fwmark applied by wg-quick-op |

The Ubuntu TX-side checksum fields still appear invalid in local tcpdump captures, while receive-side OpenWrt-to-Ubuntu checksums are valid. This matches TX checksum offload/partial checksum capture behavior rather than a BPF checksum update failure.

## Runtime status evidence

Final traffic-after status showed runtime `ListenPort` / `FirewallMark` were read correctly, maps were active, and counters incremented with no bad type:

- OpenWrt marks: `0x10005303`, ports `52101`, `52102`, `52103`.
- Ubuntu mark: `0x10005200`, port `52000`.
- `egress_rewrite_ok` and `ingress_rewrite_ok` incremented on both endpoints for each mode.
- `ingress_bad_type = 0` in the final runs.

## Cleanup

Remote cleanup removed test WireGuard interfaces, agent TC filters, `/tmp/wme-test`, `/sys/fs/bpf/wme-test`, and temporary OpenWrt bash. Empty `clsact` qdiscs were left in place deliberately because detach only deletes this agent's filters and must not remove qdiscs that could be shared with other TC users.

## Remaining gaps

This was still a smoke validation, not a full MVP release validation. Remaining release-level items include synthetic/real fragment tests, IPv6 extension-header tests, reload failure/generation rollback tests, startup guard crash-window tests, and OpenWrt VLAN/PPPoE/underlay-overlap matrix tests.
