# 2026-05-07 OpenWrt Dataplane Validation

## Code Changes

- Hardened config defaults so explicit `false` values for runtime booleans are preserved.
- Rejected reserved `fwmark_policy` modes during static validation instead of half-accepting unsupported modes.
- Added runtime interface ifindex discovery from `wgctrl` device names.
- Implemented OpenWrt `openwrt-interface` underlay resolution through `ifstatus`.
- Added duplicate ingress/egress rule validation to prevent silent map entry overwrite.
- Changed nft startup guard cleanup/setup to use `destroy table` so first-run cleanup does not fail when the table is absent.
- Reworked TC BPF parsing to avoid first-byte L3 guessing, support Ethernet/VLAN plus L3-ish devices through `skb->protocol`, and parse bounded IPv6 extension headers.
- Adjusted ingress fragment/IPv6 extension handling so unmanaged packets pass, while packets matching a managed listener fail closed.
- Switched TC filter update from delete-before-add to `FilterReplace`, then removing duplicate filters owned by this agent.
- Added `/refs/` to `.gitignore` for new reference files.

## Validation

- Local: `CGO_ENABLED=0 go test ./...` passed.
- Local: Linux amd64 cross-build passed.
- Ubuntu dev host: `make test-unit`, `make build`, `make build-bpf`, BPF load test, and netns WireGuard smoke passed.
- Netns smoke pcap summary: 28 mixed `type_word` packets, 0 standard `type_word` leaks.
- OpenWrt 3.3 x86: installed minimal runtime dependencies needed for WireGuard and TC/BPF, then BPF object load test passed.
- OpenWrt 3.3 x86 to Ubuntu dev host: temporary `wme0` with `Table = off` config stubs and `10.191.65.0/30` addresses passed 3.3 -> dev host WireGuard ping, 4/4 replies.
- OpenWrt 3.1 router: only read-only capture/status commands were used. WAN-side tcpdump showed mixed `type_word` values including `6b f0 df 13` and `e6 c2 58 f6` on the WireGuard UDP payload prefix.
- Reverse ping from dev host to OpenWrt 3.3 was blocked by OpenWrt firewall on the temporary interface and was not forced open to keep the test footprint small.

## Cleanup

- Detached dataplane programs on the Ubuntu dev host and OpenWrt 3.3.
- Deleted temporary `wme0` interfaces and `/tmp/wme-test` directories on both writable test hosts.
- Removed local temporary capture/transfer artifacts.
- Left installed OpenWrt packages on 3.3 because they are the minimal dependencies for future WG/TC/BPF validation.
