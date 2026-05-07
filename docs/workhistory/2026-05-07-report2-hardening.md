# 2026-05-07 Report2 Hardening

## Changes

- Changed managed ingress/egress profile-map misses from pass/fallback to drop after a managed rule has already matched.
- Added an `underlay_config_map` ABI entry and BPF parser modes so each underlay can use `auto`, `ethernet`, or `l3` parsing.
- Added `underlays[].parser` config support and automatic parser inference from Linux netlink link type.
- Bumped BPF/control ABI to version 2.
- Rejected policy values that are not actually implemented by the MVP dataplane, removing misleading configurable behavior.
- Wired `reload` into the startup guard lifecycle: apply nft guard before attach and cleanup after successful attach; leave guard in place on attach failure.
- Added dataplane status inspection for actual TC filter presence on managed underlays.
- Expanded feature probe output with bpffs, BPF JIT, unprivileged BPF, and common TC/BPF module visibility.
- Updated the test plan to require raw `wg/ip`, official `wg-quick`, and `wg-quick-op` startup paths in future external tests.

## Validation

- Local `CGO_ENABLED=0 go test ./...` passed.
- Local Linux amd64 cross-build passed.
- Remote Ubuntu dev host `make test-unit`, `make build`, `make build-bpf`, BPF load test, and netns WireGuard smoke passed.
- Netns pcap summary remained `mixed_type_words=28` and `standard_type_words=0`.
