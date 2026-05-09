# 2026-05-09 Control Plane, Daemon, And Profile Commands

Implemented the next control-plane layer for the minimal command design.

## Changes

- Added lenient config loading, config saving, and a safe idle template for install/init/profile workflows.
- Added profile random generation and `wgmix1.<payload>.<crc32>` token import/export/check support.
- Added `doctor`, `install`, `init`, `profile`, `run`, and `uninstall` commands while keeping existing validate/status/reload/guard commands.
- Added a shared `internal/reconcile` package so CLI and daemon use the same validate/reload/detach paths.
- Added a minimal daemon loop that writes `/run/wg-mix-ebpf/status.json`, polls, and handles `reload.request`.
- Added systemd/OpenWrt install helpers. `install` does not start or enable by default; `install --enable` enables only.
- Added uninstall planning/execution that keeps config by default and uses `--purge` for config removal.
- Updated docs for idle templates, profile commands, service semantics, and daemon reconcile behavior.

## Boundaries Preserved

- No WireGuard config mutation.
- No `wg set` or `wg syncconf` execution.
- No IP/UDP tuple rewrite.
- No peer endpoint in dataplane.
- `profile remove --force` only removes agent management entries; it does not modify WireGuard.

## Tests

- Local `go test ./...` passed on macOS.
- Linux BPF/load/netns validation still needs external Linux execution after syncing this change set.
