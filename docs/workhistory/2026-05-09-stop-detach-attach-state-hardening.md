# Stop / Detach / Attach-State Hardening

Implemented the next round of control-plane hardening from review feedback.

## Changes

- Added persistent attach metadata at `/var/lib/wg-mix-ebpf/attach-state.json`.
- `reload` writes attach-state after successful dataplane apply.
- `reload` compares previous attach-state with current desired underlays and detaches stale ifindexes that disappeared or changed.
- `detach` now prefers attach-state and no longer depends on the WireGuard runtime interface still existing.
- `stop` now performs dataplane detach plus startup guard cleanup, and daemon SIGTERM/SIGINT uses the same path.
- Manual `reload` / `stop` requests sent to a running daemon now reject mismatched `--config` paths.
- Daemon poll treats config content changes as operator-controlled: it records `config_changed` / `need_reload` instead of automatically applying profile or underlay edits.
- `install` now treats `systemctl daemon-reload` failure as a hard install error.

## Validation

- Added unit tests for attach-state round-trip/stale selection.
- Added unit test for daemon config-path mismatch protection.
- Added reconcile tests for stop dry-run and empty detach-state behavior.
- `go test ./...` passed locally.

## Remaining Work

- Add rtnetlink event watcher for lower-latency runtime reconcile.
- Add `doctor --deep` for real BPF/TC/nft probes.
- Add status inspection for whether the nft guard table currently exists.
- Extend OpenWrt underlay path-overlap detection beyond same-ifindex checks.
