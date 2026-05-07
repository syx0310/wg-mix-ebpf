# 2026-05-07 PostUp FwMark Compatibility

## Summary

- Added compatibility for WireGuard configs that set runtime fwmark through `PostUp = wg set %i fwmark <mark>`.
- This supports `wg-quick-op v0.4.1` style deployments where `[Interface] FwMark` is not accepted by the parser but `PostUp` hooks are supported.
- Commented `#PostUp` lines are ignored, matching actual config behavior.
- Explicit `[Interface] FwMark` remains the preferred source and takes precedence when present.

## Validation

- `CGO_ENABLED=0 go test ./...` passed.
- `git diff --check` passed.
