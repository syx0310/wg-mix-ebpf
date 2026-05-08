# 2026-05-08 Generation Key Reload Hardening

## Summary

- Bumped the dataplane ABI to v3.
- Added `generation` to profile, underlay, managed fwmark, egress rule, and ingress listener map keys.
- Kept map values tagged with `generation` as a consistency check.
- Updated BPF lookups to read `control_map.active_generation` first, then include that generation in each dataplane map lookup.
- Increased dataplane map capacities so active and next generations can coexist during reload.
- Added prepare-time cleanup for stale entries from the target next generation before writing a new snapshot.
- Rejected `runtime.allow_zero_fwmark_fallback` in MVP configuration validation.
- Synchronized docs and example config so managed ingress IPv6 extension-header policy is `drop`.

## Rationale

Using generation only in map values was not enough for atomic reload. A reload could overwrite active-generation entries with next-generation values before `control_map.active_generation` was committed, temporarily making active rules invisible. Moving generation into keys lets old and new generations coexist until commit.

## Deferred

- Fragment / IPv6 extension-header managed-versus-unmanaged packet tests.
- OpenWrt PPPoE, VLAN, and `openwrt-interface` real underlay matrix tests.
- Historical attach-state cleanup for underlays removed from the current config.
