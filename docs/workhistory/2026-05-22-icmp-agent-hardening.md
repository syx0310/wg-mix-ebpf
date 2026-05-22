# 2026-05-22 ICMP Agent Hardening

## Summary

Integrated the parallel agent fixes for ICMP transport hardening and regression coverage.

## Changes

- Added UDP ingress drop listeners for ICMP-managed WireGuard listen ports to prevent raw UDP bypass.
- Added explicit ICMP wildcard-listener flags so server-side wildcard ID matching does not accidentally apply to exact client listeners.
- Allowed ordinary non-WireGuard ICMP Echo traffic to pass the wildcard server listener when it fails only mixed type-word or WireGuard length checks.
- Hardened ICMP sequence state keys with generation, underlay ifindex, WireGuard interface id, remote IPv4, and ICMP id.
- Added ICMP checksum/store/load observability for the rewritten dataplane path.
- Extended the pcap checker with ICMP Echo parsing and checksum validation.
- Added an ICMP netns smoke script with optional enforced negative checks for ordinary ping pass-through and raw UDP bypass blocking.
- Documented current ICMP mode limitations and regression entry points.

## Validation

Local:

```text
git diff --check
go test ./internal/control ./internal/abi ./internal/config
```

dev28:

```text
make build-bpf
go test ./...
make build-linux-amd64
WG_MIX_EBPF_OBJECT=$PWD/build/wg_mix_tc.o ./bin/wg-mix-ebpf-linux-amd64 bpf-load-test
make test-netns-smoke
make test-netns-icmp-smoke
NEGATIVE_CHECKS=enforce scripts/smoke-netns-icmp.sh
```

Results:

- UDP netns smoke: mixed initiation/response/transport observed, standard type_word count 0.
- ICMP netns smoke: Echo Request/Reply observed, mixed initiation/response/transport observed, standard type_word count 0, ICMP checksum valid.
- ICMP negative checks: ordinary underlay ping to wildcard ICMP listener passed; raw UDP WireGuard did not increase server receive bytes.
