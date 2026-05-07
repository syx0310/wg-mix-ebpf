# 2026-05-07 Netns WireGuard Smoke

## Summary

Added and ran a single-machine Linux smoke test using temporary network namespaces:

```text
nsA <-> nsR <-> nsB
```

The test creates temporary veth links and temporary `wg0` interfaces in `nsA` and `nsB`, attaches `wg-mix-ebpf` only to the temporary underlay veth devices, captures packets in `nsR`, and validates that on-wire WireGuard UDP payloads use mixed `type_word` values.

## Verification

Run on the Ubuntu development machine under `~/codes/wg-mix-ebpf`:

```bash
make build build-bpf
sudo -E scripts/smoke-netns-wg.sh
```

Result:

```text
dataplane reloaded
dataplane reloaded
pcap_udp_payload_words=28 mixed_type_words=28 standard_type_words=0
netns WireGuard + eBPF smoke passed
```

Post-test namespace check:

```text
post_netns=
```

## Cleanup Scope

The script uses unique `wme*` namespace names, temporary files under `/tmp`, and a trap that detaches the agent and deletes all test namespaces. It does not touch host WireGuard configuration or host underlay interfaces.
