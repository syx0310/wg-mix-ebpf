# Final Control-Plane Hardening Real-Host Validation

## Scope

Validated the stop/detach/attach-state hardening on controlled real hosts after implementing the required P0/P1 fixes.

Hosts:

- Build host: `192.168.10.28`, Ubuntu x86_64.
- Public host: `47.116.202.155`, Ubuntu x86_64, underlay `eth0`, WireGuard UDP `52000`.
- NAT host: `172.16.8.134`, Debian x86_64, underlay `eth0`, WireGuard UDP `52000`.
- OpenWrt host: `10.191.3.3`, x86_64, underlay `br-lan`.

No source code was copied to public/NAT/OpenWrt endpoints. Only the Linux amd64 binary, temporary configs, temporary keys, helper scripts, and pcaps were placed under `/tmp/wme-final-realhost` and removed after validation.

## Build Host

On `192.168.10.28`:

```text
go test ./...: pass
make build-linux-amd64: pass
bpf-load-test: pass
scripts/smoke-netns-wg.sh: pass
```

Linux amd64 binary:

```text
sha256: 1446a2ebbe59cff97a8d937848e3dc2a2681ab5bf3588ad1e2e20b22aa32d763
```

Netns smoke summary:

```text
mixed_type_words=14
standard_type_words=0
mixed initiation=2 response=2 transport=10
```

## NAT To Public eBPF Validation

Clean sequence:

```text
1. Create temporary wme0 on public and NAT hosts.
2. Reload wg-mix-ebpf on both sides before adding peers.
3. Add peers with PersistentKeepalive=5 on NAT side.
4. Run bidirectional ping and capture public-side UDP/52000 traffic.
```

Result:

```text
NAT -> public ping: 6/6 received, avg 8.583 ms
Public -> NAT ping: 6/6 received, avg 8.669 ms
```

Public-side pcap checker:

```text
udp_packets=24
mixed_type_words=24
standard_type_words=0
mixed transport=24
udp_checksum_valid=12
udp_checksum_invalid=12
```

The checksum-invalid half is public TX-side capture with checksum offload. Runtime status counters on both endpoints had zero `checksum_error`, `skb_load_error`, and `skb_store_error`.

## OpenWrt To Public eBPF Validation

OpenWrt to public temporary `wmeop` was validated using underlay `br-lan` on OpenWrt and `eth0` on public.

Result:

```text
OpenWrt -> public ping: 6/6 received, avg 6.820 ms
```

Public-side pcap checker output from the run:

```text
udp_packets=16
mixed_type_words=16
standard_type_words=0
mixed initiation=3
mixed transport=13
udp_checksum_valid=10
udp_checksum_invalid=6
```

The OpenWrt rerun pcap file was not retained locally because the first pull step used the wrong direction. The pcap checker output is retained in the verification logs. The NAT/public rerun includes both raw pcap and checker output.

## Control-Plane Checks

### Config Change Policy

A daemon was started on the public host, then its config file was edited while the daemon was running.

Observed daemon status:

```text
daemon-status-initial.json active None None
daemon-status-config-changed.json config_changed True config file changed; run wg-mix-ebpf reload or systemctl reload wg-mix-ebpf to apply
```

This confirms that poll/runtime handling no longer auto-applies config file content changes.

### Reload Config-Path Guard

A reload request was sent to the running daemon with a different `--config` path.

Result:

```text
expected-fail
daemon is running with config daemon-agent.yaml, refusing reload request for /tmp/wme-final-realhost/not-this-config.yaml
```

### Stop After WireGuard Deletion

On the public host, dataplane was loaded, a startup guard was applied, the WireGuard interface was deleted first, and then `wg-mix-ebpf stop` was run.

Result:

```text
dataplane detached
tc_ingress_wg_mix=0
tc_egress_wg_mix=0
pins_after=0
guard_after=removed
```

This validates attach-state based cleanup when the WireGuard runtime device no longer exists, and verifies that `stop` removes the nft startup guard.

## Cleanup

After validation:

- Removed temporary `wme0` and `wmeop` interfaces.
- Removed this agent's `wg_mix_*` TC filters by exact priority/handle.
- Removed `/sys/fs/bpf/wme-final-*` pin trees.
- Removed the nft startup guard table.
- Removed `/tmp/wme-final-realhost` from all test hosts.

Final verification showed no temporary interfaces, no `wg_mix_*` TC filters, and no `wme-final-*` BPF pins on public/NAT/OpenWrt hosts.

## Remaining Work

- Add rtnetlink watcher for lower-latency runtime reconcile.
- Add `doctor --deep` for real BPF/TC/nft probes.
- Add status inspection for nft guard table presence.
- Extend OpenWrt path-overlap detection beyond same-ifindex checks.
- Add a retained OpenWrt raw pcap artifact in the next verification cycle.
