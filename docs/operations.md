# Operations

This document describes the intended operational flow for `wg-mix-ebpf`.

## Command Model

The normal user-facing commands are:

```text
doctor
install
init
profile
reload
status
stop
uninstall
```

`run` is the daemon entrypoint used by systemd or OpenWrt procd. It is available as a command, but users normally interact with it through the service manager.

## Install

`install` only installs files and service definitions:

```bash
sudo wg-mix-ebpf install
```

It does not start the service, enable boot startup, attach TC filters, reload dataplane state, or modify WireGuard configuration.

To enable the service without starting it:

```bash
sudo wg-mix-ebpf install --enable
```

Start explicitly:

```bash
sudo systemctl start wg-mix-ebpf
```

On OpenWrt:

```bash
/etc/init.d/wg-mix-ebpf start
```

## Init

`init` creates or updates `/etc/wg-mix-ebpf/config.yaml`. It can create or import a profile and bind WireGuard interfaces to underlays:

```bash
sudo wg-mix-ebpf init \
  --wg wg0 \
  --underlay eth0:netdev \
  --profile home \
  --profile-preset wireguard-mix-wire-values-v1
```

For a matching endpoint profile:

```bash
sudo wg-mix-ebpf profile token home
sudo wg-mix-ebpf profile check 'wgmix1....'
sudo wg-mix-ebpf init --wg wg0 --underlay eth0:netdev --profile-token 'wgmix1....'
```

`init` reads the expected `FwMark` from the WireGuard config or supported `PostUp = wg set %i fwmark ...` command. It does not add or change `FwMark`, `ListenPort`, peers, routes, or addresses.

## Daemon Reconcile

The daemon performs startup reconcile, poll reconcile, and reload-request handling:

```bash
sudo wg-mix-ebpf run --config /etc/wg-mix-ebpf/config.yaml
```

The reconcile loop reloads dataplane state when local runtime inputs change:

```text
WireGuard runtime ListenPort
WireGuard runtime FirewallMark
WireGuard interface presence/state
underlay ifindex/link state
OpenWrt hotplug reload request
manual reload request
```

Config file changes are not applied automatically by the low-frequency poll loop. When the daemon notices a config content change during poll/runtime handling, it reports `config_changed` and `need_reload` in status. Apply config changes explicitly:

```bash
sudo wg-mix-ebpf reload
```

This keeps runtime changes automatic while making profile and underlay edits operator-controlled.

It does not update dataplane maps for peer endpoint, handshake time, transfer counter, or DDNS changes.

## Reload

Manual reload uses the same reconcile path as the daemon:

```bash
sudo wg-mix-ebpf reload
```

If the daemon is running, `reload` writes a reload request and waits for daemon reconcile. If the daemon is not running, it performs a one-shot reconcile.

Reload uses generation-scoped maps. New entries are prepared under a new generation, then `active_generation` is committed, and stale generations are cleaned afterward.

Reload and detach operations are serialized with a file lock under the runtime directory. This prevents daemon reconcile, manual reload, manual detach, service stop, and uninstall cleanup from racing with each other.

## Status

`status` reports config, runtime, attach, generation, and stats state:

```bash
wg-mix-ebpf status
```

Important fields:

```text
active_generation
runtime ListenPort
runtime FirewallMark
underlay ifindex/link type/parser
TC ingress/egress attach state
dataplane counters
last reconcile result
```

`status` reads desired state and pinned dataplane state. It does not currently inspect the nft startup guard table directly; if a guard table is suspected to be left behind, run `guard-cleanup` or inspect nftables manually.

## Stop And Detach

Stopping the service detaches this agent's TC filters:

```bash
sudo systemctl stop wg-mix-ebpf
```

OpenWrt:

```bash
/etc/init.d/wg-mix-ebpf stop
```

If WireGuard continues running after service stop, it may send standard WireGuard type words because the transparent transform is no longer attached.

Service stop calls:

```bash
wg-mix-ebpf stop --config /etc/wg-mix-ebpf/config.yaml
```

When the daemon is alive, `stop` requests the daemon to stop polling, detach dataplane under the shared lock, remove the nft startup guard table, write stopped status, and exit. If the daemon is not alive, `stop` falls back to one-shot stop cleanup.

Dataplane cleanup uses `/var/lib/wg-mix-ebpf/attach-state.json` when available. This lets `stop`, `detach`, and `uninstall` remove TC filters even if the WireGuard interface was already stopped or deleted.

## Uninstall

Default uninstall removes network-impacting state but keeps configuration:

```bash
sudo wg-mix-ebpf uninstall
```

It stops the service, detaches this agent's TC filters using attach-state when available, removes BPF pins, removes the nft guard table, removes runtime/state/service files, and leaves `/etc/wg-mix-ebpf/config.yaml` in place.

To remove the config directory too:

```bash
sudo wg-mix-ebpf uninstall --purge
```

The binary and WireGuard configuration are not deleted by either form.

`--purge` refuses custom config paths whose parent directory is not the owned config directory. For example, `--config /etc/wg-mix-ebpf.yaml --purge` is rejected rather than deleting `/etc`.

If the binary was installed manually, remove it manually after uninstall. If it was installed by a package manager, remove it with that package manager.
