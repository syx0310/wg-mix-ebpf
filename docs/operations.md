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

It does not update dataplane maps for peer endpoint, handshake time, transfer counter, or DDNS changes.

## Reload

Manual reload uses the same reconcile path as the daemon:

```bash
sudo wg-mix-ebpf reload
```

If the daemon is running, `reload` writes a reload request and waits for daemon reconcile. If the daemon is not running, it performs a one-shot reconcile.

Reload uses generation-scoped maps. New entries are prepared under a new generation, then `active_generation` is committed, and stale generations are cleaned afterward.

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
startup guard status
dataplane counters
last reconcile result
```

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

## Uninstall

Default uninstall removes network-impacting state but keeps configuration:

```bash
sudo wg-mix-ebpf uninstall
```

It stops the service, detaches this agent's TC filters, removes BPF pins, removes the nft guard table, removes runtime/state/service files, and leaves `/etc/wg-mix-ebpf/config.yaml` in place.

To remove the config directory too:

```bash
sudo wg-mix-ebpf uninstall --purge
```

The binary and WireGuard configuration are not deleted by either form.
