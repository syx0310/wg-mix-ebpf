# Build

This project ships one userspace Go binary with an embedded TC/eBPF object. Target machines do not need clang or kernel headers at runtime when using the packaged binary.

## Requirements

Build requirements on Linux:

```text
Go version from go.mod
clang
llvm
gcc
Linux UAPI headers, for example linux-libc-dev on Ubuntu
make
```

Runtime requirements on Linux:

```text
root privileges
WireGuard kernel support
BPF syscall support
TC clsact / sched_cls support
bpffs mounted at /sys/fs/bpf
nft, when startup_guard.mode is nft-temporary-drop
wg, when reading live WireGuard runtime state
```

## Local Build

Build the default binary for the current machine:

```bash
make build
```

Build the TC/eBPF object only:

```bash
make build-bpf
```

Build a Linux amd64 release-style binary:

```bash
make build-linux-amd64
```

Build a Linux arm64 binary from a suitable build host:

```bash
make build-linux-arm64
```

Both Linux binary targets run `prepare-embedded-bpf` first. That compiles:

```text
bpf/wg_mix_tc.c -> build/wg_mix_tc.o
```

and copies the object to:

```text
internal/dataplane/embedded/wg_mix_tc.o
```

The Go compiler embeds that object into the final binary. The runtime loader uses the embedded object unless an override is provided.

## Object Override

For development, override the embedded BPF object:

```bash
WG_MIX_EBPF_OBJECT=/path/to/wg_mix_tc.o wg-mix-ebpf bpf-load-test
```

or:

```bash
wg-mix-ebpf bpf-load-test --object /path/to/wg_mix_tc.o
```

`bpf-load-test` loads and closes the BPF collection. It does not attach TC filters, create network namespaces, read WireGuard runtime state, or send WireGuard traffic.

## CI Build

GitHub Actions currently runs a single native Linux amd64 job. It performs:

```text
go test ./...
go test -race ./...
make build-linux-amd64
offline config validation
amd64 tar.gz artifact packaging
```

The normal build and release binary use `CGO_ENABLED=0`. The race-test step explicitly sets `CGO_ENABLED=1` because Go's race detector requires cgo on Linux; this is a CI-only test setting and does not affect the packaged binary.

The public CI intentionally does not run live TC attach, WireGuard, OpenWrt, PPPoE, VLAN, or public-internet tests. Those tests require controlled external machines and should be run in a private lab.

## Release Packaging

The amd64 CI artifact contains:

```text
wg-mix-ebpf
README.md
configs/
```

The binary already includes the BPF object. There is no separate `.o` file required on target machines for normal use.
