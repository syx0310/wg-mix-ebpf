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

## Artifact Identity

Packaged builds expose their identity without reading Git or the build host at
runtime:

```bash
wg-mix-ebpf version --json
```

The JSON contains the userspace version, source commit, BPF ABI version, and
SHA-256 of the exact `wg_mix_tc.o` bytes embedded in that executable. `status`
reports the querying executable under `client_build`. A running daemon records
its own immutable startup identity under `daemon.build`, so replacing the
on-disk CLI cannot make an older daemon appear to run the newer artifact.

`make build` and both `build-linux-*` targets inject `HEAD` only when the
worktree is clean and Git returns a canonical 40-character lowercase commit.
A dirty worktree, missing Git metadata, or invalid output produces
`"source_commit": "unknown"`; the default userspace version remains `"dev"`.
The commit value is not accepted from the environment or Make command line,
and identity discovery uses the fixed system Git with a minimal environment.
The Go build clears inherited `GOFLAGS`, disables `GOENV` and `GOWORK`, uses
the checked-in module in read-only mode, and disables ambient VCS stamping.
The selected Go/Clang toolchain binaries and installed headers remain trusted
build inputs; their versions should be recorded with release evidence.

For a load-only verifier check, deterministic machine-readable output is also
available:

```bash
wg-mix-ebpf bpf-load-test --json
wg-mix-ebpf bpf-load-test --object /path/to/wg_mix_tc.o --json
```

The `object.sha256` value is calculated from the same byte slice passed to the
ELF parser. For an override, it therefore identifies the exact object that was
loaded rather than the object path alone.

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
gofmt, go vet, Bash syntax, and Python syntax checks
go test -race ./...
make build-linux-amd64
make build-linux-arm64
offline config validation
amd64 tar.gz artifact packaging
```

The normal build and release binary use `CGO_ENABLED=0`. The
`test-unit-race` target explicitly sets `CGO_ENABLED=1` because Go's race
detector requires cgo on Linux; this is a test-only setting and does not affect
the packaged binary.

The public CI intentionally does not run live TC attach, WireGuard, OpenWrt, PPPoE, VLAN, or public-internet tests. Those tests require controlled external machines and should be run in a private lab.

Every supported kernel baseline must run `bpf-load-test`; compiling the object
does not prove that an older verifier will accept all program paths. The
controlled kernel matrix currently needs at least Linux 5.15 and 6.8.

## Release Packaging

The amd64 CI artifact contains:

```text
wg-mix-ebpf
README.md
configs/
```

The binary already includes the BPF object. There is no separate `.o` file required on target machines for normal use.
