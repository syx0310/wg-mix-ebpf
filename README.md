# wg-mix-ebpf

Transparent WireGuard `type_word` transform using eBPF.

Current status: control-plane foundation, fixed map ABI, startup guard tooling, and Linux-only TC/eBPF loader source are implemented. BPF object build/load/TC attach tests must run on external Linux machines.

## Commands

```bash
wg-mix-ebpf validate --config configs/example.yaml --offline
wg-mix-ebpf status --config configs/example.yaml --offline
wg-mix-ebpf dump --config configs/example.yaml --offline
wg-mix-ebpf dump-abi --config configs/example.yaml --offline
wg-mix-ebpf guard-plan --config configs/example.yaml --offline
wg-mix-ebpf guard-apply --config configs/example.yaml --offline --dry-run
wg-mix-ebpf guard-cleanup --config configs/example.yaml --offline --dry-run
wg-mix-ebpf features
```

`--offline` skips runtime WireGuard and underlay reads. It is intended for local static validation and unit-test environments.

## Development

```bash
make test-unit
CGO_ENABLED=0 go build -o /tmp/wg-mix-ebpf ./cmd/wg-mix-ebpf
```

The default Makefile build and test targets use `CGO_ENABLED=0` for reproducible cross-platform builds.

## Linux Dataplane

The Go binary does not require cgo. The TC/eBPF program is compiled and embedded into the binary by the standard build targets:

```bash
make build-bpf
make build-linux-amd64
sudo ./bin/wg-mix-ebpf bpf-load-test --object build/wg_mix_tc.o
```

At runtime the loader uses the embedded BPF object. To override it for development, set:

```text
WG_MIX_EBPF_OBJECT=/path/to/wg_mix_tc.o
```

Do not run BPF load, TC attach, netns, OpenWrt, offload, or performance tests on non-Linux development machines.

`bpf-load-test` only loads and closes the BPF collection. It does not read WireGuard runtime state, attach TC filters, create network namespaces, or send tunnel traffic.
