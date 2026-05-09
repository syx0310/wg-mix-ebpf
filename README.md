# wg-mix-ebpf

Transparent WireGuard `type_word` transform using eBPF.

Current status: control-plane foundation, daemon reconcile loop, profile management, generation-scoped map ABI, startup guard tooling, attach-state cleanup, embedded BPF packaging, and Linux TC/eBPF dataplane loading are implemented. Live BPF load, TC attach, WireGuard, offload, OpenWrt, and public-network tests must run on controlled external Linux machines.

## Commands

```bash
wg-mix-ebpf doctor
wg-mix-ebpf install --dry-run
wg-mix-ebpf init --wg wg0 --underlay eth0:netdev --profile home --profile-preset wireguard-mix-wire-values-v1
wg-mix-ebpf profile list
wg-mix-ebpf profile show home
wg-mix-ebpf profile add home-random
wg-mix-ebpf profile token home
wg-mix-ebpf profile check 'wgmix1....'
wg-mix-ebpf profile remove home --force
wg-mix-ebpf run --once --offline --dry-run
wg-mix-ebpf reload --config configs/example.yaml --offline
wg-mix-ebpf validate --config configs/example.yaml --offline
wg-mix-ebpf status --config configs/example.yaml --offline
wg-mix-ebpf dump --config configs/example.yaml --offline
wg-mix-ebpf dump-abi --config configs/example.yaml --offline
wg-mix-ebpf guard-plan --config configs/example.yaml --offline
wg-mix-ebpf guard-apply --config configs/example.yaml --offline --dry-run
wg-mix-ebpf guard-cleanup --config configs/example.yaml --offline --dry-run
wg-mix-ebpf features
wg-mix-ebpf uninstall --dry-run --yes
```

`--offline` skips runtime WireGuard and underlay reads. It is intended for local static validation and unit-test environments.

`install` only installs files and registers service/init scripts. It does not start, enable, reload, attach TC, or modify WireGuard. Use `install --enable` if service enablement is desired, then start the service explicitly with systemd or OpenWrt init.

`run` is the internal daemon entrypoint used by service managers. It performs startup reconcile, periodic runtime reconcile, and reload-request handling. Manual `reload` notifies the daemon when it is running; otherwise it performs a one-shot reconcile.

`profile remove <name> --force` removes the profile and stops managing WireGuard entries that reference it. It does not change WireGuard configuration or interfaces.

Operational behavior is documented in:

```text
docs/architecture.md
docs/build.md
docs/compatibility.md
docs/configuration.md
docs/operations.md
```

## Development

```bash
make test-unit
CGO_ENABLED=0 go build -o /tmp/wg-mix-ebpf ./cmd/wg-mix-ebpf
```

The default Makefile build and test targets use `CGO_ENABLED=0` for reproducible cross-platform builds.

## Linux Dataplane

The Go binary does not require cgo. The TC/eBPF program is compiled during packaging and embedded into the binary:

```bash
make build-bpf
make build-linux-amd64
sudo ./bin/wg-mix-ebpf-linux-amd64 bpf-load-test
```

Packaged binaries do not need clang, kernel headers, or a separate `.o` file on the target machine. For development, override the embedded object with:

```text
WG_MIX_EBPF_OBJECT=/path/to/wg_mix_tc.o
```

or `--object /path/to/wg_mix_tc.o`.

Do not run BPF load, TC attach, netns, OpenWrt, offload, or performance tests on non-Linux development machines.

`bpf-load-test` only loads and closes the BPF collection. It does not read WireGuard runtime state, attach TC filters, create network namespaces, or send tunnel traffic.

External Linux/OpenWrt/BPF/TC tests require controlled machines. Do not run those tests on laptops or unrelated shared hosts.
