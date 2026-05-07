# wg-mix-ebpf

Transparent WireGuard `type_word` transform using eBPF.

Current status: control-plane foundation and unit-testable logic are implemented. Linux TC/eBPF dataplane integration is planned in `docs/plans`.

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

External Linux/OpenWrt/BPF/TC tests are tracked in:

```text
docs/plans/2026-05-07-transparent-typeword-ebpf-test-plan.md
```
