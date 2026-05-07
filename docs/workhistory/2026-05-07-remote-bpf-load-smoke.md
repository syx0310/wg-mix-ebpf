# 2026-05-07 Remote BPF Load Smoke

## Summary

- Added a Linux remote build/load-smoke path without running WireGuard, netns, TC attach, or tunnel traffic tests.
- Installed user-local Go 1.25.4 on the Ubuntu x86_64 development machine.
- Installed clang/llvm/libbpf-dev as BPF build dependencies on the development machine.
- Fixed BPF source portability for Ubuntu 24.04 UAPI headers.

## Verification

On the development machine under `~/codes/wg-mix-ebpf`:

```bash
make test-unit
make build
make build-bpf
sudo ./bin/wg-mix-ebpf bpf-load-test --object build/wg_mix_tc.o
```

Result:

```text
Go unit tests passed.
CGO_ENABLED=0 binary build passed.
BPF object build passed.
BPF collection load-smoke passed.
```

## Scope

No WireGuard interface tests, netns tests, TC attach tests, endpoint tests, or tunnel traffic tests were run in this step.
