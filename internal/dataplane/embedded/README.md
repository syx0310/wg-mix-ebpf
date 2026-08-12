# Embedded BPF Object

`make prepare-embedded-bpf` compiles and copies three independent objects here:

- `wg_mix_tc.o` for the baseline UDP/ICMP dataplane;
- `wg_mix_faketcp.o` for the modern production FakeTCP/kfunc dataplane;
- `wg_mix_faketcp_legacy_515.o` for the Linux 5.15 FakeTCP/kprobe dataplane.

The Go binary embeds all three objects so target machines do not need clang or
kernel headers at runtime. The two FakeTCP variants have separate identities
and manifests; neither loader falls back to the baseline or other variant.

At runtime, artifact diagnostics calculate SHA-256 directly from these
embedded bytes. No separately supplied checksum is trusted.
