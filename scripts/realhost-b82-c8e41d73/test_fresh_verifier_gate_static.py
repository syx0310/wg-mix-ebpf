#!/usr/bin/env python3
"""Static safety contract for the versioned .82 fresh verifier authority."""

from __future__ import annotations

import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"fresh verifier static test failed: {message}")


if len(sys.argv) != 2:
    fail("expected exactly one script path")

path = pathlib.Path(sys.argv[1])
if not path.is_absolute() or not path.is_file() or path.is_symlink():
    fail("script must be an absolute regular non-symlink file")
source = path.read_text(encoding="utf-8")

required = (
    "case \"${MODE}\" in plan | run | restore)",
    "readonly STAGE_ROOT=\"${STAGING_PREFIX}/${GATE_ID}\"",
    "readonly RESERVED_PIN=\"/sys/fs/bpf/wg-mix-ebpf-${GATE_ID}\"",
    "GOCACHE=\"${GO_CACHE}\"",
    "GOMODCACHE=\"${GO_MOD_CACHE}\"",
    "GOTMPDIR=\"${GO_TMP}\"",
    "HOME=\"${GO_HOME}\"",
    "XDG_CACHE_HOME=\"${XDG_CACHE}\"",
    "XDG_CONFIG_HOME=\"${XDG_CONFIG}\"",
    "GOTOOLCHAIN=local",
    "GOPROXY=https://proxy.golang.org",
    "GOVCS=off",
    "GOTELEMETRY=off",
    "build-faketcp-checksum-kmod build-faketcp-verifier-launcher-linux-amd64",
    "build test-bpf-object-manifests",
    "run-faketcp-verifier-only.py",
    "TestFakeTCPBPFPacketProbe",
    "--runner-sha256 \"${RUNNER_SHA256}\"",
    "--binary-sha256 \"${BINARY_SHA256}\"",
    "--object-sha256 \"${EXPERIMENTAL_SHA256}\"",
    "persistent_bpf_delta=zero",
    "restore=explicit-only",
    "phase-restore-intent.v1",
    "reverse_argv=/usr/sbin/rmmod wg_mix_faketcp_checksum",
    "automatic_cleanup=0",
    "noclobber create ${STEP_LOG}",
    "/usr/bin/tee -a \"${STEP_LOG}\"",
)
for value in required:
    if value not in source:
        fail(f"missing required contract {value!r}")

for forbidden in (
    "rm -rf",
    "find -delete",
    "xargs rm",
    "rsync --delete",
    "chroot",
    "nsenter",
    "--privileged",
    "-v /:/host",
    "eval ",
    "|| true",
    "/proc/1/root",
    "docker ",
    "podman ",
    "ssh ",
    "scp ",
    "credientials",
    "/usr/sbin/ip link",
    "/usr/sbin/tc ",
    "/usr/sbin/ethtool -K",
    "/usr/sbin/nft",
):
    if forbidden in source:
        fail(f"forbidden token present: {forbidden!r}")
if re.search(r"(?m)^\s*trap(?:\s|$)", source):
    fail("trap-based cleanup is forbidden")
if re.search(r"(?:>|2>|&>)\s*/dev/null", source):
    fail("output or errors must not be discarded to /dev/null")

if source.count("module-unload) OP_TARGET") != 1:
    fail("module unload operation must have one argv authority")
run_start = source.find("run_gate() {")
run_end = source.find("validate_restore_state() {", run_start)
restore_start = source.find("restore_gate() {", run_end)
main_start = source.find("main() {", restore_start)
if min(run_start, run_end, restore_start, main_start) < 0:
    fail("could not identify run/restore state-machine bodies")
run_body = source[run_start:run_end]
restore_body = source[restore_start:main_start]
if "module-unload" in run_body or "restore_gate" in run_body:
    fail("run path contains automatic module cleanup")
if "run_operation R.module module-unload" not in restore_body:
    fail("explicit restore does not use the sole module-unload authority")

if source.count("/usr/bin/mkdir --mode=0700 --") < 7:
    fail("fresh stage/cache directories are not exact mkdir operations")
if "/usr/bin/mkdir -p" in source or "mkdir --parents" in source:
    fail("recursive/shared mkdir authority is forbidden")

if not re.search(
    r"\[\[ ! -e \"\$\{STAGE_ROOT\}\" && ! -L \"\$\{STAGE_ROOT\}\" \]\]",
    source,
):
    fail("run does not reject every pre-existing stage path before creation")
if source.count("snapshot-progs") < 4 or source.count("snapshot-maps") < 4 or source.count("snapshot-links") < 4:
    fail("BPF program/map/link baseline is not checked around both kernel gates")
if source.count("reserved-pin-absent") < 4:
    fail("reserved exact pin absence is not checked around both kernel gates")

print("fresh verifier static safety test passed")
