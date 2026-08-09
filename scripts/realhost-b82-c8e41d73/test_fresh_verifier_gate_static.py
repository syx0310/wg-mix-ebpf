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
    "readonly SNAPSHOT_MANIFEST=\"${INTAKE_ROOT}/package-manifest.v1\"",
    "readonly SNAPSHOT_BUNDLE=\"${INTAKE_ROOT}/source-${PACKAGE_ID}.bundle\"",
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
    'exec {MANIFEST_FD}<"${MANIFEST}"',
    'exec {BUNDLE_FD}<"${BUNDLE}"',
    'source="/proc/self/fd/${descriptor}"',
    'noclobber copy held ${source} to ${destination}',
    'load_manifest_once',
    'clone --no-local --no-checkout --single-branch',
    '"${SNAPSHOT_BUNDLE}" "${SOURCE}"',
    "rev-parse --is-shallow-repository",
    "rev-list --count",
    "rev-list --max-parents=0 --reverse",
    "rev-list --parents --objects",
    "--missing=print",
    "fsck --full --strict --no-dangling",
    "strict_fsck=passed",
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
    'ensure_phase "${RESTORE_INTENT_PHASE}"',
    'ensure_phase "${RESTORED_PHASE}"',
    'ensure_phase "${FILESYSTEM_PHASE}"',
    "reverse_argv=/usr/sbin/rmmod wg_mix_faketcp_checksum",
    "automatic_cleanup=0",
    "noclobber create ${STEP_LOG}",
    "/usr/bin/tee -a \"${STEP_LOG}\"",
    'restore_module_transition "${live}${loaded_receipt}"',
    "01 | 00) printf '%s\\n' already-absent ;;",
    "assert_bpf_baseline_convergent R.final",
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
if "run_convergent_operation R.module module-unload" not in restore_body:
    fail("explicit restore does not use the sole module-unload authority")
if "fail 'already-restored'" in restore_body:
    fail("restore still rejects its replayable terminal state")
intent_index = restore_body.find('ensure_phase "${RESTORE_INTENT_PHASE}"')
state_index = restore_body.find('restore_module_transition "${live}${loaded_receipt}"')
unload_index = restore_body.find("run_convergent_operation R.module module-unload")
if min(intent_index, state_index, unload_index) < 0 or not intent_index < state_index < unload_index:
    fail("restore intent is not durable before state inspection and module mutation")

if "manifest_value()" in source or "manifest_value " in source:
    fail("manifest is reparsed by key instead of consumed exactly once")
snapshot_index = source.find("snapshot_held_inputs", run_start)
audit_index = source.find("create_audit_log", source.find("run_gate() {"))
clone_index = source.find("create_fresh_source", source.find("run_gate() {"))
if min(snapshot_index, audit_index, clone_index) < 0 or not snapshot_index < audit_index < clone_index:
    fail("stable input snapshots are not sealed before clone/build")

warning_index = source.find(
    '/usr/bin/cmp -s "${EVIDENCE_ROOT}/A.kwarn.out" "${EVIDENCE_ROOT}/M.kwarn.out"'
)
loaded_index = source.find('write_phase "${MODULE_LOADED_PHASE}"')
if min(warning_index, loaded_index) < 0 or warning_index > loaded_index:
    fail("module warning delta is not checked before publishing the loaded receipt")

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
