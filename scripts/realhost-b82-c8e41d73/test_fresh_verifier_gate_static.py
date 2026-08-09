#!/usr/bin/env python3
"""Static safety contract for the versioned .82 fresh verifier authority."""

from __future__ import annotations

import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"fresh verifier static test failed: {message}")


if len(sys.argv) not in (3, 4):
    fail("expected root gate, shared module helper, and optional manifest paths")

path = pathlib.Path(sys.argv[1])
helper_path = pathlib.Path(sys.argv[2])
if any(
    not candidate.is_absolute() or not candidate.is_file() or candidate.is_symlink()
    for candidate in (path, helper_path)
):
    fail("inputs must be absolute regular non-symlink files")
source = path.read_text(encoding="utf-8")
helper = helper_path.read_text(encoding="utf-8")

MANIFEST_PREFIX = (
    "format",
    "run_id",
    "package_id",
    "integration_ref",
    "integration_commit",
    "bundle_name",
    "bundle_sha256",
    "history_verification",
    "history_commit_count",
    "history_roots_sha256",
    "history_objects_sha256",
    "wg_state",
    "wg_interface",
    "wg_local_address",
    "wg_peer_address",
    "local_repository",
    "local_package_dir",
    "remote_package_dir",
    "remote_source",
    "target_user",
    "target_host",
    "target_hostname",
    "target_kernel",
    "target_machine_id",
    "target_interface",
    "peer_address",
    "peer_port",
    "soak_seconds",
    "session_seconds",
    "physical_nic_forward_authority",
    "physical_interface_lock",
    "legacy_matrix_mode",
    "realnic_profile",
    "realnic_traffic_seconds",
)
IDENTITY_KEYS = (
    "bind_final_package_sh",
    "controller_sh",
    "locked_transport_exp",
    "root_matrix_n_r_sh",
    "check_realhost_iperf_py",
    "test_hermetic_matrix_sh",
    "test_matrix_static_py",
    "checksum_module_lease_sh",
    "root_fresh_verifier_gate_sh",
    "test_hermetic_fresh_verifier_gate_sh",
    "test_fresh_verifier_gate_static_py",
    "prepare_stage_root_sh",
    "realnic_acceptance_py",
    "test_realnic_acceptance_py",
    "test_realnic_acceptance_static_py",
    "provision_ubuntu_test_host_sh",
    "root_veth_n_r_sh",
    "test_hermetic_veth_runner_sh",
    "test_veth_runner_static_py",
    "controller_seam_sh",
    "root_routed_veth_n_r_sh",
    "test_hermetic_routed_veth_harness_sh",
    "test_routed_veth_harness_static_py",
)
EXPECTED_MANIFEST_KEYS = MANIFEST_PREFIX + tuple(
    f"{key}_{suffix}"
    for key in IDENTITY_KEYS
    for suffix in ("path", "blob", "sha256")
)
if len(EXPECTED_MANIFEST_KEYS) != 103 or len(set(EXPECTED_MANIFEST_KEYS)) != 103:
    fail("test's exact manifest schema is not 103 unique keys")

load_match = re.search(
    r"(?ms)^load_manifest_once\(\) \{\n(?P<body>.*?)^\}\n\nphase_value\(\) \{",
    source,
)
if load_match is None:
    fail("could not isolate load_manifest_once")
load_body = load_match.group("body")
loaded_keys = tuple(
    re.findall(r"(?m)^\s*read_manifest_field\s+([a-z0-9_]+)\s+", load_body)
)
if loaded_keys != EXPECTED_MANIFEST_KEYS:
    fail("load_manifest_once does not consume the exact package-v4 103-key sequence")
if len(set(loaded_keys)) != len(loaded_keys):
    fail("load_manifest_once contains duplicate manifest keys")
if load_body.count('IFS= read -r -u "${MANIFEST_FD}" unexpected') != 1 or not re.search(
    r'''(?mx)
    if\ IFS=\ read\ -r\ -u\ "\$\{MANIFEST_FD\}"\ unexpected
    \ \|\|\ \[\[\ -n\ "\$\{unexpected\}"\ \]\];\ then\n
    \s*exec\ \{MANIFEST_FD\}<\&-\n
    \s*return\ 65\n
    \s*fi\n
    \s*exec\ \{MANIFEST_FD\}<\&-
    ''',
    load_body,
):
    fail("load_manifest_once lacks the strict complete-line and unterminated-tail EOF gate")

validation_start = source.find("validate_snapshot_contract() {")
validation_end = source.find("\n}\n", validation_start)
validation_body = source[validation_start:validation_end]
format_check = "[[ \"${FORMAT}\" == 'wg-mix-ebpf-b82-v6-package-v4' &&"
if (
    validation_start < 0
    or "load_manifest_once || return $?" not in validation_body
    or format_check not in validation_body
    or validation_body.find("load_manifest_once || return $?")
    >= validation_body.find(format_check)
):
    fail("package-v4 validation is not immediately downstream of the one-pass reader")

if len(sys.argv) == 4:
    manifest_path = pathlib.Path(sys.argv[3])
    if (
        not manifest_path.is_absolute()
        or not manifest_path.is_file()
        or manifest_path.is_symlink()
    ):
        fail("optional manifest must be an absolute regular non-symlink file")
    manifest_bytes = manifest_path.read_bytes()
    if not manifest_bytes.endswith(b"\n"):
        fail("manifest fixture must end in a newline")
    try:
        manifest_text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"manifest fixture is not UTF-8: {error}")
    records = manifest_text.splitlines()
    fields = [record.split("\t") for record in records]
    if len(records) != 103 or any(
        len(field) != 2 or not field[0] or not field[1] for field in fields
    ):
        fail("manifest fixture is not exactly 103 nonempty key/value records")
    fixture_keys = tuple(field[0] for field in fields)
    if fixture_keys != EXPECTED_MANIFEST_KEYS or len(set(fixture_keys)) != 103:
        fail("manifest fixture does not use the exact unique production key sequence")
    if fields[0][1] != "wg-mix-ebpf-b82-v6-package-v4":
        fail("manifest fixture is not package-v4")

required = (
    "case \"${MODE}\" in plan | run | restore)",
    "wg-mix-ebpf-b82-v6-package-v4",
    "read_manifest_field physical_nic_forward_authority discard",
    "read_manifest_field physical_interface_lock discard",
    "read_manifest_field legacy_matrix_mode discard",
    "read_manifest_field realnic_profile discard",
    "read_manifest_field realnic_traffic_seconds discard",
    "read_manifest_field realnic_acceptance_py_path discard",
    "read_manifest_field test_realnic_acceptance_py_path discard",
    "read_manifest_field test_realnic_acceptance_static_py_path discard",
    "read_manifest_field root_veth_n_r_sh_path discard",
    "read_manifest_field test_hermetic_veth_runner_sh_path discard",
    "read_manifest_field test_veth_runner_static_py_path discard",
    "read_manifest_field controller_seam_sh_path discard",
    "read_manifest_field root_routed_veth_n_r_sh_path discard",
    "read_manifest_field test_hermetic_routed_veth_harness_sh_path discard",
    "read_manifest_field test_routed_veth_harness_static_py_path discard",
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
    "readonly MODULE_RESOURCE_ID='f3e5c8a1'",
    'readonly MODULE_LEASE_ID="${CONTROLLER_RUN_ID}-${MODULE_RESOURCE_ID}"',
    "checksum-module-lease.v1.lock",
    'source "${MODULE_LEASE_HELPER}"',
    "c8_checksum_module_acquire L0",
    'c8_checksum_module_configure "${CONTROLLER_RUN_ID}" "${MODULE_RESOURCE_ID}"',
    "c8_checksum_module_load M",
    "c8_checksum_module_restore R.module",
    "module_state=shared-owned-loaded",
    "phase-restore-intent.v1",
    'ensure_phase "${RESTORE_INTENT_PHASE}"',
    'ensure_phase "${RESTORED_PHASE}"',
    'ensure_phase "${FILESYSTEM_PHASE}"',
    "reverse_helper=c8_checksum_module_restore",
    "automatic_cleanup=0",
    "noclobber create ${STEP_LOG}",
    "/usr/bin/tee -a \"${STEP_LOG}\"",
    "assert_bpf_baseline_convergent R.final",
)
for value in required:
    if value not in source:
        fail(f"missing required contract {value!r}")

for value in (
    "readonly C8_CHECKSUM_MODULE_FRESH_RESOURCE_ID='f3e5c8a1'",
    'readonly C8_CHECKSUM_MODULE_FRESH_OBJECT="${C8_CHECKSUM_MODULE_FRESH_ROOT}/source/build/faketcp_checksum_kmod/${C8_CHECKSUM_MODULE_NAME}.ko"',
    'readonly C8_CHECKSUM_MODULE_FRESH_EVIDENCE="${C8_CHECKSUM_MODULE_FRESH_ROOT}/evidence"',
    "c8_checksum_module_acquire()",
    "c8_checksum_module_configure()",
    "c8_checksum_module_load()",
    "c8_checksum_module_restore()",
    '"${C8_CHECKSUM_MODULE_PARAMETER}=${C8_CHECKSUM_MODULE_LEASE_ID}"',
):
    if value not in helper:
        fail(f"shared helper missing fresh contract {value!r}")

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

for legacy in (
    "MODULE_INTENT_PHASE",
    "MODULE_LOADED_PHASE",
    "restore_module_transition",
    "module-load) OP_TARGET",
    "module-unload) OP_TARGET",
    "run_operation M.load module-load",
    "run_convergent_operation R.module module-unload",
    "/usr/sbin/insmod",
    "/usr/sbin/rmmod",
):
    if legacy in source:
        fail(f"fresh gate retained a second module authority: {legacy!r}")
run_start = source.find("run_gate() {")
run_end = source.find("validate_restore_state() {", run_start)
restore_start = source.find("restore_gate() {", run_end)
main_start = source.find("main() {", restore_start)
if min(run_start, run_end, restore_start, main_start) < 0:
    fail("could not identify run/restore state-machine bodies")
run_body = source[run_start:run_end]
restore_body = source[restore_start:main_start]
if "c8_checksum_module_restore" in run_body or "restore_gate" in run_body:
    fail("run path contains automatic module cleanup")
if "fail 'already-restored'" in restore_body:
    fail("restore still rejects its replayable terminal state")
if "EXPLICIT_RESTORE_ONLY.R.pre-kwarn" in source:
    fail("plan advertises a restore warning snapshot that is not executed")
if source.count(
    "plan_operation EXPLICIT_RESTORE_ONLY.R.kwarn snapshot-kernel-warnings"
) != 1:
    fail("plan must advertise exactly one post-restore warning snapshot")
convergent_start = source.find("assert_bpf_baseline_convergent() {")
convergent_end = source.find("build_argv() {", convergent_start)
convergent_body = source[convergent_start:convergent_end]
if min(convergent_start, convergent_end) < 0 or convergent_body.count(
    'run_convergent_operation "${label}.kwarn" snapshot-kernel-warnings'
) != 1:
    fail("convergent baseline must execute exactly one labeled warning snapshot")
if restore_body.count("assert_bpf_baseline_convergent R.final") != 1:
    fail("restore warning snapshot is not uniquely bound to R.final")
restore_order = tuple(
    restore_body.find(value)
    for value in (
        "c8_checksum_module_acquire R.lease",
        'c8_checksum_module_configure "${CONTROLLER_RUN_ID}"',
        'ensure_phase "${RESTORE_INTENT_PHASE}"',
        "c8_checksum_module_restore R.module",
        "assert_bpf_baseline_convergent R.final",
    )
)
if min(restore_order) < 0 or tuple(sorted(restore_order)) != restore_order:
    fail("shared restore lock/configure/intent/restore/baseline order drifted")

if "manifest_value()" in source or "manifest_value " in source:
    fail("manifest is reparsed by key instead of consumed exactly once")
snapshot_index = source.find("snapshot_held_inputs", run_start)
audit_index = source.find("create_audit_log", source.find("run_gate() {"))
lock_index = source.find("c8_checksum_module_acquire L0", run_start)
absent_index = source.find("L1.module-absent", run_start)
clone_index = source.find("create_fresh_source", source.find("run_gate() {"))
build_index = source.find("build_fresh_artifacts", run_start)
load_index = source.find("load_shared_module", run_start)
run_order = (snapshot_index, audit_index, lock_index, absent_index, clone_index, build_index, load_index)
if min(run_order) < 0 or tuple(sorted(run_order)) != run_order:
    fail("snapshot/audit/shared-lock/absence/clone/build/load order drifted")

load_start = source.find("load_shared_module() {")
load_end = source.find("run_verifier_and_test_run() {", load_start)
load_body = source[load_start:load_end]
warning_index = source.find(
    '/usr/bin/cmp -s "${EVIDENCE_ROOT}/A.kwarn.out" "${EVIDENCE_ROOT}/M.kwarn.out"',
    load_start,
)
helper_load_index = load_body.find("c8_checksum_module_load M")
warning_capture_index = load_body.find("run_operation M.kwarn")
warning_compare_index = load_body.find('/usr/bin/cmp -s "${EVIDENCE_ROOT}/A.kwarn.out"')
if min(helper_load_index, warning_capture_index, warning_compare_index, warning_index) < 0 or not (
    helper_load_index < warning_capture_index < warning_compare_index
):
    fail("module warning zero-delta gate does not immediately follow shared load")

callback_start = source.find("run_module_lease_argv() {")
callback_end = source.find("c8_checksum_module_run()", callback_start)
callback_body = source[callback_start:callback_end]
if min(callback_start, callback_end) < 0 or "run_step" in callback_body or not all(
    value in callback_body for value in ("audit_line start", "/usr/bin/tee -a", "audit_line finish")
):
    fail("module callback is not replayable audit-only execution")

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
