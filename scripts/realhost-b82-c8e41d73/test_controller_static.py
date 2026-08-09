#!/usr/bin/env python3
"""Static safety contract for the v6 binder, controller, transport and stager."""

from __future__ import annotations

import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


def read_regular(path_text: str) -> tuple[pathlib.Path, str]:
    path = pathlib.Path(path_text)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        fail(f"input is not an absolute regular file: {path}")
    return path, path.read_text(encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 7:
        fail(
            "usage: test_controller_static.py BINDER CONTROLLER TRANSPORT "
            "ROOT_STAGER ROOT_MATRIX PROVISIONER"
        )
    binder_path, binder = read_regular(sys.argv[1])
    controller_path, controller = read_regular(sys.argv[2])
    transport_path, transport = read_regular(sys.argv[3])
    stager_path, stager = read_regular(sys.argv[4])
    matrix_path, matrix = read_regular(sys.argv[5])
    provisioner_path, provisioner = read_regular(sys.argv[6])

    production = {
        binder_path.name: binder,
        controller_path.name: controller,
        transport_path.name: transport,
        stager_path.name: stager,
    }
    forbidden_patterns = (
        r"\brm\s+-[^\n]*r",
        r"\brmdir\b",
        r"\bfind\b[^\n]*-delete",
        r"\bxargs\b[^\n]*\brm\b",
        r"\brsync\b[^\n]*--delete",
        r"\bchroot\b",
        r"\bnsenter\b",
        r"\b(?:docker|podman)\b",
        r"(?:^|\s)eval(?:\s|$)",
        r"(?:^|\s)(?:sh|bash)\s+-c(?:\s|$)",
        r"(?:^|\s)trap(?:\s|$)",
        r"/proc/1/root",
        r"(?:^|\s)-v\s+/:/host(?:\s|$)",
        r"(?:^|\s)--privileged(?:\s|$)",
    )
    for name, payload in production.items():
        for pattern in forbidden_patterns:
            if re.search(pattern, payload, re.MULTILINE):
                fail(f"{name} contains prohibited executable pattern: {pattern}")

    for name, payload in {
        binder_path.name: binder,
        controller_path.name: controller,
        stager_path.name: stager,
    }.items():
        if re.search(r"(?:^|\s)/(?:usr/)?bin/(?:ssh|scp)(?:\s|$)", payload):
            fail(f"{name} directly invokes SSH/SCP outside Expect")

    required_binder = (
        "--source-ref",
        "--commit",
        'actual_commit="$(git_checked rev-parse --verify "${SOURCE_REF}^{commit}")"',
        '[[ "${actual_commit}" == "${COMMIT}" ]]',
        'source_ref_after="$(git_checked rev-parse --verify "${SOURCE_REF}^{commit}")"',
        "git_checked bundle create",
        "git_checked bundle verify",
        "git_checked rev-parse --is-shallow-repository",
        "[[ \"${shallow_state}\" == 'false' ]]",
        "isolated-unbundle-rev-list-fsck-v1",
        "bundle unbundle",
        "rev-list --parents --objects --missing=print",
        "fsck --full --strict --no-dangling",
        "manifest_line history_commit_count",
        "manifest_line history_roots_sha256",
        "manifest_line history_objects_sha256",
        "wg-mix-ebpf-b82-v6-package-v3",
        "manifest_line wg_state",
        "absent)",
        '"${WG_INTERFACE}" == \'absent\'',
        "prepare-stage-root.sh",
        "scripts/provision-ubuntu-test-host.sh",
        "locked-transport.exp",
        "controller.sh",
        "checksum-module-lease.sh",
        "root-fresh-verifier-gate.sh",
        "test-hermetic-fresh-verifier-gate.sh",
        "test_fresh_verifier_gate_static.py",
        "manifest_line physical_nic_forward_authority realnic-acceptance-v1",
        'manifest_line physical_interface_lock "${PHYSICAL_INTERFACE_LOCK}"',
        "manifest_line legacy_matrix_mode retired",
        "manifest_line realnic_profile acceptance",
        "manifest_line realnic_traffic_seconds 30",
        '"${REALNIC_PATH_FROM_ROOT}/realnic_acceptance.py"',
        '"${REALNIC_PATH_FROM_ROOT}/test_realnic_acceptance.py"',
        '"${REALNIC_PATH_FROM_ROOT}/test_realnic_acceptance_static.py"',
    )
    for literal in required_binder:
        if literal not in binder:
            fail(f"binder contract is missing {literal!r}")
    if re.search(r"rev-parse(?:\s+--verify)?\s+HEAD", binder):
        fail("binder defaults or resolves the package from HEAD")
    if binder.index("require_full_repository || fail 'repository-became-shallow'") > binder.index(
        "git_checked bundle create"
    ):
        fail("binder checks shallow state after bundle creation")
    if re.search(r"\b(?:apt|apt-get)\b", binder):
        fail("binder contains package installation")

    required_controller = (
        "B82_V6_LEGACY_MATRIX_RETIRED controller_entries=0 historical_recovery=frozen-original-package-before-final-staging",
        "identity-wg-interfaces",
        "identity-netns",
        "identity-driver",
        "tool-go tool-clang tool-llvm tool-bpftool tool-make tool-gcc tool-iperf3",
        "kernel-btf kernel-bpffs kernel-headers",
        "/usr/bin/expect",
        "--manifest-sha256",
        "--credential-path",
        "credential_read=0 network_operations=0 mutations=0",
        "BASE_IDENTITY_OPERATIONS",
        "POSTFLIGHT_OPERATIONS",
        "BOOTSTRAP_CREATE_OPERATIONS",
        "bootstrap-absent bootstrap-not-symlink bootstrap-create bootstrap-root-readlink bootstrap-root-stat",
        "bootstrap-install-provisioner bootstrap-install-stager",
        "bootstrap-provisioner-readlink bootstrap-provisioner-stat bootstrap-provisioner-sha",
        "bootstrap-stager-readlink bootstrap-stager-stat bootstrap-stager-sha",
        "STAGE_OPERATIONS=(stage-snapshot stage-plan stage-run)",
        "state_transition PACKAGE_BOUND BOOTSTRAP_ONLY",
        "state_transition BOOTSTRAP_ONLY PROVISION_CHECK",
        "state_transition PROVISION_CHECK AWAIT_APPLY",
        "state_transition AWAIT_APPLY PROVISION_APPLY",
        "state_transition PROVISION_APPLY POSTFLIGHT",
        "run_operation execute provision-apply",
        "B82_V6_PROVISION_AWAIT_APPLY",
        "automatic_apply=0",
        "fresh-plan | fresh-run | fresh-restore",
        "for operation in fresh-plan fresh-run fresh-restore",
        "run_operation execute fresh-plan",
        "run_operation execute fresh-run",
        "run_operation execute fresh-restore",
        "CHECKSUM_MODULE_LEASE_SH_PATH",
        "ROOT_FRESH_VERIFIER_GATE_SH_PATH",
        "realnic-plan | realnic-run | realnic-restore",
        "verify_local_approved_plan",
        "scp-realnic-approved-plan verify-sha-realnic-approved-plan",
        "stage-realnic-plan-snapshot realnic-run",
        "stage-realnic-plan-verify",
        "run_operation execute realnic-restore",
        "legacy_forward=retired",
    )
    for literal in required_controller:
        if literal not in controller:
            fail(f"controller contract is missing {literal!r}")
    if re.search(r"\b(?:apt|apt-get)\b", controller):
        fail("controller contains an implicit package installation path")
    if "open ${CREDENTIAL" in controller or "<\"${CREDENTIAL" in controller:
        fail("controller directly reads the credential file")
    for mode in ("fresh-plan", "fresh-run", "fresh-restore"):
        if not re.search(
            rf"{mode}\)\s+run_operation execute {mode}", controller, re.MULTILINE
        ):
            fail(f"controller {mode} is not an independent fixed operation")
    for retired in ("matrix-plan", "matrix-run", "matrix-restore-", "--restore-cell"):
        if retired in controller:
            fail(f"controller still exposes retired physical-NIC mode {retired}")
    if re.search(r"(?:^|[| {])restore(?:[| )}]|$)", controller):
        fail("controller still exposes the legacy top-level restore mode")
    if "hermetic-realnic-" in controller or "hermetic-realnic-" in transport:
        fail("controller/transport runs realNIC tests from the flat package copy")
    realnic_run = controller[
        controller.index("execute_realnic_run() {") : controller.index(
            "execute_realnic_restore() {"
        )
    ]
    run_order = (
        "verify_local_approved_plan",
        "scp-realnic-approved-plan verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan stage-realnic-plan-snapshot realnic-run",
    )
    positions = [realnic_run.index(item) for item in run_order]
    if positions != sorted(positions):
        fail("realNIC run does not use the single fixed intake-before-run sequence")
    realnic_restore = controller[
        controller.index("execute_realnic_restore() {") : controller.index("main() {")
    ]
    if "scp-realnic-approved-plan" in realnic_restore or realnic_restore.count(
        "stage-realnic-plan-verify"
    ) != 1:
        fail("realNIC restore recopies intake or lacks one root snapshot verification")
    prepare_body = controller[
        controller.index("execute_prepare() {") : controller.index("execute_provision_apply() {")
    ]
    if "run_operation execute provision-apply" in prepare_body:
        fail("prepare can trigger provisioning apply")
    apply_body = controller[
        controller.index("execute_provision_apply() {") : controller.index("main() {")
    ]
    if apply_body.count("run_operation execute provision-apply") != 1:
        fail("explicit apply path does not contain exactly one fixed apply operation")
    apply_order = (
        "verify_remote_package || return $?",
        "run_provision_check || return $?",
        "state_transition PROVISION_CHECK AWAIT_APPLY",
        "state_transition AWAIT_APPLY PROVISION_APPLY",
        "verify_provisioner || return $?",
        "run_operation execute provision-apply",
        "verify_provisioner || return $?",
        "run_provision_check || return $?",
        "state_transition PROVISION_APPLY POSTFLIGHT",
        "execute_postflight",
    )
    remaining = apply_body
    for literal in apply_order:
        position = remaining.find(literal)
        if position < 0:
            fail(f"explicit apply order is missing {literal!r}")
        remaining = remaining[position + len(literal) :]
    postflight_body = controller[
        controller.index("execute_postflight() {") : controller.index("execute_prepare() {")
    ]
    postflight_order = (
        "verify_remote_package || return $?",
        '"${POSTFLIGHT_OPERATIONS[@]}" controller-shellcheck hermetic-matrix',
        "verify_stager || return $?",
        '"${STAGE_OPERATIONS[@]}"',
        "B82_V6_CONTROLLER_POSTFLIGHT_COMPLETE",
    )
    positions = [postflight_body.index(item) for item in postflight_order]
    if positions != sorted(positions):
        fail("postflight no longer performs full preflight before staging")

    required_transport = (
        'set action [lindex $argv 7]',
        'if {$action eq "plan"}',
        "credential_read=0 network_operations=0",
        'if {[catch {open $credential_path r} credential_file]}',
        'send -- "$password\\r"',
        'spawn -noecho {*}$spawn_argv',
        "B82_V6_TRANSPORT_EXECUTE operation=$operation",
        "credential_in_argv=0",
        "/usr/bin/ssh",
        "/usr/bin/scp",
        "StrictHostKeyChecking=yes",
        "CheckHostIP=yes",
        "ClearAllForwardings=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ProxyCommand=none",
        "ControlMaster=no",
        "identity-wg-interfaces",
        "contains:go1.26.0",
        "contains:21.1.8",
        "/usr/sbin/bpftool -V",
        "contains:v7.7.0",
        "contains:GNU Make 4.4.1",
        "set assertion empty",
        "/usr/bin/test -r /sys/kernel/btf/vmlinux",
        "/usr/bin/findmnt --noheadings --raw --output FSTYPE,TARGET --target /sys/fs/bpf",
        "controller-shellcheck",
        "hermetic-fresh",
        "proc fresh_remote_argv",
        "fresh-plan - fresh-run - fresh-restore",
        "proc realnic_remote_argv",
        "realnic-plan - realnic-run - realnic-restore",
        "/usr/bin/python3 -B -I",
        "realnic-plan-snapshot",
        "realnic-plan-verify",
        "scp-realnic-approved-plan verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan",
        "/run/wg-mix-ebpf-source-bootstrap-c8e41d73/realnic-approved-plan.json",
        "/root-fresh-verifier-gate.sh",
        "--controller-source $source",
        'set bootstrap_root "/run/wg-mix-ebpf-source-bootstrap-c8e41d73"',
        "bootstrap-absent",
        "/usr/bin/test ! -e $bootstrap_root",
        "bootstrap-not-symlink",
        "/usr/bin/test ! -L $bootstrap_root",
        "bootstrap-create",
        "/usr/bin/mkdir --mode=0700 -- $bootstrap_root",
        "bootstrap-root-readlink",
        "bootstrap-root-stat",
        "bootstrap-install-stager",
        "/usr/bin/install --owner=root --group=root --mode=0700 --no-target-directory --",
        "bootstrap-stager-readlink",
        "bootstrap-stager-sha",
        "bootstrap-stager-stat",
        "bootstrap-install-provisioner",
        'set bootstrap_provisioner "${bootstrap_root}/provision-ubuntu-test-host.sh"',
        '"${package}/provision-ubuntu-test-host.sh" $bootstrap_provisioner',
        "bootstrap-provisioner-readlink",
        "bootstrap-provisioner-stat",
        "bootstrap-provisioner-sha",
        "provision-check - provision-apply",
        "/bin/bash -p $bootstrap_provisioner $provision_mode",
        "--expected-address 192.168.10.82",
        "--expected-interface ens33",
        "--expected-hostname ubuntu-2604-test",
        "--expected-kernel 7.0.0-28-generic",
        "--expected-machine-id 9db3fb717cc74974b2a6b243d67f67b9",
        "provision_plan_policy",
        "unexpected-missing-set",
        "B82_V6_PROVISION_AUDIT",
        "child_rc=$child_rc plan=unverified missing_set=unverified next_state=STOP",
        "stage-snapshot",
        'set snapshot_manifest "${bootstrap_root}/package-manifest.v1"',
        'snapshot --manifest "${package}/package-manifest.v1"',
        "$stage_mode --manifest $snapshot_manifest",
        'set assertion exact:root:root:700:1:regular\\ file',
        "/usr/bin/test -d /usr/src/linux-headers-7.0.0-28-generic",
    )
    for literal in required_transport:
        if literal not in transport:
            fail(f"transport contract is missing {literal!r}")
    if transport.index('if {$action eq "plan"}') > transport.index("open $credential_path r"):
        fail("transport opens credentials before the plan-mode exit")
    if re.search(r"puts[^\n]*\$password", transport):
        fail("transport prints the credential variable")
    if re.search(r"spawn[^\n]*\$password", transport):
        fail("transport places the password in child argv")
    if "lrange $argv 2 end" in transport or "--remote-argv" in transport:
        fail("transport accepts a caller-supplied remote argv")
    if "/usr/sbin/bpftool version" in transport:
        fail("transport retains the legacy bpftool version argv")
    for retired in (
        "matrix-plan - matrix-run",
        '"matrix-plan"',
        '"matrix-run"',
        "matrix-restore-",
        "proc matrix_remote_argv",
    ):
        if retired in transport:
            fail(f"transport still exposes retired physical-NIC operation {retired}")
    fresh_argv_body = transport[
        transport.index("proc fresh_remote_argv") : transport.index("proc package_sha")
    ]
    if "wg_state" in fresh_argv_body or "wireguard" in fresh_argv_body.lower():
        fail("fresh transport reachability depends on WireGuard topology")
    if re.search(
        r'/bin/bash\s+-p\s+"?\$\{package\}/prepare-stage-root\.sh', transport
    ):
        fail("transport executes the user-writable package stager")
    bootstrap_order = (
        "bootstrap-absent",
        "bootstrap-not-symlink",
        "bootstrap-create",
        "bootstrap-root-readlink",
        "bootstrap-root-stat",
        "bootstrap-install-stager",
        "bootstrap-stager-readlink",
        "bootstrap-stager-sha",
        "bootstrap-stager-stat",
        "stage-snapshot",
        "stage-plan - stage-run",
    )
    positions = [transport.index(item) for item in bootstrap_order]
    if positions != sorted(positions):
        fail("root-owned bootstrap operation order changed")
    if transport.count('set bootstrap_root "/run/wg-mix-ebpf-source-bootstrap-c8e41d73"') != 1:
        fail("transport has zero or multiple bootstrap roots")
    if transport.count('set bootstrap_provisioner "${bootstrap_root}/provision-ubuntu-test-host.sh"') != 1:
        fail("transport has zero or multiple provisioner paths")
    provision_verify = (
        "bootstrap-provisioner-readlink",
        "bootstrap-provisioner-stat",
        "bootstrap-provisioner-sha",
    )
    verify_positions = [transport.index(item) for item in provision_verify]
    if verify_positions != sorted(verify_positions):
        fail("provisioner canonical path/stat/SHA order changed")

    required_stager = (
        "root-required",
        "host-identity",
        "snapshot-bundle",
        "stage-exists",
        "clone --no-local",
        "checkout --detach",
        "staged-content",
        "/usr/bin/shellcheck",
        "status --porcelain=v1",
        "noclobber",
        "retained=1",
        'readonly BOOTSTRAP_ROOT="/run/wg-mix-ebpf-source-bootstrap-${RUN_ID}"',
        'readonly EXPECTED_SELF="${BOOTSTRAP_ROOT}/prepare-stage-root.sh"',
        'readonly USER_MANIFEST="${EXPECTED_REMOTE_PACKAGE}/package-manifest.v1"',
        'readonly USER_BUNDLE="${EXPECTED_REMOTE_PACKAGE}/source-${PACKAGE_ID}.bundle"',
        'readonly SNAPSHOT_MANIFEST="${BOOTSTRAP_ROOT}/package-manifest.v1"',
        'readonly SNAPSHOT_BUNDLE="${BOOTSTRAP_ROOT}/source-${PACKAGE_ID}.bundle"',
        "snapshot-plan | snapshot | plan | run",
        "copy_noclobber",
        '/usr/bin/cat -- "${source}" >"${destination}"',
        "snapshot-destination-exists",
        "root:root:600:1:regular file",
        'local bundle="${SNAPSHOT_BUNDLE}"',
        '[[ "${MANIFEST}" == "${SNAPSHOT_MANIFEST}" ]]',
        "require_root_owned_self",
        "root:root:700:1:regular file",
        'canonical_self="$(/usr/bin/readlink -e -- "$0")"',
        '[[ "$(sha256_file "${EXPECTED_SELF}")" == "${PREPARE_SHA256}" ]]',
        'readonly MODULE_LEASE_LOCK="${STAGE_ROOT}/checksum-module-lease.v1.lock"',
        'readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-${RUN_ID}/checksum-module-lease.sh"',
        "plan_command S3.lock /usr/bin/install --owner=root --group=root --mode=0600",
        '--no-target-directory -- /dev/null "${MODULE_LEASE_LOCK}"',
        "require_module_lease_lock",
        "module-lease-lock-create",
        "module-lease-lock-drift",
        '"module_lease_lock=${MODULE_LEASE_LOCK}"',
        '"${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}"',
        "checksum_module_lease_sh_path",
        "root_fresh_verifier_gate_sh_path",
        "test_hermetic_fresh_verifier_gate_sh_path",
        "test_fresh_verifier_gate_static_py_path",
        '"${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}"',
        "provision_ubuntu_test_host_sh_path",
        "provision_ubuntu_test_host_sh_blob",
        "provision_ubuntu_test_host_sh_sha256",
        "${EXPECTED_SOURCE}/${PROVISION_PATH}",
        'readonly USER_REALNIC_PLAN="${EXPECTED_REMOTE_PACKAGE}/realnic-approved-plan.json"',
        'readonly ROOT_REALNIC_PLAN="${BOOTSTRAP_ROOT}/realnic-approved-plan.json"',
        "realnic-plan-snapshot | realnic-plan-verify",
        "require_completed_stage",
        "open_approved_plan_intake",
        'exec {APPROVED_PLAN_FD}<"${USER_REALNIC_PLAN}"',
        '"/proc/self/fd/${APPROVED_PLAN_FD}"',
        'APPROVED_PLAN_PENDING="${ROOT_REALNIC_PLAN}.pending.${APPROVED_PLAN_SHA256}"',
        "create_approved_plan_pending",
        "write_approved_plan_pending",
        "require_approved_plan_pending_fd",
        "fsync_exact_target",
        '/bin/ln --no-target-directory --',
        "held-fd-writeall-fsync-hardlink-noclobber",
        "final-pending-same-inode",
        "approved-plan-preexisting-differs",
        "approved-plan-root-snapshot",
        "verified-existing",
        "verify_realnic_plan",
        "root:root:600:1:regular file",
        "siyixuan:siyixuan",
        "realnic_acceptance_py_path",
        "test_realnic_acceptance_py_path",
        "test_realnic_acceptance_static_py_path",
        "S6.realnic-unit",
        "S6.realnic-static",
        "PYTHONDONTWRITEBYTECODE=1",
        '"${EXPECTED_SOURCE}/${REALNIC_TEST_PATH}"',
        '"${EXPECTED_SOURCE}/${REALNIC_STATIC_PATH}"',
        "realnic-hermetic-unit",
        "realnic-hermetic-static",
    )
    for literal in required_stager:
        if literal not in stager:
            fail(f"root stager contract is missing {literal!r}")
    if re.search(r"\b(?:apt|apt-get)\b", stager):
        fail("root stager contains package installation")
    if "${EXPECTED_SOURCE}" not in stager or "${STAGE_ROOT}" not in stager:
        fail("root stager does not use the fixed run-owned stage")
    if "require_package_file" in stager:
        fail("root stager still revalidates user-owned package scripts")
    if 'local bundle="${EXPECTED_REMOTE_PACKAGE}/${BUNDLE_NAME}"' in stager:
        fail("root stager clones by reopening the user-owned bundle")
    if stager.index('run_copy_step C7 "${USER_BUNDLE}"') > stager.index(
        'require_snapshot_file "${SNAPSHOT_MANIFEST}"'
    ):
        fail("root stager parses or validates the manifest before both intake copies complete")
    if stager.index('run_copy_step C7 "${USER_BUNDLE}"') > stager.index(
        'MANIFEST="${SNAPSHOT_MANIFEST}"'
    ):
        fail("root stager parses the manifest before the bundle intake copy completes")
    if stager.count("validate_manifest || fail 'manifest-contract'") != 2:
        fail("root stager manifest parsing escaped the two root-snapshot consumers")
    if stager.index("run_step S3.lock") > stager.index("run_step S4"):
        fail("root stager creates the shared module lock after source staging begins")
    if stager.index("require_module_lease_lock || fail 'module-lease-lock-drift'") > stager.index(
        "write_binding_marker || fail 'binding-marker'"
    ):
        fail("root stager binds the stage before revalidating the shared module lock")
    staged_gate_order = (
        'checkout --detach "${INTEGRATION_COMMIT}"',
        "require_staged_content || fail 'staged-content'",
        "run_step S6.realnic-unit",
        "run_step S6.realnic-static",
        "require_staged_content || fail 'staged-content-postcheck'",
        "write_binding_marker || fail 'binding-marker'",
    )
    positions = [stager.index(item) for item in staged_gate_order]
    if positions != sorted(positions):
        fail("realNIC tests do not gate the staged source before binding")
    if stager.count('readonly BOOTSTRAP_ROOT="/run/wg-mix-ebpf-source-bootstrap-${RUN_ID}"') != 1:
        fail("root stager has zero or multiple bootstrap roots")
    if stager.count('readonly ROOT_REALNIC_PLAN="${BOOTSTRAP_ROOT}/realnic-approved-plan.json"') != 1:
        fail("root stager has zero or multiple approved-plan authorities")
    snapshot_body = stager[
        stager.index("snapshot_realnic_plan() {") : stager.index("verify_realnic_plan() {")
    ]
    publish_order = (
        "require_completed_stage",
        "acquire_physical_interface_lock",
        "open_approved_plan_intake",
        "create_approved_plan_pending",
        "write_approved_plan_pending",
        'fsync_exact_target "${BOOTSTRAP_ROOT}" directory',
        "require_approved_plan_pending_fd",
        '/bin/ln --no-target-directory --',
        'require_approved_plan_path "${ROOT_REALNIC_PLAN}"',
        'fsync_exact_target "${BOOTSTRAP_ROOT}" directory',
    )
    remaining = snapshot_body
    for literal in publish_order:
        position = remaining.find(literal)
        if position < 0:
            fail(f"realNIC durable publish order is missing {literal!r}")
        remaining = remaining[position + len(literal) :]
    if snapshot_body.count('/bin/ln --no-target-directory --') != 1:
        fail("realNIC durable publish has zero or multiple final link primitives")
    if snapshot_body.count('fsync_exact_target "${BOOTSTRAP_ROOT}" directory') != 2:
        fail("realNIC durable publish does not fsync the parent before and after link")
    verify_body = stager[
        stager.index("verify_realnic_plan() {") : stager.index("run_stage() {")
    ]
    if "USER_REALNIC_PLAN" in verify_body or "write_approved_plan_pending" in verify_body:
        fail("realNIC restore verification reopens or recopies user intake")
    if "published.v1" in stager or "publish-receipt" in stager:
        fail("root stager introduced a second approved-plan terminal authority")
    redundant_manifest_fields = (
        "manifest_line physical_interface_lock_interface",
        "manifest_line legacy_matrix_restore_cells",
        "manifest_line legacy_retirement_reservation",
        "manifest_line realnic_soak_window_seconds",
        "manifest_line realnic_plan_intake_name",
        "manifest_line realnic_root_plan",
    )
    for literal in redundant_manifest_fields:
        if literal in binder:
            fail(f"binder repeats derivable manifest field {literal}")

    required_provisioner = (
        "--check",
        "--apply",
        "BPFTOOL_VERSION_COMMAND",
        "/usr/sbin/bpftool -V",
        "missing_packages=",
        "plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0",
    )
    for literal in required_provisioner:
        if literal not in provisioner:
            fail(f"reviewed provisioner contract is missing {literal!r}")
    if "/usr/sbin/bpftool version" in provisioner:
        fail("reviewed provisioner retains the legacy bpftool version argv")

    matrix_forbidden = (
        "chroot",
        "nsenter",
        "--privileged",
        "find -delete",
        "rm -rf",
        "/usr/sbin/ethtool",
        "/usr/sbin/ip",
        "/usr/sbin/bpftool",
        "/usr/bin/iperf3",
        "--restore-cell",
    )
    for literal in matrix_forbidden:
        if literal in matrix:
            fail(f"existing matrix contains prohibited literal: {literal}")
    if "readonly RUN_ID='c8e41d73'" not in matrix:
        fail("existing matrix run identity changed")
    for literal in (
        "REALHOST_V6_LEGACY_CONTROLLER_AUTHORITY state=retired controller_entries=0 restore_entries=0",
        "REALHOST_V6_HISTORICAL_RECOVERY package=frozen-original-package timing=before-final-staging",
        "legacy-matrix-retired-use-frozen-original-package-before-final-staging",
    ):
        if literal not in matrix:
            fail(f"retired matrix contract is missing {literal!r}")

    print("static v6 binder/controller/transport/stager safety contract: PASS")


if __name__ == "__main__":
    main()
