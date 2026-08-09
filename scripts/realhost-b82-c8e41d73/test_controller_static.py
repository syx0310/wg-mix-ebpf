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
        "wg-mix-ebpf-b82-v6-package-v2",
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
        "B82_V6_MATRIX_BLOCKED reason=wireguard-topology-absent",
        "require_bound_wireguard",
        "fail 'wireguard-topology-absent' 78",
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
        "wireguard-topology-absent",
        "/usr/bin/test -r /sys/kernel/btf/vmlinux",
        "/usr/bin/findmnt --noheadings --raw --output FSTYPE,TARGET --target /sys/fs/bpf",
        "controller-shellcheck",
        "hermetic-fresh",
        "proc fresh_remote_argv",
        "fresh-plan - fresh-run - fresh-restore",
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
        "staged-script-hash",
        "/usr/bin/shellcheck",
        "status --porcelain=v1 --untracked-files=all",
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
    if stager.count('readonly BOOTSTRAP_ROOT="/run/wg-mix-ebpf-source-bootstrap-${RUN_ID}"') != 1:
        fail("root stager has zero or multiple bootstrap roots")

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
    )
    for literal in matrix_forbidden:
        if literal in matrix:
            fail(f"existing matrix contains prohibited literal: {literal}")
    if "readonly RUN_ID='c8e41d73'" not in matrix:
        fail("existing matrix run identity changed")

    print("static v6 binder/controller/transport/stager safety contract: PASS")


if __name__ == "__main__":
    main()
