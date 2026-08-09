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
    if len(sys.argv) != 6:
        fail(
            "usage: test_controller_static.py BINDER CONTROLLER TRANSPORT "
            "ROOT_STAGER ROOT_MATRIX"
        )
    binder_path, binder = read_regular(sys.argv[1])
    controller_path, controller = read_regular(sys.argv[2])
    transport_path, transport = read_regular(sys.argv[3])
    stager_path, stager = read_regular(sys.argv[4])
    matrix_path, matrix = read_regular(sys.argv[5])

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
        "manifest_line wg_state",
        "absent)",
        '"${WG_INTERFACE}" == \'absent\'',
        "prepare-stage-root.sh",
        "locked-transport.exp",
        "controller.sh",
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
        "BOOTSTRAP_OPERATIONS",
        "bootstrap-absent bootstrap-not-symlink bootstrap-create bootstrap-root-readlink bootstrap-root-stat",
        "bootstrap-stager-readlink bootstrap-stager-sha bootstrap-stager-stat",
        "STAGE_OPERATIONS=(stage-snapshot stage-plan stage-run)",
    )
    for literal in required_controller:
        if literal not in controller:
            fail(f"controller contract is missing {literal!r}")
    if re.search(r"\b(?:apt|apt-get)\b", controller):
        fail("controller contains an implicit package installation path")
    if "open ${CREDENTIAL" in controller or "<\"${CREDENTIAL" in controller:
        fail("controller directly reads the credential file")

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
        "contains:v7.7.0",
        "contains:GNU Make 4.4.1",
        "set assertion empty",
        "wireguard-topology-absent",
        "/usr/bin/test -r /sys/kernel/btf/vmlinux",
        "/usr/bin/findmnt --noheadings --raw --output FSTYPE,TARGET --target /sys/fs/bpf",
        "controller-shellcheck",
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
