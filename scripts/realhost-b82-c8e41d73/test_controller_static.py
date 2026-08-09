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

    required_stager = (
        "root-required",
        "host-identity",
        "bundle-file",
        "stage-exists",
        "clone --no-local",
        "checkout --detach",
        "staged-script-hash",
        "/usr/bin/shellcheck",
        "status --porcelain=v1 --untracked-files=all",
        "noclobber",
        "retained=1",
    )
    for literal in required_stager:
        if literal not in stager:
            fail(f"root stager contract is missing {literal!r}")
    if re.search(r"\b(?:apt|apt-get)\b", stager):
        fail("root stager contains package installation")
    if "${EXPECTED_SOURCE}" not in stager or "${STAGE_ROOT}" not in stager:
        fail("root stager does not use the fixed run-owned stage")

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
