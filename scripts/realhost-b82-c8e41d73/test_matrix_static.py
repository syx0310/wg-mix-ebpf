#!/usr/bin/env python3
"""Static contract for retired physical-NIC authority and its stage sentinel."""

from __future__ import annotations

import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


def function_body(source: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(?P<body>.*?)(?=^\}}\n)",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        fail(f"missing shell function {name}")
    return match.group("body")


def require_literals(source: str, label: str, literals: tuple[str, ...]) -> None:
    for literal in literals:
        if literal not in source:
            fail(f"{label} contract is missing {literal!r}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: test_matrix_static.py ROOT_MATRIX ROOT_STAGER")
    matrix_path, stager_path = (pathlib.Path(value) for value in sys.argv[1:])
    if not matrix_path.is_absolute() or not stager_path.is_absolute():
        fail("review paths must be absolute")
    matrix = matrix_path.read_text(encoding="utf-8")
    stager = stager_path.read_text(encoding="utf-8")

    forbidden_patterns = {
        "recursive remove": r"\brm\s+-[^\n]*r",
        "find deletion": r"\bfind\b[^\n]*-delete",
        "batch remover": r"\bxargs\b[^\n]*\brm\b",
        "sync deletion": r"\brsync\b[^\n]*--delete",
        "host root transition": r"\b(chroot|nsenter)\b",
        "container escape": r"\b(docker|podman)\b",
        "cleanup signal handler": r"\btrap\b",
        "dynamic evaluation": r"\beval\b",
        "error suppression": r"\|\|\s*true\b",
        "unbounded loop": r"\bwhile\s+true\b|\bfor\s*\(\s*;\s*;",
    }
    for label, pattern in forbidden_patterns.items():
        if re.search(pattern, matrix + stager):
            fail(f"reviewed scripts contain forbidden {label}")
    if "192.168.10.28" in matrix + stager:
        fail("retired host appears in reviewed scripts")

    require_literals(
        matrix,
        "retired matrix",
        (
            "readonly PHYSICAL_INTERFACE_LOCK='/run/wg-mix-ebpf-realnic-physical-interface.v1.lock'",
            "readonly PHYSICAL_INTERFACE_LOCK_INTERFACE='ens33'",
            "REALHOST_V6_FORWARD_AUTHORITY state=retired replacement=realnic-acceptance",
            "REALHOST_V6_PLAN_SCOPE restore-only=1 network-writes-executed=0 filesystem-writes-executed=0",
            "REALHOST_V6_PLAN_COMPLETE restore_entries=9 no_commands_executed=1",
            "fail 'legacy-forward-authority-retired-use-realnic-acceptance' 78",
            "acquire_physical_interface_lock",
            "physical-interface-lock-replaced-after-acquire",
            "validate_owner_marker",
            "restore_nic_state Z.restore",
            "REALHOST_V6_RESTORE_COMPLETE",
        ),
    )
    for name in ("run_all", "create_evidence_root", "snapshot_host", "run_traffic"):
        if re.search(rf"^{name}\(\)", matrix, re.MULTILINE):
            fail(f"unreachable forward function survived retirement: {name}")
    if "check-realhost-iperf.py" in matrix:
        fail("legacy iperf checker glue survived matrix retirement")

    plan = function_body(matrix, "render_plan")
    if plan.count('plan_command "restore-${cell}"') != 1:
        fail("restore plan must be emitted by one fixed nine-cell loop")
    match = re.search(r"for cell in (?P<cells>[^;]+); do", plan)
    if not match or match.group("cells").split() != [
        "tcx",
        "original",
        "all-on",
        "all-off",
        "tx-path",
        "rx-path",
        "mtu1492",
        "mtu1500",
        "soak",
    ]:
        fail("restore plan cell set is not exact")
    for forward in ("iperf3", 'ethtool -K', "ip link set", "WG_MIX_EBPF_SCOPED_REALNIC_ACTION=run"):
        if forward in plan:
            fail(f"restore-only plan contains forward action {forward!r}")

    top_level = matrix[matrix.rfind('\nparse_arguments "$@"') :]
    retired = top_level.find("legacy-forward-authority-retired-use-realnic-acceptance")
    tooling = top_level.find("require_tooling")
    restore = top_level.find("restore_after_failure")
    if not 0 <= retired < tooling < restore:
        fail("legacy run is not stopped before tooling and restore dispatch")
    restore_body = function_body(matrix, "restore_after_failure")
    ordered = (
        "acquire_physical_interface_lock",
        "validate_common_identity",
        "validate_owner_marker",
        "c8_checksum_module_acquire L0.restore",
        "restore_nic_state Z.restore",
    )
    positions = [restore_body.index(value) for value in ordered]
    if positions != sorted(positions):
        fail("legacy restore lock/identity/mutation order is not exact")

    require_literals(
        stager,
        "root stager",
        (
            'readonly LEGACY_RETIREMENT_RESERVATION="${STAGE_ROOT}/realhost-v6-6bd913ac"',
            "readonly LEGACY_RETIREMENT_RESERVATION_SHAPE='root:root:600:1:0:regular file'",
            "creator=root-stager-O_CREAT|O_EXCL existing=reject-retain",
            "legacy_retirement_reservation=${LEGACY_RETIREMENT_RESERVATION}",
            "legacy_retirement_reservation_shape=${LEGACY_RETIREMENT_RESERVATION_SHAPE}",
            "S3.physical-lock-hold",
            "legacy-retirement-reservation-create",
            "legacy-retirement-reservation-drift",
        ),
    )
    create = function_body(stager, "create_legacy_retirement_reservation")
    require = function_body(stager, "require_legacy_retirement_reservation")
    if (
        '[[ ! -e "${LEGACY_RETIREMENT_RESERVATION}"' not in create
        or '! -L "${LEGACY_RETIREMENT_RESERVATION}"' not in create
        or "set -o noclobber" not in create
        or ': >"${LEGACY_RETIREMENT_RESERVATION}"' not in create
    ):
        fail("stager reservation is not one no-clobber create primitive")
    if '-f "${LEGACY_RETIREMENT_RESERVATION}"' not in require or " -d " in require:
        fail("stager accepts a non-file retirement state")
    stage = function_body(stager, "run_stage")
    ordered = (
        'run_step S3 /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}"',
        "acquire_physical_interface_lock",
        "run_step S3.legacy-reservation create_legacy_retirement_reservation",
        "require_legacy_retirement_reservation",
        "clone --no-local --no-checkout",
        "write_binding_marker",
    )
    positions = [stage.index(value) for value in ordered]
    if positions != sorted(positions):
        fail("stager lock/reservation/clone/binding order is not exact")

    print("static legacy retirement and root-stager reservation contract: PASS")


if __name__ == "__main__":
    main()
