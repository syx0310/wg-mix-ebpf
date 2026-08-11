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
            "readonly RUN_ID='c8e41d73'",
            "REALHOST_V6_FORWARD_AUTHORITY state=retired replacement=realnic-acceptance-v1",
            "REALHOST_V6_LEGACY_CONTROLLER_AUTHORITY state=retired controller_entries=0 restore_entries=0",
            "REALHOST_V6_HISTORICAL_RECOVERY package=frozen-original-package timing=before-final-staging",
            "REALHOST_V6_PLAN_COMPLETE commands_executed=0 filesystem_writes=0 network_writes=0",
            "legacy-matrix-retired-use-frozen-original-package-before-final-staging",
            "run | restore)",
            "return 78",
        ),
    )
    functions = set(re.findall(r"^([a-z][a-z0-9_]*)\(\) \{", matrix, re.MULTILINE))
    if functions != {"usage", "retired", "main"}:
        fail(f"legacy executable authority survived retirement: {sorted(functions)}")
    retired_forbidden = (
        "/usr/sbin/ethtool",
        "/usr/sbin/ip",
        "/usr/sbin/bpftool",
        "/usr/bin/iperf3",
        "/usr/bin/flock",
        "/usr/bin/sudo",
        "/usr/bin/mkdir",
        "WG_MIX_EBPF_",
        "--restore-cell",
        "/sys/",
        "/run/wg-mix-ebpf-source-stages/",
    )
    for literal in retired_forbidden:
        if literal in matrix:
            fail(f"retired matrix retains executable authority {literal!r}")
    main_body = function_body(matrix, "main")
    if len(re.findall(r"^\s+retired$", main_body, re.MULTILINE)) != 1 or "run | restore)" not in main_body:
        fail("run and restore do not share one unconditional retirement exit")
    if not matrix.rstrip().endswith('main "$@"'):
        fail("retired matrix does not have one fixed entrypoint")

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
            '"${MODULE_SOURCE_PATH}" == \'kernel/faketcp_checksum/wg_mix_faketcp_checksum.c\'',
        ),
    )
    staged_content = function_body(stager, "require_staged_content")
    require_literals(
        staged_content,
        "root stager checksum C identity",
        (
            '"$(sha256_file "${EXPECTED_SOURCE}/${MODULE_SOURCE_PATH}")" == '
            '"${MODULE_SOURCE_SHA256}"',
            'require_staged_identity "${MODULE_SOURCE_PATH}" "${MODULE_SOURCE_BLOB}"',
            '"${MODULE_SOURCE_SHA256}" 100644 600',
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
