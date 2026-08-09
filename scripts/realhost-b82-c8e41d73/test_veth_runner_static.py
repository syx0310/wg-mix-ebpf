#!/usr/bin/env python3
"""Static and modeled safety contract for the standalone .82 veth runner."""

from __future__ import annotations

import pathlib
import re
import stat
import sys
import tempfile


def fail(message: str) -> None:
    raise SystemExit(message)


def read_regular(path_text: str) -> tuple[pathlib.Path, str]:
    path = pathlib.Path(path_text)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        fail(f"input is not an absolute regular file: {path}")
    return path, path.read_text(encoding="utf-8")


def modeled_self_contract(
    invoked: pathlib.Path,
    expected: pathlib.Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    nlink: int,
    regular: bool,
    symlink: bool,
    sha_equal: bool,
    blob_equal: bool,
) -> bool:
    """Mirror every independent predicate enforced before runner mutation."""
    return (
        invoked.is_absolute()
        and invoked == expected
        and invoked.resolve(strict=False) == expected
        and uid == 0
        and gid == 0
        and mode == 0o700
        and nlink == 1
        and regular
        and not symlink
        and sha_equal
        and blob_equal
    )


def exercise_self_identity_failures() -> None:
    with tempfile.TemporaryDirectory(prefix="wg-mix-veth-self-contract-") as root_text:
        root = pathlib.Path(root_text).resolve()
        expected = root / "root-owned" / "root-veth-n-r.sh"
        expected.parent.mkdir(mode=0o700)
        expected.write_text("fixture\n", encoding="utf-8")
        expected.chmod(0o700)
        wrong = root / "elsewhere" / "root-veth-n-r.sh"
        wrong.parent.mkdir(mode=0o700)
        wrong.write_text("fixture\n", encoding="utf-8")
        wrong.chmod(0o700)
        link = root / "runner-link"
        link.symlink_to(expected)
        base = dict(
            uid=0,
            gid=0,
            mode=0o700,
            nlink=1,
            regular=True,
            symlink=False,
            sha_equal=True,
            blob_equal=True,
        )
        if not modeled_self_contract(expected, expected, **base):
            fail("modeled exact root-owned self identity was rejected")
        cases = {
            "wrong-self-path": (wrong, expected, base),
            "relative-self-path": (pathlib.Path("root-veth-n-r.sh"), expected, base),
            "symlink-self": (link, expected, {**base, "symlink": True}),
            "mode-drift": (expected, expected, {**base, "mode": 0o755}),
            "owner-drift": (expected, expected, {**base, "uid": 1000}),
            "hardlink-drift": (expected, expected, {**base, "nlink": 2}),
            "sha-drift": (expected, expected, {**base, "sha_equal": False}),
            "blob-drift": (expected, expected, {**base, "blob_equal": False}),
        }
        for label, (invoked, expected_path, values) in cases.items():
            if modeled_self_contract(invoked, expected_path, **values):
                fail(f"modeled self contract accepted {label}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: test_veth_runner_static.py ROOT_VETH_RUNNER EXISTING_ROOT_MATRIX")
    runner_path, runner = read_regular(sys.argv[1])
    matrix_path, matrix = read_regular(sys.argv[2])

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
        r"(?:^|\s)--privileged(?:\s|$)",
    )
    for pattern in forbidden_patterns:
        if re.search(pattern, runner, re.MULTILINE):
            fail(f"{runner_path.name} contains prohibited executable pattern: {pattern}")

    forbidden_literals = (
        "/usr/bin/ssh",
        "/usr/bin/scp",
        "/usr/bin/sudo",
        "credientials/",
        "--remote-argv",
        "ethtool -K",
        "qdisc add",
        "qdisc del",
        "qdisc replace",
        "filter add",
        "filter del",
        "filter replace",
        "route add",
        "route del",
        "route replace",
        "WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION=1",
    )
    for literal in forbidden_literals:
        if literal in runner:
            fail(f"standalone runner contains forbidden literal: {literal}")
    if re.search(r"\b(?:apt|apt-get)\b", runner):
        fail("standalone runner contains package installation")

    required_literals = (
        "readonly VETH_RUN_ID='a19f7c2e'",
        "readonly RESOURCE_ID='d34b8e65'",
        'readonly VETH_STAGE_ROOT="${STAGES_ROOT}/${VETH_RUN_ID}"',
        'readonly ROOT_BUNDLE="${VETH_STAGE_ROOT}/source-${PACKAGE_ID}-${RESOURCE_ID}.bundle"',
        'readonly EVIDENCE_ROOT="${VETH_STAGE_ROOT}/veth-evidence-${RESOURCE_ID}"',
        'readonly PIN_PATH="/sys/fs/bpf/wg-mix-ebpf-${VETH_RUN_ID}-tcx"',
        'readonly TCX_RUNTIME_ROOT="${EVIDENCE_ROOT}/tcx-runtime"',
        "plan | run | restore",
        '"${WG_STATE}" == \'absent\'',
        "commands_are_review_templates=1 no_commands_executed=1",
        "wg_active_scoped=not-covered pass=0",
        "raw_ens33=not-covered raw_ens33_pass=0",
        "peer_47=read-only peer_access=0",
        "capability_bits_changed=0",
        "TestBPFFSPinLifecycleIntegration",
        "TestFakeTCPBPFPacketProbe",
        "TestExperimentalFakeTCPRealHostLifecycleIntegration",
        "TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration",
        "TestBaselineExperimentalRealHostMutualExclusionIntegration",
        "TestFakeTCPRealHostVirtioNetHeaderEncoding",
        "TestFakeTCPRealHostGSOOutputMatcher",
        "TestFakeTCPRealHostGSOProbeIsolationContract",
        "validate_owner_marker",
        "verify_created_veth",
        "restore_exact_tcx_lifecycle",
        "unload_checksum_module",
        "delete_owned_veth",
        "verify_final_state",
        "snapshot-missing-with-mutation-intent",
        "module-loaded-without-ownership-marker",
        "veth-created-without-identity-marker",
        "no automatic teardown",
        "/usr/bin/cp --no-clobber --no-preserve=mode,ownership,timestamps",
        "/usr/bin/chmod 0600",
        "root-bundle-hash-mismatch",
        'clone --no-local --no-checkout -- "${ROOT_BUNDLE}"',
    )
    for literal in required_literals:
        if literal not in runner:
            fail(f"standalone runner contract is missing {literal!r}")

    self_literals = (
        '[[ "$0" == /* && "$0" == "${self_path}" ]]',
        '[[ -f "$0" && ! -L "$0" ]]',
        "/usr/bin/readlink -e -- \"$0\"",
        "/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- \"$0\"",
        "0:0:700:1:regular file",
        "runner-self-metadata",
        "runner-self-sha256",
        "runner-committed-sha256",
        "runner-sha256-mismatch",
        "hash-object --",
        'rev-parse "${COMMIT}:${SELF_PATH_FROM_ROOT}"',
    )
    for literal in self_literals:
        if literal not in runner:
            fail(f"runner self-identity contract is missing {literal!r}")
    if runner.index("((EUID == 0)) || fail 'root-required' 77") > runner.index("require_tooling\ncase"):
        fail("root gate does not precede tooling and every non-plan dispatch")
    if "\n((EUID == 0)) || fail 'root-required' 77\nrequire_tooling\ncase" not in runner:
        fail("non-plan dispatch does not fail on EUID before tooling")
    run_all_match = re.search(r"run_all\(\) \{(?P<body>.*?)\n\}", runner, re.DOTALL)
    restore_match = re.search(r"restore_after_failure\(\) \{(?P<body>.*?)\n\}", runner, re.DOTALL)
    if run_all_match is None or restore_match is None:
        fail("cannot isolate run and restore entry points")
    if "validate_package_bundle" not in run_all_match.group("body"):
        fail("run does not bind the user package before the root-owned copy")
    if "validate_package_bundle" in restore_match.group("body"):
        fail("restore incorrectly depends on the mutable user package bundle")
    if "validate_veth_source" not in restore_match.group("body"):
        fail("restore does not bind the retained root-owned source and bundle")

    tooling_match = re.search(r"require_tooling\(\) \{(?P<body>.*?)\n\}", runner, re.DOTALL)
    plan_match = re.search(r"render_plan\(\) \{(?P<body>.*?)\n\}", runner, re.DOTALL)
    if tooling_match is None or plan_match is None:
        fail("cannot isolate tooling or plan functions")
    tooling = tooling_match.group("body")
    plan = plan_match.group("body")
    absolute_commands = set(
        re.findall(r"/(?:usr/)?(?:s?bin)/[A-Za-z0-9_.-]+", runner)
    )
    absolute_commands.discard("/bin/wg-mix-ebpf")  # commit-bound built artifact
    missing_tools = sorted(command for command in absolute_commands if command not in tooling)
    if missing_tools:
        fail(f"absolute commands missing from require_tooling: {missing_tools}")
    for literal in (
        "S0.copy",
        "/usr/bin/cp --no-clobber --no-preserve=mode,ownership,timestamps",
        "S0.mode",
        "/usr/bin/chmod 0600",
        'clone --no-local --no-checkout -- "${ROOT_BUNDLE}"',
        "S3.cache",
        "S3.mod-cache",
        "S3.go-path",
        "S3.tmp",
        "N.add",
        "M.load",
        "R.tcx",
        "R.module",
        "R.veth",
        "B82_VETH_V6_WRITE_SET",
    ):
        if literal not in plan:
            fail(f"complete plan is missing write/restoration template {literal!r}")
    if re.search(r'clone[^\n]*"\$\{BUNDLE\}"', runner):
        fail("runner clones directly from the user-owned package bundle")

    mutable_interface_patterns = (
        r"ip\s+link\s+set\s+dev\s+[^\n]*ens33",
        r"ethtool\s+-K\s+[^\n]*ens33",
        r"tc\s+(?:qdisc|filter)\s+(?:add|change|replace|del)\s+[^\n]*ens33",
    )
    for pattern in mutable_interface_patterns:
        if re.search(pattern, runner):
            fail(f"runner mutates the read-only interface: {pattern}")

    if "readonly RUN_ID='c8e41d73'" not in matrix:
        fail(f"existing matrix identity changed in {matrix_path}")
    exercise_self_identity_failures()
    print("static standalone veth runner safety and ownership contract: PASS")


if __name__ == "__main__":
    main()
