#!/usr/bin/env python3
"""Static and modeled safety contract for the standalone .82 veth runner."""

from __future__ import annotations

from dataclasses import dataclass
import pathlib
import re
import sys
import tempfile


STATE_SCHEMA = (
    "owner,baseline,mutation-plan,veth,tcx,module,cleanup-intent,"
    "restored|filesystem-retained"
)


def fail(message: str) -> None:
    raise SystemExit(message)


def read_regular(path_text: str) -> tuple[pathlib.Path, str]:
    path = pathlib.Path(path_text)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        fail(f"input is not an absolute regular file: {path}")
    return path, path.read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}$",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        fail(f"cannot isolate runner function {name}")
    return match.group("body")


def case_arm(case_body: str, label: str) -> str:
    match = re.search(
        rf"^\s*{re.escape(label)}\)\s*(?P<body>.*?)\s*;;$",
        case_body,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        fail(f"cannot isolate argv operation {label}")
    return match.group("body")


def require_literals(source: str, literals: tuple[str, ...], contract: str) -> None:
    for literal in literals:
        if literal not in source:
            fail(f"{contract} is missing {literal!r}")


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
    """Mirror every independent identity predicate before runner mutation."""
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
            "wrong-path": (wrong, expected, base),
            "relative-path": (pathlib.Path("root-veth-n-r.sh"), expected, base),
            "symlink": (link, expected, {**base, "symlink": True}),
            "mode": (expected, expected, {**base, "mode": 0o755}),
            "uid": (expected, expected, {**base, "uid": 1000}),
            "gid": (expected, expected, {**base, "gid": 1000}),
            "hardlink": (expected, expected, {**base, "nlink": 2}),
            "file-type": (expected, expected, {**base, "regular": False}),
            "sha": (expected, expected, {**base, "sha_equal": False}),
            "blob": (expected, expected, {**base, "blob_equal": False}),
        }
        for label, (invoked, expected_path, values) in cases.items():
            if modeled_self_contract(invoked, expected_path, **values):
                fail(f"modeled self contract accepted {label} drift")


class ModelRejected(RuntimeError):
    """The modeled runner rejected ambiguous or unowned state."""


class FailureCut(RuntimeError):
    """Power/process loss immediately after one audited convergence point."""


@dataclass
class RestoreState:
    owner: bool = True
    baseline: bool = True
    mutation: bool = True
    veth_phase: bool = True
    tcx: str = "phase"  # none, started, run-internal, explicit-internal, phase
    module_phase: bool = True
    cleanup: bool = False
    terminal: str | None = None
    veth: str = "owned"  # absent, owned, partial, unowned
    module: str = "owned"  # absent, owned, unowned
    pin_present: bool = False
    final_matches_baseline: bool = True
    writes: int = 0


def checkpoint(state: RestoreState, name: str, cut_after: str | None) -> None:
    state.writes += 1
    if name == cut_after:
        raise FailureCut(name)


def restore_model(state: RestoreState, cut_after: str | None = None) -> str:
    """Small executable model of the runner's convergent restore state machine."""
    if not state.owner:
        raise ModelRejected("owner")
    if state.terminal == "restored":
        if not state.baseline or state.veth != "absent" or state.module != "absent":
            raise ModelRejected("restored-drift")
        if state.pin_present or not state.final_matches_baseline:
            raise ModelRejected("restored-drift")
        return "already-restored"
    if state.terminal == "filesystem-retained":
        if state.baseline or any(
            (state.mutation, state.veth_phase, state.module_phase, state.cleanup)
        ) or state.tcx != "none":
            raise ModelRejected("filesystem-with-mutation")
        return "filesystem-retained"
    if state.terminal is not None:
        raise ModelRejected("terminal")

    if not state.baseline:
        if any((state.mutation, state.veth_phase, state.module_phase, state.cleanup)):
            raise ModelRejected("filesystem-with-mutation")
        if state.tcx != "none" or state.veth != "absent" or state.module != "absent":
            raise ModelRejected("filesystem-with-resource")
        state.terminal = "filesystem-retained"
        checkpoint(state, "filesystem-retained", cut_after)
        return "filesystem-retained"

    if not state.mutation:
        if state.veth_phase or state.module_phase or state.tcx != "none":
            raise ModelRejected("resource-without-mutation-plan")
        if state.veth != "absent" or state.module != "absent" or state.pin_present:
            raise ModelRejected("resource-without-mutation-plan")
    else:
        if state.veth in {"partial", "unowned"}:
            raise ModelRejected("veth-identity")
        if state.module == "unowned":
            raise ModelRejected("module-identity")
        if not state.cleanup:
            if state.veth_phase and state.veth == "absent":
                raise ModelRejected("veth-absent-before-cleanup-intent")
            if state.module_phase and state.module == "absent":
                raise ModelRejected("module-absent-before-cleanup-intent")
        if not state.veth_phase and state.veth == "owned":
            state.veth_phase = True
            checkpoint(state, "veth-phase", cut_after)
        if not state.module_phase and state.module == "owned":
            state.module_phase = True
            checkpoint(state, "module-phase", cut_after)

        if state.tcx == "started":
            state.tcx = "explicit-internal"
            state.pin_present = False
            checkpoint(state, "tcx-explicit-receipt", cut_after)
        if state.tcx in {"run-internal", "explicit-internal"}:
            receipt = state.tcx
            state.tcx = "phase"
            checkpoint(state, f"tcx-phase-from-{receipt}", cut_after)
        elif state.tcx == "none":
            state.tcx = "phase"
            checkpoint(state, "tcx-phase-not-started", cut_after)
        elif state.tcx != "phase":
            raise ModelRejected("tcx")
        if state.pin_present:
            raise ModelRejected("tcx-pin")

    if not state.cleanup:
        state.cleanup = True
        checkpoint(state, "cleanup-intent", cut_after)

    if state.module_phase:
        if state.module == "owned":
            state.module = "absent"
            checkpoint(state, "module-delete", cut_after)
        elif state.module != "absent":
            raise ModelRejected("module-cleanup")
    elif state.module != "absent":
        raise ModelRejected("unowned-module")

    if state.veth_phase:
        if state.veth == "owned":
            state.veth = "absent"
            checkpoint(state, "veth-delete", cut_after)
        elif state.veth != "absent":
            raise ModelRejected("veth-cleanup")
    elif state.veth != "absent":
        raise ModelRejected("unowned-veth")

    if state.pin_present or not state.final_matches_baseline:
        raise ModelRejected("final-verification")
    checkpoint(state, "final-verify", cut_after)
    state.terminal = "restored"
    checkpoint(state, "restored", cut_after)
    return "restored"


def expect_model_rejection(label: str, state: RestoreState) -> None:
    try:
        restore_model(state)
    except ModelRejected:
        return
    fail(f"modeled restore accepted {label}")


def exercise_failure_cut_model() -> None:
    scenarios = {
        "filesystem-retained": RestoreState(
            baseline=False,
            mutation=False,
            veth_phase=False,
            tcx="none",
            module_phase=False,
            veth="absent",
            module="absent",
        ),
        "veth-phase": RestoreState(veth_phase=False),
        "module-phase": RestoreState(module_phase=False),
        "tcx-explicit-receipt": RestoreState(tcx="started", pin_present=True),
        "tcx-phase-from-run-internal": RestoreState(tcx="run-internal"),
        "tcx-phase-from-explicit-internal": RestoreState(tcx="explicit-internal"),
        "tcx-phase-not-started": RestoreState(tcx="none"),
        "cleanup-intent": RestoreState(),
        "module-delete": RestoreState(cleanup=True),
        "veth-delete": RestoreState(cleanup=True, module="absent"),
        "final-verify": RestoreState(cleanup=True, module="absent", veth="absent"),
        "restored": RestoreState(cleanup=True, module="absent", veth="absent"),
    }
    for cut, state in scenarios.items():
        try:
            restore_model(state, cut)
        except FailureCut as exc:
            if str(exc) != cut:
                fail(f"modeled cut {cut} stopped at {exc}")
        else:
            fail(f"modeled cut {cut} was not reached")
        restore_model(state)
        if cut == "filesystem-retained":
            if state.terminal != "filesystem-retained":
                fail("filesystem-only retry did not retain its distinct terminal")
        elif state.terminal != "restored":
            fail(f"modeled cut {cut} did not converge to restored")

    restored = RestoreState(
        cleanup=True, module="absent", veth="absent", terminal="restored"
    )
    writes = restored.writes
    if restore_model(restored) != "already-restored" or restored.writes != writes:
        fail("already-restored retry created new evidence")

    for label, state in {
        "dual/invalid filesystem terminal": RestoreState(
            baseline=True, terminal="filesystem-retained"
        ),
        "mutation without baseline": RestoreState(baseline=False),
        "partial veth pair": RestoreState(veth="partial"),
        "unowned veth pair": RestoreState(veth="unowned"),
        "unowned module": RestoreState(module="unowned"),
        "unreceipted veth": RestoreState(veth_phase=False, veth="unowned"),
        "unreceipted module": RestoreState(module_phase=False, module="unowned"),
        "module absent before cleanup intent": RestoreState(module="absent"),
        "veth absent before cleanup intent": RestoreState(veth="absent"),
        "final baseline drift": RestoreState(
            cleanup=True,
            module="absent",
            veth="absent",
            final_matches_baseline=False,
        ),
    }.items():
        expect_model_rejection(label, state)


def check_forbidden_operations(runner_path: pathlib.Path, runner: str) -> None:
    patterns = (
        r"\brm\s+-[^\n]*r",
        r"\brmdir\b",
        r"\bunlink\b",
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
        r"\|\|\s*true\b",
        r">\s*/dev/null",
    )
    for pattern in patterns:
        if re.search(pattern, runner, re.MULTILINE):
            fail(f"{runner_path.name} contains prohibited pattern: {pattern}")
    literals = (
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
    for literal in literals:
        if literal in runner:
            fail(f"standalone runner contains forbidden literal: {literal}")
    if re.search(r"\b(?:apt|apt-get)\b", runner):
        fail("standalone runner contains package installation")
    for pattern in (
        r"ip\s+link\s+set\s+dev\s+[^\n]*ens33",
        r"ethtool\s+-K\s+[^\n]*ens33",
        r"tc\s+(?:qdisc|filter)\s+(?:add|change|replace|del)\s+[^\n]*ens33",
    ):
        if re.search(pattern, runner):
            fail(f"runner mutates the read-only interface: {pattern}")


def check_state_machine(runner: str) -> None:
    schemas = re.findall(r"^readonly STATE_SCHEMA='([^']+)'$", runner, re.MULTILINE)
    if schemas != [STATE_SCHEMA]:
        fail(f"runner state schema is not exact: {schemas!r}")
    expected_phases = {
        "OWNER_PHASE": "phase-owner.v1",
        "BASELINE_PHASE": "phase-baseline.v1",
        "MUTATION_PHASE": "phase-mutation-plan.v1",
        "VETH_PHASE": "phase-veth.v1",
        "TCX_PHASE": "phase-tcx.v1",
        "MODULE_PHASE": "phase-module.v1",
        "CLEANUP_PHASE": "phase-cleanup-intent.v1",
        "RESTORED_PHASE": "phase-restored.v1",
        "FILESYSTEM_PHASE": "phase-filesystem-retained.v1",
    }
    found = dict(
        re.findall(
            r'^readonly ([A-Z]+_PHASE)="\$\{EVIDENCE_ROOT\}/([^"/]+)"$',
            runner,
            re.MULTILINE,
        )
    )
    if found != expected_phases:
        fail(f"runner phase files are not the exact state schema: {found!r}")

    cleanup = function_body(runner, "render_cleanup_intent")
    require_literals(
        cleanup,
        (
            'mutation_sha256=$(file_sha_or_absent "${MUTATION_PHASE}")',
            'veth_sha256=$(file_sha_or_absent "${VETH_PHASE}")',
            'tcx_sha256=$(file_sha_or_absent "${TCX_PHASE}")',
            'module_sha256=$(file_sha_or_absent "${MODULE_PHASE}")',
            '"pin=${PIN_PATH}"',
            '"runtime=${TCX_RUNTIME_ROOT}"',
            '"veth_a=${VETH_A}"',
            '"veth_b=${VETH_B}"',
            '"module=${MODULE_NAME}"',
        ),
        "cleanup ownership receipt",
    )
    restore = function_body(runner, "converge_restore")
    require_literals(
        restore,
        (
            '[[ ! -e "${FILESYSTEM_PHASE}" ]] || fail \'dual-terminal-state\'',
            '[[ ! -e "${RESTORED_PHASE}" ]] || fail \'invalid-restored-phase\'',
            "filesystem-terminal-with-mutation",
            "filesystem-phase-with-baseline",
            "ensure_cleanup_intent",
            "converge_module_absent",
            "converge_veth_absent",
            "assert_bpf_baseline R.cleanup-bpf",
            "verify_final_state R.final",
            'write_phase "${RESTORED_PHASE}"',
        ),
        "restore state machine",
    )
    ordered = (
        "ensure_cleanup_intent",
        "converge_module_absent",
        "converge_veth_absent",
        "assert_bpf_baseline R.cleanup-bpf",
        "verify_final_state R.final",
        'write_phase "${RESTORED_PHASE}"',
    )
    if [restore.index(item) for item in ordered] != sorted(restore.index(item) for item in ordered):
        fail("restore ownership, cleanup, verification, and terminal order drifted")
    restored_branch = restore[: restore.index('[[ ! -e "${RESTORED_PHASE}" ]]')]
    if "validate_completed_chain" not in restored_branch or "write_phase" in restored_branch:
        fail("already-restored retry does not validate the full chain read-only")
    filesystem_start = restore.index('if [[ ! -e "${BASELINE_PHASE}" ]]')
    filesystem_end = restore.index('[[ ! -e "${FILESYSTEM_PHASE}" ]]', filesystem_start)
    if 'write_phase "${RESTORED_PHASE}"' in restore[filesystem_start:filesystem_end]:
        fail("filesystem-only convergence can write the restored terminal")
    completed = function_body(runner, "validate_completed_chain")
    require_literals(
        completed,
        (
            "validate_baseline",
            "validate_mutation_plan",
            "ensure_veth_phase",
            "ensure_module_phase",
            "validate_tcx_phase",
            "validate_cleanup_intent",
            "assert_bpf_baseline R.completed-bpf",
        ),
        "already-restored chain validation",
    )
    for function, required in {
        "ensure_veth_phase": ("CLEANUP_PHASE", "partial-veth-pair", "veth-identity-drift"),
        "ensure_module_phase": ("CLEANUP_PHASE", "module-identity-drift"),
        "converge_veth_absent": (
            "VETH_PHASE",
            "cleanup-veth-identity",
            "cleanup-partial-veth",
            "unowned-veth-present",
        ),
        "converge_module_absent": (
            "MODULE_PHASE",
            "cleanup-module-identity",
            "unowned-module-present",
        ),
    }.items():
        require_literals(function_body(runner, function), required, function)
    tcx = function_body(runner, "converge_tcx")
    require_literals(
        tcx,
        (
            "bpffs-restored.v1.json",
            "bpffs-explicit-restore.v1.json",
            "tcx-run-receipt-pin",
            "tcx-restore-receipt-pin",
            "R.tcx-run-cut",
            "R.tcx-restore-cut",
        ),
        "TCX internal-receipt convergence",
    )


def check_shared_argv_and_parser(runner: str) -> None:
    builder = function_body(runner, "build_argv")
    plan_operation = function_body(runner, "plan_operation")
    run_operation = function_body(runner, "run_operation")
    capture_operation = function_body(runner, "capture_operation")
    for name, body in (
        ("bootstrap_operation", function_body(runner, "bootstrap_operation")),
        ("plan_operation", plan_operation),
        ("run_operation", run_operation),
        (
            "run_convergent_operation",
            function_body(runner, "run_convergent_operation"),
        ),
        ("capture_operation", capture_operation),
    ):
        if body.count('build_argv "${operation}"') != 1:
            fail(f"{name} does not use the single shared argv builder exactly once")
    if "run_step" in plan_operation or '"${OP_ARGV[@]}"' not in run_operation:
        fail("plan/run argv execution boundary drifted")
    convergence = function_body(runner, "run_convergent_operation")
    require_literals(
        convergence,
        (
            "audit_line start",
            "audit_line output",
            "audit_line finish",
            'CONVERGENCE_OUTPUT="$("${OP_ARGV[@]}" 2>&1)"',
        ),
        "retry-safe reverse-operation audit",
    )
    if "run_step" in convergence or "STEP_LOG" in convergence:
        fail("reverse convergence can be blocked by a noclobber step receipt")
    for call in (
        "run_convergent_operation R.tcx tcx-restore",
        "run_convergent_operation R.module module-unload",
        "run_convergent_operation R.veth veth-delete",
    ):
        if call not in runner:
            fail(f"dangerous reverse operation is not retry-safe: {call}")

    require_literals(
        builder,
        (
            "bundle-copy)",
            "/usr/bin/timeout --signal=TERM --kill-after=10s 2m",
            "build)",
            "--kill-after=30s 30m",
            "tcx-run | tcx-restore)",
            "outer=3m; inner=2m",
            "action=restore; outer=5m; inner=4m",
            "verifier)",
            "3m",
            "packet-probe)",
            "4m",
            "offload:*)",
            "realhost:*)",
            "6m",
            "module-unload)",
            'OP_ARGV=(/usr/sbin/rmmod "${MODULE_NAME}")',
            "veth-delete)",
            'OP_ARGV=(/usr/sbin/ip link delete dev "${VETH_A}")',
        ),
        "shared argv/timeouts",
    )
    timeout_contracts = {
        "bundle-copy": ("--kill-after=10s 2m",),
        "build": ("--kill-after=30s 30m",),
        "list:*": ("--kill-after=10s 5m",),
        "tcx-run | tcx-restore": (
            "outer=3m; inner=2m",
            "action=restore; outer=5m; inner=4m",
            '"${outer}"',
            '-timeout="${inner}"',
        ),
        "verifier": ("--kill-after=10s 3m",),
        "packet-probe": ("--kill-after=10s 4m", "-timeout=3m"),
        "offload:*": ("--kill-after=10s 3m", "-timeout=2m"),
        "realhost:*": ("--kill-after=10s 6m", "-timeout=5m"),
    }
    for operation, fragments in timeout_contracts.items():
        require_literals(case_arm(builder, operation), fragments, f"{operation} timeout")
    plan = function_body(runner, "render_plan")
    require_literals(
        plan,
        (
            "plan_operation R.tcx tcx-restore",
            "plan_operation R.module module-unload",
            "plan_operation R.veth veth-delete",
            'for spec in "${FINAL_SPECS[@]}"',
            "argv_builder=shared",
            "commands_are_review_templates=1 no_commands_executed=1",
        ),
        "complete plan",
    )
    verify_final = function_body(runner, "verify_final_state")
    require_literals(
        verify_final,
        (
            "snapshot:netns",
            '! -e "${PIN_PATH}"',
            '! -e "/sys/module/${MODULE_NAME}"',
            '"$(veth_presence)" == 00',
            'for spec in "${FINAL_SPECS[@]}"',
            "compare_baseline",
        ),
        "final verification",
    )

    parser = function_body(runner, "parse_arguments")
    options = {
        "--controller-source": ("seen_source", "CONTROLLER_SOURCE"),
        "--commit": ("seen_commit", "COMMIT"),
        "--bundle": ("seen_bundle", "BUNDLE"),
        "--bundle-sha256": ("seen_bundle_sha", "BUNDLE_SHA256"),
        "--wg-state": ("seen_wg", "WG_STATE"),
    }
    for option, (seen, variable) in options.items():
        pattern = (
            rf"{re.escape(option)}\)\s*\n\s*\(\({seen} == 0\)\) \|\| return 65\s*\n"
            rf'\s*{seen}=1; {variable}="\$2"'
        )
        if re.search(pattern, parser) is None:
            fail(f"parser lacks duplicate guard for {option}")
    if parser.count("seen_commit == 0") != 1 or "seen_commit == 1" not in parser:
        fail("second --commit is not rejected and exactly one --commit required")


def check_self_and_tooling(runner: str) -> None:
    controller = function_body(runner, "validate_controller_identity")
    require_literals(
        controller,
        (
            '[[ "$0" == /* && "$0" == "${self_path}" && -f "$0" && ! -L "$0" ]]',
            '/usr/bin/readlink -e -- "$0"',
            "/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- \"$0\"",
            "0:0:700:1:regular file",
            "hash-object --",
            'rev-parse "${COMMIT}:${SELF_PATH_FROM_ROOT}"',
            'show "${COMMIT}:${SELF_PATH_FROM_ROOT}" | /usr/bin/sha256sum',
            '"${actual_blob}" == "${commit_blob}"',
            '"${actual_sha}" == "${commit_sha}"',
        ),
        "runner self path/mode/blob/SHA identity",
    )
    run_all = function_body(runner, "run_all")
    restore_all = function_body(runner, "restore_all")
    if not run_all.lstrip().startswith("validate_controller_identity"):
        fail("run does not validate controller/self identity before mutation")
    if not restore_all.lstrip().startswith("validate_controller_identity"):
        fail("restore does not validate controller/self identity first")
    if "validate_package_bundle" in restore_all or "validate_staged_source" not in function_body(runner, "converge_restore"):
        fail("restore depends on mutable package or omits retained source validation")
    gate = "((EUID == 0)) || fail 'root-required' 77\nrequire_tooling\ncase"
    if gate not in runner:
        fail("non-plan dispatch does not gate EUID before tooling")

    tooling = function_body(runner, "require_tooling")
    absolute_commands = set(re.findall(r"/(?:usr/)?(?:s?bin)/[A-Za-z0-9_.-]+", runner))
    absolute_commands.discard("/bin/wg-mix-ebpf")  # commit-bound built artifact
    missing = sorted(command for command in absolute_commands if command not in tooling)
    if missing:
        fail(f"absolute commands missing from require_tooling: {missing}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: test_veth_runner_static.py ROOT_VETH_RUNNER EXISTING_ROOT_MATRIX")
    runner_path, runner = read_regular(sys.argv[1])
    matrix_path, matrix = read_regular(sys.argv[2])

    check_forbidden_operations(runner_path, runner)
    require_literals(
        runner,
        (
            "readonly VETH_RUN_ID='a19f7c2e'",
            "readonly RESOURCE_ID='d34b8e65'",
            'readonly VETH_STAGE_ROOT="${STAGES_ROOT}/${VETH_RUN_ID}"',
            'readonly ROOT_BUNDLE="${VETH_STAGE_ROOT}/source-${PACKAGE_ID}-${RESOURCE_ID}.bundle"',
            'readonly EVIDENCE_ROOT="${VETH_STAGE_ROOT}/veth-evidence-${RESOURCE_ID}"',
            'readonly PIN_PATH="/sys/fs/bpf/wg-mix-ebpf-${VETH_RUN_ID}-tcx"',
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
            "/usr/bin/cp --no-clobber --no-preserve=mode,ownership,timestamps",
            'clone --no-local --no-checkout -- "${ROOT_BUNDLE}"',
            "no automatic teardown",
        ),
        "standalone runner contract",
    )
    if re.search(r'clone[^\n]*"\$\{BUNDLE\}"', runner):
        fail("runner clones directly from the user-owned package bundle")
    check_state_machine(runner)
    check_shared_argv_and_parser(runner)
    check_self_and_tooling(runner)
    exercise_self_identity_failures()
    exercise_failure_cut_model()

    if "readonly RUN_ID='c8e41d73'" not in matrix:
        fail(f"existing matrix identity changed in {matrix_path}")
    if "a19f7c2e" in matrix or "d34b8e65" in matrix:
        fail(f"standalone veth identity leaked into existing matrix {matrix_path}")
    print(
        "static standalone veth runner: PASS "
        "state_positions=8 failure_cut_fixtures=12"
    )


if __name__ == "__main__":
    main()
