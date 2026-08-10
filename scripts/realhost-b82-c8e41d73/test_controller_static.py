#!/usr/bin/env python3
"""Static safety contract for the v6 binder, controller, transport and stager."""

from __future__ import annotations

import ast
import hashlib
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


def bash_function(payload: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(name)}\(\) \{{\n(?P<body>.*?)^\}}\n", payload
    )
    if not match:
        fail(f"cannot isolate Bash function {name}")
    return match.group("body")


def bash_array(payload: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^readonly -a {re.escape(name)}=\((?P<body>.*?)\)\n", payload
    )
    if not match:
        fail(f"cannot isolate Bash array {name}")
    return match.group("body").strip("\n")


def tcl_proc(payload: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^proc {re.escape(name)} \{{[^}}]*\}} \{{\n(?P<body>.*?)^\}}\n",
        payload,
    )
    if not match:
        fail(f"cannot isolate Tcl procedure {name}")
    return match.group("body")


def indented_tcl_proc(payload: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^(?P<indent>[ \t]+)proc {re.escape(name)} "
        rf"\{{[^}}]*\}} \{{\n(?P<body>.*?)^(?P=indent)\}}\n",
        payload,
    )
    if not match:
        fail(f"cannot isolate indented Tcl procedure {name}")
    return match.group("body")


def python_function(payload: str, name: str) -> str:
    match = re.search(rf"(?m)^def {re.escape(name)}\(", payload)
    if not match:
        fail(f"cannot isolate embedded Python function {name}")
    start = match.start()
    following = re.search(
        r"(?m)^(?:def [A-Za-z_][A-Za-z0-9_]*\(|class [A-Za-z_][A-Za-z0-9_]*|try:\s*$)",
        payload[start + 1 :],
    )
    end = len(payload) if not following else start + 1 + following.start()
    return payload[start:end]


def python_string_tuple(payload: str, name: str) -> tuple[str, ...]:
    tree = ast.parse(payload)
    matches = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    if len(matches) != 1:
        fail(f"cannot isolate Python tuple {name}")
    try:
        value = ast.literal_eval(matches[0])
    except (TypeError, ValueError) as exc:
        fail(f"Python tuple {name} is not literal: {exc}")
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        fail(f"Python tuple {name} is not an exact string tuple")
    return value


def bash_function_until(payload: str, name: str, next_name: str) -> str:
    start_marker = f"{name}() {{\n"
    end_marker = f"\n\n{next_name}() {{\n"
    if payload.count(start_marker) != 1 or payload.count(end_marker) != 1:
        fail(f"cannot isolate Bash function {name} before {next_name}")
    start = payload.index(start_marker) + len(start_marker)
    end = payload.index(end_marker, start)
    body = payload[start:end]
    closing = re.search(r"\n}\n?$", body)
    if not closing:
        fail(f"Bash function {name} has no exact closing brace before {next_name}")
    return body[: closing.start()]


def ordered_unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def tcl_return_words(payload: str, name: str) -> tuple[str, ...]:
    match = re.search(
        rf"(?ms)^proc {re.escape(name)} \{{[^\n]*\}} \{{\s*return \{{(.*?)\}}\s*\}}\n",
        payload,
    )
    if not match:
        fail(f"cannot isolate fixed Tcl list {name}")
    return tuple(match.group(1).split())


def tcl_literal_return_words(payload: str, name: str) -> tuple[str, ...]:
    """Return a Tcl proc's sole literal list, permitting only comments around it."""
    body = tcl_proc(payload, name)
    uncommented = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    ).strip()
    match = re.fullmatch(r"return \{(?P<body>.*)\}", uncommented, re.DOTALL)
    if not match:
        fail(f"Tcl procedure {name} is not a sole fixed literal list")
    return tuple(match.group("body").split())


def ordered(body: str, literals: tuple[str, ...], contract: str) -> None:
    remaining = body
    for literal in literals:
        position = remaining.find(literal)
        if position < 0:
            fail(f"{contract} is missing ordered literal {literal!r}")
        remaining = remaining[position + len(literal) :]


def validate_engine_harness_execution_ast(payload: str) -> None:
    """Bind the actual engine child dispatch, output oracle and rc controls."""
    try:
        tree = ast.parse(payload)
    except SyntaxError as exc:
        fail(f"hermetic R2 engine harness is not valid Python: {exc}")

    def one_function(name: str) -> ast.FunctionDef:
        matches = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        if len(matches) != 1:
            fail(f"hermetic R2 engine harness function is not unique: {name}")
        return matches[0]

    def dump_expression(source: str) -> str:
        return ast.dump(
            ast.parse(source, mode="eval").body, include_attributes=False
        )

    module_main_calls = [
        node
        for node in tree.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "main"
    ]
    if (
        len(module_main_calls) != 1
        or tree.body[-1] is not module_main_calls[0]
        or module_main_calls[0].value.args
        or module_main_calls[0].value.keywords
    ):
        fail("hermetic R2 engine harness does not end in one direct main() dispatch")

    main_node = one_function("main")
    if (
        len(main_node.body) != 3
        or not isinstance(main_node.body[0], ast.If)
        or not isinstance(main_node.body[1], ast.If)
        or not isinstance(main_node.body[2], ast.Expr)
    ):
        fail("hermetic R2 engine harness main dispatch shape drifted")
    child_branch = main_node.body[0]
    if ast.dump(child_branch.test, include_attributes=False) != dump_expression(
        'len(sys.argv) >= 2 and sys.argv[1] == "child"'
    ) or tuple(type(node) for node in child_branch.body) != (
        ast.If,
        ast.Assign,
        ast.Assign,
        ast.Assign,
        ast.Assign,
        ast.If,
        ast.Assign,
        ast.Expr,
        ast.Return,
    ):
        fail("hermetic R2 engine child branch is not exact and reachable")
    expected_child_argc_gate = ast.parse(
        "if len(sys.argv) != 12:\n"
        "    raise SystemExit(64)\n"
    ).body[0]
    expected_child_cut_gate = ast.parse(
        "if (expected_renames < -1 or expected_renames > 4 or\n"
        "        cut_call not in {0, 1, 2, 3, 4} or\n"
        "        cut_phase not in {'none', 'pre', 'post'} or\n"
        "        cut_kind not in {'none', 'exit91', 'sigterm'} or\n"
        "        ((cut_call == 0) != (cut_phase == 'none')) or\n"
        "        ((cut_call == 0) != (cut_kind == 'none'))):\n"
        "    raise SystemExit(64)\n"
    ).body[0]
    if (
        ast.dump(child_branch.body[0], include_attributes=False)
        != ast.dump(expected_child_argc_gate, include_attributes=False)
        or ast.dump(child_branch.body[5], include_attributes=False)
        != ast.dump(expected_child_cut_gate, include_attributes=False)
    ):
        fail("hermetic R2 engine child argc/cut coupling gates are not exact")
    expected_child_bindings = (
        "expected_renames = int(sys.argv[8])",
        "cut_call = int(sys.argv[9])",
        "cut_phase = sys.argv[10]",
        "cut_kind = sys.argv[11]",
        "manifest_sha = digest(sys.argv[3])",
    )
    actual_child_bindings = (
        *child_branch.body[1:5],
        child_branch.body[6],
    )
    if tuple(
        ast.dump(node, include_attributes=False) for node in actual_child_bindings
    ) != tuple(
        ast.dump(ast.parse(source).body[0], include_attributes=False)
        for source in expected_child_bindings
    ):
        fail("hermetic R2 engine child argv bindings drifted")
    child_call_statement = child_branch.body[-2]
    expected_child_call = dump_expression(
        "execute_engine_child(sys.argv[2], sys.argv[6], sys.argv[7], "
        "manifest_sha, expected_renames, cut_call, cut_phase, cut_kind)"
    )
    if (
        not isinstance(child_call_statement, ast.Expr)
        or ast.dump(child_call_statement.value, include_attributes=False)
        != expected_child_call
        or not isinstance(child_branch.body[-1], ast.Return)
        or child_branch.body[-1].value is not None
    ):
        fail("hermetic R2 engine child branch omits actual execute_engine_child")
    execute_child_calls = [
        node
        for node in ast.walk(main_node)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "execute_engine_child"
    ]
    driver_calls = [
        node
        for node in ast.walk(main_node)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "driver"
    ]
    expected_nonchild_argc_gate = ast.parse(
        "if len(sys.argv) != 6:\n"
        "    raise SystemExit(64)\n"
    ).body[0]
    if (
        len(execute_child_calls) != 1
        or len(driver_calls) != 1
        or ast.dump(main_node.body[1], include_attributes=False)
        != ast.dump(expected_nonchild_argc_gate, include_attributes=False)
        or ast.dump(driver_calls[0], include_attributes=False)
        != dump_expression(
            "driver(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], "
            "sys.argv[5])"
        )
        or main_node.body[2].value is not driver_calls[0]
    ):
        fail("hermetic R2 engine main child/non-child dispatch is not exact")

    exact_line_node = one_function("exact_line")
    expected_exact_line = ast.parse(
        "def exact_line(output, expected):\n"
        "    if output.splitlines().count(expected) != 1:\n"
        "        raise AssertionError(\"exact-output-line:%s:%s\" % "
        "(expected, output))\n"
    ).body[0]
    if ast.dump(exact_line_node, include_attributes=False) != ast.dump(
        expected_exact_line, include_attributes=False
    ):
        fail("hermetic R2 engine exact_line is not a real exact-once assertion")

    driver_node = one_function("driver")
    actual_exact_calls = sorted(
        (
            node
            for node in ast.walk(driver_node)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "exact_line"
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    expected_exact_calls = (
        "exact_line(result.stdout, "
        "'B82_V6_RETIREMENT_COMPLETE state=T disposition=advanced "
        "namespace_writes=6 same_boot=1')",
        "exact_line(verify.stdout, "
        "'B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 same_boot=1 "
        "receipt=' + PATHS['receipt_final'])",
        "exact_line(resumed.stdout, "
        "'B82_V6_RETIREMENT_COMPLETE state=T disposition=verified-existing "
        "namespace_writes=0 same_boot=1')",
        "exact_line(resumed.stdout, "
        "'B82_V6_RETIREMENT_COMPLETE state=T disposition=advanced "
        "namespace_writes=%s same_boot=1' % resume_writes)",
        "exact_line(verified.stdout, "
        "'B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 same_boot=1 "
        "receipt=' + PATHS['receipt_final'])",
        "exact_line(failed.stdout, "
        "'B82_V6_RETIREMENT_ENGINE_STOP reason=%s rc=79 cleanup=0 retained=1' "
        "% reason)",
    )
    if tuple(
        ast.dump(node, include_attributes=False) for node in actual_exact_calls
    ) != tuple(dump_expression(source) for source in expected_exact_calls):
        fail("hermetic R2 engine driver does not route six outputs through exact_line")

    returncode_ifs = sorted(
        (
            node
            for node in ast.walk(driver_node)
            if isinstance(node, ast.If)
            and any(
                isinstance(child, ast.Attribute) and child.attr == "returncode"
                for child in ast.walk(node.test)
            )
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    expected_returncode_tests = (
        "result.returncode != 0",
        "verify.returncode != 0",
        "interrupted.returncode != expected_rc",
        "resumed.returncode != 0",
        "verified.returncode != 0",
        "failed.returncode != 79 or elapsed >= 5.0",
    )
    if (
        tuple(
            ast.dump(node.test, include_attributes=False)
            for node in returncode_ifs
        )
        != tuple(dump_expression(source) for source in expected_returncode_tests)
        or any(
            len(node.body) != 1
            or not isinstance(node.body[0], ast.Raise)
            or node.orelse
            for node in returncode_ifs
        )
    ):
        fail("hermetic R2 engine returncode results are not six direct fail-closed gates")

    run_process_node = one_function("run_engine_process")
    execute_child_node = one_function("execute_engine_child")
    run_returns = [
        node for node in ast.walk(run_process_node) if isinstance(node, ast.Return)
    ]
    if (
        tuple(type(node) for node in run_process_node.body) != (ast.Assign, ast.Try)
        or len(run_returns) != 1
        or not run_process_node.body[1].body
        or run_process_node.body[1].body[0] is not run_returns[0]
        or any(isinstance(node, ast.Return) for node in ast.walk(execute_child_node))
        or tuple(type(node) for node in execute_child_node.body)
        != (ast.Assign, ast.Assign, ast.Assign, ast.Expr, ast.If, ast.Expr)
    ):
        fail("hermetic R2 engine process/child execution contains an early return")


def manifest_reader_keys(payload: str, function_name: str) -> tuple[str, ...]:
    body = bash_function(payload, function_name)
    return tuple(
        re.findall(r"(?m)^\s*read_manifest_field ([a-z0-9_]+) [A-Z_a-z0-9{}\"$-]+", body)
    )


def array_path_basenames(body: str) -> tuple[str, ...]:
    return tuple(re.findall(r'/([A-Za-z0-9_.-]+)"', body))


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
    fresh_path, fresh = read_regular(
        str(controller_path.with_name("root-fresh-verifier-gate.sh"))
    )
    realnic_path, realnic = read_regular(
        str(
            controller_path.parent.parent
            / "realhost-b82-acceptance-v1"
            / "realnic_acceptance.py"
        )
    )
    hermetic_path, hermetic = read_regular(
        str(controller_path.with_name("test-hermetic-controller.sh"))
    )

    production = {
        binder_path.name: binder,
        controller_path.name: controller,
        transport_path.name: transport,
        stager_path.name: stager,
        fresh_path.name: fresh,
    }
    retained_retirement_commit = "4bdfdfd9075669566d5137de4550aefb240d13c4"
    retained_retirement_manifest_sha = (
        "c4532671304d30755b1c42bb55f82186d96df3f6c84af73078ca16c3fddfe4e6"
    )
    retained_retirement_helper_sha = (
        "a4a1c89dcd9f087b79149f52a01346ed6db5c209ad4985bdbb8c9132276c0077"
    )
    retained_retirement_receipt_sha = (
        "4c3e9bfd3d4e64f6626abaa43e20cf5e4df6b193395cee6a39953b1c4da7d188"
    )
    r2_predecessor_commit = "f75fe7678cfdecf08173fd201be5c055417d6e11"
    r2_predecessor_manifest_sha = (
        "2d6c6caac080b599fbfa0f73c64f6976cf30d1504fc506ebd39c638b2f9449e3"
    )
    r2_predecessor_bundle_sha = (
        "b74811808e0413714dcf20b8292fe68631f603c0b9a68bc9951af481477b413b"
    )
    r2_predecessor_package = (
        "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-f75fe7678cfd"
    )
    r2_predecessor_remote_package = (
        "/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61"
    )
    r2_predecessor_bootstrap = "/run/wg-mix-ebpf-source-bootstrap-c8e41d73"
    r2_retire_id = "c8e41d73-f75fe7678cfd-r2"
    r2_user_intake = (
        "/home/siyixuan/wg-mix-ebpf-test/"
        "retire-postflight-c8e41d73-f75fe7678cfd-r2.intake"
    )
    r2_home_qroot = "/home/.wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2"
    r2_run_qroot = "/run/wg-mix-ebpf-retirement-c8e41d73-f75fe7678cfd-r2"
    r2_predecessor_package_contract = (
        ("source-4f2a9b61.bundle", r2_predecessor_bundle_sha, 2469874),
        ("package-manifest.v1", r2_predecessor_manifest_sha, 7315),
        ("bind-final-package.sh", "a808a7879ef64190eff9e81e6b694acea7bc04b1b74ffad44109b237a5eb14ca", 17015),
        ("controller.sh", "fb8a7a685b5a6b73de851ee9a3396f4154cc4ae083a7c36f3b3128b2b9a2e77d", 43303),
        ("prepare-stage-root.sh", "1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea", 54230),
        ("provision-ubuntu-test-host.sh", "078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f", 19437),
        ("root-matrix-n-r.sh", "9ec125c2933866431779b760d41c6484cc0fbb9e5e9f3b5431c4a56fbab63e07", 1101),
        ("check-realhost-iperf.py", "9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67", 21027),
        ("test-hermetic-matrix.sh", "9b81949416a1b4df91fee0e7d31a3de2c6ba9b474dc9c0f4dbbb1cc609207499", 6694),
        ("test_matrix_static.py", "8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8", 5656),
        ("checksum-module-lease.sh", "4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2", 23755),
        ("root-fresh-verifier-gate.sh", "4c2cf85b7e571df9b7ed4a77fa720c9f5e35950d44af5a39499a7ad700fe6a27", 65201),
        ("test-hermetic-fresh-verifier-gate.sh", "c9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3", 14628),
        ("test_fresh_verifier_gate_static.py", "ace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3", 17307),
        ("realnic_acceptance.py", "a88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339", 216405),
        ("test_realnic_acceptance.py", "fcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c", 148160),
        ("test_realnic_acceptance_static.py", "ba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2", 14894),
    )
    r2_predecessor_package_names = tuple(
        item[0] for item in r2_predecessor_package_contract
    )
    if len(r2_predecessor_package_names) != 17:
        fail("test R2 predecessor package oracle is not the fixed 17-file tuple")
    r2_authority_phases = (
        "absent",
        "home-qroot",
        "auth-root",
        "run-qroot",
        "manifest-pending",
        "manifest-pair",
        "self-pending",
        "complete",
    )
    r2_stale_operations = (
        "stale-alternate-bootstrap-root",
        "stale-stage-root",
        "stale-fresh-root",
        "stale-standalone-root",
        "stale-routed-evidence-root",
        "stale-realnic-run-roots",
        "stale-realnic-interface-leases",
        "stale-veth-wgc8e41a",
        "stale-veth-wgc8e41b",
        "stale-veth-wga19f7a",
        "stale-veth-wga19f7b",
        "stale-veth-wg5b8d3a",
        "stale-veth-wg5b8d3b",
        "stale-pin-fresh",
        "stale-pin-standalone",
        "stale-pin-legacy-tcx",
        "stale-pin-legacy-nic-original",
        "stale-pin-legacy-nic-all-on",
        "stale-pin-legacy-nic-all-off",
        "stale-pin-legacy-nic-tx-path",
        "stale-pin-legacy-nic-rx-path",
        "stale-pin-legacy-nic-mtu1492",
        "stale-pin-legacy-nic-mtu1500",
        "stale-pin-legacy-nic-soak",
        "stale-checksum-module",
        "stale-checksum-module-btf",
        "stale-checksum-module-lock",
        "stale-physical-interface-lock",
    )
    r2_raw_operations = (
        "r2-raw-intake-mkdir",
        "r2-raw-scp-manifest",
        "r2-raw-scp-self",
        "r2-raw-sync-intake-manifest",
        "r2-raw-sync-intake-self",
        "r2-raw-sync-intake-directory",
        "r2-raw-sync-intake-parent",
        "r2-raw-home-qroot-create",
        "r2-raw-auth-root-create",
        "r2-raw-run-qroot-create",
        "r2-raw-auth-manifest-install",
        "r2-raw-auth-self-install",
        "r2-raw-sync-auth-manifest-pending",
        "r2-raw-sync-auth-self-pending",
        "r2-raw-link-auth-manifest",
        "r2-raw-link-auth-self",
        "r2-raw-sync-auth-root",
        "r2-raw-sync-home-parent",
        "r2-raw-sync-home-qroot",
        "r2-raw-sync-run-parent",
        "r2-raw-helper-mutate",
    )
    r2_ro_operations = (
        "r2-ro-exists-home-qroot",
        "r2-ro-exists-auth-root",
        "r2-ro-exists-run-qroot",
        "r2-ro-exists-auth-manifest-pending",
        "r2-ro-exists-auth-manifest",
        "r2-ro-exists-auth-self-pending",
        "r2-ro-exists-auth-self",
        "r2-ro-exists-quarantine-intake",
        "r2-ro-exists-quarantine-package",
        "r2-ro-exists-quarantine-bootstrap",
        "r2-ro-exists-lock",
        "r2-ro-exists-receipt-pending",
        "r2-ro-exists-receipt-final",
        "r2-ro-old-package-sha-source-4f2a9b61.bundle",
        "r2-ro-old-package-stat-source-4f2a9b61.bundle",
        "r2-ro-old-package-sha-package-manifest.v1",
        "r2-ro-old-package-stat-package-manifest.v1",
        "r2-ro-old-package-sha-bind-final-package.sh",
        "r2-ro-old-package-stat-bind-final-package.sh",
        "r2-ro-old-package-sha-controller.sh",
        "r2-ro-old-package-stat-controller.sh",
        "r2-ro-old-package-sha-prepare-stage-root.sh",
        "r2-ro-old-package-stat-prepare-stage-root.sh",
        "r2-ro-old-package-sha-provision-ubuntu-test-host.sh",
        "r2-ro-old-package-stat-provision-ubuntu-test-host.sh",
        "r2-ro-old-package-sha-root-matrix-n-r.sh",
        "r2-ro-old-package-stat-root-matrix-n-r.sh",
        "r2-ro-old-package-sha-check-realhost-iperf.py",
        "r2-ro-old-package-stat-check-realhost-iperf.py",
        "r2-ro-old-package-sha-test-hermetic-matrix.sh",
        "r2-ro-old-package-stat-test-hermetic-matrix.sh",
        "r2-ro-old-package-sha-test_matrix_static.py",
        "r2-ro-old-package-stat-test_matrix_static.py",
        "r2-ro-old-package-sha-checksum-module-lease.sh",
        "r2-ro-old-package-stat-checksum-module-lease.sh",
        "r2-ro-old-package-sha-root-fresh-verifier-gate.sh",
        "r2-ro-old-package-stat-root-fresh-verifier-gate.sh",
        "r2-ro-old-package-sha-test-hermetic-fresh-verifier-gate.sh",
        "r2-ro-old-package-stat-test-hermetic-fresh-verifier-gate.sh",
        "r2-ro-old-package-sha-test_fresh_verifier_gate_static.py",
        "r2-ro-old-package-stat-test_fresh_verifier_gate_static.py",
        "r2-ro-old-package-sha-realnic_acceptance.py",
        "r2-ro-old-package-stat-realnic_acceptance.py",
        "r2-ro-old-package-sha-test_realnic_acceptance.py",
        "r2-ro-old-package-stat-test_realnic_acceptance.py",
        "r2-ro-old-package-sha-test_realnic_acceptance_static.py",
        "r2-ro-old-package-stat-test_realnic_acceptance_static.py",
        "r2-ro-user-intake-exists",
        "r2-ro-old-package-readlink",
        "r2-ro-old-package-stat",
        "r2-ro-old-package-entries",
        "r2-ro-old-bootstrap-root-readlink",
        "r2-ro-old-bootstrap-root-stat",
        "r2-ro-old-bootstrap-provisioner-readlink",
        "r2-ro-old-bootstrap-provisioner-stat",
        "r2-ro-old-bootstrap-provisioner-sha",
        "r2-ro-old-bootstrap-stager-readlink",
        "r2-ro-old-bootstrap-stager-stat",
        "r2-ro-old-bootstrap-stager-sha",
        "r2-ro-old-bootstrap-entries",
        "r2-ro-old-provision-check",
        "r2-ro-intake-readlink",
        "r2-ro-intake-stat",
        "r2-ro-intake-entries",
        "r2-ro-intake-manifest-stat",
        "r2-ro-intake-manifest-shape",
        "r2-ro-intake-manifest-sha",
        "r2-ro-intake-manifest-sha-observe",
        "r2-ro-intake-self-stat",
        "r2-ro-intake-self-shape",
        "r2-ro-intake-self-sha",
        "r2-ro-intake-self-sha-observe",
        "r2-ro-home-qroot-readlink",
        "r2-ro-home-qroot-stat",
        "r2-ro-home-qroot-entries",
        "r2-ro-auth-root-readlink",
        "r2-ro-auth-root-stat",
        "r2-ro-auth-root-entries",
        "r2-ro-run-qroot-readlink",
        "r2-ro-run-qroot-stat",
        "r2-ro-run-qroot-entries",
        "r2-ro-auth-manifest-pending-shape",
        "r2-ro-auth-self-pending-shape",
        "r2-ro-auth-manifest-pending-sha-observe",
        "r2-ro-auth-self-pending-sha-observe",
        "r2-ro-auth-manifest-pending-sha",
        "r2-ro-auth-manifest-sha",
        "r2-ro-auth-manifest-pending-stat",
        "r2-ro-auth-manifest-stat",
        "r2-ro-auth-manifest-pair",
        "r2-ro-auth-self-pending-sha",
        "r2-ro-auth-self-sha",
        "r2-ro-auth-self-pending-stat",
        "r2-ro-auth-self-stat",
        "r2-ro-auth-self-pair",
        "r2-ro-helper-verify",
    )
    if (
        len(r2_raw_operations) != 21
        or len(set(r2_raw_operations)) != 21
        or len(r2_ro_operations) != 96
        or len(set(r2_ro_operations)) != 96
    ):
        fail("test R2 private operation oracle cardinality drifted")
    r2_predecessor_manifest_lines = (
        "format\twg-mix-ebpf-b82-v6-package-v4",
        "run_id\tc8e41d73",
        "package_id\t4f2a9b61",
        "integration_ref\trefs/heads/codex/tcx-faketcp-final-v2",
        f"integration_commit\t{r2_predecessor_commit}",
        "bundle_name\tsource-4f2a9b61.bundle",
        f"bundle_sha256\t{r2_predecessor_bundle_sha}",
        "history_verification\tisolated-unbundle-rev-list-fsck-v1",
        "history_commit_count\t668",
        "history_roots_sha256\t9356df63b3d4c4c362912b14ab8ee5cb54d12cd1f14be9aa1fe8e18adbad6f05",
        "history_objects_sha256\t21647f92e57f9dbb8e15707699f632544d6dfcf2e1b4279d775cce1fb82163f3",
        "wg_state\tabsent",
        "wg_interface\tabsent",
        "wg_local_address\tabsent",
        "wg_peer_address\tabsent",
        "local_repository\t/Users/siyixuan/codes-2/wg-mix-ebpf/.worktree/tcx-faketcp-final-v2",
        f"local_package_dir\t{r2_predecessor_package}",
        f"remote_package_dir\t{r2_predecessor_remote_package}",
        "remote_source\t/run/wg-mix-ebpf-source-stages/c8e41d73/source",
        "target_user\tsiyixuan",
        "target_host\t192.168.10.82",
        "target_hostname\tubuntu-2604-test",
        "target_kernel\t7.0.0-28-generic",
        "target_machine_id\t9db3fb717cc74974b2a6b243d67f67b9",
        "target_interface\tens33",
        "peer_address\t47.116.202.155",
        "peer_port\t5201",
        "soak_seconds\t3600",
        "session_seconds\t300",
        "physical_nic_forward_authority\trealnic-acceptance-v1",
        "physical_interface_lock\t/run/wg-mix-ebpf-realnic-physical-interface.v1.lock",
        "legacy_matrix_mode\tretired",
        "realnic_profile\tacceptance",
        "realnic_traffic_seconds\t30",
        "bind_final_package_sh_path\tscripts/realhost-b82-c8e41d73/bind-final-package.sh",
        "bind_final_package_sh_blob\t13ec99ddafb7452c98f05bf4855ef52c3f54b185",
        "bind_final_package_sh_sha256\ta808a7879ef64190eff9e81e6b694acea7bc04b1b74ffad44109b237a5eb14ca",
        "controller_sh_path\tscripts/realhost-b82-c8e41d73/controller.sh",
        "controller_sh_blob\t8371e5492c4e88f3e855fa3c7edfbff15bcf3a5f",
        "controller_sh_sha256\tfb8a7a685b5a6b73de851ee9a3396f4154cc4ae083a7c36f3b3128b2b9a2e77d",
        "locked_transport_exp_path\tscripts/realhost-b82-c8e41d73/locked-transport.exp",
        "locked_transport_exp_blob\t264f0cf74e6ff53d0cbee2688faa5d886898d22f",
        "locked_transport_exp_sha256\tc70e4f040dc082c4f286c237bda32fe2a60b3e5f6300ec57734645a0be12abec",
        "root_matrix_n_r_sh_path\tscripts/realhost-b82-c8e41d73/root-matrix-n-r.sh",
        "root_matrix_n_r_sh_blob\td2b2d473afb79c4463fd6c712d4eda3faeed5c7e",
        "root_matrix_n_r_sh_sha256\t9ec125c2933866431779b760d41c6484cc0fbb9e5e9f3b5431c4a56fbab63e07",
        "check_realhost_iperf_py_path\tscripts/realhost-b82-c8e41d73/check-realhost-iperf.py",
        "check_realhost_iperf_py_blob\t765871ef3af87cd8a101a42e71ea97c1245dc9da",
        "check_realhost_iperf_py_sha256\t9a52378b8a1ef6043d4d5792471c8239a0392a80da72f5c00846dd89e88ccd67",
        "test_hermetic_matrix_sh_path\tscripts/realhost-b82-c8e41d73/test-hermetic-matrix.sh",
        "test_hermetic_matrix_sh_blob\t81f7cd86d8dc5a93133ea755311ba57aa66e4c76",
        "test_hermetic_matrix_sh_sha256\t9b81949416a1b4df91fee0e7d31a3de2c6ba9b474dc9c0f4dbbb1cc609207499",
        "test_matrix_static_py_path\tscripts/realhost-b82-c8e41d73/test_matrix_static.py",
        "test_matrix_static_py_blob\t0a2b1538d3127e8bae8953b0dff59d60cc379f39",
        "test_matrix_static_py_sha256\t8de2dcdc866938da0502f1ad73ac9b38c9b6ff4066c76e9cbc946c9ca30a53f8",
        "checksum_module_lease_sh_path\tscripts/realhost-b82-c8e41d73/checksum-module-lease.sh",
        "checksum_module_lease_sh_blob\tc2e6077005e046eef0e1186c26cdaaf29c780f98",
        "checksum_module_lease_sh_sha256\t4ab9a22910e8d597cc04bb4fdde9e1b32d37a1bb2c6ad7b76f52d576b5a9adb2",
        "root_fresh_verifier_gate_sh_path\tscripts/realhost-b82-c8e41d73/root-fresh-verifier-gate.sh",
        "root_fresh_verifier_gate_sh_blob\t48dd5e68071798c3d25daf0051cbf54f8cd3297e",
        "root_fresh_verifier_gate_sh_sha256\t4c2cf85b7e571df9b7ed4a77fa720c9f5e35950d44af5a39499a7ad700fe6a27",
        "test_hermetic_fresh_verifier_gate_sh_path\tscripts/realhost-b82-c8e41d73/test-hermetic-fresh-verifier-gate.sh",
        "test_hermetic_fresh_verifier_gate_sh_blob\tf3f7367d28253ebae746eb0e225c11f90eaa8305",
        "test_hermetic_fresh_verifier_gate_sh_sha256\tc9b5b1f954c794c5c986214777727a76579f670db9587f319ac148fc0c2a05f3",
        "test_fresh_verifier_gate_static_py_path\tscripts/realhost-b82-c8e41d73/test_fresh_verifier_gate_static.py",
        "test_fresh_verifier_gate_static_py_blob\tf86736b1c4a5b884814f062edbb2d652172f024f",
        "test_fresh_verifier_gate_static_py_sha256\tace6951027788e82ad879caf285316af4e6ee81fdb6746f569cd7c22b9f80bf3",
        "prepare_stage_root_sh_path\tscripts/realhost-b82-c8e41d73/prepare-stage-root.sh",
        "prepare_stage_root_sh_blob\t057db657b0ba096a4f660eedda2e0a4242af7de5",
        "prepare_stage_root_sh_sha256\t1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea",
        "realnic_acceptance_py_path\tscripts/realhost-b82-acceptance-v1/realnic_acceptance.py",
        "realnic_acceptance_py_blob\te1edba5c9dd62c8c169d7129e8b376d4ce7d1168",
        "realnic_acceptance_py_sha256\ta88100b2a23ad41dd3e644c3ba1c7a722d58c8184a997aabf0ceab78552c6339",
        "test_realnic_acceptance_py_path\tscripts/realhost-b82-acceptance-v1/test_realnic_acceptance.py",
        "test_realnic_acceptance_py_blob\te92f8f7db9733eb3f655b388f1efd685f738c2c4",
        "test_realnic_acceptance_py_sha256\tfcb3d0dadee6da6e0ad67d028f268ebe43575287f555cd8100d279f8a3b0b79c",
        "test_realnic_acceptance_static_py_path\tscripts/realhost-b82-acceptance-v1/test_realnic_acceptance_static.py",
        "test_realnic_acceptance_static_py_blob\tb0dd244937b9139fe8c8548d6c046b76d9f611e9",
        "test_realnic_acceptance_static_py_sha256\tba8aef3219a0cf2a5c6b5058b245f64eb828a08bb532d2aa0291f51ee7206ad2",
        "provision_ubuntu_test_host_sh_path\tscripts/provision-ubuntu-test-host.sh",
        "provision_ubuntu_test_host_sh_blob\t143eb89a2e4bbbf548b510bcc2fd9f66184d3d76",
        "provision_ubuntu_test_host_sh_sha256\t078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f",
        "root_veth_n_r_sh_path\tscripts/realhost-b82-c8e41d73/root-veth-n-r.sh",
        "root_veth_n_r_sh_blob\ta72f7f2eebe765bc7fa8a5352c134233b30ac8aa",
        "root_veth_n_r_sh_sha256\tfbb8779039137383df6f51f05319faea966c69a80001da837dee22d04d8f7a70",
        "test_hermetic_veth_runner_sh_path\tscripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh",
        "test_hermetic_veth_runner_sh_blob\tae0c74eefe33cf6afda681ba6fca17b54700108f",
        "test_hermetic_veth_runner_sh_sha256\t939c3b28310596ed6bada0eb3ccdd5ebbb7eeebeaf959504c7d468b929f8174c",
        "test_veth_runner_static_py_path\tscripts/realhost-b82-c8e41d73/test_veth_runner_static.py",
        "test_veth_runner_static_py_blob\t5bc3d0ac0ac48c3adc0cd86166f533edc676c712",
        "test_veth_runner_static_py_sha256\te40da6b1a6541a9b8b6c56d9277d4d73838e037876180e479b5af5d64a4edc90",
        "controller_seam_sh_path\tscripts/realhost-b82-routed-veth-v1/controller-seam.sh",
        "controller_seam_sh_blob\t18d9e4d72a0b9022019e738d9de4fd4e23bc4903",
        "controller_seam_sh_sha256\t2bd7b65c3e770ff53445cbc7c195e741e8fff5eeef9e51bd6fcaa2f513d1f251",
        "root_routed_veth_n_r_sh_path\tscripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh",
        "root_routed_veth_n_r_sh_blob\t9d30910b692b2d42c1528c75c2a3ba0a5d0a11cb",
        "root_routed_veth_n_r_sh_sha256\t5af8b848c9fc5f915b25c6c03822622f2ac75996a54ebf8172c7c5391c9f3485",
        "test_hermetic_routed_veth_harness_sh_path\tscripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh",
        "test_hermetic_routed_veth_harness_sh_blob\t253c7b0b4d4c2d065475a82742418446146d0a0a",
        "test_hermetic_routed_veth_harness_sh_sha256\t674f96665eb26f879eae08936683fdac2beb974841ed99f9021abe9e04752032",
        "test_routed_veth_harness_static_py_path\tscripts/realhost-b82-routed-veth-v1/test_routed_veth_harness_static.py",
        "test_routed_veth_harness_static_py_blob\t06e0fa14779ce778440250f4a437426017754cd4",
        "test_routed_veth_harness_static_py_sha256\t5bb678726ecc6bcc946233ae138d541fc50dc9f6ec40ddf139350863690d88c1",
    )
    if (
        len(r2_predecessor_manifest_lines) != 103
        or len({line.split("\t", 1)[0] for line in r2_predecessor_manifest_lines})
        != 103
        or any(line.count("\t") != 1 for line in r2_predecessor_manifest_lines)
    ):
        fail("test R2 predecessor manifest oracle is not exact v4/103")
    r2_predecessor_manifest_payload = (
        "\n".join(r2_predecessor_manifest_lines) + "\n"
    )
    retained_retirement_constants = (
        'set ::RETAINED_RETIREMENT_COMMIT \\\n'
        f'    "{retained_retirement_commit}"',
        'set ::RETAINED_RETIREMENT_MANIFEST_SHA256 \\\n'
        f'    "{retained_retirement_manifest_sha}"',
        'set ::RETAINED_RETIREMENT_HELPER_SHA256 \\\n'
        f'    "{retained_retirement_helper_sha}"',
        'set ::RETAINED_RETIREMENT_RECEIPT_SHA256 \\\n'
        f'    "{retained_retirement_receipt_sha}"',
        'set ::RETIREMENT_AUTH_MANIFEST \\\n'
        '    "${::RETIREMENT_AUTH_ROOT}/package-manifest.v1"',
        'set ::RETIREMENT_AUTH_SELF \\\n'
        '    "${::RETIREMENT_AUTH_ROOT}/prepare-stage-root.sh"',
        'set ::RETIREMENT_RECEIPT_FINAL \\\n'
        '    "${::RETIREMENT_RUN_QROOT}/retirement-complete.v1"',
    )
    for literal in retained_retirement_constants:
        if transport.count(literal) != 1:
            fail(f"transport retained retirement constant drifted: {literal!r}")
    retained_constants_end = transport.index("set ::R2_RETIRE_ID")
    literal_digests = re.findall(
        r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])",
        transport[:retained_constants_end],
    )
    if literal_digests != [
        retained_retirement_manifest_sha,
        retained_retirement_helper_sha,
        retained_retirement_receipt_sha,
    ]:
        fail("transport retained R1 retirement digest preamble is not exact")

    retired_predecessor_literals = (
        "set ::PREDECESSOR_COMMIT ",
        "set ::PREDECESSOR_PACKAGE ",
        "set ::PREDECESSOR_MANIFEST ",
        "readonly PREDECESSOR_COMMIT=",
        "readonly PREDECESSOR_PACKAGE=",
        "readonly PREDECESSOR_MANIFEST=",
        "require_retirement_predecessor_authority",
        "verify_predecessor_manifest_contract",
        "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-2c690050ae1d",
    )
    for name, payload in (
        (controller_path.name, controller),
        (transport_path.name, transport),
        (stager_path.name, stager),
    ):
        for literal in retired_predecessor_literals:
            if literal in payload:
                fail(f"{name} retains predecessor-local authority: {literal!r}")

    executable_rmdir_pattern = r"(?<![A-Za-z0-9_-])rmdir(?=\s|\()"
    if re.search(executable_rmdir_pattern, "no-unlink-no-rmdir-no-copy-fallback"):
        fail("executable rmdir matcher rejects the exact retention receipt literal")
    for executable_rmdir in (
        "rmdir /fixed/path",
        "/usr/bin/rmdir /fixed/path",
        'os.rmdir("/fixed/path")',
    ):
        if not re.search(executable_rmdir_pattern, executable_rmdir):
            fail("executable rmdir matcher no longer rejects an executable form")
    forbidden_patterns = (
        r"\brm\s+-[^\n]*r",
        executable_rmdir_pattern,
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

    manifest_prefix = (
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
    package_identity_names = (
        "root-matrix-n-r.sh",
        "check-realhost-iperf.py",
        "test-hermetic-matrix.sh",
        "test_matrix_static.py",
        "checksum-module-lease.sh",
        "test-hermetic-checksum-module-lease.sh",
        "test_checksum_module_lease_static.py",
        "wg_mix_faketcp_checksum.c",
        "root-fresh-verifier-gate.sh",
        "test-hermetic-fresh-verifier-gate.sh",
        "test_fresh_verifier_gate_static.py",
        "prepare-stage-root.sh",
        "realnic_acceptance.py",
        "test_realnic_acceptance.py",
        "test_realnic_acceptance_static.py",
        "provision-ubuntu-test-host.sh",
    )
    staged_identity_names = (
        "root-veth-n-r.sh",
        "test-hermetic-veth-runner.sh",
        "test_veth_runner_static.py",
        "controller-seam.sh",
        "root-routed-veth-n-r.sh",
        "test-hermetic-routed-veth-harness.sh",
        "test_routed_veth_harness_static.py",
    )
    identity_names = (
        "bind-final-package.sh",
        "controller.sh",
        "locked-transport.exp",
        *package_identity_names,
        *staged_identity_names,
    )
    identity_keys = tuple(name.replace("-", "_").replace(".", "_") for name in identity_names)
    expected_manifest_keys = manifest_prefix + tuple(
        f"{key}_{suffix}"
        for key in identity_keys
        for suffix in ("path", "blob", "sha256")
    )
    if len(expected_manifest_keys) != 112 or len(set(expected_manifest_keys)) != 112:
        fail("test fixture no longer defines one unique package-v5/112 schema")

    package_array = bash_array(binder, "PACKAGE_PATHS")
    staged_array = bash_array(binder, "STAGED_IDENTITY_PATHS")
    identity_array = bash_array(binder, "IDENTITY_PATHS")
    if array_path_basenames(package_array) != package_identity_names:
        fail("binder package identities do not match the exact package-v5 schema")
    if array_path_basenames(staged_array) != staged_identity_names:
        fail("binder staged identities do not match the exact package-v5 schema")
    expected_identity_lines = (
        '"${REPOSITORY_PATH_FROM_ROOT}/bind-final-package.sh"',
        '"${REPOSITORY_PATH_FROM_ROOT}/controller.sh"',
        '"${REPOSITORY_PATH_FROM_ROOT}/locked-transport.exp"',
        '"${PACKAGE_PATHS[@]}"',
        '"${STAGED_IDENTITY_PATHS[@]}"',
    )
    if tuple(line.strip() for line in identity_array.splitlines()) != expected_identity_lines:
        fail("binder identity expansion is not the exact fixed package/staged sequence")
    bind_body = bash_function(binder, "bind_package")
    path_key_body = bash_function(binder, "path_key")
    ordered(
        path_key_body,
        (
            'local name="${1##*/}"',
            'name="${name//-/_}"',
            'name="${name//./_}"',
            "printf '%s\\n' \"${name}\"",
        ),
        "binder identity path-key mapping",
    )
    binder_prefix = tuple(
        re.findall(r"(?m)^\s*manifest_line ([a-z0-9_]+) ", bind_body)
    )
    if binder_prefix != manifest_prefix:
        fail("binder package-v5 manifest prefix changed order or cardinality")
    ordered(
        bind_body,
        (
            'for path in "${IDENTITY_PATHS[@]}"; do',
            'key="$(path_key "${path}")"',
            'manifest_line "${key}_path" "${path}"',
            'manifest_line "${key}_blob" "${blob}"',
            'manifest_line "${key}_sha256" "${sha}"',
        ),
        "binder manifest identity expansion",
    )
    if tuple(
        re.findall(r'manifest_line "\$\{key\}_([a-z0-9]+)"', bind_body)
    ) != ("path", "blob", "sha256"):
        fail("binder identity loop does not emit exactly path/blob/sha256")
    if "printf '%s\\t%s\\n' \"$1\" \"$2\"" not in bash_function(
        binder, "manifest_line"
    ):
        fail("binder manifest_line no longer emits exactly one newline-terminated field")
    binder_manifest_keys = binder_prefix + tuple(
        f"{key}_{suffix}"
        for key in identity_keys
        for suffix in ("path", "blob", "sha256")
    )

    transport_load = tcl_proc(transport, "load_manifest")
    expected_keys_match = re.search(
        r"(?ms)^\s*set expected_keys \{\n(?P<body>.*?)^\s*\}\n\s*set channel ",
        transport_load,
    )
    if not expected_keys_match:
        fail("cannot isolate transport package-v5 expected_keys")
    transport_manifest_keys = tuple(expected_keys_match.group("body").split())
    realnic_manifest_keys = python_string_tuple(
        realnic, "PACKAGE_MANIFEST_BASE_KEYS"
    ) + tuple(
        f"{key}_{suffix}"
        for key in python_string_tuple(realnic, "PACKAGE_MANIFEST_IDENTITY_KEYS")
        for suffix in ("path", "blob", "sha256")
    )
    consumer_keys = {
        "binder": binder_manifest_keys,
        "controller": manifest_reader_keys(controller, "load_manifest"),
        "root-stager": manifest_reader_keys(stager, "load_manifest"),
        "root-fresh": manifest_reader_keys(fresh, "load_manifest_once"),
        "transport": transport_manifest_keys,
        "realnic-capture": realnic_manifest_keys,
    }
    for name, keys in consumer_keys.items():
        if keys != expected_manifest_keys or len(keys) != 112 or len(set(keys)) != 112:
            fail(f"{name} does not consume the exact unique package-v5/112 key sequence")
    version_contracts = (
        (
            "binder",
            bind_body,
            "manifest_line format wg-mix-ebpf-b82-v6-package-v5",
        ),
        (
            "controller",
            bash_function(controller, "verify_manifest_contract"),
            '"${FORMAT}" == \'wg-mix-ebpf-b82-v6-package-v5\'',
        ),
        (
            "root-stager",
            bash_function(stager, "validate_manifest"),
            '"${FORMAT}" == \'wg-mix-ebpf-b82-v6-package-v5\'',
        ),
        (
            "root-fresh",
            bash_function(fresh, "validate_snapshot_contract"),
            '"${FORMAT}" == \'wg-mix-ebpf-b82-v6-package-v5\'',
        ),
        (
            "transport",
            tcl_proc(transport, "validate_manifest_values"),
            '[dict get $values format] ne "wg-mix-ebpf-b82-v6-package-v5"',
        ),
        (
            "realnic-capture",
            python_function(realnic, "load_local_capture_manifest"),
            'values["format"] != "wg-mix-ebpf-b82-v6-package-v5"',
        ),
    )
    for name, body, version_literal in version_contracts:
        if body.count(version_literal) != 1:
            fail(f"{name} does not bind exactly one package-v5 format value")

    bash_eof_contracts = (
        (
            "controller",
            bash_function(controller, "load_manifest"),
            'if IFS= read -r unexpected <&3 || [[ -n "${unexpected}" ]]; then',
        ),
        (
            "root-stager",
            bash_function(stager, "load_manifest"),
            'if IFS= read -r unexpected <&3 || [[ -n "${unexpected}" ]]; then',
        ),
        (
            "root-fresh",
            bash_function(fresh, "load_manifest_once"),
            'if IFS= read -r -u "${MANIFEST_FD}" unexpected || [[ -n "${unexpected}" ]]; then',
        ),
    )
    for name, body, eof_guard in bash_eof_contracts:
        if body.count("local unexpected=''") != 1 or body.count(eof_guard) != 1:
            fail(
                f"{name} EOF guard does not reject a 113th line both with and without newline"
            )
    nul_helpers = tuple(
        bash_function(payload, "require_manifest_fd_without_nul")
        for payload in (controller, stager, fresh)
    )
    if len(set(nul_helpers)) != 1:
        fail("Bash manifest consumers do not share one identical NUL precheck")
    nul_helper = nul_helpers[0]
    ordered(
        nul_helper,
        (
            "/usr/bin/python3 -B -I -c '",
            "descriptor = int(sys.argv[1])",
            "offset = 0",
            "chunk = os.pread(descriptor, 65536, offset)",
            'if b"\\0" in chunk:',
            "raise SystemExit(65)",
            "offset += len(chunk)",
            "except (OSError, ValueError):",
            "raise SystemExit(66)",
        ),
        "same-FD manifest NUL precheck",
    )
    if re.search(r"os\.(?:read|lseek)\(|print\(|sys\.(?:stdout|stderr)", nul_helper):
        fail("manifest NUL helper consumes the parser FD or emits file bytes")
    for name, load, open_fd, scan_fd in (
        ("controller", bash_function(controller, "load_manifest"), 'exec 3<"${MANIFEST}"', "require_manifest_fd_without_nul 3"),
        ("root-stager", bash_function(stager, "load_manifest"), 'exec 3<"${MANIFEST}"', "require_manifest_fd_without_nul 3"),
        ("root-fresh", bash_function(fresh, "load_manifest_once"), 'exec {MANIFEST_FD}<"${SNAPSHOT_MANIFEST}"', 'require_manifest_fd_without_nul "${MANIFEST_FD}"'),
    ):
        prefix = load[: load.index("read_manifest_field format FORMAT")]
        ordered(prefix, (open_fd, scan_fd, "rc=$?", 'return "${rc}"'), f"{name} NUL gate")
        if prefix.count(scan_fd) != 1:
            fail(f"{name} does not scan its already-open parser FD exactly once")
    required_transport_eof = (
        'set payload [read $channel]',
        '![string match "*\\n" $payload]',
        'set lines [split [string range $payload 0 end-1] "\\n"]',
        'if {[llength $lines] != [llength $expected_keys]}',
    )
    ordered(transport_load, required_transport_eof, "transport strict manifest EOF")
    if 'string trimright $payload "\\n"' in transport_load:
        fail("transport trims arbitrary trailing newlines before its exact line-count check")

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
        "wg-mix-ebpf-b82-v6-package-v5",
        "manifest_line wg_state",
        "absent)",
        '"${WG_INTERFACE}" == \'absent\'',
        "prepare-stage-root.sh",
        "scripts/provision-ubuntu-test-host.sh",
        "locked-transport.exp",
        "controller.sh",
        "checksum-module-lease.sh",
        "test-hermetic-checksum-module-lease.sh",
        "test_checksum_module_lease_static.py",
        "kernel/faketcp_checksum/wg_mix_faketcp_checksum.c",
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
        'readonly -a STAGED_IDENTITY_PATHS=(',
        '"${REPOSITORY_PATH_FROM_ROOT}/root-veth-n-r.sh"',
        '"${ROUTED_PATH_FROM_ROOT}/controller-seam.sh"',
        '"${ROUTED_PATH_FROM_ROOT}/root-routed-veth-n-r.sh"',
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
        "verify-package|verify-r2-predecessor-package|plan|preflight|prepare|provision-apply",
        "B82_V6_CONTROLLER_PACKAGE_VERIFIED",
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
        "BOOTSTRAP_ROOT_VERIFY_OPERATIONS=(bootstrap-root-readlink bootstrap-root-stat)",
        "PROVISIONER_VERIFY_OPERATIONS",
        "STAGER_VERIFY_OPERATIONS",
        "STAGE_OPERATIONS=(stage-snapshot stage-plan stage-run)",
        "run_operation execute prepare",
        "run_operation execute provision-apply",
        "fresh-plan | fresh-run | fresh-restore",
        "veth-plan | veth-run | veth-restore",
        "routed-plan | routed-run | routed-restore",
        "for operation in fresh-plan fresh-run fresh-restore",
        "run_operation execute fresh-plan",
        "run_operation execute fresh-run",
        "run_operation execute fresh-restore",
        "run_operation execute veth-plan",
        "run_operation execute veth-run",
        "run_operation execute veth-restore",
        "run_operation execute routed-plan",
        "run_operation execute routed-run",
        "run_operation execute routed-restore",
        "CHECKSUM_MODULE_LEASE_SH_PATH",
        "ROOT_FRESH_VERIFIER_GATE_SH_PATH",
        "realnic-plan | realnic-run | realnic-restore",
        "transport capture realnic-plan",
        "capture-local",
        "realnic-plan.${APPROVED_PLAN_SHA256}.json",
        "verify_local_approved_plan",
        "scp-realnic-approved-plan verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan stage-realnic-plan-snapshot realnic-run",
        "stage-realnic-plan-verify",
        "run_operation execute realnic-run",
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
    if re.search(r"--approved-plan(?!-sha256)", controller):
        fail("controller exposes the removed public approved-plan path argument")

    # The current package's isolated Git repository must expose exactly one
    # name, and that name must bind the manifest commit.  Object reachability
    # alone is insufficient because an injected or retargeted ref would escape
    # the package's frozen history namespace.
    current_history_verifier = bash_function(controller, "verify_bound_history")
    current_ref_gate = (
        'history_refs="$(git_history "${history_repository}" for-each-ref \\\n'
        "    '--format=%(objectname) %(refname)')\" || return 76\n"
        '  [[ "${history_refs}" == "${INTEGRATION_COMMIT} '
        'refs/heads/history-verified" ]] || return 76'
    )
    if (
        current_history_verifier.count(current_ref_gate) != 1
        or current_history_verifier.count("for-each-ref") != 1
        or current_history_verifier.count(
            "--format=%(objectname) %(refname)"
        )
        != 1
        or current_history_verifier.count("refs/heads/history-verified") != 1
    ):
        fail("controller current Bash history ref/commit gate is not exact and unique")
    current_ref_slice = current_history_verifier[
        current_history_verifier.index('history_refs="$(git_history') :
        current_history_verifier.index(
            'git_history "${history_repository}" cat-file',
            current_history_verifier.index('history_refs="$(git_history'),
        )
    ]
    if (
        current_ref_slice.count("|| return 76") != 2
        or any(
            fallback in current_ref_slice
            for fallback in (
                "show-ref",
                "symbolic-ref",
                "rev-parse",
                "/usr/bin/git",
                "git_checked",
                "|| true",
            )
        )
    ):
        fail("controller current Bash history ref gate has a fallback or wrong rc")

    approved_operations = (
        "scp-realnic-approved-plan",
        "verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan",
        "stage-realnic-plan-snapshot",
        "realnic-run",
        "stage-realnic-plan-verify",
        "realnic-restore",
    )
    controller_transport = bash_function(controller, "transport")
    approved_case = re.search(
        r'(?ms)case "\$\{operation\}" in\s*(?P<operations>.*?)\)\s*'
        r'transport_approved_sha256="\$\{APPROVED_PLAN_SHA256\}"',
        controller_transport,
    )
    if not approved_case:
        fail("cannot isolate controller approved-plan digest operation case")
    controller_approved_operations = tuple(
        re.findall(r"[a-z][a-z0-9-]+", approved_case.group("operations"))
    )
    if controller_approved_operations != approved_operations:
        fail("controller does not pass the digest for exactly seven approved operations")
    if (
        controller_transport.count("transport_approved_sha256='none'") != 1
        or controller_transport.count(
            'transport_approved_sha256="${APPROVED_PLAN_SHA256}"'
        )
        != 1
    ):
        fail("controller approved-plan digest default or sole override changed")
    ordered(
        controller_transport,
        (
            '--manifest "${MANIFEST}"',
            '--manifest-sha256 "${MANIFEST_SHA256}"',
            '--credential-path "${SUPPLIED_CREDENTIAL_PATH}"',
            '--action "${action}"',
            '--operation "${operation}"',
            '--approved-plan-sha256 "${transport_approved_sha256}"',
        ),
        "controller digest-only transport argv",
    )

    expected_stale_operations = (
        "stale-package-root",
        "stale-bootstrap-root",
        "stale-alternate-bootstrap-root",
        "stale-stage-root",
        "stale-fresh-root",
        "stale-standalone-root",
        "stale-routed-evidence-root",
        "stale-realnic-run-roots",
        "stale-realnic-interface-leases",
        "stale-veth-wgc8e41a",
        "stale-veth-wgc8e41b",
        "stale-veth-wga19f7a",
        "stale-veth-wga19f7b",
        "stale-veth-wg5b8d3a",
        "stale-veth-wg5b8d3b",
        "stale-pin-fresh",
        "stale-pin-standalone",
        "stale-pin-legacy-tcx",
        "stale-pin-legacy-nic-original",
        "stale-pin-legacy-nic-all-on",
        "stale-pin-legacy-nic-all-off",
        "stale-pin-legacy-nic-tx-path",
        "stale-pin-legacy-nic-rx-path",
        "stale-pin-legacy-nic-mtu1492",
        "stale-pin-legacy-nic-mtu1500",
        "stale-pin-legacy-nic-soak",
        "stale-checksum-module",
        "stale-checksum-module-btf",
        "stale-checksum-module-lock",
        "stale-physical-interface-lock",
    )
    actual_stale_operations = tuple(
        bash_array(controller, "PREPARE_NEW_STALE_OPERATIONS").split()
    )
    if (
        actual_stale_operations != expected_stale_operations
        or len(actual_stale_operations) != 30
        or len(set(actual_stale_operations)) != 30
    ):
        fail("PREPARE_NEW_STALE_OPERATIONS is not the exact ordered 30-item tuple")
    stale_gate = bash_function(controller, "run_prepare_new_stale_gate")
    ordered(
        stale_gate,
        (
            'local total="${#PREPARE_NEW_STALE_OPERATIONS[@]}"',
            'for operation in "${PREPARE_NEW_STALE_OPERATIONS[@]}"; do',
            "((ordinal += 1))",
            'id="${operation#stale-}"',
            'run_operation "${action}" "${operation}"',
            "rc=$?",
            "B82_V6_STALE_ITEM_V1",
            "B82_V6_STALE_SUMMARY_V1",
        ),
        "prepare-new stale gate",
    )
    if stale_gate.count('run_operation "${action}" "${operation}"') != 1:
        fail("prepare-new stale gate does not issue exactly one ordered call per tuple item")
    if (
        stale_gate.count("B82_V6_STALE_ITEM_V1") != 2
        or stale_gate.count("B82_V6_STALE_SUMMARY_V1") != 2
    ):
        fail("prepare-new stale gate does not emit exact stop/success item summaries")
    stale_calls = tuple(
        re.findall(r"(?m)^\s*run_prepare_new_stale_gate (plan|execute)(?: \|\| return \$\?)?$", controller)
    )
    if stale_calls != ("plan", "execute"):
        fail("prepare-new stale gate call sites or action order changed")
    ordered(
        bash_function(controller, "plan_all"),
        (
            'for operation in "${BASE_IDENTITY_OPERATIONS[@]}"; do',
            "run_prepare_new_stale_gate plan || return $?",
            "for operation in package-parent-stat package-mkdir; do",
        ),
        "plan prepare-new stale gate",
    )
    controller_transactions = {
        "execute_prepare": ("run_operation execute prepare",),
        "execute_provision_apply": ("run_operation execute provision-apply",),
        "execute_realnic_run": (
            "verify_local_approved_plan || return $?",
            "run_operation execute realnic-run",
        ),
        "execute_realnic_restore": ("run_operation execute realnic-restore",),
    }
    for name, expected in controller_transactions.items():
        lines = tuple(
            line.strip()
            for line in bash_function(controller, name).splitlines()
            if line.strip()
        )
        if lines != expected:
            fail(f"controller {name} is not one fixed high-level transaction")
    for mode in (
        "fresh-plan",
        "fresh-run",
        "fresh-restore",
        "veth-plan",
        "veth-run",
        "veth-restore",
        "routed-plan",
        "routed-run",
        "routed-restore",
    ):
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
    literal_executes = re.findall(r"run_operation execute ([a-z][a-z0-9-]+)", controller)
    allowed_executes = {
        "prepare", "provision-apply", "realnic-run", "realnic-restore",
        "fresh-plan", "fresh-run", "fresh-restore", "veth-plan", "veth-run",
        "veth-restore", "routed-plan", "routed-run", "routed-restore",
        "retire-postflight-f75fe7678cfd-r2", "verify-postflight-retirement-r2",
    }
    if set(literal_executes) != allowed_executes or len(literal_executes) != len(allowed_executes):
        fail("controller retains direct primitive mutation sequencing")
    controller_main = bash_function(controller, "main")
    parse_arguments = bash_function(controller, "parse_arguments")
    for retired_operation in (
        "retire-prestage-2c690050",
        "verify-retirement",
        "retire-raw-",
    ):
        if retired_operation in controller or retired_operation in parse_arguments:
            fail(f"controller exposes retired operation {retired_operation!r}")
    verify_arm = re.search(
        r"(?ms)^\s*verify-package\)\n(.*?)^\s*;;$", controller_main
    )
    if (
        not verify_arm
        or "B82_V6_CONTROLLER_PACKAGE_VERIFIED" not in verify_arm.group(1)
        or any(word in verify_arm.group(1) for word in ("run_operation", "transport "))
    ):
        fail("controller verify-package seam is not read-only")

    required_transport = (
        'set action [lindex $argv 7]',
        'if {$action eq "plan"}',
        "credential_read=0 network_operations=0",
        'if {[catch {open $credential_path r} credential_file]}',
        'send -i $child_id -- "$password\\r"',
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
        "proc veth_remote_argv",
        "veth-plan - veth-run - veth-restore",
        "proc routed_remote_argv",
        "routed-plan - routed-run - routed-restore",
        "proc realnic_remote_argv",
        "realnic-plan - realnic-run - realnic-restore",
        "/usr/bin/python3 -B -I",
        "realnic-plan-snapshot",
        "realnic-plan-verify",
        "scp-realnic-approved-plan verify-sha-realnic-approved-plan",
        "verify-stat-realnic-approved-plan",
        "/run/wg-mix-ebpf-source-bootstrap-c8e41d73/realnic-approved-plan.json",
        "proc capture_child_payload",
        "capture-payload-frame",
        "operation_requires_approved_sha",
        "proc transaction_operation",
        "proc read_only_operation",
        "proc require_controller_verifier_authority",
        "proc execute_controller_package_verifier",
        "proc require_transaction_local_authority",
        "proc execute_transaction",
        "B82_V6_TRANSPORT_TRANSACTION_START",
        "B82_V6_TRANSPORT_TRANSACTION_COMPLETE",
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

    transport_main = tcl_proc(transport, "transport_main")
    expected_transport_flags = (
        (0, "--manifest"),
        (2, "--manifest-sha256"),
        (4, "--credential-path"),
        (6, "--action"),
        (8, "--operation"),
        (10, "--approved-plan-sha256"),
    )
    actual_transport_flags = tuple(
        (int(index), flag)
        for index, flag in re.findall(
            r'\[lindex \$argv ([0-9]+)\] ne "(--[a-z0-9-]+)"', transport_main
        )
    )
    if transport_main.count("$argc != 12") != 1 or actual_transport_flags != expected_transport_flags:
        fail("transport_main is not the exact digest-only 12-argument interface")
    expected_transport_values = (
        ("manifest", 1),
        ("manifest_sha", 3),
        ("credential_path", 5),
        ("action", 7),
        ("operation", 9),
        ("approved_sha", 11),
    )
    actual_transport_values = tuple(
        (name, int(index))
        for name, index in re.findall(
            r"(?m)^\s*set ([a-z_]+) \[lindex \$argv ([0-9]+)\]$", transport_main
        )
    )
    if actual_transport_values != expected_transport_values:
        fail("transport_main does not bind all six values from the exact odd positions")
    required_action_guard = (
        'if {($action eq "capture" && $operation ne "realnic-plan") ||',
        '($action eq "execute" && ![transaction_operation $operation] &&',
        '![read_only_operation $operation])}',
        'fail "action-operation" 65',
    )
    ordered(transport_main, required_action_guard, "transport action/operation gate")
    action_guard = transport_main[
        transport_main.index('if {($action eq "capture"') : transport_main.index(
            "set sha_is_valid"
        )
    ]
    if '$action eq "plan"' in action_guard:
        fail("transport blocks fixed mutation leaves from credential-free planning")

    transaction_match = re.search(
        r"(?ms)\$operation in \{(.*?)\}",
        tcl_proc(transport, "transaction_operation"),
    )
    expected_transactions = tuple(
        "prepare provision-apply fresh-run fresh-restore veth-run veth-restore "
        "routed-run routed-restore realnic-run realnic-restore "
        "retire-postflight-f75fe7678cfd-r2".split()
    )
    if not transaction_match or tuple(transaction_match.group(1).split()) != expected_transactions:
        fail("transport high-level transaction set is not exact")
    read_only = tcl_proc(transport, "read_only_operation")
    read_only_match = re.search(r"(?ms)if \{\$operation in \{(.*?)\}\} \{", read_only)
    expected_read_only = tuple(
        "package-parent-stat bootstrap-absent bootstrap-not-symlink "
        "bootstrap-root-readlink bootstrap-root-stat bootstrap-stager-readlink "
        "bootstrap-stager-stat bootstrap-stager-sha bootstrap-provisioner-readlink "
        "bootstrap-provisioner-stat bootstrap-provisioner-sha provision-check stage-plan "
        "fresh-plan veth-plan routed-plan verify-sha-realnic-approved-plan "
        "verify-stat-realnic-approved-plan stage-realnic-plan-verify".split()
    )
    if not read_only_match or tuple(read_only_match.group(1).split()) != expected_read_only:
        fail("transport explicit read-only operation set is not exact")
    ordered(
        read_only,
        (
            "[lsearch -exact [concat [base_identity_operations] [postflight_operations]",
            "[prepare_stale_operations]] $operation] >= 0",
            r"[regexp {^verify-(?:sha|stat)-(.+)$} $operation -> name]",
            "[lsearch -exact [package_names] $name] >= 0",
            "return 0",
        ),
        "transport closed read-only operation set",
    )
    if "{^(identity-|tool-|kernel-|stale-)}" in read_only:
        fail("transport read-only authority accepts an open-ended operation prefix")

    removed_retirement_procs = (
        "retirement_mutation_operation",
        "retirement_read_only_operation",
        "retirement_helper_remote_argv",
        "build_retirement_operation",
        "execute_retirement_primitive",
        "execute_retirement_transaction",
        "execute_retirement_verify_transaction",
        "retirement_ensure_delivery",
        "retirement_converge_delivery_durability",
        "retirement_ensure_authority",
        "execute_retirement_common_gate",
        "execute_retirement_predecessor_gate",
        "require_retirement_predecessor_authority",
    )
    for proc_name in removed_retirement_procs:
        if f"proc {proc_name} " in transport:
            fail(f"transport retains retired mutation procedure {proc_name}")
    if "retire-prestage-2c690050" in transport:
        fail("transport retains the retired public retirement operation")
    if "retire-raw-" in transport:
        fail("transport retains a private retirement mutation leaf")

    retained_helper = tcl_proc(transport, "retained_retirement_helper_remote_argv")
    retained_helper_lines = tuple(
        line.strip() for line in retained_helper.splitlines() if line.strip()
    )
    if retained_helper_lines != (
        "return [list /bin/bash -p $::RETIREMENT_AUTH_SELF verify-retirement \\",
        "--manifest $::RETIREMENT_AUTH_MANIFEST \\",
        "--manifest-sha256 $::RETAINED_RETIREMENT_MANIFEST_SHA256]",
    ):
        fail("retained retirement helper argv is not the fixed verifier-only form")
    if "$mode" in retained_helper or "?" in retained_helper:
        fail("retained retirement helper argv still selects a caller-supplied mode")
    if transport.count("verify-retirement") != 1:
        fail("verify-retirement escaped the private retained-helper argv")

    public_transport_surface = "\n".join(
        (
            tcl_proc(transport, "transaction_operation"),
            read_only,
            transport_main,
        )
    )
    private_operation_guard = (
        'if {[regexp {^(?:r2-(?:ro|raw)-|lineage-)} $operation]} {\n'
        '        fail "private-operation" 65\n'
        "    }"
    )
    if transport_main.count(private_operation_guard) != 1:
        fail("transport does not reject the exact private R1/R2 namespace before policy")
    public_transport_surface_without_guard = public_transport_surface.replace(
        private_operation_guard, ""
    )
    for private_literal in (
        "retire-prestage",
        "verify-retirement",
        "retire-raw-",
        "lineage-",
        "retirement_lineage",
    ):
        if private_literal in public_transport_surface_without_guard:
            fail(f"transport CLI surface exposes private lineage literal {private_literal!r}")

    lineage_builder = tcl_proc(transport, "build_retirement_lineage_operation")
    existence_builder = lineage_builder[
        lineage_builder.index(
            "if {[regexp {^lineage-exists-(user-intake|home-qroot|run-qroot|receipt-pending)$}"
        ) : lineage_builder.index("    } else {")
    ]
    ordered(
        existence_builder,
        (
            "switch -- $path_name",
            "set fixed_path $::RETIREMENT_USER_INTAKE",
            "set fixed_path $::RETIREMENT_HOME_QROOT",
            "set fixed_path $::RETIREMENT_RUN_QROOT",
            "set fixed_path $::RETIREMENT_RECEIPT_PENDING",
            "[list /usr/bin/find [file dirname $fixed_path] -xdev",
            "-mindepth 1 -maxdepth 1 -name [file tail $fixed_path] -print",
        ),
        "fixed-parent retirement lineage existence builder",
    )
    if (
        lineage_builder.count("set assertion none") != 1
        or "set assertion" in existence_builder
        or "/usr/bin/test" in existence_builder
    ):
        fail("lineage existence builder is not stdout-only fixed-parent find")
    for mutable_argv in (
        "/usr/bin/mkdir",
        "/usr/bin/install",
        "/bin/ln",
        "/bin/mv",
        "/usr/bin/scp",
        "/bin/rm",
        "/usr/bin/touch",
    ):
        if mutable_argv in lineage_builder:
            fail(f"private lineage builder contains mutation argv {mutable_argv!r}")

    expected_current_package_names = (
        "source-4f2a9b61.bundle",
        "package-manifest.v1",
        "bind-final-package.sh",
        "controller.sh",
        "prepare-stage-root.sh",
        "provision-ubuntu-test-host.sh",
        "root-matrix-n-r.sh",
        "check-realhost-iperf.py",
        "test-hermetic-matrix.sh",
        "test_matrix_static.py",
        "checksum-module-lease.sh",
        "test-hermetic-checksum-module-lease.sh",
        "test_checksum_module_lease_static.py",
        "wg_mix_faketcp_checksum.c",
        "root-fresh-verifier-gate.sh",
        "test-hermetic-fresh-verifier-gate.sh",
        "test_fresh_verifier_gate_static.py",
        "realnic_acceptance.py",
        "test_realnic_acceptance.py",
        "test_realnic_acceptance_static.py",
    )
    if len(expected_current_package_names) != 20:
        fail("test current package oracle is not the fixed 20-file tuple")
    if tcl_return_words(transport, "package_names") != expected_current_package_names:
        fail("transport current package identity is not the fixed 20-file tuple")
    if tuple(bash_array(controller, "PACKAGE_NAMES").split()) != expected_current_package_names:
        fail("controller current package identity is not the fixed 20-file tuple")
    raw_package_match = re.search(
        r"(?ms)^readonly -a RAW_MUTATION_PACKAGE_NAMES=\((?P<body>.*?)^\)\n",
        hermetic,
    )
    if (
        not raw_package_match
        or tuple(raw_package_match.group("body").split())
        != expected_current_package_names
    ):
        fail("hermetic current package oracle is not the fixed 20-file tuple")
    ordered(
        hermetic,
        (
            'BOUND_MATRIX_OUTPUT="$(/bin/bash "${BOUND_OUTPUT}/test-hermetic-matrix.sh")"',
            "for name in test-hermetic-checksum-module-lease.sh",
            "test_checksum_module_lease_static.py wg_mix_faketcp_checksum.c; do",
            '/bin/mv -- "${bound_file}" "${bound_backup}"',
            'bound_missing_output="$(/bin/bash "${BOUND_OUTPUT}/test-hermetic-matrix.sh" 2>&1)"',
            '[[ "${bound_missing_rc}" -eq 0 ||',
            '"${bound_missing_output}" != *"review input is not a regular file: ${bound_file}"*',
            '/bin/mv -- "${bound_backup}" "${bound_file}"',
            '"$(sha256_file "${bound_file}")" == "$(manifest_value "${key}_sha256" "${BOUND_MANIFEST}")"',
            '[[ "${BOUND_CLOSURE_MISSING_CUTS}" -eq 3 ]]',
        ),
        "bound flat checksum dependency closure gate",
    )
    c_source_path = "kernel/faketcp_checksum/wg_mix_faketcp_checksum.c"
    if package_array.count(f'"{c_source_path}"') != 1:
        fail("binder does not bind exactly one fixed checksum C source path")
    for name, body, path_literal in (
        (
            "controller",
            bash_function(controller, "verify_manifest_contract"),
            '"${WG_MIX_FAKETCP_CHECKSUM_C_PATH}" == '
            f"'{c_source_path}'",
        ),
        (
            "transport",
            tcl_proc(transport, "validate_manifest_values"),
            "[dict get $values wg_mix_faketcp_checksum_c_path] ne\n"
            f'            "{c_source_path}"',
        ),
        (
            "root-stager",
            bash_function(stager, "validate_manifest"),
            f'"${{MODULE_SOURCE_PATH}}" == \'{c_source_path}\'',
        ),
    ):
        if body.count(path_literal) != 1:
            fail(f"{name} does not bind the exact checksum C source path")
    staged_identity_gate = bash_function(stager, "require_staged_content")
    ordered(
        staged_identity_gate,
        (
            '"$(sha256_file "${EXPECTED_SOURCE}/${MODULE_SOURCE_PATH}")" == '
            '"${MODULE_SOURCE_SHA256}"',
            'require_staged_identity "${MODULE_SOURCE_PATH}" "${MODULE_SOURCE_BLOB}"',
            '"${MODULE_SOURCE_SHA256}" 100644 600',
        ),
        "checksum C source blob/SHA/tree/file mode gate",
    )

    expected_retained_package_names = (
        "source-4f2a9b61.bundle",
        "package-manifest.v1",
        "bind-final-package.sh",
        "controller.sh",
        "prepare-stage-root.sh",
        "provision-ubuntu-test-host.sh",
        "root-matrix-n-r.sh",
        "check-realhost-iperf.py",
        "test-hermetic-matrix.sh",
        "test_matrix_static.py",
        "checksum-module-lease.sh",
        "root-fresh-verifier-gate.sh",
        "test-hermetic-fresh-verifier-gate.sh",
        "test_fresh_verifier_gate_static.py",
        "realnic_acceptance.py",
        "test_realnic_acceptance.py",
        "test_realnic_acceptance_static.py",
    )
    if (
        tcl_return_words(transport, "retained_retirement_package_names")
        != expected_retained_package_names
    ):
        fail("retained retirement package identity is not the fixed 17-file tuple")

    # R2 is a third, independent authority.  These expectations are deliberately
    # literal and are not derived from any production parser or package helper.
    r2_controller_constants = (
        f"readonly R2_PREDECESSOR_COMMIT='{r2_predecessor_commit}'",
        "readonly R2_PREDECESSOR_REF='refs/heads/codex/tcx-faketcp-final-v2'",
        f"readonly R2_PREDECESSOR_PACKAGE='{r2_predecessor_package}'",
        'readonly R2_PREDECESSOR_MANIFEST="${R2_PREDECESSOR_PACKAGE}/package-manifest.v1"',
        f"readonly R2_PREDECESSOR_MANIFEST_SHA256='{r2_predecessor_manifest_sha}'",
        f"readonly R2_PREDECESSOR_BUNDLE_SHA256='{r2_predecessor_bundle_sha}'",
        "readonly R2_PREDECESSOR_HISTORY_ROOTS_SHA256='9356df63b3d4c4c362912b14ab8ee5cb54d12cd1f14be9aa1fe8e18adbad6f05'",
        "readonly R2_PREDECESSOR_HISTORY_OBJECTS_SHA256='21647f92e57f9dbb8e15707699f632544d6dfcf2e1b4279d775cce1fb82163f3'",
    )
    for literal in r2_controller_constants:
        if controller.count(literal) != 1:
            fail(f"controller R2 fixed authority constant drifted: {literal!r}")
    for override in (
        "R2_PREDECESSOR_PACKAGE:-",
        "R2_PREDECESSOR_PACKAGE:=",
        "R2_PREDECESSOR_PACKAGE?",
        "getenv(\"R2_PREDECESSOR_PACKAGE\"",
        "os.environ",
    ):
        if override in controller:
            fail(f"controller permits an R2 predecessor path override: {override!r}")
    if controller.count("set -o pipefail") != 1:
        fail("controller does not preserve pipeline status explicitly")

    controller_r2_verifier = bash_function_until(
        controller,
        "verify_r2_predecessor_manifest_contract",
        "verify_r2_local_authorities",
    )
    controller_r2_manifest_match = re.search(
        r"(?ms)<<'R2_PREDECESSOR_MANIFEST_V4' \|\| return \$\?\n"
        r"(?P<payload>.*?)^R2_PREDECESSOR_MANIFEST_V4$",
        controller_r2_verifier,
    )
    if (
        not controller_r2_manifest_match
        or controller_r2_manifest_match.group("payload")
        != r2_predecessor_manifest_payload
    ):
        fail("controller predecessor manifest is not the independent canonical v4/103 bytes")
    controller_r2_required = (
        'getattr(os, "O_NONBLOCK", 0)',
        "package_fd = os.open(package_name, directory_flags)",
        "bundle_fd = kept_descriptor",
        "history_fd = os.open(\"history-verification.git\", directory_flags, dir_fd=package_fd)",
        "def enter_held_history():",
        "os.fchdir(history_fd)",
        "pass_fds=(history_fd, bundle_fd)",
        "preexec_fn=enter_held_history",
        "if result.returncode != 0:",
        'actual_objects = run_git(\n        ("rev-list", "--parents", "--objects", "--missing=print", integration_commit)',
        "file_identity(os.fstat(bundle_fd)) != initial_file_identities[",
        "directory_identity(held_package_after) != package_identity",
    )
    ordered(
        controller_r2_verifier,
        controller_r2_required,
        "controller held-FD predecessor verifier",
    )
    r2_history_ref_gate = (
        'if run_git((\n'
        '            "for-each-ref", "--format=%(objectname) %(refname)")) != (\n'
        '            integration_commit + " refs/heads/history-verified\\n").encode("ascii"):\n'
        "        raise SystemExit(76)"
    )
    if (
        controller_r2_verifier.count(r2_history_ref_gate) != 1
        or controller_r2_verifier.count("for-each-ref") != 1
        or controller_r2_verifier.count(
            "--format=%(objectname) %(refname)"
        )
        != 1
        or controller_r2_verifier.count("refs/heads/history-verified") != 1
    ):
        fail("controller held-FD predecessor history ref/commit gate is not exact")
    held_ref_slice = controller_r2_verifier[
        controller_r2_verifier.index('if run_git((\n            "for-each-ref"') :
        controller_r2_verifier.index(
            'run_git(("fsck"',
            controller_r2_verifier.index('if run_git((\n            "for-each-ref"'),
        )
    ]
    if (
        held_ref_slice.count("raise SystemExit(76)") != 1
        or controller_r2_verifier.count("subprocess.run(") != 1
        or any(
            fallback in held_ref_slice
            for fallback in (
                "package_name",
                "history_repository",
                "history-verification.git",
                "cwd=",
                '"-C"',
                "show-ref",
                "symbolic-ref",
                "rev-parse",
            )
        )
    ):
        fail("controller predecessor ref gate escapes held-FD Git or lacks rc 76")
    if controller_r2_verifier.count("O_NONBLOCK") != 2:
        fail("controller predecessor verifier does not nonblock both file and directory opens")
    if any(
        forbidden in controller_r2_verifier
        for forbidden in (
            "shell=True",
            "os.chdir(",
            "cwd=package_name",
            '"rev-parse", "HEAD"',
        )
    ):
        fail("controller predecessor verifier escapes its held history/package authority")

    controller_r2_transport_modes = (
        "retire-postflight-f75fe7678cfd-r2",
        "verify-postflight-retirement-r2",
    )
    for mode in controller_r2_transport_modes:
        if controller_main.count(f"run_operation execute {mode}") != 1:
            fail(f"controller R2 public mode is not one high-level call: {mode}")
    r2_verify_arm = re.search(
        r"(?ms)^\s*verify-r2-predecessor-package\)\n(?P<body>.*?)^\s*;;$",
        controller_main,
    )
    if not r2_verify_arm:
        fail("cannot isolate controller local-only R2 predecessor verifier arm")
    r2_verify_arm_body = r2_verify_arm.group("body")
    r2_verify_marker_prefix = (
        "B82_V6_CONTROLLER_R2_PREDECESSOR_VERIFIED "
        "predecessor_manifest_sha256=%s predecessor_commit=%s "
        "package_device_inode=%s credential_read=0 network_operations=0"
    )
    if (
        r2_verify_arm_body.count(r2_verify_marker_prefix) != 1
        or any(
            token in r2_verify_arm_body
            for token in (
                "run_operation",
                "transport ",
                "CREDENTIAL",
                "/usr/bin/expect",
                "/usr/bin/ssh",
                "/usr/bin/scp",
            )
        )
        or not r2_verify_arm_body.rstrip().endswith('"${R2_PREDECESSOR_DEVICE_INODE}"')
    ):
        fail("controller local-only R2 verifier is not the exact-last no-network marker seam")
    r2_outer_authority = controller_main[: controller_main.index('case "${MODE}" in\n    veth-plan')]
    ordered(
        r2_outer_authority,
        (
            "verify_manifest_contract || fail 'manifest-contract' $?",
            "verify-r2-predecessor-package | \\",
            "retire-postflight-f75fe7678cfd-r2 | verify-postflight-retirement-r2)",
            "verify_r2_local_authorities || fail 'r2-local-authority' $?",
        ),
        "controller R2 current/predecessor local authority order",
    )
    r2_local_authorities = bash_function(controller, "verify_r2_local_authorities")
    ordered(
        r2_local_authorities,
        (
            "format=v5 fields=112 package_files=20 credential_read=0 network_operations=0",
            'R2_PREDECESSOR_DEVICE_INODE="$(verify_r2_predecessor_manifest_contract)"',
            "format=v4 fields=103 package_files=17 credential_read=0 network_operations=0",
        ),
        "controller independent current/predecessor authority seam",
    )

    transport_r2_oracle_words = tcl_return_words(
        transport, "r2_predecessor_manifest_oracle"
    )
    if len(transport_r2_oracle_words) != 206:
        fail("transport R2 predecessor oracle is not 103 key/value pairs")
    transport_r2_manifest_lines = tuple(
        f"{transport_r2_oracle_words[index]}\t{transport_r2_oracle_words[index + 1]}"
        for index in range(0, len(transport_r2_oracle_words), 2)
    )
    if transport_r2_manifest_lines != r2_predecessor_manifest_lines:
        fail("transport predecessor parser does not bind the independent canonical v4/103")
    r2_load_predecessor = tcl_proc(transport, "r2_load_predecessor_manifest")
    ordered(
        r2_load_predecessor,
        (
            "r2_predecessor_manifest_oracle",
            "[llength $lines] != 103",
            "[llength $oracle] != 206",
            "foreach {expected_key expected_value} $oracle",
            "[lindex $fields 0] ne $expected_key",
            "[lindex $fields 1] ne $expected_value",
        ),
        "transport separate v4/103 predecessor parser",
    )
    for current_authority in ("load_manifest ", "package_names", "validate_manifest_values"):
        if current_authority in r2_load_predecessor:
            fail(f"transport predecessor parser reuses current authority: {current_authority}")

    if (
        tcl_return_words(transport, "r2_predecessor_package_names")
        != r2_predecessor_package_names
    ):
        fail("transport R2 predecessor package identity is not the fixed 17-file tuple")
    if tcl_return_words(transport, "r2_mutation_operations") != r2_raw_operations:
        fail("transport R2 raw mutation surface/order is not the fixed 21-item tuple")
    r2_stale_body = tcl_proc(transport, "r2_stale_operations")
    r2_stale_match = re.search(
        r"(?ms)^\s*set operations \{(?P<body>.*?)\}", r2_stale_body
    )
    if (
        not r2_stale_match
        or tuple(r2_stale_match.group("body").split()) != r2_stale_operations
        or "prepare_stale_operations" in r2_stale_body
    ):
        fail("transport R2 stale oracle is not the independent fixed 28-item tuple")
    r2_sha_body = tcl_proc(transport, "r2_predecessor_package_sha")
    r2_size_body = tcl_proc(transport, "r2_predecessor_package_size")
    for name, expected_sha, expected_size in r2_predecessor_package_contract:
        sha_case = rf"(?ms)^\s*{re.escape(name)} \{{\s*return {expected_sha}\s*\}}"
        size_case = rf"(?m)^\s*{re.escape(name)} \{{ return {expected_size} \}}$"
        if not re.search(sha_case, r2_sha_body) or not re.search(size_case, r2_size_body):
            fail(f"transport R2 predecessor SHA/size contract drifted: {name}")
    for producer_body, producer_name in (
        (tcl_proc(transport, "package_names"), "current package list"),
        (tcl_proc(transport, "retained_retirement_package_names"), "R1 package list"),
        (tcl_proc(transport, "r2_predecessor_package_names"), "R2 package list"),
    ):
        if any(
            other in producer_body
            for other in (
                "package_names]",
                "retained_retirement_package_names]",
                "r2_predecessor_package_names]",
            )
        ):
            fail(f"transport {producer_name} is derived from another package authority")

    r2_mutation_classifier = tcl_proc(transport, "r2_mutation_operation")
    r2_read_classifier = tcl_proc(transport, "r2_read_only_operation")
    if (
        tuple(re.findall(r'"([a-z0-9-]+)"', r2_mutation_classifier))
        != (controller_r2_transport_modes[0],)
        or tuple(re.findall(r'"([a-z0-9-]+)"', r2_read_classifier))
        != (controller_r2_transport_modes[1],)
    ):
        fail("transport R2 public surface is not exactly one mutation plus one verifier")
    build_r2 = tcl_proc(transport, "build_r2_operation")

    # Close the private RO surface in both directions.  The test owns the 96
    # literal names above; production must make exactly 13 fixed-path probes,
    # 17 x 2 frozen predecessor probes, and 49 explicit switch leaves
    # reachable.  Merely finding all 96 strings somewhere in the builder would
    # permit dead labels or an unreviewed generated family.
    r2_fixed_path = tcl_proc(transport, "r2_fixed_path")
    expected_fixed_paths = (
        ("home-qroot", "$::R2_HOME_QROOT"),
        ("auth-root", "$::R2_AUTH_ROOT"),
        ("run-qroot", "$::R2_RUN_QROOT"),
        ("auth-manifest-pending", "$::R2_AUTH_MANIFEST_PENDING"),
        ("auth-manifest", "$::R2_AUTH_MANIFEST"),
        ("auth-self-pending", "$::R2_AUTH_SELF_PENDING"),
        ("auth-self", "$::R2_AUTH_SELF"),
        ("quarantine-intake", "$::R2_Q_INTAKE"),
        ("quarantine-package", "$::R2_Q_PACKAGE"),
        ("quarantine-bootstrap", "$::R2_Q_BOOTSTRAP"),
        ("lock", "$::R2_LOCK"),
        ("receipt-pending", "$::R2_RECEIPT_PENDING"),
        ("receipt-final", "$::R2_RECEIPT_FINAL"),
    )
    actual_fixed_paths = tuple(
        re.findall(
            r"(?m)^\s{8}([a-z0-9-]+) \{ return (\$::R2_[A-Z_]+) \}$",
            r2_fixed_path,
        )
    )
    if (
        actual_fixed_paths != expected_fixed_paths
        or r2_fixed_path.count(
            'default { return -code error "r2-fixed-path" }'
        )
        != 1
    ):
        fail("transport R2 fixed-path resolver is not the exact 13-path map")
    generated_exists = tuple(
        f"r2-ro-exists-{name}" for name, _ in expected_fixed_paths
    )
    generated_old_package = tuple(
        f"r2-ro-old-package-{family}-{name}"
        for name in r2_predecessor_package_names
        for family in ("sha", "stat")
    )
    dynamic_ro_families = tuple(
        re.findall(
            r"(?ms)\[regexp \{\^(r2-ro-[^}]*)\}\s*(?:\\\n\s*)?"
            r"\$operation -> ([^\]]+)\]",
            build_r2,
        )
    )
    if (
        dynamic_ro_families
        != (
            ("r2-ro-exists-(.+)$", "path_name"),
            ("r2-ro-old-package-(sha|stat)-(.+)$", "family name"),
        )
        or
        build_r2.count(r"[regexp {^r2-ro-exists-(.+)$} $operation -> path_name]")
        != 1
        or build_r2.count("set fixed_path [r2_fixed_path $path_name]") != 1
        or build_r2.count(
            "[regexp {^r2-ro-old-package-(sha|stat)-(.+)$} \\\n"
            "        $operation -> family name]"
        )
        != 1
        or build_r2.count(
            "[lsearch -exact [r2_predecessor_package_names] $name] < 0"
        )
        != 1
    ):
        fail("transport R2 generated RO families are not exact and closed")
    explicit_switch_start = build_r2.index(
        "    } else {\n        switch -- $operation {"
    )
    explicit_switch_end = build_r2.index(
        '\n            default { return -code error "r2-operation" }',
        explicit_switch_start,
    )
    explicit_switch = build_r2[explicit_switch_start:explicit_switch_end]
    explicit_case_labels = tuple(
        label
        for line in explicit_switch.splitlines()
        if line.startswith("            r2-")
        for label in re.findall(r"r2-(?:ro|raw)-[a-z0-9.-]+", line)
    )
    explicit_ro = tuple(
        label for label in explicit_case_labels if label.startswith("r2-ro-")
    )
    explicit_raw = tuple(
        label for label in explicit_case_labels if label.startswith("r2-raw-")
    )
    effective_ro = (*generated_exists, *generated_old_package, *explicit_ro)
    actual_ro_literals = ordered_unique(
        tuple(re.findall(r"r2-ro-[a-z0-9.-]+", build_r2))
    )
    if (
        len(generated_exists) != 13
        or set(generated_exists) != set(r2_ro_operations[:13])
        or len(generated_old_package) != 34
        or set(generated_old_package) != set(r2_ro_operations[13:47])
        or len(explicit_ro) != 49
        or len(set(explicit_ro)) != 49
        or set(explicit_ro) != set(r2_ro_operations[47:])
        or len(effective_ro) != 96
        or len(set(effective_ro)) != 96
        or set(effective_ro) != set(r2_ro_operations)
        or actual_ro_literals
        != ("r2-ro-exists-", "r2-ro-old-package-", *explicit_ro)
        or explicit_raw != r2_raw_operations
    ):
        fail("transport R2 builder effective private surface is not 13+34+49 RO/21 raw")
    actual_raw_literals = ordered_unique(
        tuple(re.findall(r"r2-raw-[a-z0-9-]+", build_r2))
    )
    if actual_raw_literals != r2_raw_operations:
        fail("transport R2 builder raw leaf set/order is not exact 21")
    for prohibited_mutation in (
        "/bin/rm",
        "/usr/bin/rm",
        "/bin/rmdir",
        "/usr/bin/rmdir",
        "/bin/mv",
        "/usr/bin/cp",
        "--delete",
        "-p $::R2_",
    ):
        if prohibited_mutation in build_r2:
            fail(f"transport R2 builder contains prohibited mutation fallback: {prohibited_mutation}")
    ordered(
        build_r2,
        (
            "r2-raw-intake-mkdir",
            "/usr/bin/mkdir --mode=0700 -- $::R2_USER_INTAKE",
            "r2-raw-scp-manifest",
            "r2-raw-scp-self",
            "r2-raw-home-qroot-create",
            "r2-raw-home-qroot-create { set fixed_path $::R2_HOME_QROOT }",
            "/usr/bin/mkdir --mode=0700 -- $fixed_path",
            "r2-raw-auth-manifest-install",
            "/usr/bin/install --owner=root --group=root --mode=0600",
            "--no-target-directory -- $source",
            "r2-raw-link-auth-manifest",
            "/usr/bin/ln --no-target-directory --",
            "r2-raw-helper-mutate",
            "r2_helper_remote_argv $manifest_sha",
        ),
        "transport fixed R2 mutation argv surface",
    )

    # A resumable authority install may overwrite only bytes that were first
    # proved to be an exact prefix of the still-bound local artifact.  Keep the
    # four observation leaves explicit so the private RO surface cannot grow by
    # hiding an unreviewed write-adjacent probe behind a generic operation.
    pending_shape_arm = build_r2[
        build_r2.index("r2-ro-auth-manifest-pending-shape -") :
        build_r2.index("r2-ro-auth-manifest-pending-sha-observe -")
    ]
    pending_sha_arm = build_r2[
        build_r2.index("r2-ro-auth-manifest-pending-sha-observe -") :
        build_r2.index("r2-ro-auth-manifest-pending-sha -")
    ]
    if ordered_unique(
        tuple(re.findall(r"r2-ro-auth-[a-z-]+", pending_shape_arm))
    ) != (
        "r2-ro-auth-manifest-pending-shape",
        "r2-ro-auth-self-pending-shape",
    ):
        fail("transport R2 pending shape operation labels are not exact")
    ordered(
        pending_shape_arm,
        (
            "r2-ro-auth-manifest-pending-shape",
            "set artifact $::R2_AUTH_MANIFEST_PENDING",
            "set artifact $::R2_AUTH_SELF_PENDING",
            "/usr/bin/stat -Lc %U:%G:%a:%h:%s:%F -- $artifact",
        ),
        "transport R2 pending shape operation argv",
    )
    if ordered_unique(
        tuple(re.findall(r"r2-ro-auth-[a-z-]+", pending_sha_arm))
    ) != (
        "r2-ro-auth-manifest-pending-sha-observe",
        "r2-ro-auth-self-pending-sha-observe",
    ):
        fail("transport R2 pending observed-SHA operation labels are not exact")
    ordered(
        pending_sha_arm,
        (
            "r2-ro-auth-manifest-pending-sha-observe",
            "$::R2_AUTH_MANIFEST_PENDING : $::R2_AUTH_SELF_PENDING",
            "/usr/bin/sha256sum -- $artifact",
        ),
        "transport R2 pending observed-SHA operation argv",
    )
    if "set assertion" in pending_shape_arm or "set assertion" in pending_sha_arm:
        fail("transport R2 pending observations are not raw observed values")

    r2_local_delivery = tcl_proc(transport, "r2_local_delivery_file")
    ordered(
        r2_local_delivery,
        (
            "set package [dict get $values local_package_dir]",
            "package-manifest.v1 { set expected_sha $manifest_sha }",
            "prepare-stage-root.sh {",
            "[dict get $values prepare_stage_root_sh_sha256]",
            'default { return -code error "r2-delivery-name" }',
            'set artifact "${package}/${name}"',
            "[file normalize $artifact] ne $artifact",
            "file lstat $artifact artifact_stat",
            "file lstat $package package_stat",
            '$artifact_stat(type) ne "file"',
            "$artifact_stat(nlink) != 1",
            "$artifact_stat(size) < 1",
            "$artifact_stat(size) > 16777216",
            "($artifact_stat(mode) & 07777) != 0600",
            '$package_stat(type) ne "directory"',
            "($package_stat(mode) & 07777) != 0700",
            "$artifact_stat(uid) != $package_stat(uid)",
            "$artifact_stat(gid) != $package_stat(gid)",
            "[file_sha256 $artifact] ne $expected_sha",
            "return [list $artifact $expected_sha]",
        ),
        "transport R2 local delivery authority",
    )
    r2_prefix_sha = tcl_proc(transport, "r2_file_prefix_sha256")
    ordered(
        r2_prefix_sha,
        (
            "[string is integer -strict $length]",
            "$length < 0",
            "$length > 16777216",
            "[file normalize $path] ne $path",
            '[file type $path] ne "file"',
            "set channel [open $path r]",
            "fconfigure $channel -encoding binary -translation binary",
            "read $channel $length",
            "[string bytelength $payload] != $length",
            "exec /usr/bin/shasum -a 256 << $payload",
            "^[0-9a-f]{64}$",
        ),
        "transport local held-authority prefix digest",
    )
    r2_pending_size = tcl_proc(transport, "r2_observe_auth_pending_size")
    if re.search(r'(?m)^\s*set pattern "[^"\n]*\[0-9\]', r2_pending_size):
        fail("transport R2 pending size regexp permits Tcl command substitution")
    if (
        "set pattern [format {" not in r2_pending_size
        or "([0-9]+):regular file$}" not in r2_pending_size
        or "$expected_mode]" not in r2_pending_size
    ):
        fail("transport R2 pending size regexp is not brace/format safe")
    ordered(
        r2_pending_size,
        (
            "r2_step $values $manifest_sha $predecessor_values",
            "package-manifest.v1 { set expected_mode 600 }",
            "prepare-stage-root.sh { set expected_mode 700 }",
            "set pattern [format {",
            "([0-9]+):regular file$}",
            "$expected_mode]",
            "$size < 0",
            "$size > 16777216",
        ),
        "transport root-owned pending shape observation",
    )
    r2_observe_sha = tcl_proc(transport, "r2_observe_sha")
    ordered(
        r2_observe_sha,
        (
            "r2_step $values $manifest_sha $predecessor_values",
            "$operation $password",
            "output_value [lindex $result 2]",
            "set digest [string range $value 0 63]",
            "^[0-9a-f]{64}$",
            '[string range $value 64 end] ne "  ${artifact}"',
            'fail "r2-sha-output" 78',
            "return $digest",
        ),
        "transport R2 observed remote SHA parser",
    )
    r2_pending_prefix = tcl_proc(transport, "r2_require_auth_pending_prefix")
    ordered(
        r2_pending_prefix,
        (
            "package-manifest.v1 {",
            "set shape_operation r2-ro-auth-manifest-pending-shape",
            "set sha_operation r2-ro-auth-manifest-pending-sha-observe",
            "set remote_artifact $::R2_AUTH_MANIFEST_PENDING",
            "prepare-stage-root.sh {",
            "set shape_operation r2-ro-auth-self-pending-shape",
            "set sha_operation r2-ro-auth-self-pending-sha-observe",
            "set remote_artifact $::R2_AUTH_SELF_PENDING",
            "r2_local_delivery_file $values $manifest_sha $name",
            "file lstat $local_artifact local_stat",
            "r2_observe_auth_pending_size $values $manifest_sha",
            "r2_observe_sha $values $manifest_sha $predecessor_values",
            "$remote_size > $local_stat(size)",
            'fail "r2-auth-pending-oversize" 78',
            "$remote_size == $local_stat(size) && $remote_sha eq $expected_sha",
            "set prefix_class exact",
            "r2_file_prefix_sha256 $local_artifact $remote_size",
            "$remote_sha ne $prefix_sha",
            'fail "r2-auth-pending-nonprefix" 78',
            "$remote_size == 0",
            "set prefix_class empty",
            "set prefix_class prefix",
            "r2_local_delivery_file $values $manifest_sha $name",
            "$rechecked_artifact ne $local_artifact",
            "$rechecked_sha ne $expected_sha",
            "file lstat $rechecked_artifact rechecked_stat",
            "foreach field {dev ino size mode nlink uid gid type}",
            "return $prefix_class",
        ),
        "transport resumable authority prefix proof",
    )
    if (
        r2_pending_prefix.count("r2_local_delivery_file") != 2
        or r2_pending_prefix.count("r2_observe_auth_pending_size") != 1
        or r2_pending_prefix.count("r2_observe_sha") != 1
        or r2_pending_prefix.count("r2_file_prefix_sha256") != 1
        or r2_pending_prefix.count("return $prefix_class") != 1
    ):
        fail("transport R2 pending-prefix proof cardinality drifted")
    if (
        r2_pending_prefix.count("set prefix_class exact") != 1
        or r2_pending_prefix.count("set prefix_class empty") != 1
        or r2_pending_prefix.count("set prefix_class prefix") != 1
        or r2_pending_prefix.count(
            "$rechecked_stat($field) ne $local_stat($field)"
        )
        != 1
    ):
        fail("transport R2 pending-prefix classification/recheck drifted")

    r2_ensure_authority = tcl_proc(transport, "r2_ensure_authority")
    if r2_ensure_authority.count("r2_require_auth_pending_prefix") != 4:
        fail("transport R2 authority resume does not prove every existing pending file")
    manifest_resume = r2_ensure_authority[
        r2_ensure_authority.index('if {$phase eq "manifest-pending"}') :
        r2_ensure_authority.index('if {$phase eq "manifest-pair"}')
    ]
    ordered(
        manifest_resume,
        (
            "set self_present [dict get [dict get $state present] auth-self-pending]",
            "r2_require_auth_pending_prefix",
            "package-manifest.v1 $password",
            '$manifest_prefix_class ne "exact"',
            "r2-raw-auth-manifest-install",
            "r2-ro-auth-manifest-pending-sha",
            "r2-raw-auth-self-install",
            "elseif {!$manifest_installed_here || !$self_installed_here}",
            "r2_require_auth_pending_prefix",
            "package-manifest.v1 $password",
            "r2_require_auth_pending_prefix",
            "prepare-stage-root.sh $password",
            '$manifest_prefix_class ne "exact"',
            "r2-raw-auth-manifest-install",
            '$self_prefix_class ne "exact"',
            "r2-raw-auth-self-install",
        ),
        "transport manifest-pending no-blind-overwrite resume",
    )
    if (
        manifest_resume.count("r2-raw-auth-manifest-install") != 2
        or manifest_resume.count("r2-raw-auth-self-install") != 2
    ):
        fail("transport manifest-pending resume has an unproved install path")
    self_resume = r2_ensure_authority[
        r2_ensure_authority.index('if {$phase eq "self-pending"}') :
        r2_ensure_authority.index('if {$phase ne "complete"}')
    ]
    ordered(
        self_resume,
        (
            "r2_require_auth_pending_prefix",
            "prepare-stage-root.sh $password",
            '$self_prefix_class ne "exact"',
            "r2-raw-auth-self-install",
            "r2-ro-auth-self-pending-sha",
        ),
        "transport self-pending no-blind-overwrite resume",
    )
    if self_resume.count("r2-raw-auth-self-install") != 1:
        fail("transport self-pending resume has an unproved install path")
    for resume_flag in (
        "pending_pair_synced",
        "manifest_installed_here",
        "self_installed_here",
    ):
        flag_values = re.findall(
            rf"(?m)^\s*set {re.escape(resume_flag)} ([^\s]+)$",
            r2_ensure_authority,
        )
        if not flag_values or flag_values[0] != "0" or set(flag_values) - {"0", "1"}:
            fail(f"transport R2 resume flag is not monotone 0-to-1: {resume_flag}")

    r2_authority_state = tcl_proc(transport, "r2_authority_state")
    authority_names_match = re.search(
        r"(?ms)^\s*set names \{(?P<body>.*?)\}", r2_authority_state
    )
    expected_authority_names = (
        "home-qroot",
        "auth-root",
        "run-qroot",
        "auth-manifest-pending",
        "auth-manifest",
        "auth-self-pending",
        "auth-self",
        "quarantine-intake",
        "quarantine-package",
        "quarantine-bootstrap",
        "lock",
        "receipt-pending",
        "receipt-final",
    )
    if (
        not authority_names_match
        or tuple(authority_names_match.group("body").split())
        != expected_authority_names
    ):
        fail("transport R2 authority state does not probe exactly 13 fixed paths")
    actual_authority_phases = ordered_unique(
        tuple(
            re.findall(
                r"(?:set phase|return \[dict create phase) ([A-Za-z0-9_-]+)",
                r2_authority_state,
            )
        )
    )
    if (
        set(actual_authority_phases) != set(r2_authority_phases)
        or len(actual_authority_phases) != len(r2_authority_phases)
        or r2_authority_state.count("phase manifest-pending present") != 2
        or any(
            r2_authority_state.count(f"phase {phase} present") != 1
            for phase in r2_authority_phases
            if phase != "manifest-pending"
        )
    ):
        fail("transport R2 authority classifier phase set/cardinality is not exact")
    if "pending-pair" in r2_authority_state:
        fail("transport R2 authority classifier introduces an unowned pending-pair phase")

    ordered(
        transport_main,
        (
            "require_transaction_local_authority $values $manifest_sha",
            "set predecessor_values [r2_require_predecessor_authority]",
            "execute_r2_predecessor_controller_verifier $values $manifest_sha",
            "set password [read_execute_credential $credential_path]",
        ),
        "transport R2 precredential current/predecessor/controller order",
    )
    private_guard_index = transport_main.index(private_operation_guard)
    manifest_load_index = transport_main.index("load_manifest $manifest $manifest_sha")
    credential_index = transport_main.index("set password [read_execute_credential")
    if not private_guard_index < manifest_load_index < credential_index:
        fail("transport private operation rejection is not before manifest and credential access")
    postcredential = transport_main[credential_index:]
    ordered(
        postcredential,
        (
            "set password [read_execute_credential $credential_path]",
            "if {[r2_mutation_operation $operation]}",
            "execute_r2_transaction",
            "elseif {[r2_read_only_operation $operation]}",
            "execute_r2_verify_transaction",
        ),
        "transport R2 high-level dispatch after credential",
    )

    r2_transaction = tcl_proc(transport, "execute_r2_transaction")
    ordered(
        r2_transaction,
        (
            "r2_require_r1_terminal $values $manifest_sha $password preflight",
            "r2_authority_state",
            "r2_execute_common_gate",
            "r2_execute_predecessor_gate",
            "r2_ensure_delivery",
            "r2_ensure_authority",
            "r2-raw-helper-mutate",
            "r2_exact_verify",
            "r2_require_r1_terminal $values $manifest_sha $password postflight",
            "B82_V6_R2_TRANSACTION_COMPLETE",
        ),
        "transport R2 transaction pre/post lineage and sole helper seam",
    )
    r2_verify_transaction = tcl_proc(transport, "execute_r2_verify_transaction")
    if (
        "r2_exact_verify" not in r2_verify_transaction
        or "r2_require_r1_terminal" not in r2_verify_transaction
        or "r2-raw-" in r2_verify_transaction
    ):
        fail("transport R2 verify transaction is not a read-only terminal check")

    expected_lineage_deep_operations = (
        "lineage-home-readlink",
        "lineage-home-stat",
        "lineage-home-entries",
        "lineage-auth-readlink",
        "lineage-auth-stat",
        "lineage-auth-entries",
        "lineage-run-readlink",
        "lineage-run-stat",
        "lineage-run-entries",
        "lineage-auth-manifest-pending-stat",
        "lineage-auth-manifest-pending-sha",
        "lineage-auth-manifest-stat",
        "lineage-auth-manifest-sha",
        "lineage-auth-manifest-pair",
        "lineage-auth-self-pending-stat",
        "lineage-auth-self-pending-sha",
        "lineage-auth-self-stat",
        "lineage-auth-self-sha",
        "lineage-auth-self-pair",
        "lineage-q-intake-readlink",
        "lineage-q-intake-stat",
        "lineage-q-intake-entries",
        "lineage-q-intake-manifest-stat",
        "lineage-q-intake-manifest-sha",
        "lineage-q-intake-self-stat",
        "lineage-q-intake-self-sha",
        "lineage-q-package-readlink",
        "lineage-q-package-stat",
        "lineage-q-package-entries",
        "lineage-q-bootstrap-readlink",
        "lineage-q-bootstrap-stat",
        "lineage-q-bootstrap-entries",
        "lineage-lock-stat",
        "lineage-receipt-stat",
        "lineage-receipt-sha",
    )
    r2_r1_terminal_prewrite = (
        "lineage-exists-user-intake",
        "lineage-exists-home-qroot",
        "lineage-exists-run-qroot",
        "lineage-exists-receipt-pending",
        *expected_lineage_deep_operations,
        "lineage-exists-user-intake",
        "lineage-exists-home-qroot",
        "lineage-exists-run-qroot",
        "lineage-exists-receipt-pending",
        "lineage-retained-helper-verify",
    )
    r2_fresh_authority_prewrite = r2_ro_operations[:13]
    r2_common_prewrite = (
        "identity-hostname",
        "identity-kernel",
        "identity-machine",
        "identity-netns",
        "identity-interface",
        *r2_stale_operations,
    )
    r2_predecessor_prewrite = (
        "package-parent-stat",
        "r2-ro-old-package-readlink",
        "r2-ro-old-package-stat",
        "r2-ro-old-package-entries",
        *tuple(
            operation
            for name in r2_predecessor_package_names
            for operation in (
                f"r2-ro-old-package-sha-{name}",
                f"r2-ro-old-package-stat-{name}",
            )
        ),
        "r2-ro-old-bootstrap-root-readlink",
        "r2-ro-old-bootstrap-root-stat",
        "r2-ro-old-bootstrap-provisioner-readlink",
        "r2-ro-old-bootstrap-provisioner-stat",
        "r2-ro-old-bootstrap-provisioner-sha",
        "r2-ro-old-bootstrap-stager-readlink",
        "r2-ro-old-bootstrap-stager-stat",
        "r2-ro-old-bootstrap-stager-sha",
        "r2-ro-old-bootstrap-entries",
        "r2-ro-old-provision-check",
    )
    expected_r2_prewrite_sequence = (
        *r2_r1_terminal_prewrite,
        *r2_fresh_authority_prewrite,
        *r2_common_prewrite,
        *r2_predecessor_prewrite,
    )
    if (
        tuple(
            len(group)
            for group in (
                r2_r1_terminal_prewrite,
                r2_fresh_authority_prewrite,
                r2_common_prewrite,
                r2_predecessor_prewrite,
            )
        )
        != (44, 13, 33, 48)
        or len(expected_r2_prewrite_sequence) != 138
        or expected_r2_prewrite_sequence[63] != "stale-stage-root"
        or expected_r2_prewrite_sequence[-1] != "r2-ro-old-provision-check"
    ):
        fail("test R2 prewrite oracle is not exact 44+13+33+48=138")

    r2_common_gate = tcl_proc(transport, "r2_execute_common_gate")
    ordered(
        r2_common_gate,
        (
            "foreach operation [base_identity_operations]",
            "set operations [r2_stale_operations]",
            "items=28",
            "identities=5 stale_absent=28 writes=0 result=PASS",
        ),
        "transport R2 fixed 5+28 common prewrite gate",
    )
    r2_predecessor_gate = tcl_proc(transport, "r2_execute_predecessor_gate")
    ordered(
        r2_predecessor_gate,
        (
            "transaction_step $values $manifest_sha package-parent-stat none $password",
            "r2-ro-old-package-readlink r2-ro-old-package-stat",
            "r2-ro-old-package-entries",
            "foreach name [r2_predecessor_package_names]",
            "foreach family {sha stat}",
            '"r2-ro-old-package-${family}-${name}"',
            "r2-ro-old-bootstrap-root-readlink r2-ro-old-bootstrap-root-stat",
            "r2-ro-old-bootstrap-provisioner-readlink",
            "r2-ro-old-bootstrap-provisioner-stat",
            "r2-ro-old-bootstrap-provisioner-sha",
            "r2-ro-old-bootstrap-stager-readlink",
            "r2-ro-old-bootstrap-stager-stat r2-ro-old-bootstrap-stager-sha",
            "r2-ro-old-bootstrap-entries",
            "r2-ro-old-provision-check",
            '[lindex $result 3] ne "none"',
            "package_files=17 bootstrap_files=2 provision_missing=none primitives=48 writes=0 result=PASS",
        ),
        "transport R2 exact 48-primitive predecessor prewrite gate",
    )
    if "--apply" in r2_predecessor_gate or r2_predecessor_gate.count(
        "r2-ro-old-provision-check"
    ) != 1:
        fail("transport R2 predecessor gate is not one frozen --check-only proof")
    r2_delivery = tcl_proc(transport, "r2_ensure_delivery")
    delivery_first_mutation = r2_delivery.index("r2_try_intake_mkdir")
    if "r2-raw-" in r2_delivery[:delivery_first_mutation]:
        fail("transport R2 delivery mutates before the fixed intake mkdir seam")
    r2_try_mkdir = tcl_proc(transport, "r2_try_intake_mkdir")
    if (
        r2_try_mkdir.count("execute_r2_primitive") != 1
        or r2_try_mkdir.count("r2_mutation_trace_record r2-raw-intake-mkdir") != 1
        or "r2-raw-scp-" in r2_try_mkdir
    ):
        fail("transport R2 first write is not the sole intake mkdir operation")
    intake_mkdir_case = build_r2[
        build_r2.index("r2-raw-intake-mkdir {") : build_r2.index(
            "r2-raw-scp-manifest", build_r2.index("r2-raw-intake-mkdir {")
        )
    ]
    ordered(
        intake_mkdir_case,
        (
            "r2-raw-intake-mkdir",
            "/usr/bin/mkdir --mode=0700 -- $::R2_USER_INTAKE",
        ),
        "transport R2 0-based first-write index 138 exact argv",
    )
    for operation in expected_lineage_deep_operations:
        if operation not in lineage_builder:
            fail(f"private lineage builder is missing fixed operation {operation}")

    lineage_primitive = tcl_proc(
        transport, "execute_retirement_lineage_primitive"
    )
    ordered(
        lineage_primitive,
        (
            "require_manifest_authority $values $manifest_sha",
            "build_retirement_lineage_operation $values $operation",
            'fail "retirement-lineage-policy" 66',
            "execute_operation_spec $operation $operation_spec $password",
        ),
        "private lineage primitive authority/execution seam",
    )
    if transport.count("build_retirement_lineage_operation") != 2:
        fail("private lineage builder is reachable outside its sole executor")

    lineage_exists = tcl_proc(transport, "retirement_lineage_path_exists")
    ordered(
        lineage_exists,
        (
            "switch -- $operation",
            "set fixed_path $::RETIREMENT_USER_INTAKE",
            "set fixed_path $::RETIREMENT_HOME_QROOT",
            "set fixed_path $::RETIREMENT_RUN_QROOT",
            "set fixed_path $::RETIREMENT_RECEIPT_PENDING",
            "execute_retirement_lineage_primitive $values $manifest_sha",
            'if {[lindex $result 0] ne "ok"}',
            'fail "retirement-lineage-partial-$operation" 78',
            "set value [output_value [lindex $result 2]]",
            'if {$value eq ""}',
            "return 0",
            "if {$value eq $fixed_path}",
            "return 1",
            'fail "retirement-lineage-presence-output-$operation" 78',
        ),
        "lineage stdout existence classifier",
    )
    if "child-failure" in lineage_exists or "child-signal" in lineage_exists:
        fail("lineage existence classifier admits child failures as absence")

    lineage_step = tcl_proc(transport, "retirement_lineage_step")
    ordered(
        lineage_step,
        (
            "execute_retirement_lineage_primitive",
            'if {[lindex $result 0] ne "ok"}',
            'fail "retirement-lineage-partial-$operation" 78',
            "writes=0",
        ),
        "retirement lineage fail-stop step",
    )

    lineage_gate = tcl_proc(transport, "execute_retirement_lineage_gate")
    deep_match = re.search(
        r"(?ms)foreach operation \{(?P<body>.*?)\} \{\s*"
        r"retirement_lineage_step \$values \$manifest_sha \$operation \$password",
        lineage_gate,
    )
    if (
        not deep_match
        or tuple(deep_match.group("body").split())
        != expected_lineage_deep_operations
    ):
        fail("terminal lineage deep-operation tuple is not exact")
    ordered(
        lineage_gate,
        (
            "lineage-exists-user-intake $password",
            "lineage-exists-home-qroot $password",
            "lineage-exists-run-qroot $password",
            'if {!$user_intake && !$home_qroot && !$run_qroot}',
            "state=FRESH",
            "namespace_writes=0",
            "return FRESH",
            'if {$user_intake || !$home_qroot || !$run_qroot}',
            'fail "retirement-lineage-partial-state" 78',
            "lineage-exists-receipt-pending $password",
            'fail "retirement-lineage-receipt-pending" 78',
            "foreach operation {",
            "lineage-exists-user-intake $password",
            "lineage-exists-home-qroot $password",
            "lineage-exists-run-qroot $password",
            "lineage-exists-receipt-pending $password",
            'fail "retirement-lineage-terminal-recheck" 78',
            "lineage-retained-helper-verify $password",
            "state=TERMINAL",
            "retained_commit=$::RETAINED_RETIREMENT_COMMIT",
            "retained_manifest_sha256=$::RETAINED_RETIREMENT_MANIFEST_SHA256",
            "retained_helper_sha256=$::RETAINED_RETIREMENT_HELPER_SHA256",
            "receipt_sha256=$::RETAINED_RETIREMENT_RECEIPT_SHA256",
            "namespace_writes=0",
            "return TERMINAL",
        ),
        "fresh/terminal retirement lineage classifier",
    )
    if lineage_gate.count("lineage-retained-helper-verify") != 1:
        fail("terminal lineage verifier is not one final fail-stop step")

    approved_proc = tcl_proc(transport, "operation_requires_approved_sha")
    approved_match = re.search(r"(?ms)\$operation in \{(?P<body>.*?)\}", approved_proc)
    if not approved_match or tuple(approved_match.group("body").split()) != approved_operations:
        fail("transport digest requirement is not the exact seven-operation tuple")
    if transport_main.count("operation_requires_approved_sha $operation") != 2:
        fail("transport does not enforce both required-digest and forbidden-digest directions")

    build_operation = tcl_proc(transport, "build_operation")
    stale_switch = build_operation[
        build_operation.index("stale-package-root") : build_operation.index("package-mkdir")
    ]
    transport_stale_operations = re.findall(r"stale-[a-z0-9-]+", stale_switch)
    if (
        len(transport_stale_operations) != 30
        or set(transport_stale_operations) != set(expected_stale_operations)
    ):
        fail("transport does not implement exactly the controller's 30 stale operations")

    prepare_transaction = tcl_proc(transport, "execute_prepare_transaction")
    ordered(
        prepare_transaction,
        (
            "execute_stale_transaction_gate $values $manifest_sha $password",
            "transaction_step $values $manifest_sha package-parent-stat none $password",
            "execute_retirement_lineage_gate $values $manifest_sha $password",
            "transaction_step $values $manifest_sha package-mkdir none $password",
            "foreach name [package_names]",
            'transaction_step $values $manifest_sha "scp-$name" none $password',
            'transaction_step $values $manifest_sha "verify-sha-$name" none $password',
            'transaction_step $values $manifest_sha "verify-stat-$name" none $password',
            "foreach operation [bootstrap_create_operations]",
        ),
        "atomic prepare transaction copy/verify sequence",
    )
    prepare_lines = tuple(
        line.strip() for line in prepare_transaction.splitlines() if line.strip()
    )
    parent_index = prepare_lines.index(
        "transaction_step $values $manifest_sha package-parent-stat none $password"
    )
    if prepare_lines[parent_index : parent_index + 3] != (
        "transaction_step $values $manifest_sha package-parent-stat none $password",
        "execute_retirement_lineage_gate $values $manifest_sha $password",
        "transaction_step $values $manifest_sha package-mkdir none $password",
    ):
        fail("private lineage gate is not adjacent to the first namespace write")
    if prepare_transaction.count("execute_retirement_lineage_gate") != 1:
        fail("prepare does not execute exactly one private lineage gate")
    ordered(
        tcl_proc(transport, "verify_remote_package_transaction"),
        (
            "foreach name [package_names]",
            'transaction_step $values $manifest_sha "verify-sha-$name" none $password',
            'transaction_step $values $manifest_sha "verify-stat-$name" none $password',
        ),
        "remote package verification transaction",
    )
    execute_transaction = tcl_proc(transport, "execute_transaction")
    for operation, expected in (
        ("realnic-run", "scp-realnic-approved-plan verify-sha-realnic-approved-plan verify-stat-realnic-approved-plan stage-realnic-plan-snapshot realnic-run"),
        ("realnic-restore", "stage-realnic-plan-verify realnic-restore"),
    ):
        match = re.search(
            rf"(?ms)^\s*{operation} \{{\s*foreach primitive \{{(.*?)\}} \{{",
            execute_transaction,
        )
        if not match or tuple(match.group(1).split()) != tuple(expected.split()):
            fail(f"transport {operation} transaction leaf sequence is not exact")

    generic_package = build_operation[build_operation.index(
        '} elseif {[regexp {^(scp|verify-sha|verify-stat)-(.+)$} $operation'
    ) :]
    ordered(
        generic_package,
        (
            "set expected_sha [package_sha $values $name]",
            'if {$family eq "scp"}',
            "file lstat $local_path local_stat",
            "$local_stat(size) < 1 || $local_stat(size) > 16777216",
            "[file_sha256 $local_path] ne $expected_sha",
            'return -code error "scp-local-file"',
            "return [list scp $spawn_argv",
            '} elseif {$family eq "verify-sha"}',
            "/usr/bin/sha256sum",
            "/usr/bin/stat -Lc %U:%G:%a:%h:%F",
        ),
        "bounded manifest-bound generic SCP",
    )

    clean_status = tcl_proc(transport, "clean_child_exit_status")
    clean_status_contract = (
        "[llength $wait_status] != 4",
        "[lindex $wait_status 2] != 0",
        "![string is integer -strict [lindex $wait_status 3]]",
        "[lindex $wait_status 3] < 0",
        "[lindex $wait_status 3] > 255",
        'return -code error "child-wait-status"',
        "return [lindex $wait_status 3]",
    )
    ordered(clean_status, clean_status_contract, "clean child exit status")
    if transport.count("clean_child_exit_status $wait_status") != 3:
        fail("not every capture/ordinary child wait uses the signal-rejecting status parser")
    ordinary_execute = tcl_proc(transport, "execute_operation_spec")
    ordered(
        ordinary_execute,
        (
            "spawn -noecho {*}$spawn_argv",
            "set child_id $spawn_id",
            "wait -i $child_id",
            "clean_child_exit_status $wait_status",
            'fail "child-wait-status" 78',
            "if {$child_rc != 0}",
            "return [list child-failure $child_rc $captured_output none]",
            "if {$assertion eq \"provision-check\"}",
            "assert_output $assertion $captured_output",
        ),
        "ordinary execute signal fail-closed path",
    )
    if transport_main.index('if {$action eq "plan"}') > transport_main.index(
        "read_execute_credential $credential_path"
    ):
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
        transport.index("proc fresh_remote_argv") : transport.index("proc veth_remote_argv")
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
        "root_veth_n_r_sh_path",
        "test_hermetic_veth_runner_sh_path",
        "test_veth_runner_static_py_path",
        "controller_seam_sh_path",
        "root_routed_veth_n_r_sh_path",
        "test_hermetic_routed_veth_harness_sh_path",
        "test_routed_veth_harness_static_py_path",
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
        "S6.veth-hermetic",
        "S6.veth-static",
        "S6.routed-hermetic",
        "S6.routed-static",
        "S7 /usr/bin/shellcheck --norc --shell=bash --",
        "PYTHONDONTWRITEBYTECODE=1",
        '"${EXPECTED_SOURCE}/${REALNIC_TEST_PATH}"',
        '"${EXPECTED_SOURCE}/${REALNIC_STATIC_PATH}"',
        "realnic-hermetic-unit",
        "realnic-hermetic-static",
    )
    for literal in required_stager:
        if literal not in stager:
            fail(f"root stager contract is missing {literal!r}")

    for removed_engine_literal in (
        "run_retirement_engine",
        "retire-prestage-2c690050",
        "verify-retirement",
        "readonly RETIRE_ID=",
        '"${RETIREMENT_USER_INTAKE}"',
        '"${RETIREMENT_HOME_QROOT}"',
        '"${RETIREMENT_AUTH_ROOT}"',
        '"${RETIREMENT_AUTH_MANIFEST}"',
        '"${RETIREMENT_AUTH_SELF}"',
        '"${RETIREMENT_Q_INTAKE}"',
        '"${RETIREMENT_Q_PACKAGE}"',
        '"${RETIREMENT_RUN_QROOT}"',
        '"${RETIREMENT_Q_BOOTSTRAP}"',
        '"${RETIREMENT_RECEIPT_FINAL}"',
    ):
        if removed_engine_literal in stager:
            fail(
                "root stager retains embedded retirement engine literal "
                f"{removed_engine_literal!r}"
            )

    r2_engine_shell = bash_function_until(
        stager, "run_r2_retirement_engine", "run_stage"
    )
    r2_engine_match = re.search(r"(?ms)<<'PY'\n(?P<payload>.*?)^PY$", r2_engine_shell)
    if not r2_engine_match or r2_engine_shell.count("<<'PY'") != 1:
        fail("root stager does not embed exactly one R2 retirement engine")
    r2_engine = r2_engine_match.group("payload")
    try:
        r2_engine_tree = ast.parse(r2_engine)
    except SyntaxError as exc:
        fail(f"root stager R2 engine is not valid Python: {exc}")
    engine_function_nodes = tuple(
        node for node in r2_engine_tree.body if isinstance(node, ast.FunctionDef)
    )
    expected_engine_functions = (
        "stop",
        "require_absolute",
        "open_abs_dir",
        "open_parent",
        "fd_mnt_id",
        "require_dir_fd",
        "names_at",
        "entry_stat",
        "entry_is_directory",
        "read_all",
        "sha256_fd",
        "require_file_at",
        "require_sized_file_at",
        "parse_manifest_ordered",
        "require_pair",
        "same_open_inode",
        "require_host_identity",
        "require_exact_names",
        "open_child_dir",
        "require_path_absent",
        "r1_receipt_bytes",
        "validate_r1_retained_entries",
        "validate_r1_terminal",
        "validate_current_manifest_payload",
        "validate_current_authority",
        "converge_current_authority",
        "validate_intake",
        "validate_old_package",
        "validate_old_bootstrap",
        "verify_old_provisioner_check",
        "regular_present",
        "classify_state",
        "boot_identity",
        "write_all",
        "acquire_retirement_lock",
        "initialize_or_verify_boot_marker",
        "receipt_bytes",
        "validate_receipt",
        "validate_pending_receipt",
        "validate_state_objects",
        "renameat2_noreplace",
        "rename_directory_noreplace",
        "publish_receipt",
        "converge_completed_rename",
        "converge_completed_rename_parents",
        "converge_resumed_state",
        "converge_terminal",
        "engine_main",
    )
    if tuple(node.name for node in engine_function_nodes) != expected_engine_functions:
        fail("root stager R2 engine function surface/order drifted")
    engine_functions = {
        node.name: ast.get_source_segment(r2_engine, node) or ""
        for node in engine_function_nodes
    }
    if r2_engine.count("engine_main()") != 2 or not re.search(
        r"(?ms)^try:\n    engine_main\(\)\nexcept RetirementStop", r2_engine
    ):
        fail("root stager does not invoke its actual R2 engine_main exactly once")

    engine_assignments: dict[str, ast.AST] = {}
    for node in r2_engine_tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    engine_assignments[target.id] = node.value
    for required_assignment in (
        "CURRENT_KEYS",
        "OLD_MANIFEST_BYTES",
        "OLD_PACKAGE_FILES",
        "OLD_BOOTSTRAP_FILES",
    ):
        if required_assignment not in engine_assignments:
            fail(f"root stager R2 engine omits {required_assignment}")
    try:
        engine_current_keys = ast.literal_eval(engine_assignments["CURRENT_KEYS"])
        engine_old_package = ast.literal_eval(engine_assignments["OLD_PACKAGE_FILES"])
        engine_old_bootstrap = ast.literal_eval(engine_assignments["OLD_BOOTSTRAP_FILES"])
    except (TypeError, ValueError) as exc:
        fail(f"root stager R2 package authority is not literal: {exc}")
    expected_old_package = {
        name: (size, digest)
        for name, digest, size in r2_predecessor_package_contract
    }
    expected_old_bootstrap = {
        "prepare-stage-root.sh": (
            54230,
            "1bcb8db91d976d2a1d95f7d87223a2dac4a1678f74c1c25542e54b01ee10eeea",
        ),
        "provision-ubuntu-test-host.sh": (
            19437,
            "078d191b0edbafe27e9f684d3fa495e04d7217a01d0ec1fd32eaede211178c8f",
        ),
    }
    if engine_current_keys != expected_manifest_keys:
        fail("root stager R2 current authority is not independent v5/112")
    if engine_old_package != expected_old_package or tuple(
        engine_old_package
    ) != r2_predecessor_package_names:
        fail("root stager R2 predecessor authority is not independent v4/103/17")
    if engine_old_bootstrap != expected_old_bootstrap:
        fail("root stager R2 predecessor bootstrap is not the fixed two-file tuple")
    old_manifest_node = engine_assignments["OLD_MANIFEST_BYTES"]
    if (
        not isinstance(old_manifest_node, ast.Call)
        or not isinstance(old_manifest_node.func, ast.Attribute)
        or old_manifest_node.func.attr != "encode"
        or not isinstance(old_manifest_node.func.value, ast.Constant)
        or old_manifest_node.func.value.value != r2_predecessor_manifest_payload
    ):
        fail("root stager R2 predecessor manifest is not canonical v4/103 bytes")
    for old_authority in (
        "CURRENT_KEYS",
        "validate_current_manifest_payload",
        "validate_current_authority",
    ):
        if old_authority in engine_functions["validate_old_package"]:
            fail(f"root stager predecessor parser reuses current authority: {old_authority}")
    for predecessor_authority in (
        "OLD_MANIFEST_BYTES",
        "OLD_PACKAGE_FILES",
        "validate_old_package",
    ):
        if predecessor_authority in engine_functions["validate_current_authority"]:
            fail(
                "root stager current parser reuses predecessor authority: "
                f"{predecessor_authority}"
            )

    ordered(
        r2_engine_shell,
        (
            '"${MODE}" "${MANIFEST}" "${MANIFEST_SHA256}"',
            '"${R2_AUTH_MANIFEST_PENDING}" "${R2_AUTH_SELF}"',
            '"${R2_AUTH_SELF_PENDING}"',
            '"${R2_USER_INTAKE}" "${R2_HOME_QROOT}"',
            '"${R2_AUTH_ROOT}" "${R2_Q_INTAKE}"',
            '"${R2_Q_PACKAGE}" "${EXPECTED_REMOTE_PACKAGE}" "${BOOTSTRAP_ROOT}"',
            '"${R2_RUN_QROOT}" "${R2_Q_BOOTSTRAP}" "${R2_LOCK}"',
            '"${R2_RECEIPT_PENDING}" "${R2_RECEIPT_FINAL}"',
            '"${R2_PREDECESSOR_COMMIT}" "${R2_PREDECESSOR_MANIFEST_SHA256}"',
            '"${EXPECTED_HOSTNAME}" "${EXPECTED_KERNEL}" "${EXPECTED_MACHINE_ID}"',
        ),
        "root stager fixed R2 engine argv",
    )
    ordered(
        r2_engine,
        (
            "if len(sys.argv) != 24:",
            'stop("engine-arguments", 64)',
            "(mode, current_manifest, current_manifest_sha, current_manifest_pending,",
            "current_self, current_self_pending, user_intake, home_qroot,",
            "expected_machine_id) = sys.argv[1:]",
            "current_self_sha = None",
        ),
        "root stager exact 24-argument held-authority engine interface",
    )
    if "PREPARE_SHA256" in r2_engine_shell or "prepare_sha" in r2_engine:
        fail("root stager passes an independently trusted self SHA into the R2 engine")
    if r2_engine.count('mode not in {"retire-postflight-f75fe7678cfd-r2", "verify-postflight-retirement-r2"}') != 1:
        fail("root stager R2 engine mode surface is not exact")
    stager_main = bash_function(stager, "main")
    if (
        stager_main.count(
            "retire-postflight-f75fe7678cfd-r2 | verify-postflight-retirement-r2)"
        )
        != 1
        or stager_main.count("load_r2_retirement_authority_contract") != 1
        or stager_main.count("run_r2_retirement_engine") != 1
    ):
        fail("root stager exposes anything other than the two fixed R2 engine modes")
    r2_authority_loader = bash_function(stager, "load_r2_retirement_authority_contract")
    ordered(
        r2_authority_loader,
        (
            '[[ "$(/usr/bin/id -u)" == \'0\' ]]',
            '"${MANIFEST}" == "${R2_AUTH_MANIFEST}"',
            '[[ "$0" == "${R2_AUTH_SELF}" ]]',
        ),
        "root stager pre-engine fixed-path-only authority gate",
    )
    if any(
        forbidden_loader_io in r2_authority_loader
        for forbidden_loader_io in (
            "sha256_file",
            "validate_manifest",
            "read_manifest_field",
            "readlink",
            "stat ",
            "exec {",
            "<\"",
        )
    ):
        fail("root stager reopens or parses current authority before the held-FD engine")

    validate_current_authority = engine_functions["validate_current_authority"]
    ordered(
        validate_current_authority,
        (
            "require_exact_names(auth_descriptor, {",
            "os.path.basename(current_manifest)",
            "os.path.basename(current_manifest_pending)",
            "os.path.basename(current_self)",
            "os.path.basename(current_self_pending)",
            '"authority-manifest-pending"',
            '"authority-manifest-final"',
            "require_file_at(",
            "same_open_inode(descriptors[0], descriptors[1]",
            "manifest_payload = read_all(descriptors[1])",
            "values = validate_current_manifest_payload(",
            'authority_self_sha = values["prepare_stage_root_sh_sha256"]',
            '"authority-self-pending"',
            '"authority-self-final"',
            "require_file_at(",
            "same_open_inode(descriptors[2], descriptors[3]",
            "hashlib.sha256(read_all(descriptors[3])).hexdigest()",
            "return values, authority_self_sha, tuple(descriptors)",
        ),
        "root stager current manifest-pair-derived held self authority",
    )
    if (
        validate_current_authority.count("require_file_at(") != 2
        or validate_current_authority.count("descriptors.append") != 2
        or 'expected_sha = current_self_sha' in validate_current_authority
    ):
        fail("root stager current authority does not hold exactly four manifest-derived FDs")
    converge_current_authority = engine_functions["converge_current_authority"]
    ordered(
        converge_current_authority,
        (
            "if len(descriptors) != 4:",
            'stop("authority-held-count", 65)',
            "for descriptor in descriptors:",
            "os.fsync(descriptor)",
            "os.fsync(auth_descriptor)",
            "require_exact_names(auth_descriptor",
            "for descriptor, (name, mode_bits, expected_sha, label) in zip(",
            "metadata = os.fstat(descriptor)",
            "named = os.stat(name, dir_fd=auth_descriptor, follow_symlinks=False)",
            "(metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)",
            "sha256_fd(descriptor) != expected_sha",
            "same_open_inode(descriptors[0], descriptors[1]",
            "same_open_inode(descriptors[2], descriptors[3]",
            "validate_current_manifest_payload(",
            'post_values["prepare_stage_root_sh_sha256"] != authority_self_sha',
            "hashlib.sha256(read_all(descriptors[3])).hexdigest() != authority_self_sha",
        ),
        "root stager held current authority post-fsync convergence",
    )

    # Opening an attacker-controlled FIFO must never block before the regular
    # file check.  O_NONBLOCK is harmless for the required regular files.
    for literal in (
        '"O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"',
        "O_NONBLOCK = os.O_NONBLOCK",
    ):
        if r2_engine.count(literal) != 1:
            fail(f"root stager R2 FIFO/nonblocking gate drifted: {literal!r}")
    for function_name in (
        "require_file_at",
        "acquire_retirement_lock",
        "publish_receipt",
    ):
        function_body = engine_functions[function_name]
        if function_body.count("O_NONBLOCK") != 1 or "os.open(" not in function_body:
            fail(f"root stager R2 {function_name} can block on a FIFO before fstat")

    prohibited_engine_calls = []
    for node in ast.walk(r2_engine_tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and (
                (node.func.value.id == "os" and node.func.attr in {
                    "unlink",
                    "remove",
                    "rmdir",
                    "removedirs",
                    "rename",
                    "renames",
                    "replace",
                })
                or (node.func.value.id in {"shutil", "pathlib"} and node.func.attr in {
                    "copy",
                    "copy2",
                    "copyfile",
                    "copytree",
                    "move",
                    "rmtree",
                    "rename",
                    "replace",
                    "unlink",
                    "rmdir",
                })
            )
        ):
            prohibited_engine_calls.append(
                f"{node.func.value.id}.{node.func.attr}"
            )
    if prohibited_engine_calls:
        fail(f"root stager R2 engine has destructive/copy fallback: {prohibited_engine_calls}")
    if "import shutil" in r2_engine or "from shutil" in r2_engine:
        fail("root stager R2 engine imports a copy/move fallback")

    classify_state = engine_functions["classify_state"]
    classify_node = next(node for node in engine_function_nodes if node.name == "classify_state")
    state_assignments = [
        node.value
        for node in ast.walk(classify_node)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "states" for target in node.targets)
    ]
    if len(state_assignments) != 1:
        fail("root stager R2 engine does not have one literal state classifier")
    try:
        actual_state_matrix = ast.literal_eval(state_assignments[0])
    except (TypeError, ValueError) as exc:
        fail(f"root stager R2 state matrix is not literal: {exc}")
    expected_state_matrix = {
        (True, True, True, False, False, False, False, False): "D",
        (False, True, True, True, False, False, False, False): "I",
        (False, False, True, True, True, False, False, False): "S1",
        (False, False, False, True, True, True, False, False): "S2",
        (False, False, False, True, True, True, True, False): "S2P",
        (False, False, False, True, True, True, False, True): "T_CANDIDATE",
    }
    if actual_state_matrix != expected_state_matrix:
        fail("root stager R2 engine state classifier is not D/I/S1/S2/S2P/T_CANDIDATE")
    if 'return "T"' not in engine_functions["converge_terminal"]:
        fail("root stager R2 engine lacks the separately verified T convergence")

    rename_directory = engine_functions["rename_directory_noreplace"]
    ordered(
        rename_directory,
        (
            "source_parent, source_name = open_parent(source)",
            "destination_parent, destination_name = open_parent(destination)",
            "source_parent_metadata = os.fstat(source_parent)",
            "destination_parent_metadata = os.fstat(destination_parent)",
            "fd_mnt_id(source_parent) != fd_mnt_id(destination_parent)",
            "held_descriptor = open_child_dir(",
            "held_identity = os.fstat(held_descriptor)",
            "held_mount = fd_mnt_id(held_descriptor)",
            "renameat2_noreplace(source_parent, source_name,",
            "destination_descriptor = open_child_dir(",
            "same_open_inode(held_descriptor, destination_descriptor",
            "held_mount != fd_mnt_id(destination_descriptor)",
            "os.fsync(source_parent)",
            "os.fsync(destination_parent)",
            "same_open_inode(held_descriptor, destination_descriptor",
            "validator(destination_descriptor)",
            "validator(held_descriptor)",
        ),
        "root stager held-inode/mount rename transaction",
    )
    if (
        rename_directory.count("os.fsync(source_parent)") != 1
        or rename_directory.count("os.fsync(destination_parent)") != 1
        or r2_engine.count("libc.renameat2") != 1
        or r2_engine.count("RENAME_NOREPLACE = 1") != 1
    ):
        fail("root stager R2 rename primitive/double-parent durability drifted")
    engine_main_body = engine_functions["engine_main"]
    ordered(
        engine_main_body,
        (
            'if state == "D":',
            "rename_directory_noreplace(\n                user_intake, q_intake",
            'if state != "I":',
            'if state == "I":',
            "rename_directory_noreplace(\n                source_package, q_package",
            'if state != "S1":',
            'if state == "S1":',
            "rename_directory_noreplace(\n                source_bootstrap, q_bootstrap",
            'if state != "S2":',
            'if state not in {"S2", "S2P"}:',
            "publish_receipt(",
            'if state != "T_CANDIDATE":',
            "converge_terminal(",
        ),
        "root stager exact D/I/S1/S2/S2P/T_CANDIDATE/T transition order",
    )
    verify_branch = engine_main_body[
        engine_main_body.index('if mode == "verify-postflight-retirement-r2":') :
        engine_main_body.index('if state == "T_CANDIDATE":')
    ]
    if (
        "namespace_writes=0" not in verify_branch
        or any(
            mutation in verify_branch
            for mutation in (
                "rename_directory_noreplace",
                "publish_receipt",
                "write_all",
                "os.ftruncate",
                "os.write",
            )
        )
    ):
        fail("root stager R2 verify mode is not namespace-write-free")
    acquire_lock = engine_functions["acquire_retirement_lock"]
    initialize_lock = engine_functions["initialize_or_verify_boot_marker"]
    ordered(
        acquire_lock,
        (
            'writable = mode == "retire-postflight-f75fe7678cfd-r2"',
            "if not writable:",
            'stop("retirement-lock-absent", 78)',
            "os.O_CREAT | os.O_EXCL",
            "fcntl.LOCK_EX if writable else fcntl.LOCK_SH",
            "fcntl.LOCK_NB",
        ),
        "root stager same-boot lock mode/create gate",
    )
    ordered(
        initialize_lock,
        (
            'writable = mode == "retire-postflight-f75fe7678cfd-r2"',
            'expected = f"boot_id\\t{boot_id}\\n".encode("ascii")',
            "if existing == expected:",
            'if (state != "D" or not writable or not expected.startswith(existing)):',
            'stop("same-boot-residual")',
            "os.ftruncate(lock_descriptor, 0)",
            "write_all(lock_descriptor, expected)",
            "os.fsync(lock_descriptor)",
            "os.fsync(run_descriptor)",
        ),
        "root stager same-boot marker convergence",
    )

    provision_check = engine_functions["verify_old_provisioner_check"]
    ordered(
        provision_check,
        (
            '"provision-ubuntu-test-host.sh"',
            '["/bin/bash", "-p", f"/proc/self/fd/{provisioner}", "--check"',
            '"--expected-address", "192.168.10.82"',
            '"--expected-interface", "ens33"',
            "timeout=600",
            "pass_fds=(provisioner,)",
            "if result.returncode != 0:",
            '"mode=check"',
            '"missing_packages="',
            '"plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0"',
            "held = os.fstat(provisioner)",
            'named = os.stat("provision-ubuntu-test-host.sh"',
            "sha256_fd(provisioner)",
            'return ("none", "0")',
        ),
        "root stager frozen predecessor provision --check self-verification",
    )
    if '"--apply"' in provision_check or "shell=True" in provision_check:
        fail("root stager predecessor provision proof can apply or invoke a shell string")

    receipt_function_node = next(
        node for node in engine_function_nodes if node.name == "receipt_bytes"
    )
    receipt_line_assignments = [
        node.value
        for node in ast.walk(receipt_function_node)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "lines" for target in node.targets)
    ]
    if len(receipt_line_assignments) != 1 or not isinstance(
        receipt_line_assignments[0], ast.Tuple
    ):
        fail("root stager R2 receipt does not have one literal ordered tuple")
    receipt_environment = {
        "current_manifest_sha": "a" * 64,
        "current_self_sha": "b" * 64,
        "source_package": r2_predecessor_remote_package,
        "source_bootstrap": r2_predecessor_bootstrap,
        "user_intake": r2_user_intake,
        "q_intake": f"{r2_home_qroot}/intake",
        "q_package": f"{r2_home_qroot}/package",
        "q_bootstrap": f"{r2_run_qroot}/bootstrap",
    }

    def receipt_value(node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in receipt_environment:
            return receipt_environment[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return receipt_value(node.left) + receipt_value(node.right)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "current_values"
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "integration_commit"
        ):
            return "c" * 40
        fail(f"root stager R2 receipt has a non-contract expression: {ast.dump(node)}")
        raise AssertionError

    actual_receipt_pairs = []
    for item in receipt_line_assignments[0].elts:
        if not isinstance(item, ast.Tuple) or len(item.elts) != 2:
            fail("root stager R2 receipt entry is not one key/value pair")
        actual_receipt_pairs.append(
            (receipt_value(item.elts[0]), receipt_value(item.elts[1]))
        )
    expected_receipt_pairs = (
        ("format", "wg-mix-ebpf-b82-postflight-retirement-terminal-v1"),
        ("retire_id", r2_retire_id),
        ("state", "TERMINAL"),
        ("predecessor_commit", r2_predecessor_commit),
        ("predecessor_manifest_sha256", r2_predecessor_manifest_sha),
        ("predecessor_bundle_sha256", r2_predecessor_bundle_sha),
        ("predecessor_package_format", "wg-mix-ebpf-b82-v6-package-v4"),
        ("predecessor_manifest_field_count", "103"),
        ("predecessor_package_entry_count", "17"),
        ("predecessor_bootstrap_entry_count", "2"),
        ("authority_manifest_sha256", "a" * 64),
        ("authority_prepare_stage_root_sha256", "b" * 64),
        ("authority_integration_commit", "c" * 40),
        ("authority_package_format", "wg-mix-ebpf-b82-v6-package-v5"),
        ("authority_manifest_field_count", "112"),
        ("authority_transfer_entry_count", "20"),
        ("prior_retirement_id", "c8e41d73-2c690050ae1d-r1"),
        ("prior_retirement_receipt_sha256", retained_retirement_receipt_sha),
        ("failure_cut", "postflight-hermetic-matrix-before-stage-snapshot"),
        ("failure_point", "hermetic-matrix"),
        ("failure_reason", "review-input-is-not-a-regular-file"),
        (
            "failure_path",
            f"{r2_predecessor_remote_package}/test-hermetic-checksum-module-lease.sh",
        ),
        ("failure_rc", "1"),
        ("provision_check", "missing_set=none,writes=0"),
        ("bootstrap_snapshot_state", "absent"),
        ("stage_root_state", "absent"),
        ("source_intake", r2_user_intake),
        ("source_package", r2_predecessor_remote_package),
        ("source_bootstrap", r2_predecessor_bootstrap),
        ("quarantine_intake", f"{r2_home_qroot}/intake"),
        ("quarantine_package", f"{r2_home_qroot}/package"),
        ("quarantine_bootstrap", f"{r2_run_qroot}/bootstrap"),
        ("rename_order", "intake,package,bootstrap"),
        ("rename_primitive", "renameat2-RENAME_NOREPLACE-dirfd-v1"),
        ("retention", "no-unlink-no-rmdir-no-copy-fallback"),
    )
    if tuple(actual_receipt_pairs) != expected_receipt_pairs:
        fail("root stager R2 receipt is not the exact independently fixed 35-key order")
    expected_receipt_payload = "".join(
        f"{key}\t{value}\n" for key, value in expected_receipt_pairs
    ).encode("ascii")
    if (
        len(expected_receipt_pairs) != 35
        or len({key for key, _ in expected_receipt_pairs}) != 35
        or len(expected_receipt_payload) != 1998
        or expected_receipt_payload.count(b"\n") != 35
        or b"\0" in expected_receipt_payload
        or b"\r" in expected_receipt_payload
        or not expected_receipt_payload.endswith(b"\n")
    ):
        fail("test R2 receipt oracle is not exact 35-key/1998-byte canonical bytes")
    receipt_body = engine_functions["receipt_bytes"]
    ordered(
        receipt_body,
        (
            're.fullmatch(r"[0-9a-f]{64}", current_manifest_sha)',
            're.fullmatch(r"[0-9a-f]{64}", current_self_sha)',
            're.fullmatch(r"[0-9a-f]{40}"',
            'payload = ("".join(f"{key}\\t{value}\\n" for key, value in lines)).encode("ascii")',
            "len(lines) != 35",
            "len(payload) != 1998",
        ),
        "root stager deterministic R2 receipt construction",
    )
    if re.search(r"(?i)R2_[A-Z_]*RECEIPT_SHA", r2_engine):
        fail("root stager hardcodes a live R2 receipt SHA self-reference")

    publish_receipt = engine_functions["publish_receipt"]
    ordered(
        publish_receipt,
        (
            "os.O_RDWR | os.O_CREAT | os.O_EXCL",
            "os.fsync(run_descriptor)",
            "os.ftruncate(pending_descriptor, 0)",
            "write_all(pending_descriptor, payload)",
            "os.fsync(pending_descriptor)",
            "read_all(pending_descriptor, 8192) != payload",
            "renameat2_noreplace(run_descriptor, pending_name, run_descriptor, final_name)",
            "final_descriptor = validate_receipt(run_descriptor, payload)",
            "os.fsync(final_descriptor)",
            "os.fsync(run_descriptor)",
        ),
        "root stager S2/S2P receipt durability transaction",
    )
    if publish_receipt.count("renameat2_noreplace(") != 1:
        fail("root stager receipt publication is not one NOREPLACE rename")

    r1_validation_surface = "\n".join(
        engine_functions[name]
        for name in (
            "r1_receipt_bytes",
            "validate_r1_retained_entries",
            "validate_r1_terminal",
        )
    )
    for r1_literal in (
        'R1_ID = "c8e41d73-2c690050ae1d-r1"',
        f'R1_AUTH_MANIFEST_SHA = "{retained_retirement_manifest_sha}"',
        f'R1_AUTH_SELF_SHA = "{retained_retirement_helper_sha}"',
        f'R1_RECEIPT_SHA = "{retained_retirement_receipt_sha}"',
        "validate_r1_terminal(boot_id, user_uid, user_gid)",
    ):
        if r1_literal not in r2_engine:
            fail(f"root stager dropped read-only R1 terminal binding: {r1_literal!r}")
    if any(
        token in r1_validation_surface
        for token in (
            "os.write",
            "write_all",
            "os.ftruncate",
            "renameat2_noreplace",
            "os.O_CREAT",
        )
    ):
        fail("root stager R1 terminal verifier is not strictly read-only")
    expect_harness_marker = "<<'EXPECT_HARNESS'\n"
    if hermetic.count(expect_harness_marker) != 1:
        fail("hermetic test does not define one transport transaction harness")
    expect_harness_start = hermetic.index(expect_harness_marker) + len(
        expect_harness_marker
    )
    expect_harness_end = hermetic.index("\nEXPECT_HARNESS\n", expect_harness_start)
    transport_harness = hermetic[expect_harness_start:expect_harness_end]
    harness_case_names = (
        "prepare-sequence",
        "prewrite-cuts",
        "mkdir-failure",
        "child-nonzero",
        "child-signal",
        "scp-build",
        "lineage-existence",
        "lineage-gate",
        "prepare-lineage",
        "r2-prewrite-cuts",
        "r2-first-write",
        "r2-provision-cuts",
        "r2-private-surface",
        "r2-precredential",
        "r2-authority-prefixes",
        "r2-raw-sequence",
    )
    harness_cases: dict[str, str] = {}
    for index, case_name in enumerate(harness_case_names):
        start_marker = f"    {case_name} {{"
        start = transport_harness.index(start_marker)
        end_marker = (
            f"    {harness_case_names[index + 1]} {{"
            if index + 1 < len(harness_case_names)
            else "    default { harness_die"
        )
        end = transport_harness.index(end_marker, start)
        harness_cases[case_name] = transport_harness[start:end]

    # The R2 expected sequences must be flat test literals.  Comparing a
    # production builder with a second call to that same builder would only
    # prove internal consistency, so reject every production-derived oracle.
    hermetic_r2_prewrite = tcl_literal_return_words(
        transport_harness, "r2_test_prewrite_sequence"
    )
    hermetic_r2_raw = tcl_literal_return_words(
        transport_harness, "r2_test_raw_sequence"
    )
    hermetic_r2_ro = tcl_literal_return_words(
        transport_harness, "r2_test_private_read_only"
    )
    hermetic_r2_package_names = tcl_literal_return_words(
        transport_harness, "r2_test_package_names"
    )
    if hermetic_r2_prewrite != expected_r2_prewrite_sequence:
        fail("hermetic R2 prewrite oracle is not the independent flat 138 tuple")
    if hermetic_r2_raw != r2_raw_operations:
        fail("hermetic R2 mutation oracle is not the independent ordered 21 tuple")
    if (
        len(hermetic_r2_ro) != 96
        or len(set(hermetic_r2_ro)) != 96
        or set(hermetic_r2_ro) != set(r2_ro_operations)
    ):
        fail("hermetic R2 private read-only oracle is not the independent flat 96 set")
    if hermetic_r2_package_names != r2_predecessor_package_names:
        fail("hermetic R2 predecessor package oracle is not the independent 17 tuple")
    r2_oracle_procs = "\n".join(
        tcl_proc(transport_harness, name)
        for name in (
            "r2_test_prewrite_sequence",
            "r2_test_raw_sequence",
            "r2_test_private_read_only",
            "r2_test_package_names",
        )
    )
    for production_oracle in (
        "[build_r2_operation",
        "[r2_mutation_operations",
        "[r2_stale_operations",
        "[r2_predecessor_package_names",
        "[retained_retirement_package_names",
        "[package_names",
        "[base_identity_operations",
        "[execute_retirement_lineage_gate",
    ):
        if production_oracle in r2_oracle_procs:
            fail(f"hermetic R2 expected tuple is production-derived: {production_oracle}")

    r2_case_names = harness_case_names[harness_case_names.index("r2-prewrite-cuts") :]
    r2_cases = "\n".join(harness_cases[name] for name in r2_case_names)
    for protected_procedure in (
        "r2_authority_state",
        "r2_require_auth_pending_prefix",
        "execute_retirement_lineage_gate",
        "r2_execute_common_gate",
        "r2_execute_predecessor_gate",
        "build_r2_operation",
        "execute_r2_primitive",
        "execute_r2_transaction",
        "execute_r2_verify_transaction",
    ):
        if f"rename {protected_procedure} " in r2_cases or re.search(
            rf"(?m)^\s*proc {re.escape(protected_procedure)}\s", r2_cases
        ):
            fail(
                "hermetic R2 harness replaces production control logic: "
                f"{protected_procedure}"
            )

    r2_prewrite_case = harness_cases["r2-prewrite-cuts"]
    ordered(
        r2_prewrite_case,
        (
            "set ::r2_expected [r2_test_prewrite_sequence]",
            "[llength $::r2_expected] != 138",
            '[lindex $::r2_expected 137] ne "r2-ro-old-provision-check"',
            "rename execute_operation_spec transport_original_execute_operation_spec",
            "proc execute_operation_spec {operation operation_spec password}",
            "set ordinal [llength $::r2_observed]",
            "set expected_operation [lindex $::r2_expected $ordinal]",
            "if {$operation ne $expected_operation}",
            "lappend ::r2_observed $operation",
            "if {$ordinal == $::r2_cut}",
            "foreach cut_kind {child-nonzero signal}",
            "for {set cut 0} {$cut < 138} {incr cut}",
            "unset -nocomplain ::R2_MUTATION_TRACE_ACTIVE",
            "::R2_MUTATION_INTAKE_CREATED",
            "execute_r2_transaction $values $manifest_sha",
            '$cut_kind eq "signal" || $cut < 44 ? 78 : 73',
            "[llength $::r2_mutations] != 0",
            "HARNESS_R2_PREWRITE_CUTS primitives=138 cuts=138 mutations=0",
            "child_nonzero=138 child_signal=138 result=PASS",
        ),
        "hermetic actual R2 138-prewrite cut harness",
    )
    if (
        r2_prewrite_case.count("execute_r2_transaction") != 1
        or r2_prewrite_case.count("rename execute_operation_spec ") != 1
        or "lappend ::r2_expected" in r2_prewrite_case
    ):
        fail("hermetic R2 prewrite harness does not instrument one actual transaction")

    r2_first_write_case = harness_cases["r2-first-write"]
    ordered(
        r2_first_write_case,
        (
            "set ::r2_expected [r2_test_prewrite_sequence]",
            "rename execute_operation_spec transport_original_execute_operation_spec",
            "set ordinal [llength $::r2_observed]",
            "if {$ordinal < 138}",
            "set expected_operation r2-raw-intake-mkdir",
            "if {$ordinal == 138}",
            "/usr/bin/mkdir --mode=0700 --",
            "/home/siyixuan/wg-mix-ebpf-test/retire-postflight-c8e41d73-f75fe7678cfd-r2.intake",
            "return [list child-failure 73",
            "execute_r2_transaction $values $manifest_sha",
            "HARNESS_R2_FIRST_WRITE index=138 operation=r2-raw-intake-mkdir",
            "rc=73 scp=0 result=PASS",
        ),
        "hermetic actual R2 first-write harness",
    )
    if (
        r2_first_write_case.count("execute_r2_transaction") != 1
        or r2_first_write_case.count("rename execute_operation_spec ") != 1
    ):
        fail("hermetic R2 first-write harness does not instrument one actual transaction")

    r2_provision_case = harness_cases["r2-provision-cuts"]
    provision_payload_oracle = tcl_proc(
        transport_harness, "r2_test_provision_payload"
    )
    if any(
        production_oracle in provision_payload_oracle
        for production_oracle in (
            "[provision_plan_policy",
            "[build_r2_operation",
            "[execute_r2_primitive",
        )
    ):
        fail("hermetic R2 provision expected payload is production-derived")
    ordered(
        provision_payload_oracle,
        (
            "initial {",
            "missing_packages= clang gcc golang-go iperf3 libbpf-dev llvm make pkg-config shellcheck wireguard-tools",
            "plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0",
            "iperf3 {",
            "missing_packages= iperf3",
            "plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0",
            "malformed {",
            "plan_apt_commands=skipped reason=fixed-package-set-already-installed",
            "writes1 {",
            "plan_complete planned_commands_executed=0 writes=1 automatic_cleanup=0",
        ),
        "hermetic independent R2 provision result oracle",
    )
    ordered(
        r2_provision_case,
        (
            "set ::r2_expected [r2_test_prewrite_sequence]",
            "rename execute_operation_spec transport_original_execute_operation_spec",
            'if {$operation eq "stale-stage-root"',
            "$::r2_scenario in {stage-present stage-symlink}",
            "/run/wg-mix-ebpf-source-stages/c8e41d73",
            "[lrange $spawn_argv 0 end] ne [lrange $expected 0 end]",
            'if {$operation eq "r2-ro-old-provision-check"}',
            "/bin/bash -p $provisioner --check",
            "--expected-address 192.168.10.82",
            "--expected-interface ens33",
            "--expected-hostname ubuntu-2604-test",
            "--expected-kernel 7.0.0-28-generic",
            "--expected-machine-id",
            "9db3fb717cc74974b2a6b243d67f67b9",
            "[lrange $spawn_argv 0 end] ne [lrange $expected 0 end]",
            "child-nonzero {",
            "signal { fail \"child-wait-status\" 78 }",
            "initial - iperf3 - malformed - writes1",
            "foreach scenario {",
            "stage-present stage-symlink initial iperf3 malformed writes1",
            "child-nonzero signal",
            "execute_r2_transaction $values $manifest_sha",
            "[llength $::r2_mutations] != 0",
            "[llength $trace] != 0",
            "$::r2_scp != 0",
            "HARNESS_R2_PROVISION_CUTS stage_present_symlink=2",
            "provision_initial_iperf3_malformed_writes1_nonzero_signal=6",
            "prewrite_mutations=0 scp=0 result=PASS",
        ),
        "hermetic actual R2 stage/provision prewrite cuts",
    )
    if (
        r2_provision_case.count("execute_r2_transaction") != 1
        or r2_provision_case.count("rename execute_operation_spec ") != 1
        or r2_provision_case.count("--apply") != 1
        or re.search(r"\[list[^\n]*--apply", r2_provision_case)
    ):
        fail("hermetic R2 provision cuts do not instrument one check-only transaction")

    r2_private_case = harness_cases["r2-private-surface"]
    ordered(
        r2_private_case,
        (
            "set private_ro [r2_test_private_read_only]",
            "set private_raw [r2_test_raw_sequence]",
            "[llength $private_ro] != 96",
            "[llength $private_raw] != 21",
            "foreach operation [concat $private_ro $private_raw]",
            "foreach action {plan execute}",
            "transport_main $invocation",
            "{B82FAIL 65}",
            '$message ne "private-operation"',
            "$rejections != 234",
            "$::credential_reads != 0",
            "$::spawns != 0",
            "HERMETIC_R2_PRIVATE_SURFACE public=2 ro=96 raw=21",
            "plan_execute_rejections=234 credential_reads=0 spawns=0 result=PASS",
        ),
        "hermetic R2 closed private surface",
    )

    r2_precredential_case = harness_cases["r2-precredential"]
    ordered(
        r2_precredential_case,
        (
            "production_require_transaction_local_authority",
            "lappend ::r2_authority_trace current",
            "production_r2_require_predecessor_authority",
            "lappend ::r2_authority_trace predecessor",
            "production_execute_r2_predecessor_controller_verifier",
            "lappend ::r2_authority_trace controller-seam",
            "rename read_execute_credential production_read_execute_credential",
            "lappend ::r2_authority_trace credential",
            "transport_main $invocation",
            "{current predecessor controller-seam credential}",
            "$::r2_credential_reads != 1",
            "$::r2_remote_spawns != 0",
            "HERMETIC_R2_PRECREDENTIAL current=v5/112/20 predecessor=v4/103/17",
            "order=current,predecessor,credential controller_seam=before-credential",
            "credential_reads=1 remote_spawns=0 result=PASS",
        ),
        "hermetic R2 actual precredential authority order",
    )

    r2_authority_case = harness_cases["r2-authority-prefixes"]
    authority_fixture_names = re.search(
        r"(?ms)^\s*set names \{(?P<body>.*?)^\s*\}\n\s*set legal ",
        r2_authority_case,
    )
    if (
        not authority_fixture_names
        or tuple(authority_fixture_names.group("body").split())
        != expected_authority_names
    ):
        fail("hermetic R2 authority fixture does not own the literal 13-path matrix")
    ordered(
        r2_authority_case,
        (
            "set legal [list",
            "[list absent {}]",
            "[list home-qroot {home-qroot}]",
            "[list auth-root {home-qroot auth-root}]",
            "[list run-qroot {home-qroot auth-root run-qroot}]",
            "[list manifest-pending",
            "{home-qroot auth-root run-qroot auth-manifest-pending}",
            "[list manifest-pair",
            "{home-qroot auth-root run-qroot auth-manifest-pending auth-manifest}",
            "[list self-pending",
            "{home-qroot auth-root run-qroot auth-manifest-pending auth-manifest auth-self-pending}",
            "[list complete",
            "{home-qroot auth-root run-qroot auth-manifest-pending auth-manifest auth-self-pending auth-self}",
            "set state [r2_authority_state",
            "[dict get $state phase] ne $expected_phase",
            "{home-qroot auth-root run-qroot auth-manifest-pending auth-self-pending}",
            '[dict get $pending_pair phase] ne "manifest-pending"',
            "HARNESS_R2_AUTHORITY_PREFIXES legal=8 both_pending=manifest-pending",
            "invalid=5 foreign=STOP complete_unknown_type_rejects=6",
            "pending_accepts=6 pending_rejects=4 result=PASS",
        ),
        "hermetic R2 literal authority prefix matrix",
    )
    invalid_authority = r2_authority_case[
        r2_authority_case.index("        set invalid [list \\\n") :
        r2_authority_case.index("        set complete_names {")
    ]
    ordered(
        invalid_authority,
        (
            "[list auth-without-home {auth-root} none]",
            "[list run-without-auth {home-qroot run-qroot} none]",
            "[list final-without-pending",
            "{home-qroot auth-root run-qroot auth-manifest} none]",
            "[list quarantine-before-authority {quarantine-package} none]",
            "[list foreign-auth {home-qroot auth-root} auth]",
            "set invalid_count 0",
            "foreach scenario $invalid",
            "r2_authority_state $values $manifest_sha $predecessor_values",
            "[dict get $options -errorcode] ne {B82FAIL 78}",
            "incr invalid_count",
        ),
        "hermetic R2 actual invalid authority matrix",
    )
    if (
        len(re.findall(r"(?m)^\s{12}\[list ", invalid_authority)) != 5
        or invalid_authority.count("r2_authority_state ") != 1
        or invalid_authority.count("{B82FAIL 78}") != 1
        or invalid_authority.count("incr invalid_count") != 1
    ):
        fail("hermetic R2 invalid authority matrix is not five actual rc78 calls")

    complete_authority = r2_authority_case[
        r2_authority_case.index("        set complete_names {") :
        r2_authority_case.index("        set prefix_accepts 0")
    ]
    complete_names_match = re.search(
        r"(?ms)^\s*set complete_names \{(?P<body>.*?)^\s*\}",
        complete_authority,
    )
    foreign_complete_match = re.search(
        r"(?ms)^\s*foreach foreign \{(?P<body>.*?)^\s*\} \{",
        complete_authority,
    )
    if (
        not complete_names_match
        or tuple(complete_names_match.group("body").split())
        != (
            "home-qroot",
            "auth-root",
            "run-qroot",
            "auth-manifest-pending",
            "auth-manifest",
            "auth-self-pending",
            "auth-self",
            "quarantine-intake",
            "quarantine-package",
            "quarantine-bootstrap",
            "lock",
            "receipt-final",
        )
        or not foreign_complete_match
        or tuple(foreign_complete_match.group("body").split())
        != ("home", "auth", "run", "home-type", "auth-type", "run-type")
    ):
        fail("hermetic R2 complete-state invalid entry matrix is not literal 6")
    ordered(
        complete_authority,
        (
            "set complete_entry_rejects 0",
            "foreach foreign {",
            "r2_authority_state $values $manifest_sha $predecessor_values",
            "[dict get $options -errorcode] ne {B82FAIL 78}",
            "incr complete_entry_rejects",
        ),
        "hermetic R2 actual complete-state entry rejects",
    )
    if (
        complete_authority.count("r2_authority_state ") != 1
        or complete_authority.count("{B82FAIL 78}") != 1
        or complete_authority.count("incr complete_entry_rejects") != 1
    ):
        fail("hermetic R2 complete-state matrix is not six actual rc78 calls")

    prefix_authority = r2_authority_case[
        r2_authority_case.index("        set prefix_accepts 0") :
        r2_authority_case.index(
            "        if {$legal_count != 8 || $invalid_count != 5"
        )
    ]
    accept_prefix = prefix_authority[
        : prefix_authority.index("            foreach {label pending_size pending_sha}")
    ]
    reject_prefix = prefix_authority[
        prefix_authority.index("            foreach {label pending_size pending_sha}") :
    ]
    ordered(
        accept_prefix,
        (
            "foreach {name local_name full_sha} [list",
            "package-manifest.v1 package-manifest.v1 $manifest_sha",
            "prepare-stage-root.sh prepare-stage-root.sh $::r2_self_sha",
            'set local_file "[dict get $values local_package_dir]/${local_name}"',
            "file lstat $local_file local_stat",
            "foreach {expected_class pending_size pending_sha} [list",
            "empty 0",
            "prefix 17 [r2_test_file_prefix_sha $local_file 17]",
            "exact $local_stat(size) $full_sha",
            "set observed_class [r2_require_auth_pending_prefix $values",
            "$observed_class ne $expected_class",
            "incr prefix_accepts",
        ),
        "hermetic R2 actual pending-prefix accepts",
    )
    ordered(
        reject_prefix,
        (
            "foreach {label pending_size pending_sha} [list",
            "nonprefix 17 [string repeat a 64]",
            "oversize [expr {$local_stat(size) + 1}] [string repeat b 64]",
            "r2_require_auth_pending_prefix $values $manifest_sha",
            "[dict get $options -errorcode] ne {B82FAIL 78}",
            "incr prefix_rejects",
        ),
        "hermetic R2 actual pending-prefix rejects",
    )
    if (
        accept_prefix.count("r2_require_auth_pending_prefix ") != 1
        or accept_prefix.count("incr prefix_accepts") != 1
        or reject_prefix.count("r2_require_auth_pending_prefix ") != 1
        or reject_prefix.count("{B82FAIL 78}") != 1
        or reject_prefix.count("incr prefix_rejects") != 1
    ):
        fail("hermetic R2 pending-prefix matrix is not 6 accepts/4 actual rc78 rejects")
    authority_summary = r2_authority_case[
        r2_authority_case.index(
            "        if {$legal_count != 8 || $invalid_count != 5"
        ) :
    ]
    ordered(
        authority_summary,
        (
            "$legal_count != 8",
            "$invalid_count != 5",
            "$complete_entry_rejects != 6",
            "$prefix_accepts != 6",
            "$prefix_rejects != 4",
            "HARNESS_R2_AUTHORITY_PREFIXES legal=8",
        ),
        "hermetic R2 authority actual counter summary",
    )
    if (
        r2_authority_case.count("r2_authority_state $values $manifest_sha") != 4
        or r2_authority_case.count(
            "r2_require_auth_pending_prefix $values"
        )
        != 2
        or r2_authority_case.count("{B82FAIL 78}") != 3
    ):
        fail("hermetic R2 authority matrix does not call only the actual 8/5/6/6/4 paths")

    # Exercise the real controller verifier through a copied reader.  Bind the
    # copy transformation and every tamper family, rather than accepting its
    # aggregate marker as proof of the 68 artifact and 22 history cuts.
    controller_matrix_start = (
        'R2_CONTROLLER_COPY_BUILDER="${TEST_ROOT}/r2-controller-copy-builder.py"\n'
    )
    controller_matrix_end = 'R2_RECEIPT_TEST_OUTPUT="$(/usr/bin/python3 -B -I -c \'\n'
    if (
        hermetic.count(controller_matrix_start) != 1
        or hermetic.count(controller_matrix_end) != 1
    ):
        fail("cannot isolate hermetic R2 controller tamper matrix")
    controller_matrix = hermetic[
        hermetic.index(controller_matrix_start) : hermetic.index(
            controller_matrix_end, hermetic.index(controller_matrix_start)
        )
    ]
    copy_builder_open = (
        "/bin/cat >\"${R2_CONTROLLER_COPY_BUILDER}\" "
        "<<'R2_CONTROLLER_COPY_BUILDER'\n"
    )
    copy_builder_close = "\nR2_CONTROLLER_COPY_BUILDER\n"
    if (
        controller_matrix.count(copy_builder_open) != 1
        or controller_matrix.count(copy_builder_close) != 1
    ):
        fail("cannot isolate hermetic R2 controller copy builder")
    copy_builder_start = controller_matrix.index(copy_builder_open) + len(
        copy_builder_open
    )
    copy_builder_end = controller_matrix.index(
        copy_builder_close, copy_builder_start
    )
    copy_builder = controller_matrix[copy_builder_start:copy_builder_end]
    try:
        ast.parse(copy_builder)
    except SyntaxError as exc:
        fail(f"hermetic R2 controller copy builder is not Python: {exc}")
    ordered(
        copy_builder,
        (
            "source_path = pathlib.Path(sys.argv[1])",
            "physical_package = pathlib.Path(sys.argv[2])",
            'dispatch_tail = \'main "$@"\\n\'',
            'canonical_package = "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-f75fe7678cfd"',
            "source.count(canonical_assignment) != 1",
            "source.count(canonical_package) != 3",
            "source.count(canonical_manifest_record) != 1",
            'tuple_anchor = ") = sys.argv[1:]\\nexpected_manifest = sys.stdin.buffer.read()\\n"',
            "_r2_test_physical_package = __PHYSICAL_PACKAGE__",
            "_r2_test_canonical_package = package_name",
            "def _r2_test_map_path(path):",
            "def _r2_test_mapped_open(path, flags, mode=0o777, *, dir_fd=None):",
            "def _r2_test_mapped_stat(path, *, dir_fd=None, follow_symlinks=True):",
            "def _r2_test_mapped_realpath(path, *args, **kwargs):",
            "os.open = _r2_test_mapped_open",
            "os.stat = _r2_test_mapped_stat",
            "os.path.realpath = _r2_test_mapped_realpath",
            "source = source.replace(tuple_anchor, mapping, 1)",
            "git_anchor =",
            'if scenario == "baseline":',
            'elif scenario == "package-swap":',
            "os.rename(",
            'os.fspath(_r2_test_physical_package) + ".held"',
            "os.mkdir(os.fspath(_r2_test_physical_package), 0o700)",
            'elif scenario == "git-child-failure":',
            '\'    git_prefix[0] = "/usr/bin/false"\\n\' + git_anchor',
            'elif scenario == "bundle-child-failure":',
            '\'    run_git(("bundle", "verify", bundle_argument), failure_rc=67)\\n\'',
            "source.count(canonical_assignment) != 1",
            "source.count(canonical_package) != 3",
            "source.count(canonical_manifest_record) != 1",
            'source.count("_r2_test_physical_package = ") != 1',
            '"R2_CONTROLLER_COPY replacements=0 physical_open_injections=1 "',
            '"canonical_manifest_replacements=0 logical_fixed_occurrences=3"',
        ),
        "hermetic actual controller physical-open copy seam",
    )
    if (
        tuple(
            re.findall(
                r'(?m)^(?:if|elif) scenario == "([a-z-]+)":$', copy_builder
            )
        )
        != (
            "baseline",
            "package-swap",
            "git-child-failure",
            "bundle-child-failure",
        )
        or copy_builder.count("source = source.replace(") != 4
        or copy_builder.count("os.open = _r2_test_mapped_open") != 1
        or copy_builder.count("os.stat = _r2_test_mapped_stat") != 1
        or copy_builder.count("os.path.realpath = _r2_test_mapped_realpath") != 1
        or any(
            name in copy_builder
            for name in (
                "verify_r2_predecessor_manifest_contract",
                "verify_r2_predecessor_tree_mapping",
                "verify_r2_predecessor_history",
                "verify_r2_local_authorities",
            )
        )
    ):
        fail("hermetic R2 controller copy seam replaces verifier control logic")

    local_runner_open = (
        "/bin/cat >\"${R2_CONTROLLER_LOCAL_RUNNER}\" "
        "<<'R2_CONTROLLER_LOCAL_RUNNER'\n"
    )
    local_runner_close = "\nR2_CONTROLLER_LOCAL_RUNNER\n"
    if (
        controller_matrix.count(local_runner_open) != 1
        or controller_matrix.count(local_runner_close) != 1
    ):
        fail("cannot isolate hermetic R2 controller local runner")
    local_runner_start = controller_matrix.index(local_runner_open) + len(
        local_runner_open
    )
    local_runner_end = controller_matrix.index(
        local_runner_close, local_runner_start
    )
    local_runner = controller_matrix[local_runner_start:local_runner_end]
    ordered(
        local_runner,
        (
            "set -o pipefail",
            'source "${reader}" || exit $?',
            "parse_arguments() {",
            "[[ \"$1\" == verify-r2-predecessor-package ]] || return 64",
            'SUPPLIED_CREDENTIAL_PATH="${credential_path}"',
            "verify_manifest_contract() { return 0; }",
            "transport() { printf 'R2_CONTROLLER_NETWORK_TRIPWIRE",
            "run_operation() { printf 'R2_CONTROLLER_OPERATION_TRIPWIRE",
            "main verify-r2-predecessor-package",
        ),
        "hermetic actual controller local-only runner",
    )
    if any(
        f"{name}()" in local_runner
        for name in (
            "verify_r2_local_authorities",
            "verify_r2_predecessor_manifest_contract",
            "verify_r2_predecessor_tree_mapping",
            "verify_r2_predecessor_history",
        )
    ):
        fail("hermetic controller local runner replaces predecessor verifier")
    make_controller_reader = bash_function(
        controller_matrix, "make_r2_controller_reader"
    )
    ordered(
        make_controller_reader,
        (
            '/usr/bin/python3 -B -I "${R2_CONTROLLER_COPY_BUILDER}"',
            '"${FIXTURE_REVIEW}/controller.sh" "${physical_package}" "${target}"',
            '"${scenario}"',
            "R2_CONTROLLER_COPY replacements=0 physical_open_injections=1",
            "canonical_manifest_replacements=0 logical_fixed_occurrences=3",
            '/bin/chmod 0600 "${target}"',
            '/bin/bash -n "${target}"',
        ),
        "hermetic controller reader is copied from actual production",
    )
    run_controller_reader = bash_function(
        controller_matrix, "run_r2_controller_reader"
    )
    ordered(
        run_controller_reader,
        (
            "process = subprocess.Popen(",
            "sys.argv[1:]",
            "stdin=subprocess.DEVNULL",
            "stdout=subprocess.PIPE",
            "stderr=subprocess.STDOUT",
            "start_new_session=True",
            "process.communicate(timeout=4)",
            "except subprocess.TimeoutExpired:",
            "os.killpg(process.pid, signal.SIGTERM)",
            "process.communicate(timeout=2)",
            "raise SystemExit(124)",
            '/bin/bash "${R2_CONTROLLER_LOCAL_RUNNER}" "$1"',
            '"${BOUND_MANIFEST_SHA}" "${FIXTURE_COMMIT}" "$2"',
        ),
        "hermetic controller FIFO-bounded reader",
    )

    controller_positive = controller_matrix[
        controller_matrix.index('R2_CONTROLLER_CREDENTIAL_FIFO="') :
        controller_matrix.index(
            "readonly -a R2_CONTROLLER_PREDECESSOR_FILES=("
        )
    ]
    ordered(
        controller_positive,
        (
            '/usr/bin/mkfifo -m 0600 -- "${R2_CONTROLLER_CREDENTIAL_FIFO}"',
            'make_r2_controller_reader "${R2_PREDECESSOR_CLONE}" baseline',
            "R2_CONTROLLER_CLONE_OUTPUT=\"$(run_r2_controller_reader",
            '"${R2_CONTROLLER_CLONE_READER}" "${R2_CONTROLLER_CREDENTIAL_FIFO}"',
            '"${R2_CONTROLLER_CLONE_OUTPUT##*$\'\\n\'}" ==',
            '/usr/bin/grep -Fxc -- "${R2_CONTROLLER_CLONE_MARKER}"',
            "R2_CONTROLLER_MISSING_CREDENTIAL_OUTPUT=\"$(run_r2_controller_reader",
            '"${R2_CONTROLLER_MISSING_CREDENTIAL}"',
            '"${R2_CONTROLLER_MISSING_CREDENTIAL_OUTPUT##*$\'\\n\'}" ==',
            'R2_CONTROLLER_PACKAGE_FIFO="${TEST_ROOT}/r2-controller-package.fifo"',
            '/usr/bin/mkfifo -m 0600 -- "${R2_CONTROLLER_PACKAGE_FIFO}"',
            'make_r2_controller_reader "${R2_CONTROLLER_PACKAGE_FIFO}" baseline',
            '"${R2_CONTROLLER_FIFO_READER}" "${R2_CONTROLLER_CREDENTIAL_FIFO}"',
            '"${R2_CONTROLLER_FIFO_RC}" -eq 66',
            "reason=r2-local-authority rc=66",
            'make_r2_controller_reader "${R2_CONTROLLER_SWAP_PACKAGE}" package-swap',
            '"${R2_CONTROLLER_SWAP_READER}" "${R2_CONTROLLER_CREDENTIAL_FIFO}"',
            '"${R2_CONTROLLER_SWAP_RC}" -eq 66',
            '-d "${R2_CONTROLLER_SWAP_PACKAGE}"',
            '-d "${R2_CONTROLLER_SWAP_PACKAGE}.held"',
        ),
        "hermetic controller clone/FIFO/path-swap scenarios",
    )
    if (
        controller_positive.count("run_r2_controller_reader") != 4
        or controller_positive.count("R2_CONTROLLER_NETWORK_TRIPWIRE*") != 4
        or controller_positive.count("R2_CONTROLLER_OPERATION_TRIPWIRE*") != 4
        or controller_positive.count("/usr/bin/mkfifo -m 0600") != 2
    ):
        fail("hermetic controller positive/FIFO/path-swap cardinality drifted")

    controller_predecessor_files = tuple(
        bash_array(hermetic, "R2_CONTROLLER_PREDECESSOR_FILES").split()
    )
    if controller_predecessor_files != r2_predecessor_package_names:
        fail("hermetic controller tamper oracle is not the independent 17 files")
    make_artifact_case = bash_function(
        controller_matrix, "make_r2_controller_artifact_case"
    )
    ordered(
        make_artifact_case,
        (
            "((R2_CONTROLLER_ARTIFACT_ORDINAL += 1))",
            'R2_CONTROLLER_CASE_PACKAGE="${R2_CONTROLLER_ARTIFACT_CASE_ROOT}/$(printf \'%03d\'',
            '/bin/cp -R -- "${R2_PREDECESSOR_FIXED_PACKAGE}"',
            '"${R2_CONTROLLER_CASE_PACKAGE}"',
        ),
        "hermetic controller isolated artifact fixture",
    )
    expect_artifact_rc = bash_function(
        controller_matrix, "expect_r2_controller_artifact_rc"
    )
    ordered(
        expect_artifact_rc,
        (
            'make_r2_controller_reader "${R2_CONTROLLER_CASE_PACKAGE}" baseline',
            'output="$(run_r2_controller_reader "${R2_CONTROLLER_CASE_READER}"',
            '"${R2_CONTROLLER_CREDENTIAL_FIFO}" 2>&1)"',
            '"${rc}" -eq "${expected_rc}"',
            'reason=r2-local-authority rc=${expected_rc}',
            '"${output}" != *R2_CONTROLLER_NETWORK_TRIPWIRE*',
            '"${output}" != *R2_CONTROLLER_OPERATION_TRIPWIRE*',
            "((R2_CONTROLLER_ARTIFACT_CUTS += 1))",
        ),
        "hermetic controller actual artifact cut runner",
    )
    artifact_loop = controller_matrix[
        controller_matrix.index(
            'for predecessor_name in "${R2_CONTROLLER_PREDECESSOR_FILES[@]}"; do'
        ) :
        controller_matrix.index("expect_r2_controller_history_rc() {")
    ]
    artifact_rc_matrix = tuple(
        re.findall(
            r"expect_r2_controller_artifact_rc\s+(?:\\\s*)?"
            r'"\$\{predecessor_name\}-(content|mode|nlink|symlink)"\s+(\d+)',
            artifact_loop,
        )
    )
    if artifact_rc_matrix != (
        ("content", "67"),
        ("mode", "66"),
        ("nlink", "66"),
        ("symlink", "66"),
    ):
        fail("hermetic controller artifact tamper rc matrix is not exact 17x4")
    ordered(
        artifact_loop,
        (
            "path.write_bytes(bytes((payload[0] ^ 1,)) + payload[1:])",
            'expect_r2_controller_artifact_rc \\\n    "${predecessor_name}-content" 67',
            '/bin/chmod 0644 \\\n    "${R2_CONTROLLER_CASE_PACKAGE}/${predecessor_name}"',
            'expect_r2_controller_artifact_rc "${predecessor_name}-mode" 66',
            '/bin/ln "${R2_CONTROLLER_CASE_PACKAGE}/${predecessor_name}"',
            '"${R2_CONTROLLER_CASE_PACKAGE}.external-hardlink"',
            'expect_r2_controller_artifact_rc "${predecessor_name}-nlink" 66',
            '/bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}/${predecessor_name}"',
            '"${R2_CONTROLLER_CASE_PACKAGE}.symlink-target"',
            '/bin/ln -s "${R2_CONTROLLER_CASE_PACKAGE}.symlink-target"',
            'expect_r2_controller_artifact_rc "${predecessor_name}-symlink" 66',
            '"${R2_CONTROLLER_ARTIFACT_CUTS}" -eq 68',
            "HERMETIC_R2_CONTROLLER_FILES files=17 content_mode_nlink_symlink_cuts=68",
            "credential_fifo=unread network_tripwire=0 result=PASS",
        ),
        "hermetic controller real 68 artifact cuts",
    )

    expect_history_rc = bash_function(
        controller_matrix, "expect_r2_controller_history_rc"
    )
    ordered(
        expect_history_rc,
        (
            'make_r2_controller_reader "${R2_CONTROLLER_CASE_PACKAGE}" "${scenario}"',
            'output="$(run_r2_controller_reader "${R2_CONTROLLER_CASE_READER}"',
            '"${R2_CONTROLLER_CREDENTIAL_FIFO}" 2>&1)"',
            '"${rc}" -eq "${expected_rc}"',
            'reason=r2-local-authority rc=${expected_rc}',
            '"${output}" != *R2_CONTROLLER_NETWORK_TRIPWIRE*',
            '"${output}" != *R2_CONTROLLER_OPERATION_TRIPWIRE*',
        ),
        "hermetic controller actual history cut runner",
    )
    history_section = controller_matrix[
        controller_matrix.index("R2_CONTROLLER_HISTORY_REF_CUTS=0") :
        controller_matrix.index('CONTROLLER_TRANSACTION_SEAM="')
    ]
    history_file_loop = history_section[
        history_section.index("R2_CONTROLLER_HISTORY_FILE_CUTS=0") :
        history_section.index(
            "make_r2_controller_artifact_case history-git-mode"
        )
    ]
    history_file_rc_matrix = tuple(
        re.findall(
            r'expect_r2_controller_history_rc\s+"\$\{history_name\}-'
            r'(content|mode|nlink|symlink)"\s+(\d+)',
            history_file_loop,
        )
    )
    if (
        "for history_name in history-roots.v1 history-objects.v1; do"
        not in history_file_loop
        or history_file_rc_matrix
        != (
            ("content", "67"),
            ("mode", "66"),
            ("nlink", "66"),
            ("symlink", "66"),
        )
        or history_file_loop.count(
            "((R2_CONTROLLER_HISTORY_FILE_CUTS += 1))"
        )
        != 4
    ):
        fail("hermetic controller history-file matrix is not actual 2x4")
    ordered(
        history_file_loop,
        (
            "path.write_bytes(bytes((payload[0] ^ 1,)) + payload[1:])",
            'expect_r2_controller_history_rc "${history_name}-content" 67',
            '/bin/chmod 0644 "${R2_CONTROLLER_CASE_PACKAGE}/${history_name}"',
            'expect_r2_controller_history_rc "${history_name}-mode" 66',
            '/bin/ln "${R2_CONTROLLER_CASE_PACKAGE}/${history_name}"',
            'external-hardlink"',
            'expect_r2_controller_history_rc "${history_name}-nlink" 66',
            '/bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}/${history_name}"',
            'symlink-target"',
            "/bin/ln -s",
            'expect_r2_controller_history_rc "${history_name}-symlink" 66',
        ),
        "hermetic controller history content/mode/nlink/symlink cuts",
    )
    history_shape = history_section[
        history_section.index("R2_CONTROLLER_HISTORY_SHAPE_CUTS=0") :
        history_section.index(
            '[[ "${R2_CONTROLLER_HISTORY_FILE_CUTS}" -eq 8'
        )
    ]
    history_shape_calls = tuple(
        re.findall(
            r"(?m)^expect_r2_controller_history_rc\s+([^\n]+)$",
            history_shape,
        )
    )
    if history_shape_calls != (
        "package-extra 66",
        "package-missing 66",
        "package-mode 66",
        "package-symlink 66",
        "history-git-mode 66",
        "history-git-extra 66",
        "history-git-symlink 66",
        "history-git-missing 66",
        "history-git-object 76",
        "history-git-child 76 git-child-failure",
        "bundle-child 67 bundle-child-failure",
    ) or history_shape.count("((R2_CONTROLLER_HISTORY_SHAPE_CUTS += 1))") != 11:
        fail("hermetic controller history shape matrix is not actual 11 cuts")
    ordered(
        history_shape,
        (
            '/usr/bin/touch "${R2_CONTROLLER_CASE_PACKAGE}/unexpected-entry"',
            '/bin/mv -- "${R2_CONTROLLER_CASE_PACKAGE}/controller.sh"',
            '/bin/chmod 0755 "${R2_CONTROLLER_CASE_PACKAGE}"',
            '/bin/ln -s "${R2_CONTROLLER_CASE_PACKAGE}.symlink-target"',
            '/bin/chmod 0755 \\\n  "${R2_CONTROLLER_CASE_PACKAGE}/history-verification.git"',
            "history-verification.git/unexpected-entry",
            "history-git-symlink-target",
            "history-git-missing",
            "missing-pack-object",
            "history-git-child 76 git-child-failure",
            "bundle-child 67 bundle-child-failure",
        ),
        "hermetic controller history shape mutations",
    )
    if (
        history_section.count("((R2_CONTROLLER_HISTORY_REF_CUTS += 1))") != 3
        or history_section.count("refs/heads/history-verified") != 2
        or history_section.count("update-ref refs/heads/foreign") != 1
    ):
        fail("hermetic controller ref tamper matrix is not exact three cuts")
    ordered(
        history_section,
        (
            'rev-parse \\\n  "${R2_PREDECESSOR_COMMIT}^"',
            'update-ref refs/heads/history-verified "${R2_CONTROLLER_HISTORY_PARENT}"',
            "expect_r2_controller_history_rc history-ref-ancestor 76",
            'update-ref refs/heads/foreign "${R2_PREDECESSOR_COMMIT}"',
            "expect_r2_controller_history_rc history-ref-extra 76",
            'rev-parse \\\n  "${FIXTURE_COMMIT}^"',
            'update-ref refs/heads/history-verified "${R2_CURRENT_HISTORY_PARENT}"',
            "verify_manifest_contract || exit $?",
            'LOCAL_PACKAGE_DIR="$4"',
            "verify_bound_history",
            '"${R2_CURRENT_HISTORY_REF_RC}" -eq 76',
            '"${R2_CONTROLLER_HISTORY_REF_CUTS}" -eq 3',
            "HERMETIC_R2_CONTROLLER_HISTORY_REFS predecessor_ancestor=STOP",
            "predecessor_extra=STOP current_ancestor=STOP cuts=3 rc=76",
            "credential_reads=0 network_operations=0 result=PASS",
        ),
        "hermetic actual current/predecessor exact-ref cuts",
    )
    controller_summary = (
        "HERMETIC_R2_CONTROLLER_SEAMS public_modes=2 high_level_calls=2 "
        "local_only=PASS fixed_positive=1 clone_positive=2 package_fifo=1 "
        "artifact_cuts=68 history_cuts=22 path_swaps=1 replacements=0 "
        "physical_open_injections=1 canonical_manifest_replacements=0 "
        "network_tripwire=0 result=PASS"
    )
    if controller_matrix.count(controller_summary) != 1:
        fail("hermetic R2 controller matrix summary is not exact")

    engine_harness_open = (
        "/bin/cat >\"${R2_ENGINE_HARNESS}\" <<'R2_ENGINE_HARNESS'\n"
    )
    engine_harness_close = "R2_ENGINE_HARNESS\n"
    if (
        hermetic.count(engine_harness_open) != 1
        or hermetic.count(engine_harness_close) != 1
    ):
        fail("cannot isolate hermetic actual R2 engine harness")
    engine_harness_start = hermetic.index(engine_harness_open) + len(
        engine_harness_open
    )
    engine_harness_end = hermetic.index(
        engine_harness_close, engine_harness_start
    )
    engine_harness = hermetic[engine_harness_start:engine_harness_end]
    if hashlib.sha256(engine_harness.encode("utf-8")).hexdigest() != (
        "1e3d1a6fb66a2b60e2fdb67e66f0e27b5dbcd1fa707ce59d0dda323c74e8aecb"
    ):
        fail("hermetic actual R2 engine harness bytes drifted")
    try:
        engine_harness_tree = ast.parse(engine_harness)
    except SyntaxError as exc:
        fail(f"hermetic R2 engine harness is not valid Python: {exc}")
    validate_engine_harness_execution_ast(engine_harness)
    harness_assignments: dict[str, ast.AST] = {}
    for assignment_name in (
        "EXPECTED_ENGINE_FUNCTIONS",
        "EXPECTED_ENGINE_PAYLOAD_SHA256",
        "EXPECTED_ENGINE_MAIN_SHA256",
        "PREDECESSOR_COMMIT",
        "PREDECESSOR_MANIFEST_SHA256",
        "R1_MANIFEST_SHA256",
        "R1_SELF_SHA256",
        "R1_RECEIPT_SHA256",
        "R1_ID",
        "BOOT_ID",
        "HOSTNAME",
        "KERNEL",
        "MACHINE_ID",
        "PATHS",
        "PACKAGE_NAMES",
        "BOOTSTRAP_NAMES",
        "STATE_SIGNATURES",
    ):
        matches = [
            node.value
            for node in engine_harness_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == assignment_name
                for target in node.targets
            )
        ]
        if len(matches) != 1:
            fail(f"hermetic R2 engine harness assignment is not unique: {assignment_name}")
        harness_assignments[assignment_name] = matches[0]
    try:
        harness_engine_functions = ast.literal_eval(
            harness_assignments["EXPECTED_ENGINE_FUNCTIONS"]
        )
        harness_payload_sha = ast.literal_eval(
            harness_assignments["EXPECTED_ENGINE_PAYLOAD_SHA256"]
        )
        harness_main_sha = ast.literal_eval(
            harness_assignments["EXPECTED_ENGINE_MAIN_SHA256"]
        )
        harness_paths = ast.literal_eval(harness_assignments["PATHS"])
        harness_package_names = ast.literal_eval(
            harness_assignments["PACKAGE_NAMES"]
        )
        harness_bootstrap_names = ast.literal_eval(
            harness_assignments["BOOTSTRAP_NAMES"]
        )
        harness_state_signatures = ast.literal_eval(
            harness_assignments["STATE_SIGNATURES"]
        )
        harness_constants = {
            name: ast.literal_eval(harness_assignments[name])
            for name in (
                "PREDECESSOR_COMMIT",
                "PREDECESSOR_MANIFEST_SHA256",
                "R1_MANIFEST_SHA256",
                "R1_SELF_SHA256",
                "R1_RECEIPT_SHA256",
                "R1_ID",
                "BOOT_ID",
                "HOSTNAME",
                "KERNEL",
                "MACHINE_ID",
            )
        }
    except (TypeError, ValueError) as exc:
        fail(f"hermetic R2 engine harness authority is not literal: {exc}")
    expected_harness_paths = {
        "current_manifest": f"{r2_home_qroot}/authority/package-manifest.v1",
        "current_manifest_pending": (
            f"{r2_home_qroot}/authority/package-manifest.v1.pending"
        ),
        "current_self": f"{r2_home_qroot}/authority/prepare-stage-root.sh",
        "current_self_pending": (
            f"{r2_home_qroot}/authority/prepare-stage-root.sh.pending"
        ),
        "user_intake": r2_user_intake,
        "home_qroot": r2_home_qroot,
        "auth_root": f"{r2_home_qroot}/authority",
        "q_intake": f"{r2_home_qroot}/intake",
        "q_package": f"{r2_home_qroot}/package",
        "source_package": r2_predecessor_remote_package,
        "source_bootstrap": r2_predecessor_bootstrap,
        "run_qroot": r2_run_qroot,
        "q_bootstrap": f"{r2_run_qroot}/bootstrap",
        "lock": f"{r2_run_qroot}/retirement.v1.lock",
        "receipt_pending": f"{r2_run_qroot}/retirement-complete.v1.pending",
        "receipt_final": f"{r2_run_qroot}/retirement-complete.v1",
    }
    expected_harness_constants = {
        "PREDECESSOR_COMMIT": r2_predecessor_commit,
        "PREDECESSOR_MANIFEST_SHA256": r2_predecessor_manifest_sha,
        "R1_MANIFEST_SHA256": retained_retirement_manifest_sha,
        "R1_SELF_SHA256": retained_retirement_helper_sha,
        "R1_RECEIPT_SHA256": retained_retirement_receipt_sha,
        "R1_ID": "c8e41d73-2c690050ae1d-r1",
        "BOOT_ID": "01234567-89ab-cdef-0123-456789abcdef",
        "HOSTNAME": "ubuntu-2604-test",
        "KERNEL": "7.0.0-28-generic",
        "MACHINE_ID": "9db3fb717cc74974b2a6b243d67f67b9",
    }
    expected_harness_state_signatures = {
        state: tuple(int(flag) for flag in signature)
        for signature, state in expected_state_matrix.items()
    }
    if (
        harness_engine_functions != expected_engine_functions
        or len(harness_engine_functions) != 48
        or harness_constants != expected_harness_constants
        or harness_paths != expected_harness_paths
        or harness_package_names != r2_predecessor_package_names
        or harness_bootstrap_names
        != ("prepare-stage-root.sh", "provision-ubuntu-test-host.sh")
        or harness_state_signatures != expected_harness_state_signatures
        or not r2_engine.endswith("\n")
        or hashlib.sha256(r2_engine[:-1].encode("utf-8")).hexdigest()
        != harness_payload_sha
        or hashlib.sha256(engine_functions["engine_main"].encode("utf-8")).hexdigest()
        != harness_main_sha
    ):
        fail("hermetic R2 harness is not bound to the actual 48-function engine")
    ordered(
        engine_harness,
        (
            'R1_RETAINED_PACKAGE = Path(\n    "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-2c690050ae1d"',
            'R1_AUTHORITY_PACKAGE = Path(\n    "/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-4bdfdfd90756"',
        ),
        "hermetic fixed retained R1 fixture authorities",
    )

    # Compare the complete embedded module, not just its FunctionDef surface.
    # The hermetic executor may change only the two top-level root-id values;
    # imports, all other constants and the final engine_main dispatch remain
    # byte-for-byte equivalent at the AST level.
    full_engine_before = ast.parse(r2_engine[:-1])
    full_engine_after = ast.parse(r2_engine[:-1])
    full_before_nodes = tuple(
        ast.dump(node, include_attributes=False) for node in full_engine_before.body
    )
    root_id_changes = []
    for index, node in enumerate(full_engine_after.body):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in {
            "ROOT_UID",
            "ROOT_GID",
        }:
            continue
        if (
            not isinstance(node.value, ast.Constant)
            or type(node.value.value) is not int
            or node.value.value != 0
        ):
            fail(f"embedded engine {target.id} is not one top-level zero constant")
        node.value = ast.Constant(1001 + len(root_id_changes))
        root_id_changes.append((index, target.id))
    full_after_nodes = tuple(
        ast.dump(node, include_attributes=False) for node in full_engine_after.body
    )
    full_module_differences = tuple(
        index
        for index, (before_node, after_node) in enumerate(
            zip(full_before_nodes, full_after_nodes)
        )
        if before_node != after_node
    )
    if (
        tuple(name for _, name in root_id_changes) != ("ROOT_UID", "ROOT_GID")
        or full_module_differences
        != tuple(index for index, _ in root_id_changes)
        or len(full_before_nodes) != len(full_after_nodes)
        or full_module_differences[-1] == len(full_before_nodes) - 1
    ):
        fail("embedded engine full module differs beyond ROOT_UID/ROOT_GID values")
    final_dispatch = full_engine_before.body[-1]
    if (
        not isinstance(final_dispatch, ast.Try)
        or len(final_dispatch.body) != 1
        or not isinstance(final_dispatch.body[0], ast.Expr)
        or not isinstance(final_dispatch.body[0].value, ast.Call)
        or not isinstance(final_dispatch.body[0].value.func, ast.Name)
        or final_dispatch.body[0].value.func.id != "engine_main"
        or final_dispatch.body[0].value.args
        or final_dispatch.body[0].value.keywords
        or tuple(
            handler.type.id
            for handler in final_dispatch.handlers
            if isinstance(handler.type, ast.Name)
        )
        != ("RetirementStop", "KeyError", "OSError")
        or final_dispatch.orelse
        or final_dispatch.finalbody
    ):
        fail("embedded engine final engine_main dispatch is not exact and unchanged")

    extract_engine = python_function(
        engine_harness, "extract_and_transform_engine"
    )
    ordered(
        extract_engine,
        (
            'shell = Path(stager).read_text(encoding="utf-8")',
            'anchor = shell.index("run_r2_retirement_engine() {")',
            'function_end = shell.index("\\nrun_stage() {", anchor)',
            'function.count("<<\'PY\'\\n") != 1',
            'payload = function[begin:end]',
            "hashlib.sha256(payload.encode(\"utf-8\")).hexdigest() !=",
            "EXPECTED_ENGINE_PAYLOAD_SHA256",
            "original = ast.parse(payload",
            "transformed = ast.parse(payload",
            "tuple(node.name for node in original_functions) != EXPECTED_ENGINE_FUNCTIONS",
            "tuple(node.name for node in transformed_functions) != EXPECTED_ENGINE_FUNCTIONS",
            "engine_main_node = original_functions[-1]",
            "ast.get_source_segment(payload, engine_main_node)",
            "EXPECTED_ENGINE_MAIN_SHA256",
            "function_names = set(EXPECTED_ENGINE_FUNCTIONS)",
            'pending = ["engine_main"]',
            "if closure != function_names:",
            'values = {"ROOT_UID": os.geteuid(), "ROOT_GID": os.getegid()}',
            "target.id in values",
            "node.value.value != 0",
            "node.value = ast.copy_location(ast.Constant(values[target.id]), node.value)",
            'replacements != ["ROOT_UID", "ROOT_GID"]',
            "if len(original.body) != len(transformed.body):",
            'raise AssertionError("embedded-engine-module-body-cardinality")',
            "top_level_differences = []",
            "for original_node, transformed_node in zip(original.body, transformed.body):",
            "target_name = original_node.targets[0].id",
            "top_level_differences.append(target_name)",
            "ast.dump(original_node, include_attributes=False) !=",
            "ast.dump(transformed_node, include_attributes=False)",
            'raise AssertionError("production-module-rewrite")',
            'top_level_differences != ["ROOT_UID", "ROOT_GID"]',
            'raise AssertionError("production-module-difference-cardinality")',
            "after = {",
            "if after != before:",
            'return compile(transformed, str(stager) + ":embedded-r2", "exec")',
        ),
        "hermetic extraction of actual R2 engine_main closure",
    )
    if (
        extract_engine.count("ast.parse(payload") != 2
        or extract_engine.count("node.value = ") != 1
        or extract_engine.count("compile(transformed") != 1
        or extract_engine.count("for original_node, transformed_node in zip(") != 1
        or extract_engine.count("top_level_differences.append(target_name)") != 1
        or any(
            forbidden in extract_engine
            for forbidden in (
                "ast.NodeTransformer",
                "payload.replace(",
                "source.replace(",
                'namespace["engine_main"]',
                "namespace['engine_main']",
                "setattr(",
            )
        )
    ):
        fail("hermetic R2 engine AST transform is not UID/GID-only")
    extract_engine_node = next(
        node
        for node in engine_harness_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "extract_and_transform_engine"
    )
    attribute_write_targets = tuple(
        ast.get_source_segment(engine_harness, target) or ""
        for node in ast.walk(extract_engine_node)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        for target in (
            node.targets
            if isinstance(node, ast.Assign)
            else (node.target,)
        )
        if isinstance(target, ast.Attribute)
    )
    if attribute_write_targets != ("node.value",):
        fail("hermetic R2 engine AST mutates more than the two root-id values")

    engine_argv_source = python_function(engine_harness, "engine_argv")
    engine_argv_node = next(
        node
        for node in engine_harness_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "engine_argv"
    )
    argv_assignments = [
        node.value
        for node in ast.walk(engine_argv_node)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "argv"
            for target in node.targets
        )
    ]
    if (
        len(argv_assignments) != 1
        or not isinstance(argv_assignments[0], ast.List)
        or len(argv_assignments[0].elts) != 24
    ):
        fail("hermetic actual R2 engine argv is not one 24-item list")
    ordered(
        engine_argv_source,
        (
            '"embedded-r2-engine", mode, PATHS["current_manifest"], manifest_sha',
            'PATHS["current_manifest_pending"], PATHS["current_self"]',
            'PATHS["current_self_pending"], PATHS["user_intake"]',
            'PATHS["home_qroot"], PATHS["auth_root"], PATHS["q_intake"]',
            'PATHS["q_package"], PATHS["source_package"]',
            'PATHS["source_bootstrap"], PATHS["run_qroot"]',
            'PATHS["q_bootstrap"], PATHS["lock"], PATHS["receipt_pending"]',
            'PATHS["receipt_final"], PREDECESSOR_COMMIT',
            "PREDECESSOR_MANIFEST_SHA256, HOSTNAME, KERNEL, MACHINE_ID",
            "if len(argv) != 24:",
            "return argv",
        ),
        "hermetic actual R2 engine fixed argv",
    )
    if any(
        mutation in engine_argv_source
        for mutation in ("argv.append", "argv.extend", "argv.insert", "argv +=")
    ):
        fail("hermetic R2 engine argv is mutable after its 24-item authority")
    execute_engine_child = python_function(
        engine_harness, "execute_engine_child"
    )
    ordered(
        execute_engine_child,
        (
            "code = extract_and_transform_engine(stager)",
            "install_engine_boundaries(",
            "sys.argv = engine_argv(mode, manifest_sha)",
            'exec(code, {"__name__": "__main__", "__file__": "<embedded-r2-engine>"})',
            "renameat2.calls != expected_renames",
            "HERMETIC_R2_ENGINE_CHILD functions=48 closure=48 argv=24",
            "root_id_assignments=2",
        ),
        "hermetic execution of actual embedded engine_main",
    )
    if any(
        override in engine_harness
        for override in (
            'namespace["engine_main"] =',
            "namespace['engine_main'] =",
            "globals()[\"engine_main\"] =",
            "globals()['engine_main'] =",
        )
    ):
        fail("hermetic R2 harness replaces actual engine_main")

    harness_receipt_node = next(
        node
        for node in engine_harness_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "independent_r2_receipt"
    )
    harness_receipt_source = ast.get_source_segment(
        engine_harness, harness_receipt_node
    ) or ""
    harness_receipt_lines = [
        node.value
        for node in ast.walk(harness_receipt_node)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "lines"
            for target in node.targets
        )
    ]
    if len(harness_receipt_lines) != 1 or not isinstance(
        harness_receipt_lines[0], ast.Tuple
    ):
        fail("hermetic R2 engine receipt oracle is not one ordered tuple")
    harness_receipt_environment = {
        "PREDECESSOR_COMMIT": r2_predecessor_commit,
        "PREDECESSOR_MANIFEST_SHA256": r2_predecessor_manifest_sha,
        "R1_ID": "c8e41d73-2c690050ae1d-r1",
        "R1_RECEIPT_SHA256": retained_retirement_receipt_sha,
        "manifest_sha": "a" * 64,
        "self_sha": "b" * 64,
    }

    def harness_receipt_value(node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in harness_receipt_environment:
            return harness_receipt_environment[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return harness_receipt_value(node.left) + harness_receipt_value(node.right)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            if node.value.id == "PATHS" and node.slice.value in harness_paths:
                return harness_paths[node.slice.value]
            if node.value.id == "values" and node.slice.value == "integration_commit":
                return "c" * 40
        fail(
            "hermetic R2 engine receipt contains a production-derived/non-contract "
            f"expression: {ast.dump(node)}"
        )
        raise AssertionError

    harness_receipt_pairs = []
    for item in harness_receipt_lines[0].elts:
        if not isinstance(item, ast.Tuple) or len(item.elts) != 2:
            fail("hermetic R2 engine receipt entry is not a key/value pair")
        harness_receipt_pairs.append(
            (
                harness_receipt_value(item.elts[0]),
                harness_receipt_value(item.elts[1]),
            )
        )
    if tuple(harness_receipt_pairs) != expected_receipt_pairs:
        fail("hermetic R2 engine receipt oracle is not the independent exact 35 pairs")
    ordered(
        harness_receipt_source,
        (
            "manifest_payload, values = manifest_values(current_manifest)",
            "manifest_sha = hashlib.sha256(manifest_payload).hexdigest()",
            "self_sha = digest(current_self)",
            'values.get("prepare_stage_root_sh_sha256") != self_sha',
            'payload = b"".join(',
            'key.encode("ascii") + b"\\t" + value.encode("ascii") + b"\\n"',
            "len(lines) != 35",
            "len(set(keys)) != 35",
            "len(payload) != 1998",
            'payload.count(b"\\n") != 35',
            'b"\\r" in payload',
            'b"\\0" in payload',
            "return manifest_sha, payload",
        ),
        "hermetic independent exact R2 receipt bytes",
    )
    if any(
        production_receipt in harness_receipt_source
        for production_receipt in (
            "receipt_bytes(",
            "validate_receipt(",
            "EXPECTED_RECEIPT_SHA",
            "R2_RECEIPT_SHA",
        )
    ):
        fail("hermetic R2 engine computes expected receipt with production logic")

    make_pair_source = python_function(engine_harness, "make_pair")
    ordered(
        make_pair_source,
        (
            "if fifo:",
            "os.mkfifo(final, mode)",
            "else:",
            "copy_mode(source, final, mode)",
            "os.link(final, pending)",
            "first = os.lstat(final)",
            "second = os.lstat(pending)",
            "expected_type = stat.S_ISFIFO if fifo else stat.S_ISREG",
            "(first.st_dev, first.st_ino, first.st_nlink) !=",
            "(second.st_dev, second.st_ino, 2)",
        ),
        "hermetic R2 authority regular/FIFO held-pair fixture",
    )
    tree_snapshot_source = python_function(engine_harness, "tree_snapshot")
    ordered(
        tree_snapshot_source,
        (
            "metadata = os.lstat(path)",
            'kind = "d"',
            "names = tuple(sorted(os.listdir(path)))",
            'kind = "f"',
            "content = digest(path)",
            'kind = "p"',
            'kind = "l"',
            "content = os.readlink(path)",
            "relative, kind, metadata.st_dev, metadata.st_ino",
            "stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid",
            "metadata.st_nlink, metadata.st_size, content",
            "return tuple(result)",
        ),
        "hermetic exact inode/type/mode/content tree snapshot",
    )
    r1_snapshot_source = python_function(engine_harness, "r1_snapshot")
    if (
        r1_snapshot_source.count("tree_snapshot(root, R1_HOME_QROOT)") != 1
        or r1_snapshot_source.count("tree_snapshot(root, R1_RUN_QROOT)") != 1
        or "PATHS[" in r1_snapshot_source
    ):
        fail("hermetic R1 snapshot is not independently scoped to both retained roots")
    observe_state_source = python_function(engine_harness, "observe_state")
    ordered(
        observe_state_source,
        (
            "STATE_SIGNATURES.items()",
            "len(matches) != 1",
            'state == "S2P"',
            'PATHS["receipt_pending"]',
            ".read_bytes() != expected_receipt",
            'state == "T_CANDIDATE"',
            'PATHS["receipt_final"]',
            ".read_bytes() != expected_receipt",
        ),
        "hermetic state oracle binds exact pending/final receipt bytes",
    )

    engine_boundaries = python_function(
        engine_harness, "install_engine_boundaries"
    )
    ordered(
        engine_boundaries,
        (
            "real_os_open = os.open",
            "real_os_rename = os.rename",
            "real_os_stat = os.stat",
            "real_builtin_open = builtins.open",
            "def mapped_os_open(path, flags, mode=0o777, *, dir_fd=None):",
            'os.fsdecode(os.fspath(path)) == "/"',
            "return real_os_open(mapped, flags, mode)",
            "return real_os_open(mapped, flags, mode, dir_fd=dir_fd)",
            "def synthetic_open(path, mode=\"r\", *args, **kwargs):",
            'decoded == "/etc/machine-id"',
            'decoded == "/proc/sys/kernel/random/boot_id"',
            're.fullmatch(r"/proc/self/fdinfo/([0-9]+)", decoded)',
            "def fixed_subprocess_run(argv, **kwargs):",
            '"pass_fds"',
            '"/proc/self/fd/%s" % provisioner',
            '"--check"',
            "def fixed_cdll(name, *args, **kwargs):",
            'name != "libc.so.6"',
            "os.open = mapped_os_open",
            "os.uname = lambda:",
            "builtins.open = synthetic_open",
            "pwd.getpwnam = lambda name:",
            "subprocess.run = fixed_subprocess_run",
            "ctypes.CDLL = fixed_cdll",
        ),
        "hermetic engine low-level path/identity/provision/rename seams",
    )
    boundary_assignments = tuple(
        re.findall(
            r"(?m)^    ((?:os\.(?:open|uname)|builtins\.open|pwd\.getpwnam|"
            r"subprocess\.run|ctypes\.CDLL)) = ",
            engine_boundaries,
        )
    )
    if boundary_assignments != (
        "os.open",
        "os.uname",
        "builtins.open",
        "pwd.getpwnam",
        "subprocess.run",
        "ctypes.CDLL",
    ):
        fail("hermetic engine installs a non-low-level execution seam")
    for protected_engine_function in expected_engine_functions:
        if re.search(
            rf"(?m)^\s*(?:def\s+{re.escape(protected_engine_function)}\s*\(|"
            rf"{re.escape(protected_engine_function)}\s*=)",
            engine_harness,
        ):
            fail(
                "hermetic harness replaces production engine function: "
                f"{protected_engine_function}"
            )

    independent_r1_receipt = python_function(
        engine_harness, "independent_r1_receipt"
    )
    ordered(
        independent_r1_receipt,
        (
            'lines = (\n        ("format", "wg-mix-ebpf-b82-prestage-retirement-terminal-v1")',
            '("retire_id", R1_ID)',
            '("state", "TERMINAL")',
            '("authority_manifest_sha256", R1_MANIFEST_SHA256)',
            '("authority_prepare_stage_root_sha256", R1_SELF_SHA256)',
            '("rename_order", "intake,package,bootstrap")',
            '("rename_primitive", "renameat2-RENAME_NOREPLACE-dirfd-v1")',
            '("retention", "no-unlink-no-rmdir-no-copy-fallback")',
            'payload = b"".join(',
            "len(lines) != 18",
            "len(payload) != 1211",
            "hashlib.sha256(payload).hexdigest() != R1_RECEIPT_SHA256",
            "return payload",
        ),
        "hermetic independent retained R1 receipt",
    )
    if "r1_receipt_bytes(" in independent_r1_receipt:
        fail("hermetic R1 expected receipt is production-derived")
    setup_engine_fixture = python_function(
        engine_harness, "setup_engine_fixture"
    )
    ordered(
        setup_engine_fixture,
        (
            'authority_fifo not in {"none", "manifest", "self"}',
            'digest(Path(predecessor) / "package-manifest.v1") != PREDECESSOR_MANIFEST_SHA256',
            "digest(R1_RETAINED_PACKAGE / \"package-manifest.v1\")",
            "digest(R1_AUTHORITY_PACKAGE / \"package-manifest.v1\")",
            "digest(R1_AUTHORITY_PACKAGE / \"prepare-stage-root.sh\")",
            "manifest_sha, receipt = independent_r2_receipt(current_manifest, current_self)",
            'mkdir_logical(root, PATHS["home_qroot"])',
            'mkdir_logical(root, PATHS["auth_root"])',
            'mkdir_logical(root, PATHS["run_qroot"])',
            'fifo=authority_fifo == "manifest"',
            'fifo=authority_fifo == "self"',
            "copy_exact_set(\n        predecessor",
            "PACKAGE_NAMES, 0o600",
            "for name in BOOTSTRAP_NAMES:",
            "mkdir_logical(root, R1_HOME_QROOT)",
            "copy_exact_set(\n        R1_RETAINED_PACKAGE",
            "mkdir_logical(root, R1_RUN_QROOT)",
            'make_pair(\n        R1_AUTHORITY_PACKAGE / "package-manifest.v1"',
            'make_pair(\n        R1_AUTHORITY_PACKAGE / "prepare-stage-root.sh"',
            "copy_mode(R1_RETAINED_PACKAGE / name",
            "r1_final.write_bytes(independent_r1_receipt())",
            "chown_tree_current(root)",
            "return manifest_sha, receipt",
        ),
        "hermetic actual engine fixture with independent current/R1 authority",
    )

    run_engine_process = python_function(engine_harness, "run_engine_process")
    ordered(
        run_engine_process,
        (
            'sys.executable, "-B", "-I", str(Path(__file__).resolve()), "child"',
            "str(stager), str(current_manifest), str(current_self), str(predecessor)",
            "str(root), mode, str(expected_renames), str(cut_call), cut_phase, cut_kind",
            "return subprocess.run(",
            "stdin=subprocess.DEVNULL",
            "stdout=subprocess.PIPE",
            "stderr=subprocess.STDOUT",
            "check=False",
            "timeout=timeout",
            "except subprocess.TimeoutExpired",
            'raise AssertionError(\n            "engine-child-timeout:',
        ),
        "hermetic bounded actual engine child execution",
    )
    driver_node = next(
        node
        for node in engine_harness_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "driver"
    )
    driver_source = ast.get_source_segment(engine_harness, driver_node) or ""
    cut_point_assignments = [
        node.value
        for node in ast.walk(driver_node)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "cut_points"
            for target in node.targets
        )
    ]
    if len(cut_point_assignments) != 1:
        fail("hermetic actual engine cut matrix is not unique")
    try:
        harness_cut_points = ast.literal_eval(cut_point_assignments[0])
    except (TypeError, ValueError) as exc:
        fail(f"hermetic actual engine cut matrix is not literal: {exc}")
    if harness_cut_points != (
        (1, "post", "I", 3, 4),
        (2, "post", "S1", 2, 3),
        (3, "post", "S2", 1, 2),
        (4, "pre", "S2P", 1, 1),
        (4, "post", "T_CANDIDATE", 0, 0),
    ):
        fail("hermetic actual engine cut/reentry states are not exact five-by-two")
    ordered(
        driver_source,
        (
            "extract_and_transform_engine(stager)",
            "manifest_sha, expected_receipt = independent_r2_receipt(",
            'baseline = new_case("baseline")',
            "baseline_r1 = r1_snapshot(baseline)",
            "baseline_inodes = source_directory_identities(baseline)",
            'observe_state(baseline, expected_receipt, allow_lockless_d=True) != "D"',
            '"retire-postflight-f75fe7678cfd-r2", 4)',
            "result.returncode != 0",
            "B82_V6_RETIREMENT_COMPLETE state=T disposition=advanced",
            "namespace_writes=6 same_boot=1",
            'observe_state(baseline, expected_receipt) != "T_CANDIDATE"',
            '"verify-postflight-retirement-r2", 0)',
            "verify.returncode != 0",
            "B82_V6_RETIREMENT_VERIFIED state=T namespace_writes=0 same_boot=1",
            "complete_snapshot(baseline) != baseline_terminal",
            'for kind in ("exit91", "sigterm"):',
            '"retire-postflight-f75fe7678cfd-r2", -1, call, phase, kind)',
            'expected_rc = 91 if kind == "exit91" else -signal.SIGTERM',
            "interrupted.returncode != expected_rc",
            "observe_state(root, expected_receipt) != observed_state",
            "assert_completed_move_identities(root, initial_inodes, observed_state)",
            "r1_snapshot(root) != before_r1",
            '"retire-postflight-f75fe7678cfd-r2", resume_renames)',
            "resumed.returncode != 0",
            'if observed_state == "T_CANDIDATE":',
            "disposition=verified-existing namespace_writes=0 same_boot=1",
            'observe_state(root, expected_receipt) != "T_CANDIDATE"',
            "terminal_snapshot = complete_snapshot(root)",
            '"verify-postflight-retirement-r2", 0)',
            "verified.returncode != 0",
            "complete_snapshot(root) != terminal_snapshot",
            "cut_count += 1",
            "resume_count += 1",
            'if kind == "exit91":',
            "exit_count += 1",
            "signal_count += 1",
            'for fifo, reason in (\n            ("manifest", "authority-manifest-pending-metadata")',
            '("self", "authority-self-pending-metadata")):',
            'new_case("authority-%s-fifo" % fifo, fifo=fifo)',
            '"retire-postflight-f75fe7678cfd-r2", 0, timeout=5.0)',
            "failed.returncode != 79 or elapsed >= 5.0",
            "B82_V6_RETIREMENT_ENGINE_STOP reason=%s rc=79 cleanup=0 retained=1",
            'observe_state(root, expected_receipt, allow_lockless_d=True) != "D"',
            'os.path.lexists(virtual(root, PATHS["lock"]))',
            "complete_snapshot(root) != before",
            "r1_snapshot(root) != before_r1",
            "fifo_count += 1",
            "r1_comparisons) != (10, 5, 5, 10, 2, 34)",
        ),
        "hermetic actual engine cut/reentry/verify/FIFO/R1 matrix",
    )
    if (
        driver_source.count("run_engine_process(") != 6
        or driver_source.count("r1_comparisons += 1") != 6
        or driver_source.count("complete_snapshot(") != 6
        or driver_source.count("verify-postflight-retirement-r2") != 2
    ):
        fail("hermetic actual engine matrix call/counter structure drifted")

    engine_marker = (
        "HERMETIC_R2_ENGINE states=7 functions=48 argv=24 cuts=10 "
        "exit91=5 sigterm=5 resumes=10 verify_namespace_writes=0 "
        "authority_fifos=2 result=PASS"
    )
    r1_engine_marker = (
        "HERMETIC_R2_R1_INVARIANCE result=PASS snapshots=34 "
        "objects=authority,intake,package,bootstrap,lock,receipt"
    )
    driver_string_constants = tuple(
        node.value
        for node in ast.walk(driver_node)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    )
    if (
        driver_string_constants.count(engine_marker) != 1
        or driver_string_constants.count(r1_engine_marker) != 1
    ):
        fail("hermetic actual engine/R1 markers are not exact-once")
    engine_harness_outer = hermetic[
        engine_harness_end + len(engine_harness_close) :
        hermetic.index(
            "for retired_mode in retire-prestage-2c690050 verify-retirement; do",
            engine_harness_end,
        )
    ]
    ordered(
        engine_harness_outer,
        (
            '/bin/chmod 0600 "${R2_ENGINE_HARNESS}"',
            'R2_ENGINE_TEST_OUTPUT="$(/usr/bin/python3 -B -I "${R2_ENGINE_HARNESS}"',
            '"${STAGER}" "${BOUND_MANIFEST}" "${BOUND_OUTPUT}/prepare-stage-root.sh"',
            '"${R2_PREDECESSOR_CLONE}" "${TEST_ROOT}/r2-engine-cases")"',
            "fail 'actual embedded R2 engine harness'",
            "HERMETIC_R2_ENGINE ",
            "states=7 functions=48 argv=24 cuts=10 exit91=5 sigterm=5 resumes=10",
            "verify_namespace_writes=0 authority_fifos=2 result=PASS",
            "HERMETIC_R2_R1_INVARIANCE ",
            "result=PASS snapshots=34",
            'printf \'%s\\n\' "${R2_ENGINE_TEST_OUTPUT}"',
        ),
        "hermetic invocation of actual frozen stager engine harness",
    )

    r2_raw_case = harness_cases["r2-raw-sequence"]
    ordered(
        r2_raw_case,
        (
            "rename execute_operation_spec transport_original_execute_operation_spec",
            "proc execute_operation_spec {operation operation_spec password}",
            "[lsearch -exact [r2_test_raw_sequence] $operation] >= 0",
            "r2_test_validate_raw_spec $operation $operation_spec",
            "lappend ::r2_raw_observed $operation",
            "execute_r2_transaction $values $manifest_sha",
            "set expected [r2_test_raw_sequence]",
            "[llength $::r2_raw_observed] != 21",
            "HARNESS_R2_RAW_SEQUENCE leaves=21 order=exact helper=last",
            "terminal=PASS result=PASS",
        ),
        "hermetic actual R2 raw mutation sequence",
    )
    if (
        r2_raw_case.count("execute_r2_transaction") != 1
        or r2_raw_case.count("rename execute_operation_spec ") != 1
    ):
        fail("hermetic R2 raw harness does not instrument one actual transaction")

    raw_ssh_prefix = tcl_proc(transport_harness, "r2_test_exact_ssh_prefix")
    raw_scp_prefix = tcl_proc(transport_harness, "r2_test_exact_scp_prefix")
    raw_spec_oracle = tcl_proc(transport_harness, "r2_test_validate_raw_spec")
    if any(
        production_options in raw_ssh_prefix + raw_scp_prefix + raw_spec_oracle
        for production_options in (
            "[ssh_options",
            "[scp_options",
            "[env_argv",
            "[build_r2_operation",
            "[r2_helper_remote_argv",
        )
    ):
        fail("hermetic R2 raw argv oracle is production-derived")
    raw_ssh_return = re.search(
        r"(?ms)return \[list (?P<body>/usr/bin/ssh.*?)\]\s*$", raw_ssh_prefix
    )
    raw_scp_return = re.search(
        r"(?ms)return \[list (?P<body>/usr/bin/scp.*?)\]\s*$", raw_scp_prefix
    )
    if not raw_ssh_return or not raw_scp_return:
        fail("hermetic R2 raw argv oracle lacks flat SSH/SCP prefixes")

    def fixed_tcl_words(body: str) -> tuple[str, ...]:
        return tuple(body.replace("\\\n", " ").split())

    expected_raw_transport_options = (
        "-o",
        "BatchMode=no",
        "-o",
        "PasswordAuthentication=yes",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "CheckHostIP=yes",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "LocalCommand=none",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlPersist=no",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        "Compression=no",
        "-o",
        "LogLevel=ERROR",
    )
    expected_raw_ssh_prefix = (
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "$terminal",
        *expected_raw_transport_options,
        "--",
        "siyixuan@192.168.10.82",
    )
    # The lineage prefix is fixed `-tt`; the raw oracle independently chooses
    # exactly `-tt` or `-T` at the single terminal slot.
    if (
        'set terminal [expr {$tty ? "-tt" : "-T"}]' not in raw_ssh_prefix
        or fixed_tcl_words(raw_ssh_return.group("body"))
        != expected_raw_ssh_prefix
    ):
        fail("hermetic R2 raw SSH prefix is not complete and independent")
    expected_raw_scp_prefix = (
        "/usr/bin/scp",
        "-F",
        "/dev/null",
        "-q",
        *expected_raw_transport_options,
    )
    if fixed_tcl_words(raw_scp_return.group("body")) != expected_raw_scp_prefix:
        fail("hermetic R2 raw SCP prefix is not complete and independent")
    raw_case_headers = re.findall(
        r"(?m)^\s+(r2-raw-[a-z0-9-]+(?:\s+-\s+r2-raw-[a-z0-9-]+)*)\s+\{",
        raw_spec_oracle,
    )
    raw_case_operations = tuple(
        operation
        for header in raw_case_headers
        for operation in re.findall(r"r2-raw-[a-z0-9-]+", header)
    )
    if (
        len(raw_case_operations) != 21
        or len(set(raw_case_operations)) != 21
        or set(raw_case_operations) != set(r2_raw_operations)
    ):
        fail("hermetic R2 raw argv oracle does not cover exactly 21 leaves")
    ordered(
        raw_spec_oracle,
        (
            "set expected [concat [r2_test_exact_scp_prefix]",
            "[lrange $spawn_argv 0 end] ne [lrange $expected 0 end]",
            "r2-raw-intake-mkdir",
            "/usr/bin/mkdir --mode=0700 -- $intake",
            "r2-raw-auth-manifest-install",
            "/usr/bin/install --owner=root --group=root",
            "--mode=0600 --no-target-directory --",
            "r2-raw-link-auth-manifest",
            "/usr/bin/ln --no-target-directory --",
            "r2-raw-helper-mutate",
            "/bin/bash -p ${auth}/prepare-stage-root.sh",
            "retire-postflight-f75fe7678cfd-r2 --manifest",
            "${auth}/package-manifest.v1 --manifest-sha256",
            "$::r2_manifest_sha",
            "/usr/bin/sudo -- /usr/bin/env -i",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C",
            "set expected [concat [r2_test_exact_ssh_prefix $tty] $remote]",
            "[lrange $spawn_argv 0 end] ne [lrange $expected 0 end]",
        ),
        "hermetic R2 independent whole raw argv oracle",
    )
    if raw_spec_oracle.count(
        "[lrange $spawn_argv 0 end] ne [lrange $expected 0 end]"
    ) != 2:
        fail("hermetic R2 raw oracle does not compare both whole SSH/SCP argv")

    receipt_script_match = re.search(
        r"(?ms)^R2_RECEIPT_TEST_OUTPUT=\"\$\(/usr/bin/python3 -B -I -c '\n"
        r"(?P<body>.*?)\n'\)\" \|\| fail 'independent R2 receipt oracle'",
        hermetic,
    )
    if not receipt_script_match:
        fail("cannot isolate hermetic independent R2 receipt oracle")
    hermetic_receipt = receipt_script_match.group("body")
    try:
        hermetic_receipt_tree = ast.parse(hermetic_receipt)
    except SyntaxError as exc:
        fail(f"hermetic independent R2 receipt oracle is not Python: {exc}")
    receipt_line_nodes = [
        node.value
        for node in hermetic_receipt_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "lines"
            for target in node.targets
        )
    ]
    if len(receipt_line_nodes) != 1 or not isinstance(receipt_line_nodes[0], ast.Tuple):
        fail("hermetic R2 receipt oracle does not own one literal ordered tuple")
    receipt_dynamic_values = {
        "authority_manifest": "a" * 64,
        "authority_helper": "b" * 64,
        "authority_commit": "c" * 40,
    }
    hermetic_receipt_pairs = []
    for item in receipt_line_nodes[0].elts:
        if not isinstance(item, ast.Tuple) or len(item.elts) != 2:
            fail("hermetic R2 receipt oracle entry is not a key/value pair")
        key_node, value_node = item.elts
        if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
            fail("hermetic R2 receipt oracle key is not literal")
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            value = value_node.value
        elif isinstance(value_node, ast.Name) and value_node.id in receipt_dynamic_values:
            value = receipt_dynamic_values[value_node.id]
        else:
            fail("hermetic R2 receipt oracle value is production-derived")
        hermetic_receipt_pairs.append((key_node.value, value))
    if tuple(hermetic_receipt_pairs) != expected_receipt_pairs:
        fail("hermetic R2 receipt oracle is not the independent exact 35-key order")
    ordered(
        hermetic_receipt,
        (
            'authority_manifest = "a" * 64',
            'authority_helper = "b" * 64',
            'authority_commit = "c" * 40',
            'payload = b"".join(',
            'key.encode("ascii") + b"\\t" + value.encode("ascii") + b"\\n"',
            "len(lines) != 35",
            "len(set(keys)) != 35",
            "len(payload) != 1998",
            'payload.count(b"\\n") != 35',
            'not payload.endswith(b"\\n")',
            'b"\\r" in payload',
            'b"\\0" in payload',
            "tamper_rejections != 35",
            "prefix_accepts != 3",
            "prefix_rejects != 2",
            "HERMETIC_R2_RECEIPT keys=35 bytes=1998 dynamic=3",
            "hashlib.sha256(payload).hexdigest()",
        ),
        "hermetic independent R2 canonical receipt bytes",
    )
    if (
        re.search(r"\breceipt_bytes\s*\(", hermetic_receipt)
        or "prepare-stage-root.py" in hermetic_receipt
        or re.search(r"sha256=[0-9a-f]{64}", hermetic_receipt)
    ):
        fail("hermetic R2 receipt expected bytes/hash are production-derived or hardcoded")

    for removed_case in (
        "retirement-precredential",
        "retirement-sequence",
        "retirement-delivery-durability",
        "retirement-authority-prefixes",
        "retirement-intake-prefixes",
        "RETIREMENT_ENGINE_HARNESS",
        "HARNESS_RETIREMENT_",
        "set ::PREDECESSOR_PACKAGE ",
        "set ::PREDECESSOR_MANIFEST ",
    ):
        if removed_case in hermetic:
            fail(f"hermetic test retains obsolete retirement harness {removed_case!r}")

    expected_prepare_proc = tcl_proc(transport_harness, "expected_prepare_sequence")
    expected_prefix_match = re.search(
        r"(?ms)^\s*set expected \{(?P<body>.*?)^\s*\}\n\s*foreach name \{",
        expected_prepare_proc,
    )
    expected_package_match = re.search(
        r"(?ms)foreach name \{(?P<body>.*?)\n\s*\} \{",
        expected_prepare_proc,
    )
    fixed_prepare_prefix = (
        "identity-hostname",
        "identity-kernel",
        "identity-machine",
        "identity-netns",
        "identity-interface",
    ) + expected_stale_operations + (
        "package-parent-stat",
        "lineage:lineage-exists-user-intake",
        "lineage:lineage-exists-home-qroot",
        "lineage:lineage-exists-run-qroot",
        "package-mkdir",
    )
    fixed_prepare_runtime_prefix = (
        "identity-hostname",
        "identity-kernel",
        "identity-machine",
        "identity-netns",
        "identity-interface",
    ) + expected_stale_operations + (
        "package-parent-stat",
        "lineage-exists-user-intake",
        "lineage-exists-home-qroot",
        "lineage-exists-run-qroot",
        "package-mkdir",
    )
    if (
        not expected_prefix_match
        or tuple(expected_prefix_match.group("body").split()) != fixed_prepare_prefix
        or not expected_package_match
        or tuple(expected_package_match.group("body").split())
        != expected_current_package_names
    ):
        fail(
            "hermetic prepare oracle is not the independent "
            "5+30+parent+lineage+20 package tuple"
        )
    for production_oracle in (
        "[base_identity_operations]",
        "[prepare_stale_operations]",
        "[retained_retirement_package_names]",
        "[lineage_entry_assertion",
    ):
        if production_oracle in expected_prepare_proc:
            fail(f"hermetic prepare oracle is production-derived: {production_oracle}")

    lineage_harness = "\n".join(
        harness_cases[name]
        for name in (
            "prepare-sequence",
            "mkdir-failure",
            "lineage-existence",
            "lineage-gate",
            "prepare-lineage",
        )
    )
    for proc_name in (
        "build_retirement_lineage_operation",
        "execute_retirement_lineage_primitive",
        "retirement_lineage_path_exists",
        "retirement_lineage_step",
        "execute_retirement_lineage_gate",
        "assert_output",
        "execute_prepare_transaction",
    ):
        if (
            f"rename {proc_name} " in lineage_harness
            or re.search(rf"(?m)^\s*proc {re.escape(proc_name)}\s", lineage_harness)
        ):
            fail(f"hermetic lineage harness replaces production procedure {proc_name}")
    for allowed_mock in (
        "require_manifest_authority",
        "execute_operation_spec",
        "execute_primitive",
    ):
        if f"rename {allowed_mock} " not in lineage_harness:
            fail(f"hermetic lineage harness lacks explicit I/O seam {allowed_mock}")

    existence_case = harness_cases["lineage-existence"]
    ordered(
        existence_case,
        (
            "lineage-exists-user-intake",
            "lineage-exists-home-qroot",
            "lineage-exists-run-qroot",
            "lineage-exists-receipt-pending",
            "set absent [retirement_lineage_path_exists",
            "set present [retirement_lineage_path_exists",
            "foreach failure {child-nonzero signal malformed}",
            "[dict get $options -errorcode] ne {B82FAIL 78}",
            "HARNESS_LINEAGE_EXISTENCE paths=4 empty=absent exact=present",
            "child_nonzero=STOP signal=STOP malformed=STOP",
            "credential_reads=1 result=PASS",
        ),
        "lineage existence output/failure classifier matrix",
    )

    gate_case = harness_cases["lineage-gate"]
    terminal_operations_match = re.search(
        r"(?ms)^\s*proc lineage_test_terminal_operations \{\} \{\s*"
        r"return \{(?P<body>.*?)\}\s*\}",
        gate_case,
    )
    package_entries_match = re.search(
        r"(?ms)^\s*proc lineage_test_package_entries \{\} \{.*?"
        r"foreach name \{(?P<body>.*?)\n\s*\} \{",
        gate_case,
    )
    if (
        not terminal_operations_match
        or tuple(terminal_operations_match.group("body").split())
        != expected_lineage_deep_operations
        or not package_entries_match
        or tuple(package_entries_match.group("body").split())
        != expected_retained_package_names
    ):
        fail("hermetic terminal lineage oracle is not the fixed 35/17 tuple")
    ssh_prefix_match = re.search(
        r"(?ms)^\s*proc lineage_test_ssh_prefix \{\} \{\s*"
        r"return \{(?P<body>.*?)\}\s*\}",
        gate_case,
    )
    expected_ssh_prefix = (
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-tt",
        "-o",
        "BatchMode=no",
        "-o",
        "PasswordAuthentication=yes",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "CheckHostIP=yes",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "LocalCommand=none",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlPersist=no",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        "Compression=no",
        "-o",
        "LogLevel=ERROR",
        "--",
        "fixture@127.0.0.1",
    )
    if (
        not ssh_prefix_match
        or tuple(ssh_prefix_match.group("body").split()) != expected_ssh_prefix
    ):
        fail("hermetic lineage spawn oracle does not fix the complete SSH prefix")
    spawn_oracle = indented_tcl_proc(
        gate_case, "lineage_test_expected_spawn_argv"
    )
    expected_spawn_operations = (
        "lineage-exists-user-intake",
        "lineage-exists-home-qroot",
        "lineage-exists-run-qroot",
        "lineage-exists-receipt-pending",
    ) + expected_lineage_deep_operations + ("lineage-retained-helper-verify",)
    for operation in expected_spawn_operations:
        if operation not in spawn_oracle:
            fail(f"hermetic full-argv oracle omits fixed operation {operation}")
    for production_oracle in (
        "[build_retirement_lineage_operation",
        "[retirement_lineage_path_exists",
        "[lineage_entry_assertion",
        "[retained_retirement_package_names]",
        "$operation_spec",
        "$actual_spawn_argv",
    ):
        if production_oracle in spawn_oracle:
            fail(
                "hermetic full-argv oracle is production-derived: "
                f"{production_oracle}"
            )
    expected_remote_executables = {
        "/bin/bash",
        "/usr/bin/env",
        "/usr/bin/find",
        "/usr/bin/readlink",
        "/usr/bin/sha256sum",
        "/usr/bin/ssh",
        "/usr/bin/stat",
        "/usr/bin/sudo",
    }
    remote_executables = set(
        re.findall(
            r"(?<![A-Za-z0-9_.-])/(?:usr/)?bin/[A-Za-z0-9_.-]+",
            ssh_prefix_match.group("body") + spawn_oracle,
        )
    )
    if remote_executables != expected_remote_executables:
        fail("hermetic lineage argv oracle executable set is not exact")
    for mutable_find_action in (
        "-delete",
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-fprint",
        "-fprintf",
    ):
        if mutable_find_action in spawn_oracle:
            fail(
                "hermetic lineage argv oracle contains mutable find action "
                f"{mutable_find_action!r}"
            )
    ordered(
        spawn_oracle,
        (
            "/usr/bin/sudo -- /usr/bin/env -i",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C",
            "lineage-exists-user-intake",
            "set parent /home/siyixuan/wg-mix-ebpf-test",
            "retire-prestage-c8e41d73-2c690050ae1d-r1.intake",
            "lineage-exists-home-qroot",
            "set parent /home",
            ".wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1",
            "lineage-exists-run-qroot",
            "set parent /run",
            "wg-mix-ebpf-retirement-c8e41d73-2c690050ae1d-r1",
            "lineage-exists-receipt-pending",
            "set parent $::test_run_qroot",
            "set leaf retirement-complete.v1.pending",
            "[list /usr/bin/find $parent",
            "-xdev -mindepth 1 -maxdepth 1 -name $leaf -print]",
            "[list /usr/bin/readlink -e -- $fixed_path]",
            "[list /usr/bin/stat -Lc",
            "%U:%G:%a:%F -- $fixed_path]",
            "[list /usr/bin/find $fixed_path",
            "-xdev -mindepth 1 -maxdepth 1 -printf {'%f\\t%y\\n'}]",
            "%U:%G:%a:%h:%F",
            "[list /usr/bin/sha256sum -- $fixed_path]",
            "[list /usr/bin/stat -Lc",
            "%d:%i -- $first $second]",
            "if {$operation eq \"lineage-retained-helper-verify\"}",
            "[list /bin/bash -p",
            "verify-retirement --manifest",
            "--manifest-sha256",
            retained_retirement_manifest_sha,
        ),
        "independent complete retirement-lineage spawn argv oracle",
    )
    for production_oracle in (
        "[retained_retirement_package_names]",
        "[lineage_entry_assertion",
        "[build_retirement_lineage_operation",
    ):
        if production_oracle in gate_case:
            fail(f"hermetic terminal lineage oracle is production-derived: {production_oracle}")
    for digest in (
        retained_retirement_manifest_sha,
        retained_retirement_helper_sha,
        retained_retirement_receipt_sha,
    ):
        if gate_case.count(digest) < 2:
            fail(f"hermetic payload/assertion oracles do not independently bind {digest}")
    ordered(
        gate_case,
        (
            "proc lineage_test_payload {operation}",
            "proc lineage_test_assertion {operation}",
            "set actual_spawn_argv [lindex $operation_spec 1]",
            "set expected_spawn_argv",
            "[lineage_test_expected_spawn_argv $operation]",
            "[lrange $actual_spawn_argv 0 end] ne",
            "[lrange $expected_spawn_argv 0 end]",
            "set actual_assertion [lindex $operation_spec 3]",
            "set expected_assertion [lineage_test_assertion $operation]",
            "if {$actual_assertion ne $expected_assertion}",
            "assert_output $actual_assertion $payload",
            "set fresh_state [execute_retirement_lineage_gate",
            "set terminal_state [execute_retirement_lineage_gate",
            "partial-run partial-home partial-user partial-user-run",
            "partial-user-home partial-all",
            "set ::lineage_scenario receipt-pending",
            "recheck-user recheck-home recheck-run recheck-receipt",
            "set ::lineage_fail_kind missing",
            "set ::lineage_fail_kind child-nonzero",
            "lineage-home-readlink lineage-home-stat lineage-home-entries",
            "lineage-auth-manifest-sha lineage-auth-manifest-pair",
            "set ::lineage_fail_kind malformed",
            "foreach failure {child-nonzero signal}",
            "HARNESS_LINEAGE_GATE fresh=PASS terminal=PASS partial_states=6",
            "receipt_pending=STOP recheck_drifts=4 deep_missing=36",
            "deep_nonzero=35 assertion_malformed=6 helper_failures=2",
            "credential_reads=1 mutation_spawns=0 result=PASS",
        ),
        "independent fresh/terminal lineage matrix",
    )
    for mutable_argv in (
        "/usr/bin/mkdir",
        "/usr/bin/install",
        "/bin/ln",
        "/bin/mv",
        "/usr/bin/scp",
        "/bin/rm",
        "/usr/bin/touch",
    ):
        if mutable_argv not in gate_case:
            fail(f"hermetic lineage argv fence omits {mutable_argv!r}")

    prepare_lineage_case = harness_cases["prepare-lineage"]
    prepare_lineage_expected = re.search(
        r"(?ms)\n\s*set expected \{(?P<body>.*?)\n\s*\}\n\s*if ",
        prepare_lineage_case,
    )
    if (
        not prepare_lineage_expected
        or tuple(prepare_lineage_expected.group("body").split())
        != fixed_prepare_runtime_prefix
    ):
        fail("prepare-lineage harness is not the independent 39+mkdir oracle")
    ordered(
        prepare_lineage_case,
        (
            "execute_prepare_transaction $values",
            "[dict get $options -errorcode] ne {TRANSACTION_EXIT 73}",
            "$::mutation_trace ne {package-mkdir}",
            "$::scp_spawns != 0",
            "HARNESS_PREPARE_LINEAGE readonly_prefix=39",
            "first_mutation=package-mkdir mkdir_rc=73 scp=0 credential_reads=1",
        ),
        "prepare lineage placement/first-write matrix",
    )

    retired_surface_match = re.search(
        r"(?ms)^readonly -a RETIRED_PUBLIC_AND_PRIVATE_OPERATIONS=\((?P<body>.*?)^\)\n",
        hermetic,
    )
    expected_retired_surface = (
        "retire-prestage-2c690050",
        "verify-retirement",
        "retire-raw-helper-mutate",
        "retire-raw-future",
        "lineage-home-stat",
    )
    if (
        not retired_surface_match
        or tuple(retired_surface_match.group("body").split())
        != expected_retired_surface
        or "RETIRED_OPERATION_REJECTIONS=0" not in hermetic
        or 'if [[ "${operation}" == lineage-home-stat ]]' not in hermetic
        or "plan_reason=private-operation" not in hermetic
        or "execute_reason=private-operation" not in hermetic
        or '[[ "${RETIRED_OPERATION_REJECTIONS}" -eq 10 ]]' not in hermetic
    ):
        fail("hermetic retired public/private operation surface is not closed")
    for marker in (
        '"${FIXTURE_REVIEW}/locked-transport.exp" lineage-existence)',
        '"${FIXTURE_REVIEW}/locked-transport.exp" lineage-gate)',
        '"${FIXTURE_REVIEW}/locked-transport.exp" prepare-lineage)',
        'controller-retired-mode-${retired_mode}" 64',
        'stager-retired-mode-${retired_mode}" 64',
        "HARNESS_PREPARE_SEQUENCE steps=111",
        "HARNESS_MKDIR_FAILURE rc=73 steps=40",
        "prepare_steps=111 prewrite_cuts=36",
        "HERMETIC_BOUND_FLAT_CLOSURE package=v5 current_files=20 "
        "checksum_dependencies=3 missing_cuts=3 result=PASS",
        "HERMETIC_LOCAL_AUTHORITY package_names=20 package_tamper_cuts=40",
    ):
        if hermetic.count(marker) != 1:
            fail(f"hermetic F-lineage outer contract drifted: {marker!r}")

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
    render_plan = bash_function(stager, "render_plan")
    run_stage = bash_function(stager, "run_stage")
    plan_gate_order = (
        'checkout --detach "${INTEGRATION_COMMIT}"',
        "plan_command S6 /bin/bash -n",
        "plan_command S6.realnic /usr/bin/python3 -B -I",
        "plan_command S6.realnic-unit /usr/bin/env -i",
        "plan_command S6.realnic-static /usr/bin/env -i",
        "plan_command S6.veth-hermetic /usr/bin/env -i",
        "plan_command S6.veth-static /usr/bin/env -i",
        "plan_command S6.routed-hermetic /usr/bin/env -i",
        "plan_command S6.routed-static /usr/bin/env -i",
        "plan_command S7 /usr/bin/shellcheck --norc --shell=bash --",
        "plan_command S8 shell-builtin noclobber-write",
    )
    run_gate_order = (
        'checkout --detach "${INTEGRATION_COMMIT}"',
        "require_staged_content || fail 'staged-content'",
        "run_step S6 /bin/bash -n",
        "run_step S6.realnic /usr/bin/python3 -B -I",
        "run_step S6.realnic-unit",
        "run_step S6.realnic-static",
        "run_step S6.veth-hermetic",
        "run_step S6.veth-static",
        "run_step S6.routed-hermetic",
        "run_step S6.routed-static",
        "run_step S7 /usr/bin/shellcheck --norc --shell=bash --",
        "require_staged_content || fail 'staged-content-postcheck'",
        "require_physical_interface_lock || fail 'physical-interface-lock-drift'",
        "require_legacy_retirement_reservation || fail 'legacy-retirement-reservation-drift'",
        "require_module_lease_lock || fail 'module-lease-lock-drift'",
        "write_binding_marker || fail 'binding-marker'",
    )
    ordered(render_plan, plan_gate_order, "planned staged-source gates")
    ordered(run_stage, run_gate_order, "mandatory staged-source gates")
    gate_labels = (
        "S6",
        "S6.realnic",
        "S6.realnic-unit",
        "S6.realnic-static",
        "S6.veth-hermetic",
        "S6.veth-static",
        "S6.routed-hermetic",
        "S6.routed-static",
        "S7",
    )
    for label in gate_labels:
        if render_plan.count(f"plan_command {label} ") != 1:
            fail(f"stager plan has zero or multiple mandatory {label} gates")
        if run_stage.count(f"run_step {label} ") != 1:
            fail(f"stager run has zero or multiple mandatory {label} gates")
    gate_argv_contracts = (
        (
            "S6.veth-hermetic",
            "S6.veth-static",
            ('"${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}"',),
        ),
        (
            "S6.veth-static",
            "S6.routed-hermetic",
            (
                '"${EXPECTED_SOURCE}/${VETH_STATIC_PATH}"',
                '"${EXPECTED_SOURCE}/${ROOT_VETH_PATH}"',
                '"${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}"',
                '"${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}"',
            ),
        ),
        (
            "S6.routed-hermetic",
            "S6.routed-static",
            ('"${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}"',),
        ),
        (
            "S6.routed-static",
            "S7",
            (
                '"${EXPECTED_SOURCE}/${ROUTED_STATIC_PATH}"',
                '"${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}"',
                '"${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}"',
            ),
        ),
    )
    for name, body, command in (
        ("plan", render_plan, "plan_command"),
        ("run", run_stage, "run_step"),
    ):
        for label, next_label, expected_paths in gate_argv_contracts:
            gate_body = body[
                body.index(f"{command} {label} ") : body.index(
                    f"{command} {next_label} "
                )
            ]
            ordered(gate_body, expected_paths, f"{name} {label} argv")
    shellcheck_paths = (
        '"${EXPECTED_SOURCE}/${ROOT_MATRIX_PATH}"',
        '"${EXPECTED_SOURCE}/${HERMETIC_PATH}"',
        '"${EXPECTED_SOURCE}/${PREPARE_PATH}"',
        '"${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_PATH}"',
        '"${EXPECTED_SOURCE}/${ROOT_FRESH_PATH}"',
        '"${EXPECTED_SOURCE}/${FRESH_HERMETIC_PATH}"',
        '"${EXPECTED_SOURCE}/${PROVISION_PATH}"',
        '"${EXPECTED_SOURCE}/${ROOT_VETH_PATH}"',
        '"${EXPECTED_SOURCE}/${VETH_HERMETIC_PATH}"',
        '"${EXPECTED_SOURCE}/${ROUTED_SEAM_PATH}"',
        '"${EXPECTED_SOURCE}/${ROUTED_ROOT_PATH}"',
        '"${EXPECTED_SOURCE}/${ROUTED_HERMETIC_PATH}"',
    )
    plan_shellcheck = render_plan[
        render_plan.index("plan_command S7 ") : render_plan.index("plan_command S8 ")
    ]
    run_shellcheck = run_stage[
        run_stage.index("run_step S7 ") : run_stage.index(
            "require_staged_content || fail 'staged-content-postcheck'"
        )
    ]
    for name, body in (("plan", plan_shellcheck), ("run", run_shellcheck)):
        ordered(body, shellcheck_paths, f"{name} S7 shellcheck argv")
        for path in shellcheck_paths:
            if body.count(path) != 1:
                fail(f"{name} S7 shellcheck does not bind every shell path exactly once")
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
