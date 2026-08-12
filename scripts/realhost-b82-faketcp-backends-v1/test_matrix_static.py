#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
DIR = ROOT / "scripts" / "realhost-b82-faketcp-backends-v1"
MATRIX = DIR / "matrix.py"
ROOT_CELL = DIR / "root-cell.sh"
NETNS_CELL = DIR / "root-netns-cell.sh"
TCP_DROP_DIAGNOSTIC = DIR / "diagnose-retained-tcp-drop.sh"
README = DIR / "README.md"
CONFIG_GO = ROOT / "internal" / "config" / "config.go"
PLAN_SOURCE = "/var/tmp/wg-mix-ebpf-source-stages/abcdef12/source"
PLAN_COMMIT = "1" * 40
RUN_PARENT = "/var/tmp/wg-mix-ebpf-faketcp-backends-v1"
OLD_RUN_PARENT = "/run/wg-mix-ebpf-faketcp-backends-v1"


class StaticMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = MATRIX.read_text(encoding="utf-8")
        cls.root_cell = ROOT_CELL.read_text(encoding="utf-8")
        cls.netns = NETNS_CELL.read_text(encoding="utf-8")
        cls.tcp_drop_diagnostic = TCP_DROP_DIAGNOSTIC.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")
        cls.config_go = CONFIG_GO.read_text(encoding="utf-8")

    def test_sources_parse(self) -> None:
        ast.parse(self.matrix, filename=str(MATRIX))
        for path in (ROOT_CELL, NETNS_CELL, TCP_DROP_DIAGNOSTIC):
            completed = subprocess.run(
                ["/bin/bash", "-n", str(path)], text=True, capture_output=True
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        combined = self.matrix + self.root_cell + self.netns + self.readme
        self.assertNotIn(OLD_RUN_PARENT, combined)
        self.assertIn(f'RUN_PARENT = pathlib.Path("{RUN_PARENT}")', self.matrix)
        self.assertEqual(
            self.root_cell.count(f"readonly RUN_PARENT='{RUN_PARENT}'"), 1
        )
        self.assertEqual(self.netns.count(f"readonly RUN_PARENT='{RUN_PARENT}'"), 1)
        for required in (
            "RUN_PARENT.mkdir(mode=0o700, parents=False, exist_ok=False)",
            "persistent run parent must be root:root mode 0700",
            "matrix_root.mkdir(mode=0o700, parents=False, exist_ok=False)",
        ):
            self.assertIn(required, self.matrix)
        self.assertIn("validate_run_parent || fail run-parent-identity 79", self.root_cell)
        self.assertIn("'0:0:700:directory'", self.root_cell)
        self.assertIn(f"`{RUN_PARENT}/<run-id>`", self.readme)

    def test_writable_go_build_state_is_outside_run_tmpfs(self) -> None:
        combined = self.root_cell + self.netns
        self.assertIn(
            'readonly BUILD_CACHE_ROOT="${EVIDENCE_ROOT}/build-cache"',
            self.root_cell,
        )
        self.assertIn(
            'readonly BUILD_CACHE_ROOT="${ROOT}/build-cache"', self.netns
        )
        self.assertIn('readonly GO_MOD_CACHE="${STAGE_ROOT}/go-mod-cache"', combined)
        for forbidden in (
            'GO_CACHE="${STAGE_ROOT}/go-cache"',
            'GO_PATH="${STAGE_ROOT}/go-path"',
            'GO_TMP="${STAGE_ROOT}/go-tmp"',
            "stage_caches=",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn("build_caches=%s,%s,%s stage_module_cache=%s", self.root_cell)
        self.assertIn(
            'mkdir --mode=0700 -- "${GO_CACHE}" "${GO_PATH}" "${GO_TMP}"',
            self.root_cell,
        )

    def run_plan(self, release: str) -> dict[str, object]:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(MATRIX),
                "plan",
                "--source",
                PLAN_SOURCE,
                "--commit",
                PLAN_COMMIT,
                "--kernel-release",
                release,
                "--matrix-id",
                "1234abcd",
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_matrix_has_twelve_classified_cells(self) -> None:
        plan = self.run_plan("7.0.0-test")
        cells = plan["cells"]
        self.assertEqual(len(cells), 12)
        self.assertEqual({cell["wg_count"] for cell in cells}, {1, 2, 4})
        self.assertEqual(
            {cell["attachment_backend"] for cell in cells}, {"tcx", "classic_tc"}
        )
        self.assertEqual(
            {cell["checksum_backend"] for cell in cells}, {"kfunc", "kprobe"}
        )
        self.assertEqual({cell["xor"] for cell in cells}, {"none", "prefix", "full"})
        self.assertEqual({cell["gso"] for cell in cells}, {"off", "on"})
        self.assertTrue(all(cell["disposition"] == "RUN" for cell in cells))
        self.assertTrue(all("root-cell.sh" in cell["argv"][2] for cell in cells))
        self.assertEqual(len({cell["run_id"] for cell in cells}), 12)

    def test_linux_515_classification_is_pre_mutation(self) -> None:
        plan = self.run_plan("5.15.0-test")
        cells = plan["cells"]
        for cell in cells:
            if cell["attachment_backend"] == "tcx":
                self.assertEqual(cell["disposition"], "SKIP_UNSUPPORTED")
            elif cell["checksum_backend"] == "kfunc":
                self.assertEqual(cell["disposition"], "REJECT_UNSUPPORTED")
            else:
                self.assertEqual(cell["disposition"], "RUN")

    def test_root_cell_separates_audit_from_netns_driver(self) -> None:
        for required in (
            "source-status-drift",
            "source_tree_digest",
            "verify_source_immutable",
            "module_sha256=",
            "capture_diagnostics",
            "FULL_LOG_BEGIN",
            "FAILURE_RESOURCES_RETAINED",
            '"${CELL_DRIVER}" run',
            '"${CELL_DRIVER}" restore',
        ):
            self.assertIn(required, self.root_cell)
        self.assertNotIn("ip netns add", self.root_cell)
        self.assertNotIn("wg genkey", self.root_cell)

    def test_netns_driver_is_real_multi_wg_and_isolation_gate(self) -> None:
        for required in (
            'for ((index=0; index<WG_COUNT; index++))',
            'link add "wg${index}" type wireguard',
            "log_command_private_key_stdin()",
            "private_key_value_to_pipe()",
            "private-key /dev/stdin",
            "stdin=ephemeral-private-key-pipe",
            '(private_key_value_to_pipe "${private_key}") |',
            '(unset private_key; "$@")',
            'key_a="$(wg genkey)"; key_b="$(wg genkey)"',
            'unset key_a key_b; exit "${rc}"',
            'ping -I "wg${index}"',
            "iperf3 -c",
            "tcp_server_listening()",
            "run_iperf_for_wireguard()",
            "--connect-timeout 3000",
            "--snd-timeout 3000",
            "capture_iperf_failure_state",
            "configure_segmentation_profile()",
            "tx off tso off gso off gro off",
            "tx on tso on gso on gro on",
            "segmentation profile mismatch",
            "error: missing required command:",
            "same-tuple-router-test",
            "key_size=32",
            "reserved_zero=1",
            "expected=set(range(1,count+1))",
            "raw_wireguard_udp=0",
            "status-a-recovered",
            "kill -KILL",
        ):
            self.assertIn(required, self.netns)
        self.assertEqual(self.netns.count("private-key /dev/stdin"), 2)
        self.assertNotIn('private-key "${key_', self.netns)
        self.assertNotRegex(self.netns, re.compile(r"iperf3 .* -B "))
        self.assertNotIn("IPERF_PID=$!; sleep 0.4", self.netns)
        self.assertNotRegex(self.netns, re.compile(r"ethtool -K .* rx (?:on|off)"))
        self.assertNotIn("private-key ${key_", self.netns)
        self.assertNotIn('log_command "key-remove-', self.netns)
        self.assertNotIn('wg genkey >', self.netns)
        self.assertNotIn('${ROOT}/key-a-', self.netns)
        self.assertNotIn('${ROOT}/key-b-', self.netns)
        self.assertNotRegex(
            self.netns,
            re.compile(r"printf.*(?:key_a|key_b|key_path).*operations\\.log"),
        )

    def test_both_checksum_backends_verifier_sweep_before_network_mutation(self) -> None:
        sweep_command = (
            'log_command faketcp-verifier-sweep /usr/bin/timeout --signal=TERM'
        )
        self.assertEqual(self.netns.count(sweep_command), 1)
        self.assertIn(
            "verifier_mode='--faketcp'",
            self.netns,
        )
        self.assertIn("verifier_mode='--faketcp-legacy-515'", self.netns)
        self.assertIn(
            '"${BIN}" bpf-load-test "${verifier_mode}" \\\n'
            '  --object "${SELECTED_OBJECT}" --json',
            self.netns,
        )

        sweep = self.netns.index(sweep_command)

        # Both the newly-owned and pre-existing module identity paths finish
        # before the sweep. Endpoint state and every network mutation begin
        # only after it has passed.
        self.assertLess(
            self.netns.index('>"${ROOT}/module-preexisting.v1"'), sweep
        )
        for network_mutation in (
            'mkdir --mode=0700 -- "${ENDPOINT_A}"',
            'log_command netns-a ip netns add "${NSA}"',
            'link add "wg${index}" type wireguard',
            'log_command addr-a ip -n "${NSA}" address add',
            'log_command route-a ip -n "${NSA}" route add',
            'start_daemon a',
        ):
            self.assertLess(sweep, self.netns.index(network_mutation))

        self.assertLess(
            self.netns.index("verifier_mode='--faketcp-legacy-515'"),
            sweep,
        )

    def test_private_key_exec_boundary_uses_anonymous_pipe(self) -> None:
        functions = self.netns[
            self.netns.index("private_key_value_to_pipe() {") :
            self.netns.index("\nmodule_name() {")
        ]
        private_key_a = b"A" * 43 + b"="
        private_key_b = b"B" * 43 + b"="

        with tempfile.TemporaryDirectory() as raw:
            temporary = pathlib.Path(raw)
            evidence = temporary / "evidence"
            evidence.mkdir()
            old_key_a_path = temporary / "key-a-0"
            old_key_b_path = temporary / "key-b-0"
            capture_path = temporary / "capture.json"
            status_path = temporary / "status"

            consumer = temporary / "consumer.py"
            consumer.write_text(
                textwrap.dedent(
                    """\
                    import hashlib
                    import json
                    import os
                    import pathlib
                    import stat
                    import sys

                    source = sys.argv[sys.argv.index("private-key") + 1]
                    with open(source, "rb") as stream:
                        stdin_is_fifo = stat.S_ISFIFO(os.fstat(stream.fileno()).st_mode)
                        payload = stream.read()
                    descriptors = []
                    for name in os.listdir("/dev/fd"):
                        if not name.isdigit():
                            continue
                        try:
                            metadata = os.fstat(int(name))
                        except OSError:
                            continue
                        descriptors.append({
                            "device": metadata.st_dev,
                            "inode": metadata.st_ino,
                            "regular": stat.S_ISREG(metadata.st_mode),
                        })
                    record = {
                        "argv": sys.argv,
                        "stdin_is_fifo": stdin_is_fifo,
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "payload_size": len(payload),
                        "descriptors": descriptors,
                    }
                    pathlib.Path(os.environ["CAPTURE_PATH"]).write_text(
                        json.dumps(record, sort_keys=True), encoding="utf-8"
                    )
                    raise SystemExit(23)
                    """
                ),
                encoding="utf-8",
            )

            harness = "\n".join(
                (
                    "set -Eeuo pipefail",
                    functions,
                    f"EVIDENCE={shlex.quote(str(evidence))}",
                    f"key_a={shlex.quote(private_key_a.decode())}",
                    f"key_b={shlex.quote(private_key_b.decode())}",
                    "status=0",
                    "if log_command_private_key_stdin wg-set-test "
                    '"${key_a}" '
                    f"{shlex.quote(sys.executable)} "
                    f"{shlex.quote(str(consumer))} set wg0 private-key /dev/stdin; then",
                    "  status=0",
                    "else",
                    "  status=$?",
                    "  unset key_a key_b",
                    "fi",
                    f"printf '%s\\n' \"${{status}}\" >{shlex.quote(str(status_path))}",
                )
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", harness],
                text=True,
                capture_output=True,
                env={
                    "PATH": f"{temporary}:/usr/bin:/bin",
                    "LC_ALL": "C",
                    "CAPTURE_PATH": str(capture_path),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(status_path.read_text(encoding="ascii").strip(), "23")
            self.assertFalse(old_key_a_path.exists())
            self.assertFalse(old_key_b_path.exists())
            record = json.loads(capture_path.read_text(encoding="utf-8"))
            self.assertTrue(record["stdin_is_fifo"])
            expected_payload = private_key_a + b"\n"
            self.assertEqual(record["payload_size"], len(expected_payload))
            self.assertEqual(
                record["payload_sha256"], hashlib.sha256(expected_payload).hexdigest()
            )
            logs = b"".join(path.read_bytes() for path in evidence.iterdir())
            for private_key in (private_key_a, private_key_b):
                self.assertNotIn(private_key, logs)
                self.assertNotIn(private_key, completed.stdout.encode())
                self.assertNotIn(private_key, completed.stderr.encode())

    def test_legacy_key_restore_preflights_all_entries_before_exact_unlink(
        self,
    ) -> None:
        cleanup_function = self.netns[
            self.netns.index("remove_legacy_private_key_residue() {") :
            self.netns.index("\nrestore_resources() {")
        ]
        valid_key = "C" * 43 + "=\n"

        with tempfile.TemporaryDirectory() as raw:
            temporary = pathlib.Path(raw)
            root = temporary / "run"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)

            stat_stub = temporary / "stat"
            stat_stub.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import os
                    import stat
                    import sys
                    metadata = os.lstat(sys.argv[-1])
                    if sys.argv[1:3] == ["-Lc", "%d"]:
                        print(metadata.st_dev)
                        raise SystemExit(0)
                    kind = "regular file" if stat.S_ISREG(metadata.st_mode) else "other"
                    print(f"0:0:{stat.S_IMODE(metadata.st_mode):o}:{metadata.st_nlink}:{metadata.st_size}:{kind}")
                    """
                ),
                encoding="utf-8",
            )
            stat_stub.chmod(0o700)
            readlink_stub = temporary / "readlink"
            readlink_stub.write_text(
                "#!/bin/sh\neval 'last=${'$#'}'\nprintf '%s\\n' \"${last}\"\n",
                encoding="ascii",
            )
            readlink_stub.chmod(0o700)
            find_stub = temporary / "find"
            find_stub.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "for path in sorted(pathlib.Path(sys.argv[1]).iterdir()):\n"
                "    if path.name.startswith('key-'):\n"
                "        print(path.name)\n",
                encoding="ascii",
            )
            find_stub.chmod(0o700)

            def run_cleanup() -> subprocess.CompletedProcess[str]:
                harness = "\n".join(
                    (
                        "set -Eeuo pipefail",
                        cleanup_function,
                        f"ROOT={shlex.quote(str(root))}",
                        f"EVIDENCE={shlex.quote(str(evidence))}",
                        "WG_COUNT=1",
                        "log_command() {",
                        "  local phase=$1; shift",
                        "  printf 'phase=%s\\n' \"${phase}\" >>\"${EVIDENCE}/operations.log\"",
                        "  [[ $1 == /usr/bin/unlink && $2 == -- && $# -eq 3 ]] || return 79",
                        "  /bin/rm -- \"$3\"",
                        "}",
                        "status=0",
                        "if remove_legacy_private_key_residue; then :; else status=$?; fi",
                        "printf 'status=%s\\n' \"${status}\"",
                    )
                )
                return subprocess.run(
                    ["/bin/bash", "-c", harness],
                    text=True,
                    capture_output=True,
                    env={
                        "PATH": f"{temporary}:/usr/bin:/bin",
                        "LC_ALL": "C",
                    },
                )

            legacy_b = root / "key-b-0"
            legacy_b.write_text(valid_key, encoding="ascii")
            legacy_b.chmod(0o600)
            completed = run_cleanup()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "status=0")
            self.assertFalse(legacy_b.exists())

            legacy_a = root / "key-a-0"
            unexpected = root / "key-c-0"
            legacy_a.write_text(valid_key, encoding="ascii")
            legacy_a.chmod(0o600)
            unexpected.write_text(valid_key, encoding="ascii")
            unexpected.chmod(0o600)
            completed = run_cleanup()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "status=79")
            self.assertTrue(legacy_a.exists(), "preflight failure removed allowed key")
            self.assertTrue(unexpected.exists(), "preflight failure removed foreign key")

            unexpected.unlink()
            wrong_size_b = root / "key-b-0"
            wrong_size_b.write_text("D" * 43 + "\n", encoding="ascii")
            wrong_size_b.chmod(0o600)
            completed = run_cleanup()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "status=79")
            self.assertTrue(legacy_a.exists(), "full preflight was not atomic")
            self.assertTrue(wrong_size_b.exists(), "wrong-size residue was removed")

            audit = (evidence / "operations.log").read_bytes()
            self.assertNotIn(valid_key.strip().encode(), audit)
            self.assertNotIn(("D" * 43).encode(), audit)
            self.assertIn(b"phase=restore-legacy-key-b-0", audit)
            self.assertIn(b"unexpected-key-entry", audit)
            self.assertIn(b"metadata-failed label=key-b-0", audit)
            self.assertNotIn('$(<"${path}")', cleanup_function)
            self.assertNotIn('for path in "${ROOT}"/key-*', cleanup_function)

    def test_xor_secret_restore_preflights_both_before_exact_unlink(self) -> None:
        cleanup_function = self.netns[
            self.netns.index("remove_xor_secret_residue() {") :
            self.netns.index("\nrestore_resources() {")
        ]
        secret_a = b"xor-a-secret-not-for-logs-" + b"A" * 38 + b"\n"
        secret_b = b"xor-b-secret-not-for-logs-" + b"B" * 38 + b"\n"
        self.assertEqual(len(secret_a), 65)
        self.assertEqual(len(secret_b), 65)

        with tempfile.TemporaryDirectory() as raw:
            temporary = pathlib.Path(raw)
            root = temporary / "run"
            evidence = root / "evidence"
            run_a = root / "endpoint-a" / "run"
            run_b = root / "endpoint-b" / "run"
            for directory in (evidence, run_a, run_b):
                directory.mkdir(parents=True, exist_ok=True)
                directory.chmod(0o700)

            stat_stub = temporary / "stat"
            stat_stub.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import os
                    import stat
                    import sys
                    metadata = os.lstat(sys.argv[-1])
                    fmt = sys.argv[2]
                    if fmt == "%d":
                        print(metadata.st_dev)
                    elif fmt == "%u:%g:%a:%F":
                        kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "regular file"
                        print(f"0:0:{stat.S_IMODE(metadata.st_mode):o}:{kind}")
                    else:
                        kind = "regular file" if stat.S_ISREG(metadata.st_mode) else "other"
                        print(f"0:0:{stat.S_IMODE(metadata.st_mode):o}:{metadata.st_nlink}:{metadata.st_size}:{kind}")
                    """
                ),
                encoding="utf-8",
            )
            stat_stub.chmod(0o700)
            readlink_stub = temporary / "readlink"
            readlink_stub.write_text(
                "#!/bin/sh\neval 'last=${'$#'}'\nprintf '%s\\n' \"${last}\"\n",
                encoding="ascii",
            )
            readlink_stub.chmod(0o700)

            def run_cleanup() -> subprocess.CompletedProcess[str]:
                harness = "\n".join(
                    (
                        "set -Eeuo pipefail",
                        cleanup_function,
                        f"EVIDENCE={shlex.quote(str(evidence))}",
                        f"RUN_A={shlex.quote(str(run_a))}",
                        f"RUN_B={shlex.quote(str(run_b))}",
                        "XOR_MODE=full",
                        "log_command() {",
                        "  local phase=$1; shift",
                        "  printf 'phase=%s\\n' \"${phase}\" >>\"${EVIDENCE}/operations.log\"",
                        "  [[ $1 == /usr/bin/unlink && $2 == -- && $# -eq 3 ]] || return 79",
                        "  /bin/rm -- \"$3\"",
                        "}",
                        "status=0",
                        "if remove_xor_secret_residue; then :; else status=$?; fi",
                        "printf 'status=%s\\n' \"${status}\"",
                    )
                )
                return subprocess.run(
                    ["/bin/bash", "-c", harness],
                    text=True,
                    capture_output=True,
                    env={"PATH": f"{temporary}:/usr/bin:/bin", "LC_ALL": "C"},
                )

            path_a = run_a / "xor.key"
            path_b = run_b / "xor.key"
            path_a.write_bytes(secret_a)
            path_b.write_bytes(secret_b)
            path_a.chmod(0o600)
            path_b.chmod(0o600)
            completed = run_cleanup()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "status=0")
            self.assertFalse(path_a.exists())
            self.assertFalse(path_b.exists())

            path_a.write_bytes(secret_a)
            path_b.write_bytes(secret_b[:-1])
            path_a.chmod(0o600)
            path_b.chmod(0o600)
            completed = run_cleanup()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "status=79")
            self.assertTrue(path_a.exists(), "full preflight removed endpoint A")
            self.assertTrue(path_b.exists(), "wrong-size endpoint B was removed")

            audit = (evidence / "operations.log").read_bytes()
            self.assertNotIn(secret_a.rstrip(), audit)
            self.assertNotIn(secret_b.rstrip(), audit)
            self.assertIn(b"phase=restore-xor-secret-endpoint-a", audit)
            self.assertIn(b"phase=restore-xor-secret-endpoint-b", audit)
            self.assertIn(b"metadata-failed label=endpoint-b", audit)
            self.assertNotIn('$(<"${path}")', cleanup_function)

    def test_multi_wg_quotas_are_explicit_and_below_shared_limits(self) -> None:
        shell_names = {
            "session_capacity": "FAKETCP_SESSION_CAPACITY",
            "max_half_open_sessions": "FAKETCP_MAX_HALF_OPEN_SESSIONS",
            "syn_source_ledger_capacity": "FAKETCP_SYN_SOURCE_LEDGER_CAPACITY",
            "max_pending_flows": "FAKETCP_MAX_PENDING_FLOWS",
            "max_pending_bytes": "FAKETCP_MAX_PENDING_BYTES",
        }
        go_names = {
            "session_capacity": "MaxFakeTCPSessions",
            "max_half_open_sessions": "MaxFakeTCPHalfOpenSessions",
            "syn_source_ledger_capacity": "MaxFakeTCPSYNSourceLedger",
            "max_pending_flows": "MaxFakeTCPPendingFlows",
            "max_pending_bytes": "MaxFakeTCPPendingBytes",
        }

        def shell_value(name: str) -> int:
            match = re.search(rf"^readonly {name}=([0-9]+)$", self.netns, re.M)
            self.assertIsNotNone(match, name)
            return int(match.group(1))

        def go_value(name: str) -> int:
            match = re.search(rf"^\s*{name}\s*=\s*([^\n]+)$", self.config_go, re.M)
            self.assertIsNotNone(match, name)
            expression = match.group(1).strip()
            if expression.isdigit():
                return int(expression)
            shifted = re.fullmatch(r"([0-9]+)\s*<<\s*([0-9]+)", expression)
            self.assertIsNotNone(shifted, expression)
            return int(shifted.group(1)) << int(shifted.group(2))

        quotas = {field: shell_value(name) for field, name in shell_names.items()}
        limits = {field: go_value(name) for field, name in go_names.items()}
        for field, value in quotas.items():
            self.assertLess(4 * value, limits[field], field)
            self.assertIn(f"        {field}: %s", self.netns)
            self.assertIn(f'"${{{shell_names[field]}}}"', self.netns)

        half_per_source = shell_value("FAKETCP_MAX_HALF_OPEN_PER_SOURCE")
        syn_burst = shell_value("FAKETCP_SYN_BURST")
        syn_burst_per_source = shell_value("FAKETCP_SYN_BURST_PER_SOURCE")
        pending_packets = shell_value("FAKETCP_MAX_PENDING_PACKETS_PER_FLOW")
        self.assertLess(quotas["max_half_open_sessions"], quotas["session_capacity"])
        self.assertLessEqual(half_per_source, quotas["max_half_open_sessions"])
        self.assertLessEqual(half_per_source, go_value("MaxFakeTCPHalfOpenPerSource"))
        self.assertLessEqual(syn_burst_per_source, syn_burst)
        self.assertLessEqual(syn_burst, quotas["max_half_open_sessions"])
        self.assertLessEqual(syn_burst, go_value("MaxFakeTCPSYNBurst"))
        self.assertLessEqual(quotas["max_pending_flows"], quotas["max_half_open_sessions"])
        self.assertGreaterEqual(
            quotas["syn_source_ledger_capacity"], quotas["max_half_open_sessions"]
        )
        self.assertLessEqual(
            pending_packets, go_value("MaxFakeTCPPendingPacketsPerFlow")
        )
        for field in (
            "max_half_open_per_source",
            "syn_rate_interval",
            "syn_burst",
            "syn_burst_per_source",
            "syn_source_ledger_ttl",
            "max_pending_packets_per_flow",
            "handshake_timeout",
            "keepalive_interval",
            "idle_timeout",
        ):
            self.assertIn(f"        {field}: %s", self.netns)

    def test_role_offsets_have_one_authoritative_calculation(self) -> None:
        self.assertNotIn("role_port_offset", self.netns)
        self.assertNotIn("role_mark_offset", self.netns)
        self.assertEqual(self.netns.count("wg_listen_port()"), 1)
        self.assertEqual(self.netns.count("wg_fwmark()"), 1)
        for call in (
            'wg_listen_port "${role}" "${index}"',
            'wg_fwmark "${role}" "${index}"',
            'wg_listen_port a "${index}"',
            'wg_listen_port b "${index}"',
            'wg_fwmark a "${index}"',
            'wg_fwmark b "${index}"',
        ):
            self.assertIn(call, self.netns)

    def test_matrix_root_cell_netns_mode_and_argv_close(self) -> None:
        plan = self.run_plan("7.0.0-test")
        for cell in plan["cells"]:
            matrix_argv = cell["argv"]
            self.assertEqual(matrix_argv[:2], ["/bin/bash", "-p"])
            self.assertEqual(matrix_argv[3], "plan")
            completed = subprocess.run(
                ["/bin/bash", "-p", str(ROOT_CELL), *matrix_argv[3:]],
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            lines = completed.stdout.splitlines()
            run_line = next(line for line in lines if line.startswith("RUN argv="))
            restore_line = next(line for line in lines if line.startswith("RESTORE argv="))
            run_argv = shlex.split(run_line.removeprefix("RUN argv="))
            restore_argv = shlex.split(restore_line.removeprefix("RESTORE argv="))
            self.assertEqual(run_argv[:3], ["/bin/bash", "-p", f"{PLAN_SOURCE}/{NETNS_CELL.relative_to(ROOT)}"])
            self.assertEqual(run_argv[3], "run")
            self.assertEqual(restore_argv[3], "restore")
            pairs = dict(zip(run_argv[4::2], run_argv[5::2], strict=True))
            self.assertEqual(pairs["--source"], PLAN_SOURCE)
            self.assertEqual(pairs["--commit"], PLAN_COMMIT)
            self.assertEqual(pairs["--run-id"], cell["run_id"])
            self.assertEqual(pairs["--label"], cell["label"])
            self.assertEqual(pairs["--wg-count"], str(cell["wg_count"]))
            self.assertEqual(pairs["--attachment-backend"], cell["attachment_backend"])
            self.assertEqual(pairs["--checksum-backend"], cell["checksum_backend"])
            self.assertEqual(pairs["--xor"], cell["xor"])
            self.assertEqual(pairs["--gso"], cell["gso"])
            object_name = (
                "wg_mix_faketcp_experimental.o"
                if cell["artifact"] == "modern"
                else "wg_mix_faketcp_legacy_515.o"
            )
            artifact_root = f"{RUN_PARENT}/{cell['run_id']}/artifacts"
            self.assertEqual(pairs["--binary"], f"{artifact_root}/wg-mix-ebpf")
            self.assertEqual(
                pairs["--baseline-object"], f"{artifact_root}/wg_mix_tc.o"
            )
            self.assertEqual(
                pairs["--modern-object"],
                f"{artifact_root}/wg_mix_faketcp_experimental.o",
            )
            self.assertEqual(
                pairs["--legacy-object"],
                f"{artifact_root}/wg_mix_faketcp_legacy_515.o",
            )
            self.assertEqual(
                pairs["--selected-object"], f"{artifact_root}/{object_name}"
            )
            module_dir = (
                "faketcp_checksum_kmod"
                if cell["checksum_backend"] == "kfunc"
                else "faketcp_checksum_kprobe_kmod"
            )
            module_name = (
                "wg_mix_faketcp_checksum.ko"
                if cell["checksum_backend"] == "kfunc"
                else "wg_mix_faketcp_checksum_kprobe.ko"
            )
            self.assertEqual(
                pairs["--module-object"],
                f"{artifact_root}/{module_dir}/{module_name}",
            )
            self.assertEqual(
                pairs["--module-lease-id"], f"abcdef12-{cell['run_id']}"
            )
        self.assertIn('"${CELL_DRIVER}" restore', self.root_cell)
        self.assertIn("args.mode,", self.matrix)

    def test_netns_run_initialization_reaches_first_root_gate_unprivileged(self) -> None:
        # Execute the real driver, not an extracted/synthetic shell fragment.  A
        # fresh absent run root makes the first ownership gate fail closed with
        # rc=79 before any privileged or mutating command can run, even when
        # this test itself happens to be launched by root.
        for _ in range(32):
            run_id = secrets.token_hex(4)
            run_root = pathlib.Path(RUN_PARENT) / run_id
            if not run_root.exists():
                break
        else:
            self.fail("could not select an absent FakeTCP matrix run root")

        artifact_root = run_root / "artifacts"
        completed = subprocess.run(
            [
                "/bin/bash",
                "-p",
                str(NETNS_CELL),
                "run",
                "--source",
                PLAN_SOURCE,
                "--commit",
                PLAN_COMMIT,
                "--run-id",
                run_id,
                "--label",
                "dynamic-init-gate",
                "--wg-count",
                "1",
                "--attachment-backend",
                "tcx",
                "--checksum-backend",
                "kfunc",
                "--binary",
                str(artifact_root / "wg-mix-ebpf"),
                "--baseline-object",
                str(artifact_root / "wg_mix_tc.o"),
                "--modern-object",
                str(artifact_root / "wg_mix_faketcp_experimental.o"),
                "--legacy-object",
                str(artifact_root / "wg_mix_faketcp_legacy_515.o"),
                "--selected-object",
                str(artifact_root / "wg_mix_faketcp_experimental.o"),
                "--module-object",
                str(
                    artifact_root
                    / "faketcp_checksum_kmod"
                    / "wg_mix_faketcp_checksum.ko"
                ),
                "--module-lease-id",
                f"abcdef12-{run_id}",
                "--xor",
                "none",
                "--gso",
                "off",
            ],
            text=True,
            capture_output=True,
            cwd=ROOT,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        self.assertEqual(
            completed.returncode,
            79,
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        self.assertFalse(run_root.exists(), "pre-root-gate execution mutated run root")

    def test_endpoint_enters_netns_before_private_mount_namespace(self) -> None:
        endpoint = self.netns[
            self.netns.index("endpoint_child() {") :
            self.netns.index('\n\nif [[ "${1-}" == endpoint')
        ]
        start = self.netns[
            self.netns.index("start_daemon() {") :
            self.netns.index("\n\nwait_active() {")
        ]
        ordered = start + "\n" + endpoint
        tokens = (
            'ip netns exec "${netns}"',
            "unshare --mount --propagation private",
            'mount --bind "${run}" "${SHARED_RUN}"',
            'mount -t bpf -o mode=0700 bpf /sys/fs/bpf',
            'exec env -i PATH="${SAFE_PATH}" LC_ALL=C',
        )
        positions = [ordered.index(token) for token in tokens]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(
            'expected_netns="$(stat -Lc \'%d:%i\' -- "${netns_target}")"',
            endpoint,
        )
        self.assertIn(
            'actual_netns="$(stat -Lc \'%d:%i\' -- /proc/self/ns/net)"',
            endpoint,
        )
        self.assertIn(
            '[[ "${actual_netns}" == "${expected_netns}" ]] || return 79',
            endpoint,
        )
        self.assertNotIn("ip netns exec", endpoint)

    def test_endpoint_launch_order_executes_unprivileged_with_stubs(self) -> None:
        endpoint_function = self.netns[
            self.netns.index("endpoint_child() {") :
            self.netns.index('\n\nif [[ "${1-}" == endpoint')
        ]
        start_function = self.netns[
            self.netns.index("start_daemon() {") :
            self.netns.index("\n\nwait_active() {")
        ]
        run_id = "1234abcd"

        with tempfile.TemporaryDirectory() as raw:
            temporary = pathlib.Path(raw)
            binary_dir = temporary / "bin"
            binary_dir.mkdir()
            events = temporary / "events.log"
            run_parent = temporary / "runs"
            root = run_parent / run_id
            endpoint = root / "endpoint-a"
            run = endpoint / "run"
            var = endpoint / "var"
            artifacts = root / "artifacts"
            evidence = root / "evidence"
            netns_parent = temporary / "netns"
            shared_run = temporary / "shared-run"
            shared_var = temporary / "shared-var"
            shared_gate = temporary / "shared-gate"
            for directory in (
                run,
                var,
                artifacts,
                evidence,
                netns_parent,
                shared_run,
                shared_var,
            ):
                directory.mkdir(parents=True, exist_ok=True)
                directory.chmod(0o700)
            (root / "owner.v1").write_text(
                f"wg-mix-ebpf-faketcp-backends-v1:{run_id}:test\n",
                encoding="ascii",
            )
            gate = endpoint / "maintenance.gate"
            gate.touch()
            gate.chmod(0o600)
            shared_gate.touch()
            (netns_parent / f"f{run_id}a").touch()

            def write_stub(name: str, body: str) -> pathlib.Path:
                path = binary_dir / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o700)
                return path

            quoted_events = shlex.quote(str(events))
            write_stub(
                "ip",
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    set -eu
                    [ "$1" = netns ] && [ "$2" = exec ] && [ "$3" = "f{run_id}a" ]
                    printf '%s\n' netns-exec >>{quoted_events}
                    shift 3
                    exec "$@"
                    """
                ),
            )
            write_stub(
                "unshare",
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    set -eu
                    [ "$1" = --mount ] && [ "$2" = --propagation ] && [ "$3" = private ]
                    printf '%s\n' unshare >>{quoted_events}
                    shift 3
                    exec "$@"
                    """
                ),
            )
            write_stub(
                "stat",
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    set -eu
                    format=$2
                    target=$4
                    case "$format:$target" in
                      '%d:%i:/proc/self/ns/net')
                        printf '%s\n' netns-verify >>{quoted_events}
                        printf '%s\n' '101:202'
                        ;;
                      '%d:%i:'*) printf '%s\n' '101:202' ;;
                      '%u:%g:%a:%F:'*) printf '%s\n' '0:0:700:directory' ;;
                      '%u:%g:%a:%h:'*) printf '%s\n' '0:0:600:1' ;;
                      *) exit 79 ;;
                    esac
                    """
                ),
            )
            write_stub(
                "mount",
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    set -eu
                    if [ "$1" = --bind ]; then
                      case "$2" in
                        {shlex.quote(str(run))}) event=bind-run ;;
                        {shlex.quote(str(var))}) event=bind-var ;;
                        {shlex.quote(str(gate))}) event=bind-gate ;;
                        *) exit 79 ;;
                      esac
                    elif [ "$*" = '-t bpf -o mode=0700 bpf /sys/fs/bpf' ]; then
                      event=mount-bpffs
                    else
                      exit 79
                    fi
                    printf '%s\n' "$event" >>{quoted_events}
                    """
                ),
            )
            write_stub(
                "env",
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    set -eu
                    [ "$1" = -i ]
                    shift
                    while [ "$#" -gt 0 ]; do
                      case "$1" in
                        *=*) export "$1"; shift ;;
                        *) break ;;
                      esac
                    done
                    printf '%s\n' daemon-env >>{quoted_events}
                    exec "$@"
                    """
                ),
            )
            daemon = artifacts / "wg-mix-ebpf"
            daemon.write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    printf 'daemon-exec pid=%s\n' "$$" >>{quoted_events}
                    """
                ),
                encoding="utf-8",
            )
            daemon.chmod(0o700)

            harness = temporary / "launch-harness.sh"
            harness.write_text(
                "\n".join(
                    (
                        "#!/bin/bash",
                        "set -Eeuo pipefail",
                        "validate_run_id() { [[ \"$1\" =~ ^[0-9a-f]{8}$ ]]; }",
                        f"SAFE_PATH={shlex.quote(str(binary_dir))}:/usr/bin:/bin",
                        f"RUN_PARENT={shlex.quote(str(run_parent))}",
                        f"NETNS_PARENT={shlex.quote(str(netns_parent))}",
                        f"SHARED_RUN={shlex.quote(str(shared_run))}",
                        f"SHARED_VAR={shlex.quote(str(shared_var))}",
                        f"SHARED_MAINTENANCE={shlex.quote(str(shared_gate))}",
                        endpoint_function,
                        'if [[ "${1-}" == endpoint ]]; then endpoint_child "$@"; exit $?; fi',
                        start_function,
                        f"SOURCE={shlex.quote(PLAN_SOURCE)}",
                        f"RUN_ID={run_id}",
                        f"ROOT={shlex.quote(str(root))}",
                        f"EVIDENCE={shlex.quote(str(evidence))}",
                        f"NSA=f{run_id}a",
                        f"NSB=f{run_id}b",
                        "DAEMON_A_PID=''",
                        "DAEMON_B_PID=''",
                        "start_daemon a",
                        'wait "${DAEMON_A_PID}"',
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                ["/bin/bash", "-p", str(harness)],
                text=True,
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            self.assertEqual(
                completed.returncode,
                0,
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            )
            observed = events.read_text(encoding="ascii").splitlines()
            self.assertEqual(
                [event.split()[0] for event in observed],
                [
                    "netns-exec",
                    "unshare",
                    "netns-verify",
                    "bind-run",
                    "bind-var",
                    "bind-gate",
                    "mount-bpffs",
                    "daemon-env",
                    "daemon-exec",
                ],
            )
            daemon_pid = (root / "daemon-a.pid").read_text(encoding="ascii").strip()
            self.assertEqual(observed[-1], f"daemon-exec pid={daemon_pid}")

    def test_nounset_dependent_assignments_are_sequenced(self) -> None:
        for required in (
            'readonly ROOT="${RUN_PARENT}/${RUN_ID}"\nreadonly EVIDENCE="${ROOT}/evidence"',
            'local role="$1" pid_file pid netns expected_inode actual_inode status\n'
            '  local process_state wait_status\n'
            '  pid_file="${ROOT}/daemon-${role}.pid"',
            'local role="$1" log_role pid netns\n  log_role="${role}"',
        ):
            self.assertIn(required, self.netns)
        self.assertNotRegex(
            self.netns,
            re.compile(r'readonly ROOT=.*\s+EVIDENCE="\$\{ROOT\}'),
        )
        self.assertNotRegex(
            self.netns,
            re.compile(r'local role="\$1"[^\n]*(?:pid_file|log_role)="[^\n]*\$\{role\}'),
        )

    def test_frozen_source_is_never_an_artifact_target(self) -> None:
        self.assertNotIn('make --no-print-directory -C "${SOURCE}" build\n', self.root_cell)
        self.assertNotIn('"${SOURCE}/bin/wg-mix-ebpf"', self.root_cell + self.netns)
        self.assertNotIn(
            '"${SOURCE}/build/wg_mix_faketcp_experimental.o"',
            self.root_cell + self.netns,
        )
        for required in (
            'readonly ARTIFACT_ROOT="${EVIDENCE_ROOT}/artifacts"',
            'BPF_OBJECT="${BASELINE_OBJECT}"',
            'FAKETCP_EXPERIMENTAL_BPF_OBJECT="${MODERN_OBJECT}"',
            'FAKETCP_LEGACY_515_BPF_OBJECT="${LEGACY_OBJECT}"',
            '-o "${BIN}" ./cmd/wg-mix-ebpf',
            'source=frozen-read-only',
            'verify_source_immutable',
        ):
            self.assertIn(required, self.root_cell)

    def test_kfunc_module_lease_is_stage_and_run_bound(self) -> None:
        self.assertIn(
            'readonly MODULE_LEASE_ID="${STAGE_ID}-${RUN_ID}"', self.root_cell
        )
        self.assertIn(
            '"${MODULE_LEASE_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{8}$', self.netns
        )
        self.assertIn('"lease_id=${MODULE_LEASE_ID}"', self.netns)
        self.assertNotIn('"lease_id=${RUN_ID}"', self.netns)
        self.assertIn('lease_id=%s\\n', self.netns)
        self.assertIn('MOD_BUILT_SRCVERSION="$(modinfo -F srcversion -- "${MOD_OBJECT}")"', self.netns)
        self.assertIn('"${MOD_SRCVERSION}" == "${MOD_BUILT_SRCVERSION}"', self.netns)
        self.assertIn("wg-mix-ebpf-faketcp-backends-preexisting-module-v1", self.netns)

    def test_tcpdump_owner_is_the_capture_process_not_a_timeout_wrapper(self) -> None:
        self.assertIn(
            'ip netns exec "${NSR}" tcpdump -U -nn -i any', self.netns
        )
        self.assertEqual(
            self.netns.count('$(readlink -e -- "$(command -v tcpdump)")'), 2
        )
        self.assertNotIn(
            'timeout --signal=INT --kill-after=5s 90 tcpdump', self.netns
        )

    def test_exact_generic_xdp_and_backend_fields_are_fixed(self) -> None:
        combined = self.root_cell + self.netns + self.readme
        for required in (
            "xdp=exact-generic",
            "xdp-generic-exact",
            "attachment_backend",
            "checksum_backend",
            "legacy_515",
            "classic_tc",
            "kprobe",
        ):
            self.assertIn(required, combined)
        self.assertNotIn("xdp-native", combined)
        self.assertNotIn("libxdp", self.netns)

    def test_failure_logs_are_not_suppressed_or_truncated(self) -> None:
        combined = self.root_cell + self.netns
        for forbidden in (
            "2>/dev/null",
            ">/dev/null",
            "tail -",
            "head -",
            "|| true",
            "rm -rf",
            "find -delete",
            "xargs rm",
            "rsync --delete",
            "eval ",
            "chroot",
            "nsenter --mount=/proc/1",
        ):
            self.assertNotIn(forbidden, combined)
        self.assertIn('>"${out}" 2>"${err}"', self.netns)
        self.assertIn("read_text(encoding=\"utf-8\", errors=\"replace\")", self.matrix)

    def test_no_remote_or_credential_transport(self) -> None:
        combined = self.matrix + self.root_cell + self.netns
        for forbidden in (
            "credientials/",
            "/usr/bin/ssh",
            "/usr/bin/scp",
            "47.116.202.155",
            "192.168.10.28",
            "docker",
            "podman",
            "sudo ",
        ):
            self.assertNotIn(forbidden, combined)

    def test_cleanup_targets_are_run_derived_and_evidence_is_retained(self) -> None:
        for required in (
            'NSA="f${RUN_ID}a"',
            'NSR="f${RUN_ID}r"',
            'NSB="f${RUN_ID}b"',
            "restore_resources",
            "module-owned.v1",
            "restored.v1",
            "wg-mix-ebpf-faketcp-${RUN_ID}-a",
            "wg-mix-ebpf-faketcp-${RUN_ID}-b",
        ):
            self.assertIn(required, self.netns)
        self.assertNotRegex(
            self.netns,
            re.compile(r'(?:rm|rmdir)\s+(?:-[^ ]+\s+)*"?\$\{ROOT\}"?'),
        )

    def test_plan_invalid_source_and_commit_are_rejected(self) -> None:
        for source, commit in (("/tmp/source", PLAN_COMMIT), (PLAN_SOURCE, "abcd")):
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(MATRIX),
                    "plan",
                    "--source",
                    source,
                    "--commit",
                    commit,
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(completed.returncode, 0)

    def test_static_checks_create_no_pyc(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = pathlib.Path(raw)
            completed = subprocess.run(
                [sys.executable, "-I", "-c", "import ast, pathlib; ast.parse(pathlib.Path(__import__('sys').argv[1]).read_text())", str(MATRIX)],
                text=True,
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                cwd=target,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(any(DIR.rglob("*.pyc")))
        self.assertFalse(any(path.name == "__pycache__" for path in DIR.rglob("*")))

    def test_retained_tcp_drop_diagnostic_is_retry_safe(self) -> None:
        diagnostic = self.tcp_drop_diagnostic
        for required in (
            '--attempt-id) ATTEMPT_ID="$2"',
            '"${ATTEMPT_ID}" =~ ^[0-9a-f]{8}$',
            'readonly OUTPUT_PREFIX="${EVIDENCE}/tcp-drop-${ATTEMPT_ID}"',
            'readonly SUMMARY="${OUTPUT_PREFIX}-diagnostic.summary.v2"',
            'local role="$1" output="$2"\n  local pid_file="${ROOT}/daemon-${role}.pid"',
            'timeout --signal=TERM --kill-after=2s 10s python3',
            'timeout=3,',
            'timeout --signal=TERM --kill-after=1s 5s "$@"',
            'wait_capture_ready pcap-a',
            'wait_capture_ready pcap-b',
            'wait_capture_ready pcap-underlay-a',
            "grep -Fq -- 'listening on '",
            'timeout --signal=TERM --kill-after=1s 1s ip netns exec',
            'tracepoint:skb:kfree_skb',
            'tracepoint:skb:consume_skb',
            'tracepoint:net:net_dev_queue',
            'tracepoint:net:net_dev_start_xmit',
            'tracepoint:net:net_dev_xmit',
            'phase=packet-trace',
        ):
            self.assertIn(required, diagnostic)
        self.assertNotRegex(
            diagnostic,
            re.compile(r'local role="\$1"[^\n]*pid_file="[^\n]*\$\{role\}'),
        )
        self.assertNotIn('${EVIDENCE}/tcp-drop-${phase}.log', diagnostic)
        self.assertIn("fresh eight-hex `--attempt-id`", self.readme)


if __name__ == "__main__":
    unittest.main()
