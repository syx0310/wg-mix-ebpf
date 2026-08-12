#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
DIR = ROOT / "scripts" / "realhost-b82-faketcp-backends-v1"
MATRIX = DIR / "matrix.py"
ROOT_CELL = DIR / "root-cell.sh"
NETNS_CELL = DIR / "root-netns-cell.sh"
README = DIR / "README.md"
CONFIG_GO = ROOT / "internal" / "config" / "config.go"
PLAN_SOURCE = "/run/wg-mix-ebpf-source-stages/abcdef12/source"
PLAN_COMMIT = "1" * 40


class StaticMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = MATRIX.read_text(encoding="utf-8")
        cls.root_cell = ROOT_CELL.read_text(encoding="utf-8")
        cls.netns = NETNS_CELL.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")
        cls.config_go = CONFIG_GO.read_text(encoding="utf-8")

    def test_sources_parse(self) -> None:
        ast.parse(self.matrix, filename=str(MATRIX))
        for path in (ROOT_CELL, NETNS_CELL):
            completed = subprocess.run(
                ["/bin/bash", "-n", str(path)], text=True, capture_output=True
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

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
            'ping -I "wg${index}"',
            "iperf3 -c",
            "same-tuple-router-test",
            "key_size=32",
            "reserved_zero=1",
            "expected=set(range(1,count+1))",
            "raw_wireguard_udp=0",
            "status-a-recovered",
            "kill -KILL",
        ):
            self.assertIn(required, self.netns)

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
            artifact_root = (
                f"/run/wg-mix-ebpf-faketcp-backends-v1/{cell['run_id']}/artifacts"
            )
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


if __name__ == "__main__":
    unittest.main()
