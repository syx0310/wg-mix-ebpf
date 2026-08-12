#!/usr/bin/env python3
"""Static and synthetic tests for the complete B82 performance matrix."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import pathlib
import re
import statistics
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX = ROOT / "scripts" / "run-b82-complete-performance-matrix.sh"
TMUX_WRAPPER = ROOT / "scripts" / "run-b82-complete-performance-tmux.sh"
RUNNER = ROOT / "scripts" / "run-b82-production-performance-cell.sh"
REPORTER = ROOT / "scripts" / "generate-b82-performance-report.py"
EXPORTER = ROOT / "scripts" / "export-b82-production-performance-evidence.sh"
CLEANUP = ROOT / "scripts" / "cleanup-b82-production-performance-evidence.py"


def load_reporter():
    spec = importlib.util.spec_from_file_location("b82_reporter", REPORTER)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load report generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def iperf_document(
    direction: str,
    forward_bytes: int,
    reverse_bytes: int = 0,
    forward_retransmits: int = 0,
    reverse_retransmits: int = 0,
) -> dict[str, object]:
    streams = [
        {
            "sender": {
                "sender": direction != "reverse",
                "bytes": forward_bytes,
                "retransmits": forward_retransmits,
            },
            "receiver": {
                "sender": direction != "reverse",
                "bytes": forward_bytes,
            },
        }
    ]
    end: dict[str, object] = {
        "streams": streams,
        "sum_received": {"bytes": forward_bytes, "seconds": 1.0},
        "sum_sent": {
            "bytes": forward_bytes,
            "retransmits": forward_retransmits,
        },
    }
    if direction == "bidir":
        streams.append(
            {
                "sender": {
                    "sender": False,
                    "bytes": reverse_bytes,
                    "retransmits": reverse_retransmits,
                },
                "receiver": {"sender": False, "bytes": reverse_bytes},
            }
        )
        end["sum_received_bidir_reverse"] = {
            "bytes": reverse_bytes,
            "seconds": 1.0,
        }
        end["sum_sent_bidir_reverse"] = {
            "bytes": reverse_bytes,
            "retransmits": reverse_retransmits,
        }
    return {
        "start": {
            "test_start": {
                "num_streams": 1,
                "reverse": int(direction == "reverse"),
                "bidir": int(direction == "bidir"),
            }
        },
        "end": end,
    }


class B82ProductionPerformanceStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = MATRIX.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.reporter = REPORTER.read_text(encoding="utf-8")
        cls.exporter = EXPORTER.read_text(encoding="utf-8")
        cls.cleanup = CLEANUP.read_text(encoding="utf-8")

    def test_exact_63_cell_567_sample_set(self) -> None:
        reporter = load_reporter()
        cells = reporter.expected_cells()
        self.assertEqual(63, len(cells))
        self.assertEqual(63, len({cell[0] for cell in cells}))
        grouped: dict[str, int] = {}
        for cell in cells:
            grouped[cell[1]] = grouped.get(cell[1], 0) + 1
        self.assertEqual(
            {"wireguard": 1, "udp": 20, "icmp": 2, "faketcp": 40}, grouped
        )
        self.assertEqual(567, len(cells) * 3 * 3)
        fake_pairs = {(cell[2], cell[3]) for cell in cells if cell[1] == "faketcp"}
        self.assertEqual(
            {
                ("tcx", "kfunc"),
                ("classic_tc", "kfunc"),
                ("tcx", "kprobe"),
                ("classic_tc", "kprobe"),
            },
            fake_pairs,
        )
        icmp = [cell for cell in cells if cell[1] == "icmp"]
        self.assertTrue(all(cell[5:] == ("none", 0) for cell in icmp))
        emit_start = self.matrix.index("emit_cells() {")
        emit_end = self.matrix.index("\n}\n\ndeclare -A observed_cell_run_ids", emit_start) + 3
        emitter = self.matrix[emit_start:emit_end]
        harness = "\n".join(
            (
                "CELL_COUNT=63",
                "PREFIX_LENGTHS=(4 16 64 128 256 512 1024 2048)",
                emitter,
                "record_cell() { printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$@\"; }",
                "emit_cells record_cell",
            )
        )
        completed = subprocess.run(
            ["bash", "-c", harness],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        emitted = []
        for line in completed.stdout.splitlines():
            ordinal, label, transport, attachment, checksum, artifact, cipher, size = line.split("\t")
            self.assertEqual(len(emitted) + 1, int(ordinal))
            emitted.append(
                (label, transport, attachment, checksum, artifact, cipher, int(size))
            )
        self.assertEqual(cells, emitted)
        for fragment in (
            "readonly CELL_COUNT=63 SAMPLE_COUNT=567",
            "cells=63 samples=567 repetitions=3 duration_seconds=3",
            'readonly -a PREFIX_LENGTHS=(4 16 64 128 256 512 1024 2048)',
            "for checksum in kfunc kprobe; do",
            "for backend in tcx classic_tc; do",
            '"icmp-${backend}-none" icmp',
            "emit_cells run_cell",
            "emit_cells validate_cell_run_id",
            '"${#observed_cell_run_ids[@]}" -eq "${CELL_COUNT}"',
        ):
            self.assertIn(fragment, self.matrix)

    def test_read_only_plan_has_exact_argv_write_set_restore_and_tmux_budget(self) -> None:
        for fragment in (
            "PERFORMANCE_MATRIX_PLAN",
            "SOURCE_STATE source=",
            "git_clean=1",
            "tmux_budget_seconds=9000",
            "TMUX_ARGV",
            "WG_MIX_EBPF_PERFORMANCE_MATRIX_ID=${MATRIX_ID}",
            '"${TMUX_WRAPPER}"',
            "ARGV /usr/bin/env WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=",
            "/usr/bin/timeout --foreground --signal=TERM",
            "--checksum-backend %q",
            "WRITE_SET cell=",
            "ARTIFACT_BUILD_SET",
            "MODULE_LOAD_ARGV backend=kfunc",
            "MODULE_UNLOAD_ARGV backend=kprobe",
            "RESTORE_ARGV",
            "MODULE_RESTORE_ARGV",
            "readonly CELL_BUDGET_SECONDS=130 REPORT_RESERVE_SECONDS=60",
        ):
            self.assertIn(fragment, self.matrix)
        plan_start = self.matrix.index('if [[ "${operation}" == plan ]]')
        plan_end = self.matrix.index("  exit 0\nfi", plan_start) + len("  exit 0\nfi")
        plan = self.matrix[plan_start:plan_end]
        for forbidden in ("mkdir --mode", "matrix_logged ", "ip netns add", "mount --"):
            self.assertNotIn(forbidden, plan)

    def test_artifacts_are_built_once_frozen_and_revalidated(self) -> None:
        matrix = self.matrix
        self.assertEqual(1, matrix.count("matrix_logged bpf-build"))
        self.assertEqual(1, matrix.count("matrix_logged go-build"))
        self.assertEqual(1, matrix.count("matrix_logged module-kfunc-build"))
        self.assertEqual(1, matrix.count("matrix_logged module-kprobe-build"))
        for fragment in (
            "format=wg-mix-ebpf-performance-artifacts-v1",
            'chmod 0500 -- "${BUILD_BIN}"',
            'chmod 0400 -- "${BUILD_BASELINE}"',
            "metadata.st_nlink != 1",
            "validate_artifacts >\"${MATRIX_EVIDENCE}/artifact-check-${ordinal}.log\"",
            "GOCACHE=\"${GO_CACHE}\"",
            "GOMODCACHE=\"${GO_MOD_CACHE}\"",
            "GOTELEMETRY=off",
            'readonly STAGE_GO_CACHE="/var/tmp/wg-mix-ebpf-source-stages/${STAGE_ID}/go-cache"',
            "GOTMPDIR=\"${GO_TMP}\"",
            "-Wno-unused-function -target bpf",
            "binary-source-identity.log",
            "matrix_logged go-overlay python3 -I -c",
            'readonly GO_OVERLAY="${BUILD_CACHE_ROOT}/frozen-bpf-overlay.json"',
            '"-overlay=${GO_OVERLAY}"',
            "if not path.exists():",
            'internal/buildinfo.sourceCommit=${COMMIT}',
            'document.get(field) != expected',
            "source stage is dirty before build",
            "matrix_logged source-tree-before source_tree_digest",
            "matrix_logged source-tree-after-build source_tree_digest",
            "matrix_logged source-tree-final source_tree_digest",
            "artifact build changed the root-owned source tree",
            'FROZEN_BPF_CFLAGS="-O2 -g -Wall -Werror -Wno-unused-function -target bpf -I/usr/include/${bpf_multiarch}"',
        ):
            self.assertIn(fragment, matrix)

    def test_module_transitions_have_intent_owned_restore_and_no_failure_unload(self) -> None:
        matrix = self.matrix
        for fragment in (
            'readonly MODULE_LOCK="${RUN_PARENT}/checksum-module-lease.v2.lock"',
            "wg-mix-ebpf-performance-module-intent-v2",
            "wg-mix-ebpf-performance-module-owned-v2",
            "wg-mix-ebpf-performance-module-restored-v1",
            "prepare_module_intent",
            "seal_live_module_owned",
            "validate_live_module_owned",
            'matrix_logged "module-${backend}-load" insmod',
            'matrix_logged "module-${backend}-unload" rmmod',
            'refcount="$(awk -v name="${name}"',
            '[[ "${refcount}" == 0 ]]',
            "restore-module",
            "validate_module_restored kfunc",
            "validate_module_restored kprobe",
            "No automatic cell restore, module unload, or evidence cleanup was attempted.",
        ):
            self.assertIn(fragment, matrix)
        failure = matrix[matrix.index("matrix_failure()") : matrix.index("receipt_value()")]
        self.assertNotIn("rmmod", failure)

    def test_runner_uses_netns_then_private_mountns_then_bpffs_then_direct_daemon(self) -> None:
        runner = self.runner
        netns = runner.index('ip netns exec "${NSA}" unshare --mount --propagation private')
        verify = runner.index("endpoint child did not enter its exact network namespace")
        binds = runner.index('mount --bind "${endpoint_run}"')
        bpffs = runner.index("mount -t bpf -o mode=0700 bpf /sys/fs/bpf")
        direct = runner.index('exec env -i "${daemon_environment[@]}"')
        self.assertLess(verify, binds)
        self.assertLess(binds, bpffs)
        self.assertLess(bpffs, direct)
        self.assertGreater(netns, direct)
        endpoint = runner[runner.index("endpoint_child()") : runner.index('if [[ "${1-}" == "endpoint"')]
        self.assertNotIn('exec ip netns exec "${netns}"', endpoint)
        self.assertNotIn('mount --bind "${endpoint_maintenance}"', endpoint)

    def test_runner_supports_all_attachment_checksum_artifact_branches(self) -> None:
        runner = self.runner
        for fragment in (
            "wireguard|udp|icmp|faketcp",
            "none|tcx|classic_tc",
            "none|kfunc|kprobe",
            'readonly FAKETCP_LEGACY_OBJECT_NAME="build/wg_mix_faketcp_legacy_515.o"',
            "WG_MIX_EBPF_FAKETCP_LEGACY_515_OBJECT",
            "legacy-515-kprobe",
            "modern-kfunc",
            'readonly ARTIFACT_MANIFEST="${ARTIFACT_ROOT%/artifacts}/artifacts.v1"',
            "frozen performance artifact differs",
            'expected_owner = "process-owned" if backend == "tcx" else "durable-classic-tc+process-owned-runtime"',
            'xdp[0].get("mode") != "generic"',
            'checksum_status.get("lease_held") is not True',
            'daemon = doc.get("daemon")',
            "validate_classic_journal",
            "validate_no_classic_journal",
            "kprobe_lease_fds",
            "classic-journal-recovery",
            "post-traffic-health-reload",
            "reload-a-after-traffic-health",
            "validate_baseline_status",
            "performance label does not bind its exact cell arguments",
            'fake.get("object_sha256") != expected_object_sha256',
            "underlay projection differs from owner identity",
        ):
            self.assertIn(fragment, runner)
        self.assertNotIn("FakeTCP production performance requires TCX", runner)

    def test_cell_sampling_and_aggregate_contract(self) -> None:
        for fragment in (
            "readonly DURATION=3",
            "readonly REPETITIONS=3",
            "for direction in forward reverse bidir; do",
            "for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do",
            "samples=9",
            "--aggregate",
            "direction_args=(-R)",
            "direction_args=(--bidir)",
            "readonly MAXIMUM_RETRANSMITS=2147483647",
        ):
            self.assertIn(fragment, self.runner)

    def test_failure_is_full_log_no_automatic_restore(self) -> None:
        runner = self.runner
        matrix = self.matrix
        for source in (runner, matrix):
            self.assertIn("FULL_LOG_BEGIN", source)
        self.assertIn("failure-diagnostics.log", runner)
        self.assertIn("FAILURE_RESOURCES_RETAINED", runner)
        self.assertIn("No automatic cleanup was attempted", runner)
        self.assertIn("No automatic cell restore, module unload", matrix)
        failure = runner[runner.index("capture_failure_evidence()") : runner.index("dump_complete_logs()")]
        for forbidden in ("ip netns delete", "kill -", "/bin/rm"):
            self.assertNotIn(forbidden, failure)
        for forbidden in ("rm -rf", "find -delete", "xargs rm", "eval "):
            self.assertNotIn(forbidden, runner + matrix)

    def test_explicit_restore_is_owner_bound_and_exact(self) -> None:
        for fragment in (
            "validate_retained_run",
            "signal_namespace_processes TERM",
            "signal_namespace_processes KILL",
            "allowed_restore_executable",
            "refusing to signal an unproved retained process",
            "remove_retained_secret",
            "remove_retained_classic_journals",
            'ip netns delete "${netns}"',
            "PERFORMANCE_PRODUCTION_CELL_RESTORE_COMPLETE",
            'proof_value source_root "${RUN_ROOT}/manifest"',
        ):
            self.assertIn(fragment, self.runner)

    def test_export_cleanup_and_report_are_v2_bound(self) -> None:
        for fragment in (
            "wg-mix-ebpf-b82-production-performance-complete-v2",
            "artifacts_sha256",
            "results_sha256",
            "report_sha256",
        ):
            self.assertIn(fragment, self.exporter)
            self.assertIn(fragment, self.cleanup)
        self.assertIn("expected_complete_lines=10", self.exporter)
        self.assertIn('"$(proof_value samples)" != 567', self.exporter)
        self.assertIn('^0:0:700:[1-9][0-9]*$', self.exporter)
        self.assertNotIn('!= "0:0:700:1"', self.exporter)
        for fragment in (
            "65536-entry cleanup bound",
            "4 GiB cleanup inventory bound",
            "run tree crosses a filesystem boundary",
            "evidence export path is not canonical",
            "matrix checksum module is live before evidence cleanup",
            "matrix cell index row {ordinal} differs from bound results",
            "os.unlink(path)",
            "os.rmdir(path)",
            "CLEANUP_PRESERVE",
            'assert_no_live_resources(child_id, child_root, "matrix")',
        ):
            self.assertIn(fragment, self.cleanup)
        for forbidden in ("shutil.rmtree", "rm -rf", "find -delete", "shell=True"):
            self.assertNotIn(forbidden, self.cleanup)
        self.assertIn('"${canonical_output_parent}" != "${output_parent}"', self.exporter)
        self.assertIn('"${canonical_output}" != "${output}"', self.exporter)

    def test_python_sources_parse_without_bytecode(self) -> None:
        for path in (REPORTER, CLEANUP, pathlib.Path(__file__)):
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for path in (MATRIX, RUNNER):
            lines = path.read_text(encoding="utf-8").splitlines()
            for start, line in enumerate(lines):
                if "<<'PY'" not in line:
                    continue
                try:
                    finish = lines.index("PY", start + 1)
                except ValueError as error:
                    raise AssertionError(f"unterminated Python heredoc in {path}:{start + 1}") from error
                ast.parse(
                    "\n".join(lines[start + 1 : finish]) + "\n",
                    filename=f"{path}:heredoc:{start + 2}",
                )
        marker = "matrix_logged go-overlay python3 -I -c '\n"
        start = self.matrix.index(marker) + len(marker)
        finish = self.matrix.index("\n' \"${GO_OVERLAY}\"", start)
        ast.parse(self.matrix[start:finish], filename=f"{MATRIX}:go-overlay")

    def test_shell_sources_pass_bash_syntax(self) -> None:
        completed = subprocess.run(
            [
                "bash",
                "-n",
                str(MATRIX),
                str(TMUX_WRAPPER),
                str(RUNNER),
                str(EXPORTER),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        wrapper = TMUX_WRAPPER.read_text(encoding="utf-8")
        self.assertIn("--foreground --signal=TERM --kill-after=180s 9000s", wrapper)
        self.assertIn('exec /usr/bin/timeout', wrapper)
        self.assertNotIn("eval ", wrapper)

    def test_reporter_rejects_non_exact_cell_set(self) -> None:
        reporter = load_reporter()
        cells = reporter.expected_cells()
        rows = []
        for ordinal, cell in enumerate(cells, start=1):
            label, transport, attachment, checksum, artifact, cipher, max_bytes = cell
            rows.append(
                {
                    "ordinal": str(ordinal),
                    "label": label,
                    "transport": transport,
                    "attachment_backend": attachment,
                    "checksum_backend": checksum,
                    "artifact": artifact,
                    "cipher": cipher,
                    "max_bytes": str(max_bytes),
                    "run_id": f"{ordinal:08x}",
                    "evidence": f"/var/tmp/wg-mix-ebpf-performance-tests/abcd1234/children/{ordinal:08x}/evidence",
                }
            )
        reporter.validate_cell_set(rows)
        for mutation in ("missing", "duplicate", "extra"):
            changed = [dict(row) for row in rows]
            if mutation == "missing":
                changed.pop()
            elif mutation == "duplicate":
                changed[-1] = dict(changed[-2])
            else:
                changed.append(dict(changed[-1]))
            with self.assertRaises((reporter.ReportError, ValueError)):
                reporter.validate_cell_set(changed)

    def test_report_statistics_use_pstdev_samplewise_bidir_and_no_double_retransmit(self) -> None:
        reporter = load_reporter()

        with tempfile.TemporaryDirectory() as raw:
            raw_root = pathlib.Path(raw)
            for direction in ("forward", "reverse", "bidir"):
                for repetition in range(1, 4):
                    base = (repetition + 1) * 1_000_000
                    document = iperf_document(
                        direction,
                        base,
                        reverse_bytes=(repetition + 3) * 1_000_000,
                        forward_retransmits=repetition,
                        reverse_retransmits=repetition + 3,
                    )
                    (raw_root / f"iperf-{direction}-r{repetition}.json").write_text(
                        json.dumps(document), encoding="utf-8"
                    )
            checker = reporter.load_checker(ROOT)
            measured, digests = reporter.aggregate_cell(checker, raw_root)
            (raw_root / "unexpected.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(reporter.ReportError):
                reporter.aggregate_cell(checker, raw_root)
        measured_by_key = {
            (item["requested_direction"], item["direction"]): item
            for item in measured
        }
        forward = measured_by_key[("forward", "forward")]
        bidir = measured_by_key[("bidir", "aggregate")]
        self.assertEqual(9, len(digests))
        self.assertAlmostEqual(24.0, forward["throughput_mean_mbps"])
        self.assertAlmostEqual(
            statistics.pstdev((16.0, 24.0, 32.0)),
            forward["throughput_pstdev_mbps"],
        )
        self.assertAlmostEqual(64.0, bidir["throughput_mean_mbps"])
        self.assertAlmostEqual(
            statistics.pstdev((48.0, 64.0, 80.0)),
            bidir["throughput_pstdev_mbps"],
        )
        self.assertEqual(21, bidir["retransmits_total"])

        def item(requested: str, direction: str, throughput: float, retrans: int, fairness: float):
            return {
                "requested_direction": requested,
                "direction": direction,
                "samples": 3,
                "throughput_mean_mbps": throughput,
                "throughput_pstdev_mbps": 1.25,
                "throughput_min_mbps": throughput - 2,
                "throughput_max_mbps": throughput + 2,
                "retransmits_total": retrans,
                "fairness_mean": fairness,
                "fairness_min": fairness - 0.01,
            }

        aggregates = [
            item("forward", "forward", 10, 1, 0.99),
            item("reverse", "reverse", 20, 2, 0.98),
            item("bidir", "forward", 30, 4, 0.97),
            item("bidir", "reverse", 40, 8, 0.96),
            item("bidir", "aggregate", 70, 12, 0.96),
        ]
        document = {
            "matrix_id": "abcd1234",
            "commit": "a" * 40,
            "kernel_release": "test",
            "cell_results": [
                {
                    "ordinal": 1,
                    "transport": "wireguard",
                    "attachment_backend": "none",
                    "checksum_backend": "none",
                    "cipher": "none",
                    "max_bytes": 0,
                    "run_id": "00000001",
                    "aggregates": aggregates,
                }
            ],
        }
        markdown = reporter.render_markdown(document)
        self.assertIn("总重传：15", markdown)
        self.assertNotIn("总重传：27", markdown)
        self.assertIn("70.00 ± 1.25 (68.00–72.00)", markdown)
        self.assertIn("总体标准差", markdown)

    def test_complete_567_sample_fixture_generates_chinese_report(self) -> None:
        reporter = load_reporter()
        matrix_id = "abcd1234"
        with tempfile.TemporaryDirectory() as temporary:
            matrix_root = (pathlib.Path(temporary) / matrix_id).resolve(strict=False)
            (matrix_root / "cells").mkdir(parents=True)
            (matrix_root / "children").mkdir()
            (matrix_root / "manifest").write_text(
                "\n".join(
                    (
                        "format=wg-mix-ebpf-b82-performance-matrix-v2",
                        "kind=matrix",
                        f"run_id={matrix_id}",
                        f"commit={'a' * 40}",
                        "kernel_release=synthetic-7.0",
                        "cells=63",
                        "samples=567",
                        "repetitions=3",
                        "duration_seconds=3",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            rows = []
            for ordinal, cell in enumerate(reporter.expected_cells(), start=1):
                label, transport, attachment, checksum, artifact, cipher, size = cell
                run_id = hashlib.sha256(
                    f"{matrix_id}:{ordinal}:{label}".encode("ascii")
                ).hexdigest()[:8]
                evidence = matrix_root / "children" / run_id / "evidence"
                evidence.mkdir(parents=True)
                row = {
                    "ordinal": str(ordinal),
                    "label": label,
                    "transport": transport,
                    "attachment_backend": attachment,
                    "checksum_backend": checksum,
                    "artifact": artifact,
                    "cipher": cipher,
                    "max_bytes": str(size),
                    "run_id": run_id,
                    "evidence": str(evidence),
                }
                rows.append(row)
                cell_root = matrix_root / "cells" / f"{ordinal:02d}-{label}"
                raw_root = cell_root / "raw"
                raw_root.mkdir(parents=True)
                (cell_root / "cell.v1").write_text(
                    "".join(f"{key}={row[key]}\n" for key in reporter.CELL_HEADER)
                    + "samples=9\nstate=complete\n",
                    encoding="utf-8",
                )
                for direction in reporter.DIRECTIONS:
                    for repetition in range(1, 4):
                        received = 1_100_000 + ordinal * 10_000 + repetition * 1_000
                        document = iperf_document(
                            direction,
                            received,
                            reverse_bytes=received + 500_000,
                        )
                        (raw_root / f"iperf-{direction}-r{repetition}.json").write_text(
                            json.dumps(document), encoding="utf-8"
                        )
            (matrix_root / "cells.v1.tsv").write_text(
                "\t".join(reporter.CELL_HEADER)
                + "\n"
                + "".join(
                    "\t".join(row[key] for key in reporter.CELL_HEADER) + "\n"
                    for row in rows
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-I",
                    str(REPORTER),
                    "--matrix-root",
                    str(matrix_root),
                    "--source-root",
                    str(ROOT),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIn("cells=63 samples=567", completed.stdout)
            results_path = matrix_root / "results.v1.json"
            report_path = matrix_root / "report.zh-CN.md"
            results = json.loads(results_path.read_text(encoding="utf-8"))
            report = report_path.read_text(encoding="utf-8")
            self.assertEqual(63, results["cells"])
            self.assertEqual(567, results["samples"])
            self.assertEqual(63, len(results["cell_results"]))
            self.assertEqual(
                567, sum(cell["samples"] for cell in results["cell_results"])
            )
            self.assertTrue(
                all(
                    len(cell["sample_sha256"]) == 9
                    and len(cell["aggregates"]) == 5
                    for cell in results["cell_results"]
                )
            )
            self.assertIn("# B82 完整性能矩阵报告", report)
            self.assertIn("完整配置 63/63，原始 iperf3 采样 567/567", report)
            self.assertEqual(
                63,
                sum(
                    bool(re.match(r"^\| [1-9][0-9]* \|", line))
                    for line in report.splitlines()
                ),
            )
            self.assertEqual(0o600, results_path.stat().st_mode & 0o777)
            self.assertEqual(0o600, report_path.stat().st_mode & 0o777)

    def test_report_output_is_exclusive_and_deterministic(self) -> None:
        reporter = load_reporter()
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "report.md"
            reporter.write_exclusive(path, "中文\n")
            self.assertEqual("中文\n", path.read_text(encoding="utf-8"))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(reporter.ReportError):
                reporter.write_exclusive(path, "changed\n")


if __name__ == "__main__":
    unittest.main()
