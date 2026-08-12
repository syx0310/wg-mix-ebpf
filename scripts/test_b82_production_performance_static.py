#!/usr/bin/env python3
"""Static contract tests for the B82 complete production performance matrix."""

from __future__ import annotations

import ast
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX = ROOT / "scripts" / "run-b82-complete-performance-matrix.sh"
RUNNER = ROOT / "scripts" / "run-b82-production-performance-cell.sh"
EXPORTER = ROOT / "scripts" / "export-b82-production-performance-evidence.sh"
CLEANUP = ROOT / "scripts" / "cleanup-b82-production-performance-evidence.py"


class B82ProductionPerformanceStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = MATRIX.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.exporter = EXPORTER.read_text(encoding="utf-8")
        cls.cleanup = CLEANUP.read_text(encoding="utf-8")

    def test_complete_matrix_is_33_cells_and_297_samples(self) -> None:
        matrix = self.matrix
        for fragment in (
            "umask 077",
            "cells=33 repetitions=3 duration_seconds=3",
            "cells=33 samples=297",
            "run_udp_cell wireguard-baseline wireguard auto off",
            "run_udp_cell tcx-baseline ebpf tcx off",
            "run_udp_cell classic_tc-baseline ebpf classic_tc off",
            "run_production_cell icmp-tcx-baseline icmp tcx none 4",
            "run_production_cell icmp-classic_tc-baseline icmp classic_tc none 4",
            "run_production_cell faketcp-tcx-baseline faketcp tcx none 4",
            'run_production_cell "faketcp-tcx-prefix-${max_bytes}" faketcp tcx prefix',
            "run_production_cell faketcp-tcx-full-2048 faketcp tcx full 2048",
            "for max_bytes in 4 16 64 128 256 512 1024 2048; do",
            'readonly PRODUCTION_RUNNER_NAME="scripts/run-b82-production-performance-cell.sh"',
        ):
            self.assertIn(fragment, matrix)
        self.assertEqual(2, matrix.count("for max_bytes in 4 16 64 128 256 512 1024 2048; do"))
        self.assertNotIn("cells=21", matrix)
        self.assertNotIn("samples=189", matrix)

    def test_privileged_shell_entrypoints_use_a_real_effective_group_probe(self) -> None:
        for source in (self.matrix, self.runner, self.exporter):
            self.assertNotIn("${EGID}", source)
            self.assertIn(
                'if [[ "${EUID}" -ne 0 || "$(/usr/bin/id -g)" -ne 0 ]]; then',
                source,
            )

    def test_module_lease_wraps_the_entire_matrix_and_has_recovery(self) -> None:
        matrix = self.matrix
        for fragment in (
            'readonly MODULE_LOCK="${RUN_PARENT}/checksum-module-lease.v1.lock"',
            "wg-mix-ebpf-b82-performance-module-intent-v1",
            "wg-mix-ebpf-b82-performance-module-owned-v1",
            "wg-mix-ebpf-b82-performance-module-unloaded-v1",
            '"source_stage_id=${source_stage_id}"',
            '"boot_id=${boot_id}"',
            '"commit=${commit}"',
            '"ko_sha256=${module_sha256}"',
            '"srcversion=${module_srcversion}"',
            '"lease_id=${MODULE_LEASE_ID}"',
            "matrix_logged module-load /usr/sbin/insmod",
            "matrix_logged module-unload /usr/sbin/rmmod",
            'expected_lease="${intent_stage}-${matrix_id}"',
            'intent_source_root="/run/wg-mix-ebpf-source-stages/${intent_stage}/source"',
            'reason="recovered-unreceipted-live-no-btf"',
            'if ! module_identity="$(module_live_identity)"; then',
            'if [[ "${operation}" == "cleanup-module" ]]; then',
            "cleanup_owned_module",
            '"${refcount}" != "0"',
            "No automatic module unload or evidence cleanup was attempted.",
        ):
            self.assertIn(fragment, matrix)
        load = matrix.index("matrix_logged module-load /usr/sbin/insmod")
        cells = matrix.index("PERFORMANCE_MATRIX_START")
        unload = matrix.index("matrix_logged module-unload /usr/sbin/rmmod")
        self.assertLess(load, cells)
        self.assertLess(cells, unload)
        failure = matrix[matrix.index("matrix_failure()") : matrix.index("receipt_value()")]
        self.assertNotIn("rmmod", failure)

    def test_module_build_finalizes_exact_kernel_btf_before_load(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        helper = (
            ROOT / "scripts" / "finalize-faketcp-checksum-module-btf.sh"
        ).read_text(encoding="utf-8")
        for fragment in (
            'VMLINUX_BTF ?= /sys/kernel/btf/vmlinux',
            'FAKETCP_CHECKSUM_KMOD_BTF_HELPER ?=',
            '--kernel-build "$(KERNEL_BUILD)"',
            '--vmlinux-btf "$(VMLINUX_BTF)"',
            '--module "$(FAKETCP_CHECKSUM_KMOD_OBJECT)"',
        ):
            self.assertIn(fragment, makefile)
        for fragment in (
            'readonly gen_btf="${kernel_build}/scripts/gen-btf.sh"',
            'readonly resolve_btfids="${kernel_build}/tools/bpf/resolve_btfids/resolve_btfids"',
            '"${gen_btf}" --btf_base "${vmlinux_btf}" "${module}"',
            '"1:1:1"',
            'FAKETCP_CHECKSUM_MODULE_BTF state=%s',
        ):
            self.assertIn(fragment, helper)
        for forbidden in ("insmod", "modprobe", "rmmod", "modules_install"):
            self.assertNotIn(forbidden, helper)

    def test_cleanup_dispatch_and_run_root_precede_mutating_work(self) -> None:
        matrix = self.matrix
        cleanup_dispatch = matrix.index(
            'if [[ "${operation}" == "cleanup-module" ]]; then',
            matrix.index("cleanup_owned_module()") + len("cleanup_owned_module()"),
        )
        run_root_create = matrix.index(
            'mkdir --mode=0700 -- "${MATRIX_ROOT}" "${MATRIX_EVIDENCE}"'
        )
        first_run_lock = matrix.index("matrix_logged module-lock")
        module_build = matrix.index("matrix_logged module-build")
        matrix_start = matrix.index("PERFORMANCE_MATRIX_START")
        self.assertLess(cleanup_dispatch, run_root_create)
        self.assertLess(run_root_create, first_run_lock)
        self.assertLess(first_run_lock, module_build)
        self.assertLess(module_build, matrix_start)
        cleanup_branch = matrix[cleanup_dispatch:run_root_create]
        self.assertIn("cleanup_owned_module", cleanup_branch)
        self.assertIn("exit 0", cleanup_branch)

    def test_command_preflight_accepts_system_managed_symlinks(self) -> None:
        runner = self.runner
        preflight = runner[
            runner.index("for command_name in ip wg ping") : runner.index(
                "unset resolved_command"
            )
        ]
        self.assertIn('! -f "${resolved_command}"', preflight)
        self.assertNotIn('-L "${resolved_command}"', preflight)

    def test_runner_uses_two_real_resident_daemons(self) -> None:
        runner = self.runner
        self.assertGreaterEqual(runner.count("unshare --mount --propagation private"), 4)
        for fragment in (
            '"${BIN}" run --config /run/wg-mix-ebpf/config.yaml',
            "--run-dir /run/wg-mix-ebpf/runtime",
            "--state-dir /var/lib/wg-mix-ebpf/state",
            'mount --bind "${endpoint_run}" "${SHARED_RUN_TARGET}"',
            'mount --bind "${endpoint_var}" "${SHARED_VAR_TARGET}"',
            'mount --bind "${endpoint_maintenance}" "${SHARED_MAINTENANCE_TARGET}"',
            "mount -t bpf -o mode=0700 bpf /sys/fs/bpf",
            '"WG_MIX_EBPF_FAKETCP_OBJECT=${FAKETCP_OBJECT}"',
            "wait_daemon_active a",
            "wait_daemon_active b",
        ):
            self.assertIn(fragment, runner)
        for forbidden in (
            "--once",
            "--isolated-netns-test",
            "WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION",
            "WG_MIX_FAKETCP_REALHOST_OBJECT",
        ):
            self.assertNotIn(forbidden, runner)
        first_wait = runner.index("wait_daemon_active a", runner.index('stage="daemon-start"'))
        second_start = runner.index("record_background_start daemon-b-start")
        self.assertLess(second_start, first_wait)

    def test_faketcp_contract_is_fixed_tcx_generic_xdp_and_fail_closed(self) -> None:
        runner = self.runner
        for fragment in (
            '"${transport}" == "faketcp" && "${backend}" != "tcx"',
            "checksum_mode: partial-complete-reset-required",
            "ingress_mode: xdp-generic-exact",
            "ListenPort = ${port}",
            "mode: nft-temporary-drop",
            "startup_fail_mode: fail_closed_for_managed_flows",
            "/sys/module/wg_mix_faketcp_checksum",
            "/sys/kernel/btf/wg_mix_faketcp_checksum",
        ):
            self.assertIn(fragment, runner)
        self.assertNotIn("classic_tc faketcp", runner)

    def test_each_cell_is_three_by_three_by_three(self) -> None:
        runner = self.runner
        for fragment in (
            "readonly DURATION=3",
            "readonly REPETITIONS=3",
            "for direction in forward reverse bidir; do",
            "for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do",
            "samples=9",
            "--aggregate",
        ):
            self.assertIn(fragment, runner)
        self.assertIn("--bidir", runner)
        self.assertIn("direction_args=(-R)", runner)

    def test_complete_evidence_is_recorded_without_secret_argv(self) -> None:
        runner = self.runner
        for fragment in (
            "run_recorded_command()",
            "record_background_start()",
            "record_background_finish()",
            "event=start phase=%s argv=",
            "event=finish phase=%s rc=%s",
            "daemon-a.stdout.log",
            "daemon-a.stderr.log",
            "reload-a-same-key.stdout.log",
            "iperf-${sample}-client",
            "FULL_LOG_BEGIN",
            "failure-diagnostics.log",
            "No automatic cleanup was attempted after the unexpected failure.",
        ):
            self.assertIn(fragment, runner)
        self.assertNotIn("XOR_PASSWORD=", runner)
        self.assertNotIn('log_argv "${next_xor_secret}"', runner)
        self.assertNotIn('log_argv "${xor_secret}"', runner)
        self.assertNotIn("ps -eo", runner)
        self.assertIn('ps -p "${exact_pid}"', runner)

    def test_faketcp_acceptance_checks_lifecycle_and_exact_ids(self) -> None:
        runner = self.runner
        for fragment in (
            'fake.get("owner_kind") != "process-owned"',
            'fake.get("healthy") is not True',
            'fake.get("barrier") != "open"',
            'fake.get("object_source") != expected_object',
            'len(xdp) != 1',
            'len(tcx) != 2',
            'directions != {"ingress", "egress"}',
            "faketcp_same_key_reload=noop exact_identity=unchanged",
            "faketcp_changed_key_reload=serial-replacement exact_identity=replaced",
            "reload-a-same-key",
            "reload-b-same-key",
            "reload-a-changed-key",
            "reload-b-changed-key",
            "owned-bpf-ids.json",
            "exact-bpf-absence-after-stop.log",
            "exact_links_absent=1",
            "exact_programs_absent=1",
            "exact_maps_absent=1",
        ):
            self.assertIn(fragment, runner)

    def test_lifecycle_maintenance_gate_is_isolated_and_host_gate_unchanged(self) -> None:
        runner = self.runner
        for fragment in (
            'readonly SHARED_MAINTENANCE_TARGET="/run/.wg-mix-ebpf-daemon.lease.maintenance"',
            '"$(stat -c \'%u:%g:%a:%h\' -- "${SHARED_MAINTENANCE_TARGET}")" != "0:0:600:1"',
            "fcntl.LOCK_EX | fcntl.LOCK_NB",
            'maintenance_target_stat_before="$(stat -Lc',
            'maintenance_target_sha_before="$(sha256sum',
            'maintenance_target_stat_after="$(stat -Lc',
            'maintenance_target_sha_after="$(sha256sum',
            "global lifecycle maintenance target changed across isolated endpoint runs",
            "result=unchanged",
        ):
            self.assertIn(fragment, runner)

    def test_success_cleanup_is_exact_and_failure_is_read_only(self) -> None:
        runner = self.runner
        failure = runner[runner.index("capture_failure_evidence()") : runner.index("dump_complete_logs()")]
        self.assertNotIn("ip netns delete", failure)
        self.assertNotIn("kill -", failure)
        self.assertNotIn("/bin/rm", failure)
        for fragment in (
            'run_mutation netns-delete-a ip netns delete "${NSA}"',
            'run_mutation netns-delete-router ip netns delete "${NSR}"',
            'run_mutation netns-delete-b ip netns delete "${NSB}"',
            'run_mutation xor-secret-remove /bin/rm -- "${secret_path}"',
            "PERFORMANCE_PRODUCTION_CELL_COMPLETE",
            "active_resources=absent",
            "sensitive_files=absent",
        ):
            self.assertIn(fragment, runner)
        for forbidden in ("rm -rf", "find -delete", "xargs rm", "eval "):
            self.assertNotIn(forbidden, runner)

    def test_export_and_cleanup_are_versioned_and_bounded(self) -> None:
        exporter = self.exporter
        cleanup = self.cleanup
        for fragment in (
            "wg-mix-ebpf-b82-production-performance-complete-v1",
            "active_resources=absent",
            "sensitive_files=absent",
            "tar --create --format=posix --numeric-owner",
            "EVIDENCE_EXPORT_COMPLETE",
        ):
            self.assertIn(fragment, exporter)
        for fragment in (
            'RUN_PARENT = Path("/run/wg-mix-ebpf-performance-tests")',
            'if kind == "cell":',
            'if kind not in ("cell", "matrix"):',
            "run_root.resolve(strict=True) != run_root",
            "run tree file count exceeds the 4096-entry cleanup bound",
            "run tree exceeds the 1 GiB cleanup inventory bound",
            "CLEANUP_INVENTORY",
            "CLEANUP_TARGET",
            "CLEANUP_RESULT",
            "PERFORMANCE_EVIDENCE_CLEANUP_COMPLETE",
            "os.unlink(path)",
            "os.rmdir(path)",
            "CLEANUP_HOST hostname=",
            "CLEANUP_PRESERVE kind=export",
            "export_preserved=",
            "preserved evidence export changed during cleanup",
        ):
            self.assertIn(fragment, cleanup)
        self.assertNotIn("os.unlink(archive)", cleanup)
        self.assertNotIn("CLEANUP_TARGET kind=export", cleanup)
        self.assertLess(
            cleanup.index("CLEANUP_HOST hostname="),
            cleanup.index("files, directories = inventory_tree(run_root)"),
        )
        for forbidden in ("shutil.rmtree", "rm -rf", "find -delete", "shell=True"):
            self.assertNotIn(forbidden, cleanup)
        ast.parse(cleanup, filename=str(CLEANUP))


if __name__ == "__main__":
    unittest.main()
