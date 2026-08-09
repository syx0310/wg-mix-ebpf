#!/usr/bin/env python3

from __future__ import annotations

import ast
import pathlib
import unittest


SOURCE_PATH = pathlib.Path(__file__).with_name("realnic_acceptance.py")


class StaticSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_no_shell_or_recursive_cleanup_primitives(self):
        forbidden_text = (
            "shell=True",
            "os.system(",
            "os.popen(",
            "shutil.rmtree",
            "find -delete",
            "rm -rf",
            "rsync --delete",
            "chroot",
            "nsenter",
            "eval(",
        )
        for value in forbidden_text:
            self.assertNotIn(value, self.source)

    def test_no_delete_api(self):
        forbidden_attributes = {"remove", "unlink", "rmdir", "removedirs", "renames"}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, forbidden_attributes)

    def test_subprocess_calls_do_not_accept_shell_keyword(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                self.assertNotEqual(keyword.arg, "shell")

    def test_only_read_only_peer_has_peer_write_set(self):
        self.assertIn('READ_ONLY_PEER = "47.116.202.155"', self.source)
        self.assertIn('"peer": []', self.source)
        self.assertNotIn("192.168.10.28", self.source)

    def test_run_and_restore_require_review_gates(self):
        self.assertIn("current read-only snapshot no longer matches the approved plan", self.source)
        self.assertIn("run mode requires root after explicit approval", self.source)
        self.assertIn("restore mode requires root after separate explicit approval", self.source)
        self.assertIn("EXPLICIT_RESTORE_INTENT", self.source)
        self.assertIn("exact_reverse_argv", self.source)

    def test_single_staged_retirement_sentinel_is_the_only_legacy_gate(self):
        self.assertIn(
            'LEGACY_RETIREMENT_RESERVATION = (\n'
            '    "/run/wg-mix-ebpf-source-stages/c8e41d73/realhost-v6-6bd913ac"',
            self.source,
        )
        self.assertIn('"accepted_state": "exact-empty-sentinel-only"', self.source)
        self.assertIn('"creator": "root-stager-o-creat-o-excl"', self.source)
        self.assertIn("metadata.st_nlink != 1", self.source)
        self.assertIn("metadata.st_size != 0", self.source)
        self.assertIn("current.st_ino", self.source)
        for retired in (
            "legacy_git_argv",
            "legacy owner",
            "legacy bundle",
            "legacy completed marker",
            "legacy restored marker",
            "LEGACY_SOURCE",
        ):
            self.assertNotIn(retired, self.source)

    def test_retirement_sentinel_is_checked_inside_the_outer_lock_before_all_modes(self):
        start = self.source.index("def execute_with_physical_authority(")
        end = self.source.index("\ndef plan_mode(", start)
        body = self.source[start:end]
        lock = body.index("with PhysicalInterfaceLock(physical_interface_lock_path()):")
        reservation = body.index("validate_legacy_retirement_reservation()")
        mode = body.index('if mode == "plan":')
        plan_read = body.index("read_approved_plan(")
        execute = body.index("execute_validated_plan(")
        self.assertLess(lock, reservation)
        self.assertLess(reservation, mode)
        self.assertLess(reservation, plan_read)
        self.assertLess(reservation, execute)

        controller_start = self.source.index("def controller_approved_mode(")
        controller_end = self.source.index("\ndef validate_plan_shape(", controller_start)
        controller = self.source[controller_start:controller_end]
        self.assertLess(
            controller.index("with PhysicalInterfaceLock(physical_interface_lock_path()):"),
            controller.index("validate_legacy_retirement_reservation()"),
        )
        self.assertLess(
            controller.index("validate_legacy_retirement_reservation()"),
            controller.index("read_controller_approved_plan("),
        )

    def test_controller_cli_has_no_dynamic_compatibility_arguments(self):
        start = self.source.index("def parser()")
        end = self.source.index("\ndef reject_ambiguous_cli", start)
        body = self.source[start:end]
        self.assertIn('child.add_argument("--source-commit", required=True)', body)
        self.assertIn('child.add_argument("--approved-plan", required=True)', body)
        self.assertIn('child.add_argument("--approved-plan-sha256", required=True)', body)
        for retired in (
            "--run-id",
            "--run-root",
            "--interface",
            "--expected-ifindex",
            "--expected-mac",
            "--expected-driver",
            "--expected-mtu",
            "--expected-boot-id",
            "--peer-address",
            "--profile",
            "--mtu-low",
        ):
            self.assertNotIn(retired, body)

    def test_one_root_plan_authority_and_one_validated_execution_core(self):
        self.assertIn(
            'APPROVED_PLAN_PATH = "/run/wg-mix-ebpf-source-bootstrap-c8e41d73/'
            'realnic-approved-plan.json"',
            self.source,
        )
        self.assertEqual(self.source.count("with InterfaceLease("), 1)
        start = self.source.index("def read_controller_approved_plan(")
        end = self.source.index("\ndef controller_plan_mode(", start)
        body = self.source[start:end]
        self.assertIn("if path_value != APPROVED_PLAN_PATH:", body)
        self.assertIn("require_root_owned=True", body)
        self.assertIn("controller_spec_from_plan(plan, source_commit)", body)


if __name__ == "__main__":
    unittest.main()
