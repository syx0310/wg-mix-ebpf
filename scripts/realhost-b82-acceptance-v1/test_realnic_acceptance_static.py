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

    def function_node(self, name: str) -> ast.FunctionDef:
        matches = [
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        self.assertEqual(len(matches), 1, name)
        return matches[0]

    def function_source(self, name: str) -> str:
        value = ast.get_source_segment(self.source, self.function_node(name))
        self.assertIsNotNone(value, name)
        return value

    def assert_function_fragments_ordered(self, name: str, fragments: tuple[str, ...]) -> None:
        body = self.function_source(name)
        cursor = 0
        for fragment in fragments:
            location = body.find(fragment, cursor)
            self.assertNotEqual(location, -1, f"{name}: {fragment}")
            cursor = location + len(fragment)

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

    def test_only_exact_pending_name_unlink_is_allowed(self):
        unlink_attributes = [
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Attribute) and node.attr == "unlink"
        ]
        unlink_calls = [
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "unlink"
        ]
        self.assertEqual(len(unlink_attributes), 1)
        self.assertEqual(len(unlink_calls), 1)
        call = unlink_calls[0]
        self.assertIs(unlink_attributes[0], call.func)

        publisher = self.function_node("publish_local_plan")
        self.assertIn(call, list(ast.walk(publisher)))
        self.assertEqual(len(call.args), 1)
        self.assertIsInstance(call.args[0], ast.Name)
        self.assertEqual(call.args[0].id, "pending_name")
        self.assertEqual(len(call.keywords), 1)
        self.assertEqual(call.keywords[0].arg, "dir_fd")
        self.assertIsInstance(call.keywords[0].value, ast.Name)
        self.assertEqual(call.keywords[0].value.id, "directory")

        forbidden_attributes = {"remove", "rmdir", "removedirs", "renames"}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, forbidden_attributes)

    def test_pending_unlink_is_between_exact_pre_and_post_publish_gates(self):
        publisher = self.function_node("publish_local_plan")
        unlink_index = next(
            index
            for index, statement in enumerate(publisher.body)
            if any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "unlink"
                for node in ast.walk(statement)
            )
        )
        self.assertGreaterEqual(unlink_index, 3)
        self.assert_function_fragments_ordered(
            "publish_local_plan",
            (
                "os.fsync(directory)\n"
                "    validate_local_package_directory(package_dir, directory, directory_identity)\n"
                "    final = read_local_plan_at(directory, name, payload, expected_links=2)\n"
                "    pending = read_local_plan_at(directory, pending_name, payload, expected_links=2)",
                "if (final.st_dev, final.st_ino) != identity or "
                "(pending.st_dev, pending.st_ino) != identity:",
                'raise HarnessError("local plan post-link identity drifted before pending removal")',
                "os.unlink(pending_name, dir_fd=directory)",
                "os.fsync(directory)\n"
                "    validate_local_package_directory(package_dir, directory, directory_identity)\n"
                "    if local_lstat_at(directory, pending_name) is not None:",
                'raise HarnessError("local plan pending name remains after exact unlink")',
                "final = read_local_plan_at(directory, name, payload)",
                "if (final.st_dev, final.st_ino) != identity:",
                'raise HarnessError("local plan final identity drifted after durable publication")',
                "return path, already_present",
            ),
        )

        reader = self.function_node("read_local_plan_at")
        self.assertEqual(len(reader.args.kwonlyargs), 1)
        self.assertEqual(reader.args.kwonlyargs[0].arg, "expected_links")
        self.assertEqual(ast.literal_eval(reader.args.kw_defaults[0]), 1)
        self.assertIn("metadata.st_nlink != expected_links", self.function_source("read_local_plan_at"))

    def test_capture_package_authorities_bind_caller_uid_and_directory_gid(self):
        required_by_function = {
            "validate_local_package_directory": (
                "metadata.st_uid != os.geteuid()",
                "stat.S_IMODE(metadata.st_mode) != 0o700",
            ),
            "load_local_capture_manifest": (
                "manifest_metadata.st_uid != os.geteuid()",
                "manifest_metadata.st_gid != directory_metadata.st_gid",
                "publisher_metadata.st_uid != os.geteuid()",
                "publisher_metadata.st_gid != directory_metadata.st_gid",
            ),
            "revalidate_local_capture_file": (
                "metadata.st_uid != os.geteuid()",
                "metadata.st_gid != package_metadata.st_gid",
            ),
            "read_local_plan_at": (
                "metadata.st_uid != os.geteuid()",
                "metadata.st_gid != package_metadata.st_gid",
            ),
            "complete_local_plan_pending": (
                "metadata.st_uid != os.geteuid()",
                "metadata.st_gid != package_metadata.st_gid",
            ),
        }
        for function_name, required in required_by_function.items():
            body = self.function_source(function_name)
            for value in required:
                with self.subTest(function=function_name, requirement=value):
                    self.assertIn(value, body)
        capture_authority_functions = (
            *required_by_function,
            "publish_local_plan",
            "capture_local_mode",
        )
        for function_name in capture_authority_functions:
            with self.subTest(function=function_name, prohibited="os.getegid"):
                self.assertNotIn("os.getegid()", self.function_source(function_name))

    def test_capture_publish_is_behind_recursive_type_schema_and_live_gates(self):
        capture = self.function_node("capture_local_mode")
        self.assertEqual(len(capture.body), 2)
        self.assertIsInstance(capture.body[1], ast.Try)
        publish_calls = [
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "publish_local_plan"
        ]
        self.assertEqual(len(publish_calls), 1)
        publish_call = publish_calls[0]
        self.assertIn(publish_call, list(ast.walk(capture)))
        self.assertEqual(publish_call.keywords, [])
        self.assertEqual(len(publish_call.args), 5)
        self.assertTrue(all(isinstance(argument, ast.Name) for argument in publish_call.args))
        self.assertEqual(
            [argument.id for argument in publish_call.args],
            ["package_dir", "directory", "directory_identity", "payload", "digest"],
        )
        self.assert_function_fragments_ordered(
            "capture_local_mode",
            (
                "payload = read_capture_candidate()",
                "plan = json.loads(payload)",
                "not isinstance(plan, dict) or canonical_json(plan) != payload",
                'plan.get("schema") != SCHEMA',
                "spec = controller_spec_from_plan(plan, source_commit)",
                "validate_plan_shape(plan, spec, expected_traffic_oracle=expected_oracle)",
                "digest = sha256_bytes(payload)",
                "acquire_local_publish_lock(directory)",
                "revalidate_local_capture_binding(",
                "path, already_present = publish_local_plan(",
                "revalidate_local_capture_binding(",
            ),
        )

        spec_gate = self.function_source("controller_spec_from_plan")
        for value in (
            "isinstance(raw_spec, dict)",
            "set(raw_spec) != names",
            "CoreSpec(**raw_spec).validate()",
            "except TypeError as exc",
            "validate_controller_spec(spec, source_commit)",
        ):
            self.assertIn(value, spec_gate)

        recursive_gate = self.function_source("validate_plan_shape")
        for value in (
            "set(plan) != PLAN_TOP_LEVEL_KEYS",
            "validate_plan_baseline_shape(baseline, spec)",
            "not isinstance(write_set, dict)",
            "not isinstance(filesystem, list)",
            "not isinstance(cells, list)",
            "not isinstance(cell, dict)",
            "not isinstance(steps, list)",
            "plan != expected_plan",
        ):
            self.assertIn(value, recursive_gate)

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
