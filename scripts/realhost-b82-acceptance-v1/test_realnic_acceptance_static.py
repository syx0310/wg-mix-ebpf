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


if __name__ == "__main__":
    unittest.main()
