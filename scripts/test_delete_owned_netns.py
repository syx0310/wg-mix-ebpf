#!/usr/bin/env python3
"""Unprivileged tests for the final network namespace delete boundary."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest


HELPER_PATH = pathlib.Path(__file__).with_name("delete-owned-netns.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "delete_owned_netns",
    HELPER_PATH,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {HELPER_PATH}")
HELPER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HELPER
SPEC.loader.exec_module(HELPER)


class DeleteOwnedNetNSTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wg-mix-ebpf-netns-delete."
        )
        self.addCleanup(self.temporary.cleanup)
        self.netns_root = pathlib.Path(self.temporary.name).resolve()
        self.name = "wme01234567a"
        self.target = self.netns_root / self.name
        self.target.write_bytes(b"original")
        metadata = self.target.stat()
        self.expected_device = metadata.st_dev
        self.expected_inode = metadata.st_ino

    def invoke(
        self,
        *,
        delete_runner,
        before_final_recheck=None,
    ) -> None:
        HELPER.delete_owned_netns(
            netns_root=self.netns_root,
            name=self.name,
            run_id="01234567",
            role="a",
            expected_device=self.expected_device,
            expected_inode=self.expected_inode,
            delete_runner=delete_runner,
            before_final_recheck=before_final_recheck,
        )

    def test_same_name_swap_before_final_recheck_fails_without_delete(
        self,
    ) -> None:
        delete_calls: list[str] = []

        def replace_target() -> None:
            os.unlink(self.target)
            self.target.write_bytes(b"replacement")

        with self.assertRaisesRegex(
            HELPER.ContractError,
            "pathname identity changed before delete",
        ):
            self.invoke(
                delete_runner=lambda name: delete_calls.append(name) or 0,
                before_final_recheck=replace_target,
            )
        self.assertEqual([], delete_calls)
        self.assertEqual(b"replacement", self.target.read_bytes())

    def test_exact_target_delete_and_absence_check_succeed(self) -> None:
        delete_calls: list[str] = []

        def delete_target(name: str) -> int:
            delete_calls.append(name)
            os.unlink(self.target)
            return 0

        self.invoke(delete_runner=delete_target)
        self.assertEqual([self.name], delete_calls)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
