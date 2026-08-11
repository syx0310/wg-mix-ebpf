#!/usr/bin/env python3
"""Unprivileged regression tests for the fail-closed named-netns shim."""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
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


class DeleteOwnedNetNSFailClosedTests(unittest.TestCase):
    def test_legacy_api_rejects_before_invoking_any_mutation_hook(self) -> None:
        mutation_calls: list[str] = []

        def forbidden_runner(name: str) -> int:
            mutation_calls.append(name)
            return 0

        with self.assertRaisesRegex(
            HELPER.ContractError,
            "permanently disabled",
        ):
            HELPER.delete_owned_netns(
                netns_root=object(),
                name="wme01234567a",
                run_id="01234567",
                role="a",
                expected_device=1,
                expected_inode=1,
                delete_runner=forbidden_runner,
            )
        self.assertEqual([], mutation_calls)

    def test_cli_is_nonzero_and_reports_no_mutation(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(HELPER_PATH),
                "--name",
                "wme01234567a",
                "--ip-bin",
                "/usr/bin/ip",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(78, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertIn("permanently disabled", completed.stderr)
        self.assertIn("performs no filesystem", completed.stderr)

    def test_shim_contains_no_mutation_implementation(self) -> None:
        source = HELPER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import os",
            "import pathlib",
            "import subprocess",
            "subprocess.run",
            "os.unlink",
            "os.remove",
            "os.rmdir",
            'pathlib.Path("/run/netns")',
            '["ip", "netns", "delete"',
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
