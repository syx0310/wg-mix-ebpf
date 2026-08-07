#!/usr/bin/env python3
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HELPER = pathlib.Path(__file__).with_name("hold-isolated-lifecycle-lease.py")
RUN_ID = "01234567"
OWNER_TOKEN = "0123456789abcdef0123456789abcdef"
BOOT_ID = "01234567-89ab-cdef-0123-456789abcdef"


class IsolatedLifecycleLeaseHolderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wg-mix-ebpf-lifecycle-holder."
        )
        self.addCleanup(self.temporary.cleanup)
        self.run_base = pathlib.Path(self.temporary.name).resolve() / RUN_ID
        self.run_base.mkdir(mode=0o700)
        self.run_base.chmod(0o700)
        self.manifest = self.run_base / "manifest"
        self.lease = self.run_base / "lifecycle.lease"
        self.evidence = self.run_base / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.config = self.run_base / "secrets" / "agent-b.yaml"
        self.run_dir = self.run_base / "run-b"
        self.manifest.write_text(
            "\n".join(
                (
                    "format=wg-mix-ebpf-test-manifest-v2",
                    f"run_id={RUN_ID}",
                    f"owner_token={OWNER_TOKEN}",
                    f"boot_id={BOOT_ID}",
                    f"run_base={self.run_base}",
                    f"lifecycle_lease={self.lease}",
                    f"config_b={self.config}",
                    f"run_dir_b={self.run_dir}",
                    f"evidence={self.evidence}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self.manifest.chmod(0o600)
        self.lease.write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "action": "detach",
                    "config_path": str(self.config),
                    "run_dir": str(self.run_dir),
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        self.lease.chmod(0o600)

    def command(self, status_path: pathlib.Path) -> list[str]:
        return [
            sys.executable,
            str(HELPER),
            "--lease",
            str(self.lease),
            "--manifest",
            str(self.manifest),
            "--run-base",
            str(self.run_base),
            "--run-id",
            RUN_ID,
            "--owner-token",
            OWNER_TOKEN,
            "--boot-id",
            BOOT_ID,
            "--expected-config",
            str(self.config),
            "--expected-run-dir",
            str(self.run_dir),
            "--expected-uid",
            str(os.getuid()),
            "--status-path",
            str(status_path),
            "--parent-pid",
            str(os.getpid()),
        ]

    def wait_for_status(
        self,
        process: subprocess.Popen[bytes],
        status_path: pathlib.Path,
        state: str,
    ) -> None:
        expected = f"{state} {process.pid} {OWNER_TOKEN}\n"
        for _ in range(60):
            if status_path.exists():
                self.assertEqual(status_path.read_text(encoding="ascii"), expected)
                return
            if process.poll() is not None:
                break
            time.sleep(0.05)
        stderr = b""
        if process.stderr is not None:
            stderr = process.stderr.read()
        self.fail(
            f"lifecycle holder did not report {state}; "
            f"exit={process.poll()} stderr={stderr!r}"
        )

    def start_holder(
        self,
        status_path: pathlib.Path,
    ) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(
            self.command(status_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.close_process, process)
        self.wait_for_status(process, status_path, "READY")
        return process

    def close_process(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    def release_holder(
        self,
        process: subprocess.Popen[bytes],
        status_path: pathlib.Path,
    ) -> None:
        process.send_signal(signal.SIGUSR1)
        self.assertEqual(process.wait(timeout=3), 0)
        self.assertEqual(
            status_path.read_text(encoding="ascii"),
            f"RELEASED {process.pid} {OWNER_TOKEN}\n",
        )
        assert process.stderr is not None
        process.stderr.close()

    def test_concurrent_holder_fails_closed_then_reacquires_after_release(self) -> None:
        first_status = self.evidence / (
            "lifecycle-holder-" + "0" * 32 + ".status"
        )
        first = self.start_holder(first_status)

        second_status = self.evidence / (
            "lifecycle-holder-" + "1" * 32 + ".status"
        )
        second = subprocess.run(
            self.command(second_status),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
        )
        self.assertNotEqual(second.returncode, 0)
        self.assertIn(b"lifecycle lease is held", second.stderr)

        self.release_holder(first, first_status)
        third_status = self.evidence / (
            "lifecycle-holder-" + "2" * 32 + ".status"
        )
        third = self.start_holder(third_status)
        self.release_holder(third, third_status)

    def test_hard_linked_lease_is_rejected(self) -> None:
        alias = self.run_base / "lease-alias"
        os.link(self.lease, alias)
        result = subprocess.run(
            self.command(
                self.evidence
                / ("lifecycle-holder-" + "3" * 32 + ".status")
            ),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"single-link regular file", result.stderr)

    def test_non_detach_lease_owner_is_rejected(self) -> None:
        self.lease.write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "action": "reload",
                    "config_path": str(self.config),
                    "run_dir": str(self.run_dir),
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            self.command(
                self.evidence
                / ("lifecycle-holder-" + "4" * 32 + ".status")
            ),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"does not match final detach", result.stderr)

    def test_status_outside_manifest_evidence_is_rejected(self) -> None:
        result = subprocess.run(
            self.command(
                self.run_base
                / ("lifecycle-holder-" + "5" * 32 + ".status")
            ),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            b"status directory is not the run evidence directory",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
