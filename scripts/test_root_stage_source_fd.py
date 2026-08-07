#!/usr/bin/env python3
import hashlib
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parent
RUNNER = SCRIPTS / "run-root-owned-test-source-stage.sh"
LAUNCHER = SCRIPTS / "stage-root-owned-test-source.sh"
HELPER = SCRIPTS / "stage-root-owned-test-source.py"
MANIFEST = SCRIPTS / "stage-root-owned-test-source.bootstrap"
PROGRAM_VERSION = "1"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
APPROVED_CONTENT = b"reviewed bootstrap input\n"
PYTHON_BIN = "/usr/bin/python3"


def extract_copy_program() -> str:
    runner = RUNNER.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^readonly APPROVED_SOURCE_COPY_PROGRAM='(.*)'\n"
        r"export PATH LC_ALL$",
        runner,
    )
    if match is None:
        raise AssertionError("embedded approved source copy program is missing")
    program = match.group(1)
    compile(program, "APPROVED_SOURCE_COPY_PROGRAM", "exec")
    return program


COPY_PROGRAM = extract_copy_program()


def run_copy(
    source: pathlib.Path,
    approved_sha256: str,
    target: pathlib.Path,
    mode: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            PYTHON_BIN,
            "-I",
            "-B",
            "-c",
            COPY_PROGRAM,
            PROGRAM_VERSION,
            str(source),
            approved_sha256,
            str(target),
            mode,
            str(MAX_SOURCE_BYTES),
        ],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )


class AtomicApprovedSourceCopyRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not os.path.isfile(PYTHON_BIN) or not os.access(PYTHON_BIN, os.X_OK):
            raise unittest.SkipTest("fixed /usr/bin/python3 is unavailable")

    def assert_rejected_before_target_creation(
        self,
        source: pathlib.Path,
        target: pathlib.Path,
        expected_error: str,
    ) -> None:
        completed = run_copy(
            source,
            hashlib.sha256(APPROVED_CONTENT).hexdigest(),
            target,
            "0400",
        )
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("error: approved source copier:", completed.stderr)
        self.assertIn(expected_error, completed.stderr)
        self.assertFalse(os.path.lexists(target))

    def test_fifo_replacement_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wg-mix-ebpf-atomic-open-fifo-"
        ) as temporary_directory:
            root = pathlib.Path(temporary_directory)
            source = root / "approved-source"
            retained = root / "approved-source-retained"
            target = root / "root-copy"
            source.write_bytes(APPROVED_CONTENT)
            os.rename(source, retained)
            os.mkfifo(source, 0o600)
            self.assertTrue(stat.S_ISFIFO(os.lstat(source).st_mode))
            self.assert_rejected_before_target_creation(
                source,
                target,
                "source descriptor is not a regular file",
            )

    def test_device_is_rejected_without_blocking(self) -> None:
        device = pathlib.Path("/dev/null")
        if not device.exists():
            self.skipTest("/dev/null is unavailable")
        with tempfile.TemporaryDirectory(
            prefix="wg-mix-ebpf-atomic-open-device-"
        ) as temporary_directory:
            target = pathlib.Path(temporary_directory) / "root-copy"
            self.assertTrue(stat.S_ISCHR(os.stat(device).st_mode))
            self.assert_rejected_before_target_creation(
                device,
                target,
                "source descriptor is not a regular file",
            )

    def test_oversized_replacement_is_rejected_before_hash_or_copy(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wg-mix-ebpf-atomic-open-large-"
        ) as temporary_directory:
            root = pathlib.Path(temporary_directory)
            source = root / "approved-source"
            retained = root / "approved-source-retained"
            target = root / "root-copy"
            source.write_bytes(APPROVED_CONTENT)
            os.rename(source, retained)
            replacement_fd = os.open(
                source,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            try:
                os.ftruncate(replacement_fd, MAX_SOURCE_BYTES + 1)
            finally:
                os.close(replacement_fd)
            self.assertEqual(os.lstat(source).st_size, MAX_SOURCE_BYTES + 1)
            self.assert_rejected_before_target_creation(
                source,
                target,
                "source descriptor exceeds the approved byte limit",
            )

    def test_normal_launcher_helper_and_manifest_copies(self) -> None:
        sources = (
            (LAUNCHER, "0500"),
            (HELPER, "0400"),
            (MANIFEST, "0400"),
        )
        with tempfile.TemporaryDirectory(
            prefix="wg-mix-ebpf-atomic-open-normal-"
        ) as temporary_directory:
            root = pathlib.Path(temporary_directory)
            for source, mode in sources:
                with self.subTest(source=source.name):
                    target = root / source.name
                    approved_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
                    completed = run_copy(source, approved_sha256, target, mode)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn("version=1", completed.stdout)
                    self.assertEqual(target.read_bytes(), source.read_bytes())
                    self.assertEqual(
                        stat.S_IMODE(target.stat().st_mode),
                        int(mode, 8),
                    )
                    self.assertEqual(target.stat().st_nlink, 1)


if __name__ == "__main__":
    unittest.main()
