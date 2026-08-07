#!/usr/bin/env python3
import hashlib
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


INSTALL_BIN = "/usr/bin/install"
APPROVED_CONTENT = b"reviewed bootstrap input\n"
LARGE_REPLACEMENT_BYTES = 64 * 1024 * 1024


def exact_descriptor_stat(descriptor: int) -> tuple[int, ...]:
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        int(metadata.st_mtime),
        int(metadata.st_ctime),
    )


def hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 64 * 1024, offset)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)
        offset += len(chunk)


class HeldSourceDescriptorRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not os.path.isfile(INSTALL_BIN) or not os.access(INSTALL_BIN, os.X_OK):
            raise unittest.SkipTest("fixed /usr/bin/install is unavailable")
        if os.path.isdir("/proc/self/fd"):
            cls.fd_directory = "/proc/self/fd"
        elif os.path.isdir("/dev/fd"):
            cls.fd_directory = "/dev/fd"
        else:
            raise unittest.SkipTest("descriptor filesystem is unavailable")

    def install_after_path_replacement(self, replacement: str) -> None:
        with tempfile.TemporaryDirectory(
            prefix="wg-mix-ebpf-held-source-"
        ) as temporary_directory:
            root = pathlib.Path(temporary_directory)
            source = root / "approved-source"
            retained = root / "approved-source-retained"
            destination = root / "root-copy"
            source.write_bytes(APPROVED_CONTENT)
            descriptor = os.open(source, os.O_RDONLY)
            try:
                approved_stat = exact_descriptor_stat(descriptor)
                approved_sha256 = hash_descriptor(descriptor)
                os.rename(source, retained)
                if replacement == "fifo":
                    os.mkfifo(source, 0o600)
                    self.assertTrue(stat.S_ISFIFO(os.lstat(source).st_mode))
                elif replacement == "large":
                    replacement_fd = os.open(
                        source,
                        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                        0o600,
                    )
                    try:
                        os.ftruncate(replacement_fd, LARGE_REPLACEMENT_BYTES)
                    finally:
                        os.close(replacement_fd)
                    self.assertEqual(
                        os.lstat(source).st_size,
                        LARGE_REPLACEMENT_BYTES,
                    )
                else:
                    self.fail(f"unknown replacement kind: {replacement}")

                fd_path = f"{self.fd_directory}/{descriptor}"
                completed = subprocess.run(
                    [INSTALL_BIN, "-m", "0600", fd_path, str(destination)],
                    pass_fds=(descriptor,),
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(destination.read_bytes(), APPROVED_CONTENT)
                self.assertEqual(
                    stat.S_IMODE(destination.stat().st_mode),
                    0o600,
                )
                self.assertEqual(
                    exact_descriptor_stat(descriptor),
                    approved_stat,
                )
                self.assertEqual(
                    hash_descriptor(descriptor),
                    approved_sha256,
                )
                self.assertEqual(
                    approved_sha256,
                    hashlib.sha256(APPROVED_CONTENT).hexdigest(),
                )
            finally:
                os.close(descriptor)

    def test_fifo_path_replacement_is_not_reopened(self) -> None:
        self.install_after_path_replacement("fifo")

    def test_large_path_replacement_is_not_reopened(self) -> None:
        self.install_after_path_replacement("large")


if __name__ == "__main__":
    unittest.main()
