#!/usr/bin/python3
from __future__ import annotations

import importlib.util
import contextlib
import hashlib
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock


RECOVERY_PATH = pathlib.Path(__file__).with_name(
    "recover-smoke-netns-wg-failed-run.py"
)
SPEC = importlib.util.spec_from_file_location("smoke_failed_recovery", RECOVERY_PATH)
assert SPEC is not None and SPEC.loader is not None
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)


class FailedSmokeRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("receipt ownership tests require root")

    @staticmethod
    def write_file(path: pathlib.Path, payload: bytes, mode: int = 0o600) -> None:
        path.write_bytes(payload)
        path.chmod(mode)

    def build_run_fixture(
        self, parent: pathlib.Path, *, include_xor_password: bool = True
    ) -> tuple[pathlib.Path, dict[str, str], list[str]]:
        run_id = "0123abcd"
        failed_commit = "2" * 40
        owner_token = "1" * 32
        boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
        root = parent / run_id
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        child_dirs = (
            "pin-owners",
            "pin-locks",
            "bpffs",
            "secrets",
            "evidence",
            "state-a",
            "state-b",
            "run-a",
            "run-b",
        )
        for name in child_dirs:
            child = root / name
            child.mkdir(mode=0o700)
            child.chmod(0o700)

        manifest = {
            "format": "wg-mix-ebpf-test-manifest-v2",
            "run_id": run_id,
            "run_base": str(root),
            "bpffs": str(root / "bpffs"),
            "bpffs_source": "wg-mix-ebpf-unit-0123abcd",
            "pin_lock_root": str(root / "pin-locks"),
            "pin_owner_root": str(root / "pin-owners"),
            "evidence": str(root / "evidence"),
            "secrets": str(root / "secrets"),
            "owner_token": owner_token,
            "boot_id": boot_id,
            "host": "ubuntu-2604-test",
            "pin_resource_key_a": "unit-resource-a",
            "pin_resource_key_b": "unit-resource-b",
            "netns_a_dev": "9223372036854775001",
            "netns_a_ino": "9223372036854775101",
            "netns_r_dev": "9223372036854775002",
            "netns_r_ino": "9223372036854775102",
            "netns_b_dev": "9223372036854775003",
            "netns_b_ino": "9223372036854775103",
        }
        manifest_payload = "".join(
            f"{key}={value}\n" for key, value in manifest.items()
        ).encode()
        self.write_file(root / "manifest", manifest_payload)
        self.write_file(root / "bpffs.creation.v1", b"unit-bpffs\n")
        self.write_file(root / "lifecycle.lease", b"unit-lease\n")

        def owner(role: str) -> bytes:
            return (
                "format=wg-mix-ebpf-test-owner-v1\n"
                f"run_id={run_id}\n"
                f"owner_token={owner_token}\n"
                f"boot_id={boot_id}\n"
                f"role={role}\n"
            ).encode()

        self.write_file(root / ".wg-mix-ebpf-test-owner", owner("root"))
        roles = {
            "pin-owners": "pin-owners",
            "pin-locks": "pin-locks",
            "secrets": "secrets",
            "evidence": "evidence",
            "state-a": "state-a",
            "state-b": "state-b",
            "run-a": "run-a",
            "run-b": "run-b",
        }
        for dirname, role in roles.items():
            self.write_file(
                root / dirname / ".wg-mix-ebpf-test-owner", owner(role)
            )

        secret_names = [
            "netns-anchor-token",
            "a.key",
            "a.pub",
            "b.key",
            "b.pub",
            "wg-a.conf",
            "wg-b.conf",
            "agent-a.yaml",
            "agent-b.yaml",
        ]
        if include_xor_password:
            secret_names.append("xor-password")
        for name in secret_names:
            self.write_file(root / "secrets" / name, f"unit-{name}\n".encode())
        for role in ("a", "b"):
            self.write_file(root / f"state-{role}" / "attach-state.json", b"{}\n")
            self.write_file(root / f"run-{role}" / "lock", b"unit-lock\n")
        for resource in ("unit-resource-a", "unit-resource-b"):
            self.write_file(root / "pin-locks" / f"{resource}.lock", b"lock\n")
            self.write_file(
                root / "pin-owners" / f"{resource}.owner.json", b"{}\n"
            )
        self.write_file(root / "pin-owners" / "instances.v2.json", b"{}\n")

        for role in ("a", "b"):
            status = {
                "client_build": {"source_commit": failed_commit},
                "role": role,
            }
            self.write_file(
                root / "evidence" / f"status-{role}-before.json",
                (json.dumps(status, sort_keys=True) + "\n").encode(),
            )
        for role in ("a", "r", "b"):
            ready = (
                "format=wg-mix-ebpf-netns-anchor-v1\n"
                f"run_id={run_id}\n"
                f"role={role}\n"
                "anchor_pid=99999999\n"
            ).encode()
            self.write_file(root / "evidence" / f"netns-anchor-{role}.ready", ready)
        self.write_file(root / "evidence" / "sample.txt", b"owned-sample\n")

        script_sha = hashlib.sha256(RECOVERY_PATH.read_bytes()).hexdigest()
        manifest_sha = hashlib.sha256(manifest_payload).hexdigest()
        argv = [
            str(RECOVERY_PATH),
            "plan",
            "--run-id",
            run_id,
            "--manifest-sha256",
            manifest_sha,
            "--failed-source-commit",
            failed_commit,
            "--script-sha256",
            script_sha,
        ]
        return root, manifest, argv

    @staticmethod
    def snapshot(root: pathlib.Path) -> list[tuple[object, ...]]:
        result: list[tuple[object, ...]] = []
        for path in sorted((root, *root.rglob("*")), key=str):
            info = path.lstat()
            relative = "." if path == root else str(path.relative_to(root))
            digest = ""
            if stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result.append(
                (
                    relative,
                    stat.S_IFMT(info.st_mode),
                    stat.S_IMODE(info.st_mode),
                    info.st_uid,
                    info.st_gid,
                    info.st_nlink,
                    info.st_size,
                    digest,
                )
            )
        return result

    @contextlib.contextmanager
    def recovery_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            parent.chmod(0o700)
            previous = RECOVERY.TEST_PARENT
            RECOVERY.TEST_PARENT = parent
            try:
                yield parent
            finally:
                RECOVERY.TEST_PARENT = previous

    def run_main(self, argv: list[str]) -> tuple[str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(stderr):
            RECOVERY.main()
        return stdout.getvalue(), stderr.getvalue()

    def test_receipt_publish_recovers_partial_and_double_name_states(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            parent.chmod(0o700)
            previous = RECOVERY.TEST_PARENT
            RECOVERY.TEST_PARENT = parent
            try:
                payload = b'{"format":"unit","value":1}\n'
                pending, final = RECOVERY.receipt_paths("0123abcd")
                RECOVERY.publish_receipt(payload, "0123abcd")
                self.assertEqual(final.read_bytes(), payload)
                self.assertFalse(pending.exists())

                os.link(final, pending)
                self.assertEqual(final.stat().st_nlink, 2)
                RECOVERY.publish_receipt(payload, "0123abcd")
                self.assertFalse(pending.exists())
                self.assertEqual(final.stat().st_nlink, 1)

                final.unlink()
                pending.write_bytes(payload[:7])
                pending.chmod(0o600)
                RECOVERY.publish_receipt(payload, "0123abcd")
                self.assertEqual(final.read_bytes(), payload)
                self.assertFalse(pending.exists())
            finally:
                RECOVERY.TEST_PARENT = previous

    def test_recorded_inventory_allows_only_missing_not_new_or_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "run"
            evidence = root / "evidence"
            evidence.mkdir(parents=True, mode=0o700)
            root.chmod(0o700)
            evidence.chmod(0o700)
            sample = evidence / "sample.txt"
            sample.write_bytes(b"owned-evidence\n")
            sample.chmod(0o600)
            recorded = RECOVERY.tree_inventory(root, [sample])
            RECOVERY.preflight_inventory(root, [sample], recorded)

            sample.unlink()
            RECOVERY.preflight_inventory(root, [], recorded)

            replacement = evidence / "sample.txt"
            replacement.write_bytes(b"foreign-value\n")
            replacement.chmod(0o600)
            with self.assertRaises(SystemExit):
                RECOVERY.preflight_inventory(root, [replacement], recorded)

            replacement.unlink()
            extra = evidence / "allowed-name.txt"
            extra.write_bytes(b"new-entry\n")
            extra.chmod(0o600)
            with self.assertRaises(SystemExit):
                RECOVERY.preflight_inventory(root, [extra], recorded)

    def test_proc_wide_mount_and_netns_scans_reject_live_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            proc = base / "proc"
            process = proc / "123" / "ns"
            process.mkdir(parents=True)
            root = pathlib.Path("/run/wg-mix-ebpf-tests/0123abcd")
            (proc / "123" / "mountinfo").write_text(
                "10 1 0:10 / /run/wg-mix-ebpf-tests/0123abcd/bpffs rw - "
                "bpf wg-mix-ebpf-0123abcd-token rw\n",
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                RECOVERY.assert_no_live_mount(
                    root, "wg-mix-ebpf-0123abcd-token", proc
                )

            (proc / "123" / "mountinfo").write_text(
                "10 1 0:10 / /unrelated rw - tmpfs tmpfs rw\n",
                encoding="utf-8",
            )
            net = process / "net"
            net.write_bytes(b"")
            info = net.stat()
            manifest = {
                "netns_a_dev": str(info.st_dev),
                "netns_a_ino": str(info.st_ino),
                "netns_r_dev": str(info.st_dev),
                "netns_r_ino": str(info.st_ino + 1),
                "netns_b_dev": str(info.st_dev),
                "netns_b_ino": str(info.st_ino + 2),
            }
            with self.assertRaises(SystemExit):
                RECOVERY.assert_no_live_netns(manifest, proc)

    def test_main_plan_is_no_write_and_run_recovers_after_interruption(self) -> None:
        with self.recovery_parent() as parent:
            root, _manifest, plan_argv = self.build_run_fixture(parent)
            before = self.snapshot(parent)
            stdout, stderr = self.run_main(plan_argv)
            self.assertEqual(stderr, "")
            self.assertIn("SMOKE_RECOVERY_PLAN", stdout)
            self.assertIn("mutation=0", stdout)
            self.assertEqual(self.snapshot(parent), before)

            run_argv = list(plan_argv)
            run_argv[1] = "run"
            real_unlink = os.unlink
            interrupted = False

            def unlink_then_interrupt(path, *args, **kwargs):
                nonlocal interrupted
                target = pathlib.Path(path)
                real_unlink(path, *args, **kwargs)
                try:
                    target.relative_to(root)
                except ValueError:
                    return
                if not interrupted:
                    interrupted = True
                    raise RuntimeError("injected-after-first-root-unlink")

            with mock.patch.object(RECOVERY.os, "unlink", unlink_then_interrupt):
                with self.assertRaisesRegex(
                    RuntimeError, "injected-after-first-root-unlink"
                ):
                    self.run_main(run_argv)
            _pending, final = RECOVERY.receipt_paths("0123abcd")
            self.assertTrue(interrupted)
            self.assertTrue(final.exists())
            self.assertTrue(root.exists())

            stdout, stderr = self.run_main(run_argv)
            self.assertEqual(stderr, "")
            self.assertIn("SMOKE_RECOVERY_COMPLETE", stdout)
            self.assertFalse(root.exists())
            self.assertFalse(final.exists())

    def test_main_plan_accepts_non_xor_secret_set_without_writing(self) -> None:
        with self.recovery_parent() as parent:
            _root, _manifest, plan_argv = self.build_run_fixture(
                parent, include_xor_password=False
            )
            before = self.snapshot(parent)
            stdout, stderr = self.run_main(plan_argv)
            self.assertEqual(stderr, "")
            self.assertIn("SMOKE_RECOVERY_PLAN", stdout)
            self.assertEqual(self.snapshot(parent), before)

    def test_main_retry_rejects_new_allowed_name_before_another_write(self) -> None:
        with self.recovery_parent() as parent:
            root, _manifest, plan_argv = self.build_run_fixture(parent)
            run_argv = list(plan_argv)
            run_argv[1] = "run"
            real_unlink = os.unlink
            interrupted = False

            def unlink_then_interrupt(path, *args, **kwargs):
                nonlocal interrupted
                target = pathlib.Path(path)
                real_unlink(path, *args, **kwargs)
                try:
                    target.relative_to(root)
                except ValueError:
                    return
                if not interrupted:
                    interrupted = True
                    raise RuntimeError("injected-before-foreign-entry")

            with mock.patch.object(RECOVERY.os, "unlink", unlink_then_interrupt):
                with self.assertRaisesRegex(RuntimeError, "injected-before-foreign-entry"):
                    self.run_main(run_argv)
            foreign = root / "evidence" / "foreign-allowed-name.txt"
            self.write_file(foreign, b"not-recorded\n")
            before_retry = self.snapshot(parent)
            with self.assertRaises(SystemExit) as stopped:
                self.run_main(run_argv)
            self.assertEqual(stopped.exception.code, 79)
            self.assertEqual(self.snapshot(parent), before_retry)

            foreign.unlink()
            stdout, stderr = self.run_main(run_argv)
            self.assertEqual(stderr, "")
            self.assertIn("SMOKE_RECOVERY_COMPLETE", stdout)
            self.assertFalse(root.exists())

    def test_main_lock_contention_preserves_root_and_receipt_for_retry(self) -> None:
        with self.recovery_parent() as parent:
            root, _manifest, plan_argv = self.build_run_fixture(parent)
            run_argv = list(plan_argv)
            run_argv[1] = "run"
            lease_fd = os.open(root / "lifecycle.lease", os.O_RDONLY | os.O_CLOEXEC)
            try:
                RECOVERY.fcntl.flock(
                    lease_fd, RECOVERY.fcntl.LOCK_EX | RECOVERY.fcntl.LOCK_NB
                )
                root_before = self.snapshot(root)
                with self.assertRaises(SystemExit) as stopped:
                    self.run_main(run_argv)
                self.assertEqual(stopped.exception.code, 79)
                self.assertEqual(self.snapshot(root), root_before)
                _pending, final = RECOVERY.receipt_paths("0123abcd")
                self.assertTrue(final.exists())
            finally:
                RECOVERY.fcntl.flock(lease_fd, RECOVERY.fcntl.LOCK_UN)
                os.close(lease_fd)
            stdout, stderr = self.run_main(run_argv)
            self.assertEqual(stderr, "")
            self.assertIn("SMOKE_RECOVERY_COMPLETE", stdout)

    def test_main_revalidates_after_lock_before_first_root_unlink(self) -> None:
        with self.recovery_parent() as parent:
            root, _manifest, plan_argv = self.build_run_fixture(parent)
            run_argv = list(plan_argv)
            run_argv[1] = "run"
            original_flock = RECOVERY.fcntl.flock
            injected = root / "evidence" / "foreign-after-lock.txt"

            def flock_then_inject(descriptor: int, operation: int):
                result = original_flock(descriptor, operation)
                if operation & RECOVERY.fcntl.LOCK_EX and not injected.exists():
                    self.write_file(injected, b"foreign-after-lock\n")
                return result

            with mock.patch.object(RECOVERY.fcntl, "flock", flock_then_inject):
                with self.assertRaises(SystemExit) as stopped:
                    self.run_main(run_argv)
            self.assertEqual(stopped.exception.code, 79)
            self.assertTrue((root / "secrets" / "wg-b.conf").exists())
            self.assertTrue((root / "manifest").exists())
            self.assertTrue(injected.exists())

            injected.unlink()
            stdout, stderr = self.run_main(run_argv)
            self.assertEqual(stderr, "")
            self.assertIn("SMOKE_RECOVERY_COMPLETE", stdout)

    def test_main_holds_lease_through_lease_unlink_and_root_rmdir(self) -> None:
        with self.recovery_parent() as parent:
            root, _manifest, plan_argv = self.build_run_fixture(parent)
            run_argv = list(plan_argv)
            run_argv[1] = "run"
            real_unlink = os.unlink
            real_rmdir = os.rmdir
            contender_fd = os.open(
                root / "lifecycle.lease", os.O_RDONLY | os.O_CLOEXEC
            )
            observed_unlink_locked = False
            observed_rmdir_locked = False

            def recovery_holds_lock() -> bool:
                try:
                    RECOVERY.fcntl.flock(
                        contender_fd,
                        RECOVERY.fcntl.LOCK_EX | RECOVERY.fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    return True
                RECOVERY.fcntl.flock(contender_fd, RECOVERY.fcntl.LOCK_UN)
                return False

            def tracked_unlink(path, *args, **kwargs):
                nonlocal observed_unlink_locked
                if pathlib.Path(path) == root / "lifecycle.lease":
                    observed_unlink_locked = recovery_holds_lock()
                return real_unlink(path, *args, **kwargs)

            def tracked_rmdir(path, *args, **kwargs):
                nonlocal observed_rmdir_locked
                if pathlib.Path(path) == root:
                    observed_rmdir_locked = recovery_holds_lock()
                return real_rmdir(path, *args, **kwargs)

            try:
                with mock.patch.object(
                    RECOVERY.os, "unlink", tracked_unlink
                ), mock.patch.object(RECOVERY.os, "rmdir", tracked_rmdir):
                    stdout, stderr = self.run_main(run_argv)
                lock_released = not recovery_holds_lock()
                if not lock_released:
                    RECOVERY.fcntl.flock(contender_fd, RECOVERY.fcntl.LOCK_UN)
            finally:
                os.close(contender_fd)
            self.assertEqual(stderr, "")
            self.assertIn("SMOKE_RECOVERY_COMPLETE", stdout)
            self.assertTrue(observed_unlink_locked)
            self.assertTrue(observed_rmdir_locked)
            self.assertTrue(lock_released)


if __name__ == "__main__":
    unittest.main()
