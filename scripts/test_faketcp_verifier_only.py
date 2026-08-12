#!/usr/bin/python3 -I
"""Unprivileged regression tests for the descriptor-only FakeTCP verifier gate."""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import importlib.util
import io
import os
import pathlib
import platform
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
from typing import Optional


def load_runner(path: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("faketcp_verifier_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot create runner module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module


RUNNER_PATH = os.path.abspath(sys.argv[1]) if len(sys.argv) == 2 else ""
if not RUNNER_PATH or not os.path.isfile(RUNNER_PATH):
    raise SystemExit(
        "usage: test_faketcp_verifier_only.py /absolute/path/to/runner.py"
    )
sys.argv = [sys.argv[0]]
runner = load_runner(RUNNER_PATH)


class VerifierGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        evidence_root = tempfile.mkdtemp(
            prefix="wg-mix-faketcp-verifier-selftest."
        )
        cls.evidence_root = os.path.realpath(evidence_root)
        os.chmod(cls.evidence_root, 0o700)
        cls.current_owner = (os.geteuid(), os.getegid())
        cls.test_proc_prefix = "/proc/self/fd" if sys.platform.startswith("linux") else "/dev/fd"

    @classmethod
    def tearDownClass(cls) -> None:
        print(f"retained FakeTCP verifier self-test fixtures: {cls.evidence_root}")

    def new_layout(self, case_name: str):
        case_root = os.path.join(self.evidence_root, case_name)
        prefix = os.path.join(case_root, "wg-mix-ebpf-faketcp-verifier")
        staging_root = os.path.join(prefix, "caseid-01234567")
        artifact_dir = os.path.join(staging_root, "artifacts")
        os.makedirs(artifact_dir, mode=0o700)
        for path in (case_root, prefix, staging_root, artifact_dir):
            os.chmod(path, 0o700)
        owners = frozenset({(0, 0), self.current_owner})
        policy = runner.GatePolicy(
            staging_prefix=prefix,
            hostname=socket.gethostname(),
            kernel_release=platform.release(),
            directory_owners=owners,
            artifact_owner=self.current_owner,
            require_root=False,
            proc_fd_prefix=self.test_proc_prefix,
            timeout_seconds=2.0,
            term_grace_seconds=0.2,
            allow_sticky_ancestor=True,
            verify_descriptor_identity=sys.platform.startswith("linux"),
        )
        binary = os.path.join(artifact_dir, "wg-mix-ebpf")
        bpf_object = os.path.join(artifact_dir, "wg_mix_faketcp_experimental.o")
        return staging_root, binary, bpf_object, policy

    def write_file(self, path: str, content: bytes, mode: int) -> None:
        with open(path, "xb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, mode)

    def digest(self, path: str) -> str:
        value = hashlib.sha256()
        with open(path, "rb") as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                value.update(block)
        return value.hexdigest()

    def arguments(
        self,
        staging_root: str,
        binary: str,
        bpf_object: str,
        binary_sha: Optional[str] = None,
        object_sha: Optional[str] = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(
            staging_root=staging_root,
            binary=binary,
            binary_sha256=binary_sha or self.digest(binary),
            object=bpf_object,
            object_sha256=object_sha or self.digest(bpf_object),
        )

    def ordinary_files(self, case_name: str):
        staging_root, binary, bpf_object, policy = self.new_layout(case_name)
        self.write_file(binary, b"fake-binary\n", 0o700)
        self.write_file(bpf_object, b"fake-object\n", 0o600)
        return staging_root, binary, bpf_object, policy

    def assert_gate_error(self, expected: str, function, *arguments) -> None:
        with self.assertRaisesRegex(runner.GateError, re.escape(expected)):
            function(*arguments)

    def scripted_poll_factory(self, descriptor, script, events):
        class ScriptedPoll:
            def register(_self, registered_descriptor, event_mask):
                events.append(("register", registered_descriptor, event_mask))
                self.assertEqual(registered_descriptor, descriptor)
                self.assertEqual(event_mask, runner.READINESS_POLL_MASK)

            def poll(_self, timeout_milliseconds):
                events.append(("poll", timeout_milliseconds))
                if not script:
                    self.fail("readiness poll exceeded its scripted bound")
                result = script.pop(0)
                if isinstance(result, BaseException):
                    raise result
                if callable(result):
                    return result(timeout_milliseconds)
                return result

        return ScriptedPoll

    def nonblocking_readiness_pipe(self):
        ready_read, ready_write = os.pipe()
        os.set_inheritable(ready_read, False)
        os.set_inheritable(ready_write, False)
        os.set_blocking(ready_read, False)
        return ready_read, ready_write

    def bounded_cleanup_owned_child(self, pid):
        cleanup_deadline = time.monotonic() + 1.0
        signal_sent = False
        while True:
            try:
                waited_pid, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                return
            except OSError as error:
                if error.errno == errno.ECHILD:
                    return
                raise
            if waited_pid == pid:
                return
            if waited_pid != 0:
                self.fail("unexpected child returned during bounded cleanup")
            if not signal_sent:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                signal_sent = True
            if time.monotonic() >= cleanup_deadline:
                self.fail("owned child did not exit within cleanup deadline")
            time.sleep(0.01)

    def test_parse_rejects_missing_and_additional_arguments(self) -> None:
        duplicate = [
            "--runner-sha256",
            "a" * 64,
            "--runner-sha256",
            "b" * 64,
        ]
        for arguments in (
            [],
            ["--test-policy", "unsafe"],
            ["--runner-sha", "a" * 64],
            duplicate,
        ):
            with self.subTest(arguments=arguments):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        runner.parse_args(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_production_identity_and_prefix_are_locked(self) -> None:
        policy = runner.PRODUCTION_POLICY
        self.assertEqual(policy.staging_prefix, "/run/wg-mix-ebpf-faketcp-verifier")
        self.assertEqual(policy.hostname, "ubuntu-2604-test")
        self.assertEqual(policy.kernel_release, "7.0.0-28-generic")
        self.assertEqual(policy.directory_owners, frozenset({(0, 0)}))
        self.assertEqual(policy.artifact_owner, (0, 0))
        self.assertTrue(policy.require_root)
        self.assertEqual(policy.proc_fd_prefix, "/proc/self/fd")
        self.assertTrue(policy.verify_descriptor_identity)
        self.assertEqual(policy.timeout_seconds, 45.0)
        self.assertEqual(policy.term_grace_seconds, 5.0)
        self.assertEqual(runner.KILL_REAP_SECONDS, 5.0)

    def test_production_entry_requires_isolated_python(self) -> None:
        self.assertTrue(sys.flags.isolated)
        self.assertFalse(
            pathlib.Path(RUNNER_PATH).read_text(encoding="utf-8").startswith("#!")
        )
        completed = subprocess.run(
            ["/usr/bin/python3", RUNNER_PATH],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("requires /usr/bin/python3 -I", completed.stderr)

    def test_runner_requires_held_inheritable_hash_pinned_descriptor(self) -> None:
        fixture = os.path.join(self.evidence_root, "reviewed-runner.py")
        self.write_file(fixture, b"reviewed runner fixture\n", 0o600)
        descriptor = os.open(fixture, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            descriptor_prefix = self.test_proc_prefix
            descriptor_path = f"{descriptor_prefix}/{descriptor}"
            digest = self.digest(fixture)
            with self.assertRaisesRegex(runner.GateError, "remain inheritable"):
                runner.require_held_runner_descriptor(
                    descriptor_path,
                    digest,
                    self.current_owner,
                    descriptor_prefix,
                )
            os.set_inheritable(descriptor, True)
            identity = runner.require_held_runner_descriptor(
                descriptor_path,
                digest,
                self.current_owner,
                descriptor_prefix,
            )
            self.assertEqual(identity.sha256, digest)
            self.assertFalse(os.get_inheritable(descriptor))
            os.set_inheritable(descriptor, True)
            with self.assertRaisesRegex(runner.GateError, "SHA-256 mismatch"):
                runner.require_held_runner_descriptor(
                    descriptor_path,
                    "f" * 64,
                    self.current_owner,
                    descriptor_prefix,
                )
        finally:
            os.close(descriptor)

    def test_runner_self_check_is_explicitly_defense_in_depth(self) -> None:
        source = pathlib.Path(RUNNER_PATH).read_text(encoding="utf-8")
        self.assertIn("Defense-in-depth only", source)
        self.assertIn("cannot establish its own initial trust", source)

    def test_hostname_and_kernel_mismatch_are_rejected(self) -> None:
        _, _, _, policy = self.new_layout("system-identity")
        for changed_policy, expected in (
            (dataclass_replace(policy, hostname=policy.hostname + "-wrong"), "hostname mismatch"),
            (
                dataclass_replace(policy, kernel_release=policy.kernel_release + "-wrong"),
                "kernel mismatch",
            ),
        ):
            with self.subTest(expected=expected):
                self.assert_gate_error(
                    expected,
                    runner.require_system_identity,
                    changed_policy,
                )

    def test_reserved_runtime_test_environment_is_rejected(self) -> None:
        for name in (
            "WG_MIX_FAKETCP_VERIFIER_TEST_POLICY",
            "WG_MIX_FAKETCP_VERIFIER_SELF_TEST_TOOL_ROOT",
        ):
            self.assert_gate_error(
                "reserved verifier environment is forbidden",
                runner.reject_reserved_environment,
                {name: "unsafe"},
            )

    def test_staging_root_requires_direct_canonical_unique_id(self) -> None:
        _, _, _, policy = self.new_layout("root-text")
        invalid = (
            policy.staging_prefix,
            policy.staging_prefix + "/short",
            policy.staging_prefix + "/CASEID-01234567",
            policy.staging_prefix + "/caseid-01234567/nested",
            policy.staging_prefix + "/caseid-01234567/..",
        )
        for path in invalid:
            with self.subTest(path=path):
                with self.assertRaises(runner.GateError):
                    runner.validate_staging_root_text(path, policy)

    def test_prefix_escape_is_rejected_before_open(self) -> None:
        staging_root, binary, bpf_object, policy = self.ordinary_files("escape")
        escaping = staging_root + "/../outside/wg-mix-ebpf"
        arguments = self.arguments(staging_root, binary, bpf_object)
        arguments.binary = escaping
        self.assert_gate_error(
            "binary path must be an absolute normalized safe path",
            runner.verify_artifacts,
            arguments,
            policy,
        )

    def test_relative_artifact_path_is_rejected_before_open(self) -> None:
        staging_root, binary, bpf_object, policy = self.ordinary_files("relative")
        arguments = self.arguments(staging_root, binary, bpf_object)
        arguments.object = "relative/object.o"
        self.assert_gate_error(
            "object path must be an absolute normalized safe path",
            runner.verify_artifacts,
            arguments,
            policy,
        )

    def test_group_writable_ancestor_is_rejected(self) -> None:
        staging_root, binary, bpf_object, policy = self.ordinary_files("writable-parent")
        artifact_dir = os.path.dirname(binary)
        os.chmod(artifact_dir, 0o770)
        self.assert_gate_error(
            "group- or other-writable",
            runner.verify_artifacts,
            self.arguments(staging_root, binary, bpf_object),
            policy,
        )

    def test_nonaccepted_owner_ancestor_is_rejected(self) -> None:
        staging_root, binary, bpf_object, policy = self.ordinary_files("owner-parent")
        wrong_policy = dataclass_replace(
            policy,
            directory_owners=frozenset({(os.geteuid() + 1, os.getegid())}),
            allow_sticky_ancestor=False,
        )
        self.assert_gate_error(
            "not owned by an accepted uid:gid",
            runner.verify_artifacts,
            self.arguments(staging_root, binary, bpf_object),
            wrong_policy,
        )

    def test_directory_with_single_link_is_accepted(self) -> None:
        _, _, _, policy = self.new_layout("single-link-directory-metadata")
        metadata = types.SimpleNamespace(
            st_mode=runner.stat.S_IFDIR | 0o700,
            st_uid=self.current_owner[0],
            st_gid=self.current_owner[1],
            st_nlink=1,
        )
        runner.validate_directory_metadata(metadata, "/synthetic-overlay", policy)

    def test_symlink_parent_is_rejected(self) -> None:
        staging_root, _, bpf_object, policy = self.new_layout("symlink-parent")
        real_parent = os.path.join(staging_root, "real-parent")
        alias_parent = os.path.join(staging_root, "alias-parent")
        os.mkdir(real_parent, mode=0o700)
        os.symlink(real_parent, alias_parent)
        binary = os.path.join(alias_parent, "wg-mix-ebpf")
        real_binary = os.path.join(real_parent, "wg-mix-ebpf")
        self.write_file(real_binary, b"binary\n", 0o700)
        self.write_file(bpf_object, b"object\n", 0o600)
        arguments = argparse.Namespace(
            staging_root=staging_root,
            binary=binary,
            binary_sha256=self.digest(real_binary),
            object=bpf_object,
            object_sha256=self.digest(bpf_object),
        )
        with self.assertRaises(OSError):
            runner.verify_artifacts(arguments, policy)

    def test_artifact_owner_mode_hash_and_link_count_are_enforced(self) -> None:
        cases = ("owner", "mode", "hash", "link")
        for case_name in cases:
            with self.subTest(case_name=case_name):
                staging_root, binary, bpf_object, policy = self.ordinary_files(
                    "artifact-" + case_name
                )
                arguments = self.arguments(staging_root, binary, bpf_object)
                expected = ""
                if case_name == "owner":
                    policy = dataclass_replace(
                        policy,
                        artifact_owner=(os.geteuid() + 1, os.getegid()),
                    )
                    expected = "not owned by the required uid:gid"
                elif case_name == "mode":
                    os.chmod(bpf_object, 0o660)
                    expected = "group- or other-writable"
                elif case_name == "hash":
                    arguments.object_sha256 = "f" * 64
                    expected = "SHA-256 mismatch"
                else:
                    os.link(bpf_object, bpf_object + ".second-link")
                    expected = "link count must be exactly one"
                self.assert_gate_error(
                    expected,
                    runner.verify_artifacts,
                    arguments,
                    policy,
                )

    def test_child_argv_is_exact_and_descriptor_only(self) -> None:
        self.assertEqual(
            runner.child_argv("/proc/self/fd/100", "/proc/self/fd/101"),
            (
                "/proc/self/fd/100",
                "bpf-load-test",
                "--faketcp",
                "--object",
                "/proc/self/fd/101",
            ),
        )

    def test_child_deadline_precedes_pipe_and_fork(self) -> None:
        source = pathlib.Path(RUNNER_PATH).read_text(encoding="utf-8")
        child_source = source[source.index("def run_descriptor_child(") :]
        deadline_index = child_source.index("absolute_deadline = time.monotonic()")
        pipe_index = child_source.index("os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)")
        fork_index = child_source.index("os.fork()")
        self.assertLess(deadline_index, pipe_index)
        self.assertLess(pipe_index, fork_index)
        self.assertNotIn("reap_blocking", child_source)

    def test_rename_replacement_cannot_change_verified_execution(self) -> None:
        staging_root, binary, bpf_object, policy = self.new_layout("fd-rename")
        original_binary = b"""#!/bin/sh
test "$#" -eq 4 || exit 71
test "$1" = bpf-load-test || exit 72
test "$2" = --faketcp || exit 73
test "$3" = --object || exit 74
IFS= read -r payload < "$4" || exit 75
test "$payload" = verified-object || exit 76
exit 0
"""
        self.write_file(binary, original_binary, 0o700)
        self.write_file(bpf_object, b"verified-object\n", 0o600)
        arguments = self.arguments(staging_root, binary, bpf_object)
        artifacts = runner.verify_artifacts(arguments, policy)
        try:
            self.assertFalse(os.get_inheritable(artifacts.binary_fd))
            self.assertFalse(os.get_inheritable(artifacts.object_fd))
            os.rename(binary, binary + ".verified")
            os.rename(bpf_object, bpf_object + ".verified")
            self.write_file(binary, b"#!/bin/sh\nexit 88\n", 0o700)
            self.write_file(bpf_object, b"replacement-object\n", 0o600)
            for descriptor, expected in (
                (artifacts.binary_fd, original_binary),
                (artifacts.object_fd, b"verified-object\n"),
            ):
                os.lseek(descriptor, 0, os.SEEK_SET)
                self.assertEqual(os.read(descriptor, len(expected) + 32), expected)
                os.lseek(descriptor, 0, os.SEEK_SET)
                other_descriptor = (
                    artifacts.object_fd
                    if descriptor == artifacts.binary_fd
                    else artifacts.binary_fd
                )
                inherited_fd, other_inherited_fd = runner.duplicate_pair_for_exec(
                    descriptor,
                    other_descriptor,
                )
                try:
                    self.assertTrue(os.get_inheritable(inherited_fd))
                    os.lseek(inherited_fd, 0, os.SEEK_SET)
                    self.assertEqual(os.read(inherited_fd, len(expected) + 32), expected)
                finally:
                    os.close(inherited_fd)
                    os.close(other_inherited_fd)
            if sys.platform.startswith("linux"):
                self.assertEqual(runner.execute_verified(artifacts, policy), 0)
        finally:
            artifacts.close()

    def test_child_return_code_is_preserved(self) -> None:
        pid = os.fork()
        if pid == 0:
            os._exit(23)
        self.assertEqual(runner.wait_with_timeout(pid, 1.0, 0.1), 23)
        if sys.platform.startswith("linux"):
            staging_root, binary, bpf_object, policy = self.new_layout(
                "linux-child-rc"
            )
            self.write_file(binary, b"#!/bin/sh\nexit 23\n", 0o700)
            self.write_file(bpf_object, b"object\n", 0o600)
            artifacts = runner.verify_artifacts(
                self.arguments(staging_root, binary, bpf_object), policy
            )
            try:
                self.assertEqual(runner.execute_verified(artifacts, policy), 23)
            finally:
                artifacts.close()

    def test_pre_setsid_readiness_timeout_directly_kills_child(self) -> None:
        ready_read, ready_write = self.nonblocking_readiness_pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_read)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.setsid()
            os.write(ready_write, runner.READINESS_BYTE)
            os._exit(90)
        os.close(ready_write)
        events = []

        def recording_killpg(group, signal_number):
            events.append(("group", group, signal_number))
            os.killpg(group, signal_number)

        def recording_kill(child, signal_number):
            events.append(("direct", child, signal_number))
            os.kill(child, signal_number)

        try:
            with self.assertRaisesRegex(
                runner.GateError,
                "child readiness deadline expired",
            ):
                runner.wait_for_child_readiness(
                    pid,
                    ready_read,
                    time.monotonic() + 0.1,
                    killpg_function=recording_killpg,
                    kill_function=recording_kill,
                    kill_reap_seconds=1.0,
                )
            self.assertEqual(
                events,
                [("direct", pid, signal.SIGKILL)],
            )
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            os.close(ready_read)
            self.bounded_cleanup_owned_child(pid)

    def test_post_setsid_pre_ready_timeout_kills_group_and_child(self) -> None:
        ready_read, ready_write = self.nonblocking_readiness_pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_read)
            os.setsid()
            os.kill(os.getpid(), signal.SIGSTOP)
            os.write(ready_write, runner.READINESS_BYTE)
            os._exit(90)
        os.close(ready_write)
        setup_deadline = time.monotonic() + 1.0
        while os.getpgid(pid) != pid:
            if time.monotonic() >= setup_deadline:
                self.fail("child did not enter its own process group")
            time.sleep(0.01)
        events = []

        def recording_killpg(group, signal_number):
            events.append(("group", group, signal_number))
            os.killpg(group, signal_number)

        def recording_kill(child, signal_number):
            events.append(("direct", child, signal_number))
            os.kill(child, signal_number)

        try:
            with self.assertRaisesRegex(
                runner.GateError,
                "child readiness deadline expired",
            ):
                runner.wait_for_child_readiness(
                    pid,
                    ready_read,
                    time.monotonic() + 0.1,
                    killpg_function=recording_killpg,
                    kill_function=recording_kill,
                    kill_reap_seconds=1.0,
                )
            self.assertEqual(
                events,
                [
                    ("group", pid, signal.SIGKILL),
                    ("direct", pid, signal.SIGKILL),
                ],
            )
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            os.close(ready_read)
            self.bounded_cleanup_owned_child(pid)

    def test_confirmed_pre_ready_cleanup_order_is_group_direct_reap(self) -> None:
        events = []
        child_killed = False

        def fake_getpgid(pid):
            events.append(("getpgid", pid))
            return pid

        def fake_killpg(pid, signal_number):
            events.append(("group", pid, signal_number))

        def fake_kill(pid, signal_number):
            nonlocal child_killed
            events.append(("direct", pid, signal_number))
            child_killed = True

        def fake_waitpid(pid, flags):
            events.append(("wait", pid, flags))
            return (pid, 0) if child_killed else (0, 0)

        runner.cleanup_pre_ready_child(
            5000,
            waitpid_function=fake_waitpid,
            getpgid_function=fake_getpgid,
            killpg_function=fake_killpg,
            kill_function=fake_kill,
            reap_timeout_seconds=1.0,
            monotonic_function=lambda: 0.0,
            sleep_function=lambda _duration: self.fail(
                "cleanup unexpectedly slept"
            ),
        )
        self.assertEqual(
            events,
            [
                ("getpgid", 5000),
                ("group", 5000, signal.SIGKILL),
                ("direct", 5000, signal.SIGKILL),
                ("wait", 5000, os.WNOHANG),
            ],
        )

    def test_readiness_poll_and_read_errors_cleanup_direct_child(self) -> None:
        for case_name, poll_script, read_function, expected in (
            (
                "poll",
                [OSError(errno.EIO, "injected poll failure")],
                lambda _descriptor, _size: self.fail("unexpected readiness read"),
                "injected poll failure",
            ),
            (
                "read",
                [[(81, runner.select.POLLIN)]],
                lambda _descriptor, _size: (_ for _ in ()).throw(
                    OSError(errno.EIO, "injected read failure")
                ),
                "injected read failure",
            ),
        ):
            with self.subTest(case_name=case_name):
                events = []
                group_killed = False

                def fake_waitpid(pid, flags):
                    events.append(("wait", pid, flags))
                    if group_killed:
                        return pid, 0
                    return 0, 0

                def fake_getpgid(pid):
                    events.append(("getpgid", pid))
                    return pid - 1

                def fake_direct_kill(pid, signal_number):
                    nonlocal group_killed
                    events.append(("direct", pid, signal_number))
                    group_killed = True

                with self.assertRaisesRegex(OSError, expected):
                    runner.wait_for_child_readiness(
                        5001,
                        81,
                        10.0,
                        waitpid_function=fake_waitpid,
                        getpgid_function=fake_getpgid,
                        killpg_function=lambda _pid, _signal: self.fail(
                            "unconfirmed group must not be signaled"
                        ),
                        kill_function=fake_direct_kill,
                        monotonic_function=lambda: 0.0,
                        sleep_function=lambda _duration: self.fail(
                            "cleanup unexpectedly slept"
                        ),
                        poll_factory=self.scripted_poll_factory(
                            81,
                            list(poll_script),
                            events,
                        ),
                        read_function=read_function,
                    )
                self.assertEqual(
                    events[-3:],
                    [
                        ("getpgid", 5001),
                        ("direct", 5001, signal.SIGKILL),
                        ("wait", 5001, os.WNOHANG),
                    ],
                )

    def test_persistent_readiness_eintr_is_bounded_by_absolute_deadline(self) -> None:
        for case_name in ("poll", "read"):
            with self.subTest(case_name=case_name):
                events = []
                now = 0.0
                child_killed = False

                def monotonic():
                    nonlocal now
                    now += 0.4
                    return now

                class InterruptingPoll:
                    def register(_self, descriptor, event_mask):
                        events.append(("register", descriptor, event_mask))

                    def poll(_self, timeout_milliseconds):
                        events.append(("poll", timeout_milliseconds))
                        if case_name == "poll":
                            raise OSError(errno.EINTR, "persistent poll EINTR")
                        return [(84, runner.select.POLLIN)]

                def interrupting_read(_descriptor, _size):
                    events.append(("read",))
                    raise OSError(errno.EINTR, "persistent read EINTR")

                def fake_direct_kill(pid, signal_number):
                    nonlocal child_killed
                    events.append(("direct", pid, signal_number))
                    child_killed = True

                with self.assertRaisesRegex(
                    runner.GateError,
                    "child readiness deadline expired",
                ):
                    runner.wait_for_child_readiness(
                        5004,
                        84,
                        1.0,
                        waitpid_function=lambda pid, flags: (
                            (pid, 0) if child_killed else (0, 0)
                        ),
                        getpgid_function=lambda pid: pid - 1,
                        killpg_function=lambda _pid, _signal: self.fail(
                            "unconfirmed group must not be signaled"
                        ),
                        kill_function=fake_direct_kill,
                        monotonic_function=monotonic,
                        sleep_function=lambda _duration: self.fail(
                            "bounded cleanup unexpectedly slept"
                        ),
                        poll_factory=InterruptingPoll,
                        read_function=interrupting_read,
                        kill_reap_seconds=1.0,
                    )
                operation = "poll" if case_name == "poll" else "read"
                operation_calls = [event for event in events if event[0] == operation]
                self.assertEqual(len(operation_calls), 2)
                self.assertIn(("direct", 5004, signal.SIGKILL), events)

    def test_readiness_close_error_does_not_mask_cleanup_failure(self) -> None:
        events = []
        child_killed = False

        def fake_direct_kill(pid, signal_number):
            nonlocal child_killed
            events.append(("direct", pid, signal_number))
            child_killed = True

        def failing_close(descriptor):
            events.append(("close", descriptor))
            raise OSError(errno.EBADF, "injected close failure")

        with self.assertRaisesRegex(OSError, "injected poll failure"):
            runner.supervise_ready_child(
                5005,
                85,
                10.0,
                0.0,
                waitpid_function=lambda pid, flags: (
                    (pid, 0) if child_killed else (0, 0)
                ),
                getpgid_function=lambda pid: pid - 1,
                killpg_function=lambda _pid, _signal: self.fail(
                    "unconfirmed group must not be signaled"
                ),
                kill_function=fake_direct_kill,
                monotonic_function=lambda: 0.0,
                sleep_function=lambda _duration: self.fail(
                    "cleanup unexpectedly slept"
                ),
                poll_factory=self.scripted_poll_factory(
                    85,
                    [OSError(errno.EIO, "injected poll failure")],
                    events,
                ),
                read_function=lambda _descriptor, _size: self.fail(
                    "unexpected readiness read"
                ),
                close_function=failing_close,
            )
        self.assertIn(("direct", 5005, signal.SIGKILL), events)
        self.assertEqual(events[-1], ("close", 85))

    def test_readiness_eof_and_non_confirmation_are_bounded(self) -> None:
        for payload, expected in (
            (b"", "reached EOF"),
            (b"X", "non-confirmation byte"),
        ):
            with self.subTest(payload=payload):
                events = []
                child_killed = False

                def fake_waitpid(pid, flags):
                    events.append(("wait", pid, flags))
                    self.assertEqual(flags, os.WNOHANG)
                    return (pid, 0) if child_killed else (0, 0)

                def fake_direct_kill(pid, signal_number):
                    nonlocal child_killed
                    events.append(("direct", pid, signal_number))
                    child_killed = True

                with self.assertRaisesRegex(runner.GateError, expected):
                    runner.wait_for_child_readiness(
                        5002,
                        82,
                        10.0,
                        waitpid_function=fake_waitpid,
                        getpgid_function=lambda pid: pid - 1,
                        killpg_function=lambda _pid, _signal: self.fail(
                            "unconfirmed group must not be signaled"
                        ),
                        kill_function=fake_direct_kill,
                        monotonic_function=lambda: 0.0,
                        sleep_function=lambda _duration: self.fail(
                            "cleanup unexpectedly slept"
                        ),
                        poll_factory=self.scripted_poll_factory(
                            82,
                            [[(82, runner.select.POLLIN | runner.select.POLLHUP)]],
                            events,
                        ),
                        read_function=lambda _descriptor, _size: payload,
                    )
                self.assertIn(("direct", 5002, signal.SIGKILL), events)
                self.assertEqual(events[-1], ("wait", 5002, os.WNOHANG))

    def test_readiness_latency_consumes_execution_deadline(self) -> None:
        events = []
        now = 0.0
        child_killed = False

        def monotonic():
            return now

        def readiness_arrives(_timeout_milliseconds):
            nonlocal now
            now = 40.0
            return [(83, runner.select.POLLIN)]

        def fake_waitpid(pid, flags):
            events.append(("wait", now, pid, flags))
            self.assertEqual(flags, os.WNOHANG)
            return (pid, 0) if child_killed else (0, 0)

        def fake_sleep(duration):
            nonlocal now
            events.append(("sleep", now, duration))
            now = 45.0

        def fake_killpg(pid, signal_number):
            nonlocal child_killed
            events.append(("group", now, pid, signal_number))
            if signal_number == signal.SIGKILL:
                child_killed = True

        self.assertEqual(
            runner.supervise_ready_child(
                5003,
                83,
                45.0,
                0.0,
                waitpid_function=fake_waitpid,
                getpgid_function=lambda _pid: self.fail(
                    "confirmed readiness must not probe getpgid"
                ),
                killpg_function=fake_killpg,
                kill_function=lambda _pid, _signal: self.fail(
                    "confirmed group cleanup should not need direct fallback"
                ),
                monotonic_function=monotonic,
                sleep_function=fake_sleep,
                poll_factory=self.scripted_poll_factory(
                    83,
                    [readiness_arrives],
                    events,
                ),
                read_function=lambda _descriptor, _size: runner.READINESS_BYTE,
                close_function=lambda descriptor: events.append(
                    ("close", descriptor)
                ),
                kill_reap_seconds=1.0,
            ),
            124,
        )
        term_events = [
            event
            for event in events
            if event[0] == "group" and event[3] == signal.SIGTERM
        ]
        self.assertEqual(term_events, [("group", 45.0, 5003, signal.SIGTERM)])
        poll_event = next(event for event in events if event[0] == "poll")
        self.assertEqual(poll_event[1], 45_000)

    def test_wait_retries_eintr_and_preserves_child_status(self) -> None:
        calls = []

        def fake_waitpid(pid, flags):
            calls.append((pid, flags))
            if len(calls) == 1:
                raise InterruptedError()
            return pid, 23 << 8

        self.assertEqual(
            runner.wait_with_timeout(
                4321,
                1.0,
                0.1,
                waitpid_function=fake_waitpid,
                monotonic_function=lambda: 0.0,
                sleep_function=lambda _: None,
            ),
            23,
        )
        self.assertEqual(len(calls), 2)

    def test_timeout_esrch_echild_race_is_deterministic(self) -> None:
        wait_calls = []
        signals = []

        def fake_waitpid(pid, flags):
            wait_calls.append((pid, flags))
            if len(wait_calls) == 1:
                return 0, 0
            raise ChildProcessError()

        def missing_group(pid, signal_number):
            signals.append((pid, signal_number))
            raise ProcessLookupError()

        self.assertEqual(
            runner.wait_with_timeout(
                4322,
                0.0,
                0.0,
                waitpid_function=fake_waitpid,
                killpg_function=missing_group,
                monotonic_function=lambda: 0.0,
                sleep_function=lambda _: None,
            ),
            124,
        )
        self.assertEqual(
            signals,
            [(4322, signal.SIGTERM), (4322, signal.SIGKILL)],
        )

    def test_timeout_term_and_kill_esrch_still_returns_124(self) -> None:
        nonblocking_calls = 0
        signals = []
        group_killed = False

        def fake_waitpid(pid, flags):
            nonlocal nonblocking_calls
            if flags == os.WNOHANG:
                nonblocking_calls += 1
                if group_killed:
                    raise ChildProcessError()
                return 0, 0
            raise ChildProcessError()

        def missing_group(pid, signal_number):
            nonlocal group_killed
            signals.append((pid, signal_number))
            if signal_number == signal.SIGKILL:
                group_killed = True
            raise OSError(errno.ESRCH, "no such process group")

        self.assertEqual(
            runner.wait_with_timeout(
                4323,
                0.0,
                0.0,
                waitpid_function=fake_waitpid,
                killpg_function=missing_group,
                monotonic_function=lambda: 0.0,
                sleep_function=lambda _: None,
            ),
            124,
        )
        self.assertEqual(nonblocking_calls, 2)
        self.assertEqual(
            signals,
            [(4323, signal.SIGTERM), (4323, signal.SIGKILL)],
        )

    def test_timeout_keeps_leader_unreaped_until_group_kill(self) -> None:
        events = []
        group_killed = False

        def fake_waitpid(pid, flags):
            events.append(("wait", pid, flags))
            if flags == os.WNOHANG:
                if group_killed:
                    return pid, 0
                return 0, 0
            raise AssertionError("blocking waitpid is forbidden")

        def fake_killpg(pid, signal_number):
            nonlocal group_killed
            events.append(("signal", pid, signal_number))
            if signal_number == signal.SIGKILL:
                group_killed = True

        def fake_sleep(_duration):
            events.append(("sleep",))

        clock = iter((0.0, 0.0, 0.0, 0.0, 0.05, 0.05))
        self.assertEqual(
            runner.wait_with_timeout(
                4325,
                0.0,
                0.05,
                waitpid_function=fake_waitpid,
                killpg_function=fake_killpg,
                monotonic_function=lambda: next(clock),
                sleep_function=fake_sleep,
            ),
            124,
        )
        self.assertEqual(
            events,
            [
                ("wait", 4325, os.WNOHANG),
                ("signal", 4325, signal.SIGTERM),
                ("sleep",),
                ("signal", 4325, signal.SIGKILL),
                ("wait", 4325, os.WNOHANG),
            ],
        )

    def test_timeout_exception_still_kills_group_and_reaps_leader(self) -> None:
        events = []
        group_killed = False

        def fake_waitpid(pid, flags):
            events.append(("wait", pid, flags))
            if flags == os.WNOHANG:
                if group_killed:
                    return pid, 0
                return 0, 0
            raise AssertionError("blocking waitpid is forbidden")

        def fake_killpg(pid, signal_number):
            nonlocal group_killed
            events.append(("signal", pid, signal_number))
            if signal_number == signal.SIGKILL:
                group_killed = True

        def failing_sleep(_duration):
            events.append(("sleep",))
            raise RuntimeError("injected grace failure")

        clock = iter((0.0, 0.0, 0.0, 0.0, 0.0))
        with self.assertRaisesRegex(RuntimeError, "injected grace failure"):
            runner.wait_with_timeout(
                4326,
                0.0,
                0.1,
                waitpid_function=fake_waitpid,
                killpg_function=fake_killpg,
                monotonic_function=lambda: next(clock),
                sleep_function=failing_sleep,
            )
        self.assertEqual(
            events,
            [
                ("wait", 4326, os.WNOHANG),
                ("signal", 4326, signal.SIGTERM),
                ("sleep",),
                ("signal", 4326, signal.SIGKILL),
                ("wait", 4326, os.WNOHANG),
            ],
        )

    def test_wait_exception_still_kills_group_and_reaps_leader(self) -> None:
        events = []
        wait_failed = False
        group_killed = False

        def fake_waitpid(pid, flags):
            nonlocal wait_failed
            events.append(("wait", pid, flags))
            if flags == os.WNOHANG and not wait_failed:
                wait_failed = True
                raise RuntimeError("injected wait failure")
            if flags == os.WNOHANG and group_killed:
                return pid, 0
            raise AssertionError("unexpected waitpid call")

        def fake_killpg(pid, signal_number):
            nonlocal group_killed
            events.append(("signal", pid, signal_number))
            if signal_number == signal.SIGKILL:
                group_killed = True

        with self.assertRaisesRegex(RuntimeError, "injected wait failure"):
            runner.wait_with_timeout(
                4327,
                1.0,
                0.1,
                waitpid_function=fake_waitpid,
                killpg_function=fake_killpg,
                monotonic_function=lambda: 0.0,
                sleep_function=lambda _: None,
            )
        self.assertEqual(
            events,
            [
                ("wait", 4327, os.WNOHANG),
                ("signal", 4327, signal.SIGKILL),
                ("wait", 4327, os.WNOHANG),
            ],
        )

    def test_group_kill_error_uses_leader_fallback_and_bounded_reap(self) -> None:
        events = []

        def denied_group(pid, signal_number):
            events.append(("group", pid, signal_number))
            raise OSError(errno.EPERM, "injected group denial")

        def leader_kill(pid, signal_number):
            events.append(("leader", pid, signal_number))

        def reaped_leader(pid, flags):
            events.append(("wait", pid, flags))
            return pid, 0

        with self.assertRaisesRegex(PermissionError, "injected group denial"):
            runner.kill_group_and_reap(
                4328,
                waitpid_function=reaped_leader,
                killpg_function=denied_group,
                kill_function=leader_kill,
                reap_timeout_seconds=0.1,
                monotonic_function=lambda: 0.0,
                sleep_function=lambda _: None,
            )
        self.assertEqual(
            events,
            [
                ("group", 4328, signal.SIGKILL),
                ("leader", 4328, signal.SIGKILL),
                ("wait", 4328, os.WNOHANG),
            ],
        )

    def test_double_kill_failure_is_bounded_and_fail_closed(self) -> None:
        events = []

        def denied_group(pid, signal_number):
            events.append(("group", pid, signal_number))
            raise OSError(errno.EPERM, "injected group denial")

        def denied_leader(pid, signal_number):
            events.append(("leader", pid, signal_number))
            raise OSError(errno.EPERM, "injected leader denial")

        def still_running(pid, flags):
            events.append(("wait", pid, flags))
            return 0, 0

        clock = iter((0.0, 1.0))
        with self.assertRaisesRegex(
            runner.GateError,
            "fixed cleanup deadline",
        ):
            runner.kill_group_and_reap(
                4329,
                waitpid_function=still_running,
                killpg_function=denied_group,
                kill_function=denied_leader,
                reap_timeout_seconds=0.5,
                monotonic_function=lambda: next(clock),
                sleep_function=lambda _: self.fail("cleanup wait exceeded deadline"),
            )
        self.assertEqual(
            events,
            [
                ("group", 4329, signal.SIGKILL),
                ("leader", 4329, signal.SIGKILL),
                ("wait", 4329, os.WNOHANG),
            ],
        )

    def test_group_signal_retries_eintr(self) -> None:
        calls = []

        def interrupted_then_sent(pid, signal_number):
            calls.append((pid, signal_number))
            if len(calls) == 1:
                raise OSError(errno.EINTR, "injected interruption")

        runner.signal_process_group(4330, signal.SIGKILL, interrupted_then_sent)
        self.assertEqual(
            calls,
            [(4330, signal.SIGKILL), (4330, signal.SIGKILL)],
        )

    def test_echild_before_deadline_has_stable_internal_rc(self) -> None:
        self.assertEqual(
            runner.wait_with_timeout(
                4324,
                1.0,
                0.1,
                waitpid_function=lambda _pid, _flags: (_ for _ in ()).throw(
                    ChildProcessError()
                ),
                monotonic_function=lambda: 0.0,
                sleep_function=lambda _: None,
            ),
            125,
        )

    def test_timeout_returns_124(self) -> None:
        ready_read, ready_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_read)
            os.setsid()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.write(ready_write, b"R")
            os.close(ready_write)
            time.sleep(5)
            os._exit(0)
        os.close(ready_write)
        self.assertEqual(os.read(ready_read, 1), b"R")
        os.close(ready_read)
        self.assertEqual(runner.wait_with_timeout(pid, 0.1, 0.1), 124)
        if sys.platform.startswith("linux"):
            staging_root, binary, bpf_object, policy = self.new_layout(
                "linux-timeout"
            )
            self.write_file(binary, b"#!/bin/sh\n/bin/sleep 5\n", 0o700)
            self.write_file(bpf_object, b"object\n", 0o600)
            policy = dataclass_replace(
                policy,
                timeout_seconds=0.1,
                term_grace_seconds=0.1,
            )
            artifacts = runner.verify_artifacts(
                self.arguments(staging_root, binary, bpf_object), policy
            )
            try:
                self.assertEqual(runner.execute_verified(artifacts, policy), 124)
            finally:
                artifacts.close()

    def test_timeout_terminates_the_child_process_group(self) -> None:
        marker = os.path.join(self.evidence_root, "unexpected-grandchild-marker")
        ready_read, ready_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_read)
            os.setsid()
            grandchild = os.fork()
            if grandchild == 0:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                time.sleep(0.5)
                with open(marker, "xb") as output:
                    output.write(b"survived\n")
                os._exit(0)
            os.write(ready_write, b"R")
            os.close(ready_write)
            time.sleep(5)
            os._exit(0)
        os.close(ready_write)
        self.assertEqual(os.read(ready_read, 1), b"R")
        os.close(ready_read)
        self.assertEqual(runner.wait_with_timeout(pid, 0.1, 0.1), 124)
        time.sleep(0.7)
        self.assertFalse(os.path.exists(marker))

    def test_timeout_kills_term_ignoring_descendant_after_leader_exits(self) -> None:
        marker = os.path.join(
            self.evidence_root,
            "unexpected-term-ignoring-grandchild-marker",
        )
        ready_read, ready_write = os.pipe()
        pid_read, pid_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_read)
            os.close(pid_read)
            os.setsid()
            armed_read, armed_write = os.pipe()
            grandchild = os.fork()
            if grandchild == 0:
                os.close(armed_read)
                os.close(ready_write)
                os.close(pid_write)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                os.write(armed_write, b"A")
                os.close(armed_write)
                time.sleep(0.7)
                with open(marker, "xb") as output:
                    output.write(b"survived\n")
                os._exit(0)
            os.close(armed_write)
            if os.read(armed_read, 1) != b"A":
                os._exit(91)
            os.close(armed_read)
            os.write(pid_write, f"{grandchild}\n".encode("ascii"))
            os.close(pid_write)
            signal.signal(signal.SIGTERM, lambda _signum, _frame: os._exit(0))
            os.write(ready_write, b"R")
            os.close(ready_write)
            time.sleep(5)
            os._exit(0)
        os.close(ready_write)
        os.close(pid_write)
        self.assertEqual(os.read(ready_read, 1), b"R")
        os.close(ready_read)
        grandchild_pid = int(os.read(pid_read, 32).strip())
        os.close(pid_read)
        self.assertEqual(runner.wait_with_timeout(pid, 0.1, 0.2), 124)
        time.sleep(0.8)
        self.assertFalse(os.path.exists(marker))
        with self.assertRaises(ProcessLookupError):
            os.kill(grandchild_pid, 0)

    def test_runner_source_has_no_mutating_host_operations(self) -> None:
        source = pathlib.Path(RUNNER_PATH).read_text(encoding="utf-8")
        self.assertIn("os.setsid()", source)
        self.assertIn("os.killpg", source)
        forbidden = (
            r"\b(?:rm|find|sudo|chroot|nsenter)\b",
            r"\b(?:bpftool|attach|pin|populate)\b",
            r"\bmap\s+(?:create|update|delete|freeze)\b",
            r"\b(?:build|install)\b",
            r"\bos\.(?:remove|unlink|rename|renames)\b",
            r"\bshutil\b",
        )
        for expression in forbidden:
            with self.subTest(expression=expression):
                self.assertIsNone(re.search(expression, source))


def dataclass_replace(policy, **changes):
    return runner.dataclasses.replace(policy, **changes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
