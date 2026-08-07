"""Run the experimental FakeTCP verifier gate from immutable file descriptors."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    sys.stderr.write("error: verifier gate requires /usr/bin/python3 -I\n")
    raise SystemExit(1)

import argparse
import dataclasses
import datetime
import errno
import hashlib
import math
import os
import platform
import posixpath
import re
import select
import shlex
import signal
import socket
import stat
import time
from typing import FrozenSet, Optional, Sequence, Tuple


EXPECTED_HOSTNAME = "ubuntu-2604-test"
EXPECTED_KERNEL_RELEASE = "7.0.0-28-generic"
STAGING_PREFIX = "/run/wg-mix-ebpf-faketcp-verifier"
CHILD_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LOAD_TIMEOUT_SECONDS = 45.0
TERM_GRACE_SECONDS = 5.0
KILL_REAP_SECONDS = 5.0
BINARY_EXEC_FD = 100
OBJECT_EXEC_FD = 101
READINESS_BYTE = b"R"
READINESS_POLL_MASK = (
    select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL
)
MAX_POLL_TIMEOUT_MILLISECONDS = 2_147_483_647
RESERVED_ENV_PREFIX = "WG_MIX_FAKETCP_VERIFIER_"
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./+@-]+")
SAFE_RUN_ID = re.compile(r"[a-z0-9][a-z0-9-]{6,62}[a-z0-9]")
SHA256_TEXT = re.compile(r"[0-9a-f]{64}")


class GateError(RuntimeError):
    """A fail-closed verifier admission error."""


class StoreOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


@dataclasses.dataclass(frozen=True)
class GatePolicy:
    staging_prefix: str
    hostname: str
    kernel_release: str
    directory_owners: FrozenSet[Tuple[int, int]]
    artifact_owner: Tuple[int, int]
    require_root: bool
    proc_fd_prefix: str
    timeout_seconds: float
    term_grace_seconds: float
    allow_sticky_ancestor: bool = False
    verify_descriptor_identity: bool = True


PRODUCTION_POLICY = GatePolicy(
    staging_prefix=STAGING_PREFIX,
    hostname=EXPECTED_HOSTNAME,
    kernel_release=EXPECTED_KERNEL_RELEASE,
    directory_owners=frozenset({(0, 0)}),
    artifact_owner=(0, 0),
    require_root=True,
    proc_fd_prefix="/proc/self/fd",
    timeout_seconds=LOAD_TIMEOUT_SECONDS,
    term_grace_seconds=TERM_GRACE_SECONDS,
)


@dataclasses.dataclass(frozen=True)
class ArtifactIdentity:
    label: str
    original_path: str
    sha256: str
    device: int
    inode: int
    size: int
    mode: int


@dataclasses.dataclass
class VerifiedArtifacts:
    binary_fd: int
    object_fd: int
    binary: ArtifactIdentity
    object: ArtifactIdentity

    def close(self) -> None:
        first_error = None
        for descriptor in (self.binary_fd, self.object_fd):
            try:
                os.close(descriptor)
            except OSError as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="verifier-load one reviewed experimental FakeTCP BPF object",
        allow_abbrev=False,
    )
    parser.add_argument("--runner-sha256", required=True, action=StoreOnce)
    parser.add_argument("--staging-root", required=True, action=StoreOnce)
    parser.add_argument("--binary", required=True, action=StoreOnce)
    parser.add_argument("--binary-sha256", required=True, action=StoreOnce)
    parser.add_argument("--object", required=True, action=StoreOnce)
    parser.add_argument("--object-sha256", required=True, action=StoreOnce)
    return parser.parse_args(argv)


def require_isolated_runtime() -> None:
    if not sys.flags.isolated:
        raise GateError("verifier gate requires /usr/bin/python3 -I")


def reject_reserved_environment(environment: dict[str, str]) -> None:
    unexpected = sorted(
        key for key in environment if key.startswith(RESERVED_ENV_PREFIX)
    )
    if unexpected:
        raise GateError(
            "reserved verifier environment is forbidden: " + ",".join(unexpected)
        )


def lock_process_environment() -> None:
    os.environ.clear()
    os.environ.update({"PATH": CHILD_PATH, "LC_ALL": "C"})


def require_safe_path_text(value: str, label: str) -> None:
    if (
        not value
        or SAFE_PATH.fullmatch(value) is None
        or value == "/"
        or value.endswith("/")
        or value.startswith("//")
        or posixpath.normpath(value) != value
    ):
        raise GateError(f"{label} must be an absolute normalized safe path")


def require_sha256_text(value: str, label: str) -> None:
    if SHA256_TEXT.fullmatch(value) is None:
        raise GateError(
            f"{label} SHA-256 must be exactly 64 lowercase hexadecimal characters"
        )


def validate_staging_root_text(staging_root: str, policy: GatePolicy) -> str:
    require_safe_path_text(staging_root, "staging root")
    if posixpath.dirname(staging_root) != policy.staging_prefix:
        raise GateError(
            f"staging root must be one unique-ID directory below {policy.staging_prefix}"
        )
    run_id = posixpath.basename(staging_root)
    if SAFE_RUN_ID.fullmatch(run_id) is None:
        raise GateError("staging root unique ID is not canonical")
    return run_id


def target_relative_parts(path: str, staging_root: str, label: str) -> Tuple[str, ...]:
    require_safe_path_text(path, f"{label} path")
    try:
        common = posixpath.commonpath((staging_root, path))
    except ValueError as error:
        raise GateError(f"{label} path is outside the staging root") from error
    if common != staging_root or path == staging_root:
        raise GateError(f"{label} path is outside the staging root")
    relative = posixpath.relpath(path, staging_root)
    parts = tuple(relative.split("/"))
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise GateError(f"{label} path is not canonical below the staging root")
    return parts


def require_open_constants() -> Tuple[int, int]:
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    missing = tuple(name for name in required if not hasattr(os, name))
    if missing:
        raise GateError("required safe-open flags are unavailable: " + ",".join(missing))
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    return directory_flags, file_flags


def validate_directory_metadata(
    metadata: os.stat_result,
    display_path: str,
    policy: GatePolicy,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise GateError(f"staging ancestor is not a directory: {display_path}")
    owner = (metadata.st_uid, metadata.st_gid)
    if owner not in policy.directory_owners:
        raise GateError(
            f"staging ancestor is not owned by an accepted uid:gid: {display_path}"
        )
    writable = stat.S_IMODE(metadata.st_mode) & 0o022
    sticky_system_directory = (
        policy.allow_sticky_ancestor
        and owner == (0, 0)
        and bool(metadata.st_mode & stat.S_ISVTX)
    )
    if writable and not sticky_system_directory:
        raise GateError(f"staging ancestor is group- or other-writable: {display_path}")


def open_absolute_directory(path: str, policy: GatePolicy) -> int:
    directory_flags, _ = require_open_constants()
    descriptor = os.open("/", directory_flags)
    display_path = "/"
    try:
        validate_directory_metadata(os.fstat(descriptor), display_path, policy)
        for component in path.split("/")[1:]:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            display_path = posixpath.join(display_path, component)
            validate_directory_metadata(os.fstat(descriptor), display_path, policy)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_relative_parent(
    staging_descriptor: int,
    parent_parts: Sequence[str],
    staging_root: str,
    policy: GatePolicy,
) -> int:
    directory_flags, _ = require_open_constants()
    descriptor = os.dup(staging_descriptor)
    display_path = staging_root
    try:
        for component in parent_parts:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            display_path = posixpath.join(display_path, component)
            validate_directory_metadata(os.fstat(descriptor), display_path, policy)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def metadata_snapshot(metadata: os.stat_result) -> Tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def validate_artifact_metadata(
    metadata: os.stat_result,
    label: str,
    executable: bool,
    policy: GatePolicy,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise GateError(f"{label} is not a regular file")
    if (metadata.st_uid, metadata.st_gid) != policy.artifact_owner:
        raise GateError(f"{label} is not owned by the required uid:gid")
    if metadata.st_nlink != 1:
        raise GateError(f"{label} link count must be exactly one")
    if metadata.st_size <= 0:
        raise GateError(f"{label} must not be empty")
    permissions = stat.S_IMODE(metadata.st_mode)
    if permissions & 0o022:
        raise GateError(f"{label} must not be group- or other-writable")
    if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise GateError(f"{label} must not have set-user-ID or set-group-ID bits")
    if executable and not permissions & 0o111:
        raise GateError(f"{label} is not executable")


def sha256_from_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def require_held_runner_descriptor(
    source_path: str,
    expected_sha256: str,
    expected_owner: Tuple[int, int] = (0, 0),
    descriptor_prefix: str = "/proc/self/fd",
) -> ArtifactIdentity:
    # Defense-in-depth only: the independently approved Go launcher establishes
    # the initial trust boundary before this Python source can execute.  Code
    # cannot establish its own initial trust merely by hashing itself here.
    require_sha256_text(expected_sha256, "runner")
    match = re.fullmatch(re.escape(descriptor_prefix) + r"/([1-9][0-9]*)", source_path)
    if match is None:
        raise GateError("runner must be loaded from a held descriptor path")
    descriptor = int(match.group(1))
    try:
        inheritable = os.get_inheritable(descriptor)
        before = os.fstat(descriptor)
    except OSError as error:
        raise GateError("runner descriptor is not held open") from error
    if not inheritable:
        raise GateError("runner descriptor must remain inheritable")
    if not stat.S_ISREG(before.st_mode):
        raise GateError("runner descriptor is not a regular file")
    if (before.st_uid, before.st_gid) != expected_owner:
        raise GateError("runner descriptor has the wrong owner")
    if before.st_nlink != 1:
        raise GateError("runner descriptor link count must be exactly one")
    if before.st_size <= 0:
        raise GateError("runner descriptor must not be empty")
    if stat.S_IMODE(before.st_mode) & 0o022:
        raise GateError("runner descriptor must not be group- or other-writable")
    actual_sha256 = sha256_from_descriptor(descriptor)
    after = os.fstat(descriptor)
    if metadata_snapshot(after) != metadata_snapshot(before):
        raise GateError("runner descriptor metadata changed while hashing")
    if actual_sha256 != expected_sha256:
        raise GateError("runner SHA-256 mismatch")
    os.set_inheritable(descriptor, False)
    return ArtifactIdentity(
        label="runner",
        original_path=source_path,
        sha256=actual_sha256,
        device=after.st_dev,
        inode=after.st_ino,
        size=after.st_size,
        mode=stat.S_IMODE(after.st_mode),
    )


def open_verified_artifact(
    staging_descriptor: int,
    staging_root: str,
    path: str,
    expected_sha256: str,
    label: str,
    executable: bool,
    policy: GatePolicy,
) -> Tuple[int, ArtifactIdentity]:
    require_sha256_text(expected_sha256, label)
    relative_parts = target_relative_parts(path, staging_root, label)
    parent_descriptor = open_relative_parent(
        staging_descriptor,
        relative_parts[:-1],
        staging_root,
        policy,
    )
    _, file_flags = require_open_constants()
    try:
        descriptor = os.open(relative_parts[-1], file_flags, dir_fd=parent_descriptor)
    except BaseException:
        os.close(parent_descriptor)
        raise
    os.close(parent_descriptor)
    try:
        before = os.fstat(descriptor)
        validate_artifact_metadata(before, label, executable, policy)
        actual_sha256 = sha256_from_descriptor(descriptor)
        after = os.fstat(descriptor)
        if metadata_snapshot(after) != metadata_snapshot(before):
            raise GateError(f"{label} metadata changed while hashing its open descriptor")
        if actual_sha256 != expected_sha256:
            raise GateError(f"{label} SHA-256 mismatch")
        identity = ArtifactIdentity(
            label=label,
            original_path=path,
            sha256=actual_sha256,
            device=after.st_dev,
            inode=after.st_ino,
            size=after.st_size,
            mode=stat.S_IMODE(after.st_mode),
        )
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def verify_artifacts(
    arguments: argparse.Namespace,
    policy: GatePolicy,
) -> VerifiedArtifacts:
    validate_staging_root_text(arguments.staging_root, policy)
    target_relative_parts(arguments.binary, arguments.staging_root, "binary")
    target_relative_parts(arguments.object, arguments.staging_root, "object")
    staging_descriptor = open_absolute_directory(arguments.staging_root, policy)
    try:
        binary_fd, binary_identity = open_verified_artifact(
            staging_descriptor,
            arguments.staging_root,
            arguments.binary,
            arguments.binary_sha256,
            "binary",
            True,
            policy,
        )
        try:
            object_fd, object_identity = open_verified_artifact(
                staging_descriptor,
                arguments.staging_root,
                arguments.object,
                arguments.object_sha256,
                "experimental BPF object",
                False,
                policy,
            )
        except BaseException:
            os.close(binary_fd)
            raise
    finally:
        os.close(staging_descriptor)
    if (binary_identity.device, binary_identity.inode) == (
        object_identity.device,
        object_identity.inode,
    ):
        os.close(binary_fd)
        os.close(object_fd)
        raise GateError("binary and experimental BPF object must be distinct files")
    return VerifiedArtifacts(
        binary_fd=binary_fd,
        object_fd=object_fd,
        binary=binary_identity,
        object=object_identity,
    )


def require_system_identity(policy: GatePolicy) -> None:
    if policy.require_root and os.geteuid() != 0:
        raise GateError("verifier gate must run as root")
    actual_hostname = socket.gethostname()
    if actual_hostname != policy.hostname:
        raise GateError(
            f"hostname mismatch: got {actual_hostname}, want {policy.hostname}"
        )
    actual_kernel = platform.release()
    if actual_kernel != policy.kernel_release:
        raise GateError(
            f"kernel mismatch: got {actual_kernel}, want {policy.kernel_release}"
        )


def require_unused_descriptor(descriptor: int) -> None:
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise
    raise GateError(f"reserved verifier descriptor {descriptor} is already in use")


def duplicate_pair_for_exec(
    binary_descriptor: int,
    object_descriptor: int,
) -> Tuple[int, int]:
    require_unused_descriptor(BINARY_EXEC_FD)
    require_unused_descriptor(OBJECT_EXEC_FD)
    os.dup2(binary_descriptor, BINARY_EXEC_FD, inheritable=True)
    try:
        os.dup2(object_descriptor, OBJECT_EXEC_FD, inheritable=True)
    except BaseException:
        os.close(BINARY_EXEC_FD)
        raise
    try:
        os.lseek(BINARY_EXEC_FD, 0, os.SEEK_SET)
        os.lseek(OBJECT_EXEC_FD, 0, os.SEEK_SET)
        return BINARY_EXEC_FD, OBJECT_EXEC_FD
    except BaseException:
        os.close(BINARY_EXEC_FD)
        os.close(OBJECT_EXEC_FD)
        raise


def descriptor_path(descriptor: int, policy: GatePolicy) -> str:
    path = f"{policy.proc_fd_prefix}/{descriptor}"
    if policy.verify_descriptor_identity:
        source = os.fstat(descriptor)
        visible = os.stat(path)
        if (source.st_dev, source.st_ino) != (visible.st_dev, visible.st_ino):
            raise GateError("descriptor filesystem identity mismatch")
    return path


def child_argv(binary_path: str, object_path: str) -> Tuple[str, ...]:
    return (
        binary_path,
        "bpf-load-test",
        "--experimental-faketcp",
        "--object",
        object_path,
    )


def status_return_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 125


def poll_child(
    pid: int,
    waitpid_function=os.waitpid,
    retry_deadline: Optional[float] = None,
    monotonic_function=time.monotonic,
) -> Tuple[bool, Optional[int]]:
    while True:
        try:
            waited_pid, status_value = waitpid_function(pid, os.WNOHANG)
        except InterruptedError:
            if (
                retry_deadline is not None
                and monotonic_function() >= retry_deadline
            ):
                raise GateError("waitpid EINTR retry deadline expired")
            continue
        except ChildProcessError:
            return True, None
        except OSError as error:
            if error.errno == errno.EINTR:
                if (
                    retry_deadline is not None
                    and monotonic_function() >= retry_deadline
                ):
                    raise GateError("waitpid EINTR retry deadline expired")
                continue
            if error.errno == errno.ECHILD:
                return True, None
            raise
        if waited_pid == 0:
            return False, None
        if waited_pid == pid:
            return True, status_value
        raise GateError("waitpid returned an unexpected child")


def wait_until(
    pid: int,
    deadline: float,
    waitpid_function=os.waitpid,
    monotonic_function=time.monotonic,
    sleep_function=time.sleep,
) -> Tuple[bool, Optional[int]]:
    while True:
        done, status_value = poll_child(
            pid,
            waitpid_function,
            deadline,
            monotonic_function,
        )
        if done:
            return True, status_value
        remaining = deadline - monotonic_function()
        if remaining <= 0:
            return False, None
        sleep_function(min(0.05, remaining))


def signal_process_group(
    pid: int,
    signal_number: int,
    killpg_function=os.killpg,
    retry_deadline: Optional[float] = None,
    monotonic_function=time.monotonic,
) -> None:
    while True:
        try:
            killpg_function(pid, signal_number)
            return
        except InterruptedError:
            if (
                retry_deadline is not None
                and monotonic_function() >= retry_deadline
            ):
                raise GateError("process-group signal EINTR retry deadline expired")
            continue
        except ProcessLookupError:
            return
        except OSError as error:
            if error.errno == errno.EINTR:
                if (
                    retry_deadline is not None
                    and monotonic_function() >= retry_deadline
                ):
                    raise GateError(
                        "process-group signal EINTR retry deadline expired"
                    )
                continue
            if error.errno == errno.ESRCH:
                return
            raise


def signal_process(
    pid: int,
    signal_number: int,
    kill_function=os.kill,
    retry_deadline: Optional[float] = None,
    monotonic_function=time.monotonic,
) -> None:
    while True:
        try:
            kill_function(pid, signal_number)
            return
        except InterruptedError:
            if (
                retry_deadline is not None
                and monotonic_function() >= retry_deadline
            ):
                raise GateError("process signal EINTR retry deadline expired")
            continue
        except ProcessLookupError:
            return
        except OSError as error:
            if error.errno == errno.EINTR:
                if (
                    retry_deadline is not None
                    and monotonic_function() >= retry_deadline
                ):
                    raise GateError("process signal EINTR retry deadline expired")
                continue
            if error.errno == errno.ESRCH:
                return
            raise


def sleep_until(
    deadline: float,
    monotonic_function=time.monotonic,
    sleep_function=time.sleep,
) -> None:
    while True:
        remaining = deadline - monotonic_function()
        if remaining <= 0:
            return
        sleep_function(min(0.05, remaining))


def wait_for_readiness_byte(
    descriptor: int,
    deadline: float,
    monotonic_function=time.monotonic,
    poll_factory=select.poll,
    read_function=os.read,
) -> None:
    poller = poll_factory()
    poller.register(descriptor, READINESS_POLL_MASK)
    while True:
        remaining = deadline - monotonic_function()
        if remaining <= 0:
            raise GateError("child readiness deadline expired")
        timeout_milliseconds = min(
            MAX_POLL_TIMEOUT_MILLISECONDS,
            max(1, math.ceil(remaining * 1000.0)),
        )
        try:
            events = poller.poll(timeout_milliseconds)
        except InterruptedError:
            continue
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            raise
        if not events:
            continue

        event_mask = 0
        for event_descriptor, current_mask in events:
            if event_descriptor != descriptor:
                raise GateError("readiness poll returned an unexpected descriptor")
            event_mask |= current_mask
        if event_mask & select.POLLNVAL:
            raise GateError("readiness descriptor became invalid")
        try:
            ready = read_function(descriptor, 1)
        except InterruptedError:
            continue
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                if event_mask & (select.POLLHUP | select.POLLERR):
                    raise GateError("readiness pipe closed without a byte")
                continue
            raise
        if ready == b"":
            raise GateError("readiness pipe reached EOF before confirmation")
        if ready != READINESS_BYTE:
            raise GateError("readiness pipe returned a non-confirmation byte")
        if monotonic_function() > deadline:
            raise GateError("child readiness arrived after the absolute deadline")
        return


def confirmed_child_process_group(
    pid: int,
    retry_deadline: float,
    getpgid_function=os.getpgid,
    monotonic_function=time.monotonic,
) -> bool:
    while True:
        try:
            return getpgid_function(pid) == pid
        except InterruptedError:
            if monotonic_function() >= retry_deadline:
                raise GateError("getpgid EINTR retry deadline expired")
            continue
        except ProcessLookupError:
            return False
        except OSError as error:
            if error.errno == errno.EINTR:
                if monotonic_function() >= retry_deadline:
                    raise GateError("getpgid EINTR retry deadline expired")
                continue
            if error.errno == errno.ESRCH:
                return False
            raise


def kill_group_and_reap(
    pid: int,
    waitpid_function=os.waitpid,
    killpg_function=os.killpg,
    kill_function=os.kill,
    reap_timeout_seconds: float = KILL_REAP_SECONDS,
    monotonic_function=time.monotonic,
    sleep_function=time.sleep,
) -> None:
    cleanup_deadline = monotonic_function() + reap_timeout_seconds
    group_kill_error: Optional[BaseException] = None
    try:
        signal_process_group(
            pid,
            signal.SIGKILL,
            killpg_function,
            cleanup_deadline,
            monotonic_function,
        )
    except BaseException as error:
        group_kill_error = error

    leader_kill_error: Optional[BaseException] = None
    if group_kill_error is not None:
        try:
            signal_process(
                pid,
                signal.SIGKILL,
                kill_function,
                cleanup_deadline,
                monotonic_function,
            )
        except BaseException as error:
            leader_kill_error = error

    done, _ = wait_until(
        pid,
        cleanup_deadline,
        waitpid_function,
        monotonic_function,
        sleep_function,
    )
    if not done:
        if leader_kill_error is not None:
            raise GateError(
                "process-group and leader SIGKILL failed; leader was not reaped "
                "within the fixed cleanup deadline"
            ) from group_kill_error
        raise GateError(
            "leader was not reaped within the fixed post-SIGKILL cleanup deadline"
        ) from group_kill_error
    if group_kill_error is not None:
        if leader_kill_error is not None:
            raise GateError(
                "process-group SIGKILL and leader SIGKILL both failed"
            ) from group_kill_error
        raise group_kill_error


def cleanup_pre_ready_child(
    pid: int,
    waitpid_function=os.waitpid,
    getpgid_function=os.getpgid,
    killpg_function=os.killpg,
    kill_function=os.kill,
    reap_timeout_seconds: float = KILL_REAP_SECONDS,
    monotonic_function=time.monotonic,
    sleep_function=time.sleep,
) -> None:
    cleanup_deadline = monotonic_function() + reap_timeout_seconds
    group_probe_error: Optional[BaseException] = None
    group_confirmed = False
    try:
        group_confirmed = confirmed_child_process_group(
            pid,
            cleanup_deadline,
            getpgid_function,
            monotonic_function,
        )
    except BaseException as error:
        group_probe_error = error

    group_kill_error: Optional[BaseException] = None
    if group_confirmed:
        try:
            signal_process_group(
                pid,
                signal.SIGKILL,
                killpg_function,
                cleanup_deadline,
                monotonic_function,
            )
        except BaseException as error:
            group_kill_error = error

    direct_kill_error: Optional[BaseException] = None
    try:
        signal_process(
            pid,
            signal.SIGKILL,
            kill_function,
            cleanup_deadline,
            monotonic_function,
        )
    except BaseException as error:
        direct_kill_error = error

    done, _ = wait_until(
        pid,
        cleanup_deadline,
        waitpid_function,
        monotonic_function,
        sleep_function,
    )
    if not done:
        raise GateError(
            "pre-readiness child was not reaped within the fixed cleanup deadline"
        ) from direct_kill_error
    if direct_kill_error is not None:
        raise GateError("direct pre-readiness child SIGKILL failed") from direct_kill_error
    if group_kill_error is not None:
        raise group_kill_error
    if group_probe_error is not None:
        raise group_probe_error


def wait_for_child_readiness(
    pid: int,
    descriptor: int,
    deadline: float,
    waitpid_function=os.waitpid,
    getpgid_function=os.getpgid,
    killpg_function=os.killpg,
    kill_function=os.kill,
    monotonic_function=time.monotonic,
    sleep_function=time.sleep,
    poll_factory=select.poll,
    read_function=os.read,
    kill_reap_seconds: float = KILL_REAP_SECONDS,
) -> None:
    try:
        wait_for_readiness_byte(
            descriptor,
            deadline,
            monotonic_function,
            poll_factory,
            read_function,
        )
    except BaseException as readiness_error:
        try:
            cleanup_pre_ready_child(
                pid,
                waitpid_function,
                getpgid_function,
                killpg_function,
                kill_function,
                kill_reap_seconds,
                monotonic_function,
                sleep_function,
            )
        except BaseException as cleanup_error:
            raise cleanup_error from readiness_error
        raise


def wait_with_deadline(
    pid: int,
    deadline: float,
    grace_seconds: float,
    waitpid_function=os.waitpid,
    killpg_function=os.killpg,
    kill_function=os.kill,
    monotonic_function=time.monotonic,
    sleep_function=time.sleep,
    kill_reap_seconds: float = KILL_REAP_SECONDS,
) -> int:
    try:
        done, status_value = wait_until(
            pid,
            deadline,
            waitpid_function,
            monotonic_function,
            sleep_function,
        )
    except BaseException as wait_error:
        try:
            kill_group_and_reap(
                pid,
                waitpid_function,
                killpg_function,
                kill_function,
                kill_reap_seconds,
                monotonic_function,
                sleep_function,
            )
        except BaseException as cleanup_error:
            raise cleanup_error from wait_error
        raise
    if done:
        return status_return_code(status_value) if status_value is not None else 125

    # Once the deadline expires, the leader deliberately remains unreaped until
    # the original process group has received its final SIGKILL.  A zombie still
    # reserves its PID/PGID, so a fast-exiting leader cannot let the identifier be
    # reused while an ignore-SIGTERM descendant remains in the group.
    timeout_error: Optional[BaseException] = None
    grace_deadline = monotonic_function() + grace_seconds
    try:
        signal_process_group(
            pid,
            signal.SIGTERM,
            killpg_function,
            grace_deadline,
            monotonic_function,
        )
        sleep_until(
            grace_deadline,
            monotonic_function,
            sleep_function,
        )
    except BaseException as error:
        timeout_error = error

    try:
        kill_group_and_reap(
            pid,
            waitpid_function,
            killpg_function,
            kill_function,
            kill_reap_seconds,
            monotonic_function,
            sleep_function,
        )
    except BaseException as cleanup_error:
        if timeout_error is not None:
            raise cleanup_error from timeout_error
        raise

    if timeout_error is not None:
        raise timeout_error
    return 124


def wait_with_timeout(
    pid: int,
    timeout_seconds: float,
    grace_seconds: float,
    waitpid_function=os.waitpid,
    killpg_function=os.killpg,
    kill_function=os.kill,
    monotonic_function=time.monotonic,
    sleep_function=time.sleep,
    kill_reap_seconds: float = KILL_REAP_SECONDS,
) -> int:
    return wait_with_deadline(
        pid,
        monotonic_function() + timeout_seconds,
        grace_seconds,
        waitpid_function,
        killpg_function,
        kill_function,
        monotonic_function,
        sleep_function,
        kill_reap_seconds,
    )


def supervise_ready_child(
    pid: int,
    descriptor: int,
    deadline: float,
    grace_seconds: float,
    waitpid_function=os.waitpid,
    getpgid_function=os.getpgid,
    killpg_function=os.killpg,
    kill_function=os.kill,
    monotonic_function=time.monotonic,
    sleep_function=time.sleep,
    poll_factory=select.poll,
    read_function=os.read,
    close_function=os.close,
    kill_reap_seconds: float = KILL_REAP_SECONDS,
) -> int:
    supervision_error: Optional[BaseException] = None
    try:
        wait_for_child_readiness(
            pid,
            descriptor,
            deadline,
            waitpid_function,
            getpgid_function,
            killpg_function,
            kill_function,
            monotonic_function,
            sleep_function,
            poll_factory,
            read_function,
            kill_reap_seconds,
        )
        # The child writes the confirmation byte only after setsid(), so PGID=pid
        # is trusted from here onward.  The unchanged absolute deadline ensures
        # that readiness latency consumes the verifier execution budget.
        return wait_with_deadline(
            pid,
            deadline,
            grace_seconds,
            waitpid_function,
            killpg_function,
            kill_function,
            monotonic_function,
            sleep_function,
            kill_reap_seconds,
        )
    except BaseException as error:
        supervision_error = error
        raise
    finally:
        try:
            close_function(descriptor)
        except BaseException:
            if supervision_error is None:
                raise


def run_descriptor_child(
    binary_path: str,
    arguments: Sequence[str],
    environment: dict[str, str],
    policy: GatePolicy,
) -> int:
    absolute_deadline = time.monotonic() + policy.timeout_seconds
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        pid = os.fork()
    except BaseException:
        os.close(ready_read)
        os.close(ready_write)
        raise
    if pid == 0:
        try:
            os.close(ready_read)
            os.setsid()
            os.write(ready_write, READINESS_BYTE)
            os.close(ready_write)
            os.execve(binary_path, arguments, environment)
        except BaseException as error:
            message = f"error: descriptor exec failed: {type(error).__name__}\n"
            os.write(2, message.encode("ascii", "replace"))
            os._exit(126)
    try:
        os.close(ready_write)
    except BaseException as parent_error:
        try:
            os.close(ready_read)
        except BaseException:
            pass
        try:
            cleanup_pre_ready_child(pid)
        except BaseException as cleanup_error:
            raise cleanup_error from parent_error
        raise
    return supervise_ready_child(
        pid,
        ready_read,
        absolute_deadline,
        policy.term_grace_seconds,
    )


def audit_event(
    event: str,
    return_code: str,
    artifacts: VerifiedArtifacts,
    policy: GatePolicy,
) -> None:
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    fields = (
        ("timestamp", timestamp),
        ("event", event),
        ("host", policy.hostname),
        ("kernel", policy.kernel_release),
        ("rc", return_code),
        ("binary", artifacts.binary.original_path),
        ("binary_sha256", artifacts.binary.sha256),
        ("binary_dev_inode", f"{artifacts.binary.device}:{artifacts.binary.inode}"),
        ("object", artifacts.object.original_path),
        ("object_sha256", artifacts.object.sha256),
        ("object_dev_inode", f"{artifacts.object.device}:{artifacts.object.inode}"),
    )
    print("audit " + " ".join(f"{key}={shlex.quote(value)}" for key, value in fields))


def execute_verified(artifacts: VerifiedArtifacts, policy: GatePolicy) -> int:
    binary_exec_fd, object_exec_fd = duplicate_pair_for_exec(
        artifacts.binary_fd,
        artifacts.object_fd,
    )
    try:
        binary_path = descriptor_path(binary_exec_fd, policy)
        object_path = descriptor_path(object_exec_fd, policy)
        arguments = child_argv(binary_path, object_path)
        environment = {"PATH": CHILD_PATH, "LC_ALL": "C"}
        audit_event("start", "pending", artifacts, policy)
        print("verifier_argv=" + shlex.join(arguments))
        sys.stdout.flush()
        sys.stderr.flush()
        try:
            return_code = run_descriptor_child(
                binary_path,
                arguments,
                environment,
                policy,
            )
        except BaseException:
            audit_event("finish", "125", artifacts, policy)
            raise
        audit_event("finish", str(return_code), artifacts, policy)
        return return_code
    finally:
        os.close(binary_exec_fd)
        os.close(object_exec_fd)


def run_gate(arguments: argparse.Namespace, policy: GatePolicy) -> int:
    require_system_identity(policy)
    artifacts = verify_artifacts(arguments, policy)
    try:
        return execute_verified(artifacts, policy)
    finally:
        artifacts.close()


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        require_isolated_runtime()
        reject_reserved_environment(dict(os.environ))
        lock_process_environment()
        arguments = parse_args(argv)
        require_held_runner_descriptor(__file__, arguments.runner_sha256)
        return run_gate(arguments, PRODUCTION_POLICY)
    except GateError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"error: verifier gate system call failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
