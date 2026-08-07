#!/usr/bin/python3
"""Descriptor-anchored implementation for stage-root-owned-test-source.sh."""

from __future__ import annotations

import datetime
import hashlib
import os
import re
import shlex
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from typing import BinaryIO, TypeVar


STAGE_PREFIX = "/run/wg-mix-ebpf-source-stages"
BOOTSTRAP_PREFIX = "/run/wg-mix-ebpf-source-bootstrap"
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
FIXED_PATH = "/usr/bin:/bin"
FIXED_TOOLS = {
    "clang": "/usr/bin/clang",
    "gcc": "/usr/bin/gcc",
    "git": "/usr/bin/git",
    "go": "/usr/bin/go",
    "make": "/usr/bin/make",
    "timeout": "/usr/bin/timeout",
}
RUN_ID_RE = re.compile(r"[0-9a-f]{8}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
SAFE_PATH_RE = re.compile(r"/[A-Za-z0-9_+@.,/-]+\Z")
T = TypeVar("T")


class StageError(RuntimeError):
    """A fail-closed staging error."""


def utc_timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def exact_stat(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def identity_stat(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_nlink,
    )


def format_stat(metadata: os.stat_result) -> str:
    return (
        f"dev={metadata.st_dev} ino={metadata.st_ino} uid={metadata.st_uid} "
        f"gid={metadata.st_gid} mode={stat.S_IMODE(metadata.st_mode):04o} "
        f"nlink={metadata.st_nlink} size={metadata.st_size} "
        f"mtime_ns={metadata.st_mtime_ns}"
    )


def require_absolute_path(path: str, label: str) -> None:
    if (
        not SAFE_PATH_RE.fullmatch(path)
        or path == "/"
        or path.endswith("/")
        or "//" in path
        or "/./" in path
        or "/../" in path
        or path.endswith("/.")
        or path.endswith("/..")
        or os.path.normpath(path) != path
    ):
        raise StageError(f"{label} must be a canonical-looking absolute path")


def require_run_id(value: str) -> None:
    if not RUN_ID_RE.fullmatch(value):
        raise StageError("--run-id must be exactly 8 lowercase hex characters")


def require_sha256(value: str, label: str = "--bundle-sha256") -> None:
    if not SHA256_RE.fullmatch(value):
        raise StageError(f"{label} must be exactly 64 lowercase hex characters")


def require_commit(value: str) -> None:
    if not COMMIT_RE.fullmatch(value):
        raise StageError("--commit must be exactly 40 lowercase hex characters")


def require_absent(path: str, label: str) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    raise StageError(f"{label} already exists: {path}")


class Audit:
    def __init__(self) -> None:
        self._log: BinaryIO | None = None
        self._log_path = ""

    @property
    def log_path(self) -> str:
        return self._log_path

    def emit(self, fields: Sequence[tuple[str, str]]) -> None:
        line = " ".join(f"{key}={shlex.quote(value)}" for key, value in fields)
        payload = (line + "\n").encode("utf-8", "strict")
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        if self._log is not None:
            self._log.write(payload)
            self._log.flush()
            os.fsync(self._log.fileno())

    def start(self, action: str, argv: Sequence[str], target: str) -> None:
        self.emit(
            (
                ("timestamp", utc_timestamp()),
                ("event", "write_start"),
                ("action", action),
                ("argv", shlex.join(argv)),
                ("target", target),
            )
        )

    def finish(
        self, action: str, argv: Sequence[str], target: str, returncode: int
    ) -> None:
        self.emit(
            (
                ("timestamp", utc_timestamp()),
                ("event", "write_finish"),
                ("action", action),
                ("argv", shlex.join(argv)),
                ("target", target),
                ("rc", str(returncode)),
            )
        )

    def attach_new_log(self, path: str, fd: int) -> None:
        self._log_path = path
        self._log = os.fdopen(fd, "ab", buffering=0)

    def read_event(self, action: str, argv: Sequence[str], returncode: int) -> None:
        self.emit(
            (
                ("timestamp", utc_timestamp()),
                ("event", "read_finish"),
                ("action", action),
                ("argv", shlex.join(argv)),
                ("rc", str(returncode)),
            )
        )


def audited_internal(
    audit: Audit,
    action: str,
    argv: Sequence[str],
    target: str,
    operation: Callable[[], T],
) -> T:
    audit.start(action, argv, target)
    try:
        result = operation()
    except BaseException:
        audit.finish(action, argv, target, 1)
        raise
    audit.finish(action, argv, target, 0)
    return result


def run_command(
    audit: Audit,
    action: str,
    argv: Sequence[str],
    target: str,
    environment: dict[str, str],
    cwd: str,
) -> None:
    audit.start(action, argv, target)
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        returncode = completed.returncode
    except OSError as error:
        audit.finish(action, argv, target, 126)
        raise StageError(f"cannot execute {action}: {error}") from error
    audit.finish(action, argv, target, returncode)
    if returncode != 0:
        raise StageError(f"{action} failed with exit status {returncode}")


def read_command(
    audit: Audit,
    action: str,
    argv: Sequence[str],
    environment: dict[str, str],
    cwd: str,
    binary: bool = False,
) -> bytes | str:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        audit.read_event(action, argv, 126)
        raise StageError(f"cannot execute {action}: {error}") from error
    audit.read_event(action, argv, completed.returncode)
    if completed.returncode != 0:
        sys.stderr.buffer.write(completed.stderr)
        sys.stderr.buffer.flush()
        raise StageError(f"{action} failed with exit status {completed.returncode}")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise StageError(f"{action} returned non-UTF-8 output") from error


def validate_directory(
    path: str, expected_uid: int, expected_gid: int, exact_mode: int
) -> os.stat_result:
    require_absolute_path(path, "directory path")
    before = os.lstat(path)
    if not stat.S_ISDIR(before.st_mode):
        raise StageError(f"required directory is missing or a symlink: {path}")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        opened = os.fstat(descriptor)
        resolved = os.path.realpath(f"/proc/self/fd/{descriptor}")
        after = os.lstat(path)
    finally:
        os.close(descriptor)
    if (
        identity_stat(before) != identity_stat(opened)
        or exact_stat(before) != exact_stat(after)
        or before.st_uid != expected_uid
        or before.st_gid != expected_gid
        or stat.S_IMODE(before.st_mode) != exact_mode
        or resolved != path
    ):
        raise StageError(f"directory metadata or identity is unsafe: {path}")
    return before


def create_directory(
    audit: Audit,
    path: str,
    expected_uid: int,
    expected_gid: int,
    action: str,
) -> os.stat_result:
    require_absent(path, action)
    argv = ("mkdir", "--mode=0700", "--", path)
    audited_internal(audit, action, argv, path, lambda: os.mkdir(path, 0o700))
    return validate_directory(path, expected_uid, expected_gid, 0o700)


def hash_open_fd(descriptor: int, byte_limit: int | None = None) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if byte_limit is not None and total > byte_limit:
            raise StageError(f"file exceeds the {byte_limit}-byte hard limit")
        digest.update(chunk)
    return digest.hexdigest()


def open_verified_bundle(path: str, expected_sha256: str) -> tuple[int, os.stat_result]:
    require_absolute_path(path, "--bundle")
    require_sha256(expected_sha256)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise StageError("bundle must be a one-link regular file, not a symlink")
    if before.st_size <= 0 or before.st_size > MAX_BUNDLE_BYTES:
        raise StageError("bundle size is empty or exceeds the hard limit")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        opened = os.fstat(descriptor)
        if exact_stat(before) != exact_stat(opened):
            raise StageError("bundle path and opened descriptor identity differ")
        actual_sha256 = hash_open_fd(descriptor, MAX_BUNDLE_BYTES)
        after_hash = os.fstat(descriptor)
        after_path = os.lstat(path)
        if (
            exact_stat(opened) != exact_stat(after_hash)
            or exact_stat(before) != exact_stat(after_path)
        ):
            raise StageError("bundle changed while it was being verified")
        if actual_sha256 != expected_sha256:
            raise StageError(
                f"bundle SHA-256 mismatch: expected={expected_sha256} "
                f"actual={actual_sha256}"
            )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def copy_verified_bundle(
    audit: Audit,
    source_fd: int,
    source_path: str,
    source_metadata: os.stat_result,
    destination: str,
    expected_sha256: str,
    expected_uid: int,
    expected_gid: int,
) -> os.stat_result:
    require_absent(destination, "copied bundle")
    argv = (
        "copy-open-fd",
        f"--source-fd={source_fd}",
        f"--source-path={source_path}",
        f"--destination={destination}",
        "--mode=0400",
    )

    def copy_operation() -> None:
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o400,
        )
        digest = hashlib.sha256()
        try:
            os.lseek(source_fd, 0, os.SEEK_SET)
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise StageError("short write while copying bundle")
                    view = view[written:]
                digest.update(chunk)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        if digest.hexdigest() != expected_sha256:
            raise StageError("source bundle changed while it was being copied")

    audited_internal(audit, "copy_verified_bundle", argv, destination, copy_operation)
    source_after = os.fstat(source_fd)
    source_path_after = os.lstat(source_path)
    if (
        exact_stat(source_metadata) != exact_stat(source_after)
        or identity_stat(source_metadata) != identity_stat(source_path_after)
    ):
        raise StageError("source bundle identity changed after the copy")
    copied_fd, copied_metadata = open_verified_bundle(destination, expected_sha256)
    os.close(copied_fd)
    if (
        copied_metadata.st_uid != expected_uid
        or copied_metadata.st_gid != expected_gid
        or stat.S_IMODE(copied_metadata.st_mode) != 0o400
    ):
        raise StageError("copied bundle ownership or mode is unsafe")
    return copied_metadata


def create_log(
    audit: Audit, path: str, expected_uid: int, expected_gid: int
) -> os.stat_result:
    require_absent(path, "staging log")
    argv = ("open", "--create-exclusive", "--mode=0600", "--", path)
    audit.start("create_staging_log", argv, path)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
        )
    except BaseException:
        audit.finish("create_staging_log", argv, path, 1)
        raise
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        audit.finish("create_staging_log", argv, path, 1)
        raise StageError("new staging log metadata is unsafe")
    audit.attach_new_log(path, descriptor)
    audit.finish("create_staging_log", argv, path, 0)
    return metadata


def minimal_environment() -> dict[str, str]:
    return {
        "PATH": FIXED_PATH,
        "LC_ALL": "C",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def git_argv(*arguments: str) -> tuple[str, ...]:
    return (
        FIXED_TOOLS["git"],
        "--no-pager",
        "--no-replace-objects",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        *arguments,
    )


def verify_clean_source(
    audit: Audit, source: str, commit: str, environment: dict[str, str]
) -> None:
    got_head = str(
        read_command(
            audit,
            "verify_source_head",
            git_argv("-C", source, "rev-parse", "--verify", "HEAD^{commit}"),
            environment,
            source,
        )
    ).strip()
    if got_head != commit:
        raise StageError(f"checked-out source HEAD is {got_head}, expected {commit}")
    status_output = str(
        read_command(
            audit,
            "verify_source_clean",
            git_argv(
                "-C",
                source,
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
                "--ignore-submodules=none",
            ),
            environment,
            source,
        )
    )
    if status_output:
        raise StageError(f"checked-out source is not clean: {status_output!r}")
    source_commit = str(
        read_command(
            audit,
            "verify_source_commit_helper",
            (os.path.join(source, "scripts", "source-commit.sh"),),
            environment,
            source,
        )
    ).strip()
    if source_commit != commit:
        raise StageError(
            f"source-commit helper returned {source_commit!r}, expected {commit}"
        )


def verify_root_owned_worktree(source: str) -> None:
    source_metadata = validate_directory(source, 0, 0, 0o700)
    if source_metadata.st_uid != 0 or source_metadata.st_gid != 0:
        raise StageError("source clone is not root:root-owned")
    for current_root, directories, files in os.walk(source, followlinks=False):
        entries = [*directories, *files]
        for name in entries:
            path = os.path.join(current_root, name)
            metadata = os.lstat(path)
            if metadata.st_uid != 0 or metadata.st_gid != 0:
                raise StageError(f"source entry is not root:root-owned: {path}")
            if stat.S_ISLNK(metadata.st_mode):
                raise StageError(f"source tree symlink is forbidden: {path}")
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise StageError(f"source tree contains a special file: {path}")
            permission_bits = stat.S_IMODE(metadata.st_mode)
            if permission_bits & 0o6000:
                raise StageError(f"source entry has setuid or setgid bits: {path}")
            if permission_bits & 0o022:
                raise StageError(f"source entry is group/other writable: {path}")


def open_hashed_file(
    path: str, expected_uid: int, expected_gid: int
) -> tuple[str, os.stat_result]:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_uid
        or before.st_gid != expected_gid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o6000
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise StageError(f"artifact metadata is unsafe: {path}")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        opened = os.fstat(descriptor)
        if exact_stat(before) != exact_stat(opened):
            raise StageError(f"artifact identity changed while opening: {path}")
        digest = hash_open_fd(descriptor)
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
        if exact_stat(opened) != exact_stat(after) or exact_stat(before) != exact_stat(
            path_after
        ):
            raise StageError(f"artifact changed while hashing: {path}")
    finally:
        os.close(descriptor)
    return digest, before


def anchored_file(
    descriptor: int,
    path: str | None,
    expected_sha256: str,
    expected_mode: int,
) -> tuple[str, os.stat_result]:
    require_sha256(expected_sha256, "anchored file SHA-256")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        raise StageError(
            "anchored script is not a strict-mode, one-link root:root regular file"
        )
    hash_descriptor = os.dup(descriptor)
    try:
        actual = hash_open_fd(hash_descriptor)
    finally:
        os.close(hash_descriptor)
    if actual != expected_sha256:
        raise StageError("anchored script SHA-256 changed before execution")
    if path is not None:
        require_absolute_path(path, "launcher path")
        path_metadata = os.lstat(path)
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or exact_stat(path_metadata) != exact_stat(metadata)
        ):
            raise StageError("launcher path does not identify its anchored descriptor")
    return actual, metadata


def verify_bootstrap_path(launcher_path: str, run_id: str) -> None:
    bootstrap_run_root = os.path.dirname(launcher_path)
    if (
        os.path.dirname(bootstrap_run_root) != BOOTSTRAP_PREFIX
        or os.path.basename(bootstrap_run_root) != run_id
        or os.path.basename(launcher_path) != "stage-root-owned-test-source.sh"
    ):
        raise StageError(
            "launcher must run from the fixed root bootstrap path for --run-id"
        )
    validate_directory(BOOTSTRAP_PREFIX, 0, 0, 0o700)
    validate_directory(bootstrap_run_root, 0, 0, 0o700)


def require_fixed_tools() -> None:
    for name, path in FIXED_TOOLS.items():
        metadata = os.stat(path)
        if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
            raise StageError(f"fixed tool is missing or not executable: {name}={path}")


def stage_source(
    bundle: str,
    bundle_sha256: str,
    commit: str,
    run_id: str,
    launcher_path: str,
    launcher_sha256: str,
    launcher_metadata: os.stat_result,
    helper_sha256: str,
    helper_metadata: os.stat_result,
) -> None:
    require_absolute_path(bundle, "--bundle")
    require_sha256(bundle_sha256)
    require_commit(commit)
    require_run_id(run_id)
    if os.geteuid() != 0:
        raise StageError("production staging must run as root")
    verify_bootstrap_path(launcher_path, run_id)
    require_fixed_tools()
    run_parent = os.path.dirname(STAGE_PREFIX)
    run_parent_metadata = os.lstat(run_parent)
    if (
        not stat.S_ISDIR(run_parent_metadata.st_mode)
        or run_parent_metadata.st_uid != 0
        or run_parent_metadata.st_gid != 0
        or stat.S_IMODE(run_parent_metadata.st_mode) & 0o022
        or os.path.realpath(run_parent) != run_parent
    ):
        raise StageError("fixed /run parent is unsafe")

    source_fd, source_metadata = open_verified_bundle(bundle, bundle_sha256)
    audit = Audit()
    try:
        try:
            os.lstat(STAGE_PREFIX)
        except FileNotFoundError:
            create_directory(audit, STAGE_PREFIX, 0, 0, "create_stage_prefix")
        else:
            validate_directory(STAGE_PREFIX, 0, 0, 0o700)

        run_root = os.path.join(STAGE_PREFIX, run_id)
        create_directory(audit, run_root, 0, 0, "create_unique_run_root")
        log_path = os.path.join(run_root, "staging.log")
        require_absent(log_path, "staging log")
        create_log(audit, log_path, 0, 0)

        copied_bundle = os.path.join(run_root, "candidate.bundle")
        copy_verified_bundle(
            audit,
            source_fd,
            bundle,
            source_metadata,
            copied_bundle,
            bundle_sha256,
            0,
            0,
        )

        directories = {
            "git_template": os.path.join(run_root, "git-template"),
            "go_cache": os.path.join(run_root, "go-cache"),
            "go_mod_cache": os.path.join(run_root, "go-mod-cache"),
            "go_path": os.path.join(run_root, "go-path"),
            "go_tmp": os.path.join(run_root, "go-tmp"),
        }
        for label, path in directories.items():
            create_directory(audit, path, 0, 0, f"create_{label}")

        source = os.path.join(run_root, "source")
        require_absent(source, "source clone")
        environment = minimal_environment()
        clone_argv = git_argv(
            "-c",
            "protocol.file.allow=always",
            "clone",
            "--no-checkout",
            "--no-hardlinks",
            "--no-local",
            f"--template={directories['git_template']}",
            "--config=core.hooksPath=/dev/null",
            "--config=core.fsmonitor=false",
            "--config=core.attributesFile=/dev/null",
            "--",
            copied_bundle,
            source,
        )
        run_command(
            audit,
            "clone_root_owned_source",
            clone_argv,
            source,
            environment,
            run_root,
        )
        validate_directory(source, 0, 0, 0o700)

        resolved_commit = str(
            read_command(
                audit,
                "resolve_exact_commit",
                git_argv(
                    "-C", source, "rev-parse", "--verify", f"{commit}^{{commit}}"
                ),
                environment,
                source,
            )
        ).strip()
        if resolved_commit != commit:
            raise StageError(
                f"bundle resolved commit {resolved_commit!r}, expected {commit}"
            )
        checkout_argv = git_argv(
            "-C", source, "checkout", "--detach", "--no-guess", commit, "--"
        )
        run_command(
            audit,
            "checkout_exact_commit",
            checkout_argv,
            source,
            environment,
            source,
        )
        verify_clean_source(audit, source, commit, environment)
        verify_root_owned_worktree(source)

        build_environment = dict(environment)
        build_environment.update(
            {
                "CGO_ENABLED": "0",
                "GOCACHE": directories["go_cache"],
                "GOENV": "off",
                "GOFLAGS": "",
                "GOMODCACHE": directories["go_mod_cache"],
                "GOPATH": directories["go_path"],
                "GOTMPDIR": directories["go_tmp"],
                "GOWORK": "off",
                "GO111MODULE": "on",
                "TMPDIR": directories["go_tmp"],
            }
        )
        build_argv = (
            FIXED_TOOLS["timeout"],
            "--signal=TERM",
            "--kill-after=30s",
            "20m",
            FIXED_TOOLS["make"],
            "--no-print-directory",
            "-C",
            source,
            f"GO={FIXED_TOOLS['go']}",
            f"CLANG={FIXED_TOOLS['clang']}",
            "build-bpf",
            "build",
            "build-netns-anchor",
        )
        build_targets = ",".join(
            (
                os.path.join(source, "build", "wg_mix_tc.o"),
                os.path.join(source, "internal", "dataplane", "embedded", "wg_mix_tc.o"),
                os.path.join(source, "bin", "wg-mix-ebpf"),
                os.path.join(source, "bin", "wg-mix-ebpf-netns-anchor"),
                run_root,
                source,
                directories["go_cache"],
                directories["go_mod_cache"],
                directories["go_path"],
                directories["go_tmp"],
            )
        )
        run_command(
            audit,
            "build_staged_source",
            build_argv,
            build_targets,
            build_environment,
            run_root,
        )
        verify_root_owned_worktree(source)
        verify_clean_source(audit, source, commit, environment)
        verify_root_owned_worktree(source)

        artifacts = (
            ("main", os.path.join(source, "bin", "wg-mix-ebpf")),
            (
                "anchor",
                os.path.join(source, "bin", "wg-mix-ebpf-netns-anchor"),
            ),
            ("bpf_build", os.path.join(source, "build", "wg_mix_tc.o")),
            (
                "bpf_embedded",
                os.path.join(
                    source, "internal", "dataplane", "embedded", "wg_mix_tc.o"
                ),
            ),
            ("smoke_script", os.path.join(source, "scripts", "smoke-netns-wg.sh")),
            (
                "source_commit_script",
                os.path.join(source, "scripts", "source-commit.sh"),
            ),
        )
        artifact_results: list[tuple[str, str, str, os.stat_result]] = []
        for label, path in artifacts:
            digest, metadata = open_hashed_file(path, 0, 0)
            artifact_results.append((label, path, digest, metadata))
        if artifact_results[2][2] != artifact_results[3][2]:
            raise StageError("build and embedded BPF object SHA-256 values differ")

        audit.emit(
            (
                ("timestamp", utc_timestamp()),
                ("event", "stage_result"),
                ("source_path", source),
                ("commit", commit),
                ("log_path", log_path),
            )
        )
        for label, path, digest, metadata in artifact_results:
            audit.emit(
                (
                    ("timestamp", utc_timestamp()),
                    ("event", "artifact_result"),
                    ("label", label),
                    ("path", path),
                    ("sha256", digest),
                    ("stat", format_stat(metadata)),
                )
            )
        audit.emit(
            (
                ("timestamp", utc_timestamp()),
                ("event", "script_result"),
                ("label", "stage_launcher"),
                ("path", launcher_path),
                ("sha256", launcher_sha256),
                ("stat", format_stat(launcher_metadata)),
            )
        )
        audit.emit(
            (
                ("timestamp", utc_timestamp()),
                ("event", "script_result"),
                ("label", "stage_helper"),
                ("path", "/proc/self/fd/9"),
                ("sha256", helper_sha256),
                ("stat", format_stat(helper_metadata)),
            )
        )
    finally:
        os.close(source_fd)


def usage() -> str:
    return (
        "usage: scripts/stage-root-owned-test-source.sh "
        "--bundle /absolute/candidate.bundle "
        "--bundle-sha256 <64-lowercase-hex> "
        "--commit <40-lowercase-hex> --run-id <8-lowercase-hex>"
    )


def parse_internal(argv: Sequence[str]) -> tuple[str, str, str, str, list[str]]:
    if len(argv) < 5:
        raise StageError("missing anchored launcher metadata")
    expected_prefixes = (
        "--launcher-fd=",
        "--launcher-path=",
        "--launcher-sha256=",
        "--helper-fd=",
        "--helper-sha256=",
    )
    values: list[str] = []
    for argument, prefix in zip(argv[:5], expected_prefixes, strict=True):
        if not argument.startswith(prefix) or argument == prefix:
            raise StageError("invalid anchored launcher metadata")
        values.append(argument[len(prefix) :])
    return values[0], values[1], values[2], values[3], values[4], list(argv[5:])


def main() -> int:
    try:
        (
            launcher_fd_text,
            launcher_path,
            launcher_expected_sha,
            helper_fd_text,
            helper_expected_sha,
            arguments,
        ) = parse_internal(sys.argv[1:])
        if launcher_fd_text != "/proc/self/fd/8" or helper_fd_text != "/proc/self/fd/9":
            raise StageError("unexpected anchored descriptor path")
        launcher_sha, launcher_metadata = anchored_file(
            8, launcher_path, launcher_expected_sha, 0o500
        )
        helper_sha, helper_metadata = anchored_file(
            9, None, helper_expected_sha, 0o400
        )

        if len(arguments) != 8 or arguments[0::2] != [
            "--bundle",
            "--bundle-sha256",
            "--commit",
            "--run-id",
        ]:
            raise StageError(usage())
        stage_source(
            arguments[1],
            arguments[3],
            arguments[5],
            arguments[7],
            launcher_path,
            launcher_sha,
            launcher_metadata,
            helper_sha,
            helper_metadata,
        )

        final_launcher_sha, final_launcher_metadata = anchored_file(
            8, launcher_path, launcher_sha, 0o500
        )
        final_helper_sha, final_helper_metadata = anchored_file(
            9, None, helper_sha, 0o400
        )
        if (
            final_launcher_sha != launcher_sha
            or exact_stat(final_launcher_metadata) != exact_stat(launcher_metadata)
            or final_helper_sha != helper_sha
            or exact_stat(final_helper_metadata) != exact_stat(helper_metadata)
        ):
            raise StageError("anchored staging scripts changed during execution")
        return 0
    except (StageError, FileNotFoundError, PermissionError, OSError) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
