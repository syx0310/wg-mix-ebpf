#!/usr/bin/env python3
"""Build a local, path-projected OSS repository without consulting remotes."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


MANIFEST_FORMAT = "wg-mix-ebpf-oss-public-paths-v1"
MANIFEST_KEYS = {
    "format",
    "main_commit",
    "legacy_public_history_commit",
    "public_paths",
}
OUTPUT_REFS = {
    "main": "refs/heads/main",
    "legacy-public-history": "refs/heads/legacy-public-history",
}
DENIED_ROOTS = (
    b".worktree",
    b"credentials",
    b"credientials",
    b"docs",
    b"refs",
    b"scripts/private-release",
)
DENIED_LITERAL_PREFIXES = (b"scripts/realhost-b82-",)
GRAPH_BOUND_HEADERS = (b"gpgsig", b"gpgsig-sha256", b"mergetag")
EMPTY_TREE_OID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
DIAGNOSTIC_LIMIT = 2048
OID_RE = re.compile(r"[0-9a-f]{40}\Z")


class ReplayError(RuntimeError):
    pass


class CommandError(ReplayError):
    def __init__(
        self,
        argv: Sequence[str],
        returncode: int,
        stdout: bytes,
        stderr: bytes,
        reason: str,
    ) -> None:
        command = " ".join(argv)
        if len(command) > DIAGNOSTIC_LIMIT:
            command = command[:DIAGNOSTIC_LIMIT] + "...[truncated]"
        super().__init__(
            f"command {reason} ({returncode}): {command}; "
            f"{bounded_stream('stdout', stdout)}; {bounded_stream('stderr', stderr)}"
        )


@dataclass(frozen=True, order=True)
class TreeEntry:
    path: bytes
    mode: bytes
    kind: bytes
    oid: str
    size: int | None


@dataclass(frozen=True)
class CommitRecord:
    oid: str
    parents: tuple[str, ...]
    tree: str


@dataclass
class SourceHistory:
    label: str
    repo: "GitRepo"
    tip: str
    commits: list[CommitRecord]
    trees: dict[str, tuple[TreeEntry, ...]]


@dataclass(frozen=True)
class RepoBoundary:
    command_root: Path
    protected_roots: tuple[Path, ...]


def git_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    fixed_injections = (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
    )
    for name in tuple(env):
        if name in fixed_injections or name.startswith(
            ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
        ):
            env.pop(name, None)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        }
    )
    if extra:
        env.update(extra)
    return env


def bounded_stream(name: str, contents: bytes) -> str:
    sample = contents[:DIAGNOSTIC_LIMIT].decode("utf-8", "replace")
    suffix = (
        f"...[truncated {len(contents) - DIAGNOSTIC_LIMIT} bytes]"
        if len(contents) > DIAGNOSTIC_LIMIT
        else ""
    )
    return f"{name}={sample!r}{suffix}"


def run_command(
    argv: Sequence[str],
    *,
    data: bytes | None = None,
    extra_env: dict[str, str] | None = None,
) -> bytes:
    try:
        completed = subprocess.run(
            argv,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=git_environment(extra_env),
        )
    except OSError as exc:
        raise ReplayError(f"cannot execute {argv[0]}: {exc}") from exc
    if completed.returncode != 0:
        raise CommandError(
            argv,
            completed.returncode,
            completed.stdout,
            completed.stderr,
            "failed",
        )
    if completed.stderr:
        raise CommandError(
            argv,
            completed.returncode,
            completed.stdout,
            completed.stderr,
            "emitted unexpected stderr",
        )
    return completed.stdout


def decoded_path(
    raw: bytes, description: str, *, strict: bool, newline_terminated: bool
) -> Path:
    if newline_terminated:
        if not raw.endswith(b"\n"):
            raise ReplayError(f"Git returned an invalid {description}")
        value = raw[:-1]
    else:
        value = raw
    if not value or b"\0" in value:
        raise ReplayError(f"Git returned an invalid {description}")
    try:
        return Path(os.fsdecode(value)).resolve(strict=strict)
    except OSError as exc:
        raise ReplayError(f"cannot canonicalize {description}: {exc}") from exc


def canonical_repo_boundary(path: Path) -> RepoBoundary:
    try:
        requested = path.resolve(strict=True)
    except OSError as exc:
        raise ReplayError(f"repository path is not accessible: {path}: {exc}") from exc
    if not requested.is_dir():
        raise ReplayError(f"repository path is not a directory: {requested}")

    def probe(*args: str) -> bytes:
        return run_command(("git", "--no-replace-objects", "-C", str(requested), *args))

    bare = probe("rev-parse", "--is-bare-repository").decode("ascii").strip()
    if bare not in {"true", "false"}:
        raise ReplayError(f"Git returned an invalid bare-repository state: {bare!r}")
    git_dir = decoded_path(
        probe("rev-parse", "--absolute-git-dir"),
        "Git directory",
        strict=True,
        newline_terminated=True,
    )
    common_dir = decoded_path(
        probe("rev-parse", "--path-format=absolute", "--git-common-dir"),
        "Git common directory",
        strict=True,
        newline_terminated=True,
    )
    object_dir = decoded_path(
        probe("rev-parse", "--path-format=absolute", "--git-path", "objects"),
        "Git object directory",
        strict=True,
        newline_terminated=True,
    )
    worktree = (
        None
        if bare == "true"
        else decoded_path(
            probe("rev-parse", "--show-toplevel"),
            "Git worktree top level",
            strict=True,
            newline_terminated=True,
        )
    )

    for alternates_name in ("alternates", "http-alternates"):
        if os.path.lexists(object_dir / "info" / alternates_name):
            raise ReplayError(
                f"input repository object alternates are forbidden: {object_dir / 'info' / alternates_name}"
            )
    pack_dir = object_dir / "pack"
    if pack_dir.is_dir():
        with os.scandir(pack_dir) as entries:
            if any(entry.name.endswith(".promisor") for entry in entries):
                raise ReplayError(
                    f"input repository promisor packs are forbidden: {pack_dir}"
                )
    config_names = probe("config", "--name-only", "--null", "--list")
    for name in config_names.rstrip(b"\0").split(b"\0") if config_names else ():
        lowered = name.lower()
        if lowered == b"extensions.partialclone" or (
            lowered.startswith(b"remote.")
            and lowered.endswith((b".promisor", b".partialclonefilter"))
        ):
            raise ReplayError(
                f"input repository partial-clone configuration is forbidden: {os.fsdecode(name)}"
            )

    protected = {git_dir, common_dir, object_dir}
    if worktree is not None:
        protected.add(worktree)
    worktree_list = probe("worktree", "list", "--porcelain", "-z")
    for field in worktree_list.split(b"\0"):
        if field.startswith(b"worktree "):
            protected.add(
                decoded_path(
                    field.removeprefix(b"worktree "),
                    "registered Git worktree",
                    strict=False,
                    newline_terminated=False,
                )
            )
    return RepoBoundary(worktree or git_dir, tuple(sorted(protected, key=os.fspath)))


class GitRepo:
    def __init__(self, path: Path) -> None:
        self.boundary = canonical_repo_boundary(path)
        self.path = self.boundary.command_root
        if self.run_text("rev-parse", "--show-object-format") != "sha1":
            raise ReplayError(f"repository must use SHA-1 objects: {self.path}")
        if self.run_text("rev-parse", "--is-shallow-repository") != "false":
            raise ReplayError(f"shallow repositories are not accepted: {self.path}")

    def run(
        self,
        *args: str,
        data: bytes | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> bytes:
        return run_command(
            ("git", "--no-replace-objects", "-C", str(self.path), *args),
            data=data,
            extra_env=extra_env,
        )

    def run_text(self, *args: str, extra_env: dict[str, str] | None = None) -> str:
        return self.run(*args, extra_env=extra_env).decode("ascii").strip()

    def require_commit(self, oid: str) -> None:
        require_oid(oid)
        if self.run_text("cat-file", "-t", oid) != "commit":
            raise ReplayError(f"object is not a commit: {oid}")

    def commits(self, tip: str) -> list[CommitRecord]:
        self.require_commit(tip)
        raw = self.run("rev-list", "--topo-order", "--reverse", "--parents", tip)
        records: list[CommitRecord] = []
        seen: set[str] = set()
        for line in raw.decode("ascii").splitlines():
            words = line.split()
            oid = words[0]
            parents = tuple(words[1:])
            if any(parent not in seen for parent in parents):
                raise ReplayError(f"history is not parent-first at {oid}")
            tree = self.run_text("show", "--no-patch", "--format=%T", oid)
            require_oid(tree)
            records.append(CommitRecord(oid, parents, tree))
            seen.add(oid)
        if not records or records[-1].oid != tip:
            raise ReplayError(f"history walk did not end at requested commit: {tip}")
        return records

    def entries(self, tree: str) -> tuple[TreeEntry, ...]:
        raw = self.run("ls-tree", "-r", "-z", "-l", "--full-tree", tree)
        entries: list[TreeEntry] = []
        for record in raw.split(b"\0"):
            if not record:
                continue
            try:
                metadata, path = record.split(b"\t", 1)
                mode, kind, oid_bytes, size_bytes = metadata.split()
            except ValueError as exc:
                raise ReplayError(f"invalid ls-tree record for tree {tree}") from exc
            oid = oid_bytes.decode("ascii")
            require_oid(oid)
            if kind not in {b"blob", b"commit"}:
                raise ReplayError(
                    f"unsupported leaf kind {kind!r} at {display_path(path)}"
                )
            size = None if size_bytes == b"-" else int(size_bytes)
            entries.append(TreeEntry(path, mode, kind, oid, size))
        return tuple(sorted(entries))

    def object_bytes(self, kind: str, oid: str) -> bytes:
        return self.run("cat-file", kind, oid)

    def write_object(self, kind: str, contents: bytes) -> str:
        oid = (
            self.run("hash-object", "-t", kind, "-w", "--stdin", data=contents)
            .decode("ascii")
            .strip()
        )
        require_oid(oid)
        return oid

    def protects(self, path: Path) -> bool:
        return any(
            root == path or path.is_relative_to(root)
            for root in self.boundary.protected_roots
        )


def require_oid(oid: str) -> None:
    if not OID_RE.fullmatch(oid):
        raise ReplayError(
            f"commit and object IDs must be literal lowercase 40hex: {oid!r}"
        )


def path_bytes(value: str) -> bytes:
    try:
        encoded = value.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError as exc:
        raise ReplayError(
            f"manifest path is not byte-representable: {value!r}"
        ) from exc
    validate_path(encoded)
    return encoded


def validate_path(path: bytes) -> None:
    if not path or path.startswith(b"/") or path.endswith(b"/") or b"\0" in path:
        raise ReplayError(f"invalid repository path: {display_path(path)}")
    if any(part in {b"", b".", b".."} for part in path.split(b"/")):
        raise ReplayError(f"non-normalized repository path: {display_path(path)}")


def display_path(path: bytes) -> str:
    return json.dumps(path.decode("utf-8", "surrogateescape"), ensure_ascii=True)


def is_denied(path: bytes) -> bool:
    components = path.split(b"/")
    return (
        b"AGENTS.md" in components
        or any(component.lower().endswith(b".md") for component in components)
        or any(path == root or path.startswith(root + b"/") for root in DENIED_ROOTS)
        or path.startswith(DENIED_LITERAL_PREFIXES)
    )


def load_manifest(path: Path, main_commit: str, legacy_commit: str) -> frozenset[bytes]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReplayError(f"cannot read PUBLIC manifest {path}: {exc}") from exc
    if not isinstance(value, dict) or set(value) != MANIFEST_KEYS:
        raise ReplayError(
            f"PUBLIC manifest must contain exactly: {sorted(MANIFEST_KEYS)}"
        )
    if value["format"] != MANIFEST_FORMAT:
        raise ReplayError(f"unsupported PUBLIC manifest format: {value['format']!r}")
    if value["main_commit"] != main_commit:
        raise ReplayError(
            "PUBLIC manifest main_commit does not match the explicit input commit"
        )
    if value["legacy_public_history_commit"] != legacy_commit:
        raise ReplayError(
            "PUBLIC manifest legacy commit does not match the explicit input commit"
        )
    raw_paths = value["public_paths"]
    if not isinstance(raw_paths, list) or any(
        not isinstance(item, str) for item in raw_paths
    ):
        raise ReplayError("PUBLIC manifest public_paths must be a JSON string array")
    paths = [path_bytes(item) for item in raw_paths]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ReplayError(
            "PUBLIC manifest public_paths must be bytewise sorted and unique"
        )
    denied = [path for path in paths if is_denied(path)]
    if denied:
        raise ReplayError(
            f"PUBLIC manifest attempts to allow a fixed-deny path: {display_path(denied[0])}"
        )
    return frozenset(paths)


def scan_history(label: str, repo: GitRepo, tip: str) -> SourceHistory:
    commits = repo.commits(tip)
    trees: dict[str, tuple[TreeEntry, ...]] = {}
    for record in commits:
        if record.tree not in trees:
            trees[record.tree] = repo.entries(record.tree)
    return SourceHistory(label, repo, tip, commits, trees)


def classify(
    histories: Iterable[SourceHistory], public_paths: frozenset[bytes]
) -> tuple[list[tuple[str, TreeEntry]], set[str], set[str]]:
    unknown: set[tuple[str, TreeEntry]] = set()
    private_blobs: set[str] = set()
    public_blobs: set[str] = set()
    seen_paths: set[bytes] = set()
    for history in histories:
        for entries in history.trees.values():
            for entry in entries:
                seen_paths.add(entry.path)
                if is_denied(entry.path):
                    if entry.kind == b"blob":
                        private_blobs.add(entry.oid)
                elif entry.path in public_paths:
                    if entry.kind == b"blob":
                        public_blobs.add(entry.oid)
                else:
                    unknown.add((history.label, entry))
    unused = sorted(public_paths - seen_paths)
    if unused:
        raise ReplayError(
            f"PUBLIC manifest contains a path absent from both histories: {display_path(unused[0])}"
        )
    return (
        sorted(unknown, key=lambda item: (item[0], item[1])),
        private_blobs,
        public_blobs,
    )


def parse_commit(raw: bytes) -> tuple[list[list[bytes]], bytes]:
    try:
        header, message = raw.split(b"\n\n", 1)
    except ValueError as exc:
        raise ReplayError("commit object has no header/message separator") from exc
    fields: list[list[bytes]] = []
    for line in header.split(b"\n"):
        if line.startswith(b" "):
            if not fields:
                raise ReplayError("commit object starts with a continuation header")
            fields[-1].append(line)
        else:
            fields.append([line])
    return fields, message


def field_name(field: list[bytes]) -> bytes:
    return field[0].partition(b" ")[0]


def rewrite_commit(raw: bytes, tree: str, parents: tuple[str, ...]) -> bytes:
    fields, message = parse_commit(raw)
    rewritten: list[bytes] = []
    parent_index = 0
    tree_count = 0
    for field in fields:
        name = field_name(field)
        if name in GRAPH_BOUND_HEADERS:
            raise ReplayError(
                f"graph-bound commit header is not replayable: {name.decode('ascii')}"
            )
        if name == b"tree":
            tree_count += 1
            rewritten.append(b"tree " + tree.encode("ascii"))
        elif name == b"parent":
            if parent_index >= len(parents):
                raise ReplayError(
                    "commit has more parent headers than its history walk"
                )
            rewritten.append(b"parent " + parents[parent_index].encode("ascii"))
            parent_index += 1
        else:
            rewritten.append(b"\n".join(field))
    if tree_count != 1 or parent_index != len(parents):
        raise ReplayError("commit tree/parent headers do not match its history walk")
    return b"\n".join(rewritten) + b"\n\n" + message


def validated_source_commits(histories: Iterable[SourceHistory]) -> dict[str, bytes]:
    commits: dict[str, bytes] = {}
    for history in histories:
        for record in history.commits:
            raw = history.repo.object_bytes("commit", record.oid)
            previous = commits.get(record.oid)
            if previous is not None and previous != raw:
                raise ReplayError(
                    f"same source commit OID has different raw objects: {record.oid}"
                )
            fields, _ = parse_commit(raw)
            forbidden = sorted(
                {field_name(field) for field in fields} & set(GRAPH_BOUND_HEADERS)
            )
            if forbidden:
                raise ReplayError(
                    "graph-bound commit headers prevent replay; "
                    f"source={history.label} commit={record.oid} "
                    f"headers={','.join(name.decode('ascii') for name in forbidden)}"
                )
            commits[record.oid] = raw
    return commits


def graph_headers(raw: bytes) -> tuple[str, tuple[str, ...], tuple[bytes, ...], bytes]:
    fields, message = parse_commit(raw)
    tree = ""
    parents: list[str] = []
    metadata: list[bytes] = []
    for field in fields:
        name = field_name(field)
        if name == b"tree":
            tree = field[0].split(b" ", 1)[1].decode("ascii")
        elif name == b"parent":
            parents.append(field[0].split(b" ", 1)[1].decode("ascii"))
        else:
            metadata.append(b"\n".join(field))
    require_oid(tree)
    return tree, tuple(parents), tuple(metadata), message


class ReplayEngine:
    def __init__(
        self,
        histories: list[SourceHistory],
        source_commits: dict[str, bytes],
        public_paths: frozenset[bytes],
        private_blobs: set[str],
        output: Path,
    ) -> None:
        self.histories = histories
        self.source_commits = source_commits
        self.public_paths = public_paths
        self.private_blobs = private_blobs
        self.output = output
        self.destination: GitRepo | None = None
        self.commit_map: dict[str, str] = {}
        self.target_map: dict[str, str] = {}
        self.projected_graph: dict[str, tuple[str, tuple[str, ...]]] = {}
        self.tree_maps: dict[tuple[str, str], str] = {}
        self.copied_blobs: set[str] = set()

    def run(self) -> list[tuple[str, str, str]]:
        self._create_destination()
        assert self.destination is not None
        with tempfile.TemporaryDirectory(prefix="oss-replay-index-") as temp_dir:
            for history in self.histories:
                self._replay_history(history, Path(temp_dir))
        self._publish_refs()
        self._verify()
        return [
            (history.label, record.oid, self.commit_map[record.oid])
            for history in self.histories
            for record in history.commits
        ]

    def _create_destination(self) -> None:
        if os.path.lexists(self.output):
            raise ReplayError(f"output path already exists: {self.output}")
        try:
            parent = self.output.parent.resolve(strict=True)
        except OSError as exc:
            raise ReplayError(
                f"output parent is not accessible: {self.output.parent}: {exc}"
            ) from exc
        output = parent / self.output.name
        for history in self.histories:
            if history.repo.protects(output):
                raise ReplayError(
                    f"output must not be inside an input repository boundary: {output}"
                )
        run_command(
            (
                "git",
                "-c",
                "init.templateDir=",
                "-c",
                "init.defaultBranch=main",
                "init",
                "--bare",
                "--quiet",
                "--object-format=sha1",
                str(output),
            )
        )
        self.output = output
        self.destination = GitRepo(output)

    def _project_tree(self, history: SourceHistory, tree: str, index_dir: Path) -> str:
        cache_key = (history.label, tree)
        cached = self.tree_maps.get(cache_key)
        if cached:
            return cached
        assert self.destination is not None
        entries = tuple(
            entry for entry in history.trees[tree] if entry.path in self.public_paths
        )
        if not entries:
            projected = self.destination.write_object("tree", b"")
            if projected != EMPTY_TREE_OID:
                raise ReplayError(f"canonical empty tree identity changed: {projected}")
            self.tree_maps[cache_key] = projected
            return projected
        for entry in entries:
            if entry.kind != b"blob" or entry.oid in self.copied_blobs:
                continue
            contents = history.repo.object_bytes("blob", entry.oid)
            copied_oid = self.destination.write_object("blob", contents)
            if copied_oid != entry.oid:
                raise ReplayError(f"blob identity changed while copying {entry.oid}")
            self.copied_blobs.add(entry.oid)
        index_path = index_dir / f"index-{len(self.tree_maps)}"
        index_env = {"GIT_INDEX_FILE": str(index_path)}
        self.destination.run("read-tree", "--empty", extra_env=index_env)
        index_data = b"".join(
            entry.mode + b" " + entry.oid.encode("ascii") + b"\t" + entry.path + b"\0"
            for entry in entries
        )
        if index_data:
            self.destination.run(
                "update-index",
                "-z",
                "--index-info",
                data=index_data,
                extra_env=index_env,
            )
        projected = self.destination.run_text("write-tree", extra_env=index_env)
        require_oid(projected)
        self.tree_maps[cache_key] = projected
        return projected

    def _replay_history(self, history: SourceHistory, index_dir: Path) -> None:
        assert self.destination is not None
        for record in history.commits:
            projected_tree = self._project_tree(history, record.tree, index_dir)
            try:
                projected_parents = tuple(
                    self.commit_map[parent] for parent in record.parents
                )
            except KeyError as exc:
                raise ReplayError(
                    f"parent was not replayed before {record.oid}"
                ) from exc
            old_raw = history.repo.object_bytes("commit", record.oid)
            if old_raw != self.source_commits[record.oid]:
                raise ReplayError(
                    f"source commit changed after validation: {record.oid}"
                )
            old_tree, old_parents, _, _ = graph_headers(old_raw)
            if old_tree != record.tree or old_parents != record.parents:
                raise ReplayError(
                    f"raw commit graph differs from history walk at {record.oid}"
                )
            previous = self.commit_map.get(record.oid)
            if previous is not None:
                if self.projected_graph[record.oid] != (
                    projected_tree,
                    projected_parents,
                ):
                    raise ReplayError(
                        f"shared source commit projects differently across inputs: {record.oid}"
                    )
                continue
            new_raw = rewrite_commit(old_raw, projected_tree, projected_parents)
            new_oid = self.destination.write_object("commit", new_raw)
            collision = self.target_map.get(new_oid)
            if collision is not None and collision != record.oid:
                raise ReplayError(
                    "distinct source commits collapse after PUBLIC projection; "
                    f"source_a={collision} source_b={record.oid} target={new_oid}"
                )
            self.commit_map[record.oid] = new_oid
            self.target_map[new_oid] = record.oid
            self.projected_graph[record.oid] = (
                projected_tree,
                projected_parents,
            )

    def _publish_refs(self) -> None:
        assert self.destination is not None
        tips = {
            history.label: self.commit_map[history.tip] for history in self.histories
        }
        commands = ["start"]
        for label, ref in OUTPUT_REFS.items():
            commands.append(f"create {ref} {tips[label]}")
        commands.extend(("prepare", "commit", ""))
        self.destination.run(
            "update-ref", "--stdin", data="\n".join(commands).encode("ascii")
        )
        self.destination.run("symbolic-ref", "HEAD", OUTPUT_REFS["main"])

    def _verify(self) -> None:
        assert self.destination is not None
        expected_refs = sorted(OUTPUT_REFS.values())
        actual_refs = self.destination.run_text(
            "for-each-ref", "--format=%(refname)"
        ).splitlines()
        if actual_refs != expected_refs:
            raise ReplayError(
                f"output refs differ from the fixed allowlist: {actual_refs}"
            )
        if self.destination.run_text("symbolic-ref", "HEAD") != OUTPUT_REFS["main"]:
            raise ReplayError("output HEAD does not name refs/heads/main")

        output_blob_oids: set[str] = set()
        for history in self.histories:
            for record in history.commits:
                new_oid = self.commit_map[record.oid]
                old_raw = self.source_commits[record.oid]
                new_raw = self.destination.object_bytes("commit", new_oid)
                old_tree, _, old_metadata, old_message = graph_headers(old_raw)
                new_tree, new_parents, new_metadata, new_message = graph_headers(
                    new_raw
                )
                expected_parents = tuple(
                    self.commit_map[parent] for parent in record.parents
                )
                if new_parents != expected_parents:
                    raise ReplayError(
                        f"ordered parents changed while replaying {record.oid}"
                    )
                if new_metadata != old_metadata or new_message != old_message:
                    raise ReplayError(
                        f"commit metadata or message changed while replaying {record.oid}"
                    )
                expected_entries = tuple(
                    entry
                    for entry in history.trees[old_tree]
                    if entry.path in self.public_paths
                )
                actual_entries = self.destination.entries(new_tree)
                if actual_entries != expected_entries:
                    raise ReplayError(f"tree projection differs at {record.oid}")
                for entry in actual_entries:
                    if is_denied(entry.path) or entry.path not in self.public_paths:
                        raise ReplayError(
                            f"output contains a denied or unclassified path: {display_path(entry.path)}"
                        )
                    if entry.kind == b"blob":
                        output_blob_oids.add(entry.oid)

        for label, ref in OUTPUT_REFS.items():
            tip = self.destination.run_text("rev-parse", ref)
            expected_tip = self.commit_map[self._history(label).tip]
            if tip != expected_tip:
                raise ReplayError(f"output ref has the wrong tip: {ref}")
        if output_blob_oids & self.private_blobs:
            oid = sorted(output_blob_oids & self.private_blobs)[0]
            raise ReplayError(
                f"output shares a blob OID with fixed-deny content: {oid}"
            )

        reachable = set(self.destination.run_text("rev-list", "--all").splitlines())
        expected_commits = set(self.commit_map.values())
        if reachable != expected_commits or len(expected_commits) != len(
            self.commit_map
        ):
            raise ReplayError(
                "output commit graph is missing a source node or is not injective"
            )

        fsck = self.destination.run(
            "fsck",
            "--strict",
            "--full",
            "--unreachable",
            "--no-reflogs",
            "--no-progress",
        )
        if fsck.strip():
            raise ReplayError(
                f"strict fsck reported unreachable output objects: {fsck.decode('utf-8', 'replace').strip()}"
            )

    def _history(self, label: str) -> SourceHistory:
        return next(history for history in self.histories if history.label == label)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("inventory", "replay"):
        command = subparsers.add_parser(operation)
        command.add_argument("--main-repo", type=Path, required=True)
        command.add_argument("--main-commit", required=True)
        command.add_argument("--legacy-repo", type=Path, required=True)
        command.add_argument("--legacy-commit", required=True)
        if operation == "inventory":
            command.add_argument("--public-manifest", type=Path)
        else:
            command.add_argument("--public-manifest", type=Path, required=True)
            command.add_argument("--output", type=Path, required=True)
    return parser


def load_inputs(
    args: argparse.Namespace,
) -> tuple[list[SourceHistory], frozenset[bytes]]:
    require_oid(args.main_commit)
    require_oid(args.legacy_commit)
    main_repo = GitRepo(args.main_repo)
    legacy_repo = GitRepo(args.legacy_repo)
    public_paths = (
        load_manifest(args.public_manifest, args.main_commit, args.legacy_commit)
        if args.public_manifest
        else frozenset()
    )
    histories = [
        scan_history("main", main_repo, args.main_commit),
        scan_history("legacy-public-history", legacy_repo, args.legacy_commit),
    ]
    return histories, public_paths


def inventory(args: argparse.Namespace) -> int:
    histories, public_paths = load_inputs(args)
    unknown, _, _ = classify(histories, public_paths)
    for label, entry in unknown:
        print(
            json.dumps(
                {
                    "source": label,
                    "path": entry.path.decode("utf-8", "surrogateescape"),
                    "oid": entry.oid,
                    "size": entry.size,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    return 0


def replay(args: argparse.Namespace) -> int:
    histories, public_paths = load_inputs(args)
    unknown, private_blobs, public_blobs = classify(histories, public_paths)
    if unknown:
        label, entry = unknown[0]
        raise ReplayError(
            "unclassified paths prevent replay; "
            f"first={label}:{display_path(entry.path)} oid={entry.oid} size={entry.size} count={len(unknown)}"
        )
    overlap = private_blobs & public_blobs
    if overlap:
        raise ReplayError(
            f"a PUBLIC path shares fixed-deny blob content: {sorted(overlap)[0]}"
        )
    source_commits = validated_source_commits(histories)
    engine = ReplayEngine(
        histories, source_commits, public_paths, private_blobs, args.output
    )
    for label, old_oid, new_oid in engine.run():
        print(f"{label}\t{old_oid}\t{new_oid}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return inventory(args) if args.operation == "inventory" else replay(args)
    except ReplayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
