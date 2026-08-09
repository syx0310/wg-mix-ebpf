#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from oss_history_replay import ReplayError, run_command


SCRIPT = Path(__file__).with_name("oss_history_replay.py")
MANIFEST = Path(__file__).with_name("testdata") / "synthetic-public-manifest.json"
REPO_ROOT = SCRIPT.parents[2]
EMPTY_TREE_OID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
FIXTURE_MAKEFILE = b""".PHONY: test-unit test-private-oss-history-replay
test-private-oss-history-replay:
	@if test -e scripts/private-release; then \\
		test -f scripts/private-release/test_oss_history_replay.py || \\
			{ echo "private release tree is incomplete"; exit 1; }; \\
		python3 -B scripts/private-release/test_oss_history_replay.py; \\
	else \\
		echo "SKIP: private OSS history replay gate not present"; \\
	fi
test-unit: test-private-oss-history-replay
	@:
"""
ROOT_A_FILES = {
    "Makefile": FIXTURE_MAKEFILE,
    "app.txt": b"public app\n",
    "docs/secret.txt": b"private secret v1\n",
    "nested/AGENTS.md/private.txt": b"private agent policy\n",
    "README.md": b"private documentation\n",
    "scripts/private-release/internal.py": b"private tool\n",
    "scripts/realhost-b82-acceptance-v1/run.py": b"private real-host runner\n",
}


def clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
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


def run(
    argv: list[str],
    *,
    data: bytes | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        argv,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean_env(env),
        check=False,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {argv!r}\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
    return completed


@dataclass(frozen=True)
class SyntheticDag:
    repo: Path
    root_a: str
    private_only: str
    empty: str
    root_b: str
    merge: str
    tip: str
    private_blobs: frozenset[str]


@dataclass(frozen=True)
class RootRepo:
    repo: Path
    commit: str


class DagBuilder:
    def __init__(self, root: Path, name: str = "source.git") -> None:
        self.repo = root / name
        run(
            [
                "git",
                "-c",
                "init.templateDir=",
                "-c",
                "init.defaultBranch=main",
                "init",
                "--bare",
                "--quiet",
                str(self.repo),
            ]
        )
        self.index_count = 0
        self.timestamp = 1_700_000_000

    def git(
        self, *args: str, data: bytes | None = None, env: dict[str, str] | None = None
    ) -> bytes:
        return run(
            ["git", "--no-replace-objects", "-C", str(self.repo), *args],
            data=data,
            env=env,
        ).stdout

    def blob(self, contents: bytes) -> str:
        return (
            self.git("hash-object", "-t", "blob", "-w", "--stdin", data=contents)
            .decode()
            .strip()
        )

    def tree(self, files: dict[str, bytes]) -> tuple[str, dict[str, str]]:
        blobs = {path: self.blob(contents) for path, contents in files.items()}
        index = self.repo.parent / f"fixture-index-{self.index_count}"
        self.index_count += 1
        index_env = {"GIT_INDEX_FILE": str(index)}
        self.git("read-tree", "--empty", env=index_env)
        records = b"".join(
            b"100644 " + blobs[path].encode() + b"\t" + path.encode() + b"\0"
            for path in sorted(blobs)
        )
        self.git("update-index", "-z", "--index-info", data=records, env=index_env)
        tree = self.git("write-tree", env=index_env).decode().strip()
        return tree, blobs

    def commit(
        self,
        tree: str,
        parents: tuple[str, ...],
        message: bytes,
        *,
        encoding: str | None = None,
        extra_headers: tuple[bytes, ...] = (),
    ) -> str:
        identity = (
            f"Fixture Author <fixture@example.test> {self.timestamp} +0000".encode()
        )
        self.timestamp += 1
        headers = [b"tree " + tree.encode()]
        headers.extend(b"parent " + parent.encode() for parent in parents)
        headers.extend((b"author " + identity, b"committer " + identity))
        if encoding:
            headers.append(b"encoding " + encoding.encode())
        headers.extend(extra_headers)
        raw = b"\n".join(headers) + b"\n\n" + message
        return (
            self.git("hash-object", "-t", "commit", "-w", "--stdin", data=raw)
            .decode()
            .strip()
        )

    def build(self) -> SyntheticDag:
        tree_a, blobs_a = self.tree(dict(ROOT_A_FILES))
        root_a = self.commit(tree_a, (), b"root A\n")
        tree_private, blobs_private = self.tree(
            {
                "Makefile": ROOT_A_FILES["Makefile"],
                "app.txt": b"public app\n",
                "docs/secret.txt": b"private secret v2\n",
                "scripts/private-release/internal.py": b"private tool v2\n",
            }
        )
        private_only = self.commit(tree_private, (root_a,), b"private-only change\n")
        empty = self.commit(
            tree_private,
            (private_only,),
            b"caf\xe9 empty commit\n",
            encoding="ISO-8859-1",
        )
        tree_b, blobs_b = self.tree(
            {
                "refs/research.txt": b"private reference\n",
            }
        )
        root_b = self.commit(tree_b, (), b"root B\n")
        tree_merge, blobs_merge = self.tree(
            {
                "Makefile": ROOT_A_FILES["Makefile"],
                "app.txt": b"public app\n",
                "docs/secret.txt": b"private secret v2\n",
                "refs/research.txt": b"private reference\n",
                "scripts/private-release/internal.py": b"private tool v2\n",
            }
        )
        merge = self.commit(tree_merge, (empty, root_b), b"merge two roots\n")
        tree_tip, _ = self.tree(
            {
                "Makefile": ROOT_A_FILES["Makefile"],
                "app.txt": b"public app\n",
                "lib.txt": b"public library\n",
                "docs/secret.txt": b"private secret v2\n",
                "refs/research.txt": b"private reference\n",
                "scripts/private-release/internal.py": b"private tool v2\n",
            }
        )
        tip = self.commit(tree_tip, (merge,), b"publish library\n")
        private_paths = {
            blobs_a["docs/secret.txt"],
            blobs_a["scripts/private-release/internal.py"],
            blobs_a["nested/AGENTS.md/private.txt"],
            blobs_a["README.md"],
            blobs_a["scripts/realhost-b82-acceptance-v1/run.py"],
            blobs_private["docs/secret.txt"],
            blobs_private["scripts/private-release/internal.py"],
            blobs_b["refs/research.txt"],
            blobs_merge["docs/secret.txt"],
            blobs_merge["refs/research.txt"],
            blobs_merge["scripts/private-release/internal.py"],
        }
        self.git("update-ref", "refs/heads/main", tip)
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        return SyntheticDag(
            self.repo,
            root_a,
            private_only,
            empty,
            root_b,
            merge,
            tip,
            frozenset(private_paths),
        )


def build_root_repo(root: Path, name: str, files: dict[str, bytes]) -> RootRepo:
    builder = DagBuilder(root, name)
    tree, _ = builder.tree(files)
    commit = builder.commit(tree, (), b"root A\n")
    builder.git("update-ref", "refs/heads/main", commit)
    builder.git("symbolic-ref", "HEAD", "refs/heads/main")
    return RootRepo(builder.repo, commit)


def build_header_repo(root: Path, name: str, header: bytes) -> RootRepo:
    builder = DagBuilder(root, name)
    tree, _ = builder.tree({"app.txt": b"public app\n"})
    commit = builder.commit(
        tree, (), b"authenticated commit\n", extra_headers=(header,)
    )
    builder.git("update-ref", "refs/heads/main", commit)
    builder.git("symbolic-ref", "HEAD", "refs/heads/main")
    return RootRepo(builder.repo, commit)


def build_signed_ssh_repo(root: Path) -> RootRepo:
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        raise AssertionError("ssh-keygen is required for the signed-commit fixture")
    repo = root / "signed-ssh"
    run(
        [
            "git",
            "-c",
            "init.templateDir=",
            "init",
            "--quiet",
            "--initial-branch=main",
            str(repo),
        ]
    )
    signing_key = root / "fixture-signing-key"
    run([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(signing_key)])
    public_key = signing_key.with_suffix(".pub").read_text(encoding="ascii").strip()
    allowed_signers = root / "allowed-signers"
    allowed_signers.write_text(f"fixture@example.test {public_key}\n", encoding="ascii")
    app = repo / "app.txt"
    app.write_bytes(b"public app\n")
    for key, value in (
        ("user.name", "Fixture Author"),
        ("user.email", "fixture@example.test"),
        ("gpg.format", "ssh"),
        ("user.signingkey", str(signing_key)),
        ("gpg.ssh.allowedSignersFile", str(allowed_signers)),
    ):
        run(["git", "-C", str(repo), "config", key, value])
    run(["git", "-C", str(repo), "add", "app.txt"])
    commit_env = {
        "GIT_AUTHOR_DATE": "1700001000 +0000",
        "GIT_COMMITTER_DATE": "1700001000 +0000",
    }
    run(
        ["git", "-C", str(repo), "commit", "--quiet", "-S", "-m", "signed SSH"],
        env=commit_env,
    )
    commit = run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.decode().strip()
    verified = run(["git", "-C", str(repo), "verify-commit", commit])
    if b'Good "git" signature' not in verified.stdout + verified.stderr:
        raise AssertionError(
            "SSH fixture commit did not verify as a good Git signature"
        )
    return RootRepo(repo, commit)


class OssHistoryReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="oss-history-replay-test-")
        self.root = Path(self.temp.name)
        self.dag = DagBuilder(self.root).build()
        self.shared_legacy = build_root_repo(
            self.root, "legacy-shared.git", dict(ROOT_A_FILES)
        )
        self.assertEqual(self.shared_legacy.commit, self.dag.root_a)
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(self.dag.tip, self.manifest["main_commit"])
        self.assertEqual(self.dag.root_a, self.manifest["legacy_public_history_commit"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def tool(
        self,
        operation: str,
        *extra: str,
        check: bool = True,
        main_repo: Path | None = None,
        main_commit: str | None = None,
        legacy_repo: Path | None = None,
        legacy_commit: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                operation,
                "--main-repo",
                str(main_repo or self.dag.repo),
                "--main-commit",
                main_commit or self.dag.tip,
                "--legacy-repo",
                str(legacy_repo or self.shared_legacy.repo),
                "--legacy-commit",
                legacy_commit or self.shared_legacy.commit,
                *extra,
            ],
            check=check,
        )

    def git(self, repo: Path, *args: str) -> bytes:
        return run(["git", "--no-replace-objects", "-C", str(repo), *args]).stdout

    def parse_map(self, output: bytes) -> dict[tuple[str, str], str]:
        result: dict[tuple[str, str], str] = {}
        for line in output.decode("ascii").splitlines():
            label, old, new = line.split("\t")
            result[(label, old)] = new
        return result

    def write_manifest(
        self,
        name: str,
        main_commit: str,
        legacy_commit: str,
        public_paths: list[str],
    ) -> Path:
        manifest = self.root / name
        manifest.write_text(
            json.dumps(
                {
                    "format": "wg-mix-ebpf-oss-public-paths-v1",
                    "main_commit": main_commit,
                    "legacy_public_history_commit": legacy_commit,
                    "public_paths": sorted(public_paths),
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def test_replay_preserves_topology_metadata_and_is_repeatable(self) -> None:
        first = self.root / "export-one.git"
        second = self.root / "export-two.git"
        result_one = self.tool(
            "replay",
            "--public-manifest",
            str(MANIFEST),
            "--output",
            str(first),
        )
        result_two = self.tool(
            "replay",
            "--public-manifest",
            str(MANIFEST),
            "--output",
            str(second),
        )
        self.assertEqual(result_one.stdout, result_two.stdout)
        self.assertEqual(self.git(first, "show-ref"), self.git(second, "show-ref"))

        mapping = self.parse_map(result_one.stdout)
        expected_lines = 7
        self.assertEqual(len(result_one.stdout.decode().splitlines()), expected_lines)
        merge = mapping[("main", self.dag.merge)]
        empty = mapping[("main", self.dag.empty)]
        private_only = mapping[("main", self.dag.private_only)]
        root_a = mapping[("main", self.dag.root_a)]
        root_b = mapping[("main", self.dag.root_b)]
        self.assertEqual(
            root_a,
            mapping[("legacy-public-history", self.shared_legacy.commit)],
        )
        self.assertEqual(
            self.git(first, "show", "--no-patch", "--format=%P", merge)
            .decode()
            .strip(),
            f"{empty} {root_b}",
        )
        self.assertEqual(
            self.git(first, "rev-parse", f"{root_a}^{{tree}}").strip(),
            self.git(first, "rev-parse", f"{private_only}^{{tree}}").strip(),
        )
        self.assertEqual(
            self.git(first, "rev-parse", f"{private_only}^{{tree}}").strip(),
            self.git(first, "rev-parse", f"{empty}^{{tree}}").strip(),
        )
        self.assertEqual(
            self.git(first, "rev-parse", f"{empty}^{{tree}}").strip(),
            self.git(first, "rev-parse", f"{merge}^{{tree}}").strip(),
        )
        self.assertEqual(
            self.git(first, "rev-parse", f"{root_b}^{{tree}}").decode().strip(),
            EMPTY_TREE_OID,
        )
        self.assertEqual(
            self.git(first, "cat-file", "-t", EMPTY_TREE_OID).decode().strip(),
            "tree",
        )
        roots = (
            self.git(first, "rev-list", "--all", "--max-parents=0")
            .decode()
            .splitlines()
        )
        self.assertEqual(set(roots), {root_a, root_b})

        source_empty = self.git(self.dag.repo, "cat-file", "commit", self.dag.empty)
        output_empty = self.git(first, "cat-file", "commit", empty)
        self.assertIn(b"encoding ISO-8859-1\n", output_empty)
        self.assertTrue(source_empty.endswith(b"caf\xe9 empty commit\n"))
        self.assertTrue(output_empty.endswith(b"caf\xe9 empty commit\n"))

        output_blobs: set[str] = set()
        for commit in self.git(first, "rev-list", "--all").decode().splitlines():
            paths = (
                self.git(first, "ls-tree", "-r", "--name-only", commit)
                .decode()
                .splitlines()
            )
            self.assertTrue(set(paths) <= {"Makefile", "app.txt", "lib.txt"})
            records = self.git(first, "ls-tree", "-r", commit).decode().splitlines()
            output_blobs.update(record.split()[2] for record in records)
        self.assertFalse(output_blobs & self.dag.private_blobs)
        fsck = run(
            [
                "git",
                "-C",
                str(first),
                "fsck",
                "--strict",
                "--full",
                "--unreachable",
                "--no-reflogs",
                "--no-progress",
            ]
        )
        self.assertEqual(fsck.stdout, b"")
        self.assertEqual(fsck.stderr, b"")

        checkout = self.root / "projected-oss-tree"
        checkout.mkdir()
        run(
            [
                "git",
                f"--git-dir={first}",
                f"--work-tree={checkout}",
                "checkout",
                "--force",
                "refs/heads/main",
            ]
        )
        self.assertFalse((checkout / "scripts" / "private-release").exists())
        private_gate = run(
            ["make", "-C", str(checkout), "test-private-oss-history-replay"]
        )
        self.assertIn(
            b"SKIP: private OSS history replay gate not present",
            private_gate.stdout,
        )
        private_test = checkout / "scripts" / "private-release"
        private_test.mkdir(parents=True)
        (private_test / "test_oss_history_replay.py").write_text(
            "raise SystemExit(7)\n", encoding="utf-8"
        )
        failing_gate = run(
            ["make", "-C", str(checkout), "test-private-oss-history-replay"],
            check=False,
        )
        self.assertNotEqual(failing_gate.returncode, 0)

    def test_unclassified_path_fails_before_output_creation(self) -> None:
        manifest = self.root / "incomplete.json"
        value = dict(self.manifest)
        value["public_paths"] = ["app.txt"]
        manifest.write_text(json.dumps(value), encoding="utf-8")
        output = self.root / "must-not-exist.git"
        result = self.tool(
            "replay",
            "--public-manifest",
            str(manifest),
            "--output",
            str(output),
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"unclassified paths prevent replay", result.stderr)
        self.assertFalse(output.exists())

    def test_inventory_emits_only_unclassified_metadata(self) -> None:
        result = self.tool("inventory")
        records = [json.loads(line) for line in result.stdout.decode().splitlines()]
        self.assertEqual(
            {tuple(record) for record in records}, {("oid", "path", "size", "source")}
        )
        self.assertEqual(
            {record["path"] for record in records},
            {"Makefile", "app.txt", "lib.txt"},
        )
        self.assertFalse(any("docs" in record["path"] for record in records))
        self.assertFalse(any("private-release" in record["path"] for record in records))
        self.assertFalse(any("AGENTS.md" in record["path"] for record in records))
        self.assertFalse(
            any(record["path"].lower().endswith(".md") for record in records)
        )
        self.assertFalse(any("realhost-b82-" in record["path"] for record in records))

    def test_manifest_cannot_override_fixed_deny(self) -> None:
        denied_paths = (
            ".worktree/task/private.bin",
            "README.md",
            "credentials/host",
            "credientials/host",
            "docs/secret.txt",
            "internal/Guide.MD",
            "nested/AGENTS.md/private.txt",
            "refs/research.txt",
            "scripts/private-release/internal.py",
            "scripts/realhost-b82-acceptance-v1/run.py",
        )
        for index, denied_path in enumerate(denied_paths):
            with self.subTest(path=denied_path):
                manifest = self.root / f"denied-{index}.json"
                value = dict(self.manifest)
                value["public_paths"] = sorted(
                    [*self.manifest["public_paths"], denied_path]
                )
                manifest.write_text(json.dumps(value), encoding="utf-8")
                result = self.tool(
                    "replay",
                    "--public-manifest",
                    str(manifest),
                    "--output",
                    str(self.root / f"denied-{index}.git"),
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"fixed-deny path", result.stderr)

    def test_distinct_source_roots_cannot_collapse(self) -> None:
        collision_files = dict(ROOT_A_FILES)
        collision_files["docs/secret.txt"] = b"different private root\n"
        collision = build_root_repo(self.root, "legacy-collision.git", collision_files)
        self.assertNotEqual(collision.commit, self.dag.root_a)
        manifest = self.write_manifest(
            "collision-manifest.json",
            self.dag.tip,
            collision.commit,
            ["Makefile", "app.txt", "lib.txt"],
        )
        output = self.root / "collision-output.git"
        result = self.tool(
            "replay",
            "--public-manifest",
            str(manifest),
            "--output",
            str(output),
            check=False,
            legacy_repo=collision.repo,
            legacy_commit=collision.commit,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"distinct source commits collapse", result.stderr)
        self.assertTrue(output.is_dir())
        self.assertEqual(self.git(output, "for-each-ref"), b"")

    def test_graph_bound_authentication_headers_fail_before_output(self) -> None:
        signed = build_signed_ssh_repo(self.root)
        fixtures = (
            ("gpgsig", signed),
            (
                "gpgsig-sha256",
                build_header_repo(
                    self.root,
                    "signed-sha256.git",
                    b"gpgsig-sha256 -----BEGIN PGP SIGNATURE-----\n fake\n -----END PGP SIGNATURE-----",
                ),
            ),
            (
                "mergetag",
                build_header_repo(
                    self.root,
                    "mergetag.git",
                    b"mergetag object 0000000000000000000000000000000000000000\n type commit\n tag fixture",
                ),
            ),
        )
        for name, fixture in fixtures:
            with self.subTest(header=name):
                manifest = self.write_manifest(
                    f"{name}-manifest.json",
                    fixture.commit,
                    self.shared_legacy.commit,
                    ["Makefile", "app.txt"],
                )
                output = self.root / f"{name}-output.git"
                result = self.tool(
                    "replay",
                    "--public-manifest",
                    str(manifest),
                    "--output",
                    str(output),
                    check=False,
                    main_repo=fixture.repo,
                    main_commit=fixture.commit,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(name.encode(), result.stderr)
                self.assertFalse(output.exists())

    def test_subdirectory_input_protects_canonical_worktree(self) -> None:
        clone = self.root / "source-worktree"
        run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                str(self.dag.repo),
                str(clone),
            ]
        )
        nested = clone / "nested-input"
        nested.mkdir()
        output = clone / "must-not-create.git"
        result = self.tool(
            "replay",
            "--public-manifest",
            str(MANIFEST),
            "--output",
            str(output),
            check=False,
            main_repo=nested,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"input repository boundary", result.stderr)
        self.assertFalse(output.exists())

    def test_registered_worktree_with_trailing_newline_is_protected(self) -> None:
        primary = self.root / "primary-worktree"
        run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                str(self.dag.repo),
                str(primary),
            ]
        )
        linked = self.root / "linked\n"
        run(
            [
                "git",
                "-C",
                str(primary),
                "worktree",
                "add",
                "--detach",
                "--quiet",
                str(linked),
                self.dag.tip,
            ]
        )
        output = linked / "must-not-create.git"
        result = self.tool(
            "replay",
            "--public-manifest",
            str(MANIFEST),
            "--output",
            str(output),
            check=False,
            main_repo=primary,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"input repository boundary", result.stderr)
        self.assertFalse(output.exists())

    def test_alternates_and_promisor_inputs_fail_closed(self) -> None:
        facade = self.root / "facade.git"
        run(
            [
                "git",
                "-c",
                "init.templateDir=",
                "init",
                "--bare",
                "--quiet",
                str(facade),
            ]
        )
        (facade / "objects" / "info" / "alternates").write_text(
            str(self.dag.repo / "objects") + "\n", encoding="utf-8"
        )
        alternates = self.tool(
            "inventory",
            check=False,
            main_repo=facade,
            main_commit=self.dag.tip,
        )
        self.assertEqual(alternates.returncode, 1)
        self.assertIn(b"object alternates are forbidden", alternates.stderr)

        for name, configure in (
            (
                "pack",
                lambda repo: (
                    repo / "objects" / "pack" / "fixture.promisor"
                ).write_bytes(b""),
            ),
            (
                "config",
                lambda repo: run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "config",
                        "remote.origin.promisor",
                        "true",
                    ]
                ),
            ),
            (
                "filter-config",
                lambda repo: run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "config",
                        "remote.origin.partialCloneFilter",
                        "blob:none",
                    ]
                ),
            ),
        ):
            with self.subTest(promisor=name):
                repo = self.root / f"promisor-{name}.git"
                run(
                    [
                        "git",
                        "-c",
                        "init.templateDir=",
                        "init",
                        "--bare",
                        "--quiet",
                        str(repo),
                    ]
                )
                configure(repo)
                result = self.tool(
                    "inventory",
                    check=False,
                    main_repo=repo,
                    main_commit=self.dag.tip,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"forbidden", result.stderr)

        worktree_promisor = self.root / "worktree-promisor"
        run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                str(self.dag.repo),
                str(worktree_promisor),
            ]
        )
        run(
            [
                "git",
                "-C",
                str(worktree_promisor),
                "config",
                "extensions.worktreeConfig",
                "true",
            ]
        )
        run(
            [
                "git",
                "-C",
                str(worktree_promisor),
                "config",
                "--worktree",
                "remote.origin.promisor",
                "true",
            ]
        )
        result = self.tool(
            "inventory",
            check=False,
            main_repo=worktree_promisor,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"partial-clone configuration is forbidden", result.stderr)

    def test_command_diagnostics_include_bounded_stdout_and_stderr(self) -> None:
        failing = (
            "import sys;sys.stdout.write('A'*5000);"
            "sys.stderr.write('B'*5000);raise SystemExit(7)"
        )
        with self.assertRaises(ReplayError) as failure:
            run_command([sys.executable, "-c", failing])
        message = str(failure.exception)
        self.assertIn("stdout='AAAA", message)
        self.assertIn("stderr='BBBB", message)
        self.assertIn("truncated", message)
        self.assertLess(len(message), 6000)

        warning = "import sys;sys.stderr.write('audit-warning')"
        with self.assertRaisesRegex(ReplayError, "unexpected stderr"):
            run_command([sys.executable, "-c", warning])

    def test_standard_unit_gate_runs_private_replay_tests(self) -> None:
        makefile = SCRIPT.parents[2] / "Makefile"
        contents = makefile.read_text(encoding="utf-8")
        self.assertIn(
            "test-unit: test-pcap-helper test-smoke-script-helper "
            "test-stage-source-helper test-bpf-object-manifest-path-contract "
            "test-private-oss-history-replay\n",
            contents,
        )
        self.assertIn(
            "test-private-oss-history-replay:\n"
            "\t@if test -e scripts/private-release; then \\\n"
            "\t\ttest -f scripts/private-release/test_oss_history_replay.py || \\\n"
            '\t\t\t{ echo "private release tree is incomplete"; exit 1; }; \\\n'
            "\t\tpython3 -B scripts/private-release/test_oss_history_replay.py; \\\n"
            "\telse \\\n"
            '\t\techo "SKIP: private OSS history replay gate not present"; \\\n'
            "\tfi\n",
            contents,
        )


if __name__ == "__main__":
    unittest.main()
