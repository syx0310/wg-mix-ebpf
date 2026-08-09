#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path


SCRIPT = Path(__file__).with_name("oss_history_replay.py")
MANIFEST = Path(__file__).with_name("testdata") / "synthetic-public-manifest.json"


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


class DagBuilder:
    def __init__(self, root: Path) -> None:
        self.repo = root / "source.git"
        run(["git", "-c", "init.templateDir=", "init", "--bare", str(self.repo)])
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
        raw = b"\n".join(headers) + b"\n\n" + message
        return (
            self.git("hash-object", "-t", "commit", "-w", "--stdin", data=raw)
            .decode()
            .strip()
        )

    def build(self) -> SyntheticDag:
        tree_a, blobs_a = self.tree(
            {
                "app.txt": b"public app\n",
                "docs/secret.txt": b"private secret v1\n",
                "scripts/private-release/internal.py": b"private tool\n",
            }
        )
        root_a = self.commit(tree_a, (), b"root A\n")
        tree_private, blobs_private = self.tree(
            {
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
                "lib.txt": b"public library\n",
                "refs/research.txt": b"private reference\n",
            }
        )
        root_b = self.commit(tree_b, (), b"root B\n")
        tree_merge, blobs_merge = self.tree(
            {
                "app.txt": b"public app\n",
                "docs/secret.txt": b"private secret v2\n",
                "refs/research.txt": b"private reference\n",
                "scripts/private-release/internal.py": b"private tool v2\n",
            }
        )
        merge = self.commit(tree_merge, (empty, root_b), b"merge two roots\n")
        tree_tip, _ = self.tree(
            {
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
            blobs_private["docs/secret.txt"],
            blobs_private["scripts/private-release/internal.py"],
            blobs_b["refs/research.txt"],
            blobs_merge["docs/secret.txt"],
            blobs_merge["refs/research.txt"],
            blobs_merge["scripts/private-release/internal.py"],
        }
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


class OssHistoryReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="oss-history-replay-test-")
        self.root = Path(self.temp.name)
        self.dag = DagBuilder(self.root).build()
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(self.dag.tip, self.manifest["main_commit"])
        self.assertEqual(self.dag.root_a, self.manifest["legacy_public_history_commit"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def tool(
        self, operation: str, *extra: str, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        return run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                operation,
                "--main-repo",
                str(self.dag.repo),
                "--main-commit",
                self.dag.tip,
                "--legacy-repo",
                str(self.dag.repo),
                "--legacy-commit",
                self.dag.root_a,
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
            self.assertTrue(set(paths) <= {"app.txt", "lib.txt"})
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
        self.assertEqual({record["path"] for record in records}, {"app.txt", "lib.txt"})
        self.assertFalse(any("docs" in record["path"] for record in records))
        self.assertFalse(any("private-release" in record["path"] for record in records))

    def test_manifest_cannot_override_fixed_deny(self) -> None:
        manifest = self.root / "denied.json"
        value = dict(self.manifest)
        value["public_paths"] = ["app.txt", "docs/secret.txt", "lib.txt"]
        manifest.write_text(json.dumps(value), encoding="utf-8")
        result = self.tool(
            "replay",
            "--public-manifest",
            str(manifest),
            "--output",
            str(self.root / "denied.git"),
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"fixed-deny path", result.stderr)


if __name__ == "__main__":
    unittest.main()
