#!/usr/bin/env python3
import ast
import hashlib
import pathlib
import re
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parent
LAUNCHER = SCRIPTS / "stage-root-owned-test-source.sh"
HELPER = SCRIPTS / "stage-root-owned-test-source.py"


class RootOwnedSourceStageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = LAUNCHER.read_text(encoding="utf-8")
        cls.helper = HELPER.read_text(encoding="utf-8")
        cls.helper_tree = ast.parse(cls.helper, filename=str(HELPER))

    def test_launcher_pins_the_exact_helper_content(self) -> None:
        match = re.search(
            r'^readonly EXPECTED_HELPER_SHA256="([0-9a-f]{64})"$',
            self.launcher,
            re.MULTILINE,
        )
        self.assertIsNotNone(match)
        self.assertEqual(
            match.group(1),
            hashlib.sha256(HELPER.read_bytes()).hexdigest(),
        )
        self.assertIn('exec 8<"${script_path}"', self.launcher)
        self.assertIn('exec 9<"${helper_path}"', self.launcher)
        self.assertIn("/proc/self/fd/8", self.launcher)
        self.assertIn("/proc/self/fd/9", self.launcher)

    def test_production_scope_is_fixed_and_root_only(self) -> None:
        self.assertIn(
            'STAGE_PREFIX = "/run/wg-mix-ebpf-source-stages"',
            self.helper,
        )
        self.assertIn('if os.geteuid() != 0:', self.helper)
        self.assertIn('raise StageError("production staging must run as root")', self.helper)
        self.assertIn('RUN_ID_RE = re.compile(r"[0-9a-f]{8}\\Z")', self.helper)
        self.assertIn('SHA256_RE = re.compile(r"[0-9a-f]{64}\\Z")', self.helper)
        self.assertIn('COMMIT_RE = re.compile(r"[0-9a-f]{40}\\Z")', self.helper)
        self.assertIn(
            'arguments[0::2] != [\n'
            '            "--bundle",\n'
            '            "--bundle-sha256",\n'
            '            "--commit",\n'
            '            "--run-id",',
            self.helper,
        )

    def test_root_owned_outputs_require_both_uid_and_gid_zero(self) -> None:
        required = (
            "validate_directory(STAGE_PREFIX, 0, 0, 0o700)",
            'create_directory(audit, run_root, 0, 0, "create_unique_run_root")',
            "create_log(audit, log_path, 0, 0)",
            "copied_metadata.st_gid != expected_gid",
            "source_metadata.st_uid != 0 or source_metadata.st_gid != 0",
            "metadata.st_uid != 0 or metadata.st_gid != 0",
            "digest, metadata = open_hashed_file(path, 0, 0)",
            "run_parent_metadata.st_gid != 0",
            "stat.S_IMODE(run_parent_metadata.st_mode) & 0o022",
        )
        for fragment in required:
            self.assertIn(fragment, self.helper)

    def test_bundle_is_descriptor_anchored_and_rehashed_after_copy(self) -> None:
        required = (
            "os.lstat(path)",
            "os.O_NOFOLLOW | os.O_NONBLOCK",
            "before.st_nlink != 1",
            "exact_stat(before) != exact_stat(opened)",
            "hash_open_fd(descriptor, MAX_BUNDLE_BYTES)",
            "source bundle changed while it was being copied",
            "open_verified_bundle(destination, expected_sha256)",
        )
        for fragment in required:
            self.assertIn(fragment, self.helper)

    def test_git_checkout_and_build_inputs_are_isolated(self) -> None:
        required = (
            '"GIT_CONFIG_GLOBAL": "/dev/null"',
            '"GIT_CONFIG_NOSYSTEM": "1"',
            '"GIT_NO_REPLACE_OBJECTS": "1"',
            '"core.hooksPath=/dev/null"',
            '"--no-checkout"',
            '"--no-hardlinks"',
            '"--no-local"',
            '"checkout", "--detach", "--no-guess", commit, "--"',
            '"GOCACHE": directories["go_cache"]',
            '"GOMODCACHE": directories["go_mod_cache"]',
            '"GOPATH": directories["go_path"]',
            '"GOTMPDIR": directories["go_tmp"]',
            '"build-bpf"',
            '"build"',
            '"build-netns-anchor"',
        )
        for fragment in required:
            self.assertIn(fragment, self.helper)
        self.assertNotIn("safe.directory", self.helper)
        self.assertNotIn('"HOME"', self.helper)

    def test_writes_are_audited_and_failures_are_not_cleaned(self) -> None:
        for fragment in (
            '("timestamp", utc_timestamp())',
            '("event", "write_start")',
            '("event", "write_finish")',
            '("argv", shlex.join(argv))',
            '("target", target)',
            '("rc", str(returncode))',
        ):
            self.assertIn(fragment, self.helper)
        forbidden_calls = (
            "os.remove(",
            "os.removedirs(",
            "os.rename(",
            "os.renames(",
            "os.replace(",
            "os.rmdir(",
            "os.unlink(",
        )
        for call in forbidden_calls:
            self.assertNotIn(call, self.helper)
        for token in ("rm -", "find -delete", "eval ", "trap ", "sudo ", "chroot ", "nsenter "):
            self.assertNotIn(token, self.launcher)


if __name__ == "__main__":
    unittest.main()
