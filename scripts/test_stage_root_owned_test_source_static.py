#!/usr/bin/env python3
import ast
import hashlib
import os
import pathlib
import re
import subprocess
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parent
LAUNCHER = SCRIPTS / "stage-root-owned-test-source.sh"
HELPER = SCRIPTS / "stage-root-owned-test-source.py"
MANIFEST = SCRIPTS / "stage-root-owned-test-source.bootstrap"
RUNNER = SCRIPTS / "run-root-owned-test-source-stage.sh"
CLEANUP = SCRIPTS / "cleanup-root-owned-test-source-stage.sh"
BASH_ENV_FIXTURE = SCRIPTS / "testdata" / "root-stage-bash-env-injection.sh"
MAKEFILE = SCRIPTS.parent / "Makefile"


class RootOwnedSourceStageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = LAUNCHER.read_text(encoding="utf-8")
        cls.helper = HELPER.read_text(encoding="utf-8")
        cls.manifest = MANIFEST.read_text(encoding="utf-8")
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.cleanup = CLEANUP.read_text(encoding="utf-8")
        cls.makefile = MAKEFILE.read_text(encoding="utf-8")
        cls.helper_tree = ast.parse(cls.helper, filename=str(HELPER))

    def test_cleanup_explicitly_binds_legacy_inspect_helper(self) -> None:
        cleanup = self.cleanup
        for fragment in (
            "--legacy-inspect-sha256",
            'readonly legacy_inspect="${bootstrap}/inspect-linux-test-host.sh"',
            "inspect-linux-test-host.sh\\nroot-stage-runner.audit",
            "'root:root:500:1:regular file'",
            '"${legacy_inspect_sha256}  ${legacy_inspect}"',
            "legacy inspect helper identity mismatch",
            "legacy_inspect=%s",
        ):
            self.assertIn(fragment, cleanup)
        identity_check = cleanup.index("legacy inspect helper identity mismatch")
        first_delete = cleanup.index('/usr/bin/find "${stage}" -xdev -depth -delete')
        self.assertLess(identity_check, first_delete)
        self.assertNotIn("rm -rf", cleanup)

    def test_cleanup_stage_entry_subset_is_retryable_but_fail_closed(self) -> None:
        start = self.cleanup.index("validate_stage_entry_set() {")
        end = self.cleanup.index("\n}\n", start) + len("\n}\n")
        validator = self.cleanup[start:end]

        expected = (
            "candidate.bundle",
            "git-template",
            "go-cache",
            "go-mod-cache",
            "go-path",
            "go-tmp",
            "source",
            "staging.log",
        )

        def validate(entries: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    validator + '\nvalidate_stage_entry_set "$@"\n',
                    "stage-entry-fixture",
                    *entries,
                ],
                cwd="/",
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(validate(expected).returncode, 0)
        without_go_mod_cache = tuple(
            entry for entry in expected if entry != "go-mod-cache"
        )
        self.assertEqual(validate(without_go_mod_cache).returncode, 0)
        identity_only = ("candidate.bundle", "source", "staging.log")
        self.assertEqual(validate(identity_only).returncode, 0)

        foreign = validate((*expected, "foreign-entry"))
        self.assertEqual(foreign.returncode, 66)
        self.assertIn("foreign stage top-level entry", foreign.stderr)
        for required in ("candidate.bundle", "source", "staging.log"):
            missing = validate(tuple(entry for entry in expected if entry != required))
            self.assertEqual(missing.returncode, 66)
            self.assertIn(
                f"required stage top-level entry is missing: {required}",
                missing.stderr,
            )

        cleanup = self.cleanup
        for fragment in (
            "-printf '%f\\0' | /usr/bin/sort -z",
            'validate_stage_entry_set "${actual_stage_entries[@]}"',
            "staged bundle metadata is unsafe",
            "staged source metadata is unsafe",
            "staging log metadata is unsafe",
            "optional stage directory metadata is unsafe",
            "bootstrap runner metadata is unsafe",
        ):
            self.assertIn(fragment, cleanup)
        first_delete = cleanup.index('/usr/bin/find "${stage}" -xdev -depth -delete')
        for preflight in (
            'validate_stage_entry_set "${actual_stage_entries[@]}"',
            "staged source commit mismatch",
            "staged bundle digest mismatch",
            "bootstrap runner digest mismatch",
            "cleanup target crosses a filesystem boundary",
        ):
            self.assertLess(cleanup.index(preflight), first_delete)
        filesystem_preflight = cleanup[
            cleanup.index('readonly run_device=') : first_delete
        ]
        self.assertNotIn("-type d", filesystem_preflight)

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
        self.assertIn('"smoke_mountns_launcher"', self.helper)
        self.assertIn(
            '"run-smoke-netns-wg-private-mountns.sh"',
            self.helper,
        )

    def test_bootstrap_manifest_pins_launcher_helper_and_modes(self) -> None:
        fields = dict(
            line.split("=", 1)
            for line in self.manifest.splitlines()
        )
        self.assertEqual(
            fields,
            {
                "version": "1",
                "bootstrap_prefix": "/run/wg-mix-ebpf-source-bootstrap",
                "launcher_file": LAUNCHER.name,
                "launcher_mode": "0500",
                "launcher_sha256": hashlib.sha256(LAUNCHER.read_bytes()).hexdigest(),
                "helper_file": HELPER.name,
                "helper_mode": "0400",
                "helper_sha256": hashlib.sha256(HELPER.read_bytes()).hexdigest(),
                "manifest_file": MANIFEST.name,
                "manifest_mode": "0400",
                "manifest_scope": "root-copy-consistency-only",
                "authenticity_root": "external-approved-postcopy-sha256",
                "direct_user_checkout_sudo": "forbidden",
                "runner_file": RUNNER.name,
                "runner_mode": "0500",
                "runner_authenticity": "external-approved-postcopy-sha256-argument",
                "runner_entry": "env-i-fixed-path-lc-bash-root-copy",
            },
        )
        self.assertIn("mapfile -t bootstrap_contract", self.launcher)
        self.assertIn('"launcher_sha256=${launcher_sha256}"', self.launcher)
        self.assertIn('"helper_sha256=${helper_sha256}"', self.launcher)
        self.assertIn(
            "manifest check below proves only mutual consistency",
            self.launcher,
        )
        self.assertIn(
            "it is not an authenticity root",
            self.launcher,
        )

    def test_user_checkout_cannot_satisfy_root_bootstrap_contract(self) -> None:
        required = (
            'readonly BOOTSTRAP_PREFIX="/run/wg-mix-ebpf-source-bootstrap"',
            '"${bootstrap_parent}" == "${BOOTSTRAP_PREFIX}"',
            '"${bootstrap_run_id}" =~ ^[0-9a-f]{8}$',
            '"0:0:700:directory"',
            '"0:0:500:1:regular file"',
            '"0:0:400:1:regular file"',
            'exec 7<"${manifest_path}"',
            'exec 8<"${script_path}"',
            'exec 9<"${helper_path}"',
        )
        for fragment in required:
            self.assertIn(fragment, self.launcher)
        bootstrap_gate = self.launcher.index(
            '"${bootstrap_parent}" == "${BOOTSTRAP_PREFIX}"'
        )
        helper_exec = self.launcher.index('exec "${ENV_BIN}" -i')
        self.assertLess(bootstrap_gate, helper_exec)
        for fragment in (
            "metadata.st_uid != 0",
            "metadata.st_gid != 0",
            "stat.S_IMODE(metadata.st_mode) != expected_mode",
            "verify_bootstrap_path(launcher_path, run_id)",
            "validate_directory(BOOTSTRAP_PREFIX, 0, 0, 0o700)",
        ):
            self.assertIn(fragment, self.helper)

    def test_root_runner_has_an_explicit_external_authenticity_boundary(self) -> None:
        for fragment in (
            "this runner is not safe to execute from a user-owned checkout",
            "externally approved authenticity root",
            'readonly BOOTSTRAP_PREFIX="/run/wg-mix-ebpf-source-bootstrap"',
            'readonly RUNNER_BASENAME="run-root-owned-test-source-stage.sh"',
            '"0:0:500:1:regular file"',
            'runner_actual_sha="$("${SHA256_BIN}" -- /proc/self/fd/9)"',
            '"${runner_actual_sha}" == "${RUNNER_SHA256}"',
            'readonly PYTHON_BIN="/usr/bin/python3"',
            'readonly APPROVED_SOURCE_COPY_PROGRAM_VERSION="1"',
            'os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC',
            "source_fd = os.open(source, source_flags)",
            "copy_approved_source launcher",
            "copy_approved_source helper",
            "copy_approved_source manifest",
        ):
            self.assertIn(fragment, self.runner)
        self.assertLess(
            self.runner.index('"${runner_actual_sha}" == "${RUNNER_SHA256}"'),
            self.runner.index("copy_approved_source launcher"),
        )
        self.assertLess(
            self.runner.index("AUDIT_READY=1"),
            self.runner.index("copy_approved_source launcher"),
        )
        self.assertIn(
            "bash -n scripts/inspect-linux-test-host.sh",
            self.makefile,
        )
        self.assertIn(
            "scripts/run-root-owned-test-source-stage.sh scripts/stage-root-owned-test-source.sh",
            self.makefile,
        )
        self.assertIn(
            "scripts/smoke-netns-wg.sh scripts/run-root-owned-test-source-stage.sh",
            self.makefile,
        )

    def test_root_runner_arguments_and_install_targets_are_strict(self) -> None:
        for option in (
            "--runner-sha256",
            "--source-launcher",
            "--launcher-sha256",
            "--source-helper",
            "--helper-sha256",
            "--source-manifest",
            "--manifest-sha256",
            "--bundle",
            "--bundle-sha256",
            "--commit",
            "--run-id",
        ):
            self.assertIn(option, self.runner)
        for fragment in (
            '"${PYTHON_BIN}" -I -B -c "${APPROVED_SOURCE_COPY_PROGRAM}"',
            '"${source}" "${approved_sha}" "${target}" "${mode}"',
            "validate_root_copy launcher",
            "validate_root_copy helper",
            "validate_root_copy manifest",
            '"${ENV_BIN}" -i "PATH=${PATH}" "LC_ALL=${LC_ALL}"',
            '"${BASH_BIN}" "${root_launcher}"',
        ):
            self.assertIn(fragment, self.runner)
        self.assertNotIn("safe.directory", self.runner)

    def test_root_runner_atomically_opens_and_copies_approved_sources(self) -> None:
        copy_contracts = (
            (
                "launcher",
                "LAUNCHER",
                "root_launcher",
                "0500",
            ),
            (
                "helper",
                "HELPER",
                "root_helper",
                "0400",
            ),
            (
                "manifest",
                "MANIFEST",
                "root_manifest",
                "0400",
            ),
        )
        for label, upper, target, mode in copy_contracts:
            copy_call = (
                f'copy_approved_source {label} "${{SOURCE_{upper}}}" '
                f'"${{{upper}_SHA256}}" \\\n'
                f'  "${{{target}}}" {mode}'
            )
            postcopy = f"validate_root_copy {label}"
            self.assertIn(copy_call, self.runner)
            copy_at = self.runner.index(copy_call)
            postcopy_at = self.runner.index(postcopy, copy_at)
            self.assertLess(copy_at, postcopy_at)

        for fragment in (
            "source_fd = os.open(source, source_flags)",
            "source_before = os.fstat(source_fd)",
            "stat.S_ISREG(source_before.st_mode)",
            "source_before.st_nlink != 1",
            "source_before.st_size > max_bytes",
            "source_sha_before = hash_exact_size(",
            "target_fd = os.open(target, target_flags, modes[mode_text])",
            "os.O_EXCL",
            "copied_sha256 = copy_exact_size(",
            "source_after_copy = os.fstat(source_fd)",
            "source_sha_after = hash_exact_size(",
            "target_sha256 = hash_exact_size(",
            'run_write "copy_root_${label}" "${target}" "${copy_argv[@]}"',
        ):
            self.assertIn(fragment, self.runner)
        self.assertNotRegex(self.runner, r'exec [0-9]+<"\$\{SOURCE_')
        self.assertNotIn("/proc/self/fd/6", self.runner)
        self.assertNotIn("/proc/self/fd/7", self.runner)
        self.assertNotIn("/proc/self/fd/8", self.runner)
        self.assertNotIn("validate_approved_source_path", self.runner)
        self.assertNotIn("revalidate_held_source", self.runner)
        self.assertNotIn("os.lstat(source)", self.runner)
        self.assertNotIn('"${BASH_BIN}" -c', self.runner)
        self.assertNotRegex(self.runner, r"(?m)^\s*eval\b")
        self.assertIn(
            "python3 scripts/test_root_stage_source_fd.py",
            self.makefile,
        )

    def test_runner_audit_covers_every_write_boundary(self) -> None:
        for fragment in (
            "timestamp=%q host=%q event=%q action=%q argv=%q target=%q rc=%q",
            "emit_audit write_start",
            "emit_audit write_finish",
            'run_write "copy_root_${label}"',
            "validate_root_copy launcher",
            "validate_root_copy helper",
            "validate_root_copy manifest",
            "execute_root_stage",
            '"${BOOTSTRAP_PREFIX},${runner_directory},${STAGE_PREFIX},${stage_run}"',
        ):
            self.assertIn(fragment, self.runner)
        self.assertNotRegex(
            self.runner,
            r"(?m)^\s*(eval|trap|sudo|rm|chroot|nsenter)\b",
        )
        self.assertNotIn("find -delete", self.runner)

    def test_empty_root_audit_uses_numeric_gnu_stat_contract(self) -> None:
        validation_start = self.runner.index("((audit_create_rc == 0))")
        validation_end = self.runner.index('exec 10>>"${AUDIT_PATH}"')
        validation = self.runner[validation_start:validation_end]
        self.assertIn(
            '[[ ! -L "${AUDIT_PATH}" && -f "${AUDIT_PATH}" &&',
            validation,
        )
        self.assertIn(
            '"$("${STAT_BIN}" -Lc \'%u:%g:%a:%h:%s\' -- '
            '"${AUDIT_PATH}")" == \\\n  "0:0:600:1:0"',
            validation,
        )
        self.assertNotIn("%F", validation)
        self.assertIn(
            '"stat=0:0:600:1:0 type=regular-file"',
            self.runner,
        )

        fake_gnu_stat = {
            "%u": "0",
            "%g": "0",
            "%a": "600",
            "%h": "1",
            "%s": "0",
            "%F": "regular empty file",
        }
        numeric_contract = ":".join(
            fake_gnu_stat[field] for field in ("%u", "%g", "%a", "%h", "%s")
        )
        self.assertEqual(numeric_contract, "0:0:600:1:0")
        self.assertNotEqual(fake_gnu_stat["%F"], "regular file")
        for bootstrap_file in (RUNNER, LAUNCHER, HELPER, MANIFEST):
            self.assertGreater(bootstrap_file.stat().st_size, 0)

    def test_env_i_runner_entry_drops_inherited_bash_env(self) -> None:
        environment = dict(os.environ)
        environment["BASH_ENV"] = str(BASH_ENV_FIXTURE)
        environment["ENV"] = str(BASH_ENV_FIXTURE)
        environment["SHELLOPTS"] = "braceexpand:hashall:interactive-comments:xtrace"
        completed = subprocess.run(
            [
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "LC_ALL=C",
                "/bin/bash",
                str(RUNNER),
            ],
            cwd="/",
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("BASH_ENV_INJECTION_EXECUTED", completed.stdout)
        self.assertNotIn("BASH_ENV_INJECTION_EXECUTED", completed.stderr)
        self.assertFalse(
            any(line.startswith("+") for line in completed.stderr.splitlines()),
            completed.stderr,
        )

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
            "permission_bits & 0o6000",
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

    def test_post_build_tree_is_revalidated_before_and_after_helper(self) -> None:
        self.assertGreaterEqual(
            self.helper.count("verify_root_owned_worktree(source)"),
            3,
        )
        build = self.helper.index(
            '"build_staged_source",\n            build_argv,'
        )
        post_build = self.helper.index(
            "verify_root_owned_worktree(source)", build
        )
        helper_check = self.helper.index(
            "verify_clean_source(audit, source, commit, environment)",
            post_build,
        )
        post_helper = self.helper.index(
            "verify_root_owned_worktree(source)", helper_check
        )
        self.assertLess(build, post_build)
        self.assertLess(post_build, helper_check)
        self.assertLess(helper_check, post_helper)
        self.assertIn(
            'raise StageError(f"source entry has setuid or setgid bits: {path}")',
            self.helper,
        )

    def test_build_audit_names_the_complete_write_boundary(self) -> None:
        target = self.helper[
            self.helper.index("build_targets =") :
            self.helper.index(
                '\n        run_command(\n            audit,\n            "build_staged_source"'
            )
        ]
        for fragment in (
            "run_root",
            "source",
            'directories["go_cache"]',
            'directories["go_mod_cache"]',
            'directories["go_path"]',
            'directories["go_tmp"]',
        ):
            self.assertIn(fragment, target)

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
        for token in ("rm -", "find -delete", "sudo ", "chroot ", "nsenter "):
            self.assertNotIn(token, self.launcher)
        self.assertNotRegex(self.launcher, r"(?m)^\s*(eval|trap)\b")


if __name__ == "__main__":
    unittest.main()
