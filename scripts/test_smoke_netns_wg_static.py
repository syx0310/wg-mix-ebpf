#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shlex
import stat
import subprocess
import tempfile
import textwrap
import unittest


SCRIPT_PATH = pathlib.Path(__file__).with_name("smoke-netns-wg.sh")
MOUNTNS_LAUNCHER_PATH = pathlib.Path(__file__).with_name(
    "run-smoke-netns-wg-private-mountns.sh"
)
MAKEFILE_PATH = SCRIPT_PATH.parent.parent / "Makefile"
GO_MOD_PATH = SCRIPT_PATH.parent.parent / "go.mod"
GO_SUM_PATH = SCRIPT_PATH.parent.parent / "go.sum"
HOLDER_PATH = pathlib.Path(__file__).with_name(
    "hold-isolated-lifecycle-lease.py"
)
ANCHOR_PACKAGE = SCRIPT_PATH.parent.parent / "internal" / "netnsanchor"
FAILED_RUN_RECOVERY_PATH = pathlib.Path(__file__).with_name(
    "recover-smoke-netns-wg-failed-run.py"
)
FAILED_RUN_RECOVERY_TEST_PATH = pathlib.Path(__file__).with_name(
    "test_recover_smoke_netns_wg_failed_run.py"
)


class SmokeNetNSWGStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT_PATH.read_text(encoding="utf-8")
        cls.mountns_launcher = MOUNTNS_LAUNCHER_PATH.read_text(encoding="utf-8")
        cls.lines = cls.source.splitlines()
        cls.makefile_source = MAKEFILE_PATH.read_text(encoding="utf-8")
        cls.go_mod_source = GO_MOD_PATH.read_text(encoding="utf-8")
        cls.go_sum_source = GO_SUM_PATH.read_text(encoding="utf-8")
        cls.holder_source = HOLDER_PATH.read_text(encoding="utf-8")
        cls.failed_run_recovery = FAILED_RUN_RECOVERY_PATH.read_text(
            encoding="utf-8"
        )
        cls.failed_run_recovery_test = FAILED_RUN_RECOVERY_TEST_PATH.read_text(
            encoding="utf-8"
        )
        cls.anchor_linux_source = (ANCHOR_PACKAGE / "run_linux.go").read_text(
            encoding="utf-8"
        )
        cls.anchor_reviewed_tool_source = (
            ANCHOR_PACKAGE / "reviewed_system_tool_linux.go"
        ).read_text(encoding="utf-8")
        cls.anchor_staged_launch_source = (
            ANCHOR_PACKAGE / "staged_launch_linux.go"
        ).read_text(encoding="utf-8")
        cls.anchor_protocol_source = (
            ANCHOR_PACKAGE / "protocol.go"
        ).read_text(
            encoding="utf-8"
        )

    def test_password_is_unexported_before_first_child_process(self) -> None:
        capture = self.source.index('XOR_SECRET="${XOR_PASSWORD-}"')
        unset = self.source.index("unset XOR_PASSWORD")
        first_command_substitution = self.source.index('ROOT="$(cd ')
        self.assertLess(capture, unset)
        self.assertLess(unset, first_command_substitution)
        self.assertNotIn("export XOR_PASSWORD", self.source)

        for number, line in enumerate(self.lines, start=1):
            if number <= self.source[:unset].count("\n") + 1:
                continue
            if "XOR_PASSWORD" not in line:
                continue
            allowed = (
                "env -u XOR_PASSWORD",
                'startswith(b"XOR_PASSWORD=")',
                "inherited XOR_PASSWORD",
                "error: XOR_PASSWORD",
            )
            self.assertTrue(
                any(fragment in line for fragment in allowed),
                f"line {number} reads or propagates XOR_PASSWORD: {line}",
            )

    def test_wg_smoke_uses_only_reviewed_private_mountns_entry(self) -> None:
        launcher = self.mountns_launcher
        for fragment in (
            "#!/usr/bin/bash -p",
            'if [[ "$-" != *p* ]]',
            "run_anchor review-staged-launch",
            "run_anchor review-system-tools",
            'run_anchor reviewed-exec "${logical_path}" -- "$@"',
            'exec {anchor_fd}<"${anchor_path}"',
            'exec {anchor_review_fd}<&"${anchor_fd}"',
            'exec {smoke_fd}<"${smoke_path}"',
            'exec {outer_mountns_fd}<"/proc/self/ns/mnt"',
            "launch-private-mountns",
            '--child-env "${child_entry}"',
            'WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256',
            'WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_COMMIT',
            'WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_FD',
            'format=wg-mix-ebpf-smoke-mountns-launch-v1',
            'exec {xor_secret_fd}<<<"${XOR_SECRET}"',
            'launcher mount namespace identity changed while waiting for child',
        ):
            self.assertIn(fragment, launcher)
        self.assertNotIn("--make-rprivate", launcher)
        self.assertNotIn("--make-private", launcher)
        self.assertNotIn("mount --make", launcher)
        self.assertNotIn('"${ENV_BIN}" -i', launcher)
        self.assertNotIn('"${UNSHARE_BIN}"', launcher)
        self.assertNotIn('"${BASH_BIN}" "/proc/self/fd/', launcher)
        capture = launcher.index('XOR_SECRET="${XOR_PASSWORD-}"')
        unset = launcher.index("unset XOR_PASSWORD")
        first_external = launcher.index("\nrun_anchor review-staged-launch")
        self.assertLess(capture, unset)
        self.assertLess(unset, first_external)
        child_environment = launcher[
            launcher.index("child_environment=(") :
            launcher.index("\nstatus=0", launcher.index("child_environment=("))
        ]
        self.assertNotIn("XOR_PASSWORD", child_environment)
        self.assertIn("WG_MIX_EBPF_SMOKE_MOUNTNS_XOR_SECRET_FD", child_environment)

        reviewed = self.anchor_reviewed_tool_source
        for path in (
            "/usr/bin/bash",
            "/usr/bin/env",
            "/usr/bin/realpath",
            "/usr/bin/sha256sum",
            "/usr/bin/stat",
            "/usr/bin/unshare",
        ):
            self.assertIn(f'"{path}"', reviewed)
        for fragment in (
            "unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC",
            "unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS",
            "equalReviewedChains(first.chain, second.chain)",
            "argv[0] = logicalPath",
            '"/proc/self/fd/" + strconv.Itoa(resolved.targetFD)',
        ):
            self.assertIn(fragment, reviewed)

        staged = self.anchor_staged_launch_source
        for fragment in (
            "unix.RESOLVE_NO_SYMLINKS",
            "metadata.nlink != 1",
            "staged anchor path, held FD, and current image differ",
            "unix.Unshare",
            "unix.MS_REC|unix.MS_PRIVATE",
            '"/usr/bin/bash"',
            '"/proc/self/fd/" + strconv.Itoa(smokeFD)',
            "outer mount namespace FD identity differs from launch seal",
            "current and sealed outer mount namespace identities differ before unshare",
            "held staged smoke hash differs from launch seal",
            "validateAndRebindLaunchRecordFD(",
            "launch record FD content differs from its sealed contract",
            "unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING",
            "unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE",
            "unix.Dup3(sealedFD, descriptor, 0)",
            "runtime.LockOSThread",
            "runtime.UnlockOSThread",
            "unix.Gettid",
            "unix.Setns",
            "inspectCurrentThreadMountNamespace",
            "restoreOuterMountNamespaceAfterFailure(",
        ):
            self.assertIn(fragment, staged)
        launch = staged[
            staged.index("func launchPrivateMountNS(") :
            staged.index("\nfunc restoreOuterMountNamespaceAfterFailure(")
        ]
        self.assertLess(
            launch.index("validatePrivateMountNSChildEnvironment("),
            launch.index("operations.unshare(unix.CLONE_NEWNS)"),
        )
        self.assertLess(
            launch.index("operations.lockThread()"),
            launch.index("operations.unshare(unix.CLONE_NEWNS)"),
        )

        self.assertIn(
            "override WG_NETNS_SMOKE_LAUNCHER := "
            "scripts/run-smoke-netns-wg-private-mountns.sh",
            self.makefile_source,
        )
        self.assertIn("override SHELL := /bin/sh", self.makefile_source)
        for line in self.makefile_source.splitlines():
            if not line.startswith("\t") or "scripts/smoke-netns-wg.sh" not in line:
                continue
            self.assertTrue(
                "bash -n " in line or "shellcheck " in line,
                f"direct WG smoke recipe bypasses mountns launcher: {line}",
            )
        self.assertGreaterEqual(
            self.makefile_source.count("$(WG_NETNS_SMOKE_LAUNCHER)"),
            15,
        )

    def test_launcher_startup_ignores_bash_env_and_exported_functions(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("startup-injection fixture must stay unprivileged")
        bash = pathlib.Path("/usr/bin/bash")
        if not bash.is_file():
            bash = pathlib.Path("/bin/bash")
        if not bash.is_file():
            self.skipTest("startup-injection fixture requires fixed Bash")

        secret = "xor-startup-injection-secret-7b61"
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            bash_env_marker = temporary / "bash-env-ran"
            function_marker = temporary / "exported-function-ran"
            bash_env = temporary / "malicious-bash-env.sh"
            bash_env.write_text(
                f'/usr/bin/touch {shlex.quote(str(bash_env_marker))}\n',
                encoding="utf-8",
            )
            environment = {
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "BASH_ENV": str(bash_env),
                "XOR_PASSWORD": secret,
                "BASH_FUNC_echo%%": (
                    "() { /usr/bin/touch "
                    f"{shlex.quote(str(function_marker))}; "
                    'builtin echo "$@"; }'
                ),
            }

            control = subprocess.run(
                [str(bash), "-c", "echo control"],
                check=False,
                capture_output=True,
                env=environment,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            self.assertTrue(bash_env_marker.is_file())
            self.assertTrue(function_marker.is_file())
            bash_env_marker.unlink()
            function_marker.unlink()

            privileged = subprocess.run(
                [str(bash), "-p", str(MOUNTNS_LAUNCHER_PATH)],
                check=False,
                capture_output=True,
                env=environment,
            )
            self.assertNotEqual(privileged.returncode, 0)
            self.assertFalse(bash_env_marker.exists())
            self.assertFalse(function_marker.exists())
            self.assertNotIn(secret.encode(), privileged.stdout)
            self.assertNotIn(secret.encode(), privileged.stderr)

            if pathlib.Path("/usr/bin/bash").is_file():
                direct = subprocess.run(
                    [str(MOUNTNS_LAUNCHER_PATH)],
                    check=False,
                    capture_output=True,
                    env=environment,
                )
                self.assertNotEqual(direct.returncode, 0)
                self.assertFalse(bash_env_marker.exists())
                self.assertFalse(function_marker.exists())
                self.assertNotIn(secret.encode(), direct.stdout)
                self.assertNotIn(secret.encode(), direct.stderr)

    def test_make_command_line_cannot_override_smoke_entry_or_recipe_shell(
        self,
    ) -> None:
        make = pathlib.Path("/usr/bin/make")
        if not make.is_file():
            self.skipTest("make override fixture requires /usr/bin/make")
        repository = SCRIPT_PATH.parent.parent
        malicious_launcher = "/tmp/not-reviewed-wg-smoke-launcher"
        dry_run = subprocess.run(
            [
                str(make),
                "--no-print-directory",
                "-n",
                "test-netns-smoke",
                f"WG_NETNS_SMOKE_LAUNCHER={malicious_launcher}",
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertIn(
            "scripts/run-smoke-netns-wg-private-mountns.sh",
            dry_run.stdout,
        )
        self.assertNotIn(malicious_launcher, dry_run.stdout)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            shell_marker = temporary / "malicious-shell-ran"
            malicious_shell = temporary / "malicious-shell"
            malicious_shell.write_text(
                "#!/bin/sh\n"
                f"/usr/bin/touch {shlex.quote(str(shell_marker))}\n"
                "exit 91\n",
                encoding="utf-8",
            )
            malicious_shell.chmod(0o700)
            executed = subprocess.run(
                [
                    str(make),
                    "--no-print-directory",
                    "test-netns",
                    f"SHELL={malicious_shell}",
                ],
                cwd=repository,
                check=False,
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            self.assertEqual(executed.returncode, 0, executed.stderr)
            self.assertFalse(shell_marker.exists())

    def test_mountns_child_gate_precedes_every_test_resource_write(self) -> None:
        gate = self.source.index('validate_private_mountns_launch "$@"')
        shift = self.source.index("\nshift\n", gate)
        run_id = self.source.index('RUN_ID="$(python3 -')
        first_phase = self.source.index('PHASE="create-owned-run-root"')
        first_test_mkdir = self.source.index('mkdir -m 0700 -- "${TEST_ROOT}"')
        self.assertLess(gate, shift)
        self.assertLess(shift, run_id)
        self.assertLess(run_id, first_phase)
        self.assertLess(gate, first_test_mkdir)
        self.assertIn(
            'invoke WireGuard netns smoke through '
            'scripts/run-smoke-netns-wg-private-mountns.sh',
            self.source,
        )
        self.assertIn('exec {outer_fd}<&-', self.source)
        self.assertIn('exec {script_fd}<&-', self.source)
        self.assertNotIn("--make-rprivate", self.source)
        self.assertNotIn("--make-private", self.source)

    def test_prewrite_mount_chain_rejects_all_propagation_fields(self) -> None:
        function = self.source[
            self.source.index("validate_private_mount_chain() {") :
            self.source.index("\nvalidate_private_mountns_launch() {")
        ]
        target = "/run/wg-mix-ebpf-tests"
        harness = "\n".join(
            (
                "set -euo pipefail",
                function,
                f"validate_private_mount_chain {shlex.quote(target)} \"$1\"",
            )
        )

        def inspect(mountinfo: str) -> subprocess.CompletedProcess[bytes]:
            with tempfile.NamedTemporaryFile() as fixture:
                fixture.write(mountinfo.encode("ascii"))
                fixture.flush()
                return subprocess.run(
                    ["/bin/bash", "-c", harness, "mount-chain-fixture", fixture.name],
                    check=False,
                    capture_output=True,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                )

        root = "25 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"
        private_run = (
            "100 25 0:100 / /run rw,nosuid,nodev,relatime "
            "- tmpfs tmpfs rw\n"
        )
        accepted = inspect(root + private_run)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        unrelated_escaped = (
            "90 25 0:90 / /mnt/with\\040space rw,relatime "
            "- tmpfs unrelated rw\n"
        )
        accepted_unrelated = inspect(root + private_run + unrelated_escaped)
        self.assertEqual(
            accepted_unrelated.returncode,
            0,
            accepted_unrelated.stderr,
        )

        selected_target = (
            f"110 90 0:110 / {target} rw,relatime - tmpfs selected rw\n"
        )
        self.assertNotEqual(
            inspect(root + unrelated_escaped + selected_target).returncode,
            0,
        )

        for propagation in (
            "shared:77",
            "master:12",
            "propagate_from:12",
            "unbindable",
        ):
            with self.subTest(propagation=propagation):
                propagated_run = (
                    "100 25 0:100 / /run rw,nosuid,nodev,relatime "
                    f"{propagation} - tmpfs tmpfs rw\n"
                )
                self.assertNotEqual(inspect(root + propagated_run).returncode, 0)

        shared_root = (
            "25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/root rw\n"
        )
        self.assertNotEqual(inspect(shared_root + private_run).returncode, 0)

    def test_source_commit_is_resolved_from_source_root(self) -> None:
        helper = self.source[
            self.source.index("source_commit_from_root() {") :
            self.source.index(
                '\nif [[ "${1-}" == "--self-test-source-commit-cwd" ]]'
            )
        ]
        self.assertIn('builtin cd -- "${ROOT}"', helper)
        self.assertIn('"${SOURCE_COMMIT_HELPER}"', helper)
        self.assertIn(
            'EXPECTED_SOURCE_COMMIT="$(source_commit_from_root)"',
            self.source,
        )
        self.assertLess(
            self.source.index('if [[ "${1-}" == "--self-test-source-commit-cwd" ]]'),
            self.source.index('if [[ "${EUID}" -ne 0 ]]'),
        )

    def test_absolute_script_resolves_commit_from_unrelated_cwd(self) -> None:
        repository = SCRIPT_PATH.parent.parent.resolve()
        git_environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        }
        status = subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(repository),
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
                "--ignore-submodules=none",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=git_environment,
        )
        if status.stdout:
            self.skipTest("source-commit behavior requires a clean repository")
        expected = subprocess.run(
            ["/usr/bin/git", "-C", str(repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            env=git_environment,
        ).stdout.strip()
        completed = subprocess.run(
            [str(SCRIPT_PATH.resolve()), "--self-test-source-commit-cwd"],
            cwd="/",
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), expected)

    def test_plaintext_shell_variable_is_dropped_after_secret_file_write(self) -> None:
        write = self.source.index(
            'printf \'%s\\n\' "${XOR_SECRET}" >"${SECRET_DIR}/xor-password"'
        )
        unset = self.source.index("unset XOR_SECRET")
        self.assertLess(write, unset)
        self.assertNotIn("XOR_SECRET", self.source[unset + len("unset XOR_SECRET") :])
        self.assertIn(
            '--xor-udp2raw-password-file "${SECRET_DIR}/xor-password"',
            self.source,
        )
        self.assertNotIn("--xor-udp2raw-password ", self.source)

    def test_target_processes_are_sanitized_and_audited(self) -> None:
        required_labels = (
            '"agent-${ns}"',
            '"tcpdump-ra"',
            '"tcpdump-rb"',
            '"iperf3-server-${label}"',
            '"iperf3-client-${label}"',
            '"pcap-checker"',
            '"udp-zero-checksum-receiver"',
        )
        for label in required_labels:
            self.assertIn(
                f"assert_process_environment_secret_free",
                self.source,
            )
            self.assertIn(label, self.source)
        self.assertIn('pathlib.Path("/proc") / str(pid)', self.source)
        self.assertIn("descendants.add(pid)", self.source)
        self.assertIn(
            "no actual descendant observed within the environment-audit window",
            self.source,
        )
        self.assertGreaterEqual(
            self.source.count("run_bounded_in_owned_netns "),
            7,
        )
        bounded = self.source[
            self.source.index("run_bounded_in_owned_netns() {") :
            self.source.index("\ncreate_veth_pair() {")
        ]
        self.assertLess(
            bounded.index("set_netns_client_args"),
            bounded.index('"${NETNS_ANCHOR_EXEC}" exec'),
        )
        self.assertLess(
            bounded.index("sleep 0.2"),
            bounded.index("set_netns_client_args"),
        )
        self.assertIn("env -u XOR_PASSWORD", bounded)
        self.assertNotIn("sh -c", bounded)
        self.assertGreaterEqual(
            self.source.count('"${NETNS_ANCHOR_EXEC}" exec'),
            2,
        )
        self.assertNotIn("ip netns", self.source)
        self.assertNotIn("/run/netns", self.source)

    def test_setup_mutations_have_redacted_start_and_finish_audits(self) -> None:
        redactor = self.source[
            self.source.index("print_redacted_netns_argv() {") :
            self.source.index("\nset_netns_client_args() {")
        ]
        self.assertIn("private-key)", redactor)
        self.assertIn("<redacted-private-key-source>", redactor)
        self.assertIn('"$(date -u +%Y-%m-%dT%H:%M:%SZ)"', redactor)

        runner = self.source[
            self.source.index("run_in_owned_netns() {") :
            self.source.index(
                "\nrun_wg_set_with_private_key_in_owned_netns() {"
            )
        ]
        self.assertIn('audit_netns_argv start "${ns}" pending', runner)
        self.assertIn('audit_netns_argv finish "${ns}" "${status}"', runner)
        self.assertLess(
            runner.index("audit_netns_argv start"),
            runner.index('if "${command[@]}"'),
        )
        self.assertLess(
            runner.index('if "${command[@]}"'),
            runner.index("audit_netns_argv finish"),
        )

        veth = self.source[
            self.source.index("create_veth_pair() {") :
            self.source.index("\nstart_netns_anchor() {")
        ]
        self.assertIn(
            'start "${left_ns}<->${right_ns}" pending "${command[@]}"',
            veth,
        )
        self.assertIn('audit_netns_argv finish \\\n', veth)
        self.assertIn('return "${status}"', veth)

    def test_private_key_crosses_exec_boundary_only_through_anonymous_stdin(
        self,
    ) -> None:
        wrapper = self.source[
            self.source.index(
                "produce_held_private_key() {"
            ) :
            self.source.index("\nrun_bounded_in_owned_netns() {")
        ]
        self.assertIn('exec {private_key_fd}<"${private_key_file}"', wrapper)
        self.assertIn('exec 0<&"${private_key_fd}"', wrapper)
        self.assertGreaterEqual(wrapper.count('exec {private_key_fd}<&-'), 3)
        self.assertIn(
            '"${private_key_fd}" == "${NETNS_ANCHOR_IMAGE_FD}"',
            wrapper,
        )
        self.assertIn('produce_held_private_key "${private_key_fd}"', wrapper)
        self.assertIn("  ) | (\n", wrapper)
        self.assertIn("private-key /dev/stdin", wrapper)
        self.assertNotIn('cat "${private_key_file}"', wrapper)
        self.assertNotIn('private-key "${private_key_file}"', wrapper)
        self.assertNotIn("eval ", wrapper)
        self.assertNotIn("sh -c", wrapper)
        self.assertNotIn("trap ", wrapper)
        producer = wrapper[
            wrapper.index("produce_held_private_key() {") :
            wrapper.index("\nrun_wg_set_from_stdin_in_owned_netns() {")
        ]
        self.assertLess(
            producer.index('exec 0<&"${private_key_fd}"'),
            producer.index('exec {private_key_fd}<&-'),
        )
        self.assertLess(
            producer.index('exec {private_key_fd}<&-'),
            producer.index("env -u XOR_PASSWORD cat"),
        )
        consumer = wrapper[
            wrapper.index("run_wg_set_from_stdin_in_owned_netns() {") :
            wrapper.index(
                "\nrun_wg_set_with_private_key_in_owned_netns() {"
            )
        ]
        self.assertLess(
            consumer.index('exec {private_key_fd}<&-'),
            consumer.index("run_in_owned_netns"),
        )
        orchestrator = wrapper[
            wrapper.index(
                "run_wg_set_with_private_key_in_owned_netns() {"
            ) :
        ]
        self.assertLess(
            orchestrator.index(
                'exec {private_key_fd}<"${private_key_file}"'
            ),
            orchestrator.index('produce_held_private_key "${private_key_fd}"'),
        )
        self.assertLess(
            orchestrator.index('produce_held_private_key "${private_key_fd}"'),
            orchestrator.rindex('exec {private_key_fd}<&-'),
        )
        self.assertNotIn(
            'private-key "${SECRET_DIR}/',
            self.source,
        )

        run_exec = self.anchor_linux_source[
            self.anchor_linux_source.index("func runExecCommand(") :
            self.anchor_linux_source.index("\nfunc runCreateVethPairCommand(")
        ]
        self.assertIn("unix.Exec(path, command, os.Environ())", run_exec)
        self.assertIn("preserves inherited stdin", run_exec)
        self.assertNotIn("Stdin = nil", run_exec)

    def test_private_key_pipeline_preserves_stdin_rc_and_redaction(self) -> None:
        dynamic_fd_probe = subprocess.run(
            ["/bin/bash", "-c", "exec {probe_fd}</dev/null"],
            check=False,
            capture_output=True,
        )
        if dynamic_fd_probe.returncode != 0:
            self.skipTest("private-key pipeline requires Bash dynamic FDs")

        audit_functions = self.source[
            self.source.index("print_redacted_netns_argv() {") :
            self.source.index("\nset_netns_client_args() {")
        ]
        run_function = self.source[
            self.source.index("run_in_owned_netns() {") :
            self.source.index(
                "\nproduce_held_private_key() {"
            )
        ]
        private_key_function = self.source[
            self.source.index(
                "produce_held_private_key() {"
            ) :
            self.source.index("\nrun_bounded_in_owned_netns() {")
        ]
        private_key = b"private-key-behavior-sentinel-7f3a\n"

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            key_path = temporary / "input.key"
            key_path.write_bytes(private_key)
            key_path.chmod(0o600)
            occupied_path = temporary / "caller-fd-9"
            occupied_path.write_text("caller-fd-9-marker\n", encoding="ascii")
            anchor_fd_path = temporary / "anchor-held-fd"
            anchor_fd_path.write_text("anchor-held-fd-marker\n", encoding="ascii")

            producer = temporary / "cat"
            producer.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import hashlib
                    import json
                    import os
                    import pathlib
                    import stat
                    import sys

                    def describe_fds():
                        records = []
                        for name in os.listdir("/dev/fd"):
                            if not name.isdigit():
                                continue
                            descriptor = int(name)
                            try:
                                metadata = os.fstat(descriptor)
                            except OSError:
                                continue
                            records.append({
                                "fd": descriptor,
                                "device": metadata.st_dev,
                                "inode": metadata.st_ino,
                                "regular": stat.S_ISREG(metadata.st_mode),
                            })
                        return records

                    payload = sys.stdin.buffer.read()
                    record = {
                        "argv": sys.argv,
                        "environment": dict(os.environ),
                        "fds": describe_fds(),
                        "stdin_is_regular": stat.S_ISREG(os.fstat(0).st_mode),
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "payload_size": len(payload),
                    }
                    pathlib.Path(os.environ["TEST_CAPTURE_DIR"], "producer.json").write_text(
                        json.dumps(record, sort_keys=True), encoding="utf-8"
                    )
                    sys.stdout.buffer.write(payload)
                    """
                ),
                encoding="utf-8",
            )
            producer.chmod(0o700)

            anchor = temporary / "anchor-stub"
            anchor.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import pathlib
                    import stat
                    import sys

                    def describe_fds():
                        records = []
                        for name in os.listdir("/dev/fd"):
                            if not name.isdigit():
                                continue
                            descriptor = int(name)
                            try:
                                metadata = os.fstat(descriptor)
                            except OSError:
                                continue
                            records.append({
                                "fd": descriptor,
                                "device": metadata.st_dev,
                                "inode": metadata.st_ino,
                                "regular": stat.S_ISREG(metadata.st_mode),
                            })
                        return records

                    record = {
                        "argv": sys.argv,
                        "environment": dict(os.environ),
                        "fds": describe_fds(),
                        "stdin_is_fifo": stat.S_ISFIFO(os.fstat(0).st_mode),
                    }
                    pathlib.Path(os.environ["TEST_CAPTURE_DIR"], "anchor.json").write_text(
                        json.dumps(record, sort_keys=True), encoding="utf-8"
                    )
                    separator = sys.argv.index("--")
                    command = sys.argv[separator + 1 :]
                    os.execvpe(command[0], command, dict(os.environ))
                    """
                ),
                encoding="utf-8",
            )
            anchor.chmod(0o700)

            wg = temporary / "wg"
            wg.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import hashlib
                    import json
                    import os
                    import pathlib
                    import stat
                    import sys

                    def describe_fds():
                        records = []
                        for name in os.listdir("/dev/fd"):
                            if not name.isdigit():
                                continue
                            descriptor = int(name)
                            try:
                                metadata = os.fstat(descriptor)
                            except OSError:
                                continue
                            records.append({
                                "fd": descriptor,
                                "device": metadata.st_dev,
                                "inode": metadata.st_ino,
                                "regular": stat.S_ISREG(metadata.st_mode),
                            })
                        return records

                    source_index = sys.argv.index("private-key") + 1
                    private_key_source = sys.argv[source_index]
                    with open(private_key_source, "rb") as stream:
                        stdin_is_fifo = stat.S_ISFIFO(os.fstat(stream.fileno()).st_mode)
                        payload = stream.read()
                    record = {
                        "argv": sys.argv,
                        "environment": dict(os.environ),
                        "fds": describe_fds(),
                        "private_key_source": private_key_source,
                        "stdin_is_fifo": stdin_is_fifo,
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "payload_size": len(payload),
                    }
                    pathlib.Path(os.environ["TEST_CAPTURE_DIR"], "wg.json").write_text(
                        json.dumps(record, sort_keys=True), encoding="utf-8"
                    )
                    raise SystemExit(int(os.environ["WG_STUB_STATUS"]))
                    """
                ),
                encoding="utf-8",
            )
            wg.chmod(0o700)

            status_path = temporary / "status"
            harness = "\n".join(
                (
                    "set -euo pipefail",
                    audit_functions,
                    run_function,
                    private_key_function,
                    "set_netns_client_args() {",
                    "  NETNS_CLIENT_ARGS=(--socket test-socket)",
                    "}",
                    "NETNS_CLIENT_ARGS=()",
                    f"exec 9<{shlex.quote(str(occupied_path))}",
                    f"exec {{NETNS_ANCHOR_IMAGE_FD}}<{shlex.quote(str(anchor_fd_path))}",
                    f"NETNS_ANCHOR_EXEC={shlex.quote(str(anchor))}",
                    "export XOR_PASSWORD=xor-environment-sentinel",
                    "status=0",
                    "if run_wg_set_with_private_key_in_owned_netns "
                    f"test-ns {shlex.quote(str(key_path))} wg0 listen-port 31001; then",
                    "  status=0",
                    "else",
                    "  status=$?",
                    "fi",
                    "IFS= read -r caller_fd_marker <&9",
                    "IFS= read -r anchor_fd_marker <&\"${NETNS_ANCHOR_IMAGE_FD}\"",
                    f"printf '%s\\n' \"${{status}}\" >{shlex.quote(str(status_path))}",
                    "printf '%s\\n' \"${caller_fd_marker}\"",
                    "printf '%s\\n' \"${anchor_fd_marker}\"",
                )
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", harness],
                check=False,
                capture_output=True,
                env={
                    "PATH": f"{temporary}:/usr/bin:/bin",
                    "LC_ALL": "C",
                    "TEST_CAPTURE_DIR": str(temporary),
                    "WG_STUB_STATUS": "23",
                },
            )

            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(
                completed.stdout,
                b"caller-fd-9-marker\nanchor-held-fd-marker\n",
            )
            self.assertEqual(status_path.read_text(encoding="ascii").strip(), "23")
            producer_record = json.loads(
                (temporary / "producer.json").read_text(encoding="utf-8")
            )
            anchor_record = json.loads(
                (temporary / "anchor.json").read_text(encoding="utf-8")
            )
            wg_record = json.loads(
                (temporary / "wg.json").read_text(encoding="utf-8")
            )

            expected_digest = hashlib.sha256(private_key).hexdigest()
            self.assertTrue(producer_record["stdin_is_regular"])
            self.assertTrue(anchor_record["stdin_is_fifo"])
            self.assertTrue(wg_record["stdin_is_fifo"])
            self.assertEqual(producer_record["payload_sha256"], expected_digest)
            self.assertEqual(wg_record["payload_sha256"], expected_digest)
            self.assertEqual(producer_record["payload_size"], len(private_key))
            self.assertEqual(wg_record["payload_size"], len(private_key))
            self.assertEqual(wg_record["private_key_source"], "/dev/stdin")

            key_metadata = key_path.stat()
            key_identity = (key_metadata.st_dev, key_metadata.st_ino)
            caller_metadata = occupied_path.stat()
            caller_identity = (caller_metadata.st_dev, caller_metadata.st_ino)
            anchor_metadata = anchor_fd_path.stat()
            anchor_identity = (anchor_metadata.st_dev, anchor_metadata.st_ino)
            for record in (anchor_record, wg_record):
                regular_identities = {
                    (entry["device"], entry["inode"])
                    for entry in record["fds"]
                    if entry["regular"]
                }
                self.assertNotIn(key_identity, regular_identities)
                self.assertIn(caller_identity, regular_identities)
                self.assertIn(anchor_identity, regular_identities)
            producer_key_fds = [
                entry["fd"]
                for entry in producer_record["fds"]
                if (entry["device"], entry["inode"]) == key_identity
            ]
            self.assertEqual(producer_key_fds, [0])

            serialized_records = json.dumps(
                [producer_record, anchor_record, wg_record], sort_keys=True
            ).encode()
            self.assertNotIn(private_key.rstrip(), serialized_records)
            self.assertNotIn(str(key_path).encode(), serialized_records)
            for record in (producer_record, anchor_record, wg_record):
                self.assertNotIn("XOR_PASSWORD", record["environment"])

            stderr = completed.stderr
            self.assertNotIn(private_key.rstrip(), completed.stdout)
            self.assertNotIn(str(key_path).encode(), completed.stdout)
            self.assertNotIn(private_key.rstrip(), stderr)
            self.assertNotIn(str(key_path).encode(), stderr)
            self.assertNotIn(b"/dev/stdin", stderr)
            self.assertEqual(stderr.count(b"netns command start:"), 1)
            self.assertEqual(stderr.count(b"netns command finish:"), 1)
            self.assertIn(b"netns=test-ns rc=pending argv=", stderr)
            self.assertIn(b"netns=test-ns rc=23 argv=", stderr)
            self.assertEqual(stderr.count(b"redacted-private-key-source"), 2)

    def test_private_key_open_failure_is_redacted_and_starts_no_rhs(self) -> None:
        dynamic_fd_probe = subprocess.run(
            ["/bin/bash", "-c", "exec {probe_fd}</dev/null"],
            check=False,
            capture_output=True,
        )
        if dynamic_fd_probe.returncode != 0:
            self.skipTest("private-key open failure requires Bash dynamic FDs")

        audit_functions = self.source[
            self.source.index("print_redacted_netns_argv() {") :
            self.source.index("\nset_netns_client_args() {")
        ]
        private_key_functions = self.source[
            self.source.index("produce_held_private_key() {") :
            self.source.index("\nrun_bounded_in_owned_netns() {")
        ]
        private_key = b"private-key-open-failure-sentinel-19d2\n"

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            key_path = temporary / "rlimit-input.key"
            key_path.write_bytes(private_key)
            key_path.chmod(0o600)
            caller_path = temporary / "caller-nine"
            caller_path.write_text("caller-nine-marker\n", encoding="ascii")
            anchor_path = temporary / "anchor-held"
            anchor_path.write_text("anchor-held-marker\n", encoding="ascii")
            command_sentinel = temporary / "rhs-started"

            harness = "\n".join(
                (
                    "set -euo pipefail",
                    audit_functions,
                    private_key_functions,
                    "run_in_owned_netns() {",
                    f"  printf started >{shlex.quote(str(command_sentinel))}",
                    "}",
                    f"exec 9<{shlex.quote(str(caller_path))}",
                    f"exec {{NETNS_ANCHOR_IMAGE_FD}}<{shlex.quote(str(anchor_path))}",
                    "ulimit -n 11",
                    "status=0",
                    "if run_wg_set_with_private_key_in_owned_netns "
                    f"test-ns {shlex.quote(str(key_path))} wg0; then",
                    "  status=0",
                    "else",
                    "  status=$?",
                    "fi",
                    "IFS= read -r caller_marker <&9",
                    "IFS= read -r anchor_marker <&\"${NETNS_ANCHOR_IMAGE_FD}\"",
                    "echo \"${status}:${caller_marker}:${anchor_marker}\"",
                )
            )
            result = subprocess.run(
                ["/bin/bash", "-c", harness],
                check=False,
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            fields = result.stdout.decode("ascii").strip().split(":")
            self.assertNotEqual(fields[0], "0")
            self.assertEqual(fields[1:], ["caller-nine-marker", "anchor-held-marker"])
            self.assertFalse(command_sentinel.exists())
            self.assertNotIn(str(key_path).encode(), result.stderr)
            self.assertNotIn(private_key.rstrip(), result.stderr)
            self.assertNotIn(str(key_path).encode(), result.stdout)
            self.assertNotIn(private_key.rstrip(), result.stdout)
            self.assertEqual(
                result.stderr.count(b"private-key input open failure:"),
                1,
            )
            self.assertIn(b"redacted-private-key-source", result.stderr)

    def test_audit_failures_are_fatal_in_all_shell_contexts(self) -> None:
        run_function = self.source[
            self.source.index("run_in_owned_netns() {") :
            self.source.index("\nproduce_held_private_key() {")
        ]
        create_veth_function = self.source[
            self.source.index("create_veth_pair() {") :
            self.source.index("\nstart_netns_anchor() {")
        ]

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            anchor = temporary / "anchor-sentinel"
            anchor.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import os
                    import pathlib

                    pathlib.Path(os.environ["COMMAND_SENTINEL"]).write_text(
                        "executed\\n", encoding="ascii"
                    )
                    print("anchor-output")
                    raise SystemExit(int(os.environ["COMMAND_STATUS"]))
                    """
                ),
                encoding="utf-8",
            )
            anchor.chmod(0o700)

            common = "\n".join(
                (
                    "set -euo pipefail",
                    run_function,
                    create_veth_function,
                    "set_netns_client_args() {",
                    '  local prefix="${2:-}"',
                    '  NETNS_CLIENT_ARGS=("--${prefix}socket" test-socket)',
                    "  return 0",
                    "}",
                    "audit_netns_argv() {",
                    '  local phase="$1"',
                    '  if [[ "${phase}" == "${AUDIT_FAIL_PHASE}" ]]; then',
                    '    return "${AUDIT_FAIL_STATUS}"',
                    "  fi",
                    "  return 0",
                    "}",
                    "NETNS_CLIENT_ARGS=()",
                    "NETNS_ANCHOR_IMAGE_FD=10",
                    f"NETNS_ANCHOR_EXEC={shlex.quote(str(anchor))}",
                    "NSA=test-a",
                    "NSR=test-r",
                    "NSB=test-b",
                    "VETH_A=left-a",
                    "VETH_RA=right-a",
                    "VETH_B=left-b",
                    "VETH_RB=right-b",
                )
            )

            start_sentinel = temporary / "start-command"
            start_harness = "\n".join(
                (
                    common,
                    "AUDIT_FAIL_PHASE=start",
                    "AUDIT_FAIL_STATUS=71",
                    "status=0",
                    "if run_in_owned_netns test-a command-sentinel; then",
                    "  status=0",
                    "else",
                    "  status=$?",
                    "fi",
                    "echo \"${status}\"",
                )
            )
            start_result = subprocess.run(
                ["/bin/bash", "-c", start_harness],
                check=False,
                capture_output=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                    "COMMAND_SENTINEL": str(start_sentinel),
                    "COMMAND_STATUS": "0",
                },
            )
            self.assertEqual(start_result.returncode, 0, start_result.stderr)
            self.assertEqual(start_result.stdout, b"71\n")
            self.assertFalse(start_sentinel.exists())

            pipeline_sentinel = temporary / "pipeline-command"
            pipeline_harness = "\n".join(
                (
                    common,
                    "AUDIT_FAIL_PHASE=finish",
                    "AUDIT_FAIL_STATUS=72",
                    "status=0",
                    "if echo pipeline-input | "
                    "run_in_owned_netns test-a command-sentinel; then",
                    "  status=0",
                    "else",
                    "  status=$?",
                    "fi",
                    "echo \"${status}\"",
                )
            )
            pipeline_result = subprocess.run(
                ["/bin/bash", "-c", pipeline_harness],
                check=False,
                capture_output=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                    "COMMAND_SENTINEL": str(pipeline_sentinel),
                    "COMMAND_STATUS": "23",
                },
            )
            self.assertEqual(pipeline_result.returncode, 0, pipeline_result.stderr)
            self.assertEqual(pipeline_result.stdout, b"anchor-output\n72\n")
            self.assertTrue(pipeline_sentinel.is_file())

            substitution_sentinel = temporary / "substitution-command"
            substitution_harness = "\n".join(
                (
                    common,
                    "AUDIT_FAIL_PHASE=finish",
                    "AUDIT_FAIL_STATUS=73",
                    "status=0",
                    "output=",
                    "if output=\"$(create_veth_pair "
                    "left-a test-a right-a test-r)\"; then",
                    "  status=0",
                    "else",
                    "  status=$?",
                    "fi",
                    "echo \"${status}:${output}\"",
                )
            )
            substitution_result = subprocess.run(
                ["/bin/bash", "-c", substitution_harness],
                check=False,
                capture_output=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                    "COMMAND_SENTINEL": str(substitution_sentinel),
                    "COMMAND_STATUS": "0",
                },
            )
            self.assertEqual(
                substitution_result.returncode,
                0,
                substitution_result.stderr,
            )
            self.assertEqual(
                substitution_result.stdout,
                b"73:anchor-output\n",
            )
            self.assertTrue(substitution_sentinel.is_file())

    def test_audit_helpers_propagate_internal_failures(self) -> None:
        audit_functions = self.source[
            self.source.index("print_redacted_netns_argv() {") :
            self.source.index("\nset_netns_client_args() {")
        ]

        cases = {
            "timestamp": """
                date() { return 61; }
                if audit_netns_argv start test-ns pending command; then
                  status=0
                else
                  status=$?
                fi
                echo "${status}"
            """,
            "redactor": """
                date() { echo 2026-08-07T00:00:00Z; }
                print_redacted_netns_argv() { return 62; }
                if audit_netns_argv finish test-ns 23 command; then
                  status=0
                else
                  status=$?
                fi
                echo "${status}"
            """,
            "prefix-printf": """
                date() { echo 2026-08-07T00:00:00Z; }
                printf() { return 63; }
                if audit_netns_argv start test-ns pending; then
                  status=0
                else
                  status=$?
                fi
                echo "${status}"
            """,
            "newline-printf": """
                date() { echo 2026-08-07T00:00:00Z; }
                printf_calls=0
                printf() {
                  printf_calls=$((printf_calls + 1))
                  if ((printf_calls == 2)); then
                    return 64
                  fi
                  builtin printf "$@"
                }
                if audit_netns_argv finish test-ns 0; then
                  status=0
                else
                  status=$?
                fi
                echo "${status}"
            """,
        }
        expected = {
            "timestamp": b"61\n",
            "redactor": b"62\n",
            "prefix-printf": b"63\n",
            "newline-printf": b"64\n",
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                harness = "\n".join(
                    (
                        "set -euo pipefail",
                        audit_functions,
                        textwrap.dedent(body),
                    )
                )
                result = subprocess.run(
                    ["/bin/bash", "-c", harness],
                    check=False,
                    capture_output=True,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected[name])

    def test_failure_traps_report_only_and_never_mutate_resources(self) -> None:
        failure_report = self.source[
            self.source.index("failure_report() {") :
            self.source.index("\non_exit() {")
        ]
        exit_trap = self.source[
            self.source.index("on_exit() {") :
            self.source.index("\non_signal() {")
        ]
        signal_trap = self.source[
            self.source.index("on_signal() {") :
            self.source.index("\ntrap on_exit EXIT")
        ]
        self.assertIn(
            "the failure trap performed no detach, delete, unmount, kill, or file cleanup",
            failure_report,
        )
        for body in (failure_report, exit_trap, signal_trap):
            for forbidden in (
                "explicit_teardown",
                "remove_owned_file",
                "release_lifecycle_hold",
                "teardown_step",
                "rm --",
                "rmdir --",
                "kill -",
            ):
                self.assertNotIn(forbidden, body)
        self.assertIn(
            "no recovery mutation command is generated",
            failure_report,
        )
        for forbidden_recovery in (
            "print_command ip netns exec",
            "print_command ip netns delete",
            'print_command umount "${BPFFS_DIR}"',
        ):
            self.assertNotIn(forbidden_recovery, failure_report)
        for line in failure_report.splitlines():
            stripped = line.strip()
            if any(
                command in stripped
                for command in (
                    'ip netns delete "${',
                    'umount "${BPFFS_DIR}"',
                )
            ):
                self.assertTrue(
                    stripped.startswith("print_command "),
                    f"failure report executes instead of printing: {stripped}",
                )
        self.assertNotIn('"${BIN}" detach', failure_report)

    def test_manifest_seals_shared_lifecycle_and_pin_resource_contract(self) -> None:
        for field in (
            "format=wg-mix-ebpf-test-manifest-v2",
            "bpffs_source=%s",
            "bpffs_mount_id=%s",
            "pin_parent_dev=%s",
            "pin_parent_ino=%s",
            "pin_resource_key_a=%s",
            "pin_resource_key_b=%s",
            "pin_lock_root=%s",
            "pin_lock_a=%s",
            "pin_lock_b=%s",
            "pin_owner_root=%s",
            "pin_owner_a=%s",
            "pin_owner_b=%s",
            "netns_a_dev=%s",
            "netns_a_ino=%s",
            "config_a=%s",
            "underlay_a=under0",
            "lifecycle_lease=%s",
        ):
            self.assertIn(field, self.source)
        self.assertNotIn("lease_a=", self.source)
        self.assertNotIn("lease_b=", self.source)
        self.assertIn(
            'BPFFS_SOURCE="wg-mix-ebpf-${RUN_ID}-${OWNER_TOKEN}"',
            self.source,
        )
        self.assertNotIn('BPFFS_SOURCE="bpf"', self.source)
        owner_source = self.source.index(
            'BPFFS_SOURCE="wg-mix-ebpf-${RUN_ID}-${OWNER_TOKEN}"'
        )
        self.assertLess(self.source.index('RUN_ID="$(python3 -'), owner_source)
        self.assertLess(
            self.source.index('OWNER_TOKEN="$(python3 -'),
            owner_source,
        )
        self.assertIn("$5 != target", self.source)
        self.assertIn("other_bpf_count++", self.source)
        self.assertNotIn('-v production="/sys/fs/bpf"', self.source)
        self.assertIn('BPFFS_LEDGER="${RUN_BASE}/bpffs.creation.v1"', self.source)
        for field in (
            "format=wg-mix-ebpf-bpffs-creation-v1",
            "pre_target_mount_id=%s",
            "pre_target_dev=%s",
            "pre_bpf_mounts=%s",
            "post_mount_id=%s",
            "post_dev=%s",
            "post_ino=%s",
        ):
            self.assertIn(field, self.source)
        self.assertIn(
            'f"wg-mix-ebpf-pin-v1:{parent_device}:{parent_inode}:{basename}"',
            self.source,
        )
        canonical = "wg-mix-ebpf-pin-v1:42:99:wg-mix-ebpf-a"
        self.assertEqual(
            hashlib.sha256(canonical.encode("ascii")).hexdigest(),
            "0587a9fb34e37f032795767bfd901660a37e065b3faecd363ba302147f6bcbc3",
        )
        self.assertNotIn(
            "hashlib.sha256(sys.argv[1].encode()).hexdigest()",
            self.source,
        )
        seal = self.source.index('(set -o noclobber; manifest_payload >"${MANIFEST}")')
        first_reload = self.source.index(
            'run_agent_in_netns "${NSA}" "${PINA}" reload'
        )
        lock_marker = self.source.index(
            'write_marker "${PIN_LOCK_ROOT}" pin-locks'
        )
        owner_marker = self.source.index(
            'write_marker "${PIN_OWNER_ROOT}" pin-owners'
        )
        self.assertLess(lock_marker, seal)
        self.assertLess(owner_marker, seal)
        self.assertLess(
            self.source.index("\nwrite_bpffs_creation_ledger\n"),
            seal,
        )
        self.assertLess(seal, first_reload)

    def test_lifecycle_lease_is_explicitly_created_before_consumers(self) -> None:
        function_start = self.source.index("create_lifecycle_lease() {")
        function_end = self.source.index("\nmarker_payload() {", function_start)
        function = self.source[function_start:function_end]
        for gate in (
            'validate_owned_path "${LIFECYCLE_LEASE}"',
            '[[ -e "${LIFECYCLE_LEASE}" || -L "${LIFECYCLE_LEASE}" ]]',
            '(set -o noclobber; : >"${LIFECYCLE_LEASE}")',
            'chmod 0600 "${LIFECYCLE_LEASE}"',
            '[[ ! -f "${LIFECYCLE_LEASE}" || -L "${LIFECYCLE_LEASE}" ||',
            'stat -c \'%u\'',
            'stat -c \'%a\'',
            'stat -c \'%h\'',
            'realpath -e -- "${LIFECYCLE_LEASE}"',
            '"${resolved}" != "${RUN_BASE}/"*',
        ):
            self.assertIn(gate, function)
        self.assertLess(
            function.index('validate_owned_path "${LIFECYCLE_LEASE}"'),
            function.index('(set -o noclobber; : >"${LIFECYCLE_LEASE}")'),
        )
        self.assertNotIn("touch ", function)

        initialization = self.source[
            self.source.index('PHASE="create-owned-run-root"') :
            self.source.index('PHASE="mount-private-bpffs"')
        ]
        create = initialization.index("\ncreate_lifecycle_lease\n")
        for marker in (
            'write_marker "${RUN_BASE}" root',
            'write_marker "${PIN_LOCK_ROOT}" pin-locks',
            'write_marker "${PIN_OWNER_ROOT}" pin-owners',
        ):
            self.assertLess(initialization.index(marker), create)
        manifest = self.source.index(
            '(set -o noclobber; manifest_payload >"${MANIFEST}")'
        )
        first_agent = self.source.index(
            'run_agent_in_netns "${NSA}" "${PINA}" reload'
        )
        create_absolute = self.source.index("\ncreate_lifecycle_lease\n")
        self.assertLess(create_absolute, manifest)
        self.assertLess(create_absolute, first_agent)

        holder_open_start = self.holder_source.index(
            "lease_fd, lease_metadata = open_verified_file("
        )
        holder_open = self.holder_source[
            holder_open_start : self.holder_source.index(
                "\n        try:", holder_open_start
            )
        ]
        self.assertIn("os.O_RDWR", holder_open)
        self.assertNotIn("os.O_CREAT", holder_open)

    def test_lifecycle_lease_creation_unprivileged_fixture(self) -> None:
        if not pathlib.Path("/proc/self").exists():
            self.skipTest("lifecycle lease fixture requires Linux coreutils")

        functions = self.source[
            self.source.index("validate_owned_path() {") :
            self.source.index("\nmarker_payload() {")
        ]
        harness = "\n".join(
            (
                "set -euo pipefail",
                'RUN_BASE="$1"',
                'LIFECYCLE_LEASE="${RUN_BASE}/lifecycle.lease"',
                functions,
                "create_lifecycle_lease",
            )
        )

        def invoke(run_base: pathlib.Path) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                ["/bin/bash", "-c", harness, "lease-fixture", str(run_base)],
                check=False,
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory).resolve()

            success_root = temporary / "success"
            success_root.mkdir(mode=0o700)
            success = invoke(success_root)
            self.assertEqual(success.returncode, 0, success.stderr)
            lease = success_root / "lifecycle.lease"
            metadata = lease.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertFalse(lease.is_symlink())
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_uid, success_root.stat().st_uid)
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(lease.resolve(strict=True), lease)

            existing_root = temporary / "existing"
            existing_root.mkdir(mode=0o700)
            existing = existing_root / "lifecycle.lease"
            existing.write_bytes(b"do-not-clobber\n")
            rejected_existing = invoke(existing_root)
            self.assertNotEqual(rejected_existing.returncode, 0)
            self.assertEqual(existing.read_bytes(), b"do-not-clobber\n")

            symlink_root = temporary / "symlink"
            symlink_root.mkdir(mode=0o700)
            target = symlink_root / "target"
            target.write_bytes(b"do-not-follow\n")
            symlink = symlink_root / "lifecycle.lease"
            symlink.symlink_to(target.name)
            rejected_symlink = invoke(symlink_root)
            self.assertNotEqual(rejected_symlink.returncode, 0)
            self.assertTrue(symlink.is_symlink())
            self.assertEqual(target.read_bytes(), b"do-not-follow\n")

    def test_private_bpffs_mountinfo_awk_accepts_positive_fixture(self) -> None:
        start_marker = '-v expected_source="${BPFFS_SOURCE}" \'\n'
        program_start = self.source.index(start_marker) + len(start_marker)
        program_end = self.source.index(
            "\n    ' \"${mountinfo_path}\"",
            program_start,
        )
        awk_program = self.source[program_start:program_end]
        target = "/run/wg-mix-ebpf-test/private-bpffs"
        source = "wg-mix-ebpf-01234567-0123456789abcdef0123456789abcdef"
        mountinfo_prefix = (
            "25 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"
            "41 25 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec "
            "- bpf bpf rw,mode=700\n"
        )

        def inspect(
            expected_source: str,
            propagation: str = "",
        ) -> subprocess.CompletedProcess[str]:
            optional = f"{propagation} " if propagation else ""
            mountinfo = mountinfo_prefix + (
                f"77 25 0:31 / {target} rw,nosuid,nodev,noexec "
                f"{optional}- bpf {source} rw,mode=700\n"
            )
            return subprocess.run(
                [
                    "/usr/bin/awk",
                    "-v",
                    f"target={target}",
                    "-v",
                    f"expected_source={expected_source}",
                    awk_program,
                ],
                input=mountinfo,
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )

        completed = inspect(source)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "77 0:31 25 8:1\n")
        self.assertNotEqual(inspect("bpf").returncode, 0)
        self.assertNotEqual(inspect(source + "0").returncode, 0)
        for propagation in (
            "shared:77",
            "master:12",
            "propagate_from:12",
            "unbindable",
        ):
            with self.subTest(propagation=propagation):
                self.assertNotEqual(inspect(source, propagation).returncode, 0)

    def test_private_bpffs_pre_mount_snapshot_is_bound_and_sorted(self) -> None:
        function = self.source[
            self.source.index("snapshot_private_bpffs_pre_mount() {") :
            self.source.index("\ninspect_private_bpffs_mount_record() {")
        ]
        target = "/run/wg-mix-ebpf-tests/01234567/bpffs"
        harness = "\n".join(
            (
                "set -euo pipefail",
                f"BPFFS_DIR={shlex.quote(target)}",
                function,
                'snapshot_private_bpffs_pre_mount "$1"',
                'printf "%s %s %s\\n" "${BPFFS_PRE_TARGET_MOUNT_ID}" '
                '"${BPFFS_PRE_TARGET_DEVICE}" "${BPFFS_PRE_BPF_MOUNTS}"',
            )
        )

        def inspect(mountinfo: str) -> subprocess.CompletedProcess[str]:
            with tempfile.NamedTemporaryFile() as fixture:
                fixture.write(mountinfo.encode("ascii"))
                fixture.flush()
                return subprocess.run(
                    ["/bin/bash", "-c", harness, "snapshot-fixture", fixture.name],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                )

        baseline = (
            "21 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"
            "91 21 0:91 / /sys/fs/bpf rw,nosuid,nodev,noexec "
            "- bpf bpf rw\n"
            "100 21 0:100 / /run rw,nosuid,nodev,relatime "
            "- tmpfs tmpfs rw\n"
            "30 21 0:30 / /other-bpf rw,nosuid,nodev,noexec "
            "- bpf old-bpf rw\n"
        )
        accepted = inspect(baseline)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(
            accepted.stdout,
            "100 0:100 30@0:30,91@0:91\n",
        )

        exact_target = baseline + (
            f"110 100 0:110 / {target} rw,relatime - tmpfs tmpfs rw\n"
        )
        self.assertNotEqual(inspect(exact_target).returncode, 0)
        stacked_parent = baseline + (
            "101 21 0:101 / /run rw,relatime - tmpfs stacked rw\n"
        )
        self.assertNotEqual(inspect(stacked_parent).returncode, 0)
        duplicate_id = baseline + (
            "91 21 0:92 / /duplicate rw,relatime - tmpfs duplicate rw\n"
        )
        self.assertNotEqual(inspect(duplicate_id).returncode, 0)

    def test_bpffs_creation_ledger_unprivileged_fixture(self) -> None:
        if not pathlib.Path("/proc/self").exists():
            self.skipTest("bpffs ledger fixture requires Linux coreutils")

        validate_owned_path = self.source[
            self.source.index("validate_owned_path() {") :
            self.source.index("\ncreate_lifecycle_lease() {")
        ]
        payload = self.source[
            self.source.index("bpffs_creation_ledger_payload() {") :
            self.source.index("\nwrite_marker() {")
        ]
        ledger_functions = self.source[
            self.source.index("validate_bpffs_creation_state() {") :
            self.source.index("\nsnapshot_private_bpffs_pre_mount() {")
        ]
        harness = "\n".join(
            (
                "set -euo pipefail",
                "umask 077",
                'RUN_BASE="$1"',
                'RUN_ID="01234567"',
                'OWNER_TOKEN="0123456789abcdef0123456789abcdef"',
                'BPFFS_DIR="${RUN_BASE}/bpffs"',
                'BPFFS_SOURCE="wg-mix-ebpf-${RUN_ID}-${OWNER_TOKEN}"',
                'BPFFS_LEDGER="${RUN_BASE}/bpffs.creation.v1"',
                'BPFFS_PRE_TARGET_MOUNT_ID="21"',
                'BPFFS_PRE_TARGET_DEVICE="8:1"',
                'BPFFS_PRE_BPF_MOUNTS="30@0:30,91@0:91"',
                'BPFFS_MOUNT_ID="42"',
                'BPFFS_MOUNT_DEVICE="0:42"',
                'BPFFS_PARENT_INO="201"',
                validate_owned_path,
                payload,
                ledger_functions,
                'case "$2" in',
                '  legacy-source) BPFFS_SOURCE="bpf" ;;',
                '  reused-id) BPFFS_MOUNT_ID="30" ;;',
                "esac",
                "write_bpffs_creation_ledger",
                "validate_bpffs_creation_ledger",
            )
        )

        def invoke(
            run_base: pathlib.Path, mode: str = "success"
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["/bin/bash", "-c", harness, "ledger-fixture", str(run_base), mode],
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory).resolve()
            success_root = temporary / "success"
            success_root.mkdir(mode=0o700)
            success = invoke(success_root)
            self.assertEqual(success.returncode, 0, success.stderr)
            ledger = success_root / "bpffs.creation.v1"
            self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o600)
            data = ledger.read_text(encoding="ascii")
            self.assertIn(
                "source=wg-mix-ebpf-01234567-"
                "0123456789abcdef0123456789abcdef\n",
                data,
            )
            self.assertNotIn("source=bpf\n", data)
            collision = invoke(success_root)
            self.assertNotEqual(collision.returncode, 0)
            self.assertEqual(ledger.read_text(encoding="ascii"), data)

            for mode in ("legacy-source", "reused-id"):
                rejected_root = temporary / mode
                rejected_root.mkdir(mode=0o700)
                rejected = invoke(rejected_root, mode)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertFalse((rejected_root / "bpffs.creation.v1").exists())

    def test_pin_resources_are_validated_after_detach_before_exact_removal(self) -> None:
        detach_b = self.source.index('teardown_step "detach agent B pin=${PINB}"')
        owner_absent_a = self.source.index(
            'validate_pin_owner_absent "${PIN_OWNER_A}" "${PIN_RESOURCE_KEY_A}"'
        )
        validate_a = self.source.index(
            '"${PIN_LOCK_A}" "${PINA}" "${PIN_RESOURCE_KEY_A}"'
        )
        remove_a = self.source.index('remove_owned_file "${PIN_LOCK_A}"')
        remove_lock_root = self.source.index(
            'rmdir -- "${PIN_LOCK_ROOT}"'
        )
        remove_owner_root = self.source.index(
            'rmdir -- "${PIN_OWNER_ROOT}"'
        )
        self.assertLess(detach_b, owner_absent_a)
        self.assertLess(owner_absent_a, validate_a)
        self.assertLess(validate_a, remove_a)
        self.assertLess(remove_a, remove_lock_root)
        self.assertLess(remove_lock_root, remove_owner_root)
        self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", self.source)
        self.assertIn('owner["version"] != 2', self.source)
        for field in (
            '"resource_key"',
            '"parent_device"',
            '"parent_inode"',
            '"pin_basename"',
            '"pin_path"',
        ):
            self.assertIn(field, self.source)

    def test_netns_identity_is_fd_bound_before_use_and_stop(self) -> None:
        validator = self.source[
            self.source.index("validate_netns_identity() {") :
            self.source.index("\nvalidate_all_netns_identities() {")
        ]
        self.assertIn("set_netns_client_args", validator)
        self.assertIn('"${NETNS_ANCHOR_EXEC}" probe', validator)
        self.assertIn('"${NETNS_CLIENT_ARGS[@]}"', validator)
        self.assertNotIn("stat ", validator)
        self.assertNotIn("/run/", validator)

        runner = self.source[
            self.source.index("run_agent_in_netns() {") :
            self.source.index("\nteardown_step() {")
        ]
        self.assertIn(
            "reload | status | detach) isolated_args=(--isolated-netns-test)",
            runner,
        )
        first_exec = runner.index("run_bounded_in_owned_netns")
        self.assertLess(
            runner.index(
                'validate_netns_identity "${NSA}" '
                '"${NETNS_A_DEV}" "${NETNS_A_INO}" a'
            ),
            first_exec,
        )
        self.assertLess(
            runner.index(
                'validate_netns_identity "${NSB}" '
                '"${NETNS_B_DEV}" "${NETNS_B_INO}" b'
            ),
            first_exec,
        )

        stop = self.source[
            self.source.index("stop_owned_netns() {") :
            self.source.index("\nvalidate_released_pin_lock() {")
        ]
        self.assertLess(
            stop.index("validate_manifest"),
            stop.index('"${NETNS_ANCHOR_EXEC}" stop'),
        )
        self.assertIn("validate_netns_identity", stop)
        self.assertIn('wait "${anchor_pid}"', stop)
        self.assertNotIn("kill -", stop)
        self.assertNotIn("delete", stop)

        for required in (
            "unix.CLONE_NEWNET",
            "command.ExtraFiles",
            "unix.UnixRights(namespaceFD)",
            "unix.MSG_CMSG_CLOEXEC",
            "unix.NS_GET_NSTYPE",
            "unix.Setns(descriptor, unix.CLONE_NEWNET)",
            "operations.setNamespace(leftFD, unix.CLONE_NEWNET)",
            '"/proc/thread-self/ns/net"',
            "Namespace: nil",
            "PeerNamespace: netlink.NsFd(rightFD)",
            "netlink.NewHandle(unix.NETLINK_ROUTE)",
            "handle.LinkAdd",
            "runtime.LockOSThread()",
            "unix.SO_PEERCRED",
            '"@"+flags.socket',
            "PR_SET_PDEATHSIG",
            '"/proc/self/fd/3"',
            '"/proc/self/exe"',
            "validateWorkerImage(",
            "unix.PidfdOpen(",
            "unix.PidfdSendSignal(",
            "waitForAnchorExit(",
            "terminateAndReapWorker(",
        ):
            self.assertIn(required, self.anchor_linux_source)
        self.assertNotIn("os.Executable()", self.anchor_linux_source)
        self.assertNotIn("netlink.LinkByName(", self.anchor_linux_source)
        self.assertNotIn("netlink.LinkSetNsFd(", self.anchor_linux_source)
        self.assertIn("consumeBootstrapImageFD()", self.anchor_linux_source)
        self.assertIn(
            "subtle.ConstantTimeCompare",
            self.anchor_protocol_source,
        )
        self.assertNotIn("/run/netns", self.anchor_linux_source)
        self.assertNotIn("ip netns", self.anchor_linux_source)
        exec_helper = self.anchor_linux_source[
            self.anchor_linux_source.index("func runExecCommand(") :
            self.anchor_linux_source.index("\nfunc runCreateVethPairCommand(")
        ]
        self.assertLess(
            exec_helper.index("acquireNamespace(flags,"),
            exec_helper.index("unix.Setns(descriptor, unix.CLONE_NEWNET)"),
        )
        create_veth = self.anchor_linux_source[
            self.anchor_linux_source.index("func runCreateVethPairCommand(") :
            self.anchor_linux_source.index("\nfunc runStopCommand(")
        ]
        self.assertEqual(2, create_veth.count("acquireNamespace("))
        self.assertEqual(1, create_veth.count("handle.LinkAdd"))
        self.assertNotIn("netlink.LinkAdd", create_veth)
        self.assertLess(
            create_veth.index("acquireNamespace(*left,"),
            create_veth.index("acquireNamespace(*right,"),
        )
        self.assertLess(
            create_veth.index("acquireNamespace(*right,"),
            create_veth.index("createVethPairOnDedicatedThread("),
        )
        dedicated_thread = create_veth[
            create_veth.index("func createVethPairOnDedicatedThread(") :
            create_veth.index("\nfunc validateVethPairThreadContract(")
        ]
        self.assertIn("runtime.LockOSThread()", dedicated_thread)
        self.assertNotIn("defer runtime.UnlockOSThread()", dedicated_thread)
        self.assertEqual(3, dedicated_thread.count("runtime.UnlockOSThread()"))
        hold_original = dedicated_thread.index(
            '"/proc/thread-self/ns/net"'
        )
        create_in_left = dedicated_thread.index(
            "workErr := createVethPairInExactLeftNamespace("
        )
        restore = dedicated_thread.index(
            "restoreErr := operations.setNamespace(originalFD, unix.CLONE_NEWNET)"
        )
        verify_restore = dedicated_thread.index(
            "verifyIdentity(observed, originalIdentity)"
        )
        unlock_after_restore = dedicated_thread.rindex(
            "runtime.UnlockOSThread()"
        )
        self.assertLess(hold_original, create_in_left)
        self.assertLess(create_in_left, restore)
        self.assertLess(restore, verify_restore)
        self.assertLess(verify_restore, dedicated_thread.index("if restored {"))
        self.assertLess(
            dedicated_thread.index("if restored {"),
            unlock_after_restore,
        )
        exact_create = create_veth[
            create_veth.index("func createVethPairInExactLeftNamespace(") :
            create_veth.index(
                "\nfunc currentThreadNetworkNamespaceIdentity("
            )
        ]
        setns = exact_create.index(
            "operations.setNamespace(leftFD, unix.CLONE_NEWNET)"
        )
        identity = exact_create.index(
            "currentIdentity, err := operations.currentNamespaceIdentity()"
        )
        new_handle = exact_create.index(
            "handle, err := operations.newLinkHandle()"
        )
        link_add = exact_create.index("handle.LinkAdd(link)")
        self.assertLess(setns, identity)
        self.assertLess(identity, new_handle)
        self.assertLess(new_handle, link_add)
        self.assertIn("Namespace: nil", exact_create)
        self.assertIn(
            "PeerNamespace: netlink.NsFd(rightFD)",
            exact_create,
        )
        self.assertNotIn("ifindex", create_veth.lower())
        self.assertNotIn("netlink.LinkByName(", create_veth)

        shell_veth = self.source[
            self.source.index("create_veth_pair() {") :
            self.source.index("\nstart_netns_anchor() {")
        ]
        self.assertIn('"${NETNS_ANCHOR_EXEC}" create-veth-pair', shell_veth)
        self.assertIn('"left-"', shell_veth)
        self.assertIn('"right-"', shell_veth)
        self.assertNotIn("ifindex", shell_veth.lower())
        self.assertNotIn('ip link add "${VETH_', self.source)

        anchor_start = self.source[
            self.source.index("start_netns_anchor() {") :
            self.source.index('\nPHASE="create-owned-run-root"')
        ]
        inspect = anchor_start.index('"${NETNS_ANCHOR_EXEC}" inspect-ready')
        liveness = anchor_start.index('kill -0 "${anchor_pid}"')
        self.assertLess(inspect, liveness)
        self.assertIn('ready_identity="$(', anchor_start)
        self.assertNotIn("readiness contract is invalid", anchor_start)
        self.assertIn("sleep 0.05", anchor_start)

        teardown = self.source[
            self.source.index("explicit_teardown() {") :
            self.source.index("\nmake_agent_config() {")
        ]
        self.assertIn("validate_all_netns_identities || return 1", teardown)
        self.assertEqual(teardown.count("stop_owned_netns "), 3)
        self.assertLess(
            teardown.index("stop_owned_netns "),
            teardown.index('"${NETNS_AUTH_TOKEN_FILE}"'),
        )
        self.assertNotIn("delete_owned_netns", teardown)
        operational = self.source[
            self.source.index("NETNS_CLIENT_ARGS=()") :
        ]
        self.assertNotIn('"${NETNS_ANCHOR_HELPER}"', operational)
        self.assertGreaterEqual(
            operational.count(
                '"WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD='
                '${NETNS_ANCHOR_IMAGE_FD}"'
            ),
            8,
        )

        source_check = self.source.index(
            'NETNS_HELPER_SOURCE_COMMIT="$('
        )
        create_root = self.source.index('PHASE="create-owned-run-root"')
        self.assertLess(source_check, create_root)
        self.assertIn(
            '"${NETNS_HELPER_SOURCE_COMMIT}" != "${EXPECTED_SOURCE_COMMIT}"',
            self.source,
        )
        anchor_build = self.makefile_source[
            self.makefile_source.index("build-netns-anchor:") :
            self.makefile_source.index("\n\nbuild-linux-amd64:")
        ]
        self.assertIn(
            "-ldflags=$(NETNS_ANCHOR_IDENTITY_LDFLAG)",
            anchor_build,
        )

    def test_netlink_link_add_dependency_contract_is_review_pinned(
        self,
    ) -> None:
        self.assertIn(
            "github.com/vishvananda/netlink v1.3.1",
            self.go_mod_source,
        )
        self.assertIn(
            "github.com/vishvananda/netlink v1.3.1 "
            "h1:3AEMt62VKqz90r0tmNhog0r/PpWKmrEShJU0wJW6bV0=",
            self.go_sum_source,
        )
        self.assertIn(
            "netlink v1.3.1 Handle.LinkAdd calls",
            self.anchor_linux_source,
        )
        self.assertIn(
            "Handle.ensureIndex (and therefore Handle.LinkByName)",
            self.anchor_linux_source,
        )

    def test_worker_signal_failures_still_enter_one_bounded_reap(self) -> None:
        worker = self.anchor_linux_source[
            self.anchor_linux_source.index(
                "func terminateAndReapWorkerWithSignal("
            ) :
            self.anchor_linux_source.index(
                "\nfunc waitForBoundedChildReap("
            )
        ]
        signal = worker.index("rawSignalErr := sendSignal(")
        reap = worker.index("reapErr := waitForBoundedChildReap(")
        self.assertLess(signal, reap)
        self.assertNotIn("return ", worker[signal:reap])
        self.assertIn("return errors.Join(signalErr, reapErr)", worker)

        direct = self.anchor_linux_source[
            self.anchor_linux_source.index(
                "func terminateAndReapDirectChildWithKill("
            ) :
            self.anchor_linux_source.index(
                "\nfunc terminateAndReapWorker("
            )
        ]
        kill = direct.index("killErr := kill()")
        direct_reap = direct.index("reapErr := waitForBoundedChildReap(")
        self.assertLess(kill, direct_reap)
        self.assertNotIn("return ", direct[kill:direct_reap])
        self.assertIn("return errors.Join(signalErr, reapErr)", direct)

        bounded = self.anchor_linux_source[
            self.anchor_linux_source.index(
                "func waitForBoundedChildReap("
            ) :
            self.anchor_linux_source.index("\nfunc runWorkerCommand(")
        ]
        self.assertIn("time.NewTimer(timeout)", bounded)
        self.assertIn("case waitErr, ok := <-workerWait:", bounded)
        self.assertIn("case <-timer.C:", bounded)

    def test_tcp_matrix_covers_flow_count_direction_and_error_gates(self) -> None:
        self.assertIn('TCP_STREAMS="${TCP_STREAMS:-1 4 16}"', self.source)
        self.assertIn(
            'TCP_DIRECTIONS="${TCP_DIRECTIONS:-forward reverse bidir}"',
            self.source,
        )
        self.assertIn('TCP_MTUS="${TCP_MTUS:-1419 1420 1421 1422}"', self.source)
        self.assertIn('UNDERLAY_MTU="${UNDERLAY_MTU:-2200}"', self.source)
        self.assertIn("TCP_MTUS contains duplicate value", self.source)
        self.assertIn("UNDERLAY_MTU must be an integer", self.source)
        self.assertIn("WG_MTU must be an integer", self.source)
        self.assertIn(
            "TCP_GSO_CHECKS was split into TCP_INNER_GSO_CHECKS",
            self.source,
        )

        run = self.source[
            self.source.index("exercise_tcp_run() {") :
            self.source.index("\nexercise_tcp_matrix() {")
        ]
        self.assertIn("forward) ;;", run)
        self.assertIn("reverse) client_direction_args=(-R) ;;", run)
        self.assertIn("bidir) client_direction_args=(--bidir) ;;", run)
        self.assertIn('"${IPERF_CHECKER_HELPER}"', run)
        self.assertIn(
            'local capture_timeout="$((TCP_DURATION + 5))"',
            run,
        )
        self.assertIn(
            'start_tcp_capture "${label}" "${capture_timeout}"',
            run,
        )
        self.assertIn('finish_tcp_capture "${label}"', run)
        self.assertIn('check_tcp_capture "${label}"', run)
        for option in (
            "--direction",
            "--streams",
            "--minimum-bytes",
            "--maximum-retransmits",
            "--minimum-fairness",
        ):
            self.assertIn(option, run)

        matrix = self.source[
            self.source.index("exercise_tcp_matrix() {") :
            self.source.index("\nexercise_udp_zero_checksum() {")
        ]
        self.assertLess(
            matrix.index("classify_tcp_gso_capabilities"),
            matrix.index("capture_tcp_netns_evidence before"),
        )
        self.assertIn(
            'for streams in "${TCP_STREAM_VALUES[@]}"; do',
            matrix,
        )
        self.assertIn(
            'for direction in "${TCP_DIRECTION_VALUES[@]}"; do',
            matrix,
        )
        failure = matrix.index("run_status=$?")
        after_status = matrix.index('status-a-tcp-${mtu}-after.json')
        failure_return = matrix.index('return "${run_status}"')
        self.assertLess(failure, after_status)
        self.assertLess(after_status, failure_return)
        for stat in (
            "egress_fragment",
            "ingress_fragment",
            "egress_ipv6_ext",
            "ingress_ipv6_ext",
        ):
            self.assertIn(stat, matrix)

        ipv4_isolation = self.source.index(
            'sysctl -qw net.ipv6.conf.all.disable_ipv6=1'
        )
        ipv4_default_isolation = self.source.index(
            'sysctl -qw net.ipv6.conf.default.disable_ipv6=1'
        )
        first_underlay_up = self.source.index(
            'run_in_owned_netns "${NSA}" ip link set under0 up'
        )
        self.assertLess(ipv4_isolation, ipv4_default_isolation)
        self.assertLess(ipv4_default_isolation, first_underlay_up)
        self.assertIn(
            'for ipv4_netns in "${NSA}" "${NSR}" "${NSB}"; do',
            self.source,
        )

        evidence = self.source[
            self.source.index("capture_tcp_link_evidence() {") :
            self.source.index("\ntcp_server_listening() {")
        ]
        gso_evidence = self.source[
            self.source.index("tcp_gso_link_features_enabled() {") :
            self.source.index("\ncapture_tcp_netns_evidence() {")
        ]
        for link in ("wg0", "under0", "ra0", "rb0"):
            self.assertIn(link, gso_evidence)
        for feature in (
            "tx-checksumming",
            "scatter-gather",
            "tcp-segmentation-offload",
            "generic-segmentation-offload",
            "generic-receive-offload",
            "tx-udp-segmentation",
        ):
            self.assertIn(feature, gso_evidence)
        self.assertIn('fields[1] == "on"', gso_evidence)
        self.assertIn(
            'tcp evidence=outer-udp-gso mtu=%s side=%s status=%s',
            gso_evidence,
        )
        self.assertIn('status="not-covered"', gso_evidence)
        self.assertIn('status="unsupported"', gso_evidence)
        self.assertIn('status="observed"', gso_evidence)
        self.assertIn("TCP_OUTER_GSO_MEASUREMENT_OK=0", gso_evidence)
        self.assertIn("reason=measurement-error", gso_evidence)
        self.assertIn('elif ((!TCP_OUTER_GSO_MEASUREMENT_OK)); then', gso_evidence)
        self.assertIn(
            "tcp summary=inner-tcp-gso status=%s mode=%s",
            gso_evidence,
        )
        self.assertIn(
            "tcp summary=outer-udp-gso status=%s mode=%s "
            "correctness_gate=false",
            gso_evidence,
        )
        for stat in (
            "egress_gso_managed_seen",
            "egress_gso_rewrite_ok",
            "ingress_gso_listener_hit",
            "ingress_gso_rewrite_ok",
        ):
            self.assertIn(stat, gso_evidence)
        self.assertNotIn('TCP_OUTER_GSO_CHECKS}" == "enforce', self.source)
        for command in (
            "ip -details -statistics link show",
            "ethtool -k",
            "wg show wg0",
            "cat /proc/net/snmp",
            "cat /proc/net/netstat",
            "ip route show table all",
        ):
            self.assertIn(command, evidence)
        self.assertIn('tcpdump -s 192 -c "${TCP_CAPTURE_PACKETS}"', evidence)
        self.assertEqual(
            2,
            evidence.count('tcpdump -s 192 -c "${TCP_CAPTURE_PACKETS}"'),
        )
        self.assertIn('ra_status != 0 && ra_status != 124', evidence)
        self.assertIn('rb_status != 0 && rb_status != 124', evidence)
        self.assertIn("--require-xor-mixed transport", evidence)
        self.assertIn("--require-mixed transport", evidence)
        self.assertIn('"${TMPDIR}/${label}-ra.pcap"', evidence)
        self.assertIn('"${TMPDIR}/${label}-rb.pcap"', evidence)
        self.assertIn('for interface in ra rb; do', evidence)
        self.assertIn('for flow in "${flows[@]}"; do', evidence)
        self.assertIn('bidir) flows=(forward reverse) ;;', evidence)
        self.assertIn('--src "${A_UNDER}" --dst "${B_UNDER}"', evidence)
        self.assertIn('--src "${B_UNDER}" --dst "${A_UNDER}"', evidence)
        self.assertIn('--sport 31001 --dport 31002', evidence)
        self.assertIn('--sport 31002 --dport 31001', evidence)
        self.assertIn(
            '${label}-${interface}-${flow}-pcap-check.out',
            evidence,
        )
        self.assertIn('"${pcap_path}"', evidence)
        self.assertNotIn(
            '"${TMPDIR}/${label}-ra.pcap" '
            '"${TMPDIR}/${label}-rb.pcap"',
            evidence,
        )
        self.assertIn(
            'run_bounded_in_owned_netns "${NSR}" INT "${capture_timeout}"',
            evidence,
        )
        self.assertNotIn("start_tcp_capture", matrix)
        self.assertNotIn("finish_tcp_capture", matrix)
        self.assertNotIn("check_tcp_capture", matrix)
        self.assertLess(
            matrix.index("capture_tcp_netns_evidence before"),
            matrix.index('for mtu in "${TCP_MTU_VALUES[@]}"; do'),
        )
        self.assertLess(
            matrix.index("capture_tcp_netns_evidence failure"),
            matrix.index('return "${run_status}"'),
        )
        transfer_gate = self.source[
            self.source.index("assert_wg_transfer_increased() {") :
            self.source.index("\ncapture_tcp_netns_evidence() {")
        ]
        self.assertIn("wg show wg0 transfer", matrix)
        self.assertEqual(4, matrix.count("wg show wg0 transfer"))
        self.assertIn("assert_wg_transfer_increased", matrix)
        self.assertIn("tcp summary=correctness status=passed", matrix)
        self.assertIn("received_delta <= 0 or sent_delta <= 0", transfer_gate)
        self.assertIn("tcp evidence=wireguard-transfer", transfer_gate)
        self.assertLess(
            matrix.index("assert_wg_transfer_increased"),
            matrix.index("assert_stat_increased"),
        )

        for target in (
            "test-netns-tcp-native",
            "test-netns-tcp-xor-prefix",
            "test-netns-tcp-xor-full",
        ):
            recipe = self.makefile_source[
                self.makefile_source.index(f"{target}:") :
                self.makefile_source.index(
                    "\n\n",
                    self.makefile_source.index(f"{target}:"),
                )
            ]
            self.assertIn("TCP_CHECKS=enforce", recipe)
            self.assertIn("TCP_INNER_GSO_CHECKS=report", recipe)
            self.assertIn("TCP_OUTER_GSO_CHECKS=observe", recipe)
            self.assertNotIn("TCP_GSO_CHECKS=enforce", recipe)

        outer_target = self.makefile_source[
            self.makefile_source.index("test-netns-tcp-outer-gso-observe:") :
            self.makefile_source.index(
                "\n\n",
                self.makefile_source.index(
                    "test-netns-tcp-outer-gso-observe:"
                ),
            )
        ]
        for setting in (
            "TCP_OUTER_GSO_CHECKS=observe",
            'TCP_MTUS="1420"',
            'TCP_STREAMS="16"',
            'TCP_DIRECTIONS="bidir"',
            "TCP_DURATION=30",
        ):
            self.assertIn(setting, outer_target)
        self.assertNotIn("TCP_GSO_CHECKS=enforce", self.makefile_source)

        for target, family, mtus in (
            ("test-netns-tcp-pmtu-ipv4", "ipv4", "1439 1440"),
            ("test-netns-tcp-pmtu-ipv6", "ipv6", "1419 1420"),
        ):
            recipe = self.makefile_source[
                self.makefile_source.index(f"{target}:") :
                self.makefile_source.index(
                    "\n\n",
                    self.makefile_source.index(f"{target}:"),
                )
            ]
            self.assertIn(f"OUTER_FAMILY={family}", recipe)
            self.assertIn("UNDERLAY_MTU=1500", recipe)
            self.assertIn(f'TCP_MTUS="{mtus}"', recipe)
            self.assertIn("TCP_CHECKS=enforce", recipe)
        self.assertIn(
            "test-netns-tcp-pmtu-positive: "
            "test-netns-tcp-pmtu-ipv4 test-netns-tcp-pmtu-ipv6",
            self.makefile_source,
        )
        self.assertIn(
            "$(MAKE) test-netns-tcp-pmtu-positive",
            self.makefile_source,
        )

    def test_success_teardown_holds_shared_lifecycle_until_contract_is_gone(
        self,
    ) -> None:
        detach_b = self.source.index('teardown_step "detach agent B pin=${PINB}"')
        acquire = self.source.index("start_lifecycle_hold || return 1")
        first_cleanup = self.source.index(
            'remove_owned_file "${PIN_LOCK_A}"'
        )
        lease_unlink = self.source.index(
            'remove_owned_file "${LIFECYCLE_LEASE}"'
        )
        final_contract_dir = self.source.index(
            'rmdir -- "${STATE_DIR_B}"'
        )
        release = self.source.index("release_lifecycle_hold || return 1")
        self.assertLess(detach_b, acquire)
        self.assertLess(acquire, first_cleanup)
        self.assertLess(first_cleanup, lease_unlink)
        self.assertLess(lease_unlink, final_contract_dir)
        self.assertLess(final_contract_dir, release)
        self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", self.holder_source)
        self.assertIn("def recheck_verified_file(", self.holder_source)
        self.assertIn("pathname identity changed", self.holder_source)
        self.assertGreaterEqual(
            self.holder_source.count("recheck_verified_file("),
            5,
        )
        self.assertIn("manifest changed while acquiring lifecycle lease", self.holder_source)

    def test_failed_run_recovery_is_owner_bound_retryable_and_non_networking(
        self,
    ) -> None:
        recovery = self.failed_run_recovery
        for required in (
            'parser.add_argument("mode", choices=("plan", "run"))',
            '"wg-mix-ebpf-failed-run-recovery-v1"',
            'assert_no_live_mount(root, manifest["bpffs_source"])',
            "assert_no_live_netns(manifest)",
            "assert_no_run_network(args.run_id)",
            'client_build.get("source_commit") != args.failed_source_commit',
            "fcntl.LOCK_EX | fcntl.LOCK_NB",
            "publish_receipt(receipt_payload, args.run_id)",
            '"inventory": recorded_inventory',
            "recorded_by_path = preflight_inventory(root, files, recorded_inventory)",
            "recheck_recorded_path(root, path, recorded_by_path)",
            '"xor-password"',
            'f"SMOKE_RECOVERY_COMPLETE run_id={args.run_id}',
        ):
            self.assertIn(required, recovery)
        initial_validation = recovery.index(
            "validate_tree(root, manifest, initial=True)"
        )
        fresh_receipt_publish = recovery.index(
            "publish_receipt(receipt_payload, args.run_id)", initial_validation
        )
        self.assertLess(initial_validation, fresh_receipt_publish)
        for forbidden in (
            "shutil.rmtree",
            "os.system",
            "subprocess",
            "ip link delete",
            "bpftool",
            "rm -rf",
            "find -delete",
        ):
            self.assertNotIn(forbidden, recovery)
        regression = self.failed_run_recovery_test
        for required in (
            "test_receipt_publish_recovers_partial_and_double_name_states",
            "test_recorded_inventory_allows_only_missing_not_new_or_replaced",
            "test_proc_wide_mount_and_netns_scans_reject_live_resources",
            "test_main_plan_is_no_write_and_run_recovers_after_interruption",
            "test_main_plan_accepts_non_xor_secret_set_without_writing",
            "test_main_retry_rejects_new_allowed_name_before_another_write",
            "test_main_lock_contention_preserves_root_and_receipt_for_retry",
            "test_main_revalidates_after_lock_before_first_root_unlink",
            "test_main_holds_lease_through_lease_unlink_and_root_rmdir",
            "test_main_rejects_missing_lease_with_recorded_entries_before_unlink",
            "test_main_rejects_lease_removed_after_preflight_before_unlink",
            "test_main_retries_only_legal_root_only_missing_lease_state",
        ):
            self.assertIn(required, regression)


if __name__ == "__main__":
    unittest.main()
