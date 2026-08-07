#!/usr/bin/env python3
import hashlib
import pathlib
import subprocess
import unittest


SCRIPT_PATH = pathlib.Path(__file__).with_name("smoke-netns-wg.sh")
MAKEFILE_PATH = SCRIPT_PATH.parent.parent / "Makefile"
GO_MOD_PATH = SCRIPT_PATH.parent.parent / "go.mod"
GO_SUM_PATH = SCRIPT_PATH.parent.parent / "go.sum"
HOLDER_PATH = pathlib.Path(__file__).with_name(
    "hold-isolated-lifecycle-lease.py"
)
ANCHOR_PACKAGE = SCRIPT_PATH.parent.parent / "internal" / "netnsanchor"


class SmokeNetNSWGStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT_PATH.read_text(encoding="utf-8")
        cls.lines = cls.source.splitlines()
        cls.makefile_source = MAKEFILE_PATH.read_text(encoding="utf-8")
        cls.go_mod_source = GO_MOD_PATH.read_text(encoding="utf-8")
        cls.go_sum_source = GO_SUM_PATH.read_text(encoding="utf-8")
        cls.holder_source = HOLDER_PATH.read_text(encoding="utf-8")
        cls.anchor_linux_source = (ANCHOR_PACKAGE / "run_linux.go").read_text(
            encoding="utf-8"
        )
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
        self.assertIn('BPFFS_SOURCE="bpf"', self.source)
        self.assertNotIn('BPFFS_SOURCE="wg-mix-ebpf-', self.source)
        self.assertIn("$5 != target", self.source)
        self.assertIn("other_bpf_count++", self.source)
        self.assertNotIn('-v production="/sys/fs/bpf"', self.source)
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
        self.assertLess(seal, first_reload)

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


if __name__ == "__main__":
    unittest.main()
