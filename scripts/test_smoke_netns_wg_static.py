#!/usr/bin/env python3
import hashlib
import pathlib
import unittest


SCRIPT_PATH = pathlib.Path(__file__).with_name("smoke-netns-wg.sh")
HOLDER_PATH = pathlib.Path(__file__).with_name(
    "hold-isolated-lifecycle-lease.py"
)


class SmokeNetNSWGStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT_PATH.read_text(encoding="utf-8")
        cls.lines = cls.source.splitlines()
        cls.holder_source = HOLDER_PATH.read_text(encoding="utf-8")

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
            self.source.index("\nmove_link_to_owned_netns() {")
        ]
        self.assertLess(
            bounded.index("validate_named_netns_identity"),
            bounded.index('ip netns exec "${ns}"'),
        )
        self.assertLess(
            bounded.index("sleep 0.2"),
            bounded.index("validate_named_netns_identity"),
        )
        self.assertIn("env -u XOR_PASSWORD", bounded)
        self.assertNotIn("sh -c", bounded)

        direct_execs = [
            line.strip()
            for line in self.lines
            if 'ip netns exec "${' in line
            and not line.strip().startswith("print_command ")
        ]
        self.assertEqual(2, len(direct_execs))
        self.assertTrue(
            all('"${ns}"' in line for line in direct_execs),
            direct_execs,
        )

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

    def test_netns_identity_is_revalidated_before_use_and_delete(self) -> None:
        validator = self.source[
            self.source.index("validate_netns_identity() {") :
            self.source.index("\nvalidate_all_netns_identities() {")
        ]
        self.assertIn("netns_exists", validator)
        self.assertIn("stat -Lc '%d %i'", validator)
        self.assertIn('[[ ! -e "/run/netns/${ns}"', validator)
        self.assertIn('-L "/run/netns/${ns}"', validator)
        self.assertIn(
            '"${observed_device}" != "${expected_device}"',
            validator,
        )
        self.assertIn(
            '"${observed_inode}" != "${expected_inode}"',
            validator,
        )

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

        delete = self.source[
            self.source.index("delete_owned_netns() {") :
            self.source.index("\nvalidate_released_pin_lock() {")
        ]
        self.assertLess(
            delete.index("validate_netns_identity"),
            delete.index('ip netns delete "${ns}"'),
        )

        teardown = self.source[
            self.source.index("explicit_teardown() {") :
            self.source.index("\nmake_agent_config() {")
        ]
        self.assertIn("validate_all_netns_identities || return 1", teardown)
        self.assertEqual(teardown.count("delete_owned_netns "), 3)
        self.assertNotIn('teardown_step "delete netns', teardown)

    def test_tcp_matrix_covers_flow_count_direction_and_error_gates(self) -> None:
        self.assertIn('TCP_STREAMS="${TCP_STREAMS:-1 4 16}"', self.source)
        self.assertIn(
            'TCP_DIRECTIONS="${TCP_DIRECTIONS:-forward reverse bidir}"',
            self.source,
        )
        self.assertIn('TCP_MTUS="${TCP_MTUS:-1419 1420 1421 1422}"', self.source)

        run = self.source[
            self.source.index("exercise_tcp_run() {") :
            self.source.index("\nexercise_tcp_matrix() {")
        ]
        self.assertIn("forward) ;;", run)
        self.assertIn("reverse) client_direction_args=(-R) ;;", run)
        self.assertIn("bidir) client_direction_args=(--bidir) ;;", run)
        self.assertIn('"${IPERF_CHECKER_HELPER}"', run)
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
            "egress_gso_managed_seen",
            "egress_gso_rewrite_ok",
            "ingress_gso_listener_hit",
            "ingress_gso_rewrite_ok",
        ):
            self.assertIn(stat, matrix)

        evidence = self.source[
            self.source.index("capture_tcp_link_evidence() {") :
            self.source.index("\ntcp_server_listening() {")
        ]
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
        self.assertIn('"${TMPDIR}/tcp-ra.pcap"', evidence)
        self.assertIn('"${TMPDIR}/tcp-rb.pcap"', evidence)
        self.assertLess(
            matrix.index("capture_tcp_netns_evidence before"),
            matrix.index("start_tcp_capture"),
        )
        self.assertLess(
            matrix.index("start_tcp_capture"),
            matrix.index('for mtu in "${TCP_MTU_VALUES[@]}"; do'),
        )
        self.assertLess(
            matrix.index("capture_tcp_netns_evidence failure"),
            matrix.index('return "${run_status}"'),
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
