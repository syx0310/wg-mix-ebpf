#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("realnic_acceptance.py")
SPEC = importlib.util.spec_from_file_location("realnic_acceptance", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FixtureRunner(MODULE.CommandRunner):
    def __init__(self, spec, *, fixed=()):
        self.calls = []
        self.outputs = fixture_outputs(spec, fixed=fixed)

    def capture(self, argv, timeout=20):
        self.calls.append((list(argv), timeout))
        key = tuple(argv)
        if key not in self.outputs:
            raise AssertionError(f"unexpected command {argv!r}")
        return 0, self.outputs[key], b""


class FakeRunningProcess:
    def __init__(self):
        self.terminated = False
        self.waited = False
        self.pid = 10001
        self.pgid = 10001
        self.proven_absent = False
        self.convergence_attempted = False

    def wait(self, timeout):
        del timeout
        self.waited = True
        rc = -15 if self.terminated else 0
        self.proven_absent = True
        return rc, b"60 packets transmitted, 60 received, 0% packet loss\n", b""

    def converge(self, *, term_timeout=5.0, kill_timeout=5.0):
        del term_timeout, kill_timeout
        self.terminated = True
        self.waited = True
        self.convergence_attempted = True
        self.proven_absent = True
        return (
            -15,
            b"60 packets transmitted, 60 received, 0% packet loss\n",
            b"",
            {
                "pid": self.pid,
                "pgid": self.pgid,
                "term": "sent",
                "kill": "not-needed",
                "group_absent": True,
                "wrapper_rc": -15,
            },
        )


class SimulatedRunner(FixtureRunner):
    def __init__(self, spec, *, fail_iperf_call=None):
        super().__init__(spec)
        self.spec = spec
        parsed = MODULE.parse_features(self.outputs[(MODULE.TOOLS["ethtool"], "-k", spec.interface)])
        self.features = {name: entry["enabled"] for name, entry in parsed.items()}
        self.fixed = {name: entry["fixed"] for name, entry in parsed.items()}
        self.mtu = spec.expected_mtu
        self.iperf_calls = 0
        self.fail_iperf_call = fail_iperf_call
        self.ethtool_writes = 0
        self.fail_ethtool_write_call = None
        self.started = []

    def feature_output(self):
        lines = [f"Features for {self.spec.interface}:"]
        for name in MODULE.FEATURE_ORDER:
            fixed = " [fixed]" if self.fixed[name] else ""
            lines.append(f"{name}: {'on' if self.features[name] else 'off'}{fixed}")
        return ("\n".join(lines) + "\n").encode()

    def iperf_output(self, argv):
        streams = int(argv[argv.index("-P") + 1])
        count = streams * (2 if "--bidir" in argv else 1)
        document = {
            "start": {"tcp_mss_default": 1448},
            "end": {
                "streams": [
                    {"sender": {"bytes": 10_000_000, "bits_per_second": 80_000_000, "retransmits": 0}}
                    for _ in range(count)
                ]
            },
        }
        return MODULE.canonical_json(document)

    def capture(self, argv, timeout=20):
        del timeout
        argv = list(argv)
        self.calls.append((argv, 0))
        if argv[:3] == [MODULE.TOOLS["ethtool"], "-K", self.spec.interface]:
            name, value = argv[3:5]
            if self.fixed.get(name):
                return 1, b"", b"fixed\n"
            self.ethtool_writes += 1
            self.features[name] = value == "on"
            if self.fail_ethtool_write_call == self.ethtool_writes:
                raise MODULE.HarnessError("injected post-ethtool failure")
            return 0, b"", b""
        if argv == [MODULE.TOOLS["ethtool"], "-k", self.spec.interface]:
            return 0, self.feature_output(), b""
        if argv[:6] == [MODULE.TOOLS["ip"], "link", "set", "dev", self.spec.interface, "mtu"]:
            self.mtu = int(argv[6])
            return 0, b"", b""
        if argv == [MODULE.TOOLS["cat"], f"/sys/class/net/{self.spec.interface}/mtu"]:
            return 0, f"{self.mtu}\n".encode(), b""
        if argv == [MODULE.TOOLS["ip"], "-d", "-j", "link", "show", "dev", self.spec.interface]:
            return 0, json.dumps(
                [{"ifindex": self.spec.expected_ifindex, "ifname": self.spec.interface, "mtu": self.mtu, "address": self.spec.expected_mac, "flags": ["UP", "LOWER_UP"]}]
            ).encode(), b""
        if argv == [MODULE.TOOLS["ip"], "-s", "-j", "link", "show", "dev", self.spec.interface]:
            return 0, json.dumps(
                [{"ifindex": self.spec.expected_ifindex, "stats64": {"rx": {"bytes": 10, "errors": 0, "dropped": 0}, "tx": {"bytes": 20, "errors": 0, "dropped": 0}}}]
            ).encode(), b""
        if MODULE.TOOLS["iperf3"] in argv:
            self.iperf_calls += 1
            if self.fail_iperf_call == self.iperf_calls:
                return 1, b'{"error":"injected failure"}\n', b""
            return 0, self.iperf_output(argv), b""
        if MODULE.TOOLS["ping"] in argv:
            payload = int(argv[argv.index("-s") + 1]) if "-s" in argv else 56
            if payload > self.mtu - 28:
                return 1, b"1 packets transmitted, 0 received, 100% packet loss\n", b""
            return 0, b"3 packets transmitted, 3 received, 0% packet loss\n", b""
        key = tuple(argv)
        if key not in self.outputs:
            raise AssertionError(f"unexpected command {argv!r}")
        return 0, self.outputs[key], b""

    def start(self, argv):
        self.started.append(list(argv))
        return FakeRunningProcess()


def fixture_spec(**changes):
    values = dict(
        run_id="a1b2c3d4",
        run_root="/run/wg-mix-ebpf-realnic-acceptance-a1b2c3d4",
        source_commit="1234567890abcdef1234567890abcdef12345678",
        interface="ens33",
        expected_ifindex=2,
        expected_mac="00:50:56:aa:bb:cc",
        expected_driver="vmxnet3",
        expected_bus_info="0000:03:00.0",
        expected_device_path="/sys/devices/pci0000:00/0000:00:11.0/0000:03:00.0",
        expected_device_dev=19,
        expected_device_ino=4242,
        expected_mtu=1500,
        expected_hostname="ubuntu-2604-test",
        expected_kernel="7.0.0-28-generic",
        expected_machine_id="9db3fb717cc74974b2a6b243d67f67b9",
        expected_boot_id="12345678-1234-4234-9234-1234567890ab",
        peer_address=MODULE.READ_ONLY_PEER,
        peer_port=5201,
        traffic_seconds=5,
        soak_seconds=60,
        soak_window_seconds=10,
        mtu_low=1492,
    )
    values.update(changes)
    return MODULE.CoreSpec(**values).validate()


def fixture_outputs(spec, *, fixed=()):
    sysfs = f"/sys/class/net/{spec.interface}"
    features = [f"Features for {spec.interface}:"]
    initial = {
        "rx-checksumming": True,
        "tx-checksumming": True,
        "generic-segmentation-offload": True,
        "generic-receive-offload": True,
        "tcp-segmentation-offload": True,
        "tx-udp-segmentation": False,
        "rx-udp-gro-forwarding": False,
    }
    for name in MODULE.FEATURE_ORDER:
        suffix = " [fixed]" if name in fixed else ""
        features.append(f"{name}: {'on' if initial[name] else 'off'}{suffix}")
    def json_bytes(value):
        return json.dumps(value).encode()

    result = {
        (MODULE.TOOLS["hostname"],): f"{spec.expected_hostname}\n".encode(),
        (MODULE.TOOLS["uname"], "-r"): f"{spec.expected_kernel}\n".encode(),
        (MODULE.TOOLS["cat"], "/etc/machine-id"): f"{spec.expected_machine_id}\n".encode(),
        (MODULE.TOOLS["cat"], "/proc/sys/kernel/random/boot_id"): f"{spec.expected_boot_id}\n".encode(),
        (MODULE.TOOLS["readlink"], "/proc/self/ns/net"): b"net:[4026531840]\n",
        (MODULE.TOOLS["cat"], f"{sysfs}/ifindex"): f"{spec.expected_ifindex}\n".encode(),
        (MODULE.TOOLS["cat"], f"{sysfs}/address"): f"{spec.expected_mac}\n".encode(),
        (MODULE.TOOLS["cat"], f"{sysfs}/mtu"): f"{spec.expected_mtu}\n".encode(),
        (MODULE.TOOLS["readlink"], "-e", f"{sysfs}/device"): f"{spec.expected_device_path}\n".encode(),
        (MODULE.TOOLS["stat"], "-Lc", "%d:%i", f"{sysfs}/device"): f"{spec.expected_device_dev}:{spec.expected_device_ino}\n".encode(),
        (MODULE.TOOLS["ethtool"], "-i", spec.interface): (
            f"driver: {spec.expected_driver}\nversion: 1\nfirmware-version: 2\nbus-info: {spec.expected_bus_info}\n"
        ).encode(),
        (MODULE.TOOLS["ethtool"], "-k", spec.interface): ("\n".join(features) + "\n").encode(),
        (MODULE.TOOLS["ip"], "-d", "-j", "link", "show", "dev", spec.interface): json_bytes(
            [{"ifindex": spec.expected_ifindex, "ifname": spec.interface, "mtu": spec.expected_mtu, "address": spec.expected_mac, "flags": ["UP", "LOWER_UP"]}]
        ),
        (MODULE.TOOLS["ip"], "-j", "address", "show", "dev", spec.interface): json_bytes(
            [{"ifindex": spec.expected_ifindex, "ifname": spec.interface, "addr_info": [{"family": "inet", "local": "192.168.10.82", "prefixlen": 24}]}]
        ),
        (MODULE.TOOLS["ip"], "-j", "route", "show", "table", "all", "dev", spec.interface): json_bytes(
            [{"dst": "default", "gateway": "192.168.10.1", "dev": spec.interface}]
        ),
        (MODULE.TOOLS["ip"], "-j", "route", "get", spec.peer_address): json_bytes(
            [{"dst": spec.peer_address, "gateway": "192.168.10.1", "dev": spec.interface, "prefsrc": "192.168.10.82"}]
        ),
        (MODULE.TOOLS["tc"], "-j", "qdisc", "show", "dev", spec.interface): b"[]",
        (MODULE.TOOLS["tc"], "-j", "filter", "show", "dev", spec.interface, "ingress"): b"[]",
        (MODULE.TOOLS["tc"], "-j", "filter", "show", "dev", spec.interface, "egress"): b"[]",
        (MODULE.TOOLS["bpftool"], "-j", "link", "show"): b"[]",
        (MODULE.TOOLS["bpftool"], "-j", "prog", "show"): b"[]",
        (MODULE.TOOLS["bpftool"], "-j", "map", "show"): b"[]",
        (MODULE.TOOLS["wg"], "show", "interfaces"): b"wg0\n",
        (MODULE.TOOLS["ethtool"], "-S", spec.interface): b"NIC statistics:\n     rx_errors: 0\n     tx_errors: 0\n",
    }
    return result


class ProcessGroupTests(unittest.TestCase):
    @staticmethod
    def stubborn_wrapper(metadata_path):
        grandchild = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "signal.signal(signal.SIGINT,signal.SIG_IGN);"
            "signal.signal(signal.SIGHUP,signal.SIG_IGN);"
            "time.sleep(30)"
        )
        return (
            "import json,os,pathlib,signal,subprocess,sys,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "signal.signal(signal.SIGINT,signal.SIG_IGN);"
            "signal.signal(signal.SIGHUP,signal.SIG_IGN);"
            f"child=subprocess.Popen([sys.executable,'-c',{grandchild!r}]);"
            f"pathlib.Path({str(metadata_path)!r}).write_text(json.dumps({{'pgid':os.getpgrp(),'child':child.pid}}));"
            "time.sleep(30)"
        )

    @staticmethod
    def wait_metadata(path):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.exists():
                return json.loads(path.read_text())
            time.sleep(0.02)
        raise AssertionError("owned-process fixture did not publish its process group")

    @staticmethod
    def exact_group_cleanup(pgid):
        if pgid is None:
            return
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_stubborn_wrapper_and_grandchild_are_killed_as_one_owned_group(self):
        grandchild = (
            "import os,signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "print(os.getpid(),flush=True);"
            "time.sleep(30)"
        )
        wrapper = (
            "import os,signal,subprocess,sys,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            f"subprocess.Popen([sys.executable,'-c',{grandchild!r}]);"
            "time.sleep(30)"
        )
        process = MODULE.CommandRunner().start([sys.executable, "-c", wrapper])
        pgid = process.pgid
        try:
            with self.assertRaisesRegex(MODULE.HarnessError, "reviewed timeout"):
                process.wait(0.1)
            rc, stdout, stderr, report = process.converge(term_timeout=0.2, kill_timeout=3.0)
        finally:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.assertLess(rc, 0)
        self.assertEqual(stderr, b"")
        self.assertRegex(stdout.decode(), r"^[1-9][0-9]*\n$")
        self.assertEqual(report["pid"], pgid)
        self.assertEqual(report["pgid"], pgid)
        self.assertEqual(report["term"], "sent")
        self.assertEqual(report["kill"], "sent")
        self.assertTrue(report["group_absent"])
        with self.assertRaises(ProcessLookupError):
            os.killpg(pgid, 0)

    def test_foreground_timeout_converges_wrapper_and_grandchild(self):
        with tempfile.TemporaryDirectory() as temporary:
            metadata_path = pathlib.Path(temporary, "owned.json")
            wrapper = self.stubborn_wrapper(metadata_path)
            pgid = None
            try:
                with self.assertRaisesRegex(MODULE.HarnessError, "reviewed timeout"):
                    MODULE.CommandRunner().capture([sys.executable, "-c", wrapper], timeout=0.1)
                metadata = self.wait_metadata(metadata_path)
                pgid = metadata["pgid"]
                with self.assertRaises(ProcessLookupError):
                    os.killpg(pgid, 0)
            finally:
                self.exact_group_cleanup(pgid)

    def test_parent_sigterm_unwinds_and_converges_owned_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            metadata_path = pathlib.Path(temporary, "owned.json")
            wrapper = self.stubborn_wrapper(metadata_path)
            module_path = str(MODULE_PATH)
            harness = (
                "import importlib.util,sys;"
                f"spec=importlib.util.spec_from_file_location('signal_fixture',{module_path!r});"
                "module=importlib.util.module_from_spec(spec);"
                "sys.modules[spec.name]=module;"
                "spec.loader.exec_module(module);"
                "rc=0;"
                "boundary=module.TerminationBoundary();"
                "boundary.__enter__();"
                "\ntry:\n"
                f" module.CommandRunner().capture([sys.executable,'-c',{wrapper!r}],timeout=30)\n"
                "except module.HarnessError:\n rc=125\n"
                "finally:\n boundary.__exit__(None,None,None)\n"
                "raise SystemExit(rc)"
            )
            parent = subprocess.Popen([sys.executable, "-c", harness], start_new_session=True)
            pgid = None
            try:
                metadata = self.wait_metadata(metadata_path)
                pgid = metadata["pgid"]
                os.kill(parent.pid, signal.SIGTERM)
                self.assertEqual(parent.wait(timeout=8), 125)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(pgid, 0)
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait(timeout=5)
                self.exact_group_cleanup(pgid)

    def test_boundary_covers_term_int_and_hup(self):
        wanted = {signal.SIGTERM, signal.SIGINT}
        if hasattr(signal, "SIGHUP"):
            wanted.add(signal.SIGHUP)
        self.assertEqual(set(MODULE.termination_signals()), wanted)

    def test_term_signal_error_does_not_skip_kill_or_proof(self):
        process = object.__new__(MODULE.RunningProcess)
        process.pid = 101
        process.pgid = 101
        process._process = mock.Mock()
        process._process.poll.return_value = -9
        process._process.returncode = -9
        process._collect_output = mock.Mock(return_value=(b"out", b"err"))
        process._group_exists = mock.Mock(side_effect=[True, False])
        process._wait_group_absent = mock.Mock(side_effect=[False, True])
        process._signal_group = mock.Mock(side_effect=["error:PermissionError:denied", "sent"])
        rc, stdout, stderr, report = process.converge(term_timeout=0.1, kill_timeout=0.1)
        self.assertEqual((rc, stdout, stderr), (-9, b"out", b"err"))
        self.assertEqual(report["term"], "error:PermissionError:denied")
        self.assertEqual(report["kill"], "sent")
        self.assertEqual(
            process._signal_group.call_args_list,
            [mock.call(signal.SIGTERM), mock.call(signal.SIGKILL)],
        )

    def test_failed_kill_and_lingering_group_is_fatal(self):
        process = object.__new__(MODULE.RunningProcess)
        process.pid = 102
        process.pgid = 102
        process._process = mock.Mock()
        process._group_exists = mock.Mock(return_value=True)
        process._wait_group_absent = mock.Mock(side_effect=[False, False])
        process._signal_group = mock.Mock(side_effect=["sent", "error:PermissionError:denied"])
        with self.assertRaisesRegex(MODULE.HarnessError, "survived TERM and KILL"):
            process.converge(term_timeout=0.1, kill_timeout=0.1)

    def test_output_drain_failure_after_group_exit_is_fatal(self):
        process = object.__new__(MODULE.RunningProcess)
        process.pid = 103
        process.pgid = 103
        process._process = mock.Mock()
        process._process.poll.return_value = 0
        process._process.returncode = 0
        process._group_exists = mock.Mock(side_effect=[False, False])
        process._wait_group_absent = mock.Mock(return_value=True)
        process._collect_output = mock.Mock(side_effect=MODULE.HarnessError("drain failed"))
        with self.assertRaisesRegex(MODULE.HarnessError, "drain failed"):
            process.converge(term_timeout=0.1, kill_timeout=0.1)


class PlannerTests(unittest.TestCase):
    def test_plan_is_deterministic_and_read_only(self):
        spec = fixture_spec()
        first_runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, first_runner)
        first = MODULE.canonical_json(MODULE.build_plan(spec, snapshot, commands))
        second_runner = FixtureRunner(spec)
        snapshot2, commands2 = MODULE.collect_snapshot(spec, second_runner)
        second = MODULE.canonical_json(MODULE.build_plan(spec, snapshot2, commands2))
        self.assertEqual(first, second)
        self.assertTrue(first_runner.calls)
        for argv, _ in first_runner.calls:
            self.assertNotIn(argv[:2], [[MODULE.TOOLS["ethtool"], "-K"]])
            self.assertNotEqual(argv[1:3], ["link", "set"])
        plan = json.loads(first)
        self.assertEqual(plan["schema"], MODULE.SCHEMA)
        self.assertEqual(plan["write_set"]["peer"], [])
        self.assertEqual(plan["write_set"]["qdisc"], [])
        self.assertEqual(plan["write_set"]["routes"], [])
        self.assertEqual(plan["write_set"]["bpf"], [])

    def test_plan_covers_p1_without_false_faketcp_passes(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        by_name = {cell["name"]: cell for cell in plan["cells"]}
        for name in (
            "tcp-original",
            "tcp-all-on",
            "tcp-all-off",
            "tcp-tx-path",
            "tcp-rx-path",
            "tcp-mtu-low",
            "tcp-mtu-original",
            "tcp-soak-all-on",
        ):
            self.assertTrue(by_name[name]["runnable"], name)
        for name in (
            "faketcp-realnic-tcp-multiflow",
            "faketcp-checksum-none",
            "faketcp-checksum-partial",
            "faketcp-gso-gro",
            "faketcp-pmtu-boundary",
            "faketcp-bounded-soak",
        ):
            self.assertFalse(by_name[name]["runnable"], name)
            self.assertEqual(by_name[name]["classification"], "not-covered")
            self.assertEqual(by_name[name]["mutation"], [])
        self.assertFalse(plan["safety_contract"]["implemented_capability_bits_changed"])
        self.assertFalse(plan["safety_contract"]["af_packet_no_dst_positive_pmtu"])

    def test_recovery_evidence_is_append_only_journal_not_fixed_output_files(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        filesystem = set(plan["write_set"]["filesystem"])
        for cell in plan["cells"]:
            for step in cell["recovery_restore"]:
                self.assertEqual(step["evidence"], "append-only-journal")
                self.assertNotIn("stdout", step)
                self.assertNotIn("stderr", step)
                self.assertFalse(any(step["label"] in path for path in filesystem))

    def test_fixed_feature_is_unsupported_not_silently_toggled(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec, fixed={"tx-udp-segmentation"})
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        all_on = next(cell for cell in plan["cells"] if cell["name"] == "tcp-all-on")
        self.assertEqual(all_on["classification"], "unsupported")
        self.assertIn("tx-udp-segmentation", all_on["classification_reason"])
        mutated = [step["argv"][-2] for step in all_on["mutation"]]
        self.assertNotIn("tx-udp-segmentation", mutated)

    def test_each_network_mutation_has_explicit_restore(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        baseline = {name: entry["enabled"] for name, entry in snapshot["features"].items()}
        for cell in plan["cells"]:
            if not cell["runnable"]:
                continue
            changed = [step["argv"][-2] for step in cell["mutation"] if step["argv"][0] == MODULE.TOOLS["ethtool"]]
            restored = [step["argv"][-2] for step in cell["restore"] if step["argv"][0] == MODULE.TOOLS["ethtool"]]
            self.assertEqual(restored, list(reversed(changed)), cell["name"])
            for step in cell["restore"]:
                if step["argv"][0] == MODULE.TOOLS["ethtool"]:
                    name, state = step["argv"][-2:]
                    self.assertEqual(state, "on" if baseline[name] else "off")
            mtu_mutations = [step for step in cell["mutation"] if step["argv"][0] == MODULE.TOOLS["ip"]]
            mtu_restores = [step for step in cell["restore"] if step["argv"][0] == MODULE.TOOLS["ip"]]
            self.assertEqual(bool(mtu_mutations), bool(mtu_restores), cell["name"])

    def test_offload_dependency_order_is_reversible(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        all_off = next(cell for cell in plan["cells"] if cell["name"] == "tcp-all-off")
        names = [step["argv"][-2] for step in all_off["mutation"]]
        expected = [name for name in MODULE.FEATURE_DISABLE_ORDER if snapshot["features"][name]["enabled"]]
        self.assertEqual(names, expected)
        self.assertEqual(
            [step["argv"][-2] for step in all_off["restore"]],
            list(reversed(expected)),
        )

    def test_plan_mode_outputs_canonical_json_only(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        stdout = io.BytesIO()
        wrapper = io.TextIOWrapper(stdout, encoding="utf-8")
        with contextlib.redirect_stdout(wrapper):
            rc = MODULE.plan_mode(spec, runner)
            wrapper.flush()
        self.assertEqual(rc, 0)
        payload = stdout.getvalue()
        self.assertTrue(payload.endswith(b"\n"))
        self.assertEqual(payload, MODULE.canonical_json(json.loads(payload)))

    def test_identity_mismatch_fails_closed(self):
        spec = fixture_spec(expected_ifindex=9)
        runner = FixtureRunner(fixture_spec())
        with self.assertRaisesRegex(MODULE.HarnessError, "interface identity mismatch"):
            MODULE.collect_snapshot(spec, runner)

    def test_peer_and_run_root_are_locked(self):
        with self.assertRaises(MODULE.HarnessError):
            fixture_spec(peer_address="192.0.2.1")
        with self.assertRaises(MODULE.HarnessError):
            fixture_spec(run_root="/run/wrong")

    def test_duplicate_or_compound_options_are_rejected(self):
        with self.assertRaises(MODULE.HarnessError):
            MODULE.reject_ambiguous_cli(["plan", "--run-id", "a1b2c3d4", "--run-id", "b1b2c3d4"])
        with self.assertRaises(MODULE.HarnessError):
            MODULE.reject_ambiguous_cli(["plan", "--run-id=a1b2c3d4"])


class HermeticStateMachineTests(unittest.TestCase):
    def prepare(self, temporary, *, fail_iperf_call=None):
        prefix = f"{temporary}/run-"
        with mock.patch.object(MODULE, "RUN_ROOT_PREFIX", prefix):
            spec = fixture_spec(run_root=f"{prefix}a1b2c3d4")
        runner = SimulatedRunner(spec, fail_iperf_call=fail_iperf_call)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan_payload = MODULE.canonical_json(MODULE.build_plan(spec, snapshot, commands))
        plan_path = f"{temporary}/approved-plan.json"
        pathlib.Path(plan_path).write_bytes(plan_payload)
        return prefix, spec, runner, plan_path, MODULE.sha256_bytes(plan_payload)

    def test_wrong_plan_hash_stops_before_run_root_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, _ = self.prepare(temporary)
            wrong = "abcdef0123456789" * 4
            with mock.patch.object(MODULE, "RUN_ROOT_PREFIX", prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaisesRegex(MODULE.HarnessError, "SHA-256 mismatch"):
                    MODULE.run_mode(spec, plan_path, wrong, runner)
            self.assertFalse(pathlib.Path(spec.run_root).exists())

    def test_complete_characterization_restores_every_cell_and_stays_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary)
            with mock.patch.object(MODULE, "RUN_ROOT_PREFIX", prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                rc = MODULE.run_mode(spec, plan_path, digest, runner)
            self.assertEqual(rc, 3)
            self.assertEqual(runner.mtu, spec.expected_mtu)
            baseline = MODULE.parse_features(fixture_outputs(spec)[(MODULE.TOOLS["ethtool"], "-k", spec.interface)])
            self.assertEqual(runner.features, {name: entry["enabled"] for name, entry in baseline.items()})
            outcome = json.loads(pathlib.Path(spec.run_root, "results.json").read_bytes())
            self.assertEqual(outcome["overall"], "incomplete")
            self.assertEqual(outcome["classification_counts"]["passed"], 8)
            self.assertEqual(outcome["classification_counts"]["not-covered"], 6)
            events = [json.loads(line) for line in pathlib.Path(spec.run_root, "journal.jsonl").read_bytes().splitlines()]
            self.assertEqual(events[-1]["event"], "COMPLETE")
            self.assertEqual(
                sum(event["event"] == "CELL_MUTATION_INTENT" for event in events),
                8,
            )
            self.assertEqual(
                sum(event["event"] == "RESTORE_INTENT" for event in events),
                8,
            )

    def test_failure_retains_mutation_until_separately_invoked_restore(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with mock.patch.object(MODULE, "RUN_ROOT_PREFIX", prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaisesRegex(MODULE.HarnessError, "command tcp-all-on"):
                    MODULE.run_mode(spec, plan_path, digest, runner)
                self.assertTrue(runner.features["tx-udp-segmentation"])
                self.assertTrue(runner.features["rx-udp-gro-forwarding"])
                rc = MODULE.restore_mode(spec, plan_path, digest, runner)
            self.assertEqual(rc, 0)
            self.assertFalse(runner.features["tx-udp-segmentation"])
            self.assertFalse(runner.features["rx-udp-gro-forwarding"])
            self.assertEqual(runner.mtu, spec.expected_mtu)
            marker = json.loads(pathlib.Path(spec.run_root, "explicit-restored.json").read_bytes())
            self.assertEqual(marker["state"], "restored")
            events = [json.loads(line) for line in pathlib.Path(spec.run_root, "journal.jsonl").read_bytes().splitlines()]
            failed_index = next(index for index, event in enumerate(events) if event["event"] == "FAILED")
            intent_index = next(index for index, event in enumerate(events) if event["event"] == "EXPLICIT_RESTORE_INTENT")
            self.assertGreater(intent_index, failed_index)
            self.assertEqual(events[-1]["event"], "EXPLICIT_RESTORE_COMPLETE")

    def test_explicit_restore_replays_idempotently_after_nth_step_cut(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with mock.patch.object(MODULE, "RUN_ROOT_PREFIX", prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaises(MODULE.HarnessError):
                    MODULE.run_mode(spec, plan_path, digest, runner)
                runner.fail_ethtool_write_call = runner.ethtool_writes + 1
                with self.assertRaisesRegex(MODULE.HarnessError, "post-ethtool failure"):
                    MODULE.restore_mode(spec, plan_path, digest, runner)
                self.assertFalse(runner.features["rx-udp-gro-forwarding"])
                self.assertTrue(runner.features["tx-udp-segmentation"])
                runner.fail_ethtool_write_call = None
                self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)
                self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)
            self.assertFalse(runner.features["rx-udp-gro-forwarding"])
            self.assertFalse(runner.features["tx-udp-segmentation"])
            events = [json.loads(line) for line in pathlib.Path(spec.run_root, "journal.jsonl").read_bytes().splitlines()]
            intents = [event for event in events if event["event"] == "EXPLICIT_RESTORE_INTENT"]
            self.assertEqual([event["attempt"] for event in intents], [1, 2])
            starts = [event for event in events if event["event"] == "RECOVERY_COMMAND_START"]
            self.assertEqual([event["attempt"] for event in starts], [1, 2, 2])
            self.assertEqual(events[-1]["event"], "EXPLICIT_RESTORE_COMPLETE")

    def test_mutated_interface_restores_after_unterminated_journal_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with mock.patch.object(MODULE, "RUN_ROOT_PREFIX", prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaises(MODULE.HarnessError):
                    MODULE.run_mode(spec, plan_path, digest, runner)
                self.assertTrue(runner.features["tx-udp-segmentation"])
                journal_path = pathlib.Path(spec.run_root, "journal.jsonl")
                with journal_path.open("ab") as stream:
                    stream.write(b'{"event":"crash-window"')
                self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)
            self.assertFalse(runner.features["tx-udp-segmentation"])
            events = [json.loads(line) for line in journal_path.read_bytes().splitlines()]
            truncated = next(index for index, event in enumerate(events) if event["event"] == "JOURNAL_TAIL_TRUNCATED")
            restore_intent = next(index for index, event in enumerate(events) if event["event"] == "EXPLICIT_RESTORE_INTENT")
            self.assertLess(truncated, restore_intent)


class JournalDurabilityTests(unittest.TestCase):
    run_id = "a1b2c3d4"
    plan_sha256 = "1234567890abcdef" * 4

    def open_journal(self, path, *, create):
        return MODULE.Journal(str(path), self.run_id, self.plan_sha256, create=create)

    def test_append_writes_all_short_chunks_before_fsync(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "journal.jsonl")
            journal = self.open_journal(path, create=True)
            real_write = MODULE.os.write
            write_calls = []

            def short_write(descriptor, payload):
                write_calls.append(len(payload))
                return real_write(descriptor, payload[:7])

            with mock.patch.object(MODULE.os, "write", side_effect=short_write):
                journal.append("BASELINE_CAPTURED", baseline_sha256="abcdef0123456789" * 4)
            journal.close()
            self.assertGreater(len(write_calls), 1)
            reopened = self.open_journal(path, create=False)
            try:
                self.assertEqual([event["event"] for event in reopened.events], ["BASELINE_CAPTURED"])
            finally:
                reopened.close()

    def test_partial_append_is_poisoned_then_recovered_as_tail_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "journal.jsonl")
            journal = self.open_journal(path, create=True)
            journal.append("BASELINE_CAPTURED", baseline_sha256="abcdef0123456789" * 4)
            real_write = MODULE.os.write
            calls = 0

            def partial_then_stop(descriptor, payload):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_write(descriptor, payload[:11])
                return 0

            with mock.patch.object(MODULE.os, "write", side_effect=partial_then_stop):
                with self.assertRaisesRegex(MODULE.HarnessError, "no progress"):
                    journal.append("CELL_MUTATION_INTENT", cell="tcp-all-on")
                with self.assertRaisesRegex(MODULE.HarnessError, "poisoned"):
                    journal.append("FAILED", cell="tcp-all-on", reason="must-not-append-after-partial")
            journal.close()
            reopened = self.open_journal(path, create=False)
            try:
                self.assertEqual(
                    [event["event"] for event in reopened.events],
                    ["BASELINE_CAPTURED", "JOURNAL_TAIL_TRUNCATED"],
                )
            finally:
                reopened.close()

    def test_only_unterminated_tail_is_truncated_and_audited(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "journal.jsonl")
            journal = self.open_journal(path, create=True)
            journal.append("BASELINE_CAPTURED", baseline_sha256="abcdef0123456789" * 4)
            journal.close()
            fragment = b'{"event":"CELL_MUTATION_INTENT"'
            with path.open("ab") as stream:
                stream.write(fragment)
            reopened = self.open_journal(path, create=False)
            try:
                self.assertEqual(
                    [event["event"] for event in reopened.events],
                    ["BASELINE_CAPTURED", "JOURNAL_TAIL_TRUNCATED"],
                )
                audit = reopened.events[-1]
                self.assertEqual(audit["removed_bytes"], len(fragment))
                self.assertEqual(audit["removed_sha256"], MODULE.sha256_bytes(fragment))
            finally:
                reopened.close()
            self.assertTrue(path.read_bytes().endswith(b"\n"))
            self.assertNotIn(fragment, path.read_bytes())

    def test_complete_or_middle_corruption_is_never_truncated(self):
        for corruption in ("complete-tail", "middle"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as temporary:
                path = pathlib.Path(temporary, "journal.jsonl")
                journal = self.open_journal(path, create=True)
                journal.append("BASELINE_CAPTURED", baseline_sha256="abcdef0123456789" * 4)
                journal.append("FAILED", cell=None, reason="fixture")
                journal.close()
                lines = path.read_bytes().splitlines(keepends=True)
                if corruption == "complete-tail":
                    damaged = b"".join(lines) + b"not-json\n"
                else:
                    damaged = lines[0] + b"not-json\n" + lines[1]
                path.write_bytes(damaged)
                with self.assertRaisesRegex(MODULE.HarnessError, "invalid line"):
                    self.open_journal(path, create=False)
                self.assertEqual(path.read_bytes(), damaged)

    def test_complete_canonical_identity_or_hash_corruption_is_rejected(self):
        corruptions = {
            "noncanonical": b'{"event": "FAILED"}\n',
            "wrong-identity": MODULE.canonical_json(
                {
                    "schema": MODULE.JOURNAL_SCHEMA,
                    "run_id": "ffffffff",
                    "plan_sha256": self.plan_sha256,
                    "sequence": 2,
                    "monotonic_ns": 1,
                    "utc": "2026-08-09T00:00:00Z",
                    "event": "FAILED",
                }
            ),
            "wrong-hash": MODULE.canonical_json(
                {
                    "schema": MODULE.JOURNAL_SCHEMA,
                    "run_id": self.run_id,
                    "plan_sha256": "abcdef0123456789" * 4,
                    "sequence": 2,
                    "monotonic_ns": 1,
                    "utc": "2026-08-09T00:00:00Z",
                    "event": "FAILED",
                }
            ),
        }
        for name, bad_line in corruptions.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path = pathlib.Path(temporary, "journal.jsonl")
                journal = self.open_journal(path, create=True)
                journal.append("BASELINE_CAPTURED", baseline_sha256="abcdef0123456789" * 4)
                journal.close()
                original = path.read_bytes()
                path.write_bytes(original + bad_line)
                with self.assertRaises(MODULE.HarnessError):
                    self.open_journal(path, create=False)
                self.assertEqual(path.read_bytes(), original + bad_line)


if __name__ == "__main__":
    unittest.main()
