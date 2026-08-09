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
import types
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("realnic_acceptance.py")
SPEC = importlib.util.spec_from_file_location("realnic_acceptance", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CHECKER_MODULE_PATH = pathlib.Path(MODULE.iperf_checker_path())
CHECKER_SPEC = importlib.util.spec_from_file_location("realhost_iperf_checker", CHECKER_MODULE_PATH)
assert CHECKER_SPEC and CHECKER_SPEC.loader
CHECKER_MODULE = importlib.util.module_from_spec(CHECKER_SPEC)
sys.modules[CHECKER_SPEC.name] = CHECKER_MODULE
CHECKER_SPEC.loader.exec_module(CHECKER_MODULE)


@contextlib.contextmanager
def runtime_contract(prefix):
    parent = pathlib.Path(prefix).parent
    with (
        mock.patch.object(MODULE, "RUN_ROOT_PREFIX", prefix),
        mock.patch.object(MODULE, "PHYSICAL_INTERFACE_LOCK_UID", os.getuid()),
        mock.patch.object(MODULE, "PHYSICAL_INTERFACE_LOCK_GID", os.getgid()),
        mock.patch.object(
            MODULE,
            "LEGACY_RETIREMENT_RESERVATION",
            str(parent / "legacy-retirement-reservation"),
        ),
    ):
        yield


def create_runtime_authorities(prefix):
    with runtime_contract(prefix):
        paths = (
            pathlib.Path(MODULE.physical_interface_lock_path()),
            pathlib.Path(MODULE.LEGACY_RETIREMENT_RESERVATION),
        )
        for path in paths:
            path.touch(mode=0o600, exist_ok=False)
            path.chmod(0o600)
        return paths


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
    def __init__(self, stdout=b"60 packets transmitted, 60 received, 0% packet loss\n"):
        self.terminated = False
        self.waited = False
        self.pid = 10001
        self.pgid = 10001
        self.proven_absent = False
        self.convergence_attempted = False
        self.stdout = stdout

    def wait(self, timeout):
        del timeout
        self.waited = True
        rc = -15 if self.terminated else 0
        self.proven_absent = True
        return rc, self.stdout, b""

    def converge(self, *, term_timeout=5.0, kill_timeout=5.0):
        del term_timeout, kill_timeout
        self.terminated = True
        self.waited = True
        self.convergence_attempted = True
        self.proven_absent = True
        return (
            -15,
            self.stdout,
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
        self.feature_parents = {name: entry["parent"] for name, entry in parsed.items()}
        self.feature_names = tuple(parsed)
        self.mtu = spec.expected_mtu
        self.iperf_calls = 0
        self.fail_iperf_call = fail_iperf_call
        self.ethtool_writes = 0
        self.network_writes = 0
        self.fail_ethtool_write_call = None
        self.ifindex_reads = 0
        self.fail_ifindex_read = None
        self.read_failures = set()
        self.clock = 0.0
        self.counter_command_seconds = 0.0
        self.oracle_command_seconds = 0.0
        self.started = []

    def feature_output(self):
        lines = [f"Features for {self.spec.interface}:"]
        for name in self.feature_names:
            fixed = " [fixed]" if self.fixed[name] else ""
            indentation = "    " if self.feature_parents[name] is not None else ""
            lines.append(f"{indentation}{name}: {'on' if self.features[name] else 'off'}{fixed}")
        return ("\n".join(lines) + "\n").encode()

    def iperf_output(self, argv):
        streams = int(argv[argv.index("-P") + 1])
        duration = int(argv[argv.index("-t") + 1])
        direction = "bidir" if "--bidir" in argv else "reverse" if "-R" in argv else "forward"
        markers = [True] * streams
        if direction == "reverse":
            markers = [False] * streams
        elif direction == "bidir":
            markers += [False] * streams
        rows = [
            {
                "sender": {
                    "sender": marker,
                    "bytes": 10_000_000,
                    "bits_per_second": 80_000_000,
                    "retransmits": 0,
                },
                "receiver": {
                    "sender": marker,
                    "bytes": 10_000_000,
                    "bits_per_second": 80_000_000,
                },
            }
            for marker in markers
        ]
        summary = {"bytes": 10_000_000 * streams, "seconds": float(duration)}
        sent_summary = {
            "bytes": 10_000_000 * streams,
            "seconds": float(duration),
            "retransmits": 0,
        }
        document = {
            "start": {
                "tcp_mss_default": 1448,
                "test_start": {
                    "num_streams": streams,
                    "reverse": 1 if direction == "reverse" else 0,
                    "bidir": 1 if direction == "bidir" else 0,
                    "duration": duration,
                },
            },
            "end": {
                "streams": rows,
                "sum_sent": sent_summary,
                "sum_received": summary,
            },
        }
        if direction == "bidir":
            document["end"]["sum_sent_bidir_reverse"] = sent_summary
            document["end"]["sum_received_bidir_reverse"] = summary
        return MODULE.canonical_json(document)

    def capture(self, argv, timeout=20):
        del timeout
        argv = list(argv)
        self.calls.append((argv, 0))
        if any(argv == command for _, command in MODULE.monitor_command_table(self.spec)):
            self.clock += self.counter_command_seconds
        if argv[:3] == [MODULE.TOOLS["ethtool"], "-K", self.spec.interface]:
            name, value = argv[3:5]
            if self.fixed.get(name):
                return 1, b"", b"fixed\n"
            self.ethtool_writes += 1
            self.network_writes += 1
            self.features[name] = value == "on"
            if name == "tx-checksumming":
                self.features["tx-checksum-ipv4"] = value == "on"
            if self.fail_ethtool_write_call == self.ethtool_writes:
                raise MODULE.HarnessError("injected post-ethtool failure")
            return 0, b"", b""
        if argv == [MODULE.TOOLS["ethtool"], "-k", self.spec.interface]:
            return 0, self.feature_output(), b""
        if argv[:6] == [MODULE.TOOLS["ip"], "link", "set", "dev", self.spec.interface, "mtu"]:
            self.mtu = int(argv[6])
            self.network_writes += 1
            return 0, b"", b""
        if argv == [MODULE.TOOLS["cat"], f"/sys/class/net/{self.spec.interface}/ifindex"]:
            self.ifindex_reads += 1
            value = 99 if self.ifindex_reads == self.fail_ifindex_read else self.spec.expected_ifindex
            return 0, f"{value}\n".encode(), b""
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
        if argv[:3] == [MODULE.TOOLS["python3"], "-I", MODULE.iperf_checker_path()]:
            self.clock += self.oracle_command_seconds
            try:
                if argv[3] == "one":
                    options = dict(zip(argv[5::2], argv[6::2]))
                    args = types.SimpleNamespace(
                        path=pathlib.Path(argv[4]),
                        direction=options["--direction"],
                        streams=int(options["--streams"]),
                        minimum_fairness=float(options["--minimum-fairness"]),
                        maximum_retransmit_rate=float(options["--maximum-retransmit-rate"]),
                        expected_seconds=float(options["--expected-seconds"]),
                        maximum_duration_deviation=float(
                            options["--maximum-duration-deviation"]
                        ),
                        minimum_delivery_ratio=float(options["--minimum-delivery-ratio"]),
                        minimum_stream_bytes=int(options["--minimum-stream-bytes"]),
                    )
                    output = CHECKER_MODULE.check_one(args)
                else:
                    options_start = argv.index("--expected-windows")
                    options = dict(zip(argv[options_start::2], argv[options_start + 1 :: 2]))
                    args = types.SimpleNamespace(
                        paths=[pathlib.Path(value) for value in argv[4:options_start]],
                        expected_windows=int(options["--expected-windows"]),
                        streams=int(options["--streams"]),
                        minimum_fairness=float(options["--minimum-fairness"]),
                        maximum_window_retransmit_rate=float(
                            options["--maximum-window-retransmit-rate"]
                        ),
                        maximum_overall_retransmit_rate=float(
                            options["--maximum-overall-retransmit-rate"]
                        ),
                        minimum_throughput_ratio=float(options["--minimum-throughput-ratio"]),
                        expected_seconds=float(options["--expected-seconds"]),
                        maximum_duration_deviation=float(
                            options["--maximum-duration-deviation"]
                        ),
                        minimum_delivery_ratio=float(options["--minimum-delivery-ratio"]),
                        minimum_stream_bytes=int(options["--minimum-stream-bytes"]),
                    )
                    output = CHECKER_MODULE.check_soak(args)
            except CHECKER_MODULE.CheckError as exc:
                return 1, b"", f"FAIL: {exc}\n".encode()
            return 0, MODULE.canonical_json(output), b""
        if MODULE.TOOLS["ping"] in argv:
            payload = int(argv[argv.index("-s") + 1]) if "-s" in argv else 56
            if payload > self.mtu - 28:
                return (
                    1,
                    (
                        f"PING {self.spec.peer_address} ({self.spec.peer_address}) {payload} data bytes\n"
                        + 3 * f"ping: local error: message too long, mtu={self.mtu}\n"
                        + "3 packets transmitted, 0 received, +3 errors, 100% packet loss\n"
                    ).encode(),
                    b"",
                )
            return 0, b"3 packets transmitted, 3 received, 0% packet loss\n", b""
        key = tuple(argv)
        if key in self.read_failures:
            return 1, b"", b"injected unrelated read failure\n"
        if key not in self.outputs:
            raise AssertionError(f"unexpected command {argv!r}")
        return 0, self.outputs[key], b""

    def start(self, argv):
        self.started.append(list(argv))
        if MODULE.TOOLS["iperf3"] in argv:
            return FakeRunningProcess(stdout=self.iperf_output(argv))
        return FakeRunningProcess()

    def wait_until(self, deadline):
        self.clock = max(self.clock, deadline)

    def monotonic(self):
        return self.clock


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
        profile="smoke",
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
        if name == "tx-checksumming":
            features.append("    tx-checksum-ipv4: off")
    features.append("foreign-offload: on")
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
        (MODULE.TOOLS["ip"], "-s", "-j", "link", "show", "dev", spec.interface): json_bytes(
            [{"ifindex": spec.expected_ifindex, "stats64": {"rx": {"bytes": 10, "errors": 0, "dropped": 0}, "tx": {"bytes": 20, "errors": 0, "dropped": 0}}}]
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

    def test_signal_during_error_convergence_is_deferred_until_group_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            metadata_path = pathlib.Path(temporary, "owned.json")
            converging_path = pathlib.Path(temporary, "converging.json")
            wrapper = self.stubborn_wrapper(metadata_path)
            module_path = str(MODULE_PATH)
            harness = (
                "import importlib.util,json,pathlib,sys\n"
                f"spec=importlib.util.spec_from_file_location('converge_fixture',{module_path!r})\n"
                "module=importlib.util.module_from_spec(spec)\n"
                "sys.modules[spec.name]=module\n"
                "spec.loader.exec_module(module)\n"
                "original_wait=module.RunningProcess._wait_group_absent\n"
                "def marked_wait(self,timeout):\n"
                f" pathlib.Path({str(converging_path)!r}).write_text(json.dumps({{'pgid':self.pgid}}))\n"
                " return original_wait(self,timeout)\n"
                "module.RunningProcess._wait_group_absent=marked_wait\n"
                "rc=0\n"
                "try:\n"
                " with module.TerminationBoundary():\n"
                f"  with module.OwnedProcessScope(module.CommandRunner(),[sys.executable,'-c',{wrapper!r}]):\n"
                "   raise module.HarnessError('ordinary body failure')\n"
                "except module.HarnessAbort:\n"
                " rc=125\n"
                "except module.HarnessError:\n"
                " rc=126\n"
                "raise SystemExit(rc)\n"
            )
            parent = subprocess.Popen([sys.executable, "-c", harness], start_new_session=True)
            pgid = None
            try:
                metadata = self.wait_metadata(metadata_path)
                pgid = metadata["pgid"]
                self.wait_metadata(converging_path)
                os.kill(parent.pid, signal.SIGTERM)
                self.assertEqual(parent.wait(timeout=12), 125)
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


class StrictIperfOracleTests(unittest.TestCase):
    def test_bidir_requires_2p_directions_receivers_and_summaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = f"{temporary}/run-"
            with runtime_contract(prefix):
                spec = fixture_spec(run_root=f"{prefix}a1b2c3d4")
                pathlib.Path(spec.run_root, "logs").mkdir(parents=True)
                step = next(
                    item
                    for item in MODULE.iperf_steps(spec, "strict")
                    if item["streams"] == 4 and item["direction"] == "bidir"
                )
            runner = SimulatedRunner(spec)
            valid = json.loads(runner.iperf_output(step["argv"]))
            cases = {}

            incomplete = json.loads(json.dumps(valid))
            incomplete["end"]["streams"] = incomplete["end"]["streams"][:4]
            cases["count"] = (incomplete, "count=4, want 8")

            one_direction = json.loads(json.dumps(valid))
            for stream in one_direction["end"]["streams"]:
                stream["sender"]["sender"] = True
                stream["receiver"]["sender"] = True
            cases["direction"] = (one_direction, "stream count is incomplete")

            no_receive = json.loads(json.dumps(valid))
            no_receive["end"]["streams"][0]["receiver"]["bytes"] = 0
            no_receive["end"]["sum_received"]["bytes"] -= 10_000_000
            cases["receiver"] = (no_receive, "stream bytes are below minimum")

            bad_summary = json.loads(json.dumps(valid))
            bad_summary["end"]["sum_received"]["bytes"] += 1
            cases["summary"] = (bad_summary, "summary mismatch")

            bad_start_duration = json.loads(json.dumps(valid))
            bad_start_duration["start"]["test_start"]["duration"] = 1
            cases["start-duration"] = (bad_start_duration, "configured duration")

            bidir_duration_mismatch = json.loads(json.dumps(valid))
            bidir_duration_mismatch["end"]["sum_sent_bidir_reverse"]["seconds"] = 1.0
            cases["bidir-duration"] = (bidir_duration_mismatch, "measured duration")

            incomplete_delivery = json.loads(json.dumps(valid))
            for stream in incomplete_delivery["end"]["streams"]:
                stream["receiver"]["bytes"] = 2_000_000
            incomplete_delivery["end"]["sum_received"]["bytes"] = 8_000_000
            incomplete_delivery["end"]["sum_received_bidir_reverse"]["bytes"] = 8_000_000
            cases["delivery"] = (incomplete_delivery, "delivery ratio")

            inflated_receive = json.loads(json.dumps(valid))
            inflated_receive["end"]["streams"][0]["receiver"]["bytes"] += 1
            inflated_receive["end"]["sum_received"]["bytes"] += 1
            cases["inflated-receive"] = (inflated_receive, "received bytes exceed sent bytes")

            for name, (document, reason) in cases.items():
                with self.subTest(name=name):
                    pathlib.Path(step["stdout"]).write_bytes(MODULE.canonical_json(document))
                    rc, _, stderr = MODULE.CommandRunner().capture(step["oracle"]["argv"], timeout=30)
                    self.assertEqual(rc, 1)
                    self.assertIn(reason, stderr.decode())

            pathlib.Path(step["stdout"]).write_bytes(MODULE.canonical_json(valid))
            rc, stdout, stderr = MODULE.CommandRunner().capture(step["oracle"]["argv"], timeout=30)
            self.assertEqual((rc, stderr), (0, b""))
            groups = MODULE.iperf_oracle_metrics(
                stdout,
                4,
                "bidir",
                step["oracle"]["session_contract"],
            )
            self.assertEqual({group["direction"] for group in groups}, {"forward", "reverse"})
            self.assertTrue(all(group["streams"] == 4 for group in groups))

    def test_one_tiny_stream_cannot_hide_inside_a_sixteen_stream_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = f"{temporary}/run-"
            with runtime_contract(prefix):
                spec = fixture_spec(run_root=f"{prefix}a1b2c3d4")
                pathlib.Path(spec.run_root, "logs").mkdir(parents=True)
                step = next(
                    item
                    for item in MODULE.iperf_steps(spec, "strict")
                    if item["streams"] == 16 and item["direction"] == "forward"
                )
            runner = SimulatedRunner(spec)
            document = json.loads(runner.iperf_output(step["argv"]))
            document["end"]["streams"][0]["sender"]["bytes"] = 1
            document["end"]["streams"][0]["receiver"]["bytes"] = 1
            document["end"]["sum_sent"]["bytes"] -= 9_999_999
            document["end"]["sum_received"]["bytes"] -= 9_999_999
            pathlib.Path(step["stdout"]).write_bytes(MODULE.canonical_json(document))
            rc, _, stderr = MODULE.CommandRunner().capture(step["oracle"]["argv"], timeout=30)
            self.assertEqual(rc, 1)
            self.assertIn("stream bytes are below minimum", stderr.decode())

    def test_formal_30_and_300_second_sessions_reject_one_second_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = f"{temporary}/run-"
            with runtime_contract(prefix):
                spec = fixture_spec(
                    run_root=f"{prefix}a1b2c3d4",
                    profile="acceptance",
                    traffic_seconds=30,
                    soak_seconds=3600,
                    soak_window_seconds=300,
                )
                pathlib.Path(spec.run_root, "logs").mkdir(parents=True)
                runner = SimulatedRunner(spec)
                snapshot, _ = MODULE.collect_snapshot(spec, runner)
                ordinary = MODULE.iperf_steps(spec, "formal")[0]
                soak = MODULE.soak_cell(spec, snapshot)["traffic"][1]

            for expected, step in ((30, ordinary), (300, soak)):
                with self.subTest(expected=expected):
                    self.assertEqual(
                        step["oracle"]["session_contract"],
                        MODULE.iperf_session_contract(expected),
                    )
                    document = json.loads(runner.iperf_output(step["argv"]))
                    document["end"]["sum_sent"]["seconds"] = 1.0
                    document["end"]["sum_received"]["seconds"] = 1.0
                    if step["direction"] == "bidir":
                        document["end"]["sum_sent_bidir_reverse"]["seconds"] = 1.0
                        document["end"]["sum_received_bidir_reverse"]["seconds"] = 1.0
                    pathlib.Path(step["stdout"]).write_bytes(MODULE.canonical_json(document))
                    rc, _, stderr = MODULE.CommandRunner().capture(
                        step["oracle"]["argv"], timeout=30
                    )
                    self.assertEqual(rc, 1)
                    self.assertIn("measured duration", stderr.decode())


class MTUOutcomeOracleTests(unittest.TestCase):
    def setUp(self):
        self.spec = fixture_spec()
        self.negative = MODULE.mtu_outcome_contract(self.spec, 1492, False)
        self.positive = MODULE.mtu_outcome_contract(self.spec, 1492, True)

    def test_exact_local_emsgsize_is_structured_boundary_evidence(self):
        outcome = MODULE.mtu_outcome_oracle(
            self.negative,
            1,
            (
                b"PING 47.116.202.155 (47.116.202.155) 1465 data bytes\n"
                b"ping: local error: message too long, mtu=1492\n"
                b"ping: local error: message too long, mtu=1492\n"
                b"3 packets transmitted, 0 received, +3 errors, 100% packet loss\n"
            ),
            b"ping: local error: message too long, mtu=1492\n",
        )
        self.assertEqual(outcome.local_errno, "EMSGSIZE")
        self.assertEqual(outcome.reported_mtu, 1492)
        self.assertEqual(outcome.packet_bytes, 1493)
        self.assertEqual(outcome.local_error_count, 3)

    def test_non_local_failures_never_prove_the_mtu_boundary(self):
        cases = {
            "loss": (1, b"3 packets transmitted, 0 received, 100% packet loss\n", b""),
            "unreachable": (1, b"From 192.168.10.1 Destination Host Unreachable\n", b""),
            "timeout": (124, b"", b"timeout: sending signal TERM\n"),
            "remote-pmtu": (1, b"From 192.168.10.1 icmp_seq=1 Frag needed and DF set\n", b""),
        }
        for name, (rc, stdout, stderr) in cases.items():
            with self.subTest(name=name), self.assertRaises(MODULE.HarnessError):
                MODULE.mtu_outcome_oracle(self.negative, rc, stdout, stderr)

    def test_wrong_reported_mtu_or_return_code_is_rejected(self):
        for rc, mtu in ((1, 1500), (124, 1492)):
            with self.subTest(rc=rc, mtu=mtu), self.assertRaises(MODULE.HarnessError):
                MODULE.mtu_outcome_oracle(
                    self.negative,
                    rc,
                    f"ping: local error: message too long, mtu={mtu}\n".encode(),
                    b"",
                )

    def test_positive_boundary_requires_exact_three_of_three_zero_loss(self):
        outcome = MODULE.mtu_outcome_oracle(
            self.positive,
            0,
            b"3 packets transmitted, 3 received, 0% packet loss, time 2001ms\n",
            b"",
        )
        self.assertEqual(outcome.boundary, "positive")
        self.assertEqual((outcome.transmitted, outcome.received), (3, 3))
        self.assertEqual(outcome.loss_percent, 0.0)
        self.assertEqual(outcome.packet_bytes, 1492)
        self.assertIsNone(outcome.local_errno)

    def test_positive_rc_zero_with_partial_receive_is_rejected(self):
        with self.assertRaisesRegex(MODULE.HarnessError, "exact 3/3 zero-loss"):
            MODULE.mtu_outcome_oracle(
                self.positive,
                0,
                b"3 packets transmitted, 1 received, 66.7% packet loss, time 2001ms\n",
                b"",
            )

    def test_positive_boundary_rejects_local_remote_and_timeout_errors(self):
        summary = b"3 packets transmitted, 3 received, 0% packet loss\n"
        errors = (
            b"ping: local error: message too long, mtu=1492\n",
            b"From 192.168.10.1 Destination Host Unreachable\n",
            b"timeout: sending signal TERM\n",
        )
        for error in errors:
            with self.subTest(error=error), self.assertRaises(MODULE.HarnessError):
                MODULE.mtu_outcome_oracle(self.positive, 0, summary, error)


class CounterGateTests(unittest.TestCase):
    vmxnet3_stats = b"""NIC statistics:
     Tx Queue#: 0
       TSO pkts tx: 19
       pkts tx: 20
       pkts tx err: 0
       tx ring full: 0
     Tx Queue#: 1
       TSO pkts tx: 29
       pkts tx: 30
       pkts tx err: 0
       tx ring full: 0
     Rx Queue#: 0
       pkts rx: 40
       pkts rx err: 0
       rx buf alloc failure: 0
"""

    def test_vmxnet3_queue_statistics_are_unique_and_failure_gated(self):
        before = MODULE.parse_nic_counters(self.vmxnet3_stats)
        self.assertEqual(before["tx_queue_0.tso_pkts_tx"], 19)
        self.assertEqual(before["tx_queue_1.tso_pkts_tx"], 29)
        self.assertEqual(before["rx_queue_0.pkts_rx"], 40)
        failure_keys = (
            "tx_queue_0.pkts_tx_err",
            "tx_queue_0.tx_ring_full",
            "tx_queue_1.pkts_tx_err",
            "tx_queue_1.tx_ring_full",
            "rx_queue_0.pkts_rx_err",
            "rx_queue_0.rx_buf_alloc_failure",
        )
        prefixed_before = {f"/usr/sbin/ethtool:{key}": value for key, value in before.items()}
        for key in failure_keys:
            with self.subTest(key=key), self.assertRaisesRegex(MODULE.HarnessError, "counters grew"):
                after = dict(prefixed_before)
                after[f"/usr/sbin/ethtool:{key}"] += 1
                MODULE.counter_delta(prefixed_before, after)

    def test_nic_statistics_parser_rejects_ambiguous_unknown_or_empty_shapes(self):
        fixtures = {
            "duplicate-counter": b"NIC statistics:\n rx errors: 0\n rx errors: 1\n",
            "duplicate-queue": b"NIC statistics:\n Tx Queue#: 0\n  pkts tx: 1\n Tx Queue#: 0\n  pkts tx: 2\n",
            "empty-queue": b"NIC statistics:\n Tx Queue#: 0\n",
            "unknown": b"NIC statistics:\n this is not a counter\n",
            "empty": b"NIC statistics:\n",
        }
        for name, payload in fixtures.items():
            with self.subTest(name=name), self.assertRaises(MODULE.HarnessError):
                MODULE.parse_nic_counters(payload)
        with self.assertRaisesRegex(MODULE.HarnessError, "omit required fields"):
            MODULE.parse_link_counters(
                json.dumps([{"stats64": {"rx": {}, "tx": {}}}]).encode()
            )

    def test_counter_gate_rejects_error_drop_checksum_growth_and_resets(self):
        baseline = {
            "/usr/sbin/ethtool:rx_errors": 0,
            "/usr/sbin/ethtool:checksum_error": 7,
            "/usr/sbin/ethtool:rx_bad_packet": 0,
            "/usr/sbin/ethtool:rx_badpacket": 0,
            "/usr/sbin/ethtool:rx_allocfail": 0,
            "/usr/sbin/ethtool:rx_buf_alloc_failure": 0,
            "/usr/sbin/ethtool:rx_nobuf": 0,
            "/usr/sbin/ethtool:rx_no_buffer": 0,
            "/usr/sbin/ethtool:rx_overflow": 0,
            "/usr/sbin/ethtool:rx_ring_full": 0,
            "/usr/sbin/ethtool:rx_lost": 0,
            "/usr/sbin/ip:rx_dropped": 2,
            "/usr/sbin/ip:rx_bytes": 100,
        }
        self.assertEqual(
            MODULE.counter_delta(baseline, {**baseline, "/usr/sbin/ip:rx_bytes": 200})[
                "/usr/sbin/ip:rx_bytes"
            ],
            100,
        )
        for key in (
            "/usr/sbin/ethtool:rx_errors",
            "/usr/sbin/ethtool:checksum_error",
            "/usr/sbin/ethtool:rx_bad_packet",
            "/usr/sbin/ethtool:rx_badpacket",
            "/usr/sbin/ethtool:rx_allocfail",
            "/usr/sbin/ethtool:rx_buf_alloc_failure",
            "/usr/sbin/ethtool:rx_nobuf",
            "/usr/sbin/ethtool:rx_no_buffer",
            "/usr/sbin/ethtool:rx_overflow",
            "/usr/sbin/ethtool:rx_ring_full",
            "/usr/sbin/ethtool:rx_lost",
            "/usr/sbin/ip:rx_dropped",
        ):
            with self.subTest(key=key), self.assertRaisesRegex(MODULE.HarnessError, "counters grew"):
                MODULE.counter_delta(baseline, {**baseline, key: baseline[key] + 1})
        with self.assertRaisesRegex(MODULE.HarnessError, "decreased"):
            MODULE.counter_delta(baseline, {**baseline, "/usr/sbin/ip:rx_bytes": 99})
        with self.assertRaisesRegex(MODULE.HarnessError, "schema changed"):
            MODULE.counter_delta(baseline, {key: value for key, value in baseline.items() if key != "/usr/sbin/ip:rx_bytes"})

    def test_checksum_success_counters_are_observed_but_failures_are_gated(self):
        success = ("csum_good", "csum_unneeded", "hw_csum")
        failures = ("csum_err", "checksum_error", "bad_csum")
        baseline = {
            **{f"/usr/sbin/ethtool:{name}": 0 for name in success},
            **{f"/usr/sbin/ethtool:{name}": 0 for name in failures},
        }
        for name in success:
            key = f"/usr/sbin/ethtool:{name}"
            with self.subTest(success=name):
                self.assertFalse(MODULE.counter_id_is_failure(key))
                delta = MODULE.counter_delta(baseline, {**baseline, key: 1})
                self.assertEqual(delta[key], 1)
        for name in failures:
            key = f"/usr/sbin/ethtool:{name}"
            with self.subTest(failure=name):
                self.assertTrue(MODULE.counter_id_is_failure(key))
                with self.assertRaisesRegex(MODULE.HarnessError, "counters grew"):
                    MODULE.counter_delta(baseline, {**baseline, key: 1})


class PhysicalAuthorityTests(unittest.TestCase):
    @staticmethod
    def create_physical_lock_only(prefix):
        with runtime_contract(prefix):
            path = pathlib.Path(MODULE.physical_interface_lock_path())
            path.touch(mode=0o600, exist_ok=False)
            path.chmod(0o600)
            return path

    def test_exact_reservation_is_plan_bound_and_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = f"{temporary}/run-"
            create_runtime_authorities(prefix)
            with runtime_contract(prefix):
                MODULE.validate_legacy_retirement_reservation()
                contract = MODULE.legacy_retirement_contract()
                self.assertEqual(contract["path"], MODULE.LEGACY_RETIREMENT_RESERVATION)
                self.assertEqual(
                    contract["metadata"],
                    {
                        "uid": os.getuid(),
                        "gid": os.getgid(),
                        "mode": "0600",
                        "nlink": 1,
                        "size": 0,
                        "type": "regular-file",
                    },
                )
                self.assertEqual(contract["accepted_state"], "exact-empty-sentinel-only")

    def test_missing_or_drifted_reservation_blocks_all_modes_before_mode_work(self):
        for state in ("absent", "nonempty"):
            for mode in ("plan", "run", "restore"):
                with self.subTest(state=state, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    prefix = f"{temporary}/run-"
                    self.create_physical_lock_only(prefix)
                    with runtime_contract(prefix):
                        if state == "nonempty":
                            reservation = pathlib.Path(MODULE.LEGACY_RETIREMENT_RESERVATION)
                            reservation.write_bytes(b"drift")
                            reservation.chmod(0o600)
                        spec = fixture_spec(run_root=f"{prefix}a1b2c3d4")
                        runner = SimulatedRunner(spec)
                        snapshot, commands = MODULE.collect_snapshot(spec, runner)
                        plan_payload = MODULE.canonical_json(MODULE.build_plan(spec, snapshot, commands))
                        plan_path = pathlib.Path(temporary, "approved-plan.json")
                        plan_path.write_bytes(plan_payload)
                        runner.calls.clear()
                        lease_path = MODULE.interface_lease_path(spec, snapshot["host"]["netns"])
                        error = "root stager must create" if state == "absent" else "must be the staged"
                        with mock.patch.object(MODULE.os, "geteuid", return_value=0):
                            with self.assertRaisesRegex(MODULE.HarnessError, error):
                                if mode == "plan":
                                    MODULE.plan_mode(spec, runner)
                                elif mode == "run":
                                    MODULE.run_mode(
                                        spec,
                                        str(plan_path),
                                        MODULE.sha256_bytes(plan_payload),
                                        runner,
                                    )
                                else:
                                    MODULE.restore_mode(
                                        spec,
                                        str(plan_path),
                                        MODULE.sha256_bytes(plan_payload),
                                        runner,
                                    )
                        self.assertEqual(runner.calls, [])
                        self.assertEqual(runner.network_writes, 0)
                        self.assertFalse(pathlib.Path(spec.run_root).exists())
                        self.assertFalse(pathlib.Path(lease_path).exists())

    def test_directory_symlink_nonempty_mode_and_inode_drift_are_rejected(self):
        variants = ("directory", "symlink", "nonempty", "mode", "inode")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                prefix = f"{temporary}/run-"
                self.create_physical_lock_only(prefix)
                with runtime_contract(prefix):
                    path = pathlib.Path(MODULE.LEGACY_RETIREMENT_RESERVATION)
                    if variant == "directory":
                        path.mkdir(mode=0o700)
                    elif variant == "symlink":
                        target = pathlib.Path(temporary, "sentinel-target")
                        target.touch(mode=0o600)
                        path.symlink_to(target)
                    else:
                        path.touch(mode=0o600)
                        path.chmod(0o600)
                        if variant == "nonempty":
                            path.write_bytes(b"not-empty")
                        elif variant == "mode":
                            path.chmod(0o644)
                    if variant == "inode":
                        actual = os.lstat(path)
                        replacement = types.SimpleNamespace(
                            st_mode=actual.st_mode,
                            st_dev=actual.st_dev,
                            st_ino=actual.st_ino + 1,
                        )
                        context = mock.patch.object(MODULE.os, "lstat", return_value=replacement)
                    else:
                        context = contextlib.nullcontext()
                    with context, self.assertRaises(MODULE.HarnessError):
                        MODULE.validate_legacy_retirement_reservation()

    def test_physical_lock_is_exclusive_and_requires_exact_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = f"{temporary}/run-"
            physical, _ = create_runtime_authorities(prefix)
            with runtime_contract(prefix):
                with MODULE.PhysicalInterfaceLock(str(physical)):
                    with self.assertRaisesRegex(MODULE.HarnessError, "authority is busy"):
                        MODULE.PhysicalInterfaceLock(str(physical))
                physical.write_bytes(b"drift")
                with self.assertRaisesRegex(MODULE.HarnessError, "must be the staged"):
                    MODULE.PhysicalInterfaceLock(str(physical))


class ControllerPlanTests(unittest.TestCase):
    source_commit = "1234567890abcdef1234567890abcdef12345678"

    @staticmethod
    def acceptance_fixture(**changes):
        return fixture_spec(
            profile="acceptance",
            traffic_seconds=30,
            soak_seconds=3600,
            soak_window_seconds=300,
            **changes,
        )

    def test_read_only_snapshot_derives_the_complete_fixed_controller_spec(self):
        fixture = self.acceptance_fixture()
        runner = FixtureRunner(fixture)
        spec, snapshot, commands = MODULE.collect_controller_plan_snapshot(
            self.source_commit,
            runner,
        )
        identity = snapshot["interface_identity"]
        self.assertEqual(spec.source_commit, self.source_commit)
        self.assertEqual(spec.interface, MODULE.PHYSICAL_INTERFACE)
        self.assertEqual(spec.expected_ifindex, fixture.expected_ifindex)
        self.assertEqual(spec.expected_mac, fixture.expected_mac)
        self.assertEqual(spec.expected_driver, fixture.expected_driver)
        self.assertEqual(spec.expected_device_dev, fixture.expected_device_dev)
        self.assertEqual(spec.expected_mtu, fixture.expected_mtu)
        self.assertEqual(spec.mtu_low, fixture.expected_mtu - 8)
        self.assertEqual(spec.profile, MODULE.CONTROLLER_PROFILE)
        self.assertEqual(spec.traffic_seconds, MODULE.CONTROLLER_TRAFFIC_SECONDS)
        self.assertEqual(spec.soak_seconds, MODULE.CONTROLLER_SOAK_SECONDS)
        self.assertEqual(spec.soak_window_seconds, MODULE.CONTROLLER_SOAK_WINDOW_SECONDS)
        self.assertEqual(
            spec.run_id,
            MODULE.controller_run_id(self.source_commit, fixture.expected_boot_id, identity),
        )
        self.assertEqual(spec.run_root, f"{MODULE.RUN_ROOT_PREFIX}{spec.run_id}")
        self.assertEqual(
            [call[0] for call in runner.calls],
            [argv for _, argv in MODULE.snapshot_command_table(None)],
        )
        self.assertEqual([entry["argv"] for entry in commands], [call[0] for call in runner.calls])

    def test_controller_plan_is_canonical_and_rejects_wrong_static_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = f"{temporary}/run-"
            create_runtime_authorities(prefix)
            with runtime_contract(prefix):
                fixture = self.acceptance_fixture(run_root=f"{prefix}a1b2c3d4")
                runner = FixtureRunner(fixture)
                stdout = io.BytesIO()
                wrapper = io.TextIOWrapper(stdout, encoding="utf-8")
                with contextlib.redirect_stdout(wrapper):
                    self.assertEqual(MODULE.controller_plan_mode(self.source_commit, runner), 0)
                    wrapper.flush()
                payload = stdout.getvalue()
                plan = json.loads(payload)
                self.assertEqual(payload, MODULE.canonical_json(plan))
                self.assertEqual(plan["spec"]["source_commit"], self.source_commit)
                self.assertEqual(plan["spec"]["profile"], "acceptance")

                bad = FixtureRunner(fixture)
                bad.outputs[(MODULE.TOOLS["hostname"],)] = b"not-the-reviewed-host\n"
                with self.assertRaisesRegex(MODULE.HarnessError, "fixed target"):
                    MODULE.collect_controller_plan_snapshot(self.source_commit, bad)

    def test_controller_root_plan_reader_reconstructs_spec_and_rejects_other_authority(self):
        fixture = self.acceptance_fixture()
        runner = FixtureRunner(fixture)
        spec, snapshot, commands = MODULE.collect_controller_plan_snapshot(
            self.source_commit,
            runner,
        )
        payload = MODULE.canonical_json(MODULE.build_plan(spec, snapshot, commands))
        digest = MODULE.sha256_bytes(payload)
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "realnic-approved-plan.json")
            path.write_bytes(payload)
            path.chmod(0o600)
            actual = os.stat(path)
            root_metadata = types.SimpleNamespace(
                st_mode=actual.st_mode,
                st_nlink=actual.st_nlink,
                st_size=actual.st_size,
                st_uid=0,
                st_gid=0,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino,
            )
            with (
                mock.patch.object(MODULE, "APPROVED_PLAN_PATH", str(path)),
                mock.patch.object(MODULE.os, "fstat", return_value=root_metadata),
            ):
                loaded_spec, loaded_plan, loaded_payload = MODULE.read_controller_approved_plan(
                    str(path),
                    digest,
                    self.source_commit,
                )
                self.assertEqual(loaded_spec, spec)
                self.assertEqual(loaded_plan["spec"], spec.as_dict())
                self.assertEqual(loaded_payload, payload)
                with self.assertRaisesRegex(MODULE.HarnessError, "fixed controller contract"):
                    MODULE.read_controller_approved_plan(
                        str(path),
                        digest,
                        "abcdef0123456789abcdef0123456789abcdef01",
                    )
                with self.assertRaisesRegex(MODULE.HarnessError, "fixed root-owned"):
                    MODULE.read_controller_approved_plan(
                        str(path) + ".other",
                        digest,
                        self.source_commit,
                    )

    def test_public_parser_accepts_only_source_and_approval_artifact(self):
        parser = MODULE.parser()
        plan = parser.parse_args(["plan", "--source-commit", self.source_commit])
        self.assertEqual(vars(plan), {"mode": "plan", "source_commit": self.source_commit})
        run = parser.parse_args(
            [
                "run",
                "--source-commit",
                self.source_commit,
                "--approved-plan",
                MODULE.APPROVED_PLAN_PATH,
                "--approved-plan-sha256",
                "abcdef0123456789" * 4,
            ]
        )
        self.assertEqual(run.approved_plan, MODULE.APPROVED_PLAN_PATH)
        for retired in ("--run-id", "--expected-ifindex", "--expected-mtu", "--mtu-low"):
            with self.subTest(retired=retired), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(
                        ["plan", "--source-commit", self.source_commit, retired, "1"]
                    )


class PlannerTests(unittest.TestCase):
    def test_plan_rejects_incomplete_or_non_failure_counter_schemas(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        runner.outputs[(MODULE.TOOLS["ethtool"], "-S", spec.interface)] = (
            b"NIC statistics:\n packets transmitted: 10\n"
        )
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        with self.assertRaisesRegex(MODULE.HarnessError, "no reviewed failure-class"):
            MODULE.build_plan(spec, snapshot, commands)

        runner = FixtureRunner(spec)
        runner.outputs[
            (MODULE.TOOLS["ip"], "-s", "-j", "link", "show", "dev", spec.interface)
        ] = json.dumps([{"stats64": {"rx": {"bytes": 1}, "tx": {"bytes": 2}}}]).encode()
        with self.assertRaisesRegex(MODULE.HarnessError, "omit required fields"):
            MODULE.collect_snapshot(spec, runner)

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

    def test_mtu_steps_bind_exact_positive_and_negative_outcome_oracles(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        cell = next(item for item in plan["cells"] if item["name"] == "tcp-mtu-low")
        positive = next(item for item in cell["traffic"] if item["kind"] == "mtu-positive")
        negative = next(item for item in cell["traffic"] if item["kind"] == "mtu-negative")
        self.assertEqual(
            positive["outcome_oracle"],
            MODULE.mtu_outcome_contract(spec, cell["expected_mtu"], True),
        )
        self.assertEqual(positive["outcome_oracle"]["packet_bytes"], cell["expected_mtu"])
        self.assertEqual(
            negative["outcome_oracle"],
            MODULE.mtu_outcome_contract(spec, cell["expected_mtu"], False),
        )
        self.assertEqual(negative["outcome_oracle"]["packet_bytes"], cell["expected_mtu"] + 1)

        negative["outcome_oracle"]["expected_mtu"] += 1
        with self.assertRaisesRegex(MODULE.HarnessError, "outcome oracle is not exact"):
            MODULE.validate_plan_shape(plan, spec)

    def test_plan_has_one_stable_interface_lease_and_per_write_guard(self):
        spec = fixture_spec()
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        lease = plan["interface_lease"]
        self.assertEqual(lease["identity"], MODULE.lease_identity(spec, snapshot))
        self.assertEqual(lease["path"], MODULE.interface_lease_path(spec, snapshot["host"]["netns"]))
        self.assertFalse(lease["path"].startswith(f"{spec.run_root}/"))
        self.assertEqual(plan["write_set"]["filesystem"].count(lease["path"]), 1)
        self.assertIn(f"{spec.run_root}/journal-tail-recovery.json", plan["write_set"]["filesystem"])
        self.assertIn(f"{spec.run_root}/journal-tail-recovery.pending", plan["write_set"]["filesystem"])
        self.assertIn(
            f"{spec.run_root}/explicit-restored-snapshot.json.pending",
            plan["write_set"]["filesystem"],
        )
        self.assertIn(
            f"{spec.run_root}/explicit-restored.json.pending",
            plan["write_set"]["filesystem"],
        )
        self.assertTrue(lease["held_for_entire_run_or_restore"])
        self.assertTrue(lease["persistent_active_owner"])
        self.assertEqual(
            [entry["argv"] for entry in lease["guard_before_each_network_write"]],
            [argv for _, argv in MODULE.write_guard_command_table(spec)],
        )

    def test_acceptance_profile_locks_formal_durations_and_soak_gates(self):
        spec = fixture_spec(
            profile="acceptance",
            traffic_seconds=30,
            soak_seconds=3600,
            soak_window_seconds=300,
        )
        runner = FixtureRunner(spec)
        snapshot, commands = MODULE.collect_snapshot(spec, runner)
        plan = MODULE.build_plan(spec, snapshot, commands)
        soak = next(cell for cell in plan["cells"] if cell["kind"] == "tcp-soak")
        self.assertEqual(plan["execution_profile"], "acceptance")
        self.assertEqual(plan["counter_failure_policy"], MODULE.counter_failure_policy())
        self.assertIn("failure", plan["counter_failure_policy"]["failure_tokens"])
        self.assertIn("no_buffer", plan["counter_failure_policy"]["failure_phrases"])
        self.assertEqual(
            plan["counter_failure_policy"]["qualified_observation_tokens"],
            ["checksum", "csum"],
        )
        self.assertNotIn("csum", plan["counter_failure_policy"]["failure_tokens"])
        self.assertNotIn("checksum", plan["counter_failure_policy"]["failure_token_prefixes"])
        self.assertIn("tx-checksum-ipv4", plan["owned_feature_closure"])
        self.assertNotIn("foreign-offload", plan["owned_feature_closure"])
        self.assertEqual(plan["counter_gate"], MODULE.counter_gate_contract(plan["baseline"]))
        self.assertIn(
            f"{MODULE.TOOLS['ethtool']}:global.rx_errors",
            plan["counter_gate"]["failure_counter_ids"],
        )
        self.assertEqual(
            set(plan["counter_gate"]["required_link_counter_ids"]),
            {
                f"{MODULE.TOOLS['ip']}:rx_dropped",
                f"{MODULE.TOOLS['ip']}:rx_errors",
                f"{MODULE.TOOLS['ip']}:tx_dropped",
                f"{MODULE.TOOLS['ip']}:tx_errors",
            },
        )
        self.assertEqual(len(soak["traffic"]) - 1, 12)
        self.assertEqual(soak["counter_sample_schedule"]["expected_samples"], 360)
        self.assertEqual(soak["counter_sample_schedule"]["interval_seconds"], 10)
        self.assertEqual(soak["counter_sample_schedule"]["maximum_lateness_seconds"], 2)
        self.assertEqual(soak["counter_sample_schedule"]["maximum_interwindow_gap_seconds"], 2)
        self.assertEqual(soak["counter_sample_schedule"]["required_measured_seconds"], 3600)
        self.assertTrue(all("--omit" not in step["argv"] for step in soak["traffic"][1:]))
        self.assertTrue(
            all(
                step["oracle"]["session_contract"] == MODULE.iperf_session_contract(300)
                and step["oracle"]["argv"][
                    step["oracle"]["argv"].index("--expected-seconds") + 1
                ]
                == "300"
                for step in soak["traffic"][1:]
            )
        )
        ordinary = next(cell for cell in plan["cells"] if cell["name"] == "tcp-original")
        self.assertTrue(
            all(
                step["oracle"]["session_contract"] == MODULE.iperf_session_contract(30)
                for step in ordinary["traffic"]
            )
        )
        self.assertEqual(
            ordinary["traffic"][0]["oracle"]["session_contract"]["minimum_stream_bytes"],
            1_048_576,
        )
        self.assertIsNotNone(soak["soak_oracle"])
        self.assertIn("--minimum-throughput-ratio", soak["soak_oracle"]["argv"])
        self.assertEqual(
            soak["soak_oracle"]["session_contract"],
            MODULE.iperf_session_contract(300),
        )
        with self.assertRaisesRegex(MODULE.HarnessError, "acceptance profile requires exact"):
            fixture_spec(profile="acceptance")

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
            restored_primary = [name for name in restored if name in MODULE.FEATURE_ORDER]
            self.assertEqual(restored_primary, list(reversed(changed)), cell["name"])
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
            [
                step["argv"][-2]
                for step in all_off["restore"]
                if step["argv"][-2] in MODULE.FEATURE_ORDER
            ],
            list(reversed(expected)),
        )

    def test_plan_mode_outputs_canonical_json_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = f"{temporary}/run-"
            create_runtime_authorities(prefix)
            with runtime_contract(prefix):
                spec = fixture_spec(run_root=f"{prefix}a1b2c3d4")
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
    def prepare(self, temporary, *, fail_iperf_call=None, spec_changes=None):
        prefix = f"{temporary}/run-"
        changes = {"run_root": f"{prefix}a1b2c3d4", **(spec_changes or {})}
        with runtime_contract(prefix):
            spec = fixture_spec(**changes)
            runner = SimulatedRunner(spec, fail_iperf_call=fail_iperf_call)
            snapshot, commands = MODULE.collect_snapshot(spec, runner)
            plan_payload = MODULE.canonical_json(MODULE.build_plan(spec, snapshot, commands))
        create_runtime_authorities(prefix)
        plan_path = f"{temporary}/approved-plan.json"
        pathlib.Path(plan_path).write_bytes(plan_payload)
        return prefix, spec, runner, plan_path, MODULE.sha256_bytes(plan_payload)

    def test_wrong_plan_hash_stops_before_run_root_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, _ = self.prepare(temporary)
            wrong = "abcdef0123456789" * 4
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaisesRegex(MODULE.HarnessError, "SHA-256 mismatch"):
                    MODULE.run_mode(spec, plan_path, wrong, runner)
            self.assertFalse(pathlib.Path(spec.run_root).exists())

    def test_complete_characterization_restores_every_cell_and_stays_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary)
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                rc = MODULE.run_mode(spec, plan_path, digest, runner)
            self.assertEqual(rc, 3)
            self.assertEqual(runner.mtu, spec.expected_mtu)
            baseline = MODULE.parse_features(fixture_outputs(spec)[(MODULE.TOOLS["ethtool"], "-k", spec.interface)])
            self.assertEqual(runner.features, {name: entry["enabled"] for name, entry in baseline.items()})
            outcome = json.loads(pathlib.Path(spec.run_root, "results.json").read_bytes())
            self.assertEqual(outcome["overall"], "incomplete")
            self.assertEqual(outcome["profile"], "smoke")
            self.assertEqual(outcome["classification_counts"]["smoke-passed"], 8)
            self.assertEqual(outcome["classification_counts"]["not-covered"], 6)
            events = [json.loads(line) for line in pathlib.Path(spec.run_root, "journal.jsonl").read_bytes().splitlines()]
            self.assertEqual(events[-2]["event"], "COMPLETE")
            self.assertEqual(events[-1]["event"], "INTERFACE_LEASE_RELEASED")
            self.assertEqual(
                sum(event["event"] == "CELL_MUTATION_INTENT" for event in events),
                8,
            )
            self.assertEqual(
                sum(event["event"] == "RESTORE_INTENT" for event in events),
                8,
            )
            self.assertEqual(
                sum(event["event"] == "NETWORK_WRITE_GUARD_VERIFIED" for event in events),
                runner.network_writes,
            )
            samples = json.loads(
                pathlib.Path(spec.run_root, "tcp-soak-all-on.counter-samples.json").read_bytes()
            )
            self.assertEqual(samples["expected_samples"], 6)
            self.assertEqual(len(samples["samples"]), 6)
            self.assertEqual(samples["cadence"]["windows"], 6)
            self.assertEqual(samples["cadence"]["measured_seconds"], 60)
            self.assertEqual(samples["cadence"]["first_sample_offset_seconds"], 10)
            self.assertEqual(samples["cadence"]["last_sample_offset_seconds"], 60)
            self.assertEqual(samples["cadence"]["maximum_lateness_seconds"], 0)

    def test_slow_counter_sampling_fails_the_cadence_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary)
            runner.counter_command_seconds = 1.5
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaisesRegex(MODULE.HarnessError, "sample lateness"):
                    MODULE.run_mode(spec, plan_path, digest, runner)

    def test_slow_interwindow_orchestration_fails_the_cadence_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary)
            runner.oracle_command_seconds = 3
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaisesRegex(MODULE.HarnessError, "interwindow gap"):
                    MODULE.run_mode(spec, plan_path, digest, runner)

    def test_acceptance_profile_executes_360_samples_and_first_hour_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(
                temporary,
                spec_changes={
                    "profile": "acceptance",
                    "traffic_seconds": 30,
                    "soak_seconds": 3600,
                    "soak_window_seconds": 300,
                },
            )
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                self.assertEqual(MODULE.run_mode(spec, plan_path, digest, runner), 3)
            samples = json.loads(
                pathlib.Path(spec.run_root, "tcp-soak-all-on.counter-samples.json").read_bytes()
            )
            self.assertEqual(len(samples["samples"]), 360)
            result = json.loads(pathlib.Path(spec.run_root, "results.json").read_bytes())
            self.assertEqual(result["profile"], "acceptance")
            soak = next(cell for cell in result["cells"] if cell["cell"] == "tcp-soak-all-on")
            aggregate = next(
                item for item in soak["traffic"] if item["label"] == "tcp-soak-all-on.aggregate-oracle"
            )
            self.assertEqual(len(aggregate["metrics"]["windows"]), 12)

    def test_active_interface_owner_blocks_a_different_run_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaises(MODULE.HarnessError):
                    MODULE.run_mode(spec, plan_path, digest, runner)
                second = fixture_spec(run_id="b1b2c3d4", run_root=f"{prefix}b1b2c3d4")
                second_snapshot, commands = MODULE.collect_snapshot(
                    second,
                    runner,
                    allowed_mtu=frozenset({second.expected_mtu, runner.mtu}),
                )
                second_payload = MODULE.canonical_json(MODULE.build_plan(second, second_snapshot, commands))
                second_path = pathlib.Path(temporary, "second-plan.json")
                second_path.write_bytes(second_payload)
                with self.assertRaisesRegex(MODULE.HarnessError, "active run owner a1b2c3d4"):
                    MODULE.run_mode(second, str(second_path), MODULE.sha256_bytes(second_payload), runner)
                self.assertFalse(pathlib.Path(second.run_root).exists())
                self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)

    def test_each_network_write_rechecks_identity_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary)
            real_guard = MODULE.collect_write_guard_identity

            def drifted_identity(wanted_spec, wanted_runner):
                identity = real_guard(wanted_spec, wanted_runner)
                identity["ifindex"] = 99
                return identity

            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ), mock.patch.object(MODULE, "collect_write_guard_identity", side_effect=drifted_identity):
                with self.assertRaisesRegex(MODULE.HarnessError, "network-write interface identity changed"):
                    MODULE.run_mode(spec, plan_path, digest, runner)
                self.assertEqual(runner.network_writes, 0)
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)

    def test_failure_retains_mutation_until_separately_invoked_restore(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with runtime_contract(prefix), mock.patch.object(
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
            self.assertIn("EXPLICIT_RESTORE_COMPLETE", [event["event"] for event in events])
            self.assertEqual(events[-1]["event"], "INTERFACE_LEASE_RELEASED")

    def test_explicit_restore_replays_idempotently_after_nth_step_cut(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with runtime_contract(prefix), mock.patch.object(
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
            self.assertIn("EXPLICIT_RESTORE_COMPLETE", [event["event"] for event in events])
            self.assertEqual(events[-1]["event"], "INTERFACE_LEASE_RELEASED")

    def test_mutated_interface_restores_after_unterminated_journal_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with runtime_contract(prefix), mock.patch.object(
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

    def test_explicit_restore_audits_but_ignores_unrelated_host_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaises(MODULE.HarnessError):
                    MODULE.run_mode(spec, plan_path, digest, runner)
                self.assertTrue(runner.features["tx-udp-segmentation"])

                runner.outputs[(MODULE.TOOLS["bpftool"], "-j", "link", "show")] = MODULE.canonical_json(
                    [{"id": 81, "type": "xdp", "prog_id": 91, "ifindex": 9}]
                )
                runner.outputs[
                    (MODULE.TOOLS["ip"], "-j", "route", "show", "table", "all", "dev", spec.interface)
                ] = MODULE.canonical_json(
                    [{"dst": "198.51.100.0/24", "dev": spec.interface, "protocol": "static"}]
                )
                runner.outputs[(MODULE.TOOLS["tc"], "-j", "qdisc", "show", "dev", spec.interface)] = (
                    MODULE.canonical_json([{"kind": "fq_codel", "handle": "0:"}])
                )
                runner.outputs[(MODULE.TOOLS["wg"], "show", "interfaces")] = b"wg0 wg-diagnostic\n"
                runner.features["foreign-offload"] = False
                peer_route_argv = (MODULE.TOOLS["ip"], "-j", "route", "get", spec.peer_address)
                runner.read_failures.add(peer_route_argv)

                self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)
                self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)

            self.assertFalse(runner.features["tx-udp-segmentation"])
            events = [
                json.loads(line)
                for line in pathlib.Path(spec.run_root, "journal.jsonl").read_bytes().splitlines()
            ]
            diagnostics = [
                event for event in events if event["event"] == "RESTORE_UNRELATED_DIAGNOSTICS"
            ]
            self.assertGreaterEqual(len(diagnostics), 3)
            for event in diagnostics:
                self.assertTrue(
                    {"bpf_links", "features", "peer_route", "qdisc", "routes", "wg_interfaces"}
                    <= set(event["drift_labels"])
                )
            self.assertEqual(diagnostics[0]["observations"]["peer_route"]["status"], "command-failed")
            self.assertEqual(
                diagnostics[0]["observations"]["features"]["foreign_changed"],
                ["foreign-offload"],
            )

    def test_explicit_restore_requires_exact_owned_feature_dependency_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=10)
            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaises(MODULE.HarnessError):
                    MODULE.run_mode(spec, plan_path, digest, runner)
                runner.features["tx-checksum-ipv4"] = True
                with self.assertRaisesRegex(MODULE.HarnessError, "owned feature closure mismatch"):
                    MODULE.restore_mode(spec, plan_path, digest, runner)

    def test_cascaded_feature_children_have_exact_replayable_reverse_steps(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, spec, runner, plan_path, digest = self.prepare(temporary, fail_iperf_call=19)
            approved = json.loads(pathlib.Path(plan_path).read_bytes())
            cell = next(item for item in approved["cells"] if item["name"] == "tcp-all-off")
            recovery_argv = [step["argv"] for step in cell["recovery_restore"]]
            child_argv = [
                MODULE.TOOLS["ethtool"],
                "-K",
                spec.interface,
                "tx-checksum-ipv4",
                "off",
            ]
            child_index = recovery_argv.index(child_argv)
            parent_index = recovery_argv.index(
                [MODULE.TOOLS["ethtool"], "-K", spec.interface, "tx-checksumming", "on"]
            )
            self.assertEqual(child_index, parent_index + 1)

            with runtime_contract(prefix), mock.patch.object(
                MODULE.os, "geteuid", return_value=0
            ):
                with self.assertRaises(MODULE.HarnessError):
                    MODULE.run_mode(spec, plan_path, digest, runner)
                runner.fail_ethtool_write_call = runner.ethtool_writes + child_index + 1
                with self.assertRaisesRegex(MODULE.HarnessError, "post-ethtool failure"):
                    MODULE.restore_mode(spec, plan_path, digest, runner)
                runner.fail_ethtool_write_call = None
                self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)

            baseline = approved["baseline"]["features"]
            self.assertEqual(
                {name: runner.features[name] for name in approved["owned_feature_closure"]},
                {name: baseline[name]["enabled"] for name in approved["owned_feature_closure"]},
            )

    def test_terminal_restore_artifacts_replay_every_commit_cut(self):
        artifacts = ("explicit-restored-snapshot.json", "explicit-restored.json")
        cutpoints = ("partial-write", "post-replace", "post-journal")
        for artifact in artifacts:
            for cutpoint in cutpoints:
                with self.subTest(artifact=artifact, cutpoint=cutpoint), tempfile.TemporaryDirectory() as temporary:
                    prefix, spec, runner, plan_path, digest = self.prepare(
                        temporary,
                        fail_iperf_call=10,
                    )
                    plan = json.loads(pathlib.Path(plan_path).read_bytes())
                    marker_payload = MODULE.canonical_json(
                        {"run_id": spec.run_id, "plan_sha256": digest, "state": "restored"}
                    )
                    snapshot_payload = MODULE.canonical_json(
                        MODULE.restore_owned_evidence(
                            plan["baseline"],
                            plan["owned_feature_closure"],
                        )
                    )
                    payload = (
                        snapshot_payload
                        if artifact == "explicit-restored-snapshot.json"
                        else marker_payload
                    )
                    target = pathlib.Path(spec.run_root, artifact)
                    pending = pathlib.Path(f"{target}.pending")
                    with runtime_contract(prefix), mock.patch.object(
                        MODULE.os, "geteuid", return_value=0
                    ):
                        with self.assertRaises(MODULE.HarnessError):
                            MODULE.run_mode(spec, plan_path, digest, runner)

                        if cutpoint == "partial-write":
                            real_write = MODULE.os.write
                            cut = False

                            def partial_write(descriptor, chunk):
                                nonlocal cut
                                if not cut and bytes(chunk) == payload:
                                    cut = True
                                    real_write(descriptor, chunk[:7])
                                    raise MODULE.HarnessAbort("injected terminal partial write")
                                return real_write(descriptor, chunk)

                            context = mock.patch.object(MODULE.os, "write", side_effect=partial_write)
                        elif cutpoint == "post-replace":
                            real_replace = MODULE.os.replace
                            cut = False

                            def replace_then_cut(source, destination):
                                nonlocal cut
                                result = real_replace(source, destination)
                                if not cut and destination == str(target):
                                    cut = True
                                    raise MODULE.HarnessAbort("injected terminal post-replace cut")
                                return result

                            context = mock.patch.object(
                                MODULE.os,
                                "replace",
                                side_effect=replace_then_cut,
                            )
                        else:
                            real_append = MODULE.Journal.append
                            cut = False
                            wanted = (
                                "owned-snapshot"
                                if artifact == "explicit-restored-snapshot.json"
                                else "restored-marker"
                            )

                            def append_then_cut(instance, event, **fields):
                                nonlocal cut
                                result = real_append(instance, event, **fields)
                                if (
                                    not cut
                                    and event == "EXPLICIT_RESTORE_ARTIFACT_COMMITTED"
                                    and fields.get("artifact") == wanted
                                ):
                                    cut = True
                                    raise MODULE.HarnessAbort("injected terminal post-journal cut")
                                return result

                            context = mock.patch.object(MODULE.Journal, "append", new=append_then_cut)

                        with context, self.assertRaises(MODULE.HarnessAbort):
                            MODULE.restore_mode(spec, plan_path, digest, runner)
                        self.assertTrue(cut)
                        if cutpoint == "partial-write":
                            self.assertFalse(target.exists())
                            self.assertEqual(pending.read_bytes(), payload[:7])
                        else:
                            self.assertEqual(target.read_bytes(), payload)

                        self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)
                        self.assertEqual(MODULE.restore_mode(spec, plan_path, digest, runner), 0)

                    self.assertEqual(target.read_bytes(), payload)
                    self.assertFalse(pending.exists())
                    self.assertEqual(
                        pathlib.Path(spec.run_root, "explicit-restored-snapshot.json").read_bytes(),
                        snapshot_payload,
                    )
                    self.assertEqual(
                        pathlib.Path(spec.run_root, "explicit-restored.json").read_bytes(),
                        marker_payload,
                    )


class JournalDurabilityTests(unittest.TestCase):
    run_id = "a1b2c3d4"
    plan_sha256 = "1234567890abcdef" * 4

    def open_journal(self, path, *, create):
        return MODULE.Journal(str(path), self.run_id, self.plan_sha256, create=create)

    def test_terminal_writer_never_replaces_a_tampered_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary, "explicit-restored.json")
            pending = pathlib.Path(f"{target}.pending")
            target.write_bytes(b"tampered")
            pending.write_bytes(b"expected")
            with self.assertRaisesRegex(MODULE.HarnessError, "terminal evidence differs"):
                MODULE.write_terminal_exact(str(target), b"expected")
            self.assertEqual(target.read_bytes(), b"tampered")
            self.assertEqual(pending.read_bytes(), b"expected")

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

    def test_tail_receipt_survives_crash_between_truncate_and_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "journal.jsonl")
            journal = self.open_journal(path, create=True)
            journal.append("BASELINE_CAPTURED", baseline_sha256="abcdef0123456789" * 4)
            journal.close()
            fragment = b'{"event":"CELL_MUTATION_INTENT"'
            with path.open("ab") as stream:
                stream.write(fragment)

            append_record = MODULE.Journal._append_record

            def crash_before_audit(instance, record):
                if record.get("event") == "JOURNAL_TAIL_TRUNCATED":
                    raise MODULE.HarnessError("injected post-truncate crash")
                return append_record(instance, record)

            with mock.patch.object(MODULE.Journal, "_append_record", new=crash_before_audit):
                with self.assertRaisesRegex(MODULE.HarnessError, "post-truncate crash"):
                    self.open_journal(path, create=False)

            receipt_path = pathlib.Path(temporary, "journal-tail-recovery.json")
            receipt_payload = receipt_path.read_bytes()
            receipt = json.loads(receipt_payload)
            self.assertEqual(receipt["removed_sha256"], MODULE.sha256_bytes(fragment))
            self.assertEqual(receipt["removed_bytes"], len(fragment))
            self.assertTrue(path.read_bytes().endswith(b"\n"))

            reopened = self.open_journal(path, create=False)
            try:
                audit = reopened.events[-1]
                self.assertEqual(audit["event"], "JOURNAL_TAIL_TRUNCATED")
                self.assertEqual(audit["removed_sha256"], MODULE.sha256_bytes(fragment))
                self.assertEqual(audit["receipt_sha256"], MODULE.sha256_bytes(receipt_payload))
            finally:
                reopened.close()

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
