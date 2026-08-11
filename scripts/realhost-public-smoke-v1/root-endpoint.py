#!/usr/bin/env python3
"""Fail-closed root endpoint for a bounded two-host baseline-BPF smoke test."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, NoReturn


SCHEMA = "wg-mix-public-endpoint-owner-v1"
RUN_ID_RE = re.compile(r"^[0-9a-f]{12,24}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
ROLE = {
    "b82": {
        "host": "ubuntu-2604-test",
        "interface": "ens33",
        "wg": "wgps82",
        "address": "10.203.82.1/30",
        "peer_address": "10.203.82.2",
        "listen_port": 31882,
        "fwmark": "0x51820001",
    },
    "public": {
        "host": None,
        "interface": "eth0",
        "wg": "wgps47",
        "address": "10.203.82.2/30",
        "peer_address": "10.203.82.1",
        "listen_port": 31155,
        "fwmark": "0x51820002",
    },
}
TOOLS = {
    "bpftool": "/usr/sbin/bpftool",
    "ip": "/usr/sbin/ip",
    "ping": "/usr/bin/ping",
    "python": "/usr/bin/python3",
    "sha256sum": "/usr/bin/sha256sum",
    "tcpdump": "/usr/bin/tcpdump",
    "timeout": "/usr/bin/timeout",
    "uname": "/usr/bin/uname",
    "wg": "/usr/bin/wg",
}
KNOWN_ROOT_FILES = frozenset(
    {
        "root-endpoint.py",
        "owner.json",
        "intent.json",
        "wg-mix-ebpf",
        "wg_mix_tc.o",
        "traffic.py",
        "private.key",
        "public.key",
        "wg-interface.conf",
        "agent.yaml",
        "applied.json",
        "server.pid.json",
        "capture.pid.json",
        "restored.json",
    }
)
KNOWN_EVIDENCE_RE = re.compile(
    r"^(?:server|capture)\.(?:stdout|stderr|pcap)|sample\.[0-9]{6}\.json|"
    r"(?:ping|udp|tcp)\.[a-z0-9_-]+\.(?:json|txt)$"
)


def stop(reason: str, rc: int = 78) -> NoReturn:
    print(f"PUBLIC_ENDPOINT_STOP reason={reason} rc={rc}", file=sys.stderr)
    raise SystemExit(rc)


def command(
    argv: list[str], *, input_bytes: bytes | None = None, timeout: int = 60
) -> bytes:
    try:
        completed = subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        stop(f"command:{Path(argv[0]).name}:{type(error).__name__}")
    if completed.returncode != 0:
        stop(f"command:{Path(argv[0]).name}:rc{completed.returncode}", 77)
    return completed.stdout


def canonical_run_root(run_id: str, role: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id) or role not in ROLE:
        stop("arguments", 64)
    return Path(f"/run/wg-mix-ebpf-public-smoke-{run_id}-{role}")


def sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def secure_regular(path: Path, expected_sha256: str, *, root_owned: bool) -> os.stat_result:
    if not path.is_absolute() or not SHA256_RE.fullmatch(expected_sha256):
        stop("artifact-arguments", 64)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        stop(f"artifact-open:{path.name}", 79)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            stop(f"artifact-shape:{path.name}", 79)
        if root_owned and (observed.st_uid != 0 or observed.st_gid != 0 or observed.st_mode & 0o022):
            stop(f"artifact-owner:{path.name}", 79)
        if not root_owned and observed.st_mode & 0o022:
            stop(f"artifact-writable:{path.name}", 79)
        if sha256_fd(fd) != expected_sha256:
            stop(f"artifact-sha256:{path.name}", 79)
        named = os.stat(path, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (observed.st_dev, observed.st_ino):
            stop(f"artifact-pathswap:{path.name}", 79)
        return observed
    finally:
        os.close(fd)


def write_new(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, mode)
    except OSError:
        stop(f"create:{path.name}", 79)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                stop(f"write:{path.name}")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def copy_new(source: Path, target: Path, expected_sha256: str, mode: int) -> None:
    secure_regular(source, expected_sha256, root_owned=False)
    source_fd = os.open(
        source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        data = bytearray()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 128 * 1024 * 1024:
                stop(f"artifact-size:{source.name}")
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            stop(f"artifact-reread:{source.name}", 79)
        write_new(target, bytes(data), mode)
    finally:
        os.close(source_fd)


def require_root_directory(path: Path) -> os.stat_result:
    try:
        observed = os.stat(path, follow_symlinks=False)
    except OSError:
        stop(f"directory-missing:{path.name}", 79)
    if (
        not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != 0
        or observed.st_gid != 0
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        stop(f"directory-identity:{path.name}", 79)
    return observed


def self_check(root: Path, expected_sha256: str) -> None:
    expected = root / "root-endpoint.py"
    try:
        actual = Path(__file__).resolve(strict=True)
    except OSError:
        stop("self-resolve", 79)
    if actual != expected:
        stop("self-path", 79)
    secure_regular(expected, expected_sha256, root_owned=True)


def kernel_tuple(release: str) -> tuple[int, int]:
    match = re.match(r"^([0-9]+)\.([0-9]+)(?:\.|-)", release)
    if not match:
        stop("kernel-release", 79)
    return int(match.group(1)), int(match.group(2))


def probe(role: str) -> dict[str, Any]:
    spec = ROLE[role]
    missing = [path for path in TOOLS.values() if not Path(path).is_file()]
    hostname = os.uname().nodename
    release = os.uname().release
    interface = spec["interface"]
    link: Any = None
    try:
        completed = subprocess.run(
            [TOOLS["ip"], "-j", "link", "show", "dev", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        decoded = json.loads(completed.stdout) if completed.returncode == 0 else None
        if isinstance(decoded, list) and len(decoded) == 1:
            link = decoded[0]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    bpffs = False
    try:
        fs_type = subprocess.run(
            ["/usr/bin/stat", "-fc", "%T", "/sys/fs/bpf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        bpffs = fs_type.returncode == 0 and fs_type.stdout == b"bpf_fs\n"
    except (OSError, subprocess.TimeoutExpired):
        pass
    expected_host = spec["host"]
    host_ok = expected_host is None or hostname == expected_host
    kernel_ok = kernel_tuple(release) >= (6, 6)
    return {
        "schema": "wg-mix-public-endpoint-probe-v1",
        "role": role,
        "hostname": hostname,
        "kernel": release,
        "interface": interface,
        "ifindex": link.get("ifindex") if isinstance(link, dict) else None,
        "link_type": link.get("link_type") if isinstance(link, dict) else None,
        "host_identity_ok": host_ok,
        "tools_missing": missing,
        "bpffs": bpffs,
        "tcx_kernel_floor": kernel_ok,
        "eligible": host_ok and not missing and bpffs and kernel_ok and link is not None,
    }


def load_owner(root: Path, run_id: str, role: str, commit: str) -> dict[str, Any]:
    owner_path = root / "owner.json"
    fd = -1
    try:
        fd = os.open(
            owner_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        observed = os.fstat(fd)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_gid != 0
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_nlink != 1
            or observed.st_size < 2
            or observed.st_size > 16 * 1024
        ):
            stop("owner-shape", 79)
        data = os.pread(fd, observed.st_size, 0)
        named = os.stat(owner_path, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (observed.st_dev, observed.st_ino):
            stop("owner-pathswap", 79)
        owner = json.loads(data)
    except (OSError, ValueError):
        stop("owner-read", 79)
    finally:
        if fd >= 0:
            os.close(fd)
    expected = {
        "schema": SCHEMA,
        "run_id": run_id,
        "role": role,
        "commit": commit,
        "run_root": str(root),
    }
    if not isinstance(owner, dict) or any(owner.get(k) != v for k, v in expected.items()):
        stop("owner-drift", 79)
    return owner


def prepare(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    require_root_directory(root)
    self_check(root, args.script_sha256)
    if not COMMIT_RE.fullmatch(args.commit):
        stop("commit", 64)
    entries = sorted(path.name for path in root.iterdir())
    if entries != ["root-endpoint.py"]:
        stop("prepare-root-not-empty", 79)
    current_probe = probe(args.role)
    if not current_probe["eligible"]:
        stop("probe-ineligible", 77)
    artifacts = {
        "binary": (Path(args.binary_source), "wg-mix-ebpf", args.binary_sha256, 0o700),
        "object": (Path(args.object_source), "wg_mix_tc.o", args.object_sha256, 0o600),
        "traffic": (Path(args.traffic_source), "traffic.py", args.traffic_sha256, 0o700),
    }
    for source, name, digest, mode in artifacts.values():
        copy_new(source, root / name, digest, mode)
    owner = {
        "schema": SCHEMA,
        "run_id": args.run_id,
        "role": args.role,
        "commit": args.commit,
        "run_root": str(root),
        "hostname": current_probe["hostname"],
        "kernel": current_probe["kernel"],
        "interface": ROLE[args.role]["interface"],
        "ifindex": current_probe["ifindex"],
        "script_sha256": args.script_sha256,
        "binary_sha256": args.binary_sha256,
        "object_sha256": args.object_sha256,
        "traffic_sha256": args.traffic_sha256,
    }
    write_new(root / "owner.json", (json.dumps(owner, sort_keys=True) + "\n").encode(), 0o600)
    (root / "state").mkdir(mode=0o700)
    (root / "runtime").mkdir(mode=0o700)
    (root / "evidence").mkdir(mode=0o700)
    private = command([TOOLS["wg"], "genkey"])
    if len(private) != 45 or not private.endswith(b"\n"):
        stop("private-key-shape")
    public = command([TOOLS["wg"], "pubkey"], input_bytes=private)
    if len(public) != 45 or not PUBKEY_RE.fullmatch(public.decode().rstrip("\n")):
        stop("public-key-shape")
    write_new(root / "private.key", private, 0o600)
    write_new(root / "public.key", public, 0o600)
    print(
        json.dumps(
            {
                "status": "prepared",
                "role": args.role,
                "run_id": args.run_id,
                "public_key": public.decode().rstrip("\n"),
            },
            sort_keys=True,
        )
    )


def artifact_check(root: Path, owner: dict[str, Any]) -> None:
    for name, key, mode in (
        ("root-endpoint.py", "script_sha256", 0o700),
        ("wg-mix-ebpf", "binary_sha256", 0o700),
        ("wg_mix_tc.o", "object_sha256", 0o600),
        ("traffic.py", "traffic_sha256", 0o700),
    ):
        observed = secure_regular(root / name, owner[key], root_owned=True)
        if stat.S_IMODE(observed.st_mode) != mode:
            stop(f"artifact-mode:{name}", 79)


def config_bytes(root: Path, role: str) -> tuple[bytes, bytes]:
    spec = ROLE[role]
    wg_config = f"[Interface]\nListenPort = {spec['listen_port']}\nFwMark = {spec['fwmark']}\n"
    agent = f"""version: 1
mode: transparent-typeword
underlays:
  - name: {spec['interface']}
    type: netdev
    parser: ethernet
wireguards:
  - name: {spec['wg']}
    config: {root}/wg-interface.conf
    profile: public-smoke
    transport:
      mode: udp
profiles:
  public-smoke:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none
fwmark_policy:
  mode: config-required
runtime:
  poll_interval: 5s
  require_nonzero_fwmark: true
  strict_runtime_fwmark: true
  allow_zero_fwmark_fallback: false
startup_guard:
  mode: none
  egress:
    match: fwmark
  ingress:
    match: config-listen-port-if-present
    random_listen_port_behavior: best-effort
underlay_overlap_policy: reject
"""
    return wg_config.encode(), agent.encode()


def loader_env(root: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "WG_MIX_EBPF_OBJECT": str(root / "wg_mix_tc.o"),
        "WG_MIX_EBPF_PIN_PATH": f"/sys/fs/bpf/{root.name}",
    }


def binary_command(root: Path, argv: list[str], timeout: int = 120) -> bytes:
    try:
        completed = subprocess.run(
            [str(root / "wg-mix-ebpf"), *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env=loader_env(root),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        stop(f"agent:{type(error).__name__}")
    if completed.returncode != 0:
        stop(f"agent:rc{completed.returncode}", 77)
    return completed.stdout


def verify_host(owner: dict[str, Any]) -> None:
    current = probe(owner["role"])
    for key in ("hostname", "kernel", "interface", "ifindex"):
        if current.get(key) != owner.get(key):
            stop(f"host-drift:{key}", 79)
    if not current["eligible"]:
        stop("host-ineligible", 77)


def apply_endpoint(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    require_root_directory(root)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    self_check(root, owner["script_sha256"])
    artifact_check(root, owner)
    verify_host(owner)
    if not PUBKEY_RE.fullmatch(args.peer_public_key):
        stop("peer-public-key", 64)
    try:
        base64.b64decode(args.peer_public_key, validate=True)
    except ValueError:
        stop("peer-public-key", 64)
    spec = ROLE[args.role]
    wg_name = spec["wg"]
    pin_path = Path(f"/sys/fs/bpf/{root.name}")
    if Path(f"/sys/class/net/{wg_name}").exists() or pin_path.exists():
        stop("apply-resource-exists", 79)
    intent = {
        "schema": "wg-mix-public-endpoint-intent-v1",
        "run_id": args.run_id,
        "role": args.role,
        "wg": wg_name,
        "alias": f"wg-mix-public-smoke:{args.run_id}:{args.role}",
        "pin_path": str(pin_path),
        "peer_public_key": args.peer_public_key,
    }
    write_new(root / "intent.json", (json.dumps(intent, sort_keys=True) + "\n").encode(), 0o600)
    command([TOOLS["ip"], "link", "add", "dev", wg_name, "type", "wireguard"])
    command([TOOLS["ip"], "link", "set", "dev", wg_name, "alias", intent["alias"]])
    wg_argv = [
        TOOLS["wg"],
        "set",
        wg_name,
        "private-key",
        str(root / "private.key"),
        "listen-port",
        str(spec["listen_port"]),
        "fwmark",
        spec["fwmark"],
        "peer",
        args.peer_public_key,
        "allowed-ips",
        f"{spec['peer_address']}/32",
        "persistent-keepalive",
        "15",
    ]
    if args.role == "b82":
        wg_argv.extend(["endpoint", "47.116.202.155:31155"])
    command(wg_argv)
    command([TOOLS["ip"], "address", "add", spec["address"], "dev", wg_name])
    command([TOOLS["ip"], "link", "set", "dev", wg_name, "up"])
    wg_config, agent = config_bytes(root, args.role)
    write_new(root / "wg-interface.conf", wg_config, 0o600)
    write_new(root / "agent.yaml", agent, 0o600)
    binary_command(
        root,
        [
            "reload",
            "--config",
            str(root / "agent.yaml"),
            "--run-dir",
            str(root / "runtime"),
            "--state-dir",
            str(root / "state"),
        ],
    )
    status = json.loads(
        binary_command(
            root,
            [
                "status",
                "--config",
                str(root / "agent.yaml"),
                "--run-dir",
                str(root / "runtime"),
                "--state-dir",
                str(root / "state"),
            ],
        )
    )
    dataplane = status.get("dataplane") if isinstance(status, dict) else None
    underlays = dataplane.get("underlays") if isinstance(dataplane, dict) else None
    if (
        not isinstance(underlays, list)
        or len(underlays) != 1
        or not underlays[0].get("ingress_attached")
        or not underlays[0].get("egress_attached")
        or any(item.get("backend") != "tcx" for item in underlays[0].get("filters", []))
    ):
        stop("tcx-postcondition", 79)
    write_new(
        root / "applied.json",
        (json.dumps({"status": "applied", **intent}, sort_keys=True) + "\n").encode(),
        0o600,
    )
    print(json.dumps({"status": "applied", "role": args.role, "run_id": args.run_id}))


def process_start_time(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError:
        stop("process-stat", 79)
    closing = raw.rfind(")")
    if closing < 1:
        stop("process-stat-shape", 79)
    tail = raw[closing + 2 :].split()
    # tail[0] is field 3 (state); starttime is field 22.
    if len(tail) < 20 or not tail[19].isdigit():
        stop("process-stat-shape", 79)
    return tail[19]


def save_process(root: Path, name: str, process: subprocess.Popen[bytes], argv: list[str]) -> None:
    record = {
        "pid": process.pid,
        "start_time": process_start_time(process.pid),
        "argv": argv,
    }
    write_new(
        root / f"{name}.pid.json",
        (json.dumps(record, sort_keys=True) + "\n").encode(),
        0o600,
    )


def start_server(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    artifact_check(root, owner)
    if not (root / "applied.json").is_file() or (root / "server.pid.json").exists():
        stop("server-state", 79)
    spec = ROLE[args.role]
    argv = [
        TOOLS["python"],
        str(root / "traffic.py"),
        "server",
        "--address",
        spec["address"].split("/", 1)[0],
        "--port",
        "45982",
        "--seconds",
        str(args.seconds),
    ]
    stdout = open(root / "evidence/server.stdout", "xb", buffering=0)
    stderr = open(root / "evidence/server.stderr", "xb", buffering=0)
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
    finally:
        stdout.close()
        stderr.close()
    save_process(root, "server", process, argv)
    print(json.dumps({"status": "server-started", "pid": process.pid}))


def start_capture(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    artifact_check(root, owner)
    if not (root / "applied.json").is_file() or (root / "capture.pid.json").exists():
        stop("capture-state", 79)
    listen_port = str(ROLE[args.role]["listen_port"])
    argv = [
        TOOLS["timeout"],
        "--signal=INT",
        str(args.seconds),
        TOOLS["tcpdump"],
        "-i",
        ROLE[args.role]["interface"],
        "-nn",
        "-s",
        "128",
        "-c",
        "2048",
        "-w",
        str(root / "evidence/capture.pcap"),
        "udp",
        "port",
        listen_port,
    ]
    stdout = open(root / "evidence/capture.stdout", "xb", buffering=0)
    stderr = open(root / "evidence/capture.stderr", "xb", buffering=0)
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
    finally:
        stdout.close()
        stderr.close()
    save_process(root, "capture", process, argv)
    print(json.dumps({"status": "capture-started", "pid": process.pid}))


def client(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    artifact_check(root, owner)
    if not (root / "applied.json").is_file():
        stop("client-state", 79)
    mode = args.traffic_mode
    argv = [
        TOOLS["python"],
        str(root / "traffic.py"),
        mode,
        "--address",
        ROLE[args.role]["peer_address"],
        "--port",
        "45982",
    ]
    if mode == "udp-client":
        argv += ["--seconds", str(args.seconds), "--bits-per-second", str(args.bits_per_second)]
    else:
        argv += ["--bytes", str(args.bytes)]
    output = command(argv, timeout=args.seconds + 15)
    print(output.decode("utf-8"), end="")


def ping_peer(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    artifact_check(root, owner)
    if not (root / "applied.json").is_file():
        stop("ping-state", 79)
    output = command(
        [
            TOOLS["ping"],
            "-I",
            ROLE[args.role]["wg"],
            "-n",
            "-c",
            str(args.count),
            "-i",
            "1",
            "-W",
            "2",
            ROLE[args.role]["peer_address"],
        ],
        timeout=args.count + 15,
    )
    print(output.decode("utf-8"), end="")


def sample(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    artifact_check(root, owner)
    spec = ROLE[args.role]
    transfer = command([TOOLS["wg"], "show", spec["wg"], "transfer"]).decode().strip().split("\t")
    handshake = command([TOOLS["wg"], "show", spec["wg"], "latest-handshakes"]).decode().strip().split("\t")
    if len(transfer) != 3 or len(handshake) != 2 or transfer[0] != handshake[0]:
        stop("wg-sample-shape", 79)
    status = json.loads(
        binary_command(
            root,
            [
                "status",
                "--config",
                str(root / "agent.yaml"),
                "--run-dir",
                str(root / "runtime"),
                "--state-dir",
                str(root / "state"),
            ],
        )
    )
    if not isinstance(status, dict):
        stop("status-shape", 79)
    dataplane = status.get("dataplane")
    stats = dataplane.get("stats", {}) if isinstance(dataplane, dict) else {}
    if not isinstance(stats, dict):
        stop("stats-shape", 79)
    error_names = (
        "egress_bad_type",
        "egress_bad_length",
        "ingress_bad_type",
        "ingress_bad_length",
        "checksum_error",
        "skb_load_error",
        "skb_store_error",
        "ingress_bad_checksum",
        "egress_bad_checksum",
    )
    result = {
        "role": args.role,
        "timestamp": int(time.time()),
        "peer_public_key": transfer[0],
        "wg_rx": int(transfer[1]),
        "wg_tx": int(transfer[2]),
        "latest_handshake": int(handshake[1]),
        "rewrite_success": int(stats.get("egress_rewrite_ok", 0))
        + int(stats.get("ingress_rewrite_ok", 0)),
        "error_total": sum(int(stats.get(name, 0)) for name in error_names),
        "stats": stats,
    }
    print(json.dumps(result, sort_keys=True))


def export_evidence(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    artifact_check(root, owner)
    if not (root / "restored.json").is_file():
        stop("export-before-restore", 79)
    evidence = root / "evidence"
    require_root_directory(evidence)
    encoded: dict[str, str] = {}
    total = 0
    for entry in sorted(os.scandir(evidence), key=lambda item: item.name):
        if (
            not KNOWN_EVIDENCE_RE.fullmatch(entry.name)
            or not entry.is_file(follow_symlinks=False)
        ):
            stop(f"export-foreign:{entry.name}", 79)
        opened = os.open(
            entry.path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            observed = os.fstat(opened)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != 0
                or observed.st_gid != 0
                or observed.st_nlink != 1
                or observed.st_size > 4 * 1024 * 1024
            ):
                stop(f"export-shape:{entry.name}", 79)
            data = os.pread(opened, observed.st_size, 0)
        finally:
            os.close(opened)
        total += len(data)
        if total > 16 * 1024 * 1024:
            stop("export-size", 79)
        encoded[entry.name] = base64.b64encode(data).decode("ascii")
    print(
        json.dumps(
            {
                "schema": "wg-mix-public-evidence-export-v1",
                "run_id": args.run_id,
                "role": args.role,
                "files": encoded,
            },
            sort_keys=True,
        )
    )


def verify_process(record_path: Path) -> tuple[int, dict[str, Any]]:
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
        pid = int(record["pid"])
        argv = record["argv"]
    except (OSError, ValueError, KeyError, TypeError):
        stop(f"process-record:{record_path.name}", 79)
    if pid < 2 or not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        stop(f"process-record-shape:{record_path.name}", 79)
    if process_start_time(pid) != record.get("start_time"):
        stop(f"process-identity:{record_path.name}", 79)
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        stop(f"process-cmdline:{record_path.name}", 79)
    if raw.rstrip(b"\0").split(b"\0") != [item.encode() for item in argv]:
        stop(f"process-argv:{record_path.name}", 79)
    return pid, record


def stop_process(root: Path, name: str) -> None:
    record_path = root / f"{name}.pid.json"
    if not record_path.exists():
        return
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
        recorded_pid = int(record["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        stop(f"process-record:{record_path.name}", 79)
    if not Path(f"/proc/{recorded_pid}").exists():
        return
    pid, _ = verify_process(record_path)
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and Path(f"/proc/{pid}").exists():
        time.sleep(0.1)
    if Path(f"/proc/{pid}").exists():
        stop(f"process-did-not-stop:{name}", 79)


def verify_owned_link(root: Path, run_id: str, role: str) -> bool:
    name = ROLE[role]["wg"]
    if not Path(f"/sys/class/net/{name}").exists():
        return False
    raw = command([TOOLS["ip"], "-j", "-d", "link", "show", "dev", name])
    links = json.loads(raw)
    if (
        not isinstance(links, list)
        or len(links) != 1
        or links[0].get("ifalias") != f"wg-mix-public-smoke:{run_id}:{role}"
    ):
        stop("restore-link-foreign", 79)
    return True


def restore(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    artifact_check(root, owner)
    stop_process(root, "server")
    stop_process(root, "capture")
    pin_path = Path(f"/sys/fs/bpf/{root.name}")
    if pin_path.exists():
        binary_command(
            root,
            [
                "detach",
                "--config",
                str(root / "agent.yaml"),
                "--run-dir",
                str(root / "runtime"),
                "--state-dir",
                str(root / "state"),
            ],
        )
    if verify_owned_link(root, args.run_id, args.role):
        command([TOOLS["ip"], "link", "delete", "dev", ROLE[args.role]["wg"]])
    if pin_path.exists() or Path(f"/sys/class/net/{ROLE[args.role]['wg']}").exists():
        stop("restore-postcondition", 79)
    if not (root / "restored.json").exists():
        write_new(
            root / "restored.json",
            (json.dumps({"status": "restored", "run_id": args.run_id, "role": args.role}, sort_keys=True) + "\n").encode(),
            0o600,
        )
    print(json.dumps({"status": "restored", "run_id": args.run_id, "role": args.role}))


def purge(args: argparse.Namespace) -> None:
    root = canonical_run_root(args.run_id, args.role)
    owner = load_owner(root, args.run_id, args.role, args.commit)
    artifact_check(root, owner)
    if not (root / "restored.json").is_file():
        stop("purge-before-restore", 79)
    if Path(f"/sys/class/net/{ROLE[args.role]['wg']}").exists() or Path(f"/sys/fs/bpf/{root.name}").exists():
        stop("purge-live-resource", 79)
    evidence = root / "evidence"
    state_dir = root / "state"
    runtime_dir = root / "runtime"
    for directory, predicate in (
        (evidence, lambda name: KNOWN_EVIDENCE_RE.fullmatch(name) is not None),
        (state_dir, lambda name: name == "attach-state.json"),
        (
            runtime_dir,
            lambda name: name
            in {"lock", "daemon.lease", ".daemon-maintenance.gate"},
        ),
    ):
        if not directory.exists():
            continue
        require_root_directory(directory)
        for entry in os.scandir(directory):
            if not entry.is_file(follow_symlinks=False) or not predicate(entry.name):
                stop(f"purge-foreign:{directory.name}:{entry.name}", 79)
            os.unlink(entry.path)
        os.rmdir(directory)
    for entry in os.scandir(root):
        if entry.name not in KNOWN_ROOT_FILES or not entry.is_file(follow_symlinks=False):
            stop(f"purge-foreign:root:{entry.name}", 79)
    for name in sorted(KNOWN_ROOT_FILES - {"root-endpoint.py"}):
        path = root / name
        if path.exists():
            os.unlink(path)
    os.unlink(root / "root-endpoint.py")
    os.rmdir(root)
    print(json.dumps({"status": "purged", "run_id": args.run_id, "role": args.role}))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "probe",
            "prepare",
            "apply",
            "server",
            "capture",
            "client",
            "ping",
            "sample",
            "export",
            "restore",
            "purge",
        ),
    )
    parser.add_argument("--role", choices=tuple(ROLE), required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--commit")
    parser.add_argument("--script-sha256")
    parser.add_argument("--binary-source")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--object-source")
    parser.add_argument("--object-sha256")
    parser.add_argument("--traffic-source")
    parser.add_argument("--traffic-sha256")
    parser.add_argument("--peer-public-key")
    parser.add_argument("--seconds", type=int, default=900)
    parser.add_argument("--traffic-mode", choices=("udp-client", "tcp-client"))
    parser.add_argument("--bits-per-second", type=int, default=384_000)
    parser.add_argument("--bytes", type=int, default=1_048_576)
    parser.add_argument("--count", type=int, default=900)
    args = parser.parse_args(argv)
    if args.mode == "probe":
        return args
    required = ("run_id", "commit")
    if any(not getattr(args, name) for name in required):
        stop("arguments", 64)
    if not COMMIT_RE.fullmatch(args.commit):
        stop("commit", 64)
    if args.mode == "prepare":
        prepare_required = (
            "script_sha256",
            "binary_source",
            "binary_sha256",
            "object_source",
            "object_sha256",
            "traffic_source",
            "traffic_sha256",
        )
        if any(not getattr(args, name) for name in prepare_required):
            stop("prepare-arguments", 64)
    if args.mode == "apply" and not args.peer_public_key:
        stop("apply-arguments", 64)
    if args.mode == "client" and not args.traffic_mode:
        stop("client-arguments", 64)
    if (
        not 1 <= args.seconds <= 1800
        or not 1 <= args.bits_per_second <= 1_000_000
        or not 1 <= args.bytes <= 8 * 1024 * 1024
        or not 1 <= args.count <= 1800
    ):
        stop("traffic-bounds", 64)
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.mode == "probe":
        print(json.dumps(probe(args.role), sort_keys=True))
    elif args.mode == "prepare":
        prepare(args)
    elif args.mode == "apply":
        apply_endpoint(args)
    elif args.mode == "server":
        start_server(args)
    elif args.mode == "capture":
        start_capture(args)
    elif args.mode == "client":
        client(args)
    elif args.mode == "ping":
        ping_peer(args)
    elif args.mode == "sample":
        sample(args)
    elif args.mode == "export":
        export_evidence(args)
    elif args.mode == "restore":
        restore(args)
    else:
        purge(args)
    return 0


if __name__ == "__main__":
    if os.geteuid() != 0 and len(sys.argv) > 1 and sys.argv[1] != "probe":
        stop("root-required", 77)
    raise SystemExit(main(sys.argv[1:]))
