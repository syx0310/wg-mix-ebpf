#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/bin/wg-mix-ebpf"
OUTER_FAMILY="${OUTER_FAMILY:-ipv4}"
XOR_PASSWORD="${XOR_PASSWORD:-}"
XOR_SCOPE="${XOR_SCOPE:-wg-payload-full}"
XOR_MAX_BYTES="${XOR_MAX_BYTES:-2048}"
XOR_GENERATION_CHECKS="${XOR_GENERATION_CHECKS:-off}"
XOR_DISPATCH_FAILURE_CHECKS="${XOR_DISPATCH_FAILURE_CHECKS:-off}"
UDP_ZERO_CHECKSUM_CHECKS="${UDP_ZERO_CHECKSUM_CHECKS:-off}"
TCP_CHECKS="${TCP_CHECKS:-off}"
TCP_MTUS="${TCP_MTUS:-1420 1419 1421}"
TCP_DURATION="${TCP_DURATION:-2}"
TCP_PARALLEL_STREAMS="${TCP_PARALLEL_STREAMS:-4}"
TCP_MIN_BYTES="${TCP_MIN_BYTES:-1048576}"
TCP_PORT="${TCP_PORT:-5201}"
UNDERLAY_MTU="${UNDERLAY_MTU:-2200}"
WG_MTU="${WG_MTU:-2000}"

if [[ "${OUTER_FAMILY}" != "ipv4" && "${OUTER_FAMILY}" != "ipv6" ]]; then
  echo "error: OUTER_FAMILY must be ipv4 or ipv6" >&2
  exit 1
fi
if [[ "${XOR_SCOPE}" != "wg-payload-prefix" && "${XOR_SCOPE}" != "wg-payload-full" ]]; then
  echo "error: XOR_SCOPE must be wg-payload-prefix or wg-payload-full" >&2
  exit 1
fi
if [[ ! "${XOR_MAX_BYTES}" =~ ^[0-9]+$ ]] ||
  ((XOR_MAX_BYTES < 4 || XOR_MAX_BYTES > 2048 || XOR_MAX_BYTES % 4 != 0)); then
  echo "error: XOR_MAX_BYTES must be a multiple of 4 in [4, 2048]" >&2
  exit 1
fi
for check_mode in "${XOR_GENERATION_CHECKS}" "${XOR_DISPATCH_FAILURE_CHECKS}" \
  "${UDP_ZERO_CHECKSUM_CHECKS}" "${TCP_CHECKS}"; do
  if [[ "${check_mode}" != "off" && "${check_mode}" != "enforce" ]]; then
    echo "error: optional checks must be off or enforce" >&2
    exit 1
  fi
done
if [[ "${XOR_DISPATCH_FAILURE_CHECKS}" == "enforce" &&
  ( -z "${XOR_PASSWORD}" || "${XOR_SCOPE}" != "wg-payload-full" || XOR_MAX_BYTES -lt 2048 ) ]]; then
  echo "error: dispatch failure checks require full-payload XOR with max_bytes=2048" >&2
  exit 1
fi
if [[ "${UDP_ZERO_CHECKSUM_CHECKS}" == "enforce" ]]; then
  if [[ "${OUTER_FAMILY}" != "ipv6" ]]; then
    echo "error: UDP zero-checksum checks require an IPv6 underlay" >&2
    exit 1
  fi
  if [[ -n "${XOR_PASSWORD}" &&
    ( "${XOR_SCOPE}" != "wg-payload-full" || XOR_MAX_BYTES -lt 1968 ) ]]; then
    echo "error: XOR UDP zero-checksum checks require full-payload XOR with max_bytes>=1968" >&2
    exit 1
  fi
fi
TCP_MTU_VALUES=()
if [[ "${TCP_CHECKS}" == "enforce" ]]; then
  read -r -a TCP_MTU_VALUES <<<"${TCP_MTUS}"
  if ((${#TCP_MTU_VALUES[@]} == 0)); then
    echo "error: TCP_MTUS must contain at least one MTU" >&2
    exit 1
  fi
  for tcp_mtu in "${TCP_MTU_VALUES[@]}"; do
    if [[ ! "${tcp_mtu}" =~ ^[0-9]+$ ]] || ((tcp_mtu < 576 || tcp_mtu > 65535)); then
      echo "error: TCP_MTUS values must be integers in [576, 65535]" >&2
      exit 1
    fi
  done
  if [[ ! "${TCP_DURATION}" =~ ^[0-9]+$ ]] ||
    ((TCP_DURATION < 1 || TCP_DURATION > 60)); then
    echo "error: TCP_DURATION must be an integer in [1, 60]" >&2
    exit 1
  fi
  if [[ ! "${TCP_PARALLEL_STREAMS}" =~ ^[0-9]+$ ]] ||
    ((TCP_PARALLEL_STREAMS < 2 || TCP_PARALLEL_STREAMS > 32)); then
    echo "error: TCP_PARALLEL_STREAMS must be an integer in [2, 32]" >&2
    exit 1
  fi
  if [[ ! "${TCP_MIN_BYTES}" =~ ^[0-9]+$ ]] || ((TCP_MIN_BYTES < 1)); then
    echo "error: TCP_MIN_BYTES must be a positive integer" >&2
    exit 1
  fi
  if [[ ! "${TCP_PORT}" =~ ^[0-9]+$ ]] ||
    ((TCP_PORT < 1024 || TCP_PORT > 65535)); then
    echo "error: TCP_PORT must be an integer in [1024, 65535]" >&2
    exit 1
  fi
fi

for cmd in ip wg ping tcpdump python3 timeout grep; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: missing command: ${cmd}" >&2
    exit 1
  fi
done
if [[ -n "${XOR_PASSWORD}" ]] && ! command -v bpftool >/dev/null 2>&1; then
  echo "error: missing command: bpftool" >&2
  exit 1
fi
if [[ "${TCP_CHECKS}" == "enforce" ]] && ! command -v iperf3 >/dev/null 2>&1; then
  echo "error: missing command: iperf3 (required when TCP_CHECKS=enforce)" >&2
  exit 1
fi

if [[ ! -x "${BIN}" ]]; then
  echo "error: missing binary: ${BIN}" >&2
  exit 1
fi

RUN_ID="${RUN_ID:-$(printf '%x' "$$")}"
if [[ ! "${RUN_ID}" =~ ^[[:alnum:]]{1,8}$ ]]; then
  echo "error: RUN_ID must contain 1-8 alphanumeric characters" >&2
  exit 1
fi
NSA="wme${RUN_ID}a"
NSR="wme${RUN_ID}r"
NSB="wme${RUN_ID}b"
VETH_A="wma${RUN_ID}0"
VETH_RA="wmr${RUN_ID}a"
VETH_B="wmb${RUN_ID}0"
VETH_RB="wmr${RUN_ID}b"
TMPDIR="$(mktemp -d /tmp/wg-mix-ebpf-smoke.XXXXXX)"
PIN_ROOT="${PIN_ROOT:-/sys/fs/bpf}"
PIN_BASE="${PIN_ROOT}/wg-mix-ebpf-smoke-${RUN_ID}"
PINA="${PIN_BASE}/wg-mix-ebpf-${NSA}"
PINB="${PIN_BASE}/wg-mix-ebpf-${NSB}"
UDP_ZERO_CHECKSUM_RECEIVER_PID=""
TCP_SERVER_PID=""
umask 077

run_agent_in_netns() {
  local ns="$1"
  local pin="$2"
  shift 2
  local runner=(ip netns exec "${ns}")
  if command -v nsenter >/dev/null 2>&1 && [[ -e "/run/netns/${ns}" ]]; then
    runner=(nsenter "--net=/run/netns/${ns}" "--mount=/proc/1/ns/mnt")
  fi
  "${runner[@]}" sh -c '
    pin="$1"
    bin="$2"
    shift 2
    pin_root="$1"
    shift
    mkdir -p "${pin_root}"
    if ! awk -v mp="${pin_root}" '"'"'$2 == mp && $3 == "bpf" { found = 1 } END { exit !found }'"'"' /proc/mounts; then
      mount -t bpf bpf "${pin_root}"
    fi
    mkdir -p "$(dirname "${pin}")"
    WG_MIX_EBPF_PIN_PATH="${pin}" exec "${bin}" "$@"
  ' sh "${pin}" "${BIN}" "${PIN_ROOT}" "$@"
}

cleanup() {
  local status=$?
  set +e
  local keep_tmp=0
  [[ "${KEEP_TMP_ON_FAIL:-0}" == "1" && "${status}" -ne 0 ]] && keep_tmp=1
  if [[ -n "${UDP_ZERO_CHECKSUM_RECEIVER_PID}" ]]; then
    kill "${UDP_ZERO_CHECKSUM_RECEIVER_PID}" >/dev/null 2>&1
    wait "${UDP_ZERO_CHECKSUM_RECEIVER_PID}" >/dev/null 2>&1
  fi
  if [[ -n "${TCP_SERVER_PID}" ]]; then
    kill "${TCP_SERVER_PID}" >/dev/null 2>&1
    wait "${TCP_SERVER_PID}" >/dev/null 2>&1
  fi
  if ip netns list | awk '{print $1}' | grep -qx "${NSA}"; then
    run_agent_in_netns "${NSA}" "${PINA}" detach --config "${TMPDIR}/agent-a.yaml" >/dev/null 2>&1
  fi
  if ip netns list | awk '{print $1}' | grep -qx "${NSB}"; then
    run_agent_in_netns "${NSB}" "${PINB}" detach --config "${TMPDIR}/agent-b.yaml" >/dev/null 2>&1
  fi
  ip netns delete "${NSA}" >/dev/null 2>&1
  ip netns delete "${NSR}" >/dev/null 2>&1
  ip netns delete "${NSB}" >/dev/null 2>&1
  ip link delete "${VETH_A}" >/dev/null 2>&1
  ip link delete "${VETH_B}" >/dev/null 2>&1
  rm -rf "${PIN_BASE}"
  if ((keep_tmp)); then
    echo "kept smoke evidence after failure: ${TMPDIR}" >&2
  else
    rm -rf "${TMPDIR}"
  fi
  return "${status}"
}
trap cleanup EXIT INT TERM

ip netns delete "${NSA}" >/dev/null 2>&1 || true
ip netns delete "${NSR}" >/dev/null 2>&1 || true
ip netns delete "${NSB}" >/dev/null 2>&1 || true

make_agent_config() {
  local path="$1"
  local underlay="$2"
  local wg_config="$3"
  local cipher_ref=""
  local cipher_block=""
  if [[ -n "${XOR_PASSWORD}" ]]; then
    cipher_ref="    cipher: xor-home"
    cipher_block="
ciphers:
  xor-home:
    mode: xor
    auth: none
    scope: ${XOR_SCOPE}
    key_derivation: udp2raw-md5-key1
    password: \"${XOR_PASSWORD}\"
    max_bytes: ${XOR_MAX_BYTES}
"
  fi
  cat >"${path}" <<EOF_CONFIG
version: 1
mode: transparent-typeword

underlays:
  - name: ${underlay}
    type: netdev

wireguards:
  - name: wg0
    config: ${wg_config}
    profile: mix-default
${cipher_ref}

profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none
${cipher_block}

fwmark_policy:
  mode: config-required

runtime:
  require_nonzero_fwmark: true
  strict_runtime_fwmark: true
  allow_zero_fwmark_fallback: false

policy:
  managed_egress_map_miss: drop
EOF_CONFIG
}

make_wg_config_stub() {
  local path="$1"
  local port="$2"
  local mark="$3"
  cat >"${path}" <<EOF_CONFIG
[Interface]
ListenPort = ${port}
FwMark = ${mark}
EOF_CONFIG
}

wait_ping() {
  local ns="$1"
  local target="$2"

  for _ in 1 2 3 4 5; do
    if ip netns exec "${ns}" ping -c 1 -W 2 "${target}" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

large_ping() {
  local ns="$1"
  local target="$2"

  ip netns exec "${ns}" ping -c 2 -W 2 -M do -s 1900 "${target}" >/dev/null
}

exercise_tunnel() {
  wait_ping "${NSA}" 10.77.0.2
  wait_ping "${NSB}" 10.77.0.1
  if [[ -n "${XOR_PASSWORD}" && "${XOR_SCOPE}" == "wg-payload-full" &&
    "${XOR_MAX_BYTES}" -ge 2048 ]]; then
    large_ping "${NSA}" 10.77.0.2
    large_ping "${NSB}" 10.77.0.1
  fi
}

active_generation() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    doc = json.load(fh)
dataplane = doc.get("dataplane") or doc.get("kernel") or doc
print(int(dataplane.get("active_generation", 0)))
PY
}

stat_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    doc = json.load(fh)
stats = None
for container_name in ("dataplane", "kernel"):
    container = doc.get(container_name)
    if isinstance(container, dict) and "stats" in container:
        stats = container["stats"]
        break
if stats is None and "stats" in doc:
    stats = doc["stats"]
if not isinstance(stats, dict):
    raise SystemExit(f"{sys.argv[1]}: missing stats map")
stat = sys.argv[2]
if stat not in stats:
    raise SystemExit(f"{sys.argv[1]}: missing stat: {stat}")
try:
    print(int(stats[stat]))
except (TypeError, ValueError) as exc:
    raise SystemExit(
        f"{sys.argv[1]}: invalid stat value for {stat}: {stats[stat]!r}"
    ) from exc
PY
}

assert_stat_increased() {
  local before_path="$1"
  local after_path="$2"
  local stat="$3"
  local before
  local after

  before="$(stat_value "${before_path}" "${stat}")"
  after="$(stat_value "${after_path}" "${stat}")"
  if ((after <= before)); then
    echo "error: ${stat} did not increase (${before} -> ${after})" >&2
    return 1
  fi
}

assert_stat_unchanged() {
  local before_path="$1"
  local after_path="$2"
  local stat="$3"
  local before
  local after

  before="$(stat_value "${before_path}" "${stat}")"
  after="$(stat_value "${after_path}" "${stat}")"
  if ((after != before)); then
    echo "error: ${stat} changed (${before} -> ${after})" >&2
    return 1
  fi
}

tcp_server_listening() {
  ip netns exec "${NSB}" python3 - "${TCP_PORT}" <<'PY'
import pathlib
import sys

port = f"{int(sys.argv[1]):04X}"
for path in (pathlib.Path("/proc/net/tcp"), pathlib.Path("/proc/net/tcp6")):
    try:
        lines = path.read_text(encoding="ascii").splitlines()[1:]
    except FileNotFoundError:
        continue
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and fields[1].rsplit(":", 1)[-1].upper() == port:
            if fields[3] == "0A":
                raise SystemExit(0)
raise SystemExit(1)
PY
}

exercise_tcp_run() {
  local mtu="$1"
  local streams="$2"
  local label="tcp-mtu${mtu}-p${streams}"
  local client_path="${TMPDIR}/${label}-client.json"
  local client_log="${TMPDIR}/${label}-client.log"
  local server_path="${TMPDIR}/${label}-server.json"
  local server_log="${TMPDIR}/${label}-server.log"
  local server_status=0
  local client_status=0
  local ready=0
  local attempt

  timeout -s TERM -k 2 "$((TCP_DURATION + 15))" \
    ip netns exec "${NSB}" iperf3 -s -1 -p "${TCP_PORT}" -J \
    >"${server_path}" 2>"${server_log}" &
  TCP_SERVER_PID=$!

  for ((attempt = 0; attempt < 50; attempt++)); do
    if tcp_server_listening; then
      ready=1
      break
    fi
    if ! kill -0 "${TCP_SERVER_PID}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if ((ready == 0)); then
    echo "error: iperf3 server did not listen for ${label}" >&2
    kill "${TCP_SERVER_PID}" >/dev/null 2>&1 || true
    wait "${TCP_SERVER_PID}" >/dev/null 2>&1 || true
    TCP_SERVER_PID=""
    cat "${server_log}" >&2
    return 1
  fi

  if timeout -s TERM -k 2 "$((TCP_DURATION + 15))" \
    ip netns exec "${NSA}" iperf3 -c 10.77.0.2 -p "${TCP_PORT}" \
    -t "${TCP_DURATION}" -P "${streams}" -J \
    >"${client_path}" 2>"${client_log}"; then
    client_status=0
  else
    client_status=$?
  fi

  if ((client_status != 0)); then
    echo "error: iperf3 client failed for ${label} (${client_status})" >&2
    kill "${TCP_SERVER_PID}" >/dev/null 2>&1 || true
    wait "${TCP_SERVER_PID}" >/dev/null 2>&1 || true
    TCP_SERVER_PID=""
    cat "${client_log}" >&2
    [[ ! -s "${client_path}" ]] || cat "${client_path}" >&2
    return "${client_status}"
  fi

  if wait "${TCP_SERVER_PID}"; then
    server_status=0
  else
    server_status=$?
  fi
  TCP_SERVER_PID=""
  if ((server_status != 0)); then
    echo "error: iperf3 server failed for ${label} (${server_status})" >&2
    cat "${server_log}" >&2
    [[ ! -s "${server_path}" ]] || cat "${server_path}" >&2
    return "${server_status}"
  fi

  python3 - "${client_path}" "${streams}" "${TCP_MIN_BYTES}" "${mtu}" <<'PY'
import json
import sys

path, expected_streams, minimum_bytes, mtu = sys.argv[1:]
expected_streams = int(expected_streams)
minimum_bytes = int(minimum_bytes)
with open(path, "r", encoding="utf-8") as fh:
    doc = json.load(fh)
if doc.get("error"):
    raise SystemExit(f"{path}: iperf3 error: {doc['error']}")
end = doc.get("end") or {}
summary = end.get("sum_received") or {}
received = int(summary.get("bytes", 0))
required_total = minimum_bytes * expected_streams
if received < required_total:
    raise SystemExit(
        f"{path}: received {received} bytes, require at least {required_total} "
        f"for {expected_streams} streams"
    )
streams = end.get("streams") or []
receivers = [stream.get("receiver") or {} for stream in streams]
if len(receivers) != expected_streams:
    raise SystemExit(
        f"{path}: receiver stream count={len(receivers)}, want {expected_streams}"
    )
under_minimum = [
    (index, int(stream.get("bytes", 0)))
    for index, stream in enumerate(receivers)
    if int(stream.get("bytes", 0)) < minimum_bytes
]
if under_minimum:
    raise SystemExit(
        f"{path}: receiver streams below {minimum_bytes} bytes: {under_minimum}"
    )
seconds = float(summary.get("seconds", 0.0))
mbps = received * 8 / seconds / 1_000_000 if seconds > 0 else 0.0
retransmits = int((end.get("sum_sent") or {}).get("retransmits") or 0)
print(
    f"tcp mtu={mtu} streams={expected_streams} received={received} "
    f"throughput={mbps:.2f}Mbps retransmits={retransmits}"
)
PY
}

exercise_tcp_matrix() {
  local mtu
  local side
  local stat
  local before_path
  local after_path

  for mtu in "${TCP_MTU_VALUES[@]}"; do
    ip -n "${NSA}" link set wg0 mtu "${mtu}"
    ip -n "${NSB}" link set wg0 mtu "${mtu}"
    wait_ping "${NSA}" 10.77.0.2
    wait_ping "${NSB}" 10.77.0.1

    run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" \
      >"${TMPDIR}/status-a-tcp-${mtu}-before.json"
    run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" \
      >"${TMPDIR}/status-b-tcp-${mtu}-before.json"

    exercise_tcp_run "${mtu}" 1
    exercise_tcp_run "${mtu}" "${TCP_PARALLEL_STREAMS}"

    run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" \
      >"${TMPDIR}/status-a-tcp-${mtu}-after.json"
    run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" \
      >"${TMPDIR}/status-b-tcp-${mtu}-after.json"

    for side in a b; do
      before_path="${TMPDIR}/status-${side}-tcp-${mtu}-before.json"
      after_path="${TMPDIR}/status-${side}-tcp-${mtu}-after.json"
      for stat in \
        egress_bad_type ingress_bad_type \
        egress_bad_length ingress_bad_length \
        checksum_error skb_load_error skb_store_error \
        xor_key_missing xor_len_overflow xor_bad_type_after_decrypt \
        xor_load_error xor_store_error xor_csum_error \
        xor_egress_dispatch_error xor_ingress_dispatch_error \
        ingress_bad_checksum egress_bad_checksum; do
        assert_stat_unchanged "${before_path}" "${after_path}" "${stat}"
      done
      assert_stat_increased "${before_path}" "${after_path}" egress_rewrite_ok
      assert_stat_increased "${before_path}" "${after_path}" ingress_rewrite_ok
      if [[ -n "${XOR_PASSWORD}" ]]; then
        assert_stat_increased "${before_path}" "${after_path}" xor_egress_ok
        assert_stat_increased "${before_path}" "${after_path}" xor_ingress_ok
      fi
    done
  done
}

exercise_udp_zero_checksum() {
  local ready_path="${TMPDIR}/udp-zero-checksum.ready"
  local receiver_log="${TMPDIR}/udp-zero-checksum-receiver.log"
  local attempt
  local gateway_mac
  local receiver_status=0

  run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" \
    >"${TMPDIR}/status-a-zero-before.json"
  run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" \
    >"${TMPDIR}/status-b-zero-before.json"

  # Free the configured WireGuard ports while retaining the already-loaded rules.
  ip netns exec "${NSA}" wg set wg0 listen-port 0
  ip netns exec "${NSB}" wg set wg0 listen-port 0

  gateway_mac="$(ip netns exec "${NSR}" cat /sys/class/net/ra0/address)"
  if [[ -z "${gateway_mac}" ]]; then
    echo "error: could not resolve IPv6 gateway MAC for UDP zero-checksum check" >&2
    return 1
  fi

  timeout -s TERM 10 ip netns exec "${NSB}" python3 - \
    "${A_UNDER}" "${B_UNDER}" "${ready_path}" >"${TMPDIR}/udp-zero-checksum-receiver.out" \
    2>"${receiver_log}" <<'PY' &
import socket
import struct
import sys
import time

source, destination, ready_path = sys.argv[1:]
source_port = 31001
destination_port = 31002
payload = bytearray(1968)
payload[:4] = b"\x04\x00\x00\x00"
payload[-2:] = struct.pack("!H", 0x9DD3)

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind((destination, destination_port))
with open(ready_path, "x", encoding="ascii"):
    pass
deadline = time.monotonic() + 6
while True:
    sock.settimeout(max(0.01, deadline - time.monotonic()))
    data, peer = sock.recvfrom(4096)
    if peer[0] == source and peer[1] == source_port and data == payload:
        break
    if time.monotonic() >= deadline:
        raise SystemExit(
            f"did not receive expected vector; last peer={peer[:2]} length={len(data)}"
        )
PY
  UDP_ZERO_CHECKSUM_RECEIVER_PID=$!

  for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -e "${ready_path}" ]]; then
      break
    fi
    if ! kill -0 "${UDP_ZERO_CHECKSUM_RECEIVER_PID}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if [[ ! -e "${ready_path}" ]]; then
    echo "error: UDP zero-checksum receiver did not become ready" >&2
    wait "${UDP_ZERO_CHECKSUM_RECEIVER_PID}" || true
    UDP_ZERO_CHECKSUM_RECEIVER_PID=""
    cat "${receiver_log}" >&2
    return 1
  fi

  timeout -s TERM 5 ip netns exec "${NSA}" python3 - \
    "${A_UNDER}" "${B_UNDER}" "${gateway_mac}" <<'PY'
import ipaddress
import socket
import struct
import sys

source, destination, gateway_mac = sys.argv[1:]
source_port = 31001
destination_port = 31002
payload = bytearray(1968)
payload[:4] = b"\x04\x00\x00\x00"
payload[-2:] = struct.pack("!H", 0x9DD3)
udp_length = 8 + len(payload)
udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
pseudoheader = (
    ipaddress.IPv6Address(source).packed
    + ipaddress.IPv6Address(destination).packed
    + struct.pack("!I3xB", udp_length, socket.IPPROTO_UDP)
)
checksum_input = pseudoheader + udp + payload
words = struct.unpack(f"!{len(checksum_input) // 2}H", checksum_input)
folded_sum = sum(words)
while folded_sum >> 16:
    folded_sum = (folded_sum & 0xFFFF) + (folded_sum >> 16)
assert folded_sum == 0xFFFF, f"folded checksum sum={folded_sum:#06x}"
# RFC 8200 requires the computed zero checksum to be encoded as 0xffff.
computed_checksum = (~folded_sum) & 0xFFFF
wire_checksum = computed_checksum or 0xFFFF
assert wire_checksum == 0xFFFF

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x10000001)
sock.bind(("under0", 0))
source_mac = sock.getsockname()[4]
destination_mac = bytes.fromhex(gateway_mac.replace(":", ""))
ethernet = destination_mac + source_mac + struct.pack("!H", 0x86DD)
ipv6 = struct.pack(
    "!IHBB16s16s",
    6 << 28,
    udp_length,
    socket.IPPROTO_UDP,
    64,
    ipaddress.IPv6Address(source).packed,
    ipaddress.IPv6Address(destination).packed,
)
udp = struct.pack(
    "!HHHH", source_port, destination_port, udp_length, wire_checksum
)
frame = ethernet + ipv6 + udp + payload
sent = sock.send(frame)
assert sent == len(frame), f"short Ethernet send: {sent}/{len(frame)}"
PY

  if wait "${UDP_ZERO_CHECKSUM_RECEIVER_PID}"; then
    receiver_status=0
  else
    receiver_status=$?
  fi
  UDP_ZERO_CHECKSUM_RECEIVER_PID=""
  if ((receiver_status != 0)); then
    echo "error: UDP zero-checksum receiver failed (${receiver_status})" >&2
    cat "${receiver_log}" >&2
    return "${receiver_status}"
  fi

  ip netns exec "${NSA}" wg set wg0 listen-port 31001
  ip netns exec "${NSB}" wg set wg0 listen-port 31002

  run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" \
    >"${TMPDIR}/status-a-zero-after.json"
  run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" \
    >"${TMPDIR}/status-b-zero-after.json"
  assert_stat_increased "${TMPDIR}/status-a-zero-before.json" \
    "${TMPDIR}/status-a-zero-after.json" egress_rewrite_ok
  assert_stat_increased "${TMPDIR}/status-b-zero-before.json" \
    "${TMPDIR}/status-b-zero-after.json" ingress_rewrite_ok
  if [[ -n "${XOR_PASSWORD}" ]]; then
    assert_stat_increased "${TMPDIR}/status-a-zero-before.json" \
      "${TMPDIR}/status-a-zero-after.json" xor_egress_ok
    assert_stat_increased "${TMPDIR}/status-b-zero-before.json" \
      "${TMPDIR}/status-b-zero-after.json" xor_ingress_ok
  fi
  for stat in checksum_error xor_csum_error ingress_bad_checksum; do
    assert_stat_unchanged "${TMPDIR}/status-a-zero-before.json" \
      "${TMPDIR}/status-a-zero-after.json" "${stat}"
    assert_stat_unchanged "${TMPDIR}/status-b-zero-before.json" \
      "${TMPDIR}/status-b-zero-after.json" "${stat}"
  done
}

assert_generation() {
  local path="$1"
  local expected="$2"
  local actual

  actual="$(active_generation "${path}")"
  if [[ "${actual}" -ne "${expected}" ]]; then
    echo "error: ${path} active generation=${actual}, want ${expected}" >&2
    return 1
  fi
}

tail_slot_key() {
  local index="$1"

  printf '%02x 00 00 00' "${index}"
}

assert_tail_bank() {
  local pin="$1"
  local status_path="$2"
  local generation
  local bank_start
  local map
  local segment
  local index
  local key

  generation="$(active_generation "${status_path}")"
  bank_start=$(((generation & 1) * 8))
  for map in xor_egress_programs xor_ingress_programs; do
    for segment in 0 1 2 3 4 5 6 7; do
      index=$((bank_start + segment))
      key="$(tail_slot_key "${index}")"
      # shellcheck disable=SC2086
      bpftool map lookup pinned "${pin}/${map}" key hex ${key} >/dev/null
    done
  done
}

delete_tail_slot() {
  local pin="$1"
  local map="$2"
  local generation="$3"
  local segment="$4"
  local index=$((((generation & 1) * 8) + segment))
  local key

  key="$(tail_slot_key "${index}")"
  # shellcheck disable=SC2086
  bpftool map delete pinned "${pin}/${map}" key hex ${key}
}

ip netns add "${NSA}"
ip netns add "${NSR}"
ip netns add "${NSB}"

ip link add "${VETH_A}" type veth peer name "${VETH_RA}"
ip link add "${VETH_B}" type veth peer name "${VETH_RB}"
ip link set "${VETH_A}" netns "${NSA}"
ip link set "${VETH_RA}" netns "${NSR}"
ip link set "${VETH_B}" netns "${NSB}"
ip link set "${VETH_RB}" netns "${NSR}"

ip -n "${NSA}" link set lo up
ip -n "${NSR}" link set lo up
ip -n "${NSB}" link set lo up
ip -n "${NSA}" link set "${VETH_A}" name under0
ip -n "${NSB}" link set "${VETH_B}" name under0
ip -n "${NSR}" link set "${VETH_RA}" name ra0
ip -n "${NSR}" link set "${VETH_RB}" name rb0
ip -n "${NSA}" link set under0 mtu "${UNDERLAY_MTU}"
ip -n "${NSB}" link set under0 mtu "${UNDERLAY_MTU}"
ip -n "${NSR}" link set ra0 mtu "${UNDERLAY_MTU}"
ip -n "${NSR}" link set rb0 mtu "${UNDERLAY_MTU}"

if [[ "${OUTER_FAMILY}" == "ipv4" ]]; then
  A_UNDER="192.0.2.1"
  A_GW="192.0.2.254"
  B_UNDER="198.51.100.1"
  B_GW="198.51.100.254"
  A_ENDPOINT="${A_UNDER}:31001"
  B_ENDPOINT="${B_UNDER}:31002"
  ip -n "${NSA}" addr add "${A_UNDER}/24" dev under0
  ip -n "${NSR}" addr add "${A_GW}/24" dev ra0
  ip -n "${NSB}" addr add "${B_UNDER}/24" dev under0
  ip -n "${NSR}" addr add "${B_GW}/24" dev rb0
else
  A_UNDER="2001:db8:77:a::1"
  A_GW="2001:db8:77:a::ff"
  B_UNDER="2001:db8:77:b::1"
  B_GW="2001:db8:77:b::ff"
  A_ENDPOINT="[${A_UNDER}]:31001"
  B_ENDPOINT="[${B_UNDER}]:31002"
  ip -n "${NSA}" addr add "${A_UNDER}/64" dev under0
  ip -n "${NSR}" addr add "${A_GW}/64" dev ra0
  ip -n "${NSB}" addr add "${B_UNDER}/64" dev under0
  ip -n "${NSR}" addr add "${B_GW}/64" dev rb0
fi
ip -n "${NSA}" link set under0 up
ip -n "${NSR}" link set ra0 up
ip -n "${NSB}" link set under0 up
ip -n "${NSR}" link set rb0 up

if [[ "${OUTER_FAMILY}" == "ipv4" ]]; then
  ip netns exec "${NSR}" sysctl -qw net.ipv4.ip_forward=1
  ip -n "${NSA}" route add default via "${A_GW}" dev under0
  ip -n "${NSB}" route add default via "${B_GW}" dev under0
else
  ip netns exec "${NSR}" sysctl -qw net.ipv6.conf.all.forwarding=1
  ip -n "${NSA}" -6 route add default via "${A_GW}" dev under0
  ip -n "${NSB}" -6 route add default via "${B_GW}" dev under0
fi

wg genkey >"${TMPDIR}/a.key"
wg pubkey <"${TMPDIR}/a.key" >"${TMPDIR}/a.pub"
wg genkey >"${TMPDIR}/b.key"
wg pubkey <"${TMPDIR}/b.key" >"${TMPDIR}/b.pub"
chmod 0600 "${TMPDIR}/a.key" "${TMPDIR}/b.key"

A_PUB="$(cat "${TMPDIR}/a.pub")"
B_PUB="$(cat "${TMPDIR}/b.pub")"

ip -n "${NSA}" link add wg0 type wireguard
ip -n "${NSB}" link add wg0 type wireguard
ip -n "${NSA}" link set wg0 mtu "${WG_MTU}"
ip -n "${NSB}" link set wg0 mtu "${WG_MTU}"
ip netns exec "${NSA}" wg set wg0 private-key "${TMPDIR}/a.key" listen-port 31001 fwmark 0x10000001 peer "${B_PUB}" allowed-ips 10.77.0.2/32 endpoint "${B_ENDPOINT}"
ip netns exec "${NSB}" wg set wg0 private-key "${TMPDIR}/b.key" listen-port 31002 fwmark 0x10000002 peer "${A_PUB}" allowed-ips 10.77.0.1/32 endpoint "${A_ENDPOINT}"
ip -n "${NSA}" addr add 10.77.0.1/24 dev wg0
ip -n "${NSB}" addr add 10.77.0.2/24 dev wg0
ip -n "${NSA}" link set wg0 up
ip -n "${NSB}" link set wg0 up
ip -n "${NSA}" route add 10.77.0.2/32 dev wg0
ip -n "${NSB}" route add 10.77.0.1/32 dev wg0

make_wg_config_stub "${TMPDIR}/wg-a.conf" 31001 0x10000001
make_wg_config_stub "${TMPDIR}/wg-b.conf" 31002 0x10000002
make_agent_config "${TMPDIR}/agent-a.yaml" under0 "${TMPDIR}/wg-a.conf"
make_agent_config "${TMPDIR}/agent-b.yaml" under0 "${TMPDIR}/wg-b.conf"

run_agent_in_netns "${NSA}" "${PINA}" reload --config "${TMPDIR}/agent-a.yaml"
run_agent_in_netns "${NSB}" "${PINB}" reload --config "${TMPDIR}/agent-b.yaml"
run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" >"${TMPDIR}/status-a-before.json"
run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" >"${TMPDIR}/status-b-before.json"
assert_generation "${TMPDIR}/status-a-before.json" 1
assert_generation "${TMPDIR}/status-b-before.json" 1
if [[ -n "${XOR_PASSWORD}" ]]; then
  assert_tail_bank "${PINA}" "${TMPDIR}/status-a-before.json"
  assert_tail_bank "${PINB}" "${TMPDIR}/status-b-before.json"
fi

timeout -s INT 30 ip netns exec "${NSR}" tcpdump -i ra0 -w "${TMPDIR}/ra.pcap" udp >/dev/null 2>"${TMPDIR}/tcpdump-ra.log" &
TCPDUMP_RA=$!
timeout -s INT 30 ip netns exec "${NSR}" tcpdump -i rb0 -w "${TMPDIR}/rb.pcap" udp >/dev/null 2>"${TMPDIR}/tcpdump-rb.log" &
TCPDUMP_RB=$!
sleep 1

exercise_tunnel

if [[ -n "${XOR_PASSWORD}" && "${XOR_GENERATION_CHECKS}" == "enforce" ]]; then
  for expected_generation in 2 3; do
    run_agent_in_netns "${NSA}" "${PINA}" reload --config "${TMPDIR}/agent-a.yaml"
    run_agent_in_netns "${NSB}" "${PINB}" reload --config "${TMPDIR}/agent-b.yaml"
    run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" >"${TMPDIR}/status-a-gen${expected_generation}.json"
    run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" >"${TMPDIR}/status-b-gen${expected_generation}.json"
    assert_generation "${TMPDIR}/status-a-gen${expected_generation}.json" "${expected_generation}"
    assert_generation "${TMPDIR}/status-b-gen${expected_generation}.json" "${expected_generation}"
    assert_tail_bank "${PINA}" "${TMPDIR}/status-a-gen${expected_generation}.json"
    assert_tail_bank "${PINB}" "${TMPDIR}/status-b-gen${expected_generation}.json"
    exercise_tunnel
  done
fi

wait "${TCPDUMP_RA}" || true
wait "${TCPDUMP_RB}" || true

if [[ -n "${XOR_PASSWORD}" ]]; then
  python3 "${ROOT}/scripts/check-wg-pcap.py" \
    --forbid-plain-standard \
    --forbid-plain-mixed \
    --xor-udp2raw-password "${XOR_PASSWORD}" \
    --require-xor-mixed initiation,response,transport \
    "${TMPDIR}/ra.pcap" "${TMPDIR}/rb.pcap"
else
  python3 "${ROOT}/scripts/check-wg-pcap.py" \
    --forbid-standard \
    --require-mixed initiation,response,transport \
    "${TMPDIR}/ra.pcap" "${TMPDIR}/rb.pcap"
fi

if [[ "${UDP_ZERO_CHECKSUM_CHECKS}" == "enforce" ]]; then
  exercise_udp_zero_checksum
fi

run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" >"${TMPDIR}/status-a-after.json"
run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" >"${TMPDIR}/status-b-after.json"

python3 - "$TMPDIR/status-a-after.json" "$TMPDIR/status-b-after.json" <<'PY'
import json
import sys

required_zero = (
    "checksum_error",
    "skb_load_error",
    "skb_store_error",
    "icmp_checksum_error",
    "xor_key_missing",
    "xor_len_overflow",
    "xor_bad_type_after_decrypt",
    "xor_load_error",
    "xor_store_error",
    "xor_csum_error",
    "xor_egress_dispatch_error",
    "xor_ingress_dispatch_error",
    "ingress_bad_checksum",
    "egress_bad_checksum",
)
xor_enabled = bool(__import__("os").environ.get("XOR_PASSWORD"))
required_positive = ["egress_rewrite_ok", "ingress_rewrite_ok"]
if xor_enabled:
    required_positive.extend(["xor_egress_ok", "xor_ingress_ok"])
for path in sys.argv[1:]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    stats = (
        doc.get("dataplane", {}).get("stats")
        or doc.get("kernel", {}).get("stats")
        or doc.get("stats")
        or {}
    )
    if not stats:
        raise SystemExit(f"{path}: missing stats in status JSON: {json.dumps(doc, indent=2)}")
    for key in required_zero:
        if int(stats.get(key, 0)) != 0:
            raise SystemExit(f"{path}: {key}={stats.get(key)}")
    for key in required_positive:
        if int(stats.get(key, 0)) <= 0:
            raise SystemExit(f"{path}: {key}={stats.get(key)}")
PY

if [[ "${XOR_DISPATCH_FAILURE_CHECKS}" == "enforce" ]]; then
  status_a="${TMPDIR}/status-a-after.json"
  status_b="${TMPDIR}/status-b-after.json"
  generation_a="$(active_generation "${status_a}")"
  generation_b="$(active_generation "${status_b}")"
  egress_before="$(stat_value "${status_a}" xor_egress_dispatch_error)"
  ingress_before="$(stat_value "${status_b}" xor_ingress_dispatch_error)"

  delete_tail_slot "${PINA}" xor_egress_programs "${generation_a}" 7
  if large_ping "${NSA}" 10.77.0.2; then
    echo "error: large XOR packet passed with missing egress segment 7" >&2
    exit 1
  fi
  run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" >"${TMPDIR}/status-a-egress-miss.json"
  egress_after="$(stat_value "${TMPDIR}/status-a-egress-miss.json" xor_egress_dispatch_error)"
  if ((egress_after <= egress_before)); then
    echo "error: egress dispatch counter did not increase (${egress_before} -> ${egress_after})" >&2
    exit 1
  fi
  run_agent_in_netns "${NSA}" "${PINA}" reload --config "${TMPDIR}/agent-a.yaml"
  run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" >"${TMPDIR}/status-a-repaired.json"
  assert_tail_bank "${PINA}" "${TMPDIR}/status-a-repaired.json"
  large_ping "${NSA}" 10.77.0.2

  delete_tail_slot "${PINB}" xor_ingress_programs "${generation_b}" 7
  if large_ping "${NSA}" 10.77.0.2; then
    echo "error: large XOR packet passed with missing ingress segment 7" >&2
    exit 1
  fi
  run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" >"${TMPDIR}/status-b-ingress-miss.json"
  ingress_after="$(stat_value "${TMPDIR}/status-b-ingress-miss.json" xor_ingress_dispatch_error)"
  if ((ingress_after <= ingress_before)); then
    echo "error: ingress dispatch counter did not increase (${ingress_before} -> ${ingress_after})" >&2
    exit 1
  fi
  run_agent_in_netns "${NSB}" "${PINB}" reload --config "${TMPDIR}/agent-b.yaml"
  run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" >"${TMPDIR}/status-b-repaired.json"
  assert_tail_bank "${PINB}" "${TMPDIR}/status-b-repaired.json"
  large_ping "${NSA}" 10.77.0.2
fi

if [[ "${TCP_CHECKS}" == "enforce" ]]; then
  exercise_tcp_matrix
fi

if [[ -n "${XOR_PASSWORD}" ]]; then
  echo "netns WireGuard + eBPF ${OUTER_FAMILY} xor smoke passed (${XOR_SCOPE}, max_bytes=${XOR_MAX_BYTES})"
else
  echo "netns WireGuard + eBPF ${OUTER_FAMILY} smoke passed"
fi
