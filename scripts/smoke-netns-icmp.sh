#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/bin/wg-mix-ebpf"
ICMP_CLIENT_ID="${ICMP_CLIENT_ID:-0x5301}"
NEGATIVE_CHECKS="${NEGATIVE_CHECKS:-skip}"

case "${NEGATIVE_CHECKS}" in
skip | enforce | xfail) ;;
*)
  echo "error: NEGATIVE_CHECKS must be skip, enforce, or xfail" >&2
  exit 1
  ;;
esac

for cmd in ip wg ping tcpdump python3 timeout grep awk; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: missing command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -x "${BIN}" ]]; then
  echo "error: missing binary: ${BIN}" >&2
  exit 1
fi

RUN_ID="${RUN_ID:-$(printf '%x' "$$")}"
if [[ ! "${RUN_ID}" =~ ^[[:alnum:]]{1,8}$ ]]; then
  echo "error: RUN_ID must contain 1-8 alphanumeric characters" >&2
  exit 1
fi
NSC="wmi${RUN_ID}c"
NSR="wmi${RUN_ID}r"
NSS="wmi${RUN_ID}s"
VETH_C="wmc${RUN_ID}0"
VETH_RC="wmr${RUN_ID}c"
VETH_S="wms${RUN_ID}0"
VETH_RS="wmr${RUN_ID}s"
TMPDIR="$(mktemp -d /tmp/wg-mix-ebpf-icmp-smoke.XXXXXX)"
PIN_ROOT="${PIN_ROOT:-/sys/fs/bpf}"
PIN_BASE="${PIN_ROOT}/wg-mix-ebpf-icmp-smoke-${RUN_ID}"
PINC="${PIN_BASE}/wg-mix-ebpf-${NSC}"
PINS="${PIN_BASE}/wg-mix-ebpf-${NSS}"
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
  if ip netns list | awk '{print $1}' | grep -qx "${NSC}"; then
    run_agent_in_netns "${NSC}" "${PINC}" detach --config "${TMPDIR}/agent-client.yaml" >/dev/null 2>&1
  fi
  if ip netns list | awk '{print $1}' | grep -qx "${NSS}"; then
    run_agent_in_netns "${NSS}" "${PINS}" detach --config "${TMPDIR}/agent-server.yaml" >/dev/null 2>&1
  fi
  ip netns delete "${NSC}" >/dev/null 2>&1
  ip netns delete "${NSR}" >/dev/null 2>&1
  ip netns delete "${NSS}" >/dev/null 2>&1
  ip link delete "${VETH_C}" >/dev/null 2>&1
  ip link delete "${VETH_S}" >/dev/null 2>&1
  rm -rf "${PIN_BASE}"
  if ((keep_tmp)); then
    echo "kept ICMP smoke evidence after failure: ${TMPDIR}" >&2
  else
    rm -rf "${TMPDIR}"
  fi
  return "${status}"
}
trap cleanup EXIT INT TERM

ip netns delete "${NSC}" >/dev/null 2>&1 || true
ip netns delete "${NSR}" >/dev/null 2>&1 || true
ip netns delete "${NSS}" >/dev/null 2>&1 || true

make_agent_config() {
  local path="$1"
  local role="$2"
  local wg_config="$3"
  local id_line=""
  if [[ "${role}" == "client" ]]; then
    id_line="        id: ${ICMP_CLIENT_ID}"
  fi
  cat >"${path}" <<EOF_CONFIG
version: 1
mode: transparent-typeword

underlays:
  - name: under0
    type: netdev

wireguards:
  - name: wg0
    config: ${wg_config}
    profile: mix-default
    transport:
      mode: icmp
      icmp:
        role: ${role}
${id_line}

profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none

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

wg_rx_bytes() {
  ip netns exec "${NSS}" wg show wg0 transfer |
    awk -v peer="${CLIENT_PUB}" '$1 == peer { print $2; found = 1 } END { exit !found }'
}

run_negative_checks() {
  if [[ "${NEGATIVE_CHECKS}" == "skip" ]]; then
    echo "optional ICMP negative checks skipped; set NEGATIVE_CHECKS=enforce or xfail to run them"
    return 0
  fi

  local failures=()
  local rx_before
  local rx_after

  echo "running optional ICMP negative checks (${NEGATIVE_CHECKS})"

  if ip netns exec "${NSC}" ping -c 1 -W 2 "${SERVER_UNDER}" >/dev/null; then
    echo "ordinary underlay ping to ICMP server wildcard listener passed"
  else
    failures+=("ordinary underlay ping was dropped by ICMP server wildcard listener")
  fi

  if ip netns exec "${NSC}" ping -c 1 -W 2 -e 0 "${SERVER_UNDER}" >/dev/null; then
    echo "ordinary underlay ping with ICMP id 0 passed"
  else
    failures+=("ordinary underlay ping with ICMP id 0 was dropped by ICMP server wildcard listener")
  fi

  rx_before="$(wg_rx_bytes)"
  run_agent_in_netns "${NSC}" "${PINC}" detach --config "${TMPDIR}/agent-client.yaml" >/dev/null
  ip netns exec "${NSC}" wg set wg0 peer "${SERVER_PUB}" endpoint "${SERVER_ENDPOINT}"
  ip netns exec "${NSC}" ping -c 3 -W 1 10.78.0.2 >/dev/null 2>&1 || true
  sleep 1
  rx_after="$(wg_rx_bytes)"

  if ((rx_after > rx_before)); then
    failures+=("raw UDP WireGuard reached ICMP-managed ListenPort: server_rx ${rx_before}->${rx_after}")
  else
    echo "raw UDP WireGuard did not increase server receive bytes"
  fi

  rx_before="$(wg_rx_bytes)"
  ip netns exec "${NSC}" wg set wg0 peer "${SERVER_PUB}" endpoint "[${SERVER_UNDER6}]:31002"
  ip netns exec "${NSC}" ping -c 3 -W 1 10.78.0.2 >/dev/null 2>&1 || true
  sleep 1
  rx_after="$(wg_rx_bytes)"

  if ((rx_after > rx_before)); then
    failures+=("raw IPv6 UDP WireGuard reached ICMP-managed ListenPort: server_rx ${rx_before}->${rx_after}")
  else
    echo "raw IPv6 UDP WireGuard did not increase server receive bytes"
  fi

  if ((${#failures[@]} == 0)); then
    return 0
  fi

  if [[ "${NEGATIVE_CHECKS}" == "xfail" ]]; then
    printf 'xfail negative check: %s\n' "${failures[@]}" >&2
    return 0
  fi

  printf 'negative check failed: %s\n' "${failures[@]}" >&2
  return 1
}

ip netns add "${NSC}"
ip netns add "${NSR}"
ip netns add "${NSS}"

ip link add "${VETH_C}" type veth peer name "${VETH_RC}"
ip link add "${VETH_S}" type veth peer name "${VETH_RS}"
ip link set "${VETH_C}" netns "${NSC}"
ip link set "${VETH_RC}" netns "${NSR}"
ip link set "${VETH_S}" netns "${NSS}"
ip link set "${VETH_RS}" netns "${NSR}"

ip -n "${NSC}" link set lo up
ip -n "${NSR}" link set lo up
ip -n "${NSS}" link set lo up
ip -n "${NSC}" link set "${VETH_C}" name under0
ip -n "${NSS}" link set "${VETH_S}" name under0
ip -n "${NSR}" link set "${VETH_RC}" name rc0
ip -n "${NSR}" link set "${VETH_RS}" name rs0

CLIENT_UNDER="192.0.2.1"
CLIENT_GW="192.0.2.254"
SERVER_UNDER="198.51.100.1"
SERVER_GW="198.51.100.254"
CLIENT_UNDER6="2001:db8:78:1::1"
CLIENT_GW6="2001:db8:78:1::ffff"
SERVER_UNDER6="2001:db8:78:2::1"
SERVER_GW6="2001:db8:78:2::ffff"
SERVER_ENDPOINT="${SERVER_UNDER}:31002"

ip -n "${NSC}" addr add "${CLIENT_UNDER}/24" dev under0
ip -n "${NSR}" addr add "${CLIENT_GW}/24" dev rc0
ip -n "${NSS}" addr add "${SERVER_UNDER}/24" dev under0
ip -n "${NSR}" addr add "${SERVER_GW}/24" dev rs0
ip -n "${NSC}" addr add "${CLIENT_UNDER6}/64" dev under0
ip -n "${NSR}" addr add "${CLIENT_GW6}/64" dev rc0
ip -n "${NSS}" addr add "${SERVER_UNDER6}/64" dev under0
ip -n "${NSR}" addr add "${SERVER_GW6}/64" dev rs0
ip -n "${NSC}" link set under0 up
ip -n "${NSR}" link set rc0 up
ip -n "${NSS}" link set under0 up
ip -n "${NSR}" link set rs0 up

ip netns exec "${NSR}" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "${NSR}" sysctl -qw net.ipv6.conf.all.forwarding=1
ip -n "${NSC}" route add default via "${CLIENT_GW}" dev under0
ip -n "${NSS}" route add default via "${SERVER_GW}" dev under0
ip -n "${NSC}" -6 route add default via "${CLIENT_GW6}" dev under0
ip -n "${NSS}" -6 route add default via "${SERVER_GW6}" dev under0

wg genkey >"${TMPDIR}/client.key"
wg pubkey <"${TMPDIR}/client.key" >"${TMPDIR}/client.pub"
wg genkey >"${TMPDIR}/server.key"
wg pubkey <"${TMPDIR}/server.key" >"${TMPDIR}/server.pub"
chmod 0600 "${TMPDIR}/client.key" "${TMPDIR}/server.key"

CLIENT_PUB="$(cat "${TMPDIR}/client.pub")"
SERVER_PUB="$(cat "${TMPDIR}/server.pub")"

ip -n "${NSC}" link add wg0 type wireguard
ip -n "${NSS}" link add wg0 type wireguard
ip netns exec "${NSC}" wg set wg0 private-key "${TMPDIR}/client.key" listen-port 31001 fwmark 0x10000001 peer "${SERVER_PUB}" allowed-ips 10.78.0.2/32 endpoint "${SERVER_ENDPOINT}"
ip netns exec "${NSS}" wg set wg0 private-key "${TMPDIR}/server.key" listen-port 31002 fwmark 0x10000002 peer "${CLIENT_PUB}" allowed-ips 10.78.0.1/32
ip -n "${NSC}" addr add 10.78.0.1/24 dev wg0
ip -n "${NSS}" addr add 10.78.0.2/24 dev wg0
ip -n "${NSC}" link set wg0 up
ip -n "${NSS}" link set wg0 up
ip -n "${NSC}" route add 10.78.0.2/32 dev wg0
ip -n "${NSS}" route add 10.78.0.1/32 dev wg0

make_wg_config_stub "${TMPDIR}/wg-client.conf" 31001 0x10000001
make_wg_config_stub "${TMPDIR}/wg-server.conf" 31002 0x10000002
make_agent_config "${TMPDIR}/agent-client.yaml" client "${TMPDIR}/wg-client.conf"
make_agent_config "${TMPDIR}/agent-server.yaml" server "${TMPDIR}/wg-server.conf"

run_agent_in_netns "${NSC}" "${PINC}" reload --config "${TMPDIR}/agent-client.yaml"
run_agent_in_netns "${NSS}" "${PINS}" reload --config "${TMPDIR}/agent-server.yaml"
run_agent_in_netns "${NSC}" "${PINC}" status --config "${TMPDIR}/agent-client.yaml" >"${TMPDIR}/status-client-before.json"
run_agent_in_netns "${NSS}" "${PINS}" status --config "${TMPDIR}/agent-server.yaml" >"${TMPDIR}/status-server-before.json"

timeout -s INT 12 ip netns exec "${NSR}" tcpdump -i rc0 -w "${TMPDIR}/rc.pcap" icmp >/dev/null 2>"${TMPDIR}/tcpdump-rc.log" &
TCPDUMP_RC=$!
timeout -s INT 12 ip netns exec "${NSR}" tcpdump -i rs0 -w "${TMPDIR}/rs.pcap" icmp >/dev/null 2>"${TMPDIR}/tcpdump-rs.log" &
TCPDUMP_RS=$!
sleep 1

wait_ping "${NSC}" 10.78.0.2
wait_ping "${NSS}" 10.78.0.1

wait "${TCPDUMP_RC}" || true
wait "${TCPDUMP_RS}" || true

python3 "${ROOT}/scripts/check-wg-pcap.py" \
  --protocol icmp \
  --forbid-standard \
  --require-mixed initiation,response,transport \
  --require-icmp-types request,reply \
  --require-valid-icmp-checksum \
  "${TMPDIR}/rc.pcap" "${TMPDIR}/rs.pcap"

run_agent_in_netns "${NSC}" "${PINC}" status --config "${TMPDIR}/agent-client.yaml" >"${TMPDIR}/status-client-after.json"
run_agent_in_netns "${NSS}" "${PINS}" status --config "${TMPDIR}/agent-server.yaml" >"${TMPDIR}/status-server-after.json"

python3 - "$TMPDIR/status-client-after.json" "$TMPDIR/status-server-after.json" <<'PY'
import json
import sys

required_zero = (
    "checksum_error",
    "icmp_checksum_error",
    "skb_load_error",
    "skb_store_error",
    "xor_key_missing",
    "xor_len_overflow",
    "xor_bad_type_after_decrypt",
    "xor_load_error",
    "xor_store_error",
    "xor_csum_error",
    "ingress_bad_checksum",
    "egress_bad_checksum",
)
required_positive = (
    "egress_rewrite_ok",
    "ingress_rewrite_ok",
    "icmp_egress_rewrite_ok",
    "icmp_ingress_rewrite_ok",
)
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

run_negative_checks

echo "netns WireGuard + eBPF ICMP ipv4 smoke passed"
