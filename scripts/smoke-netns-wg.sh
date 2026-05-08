#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/bin/wg-mix-ebpf"

for cmd in ip wg ping tcpdump python3 timeout; do
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
NSA="wme${RUN_ID}a"
NSR="wme${RUN_ID}r"
NSB="wme${RUN_ID}b"
TMPDIR="$(mktemp -d /tmp/wg-mix-ebpf-smoke.XXXXXX)"
PIN_MOUNT="/run/wg-mix-ebpf-bpf-${RUN_ID}"
PINA="${PIN_MOUNT}/wg-mix-ebpf-${NSA}"
PINB="${PIN_MOUNT}/wg-mix-ebpf-${NSB}"
umask 077

ensure_bpffs_in_netns() {
	local ns="$1"
	ip netns exec "${ns}" sh -c 'mountpoint="$1"; mkdir -p "${mountpoint}" && awk -v mp="${mountpoint}" '"'"'$2 == mp && $3 == "bpf" { found = 1 } END { exit !found }'"'"' /proc/mounts || mount -t bpf bpf "${mountpoint}"' sh "${PIN_MOUNT}"
}

run_agent_in_netns() {
  local ns="$1"
  local pin="$2"
  shift 2
  ip netns exec "${ns}" sh -c '
    pin="$1"
    bin="$2"
    shift 2
    mountpoint="$(dirname "${pin}")"
    mkdir -p "${mountpoint}"
    mount -t bpf bpf "${mountpoint}" 2>/dev/null || true
    WG_MIX_EBPF_PIN_PATH="${pin}" exec "${bin}" "$@"
  ' sh "${pin}" "${BIN}" "$@"
}

cleanup() {
  set +e
  if ip netns list | awk '{print $1}' | grep -qx "${NSA}"; then
    run_agent_in_netns "${NSA}" "${PINA}" detach --config "${TMPDIR}/agent-a.yaml" >/dev/null 2>&1
    ip netns exec "${NSA}" umount "${PIN_MOUNT}" >/dev/null 2>&1 || true
  fi
  if ip netns list | awk '{print $1}' | grep -qx "${NSB}"; then
    run_agent_in_netns "${NSB}" "${PINB}" detach --config "${TMPDIR}/agent-b.yaml" >/dev/null 2>&1
    ip netns exec "${NSB}" umount "${PIN_MOUNT}" >/dev/null 2>&1 || true
  fi
  ip netns delete "${NSA}" >/dev/null 2>&1
  ip netns delete "${NSR}" >/dev/null 2>&1
  ip netns delete "${NSB}" >/dev/null 2>&1
  rm -rf "${TMPDIR}"
}
trap cleanup EXIT INT TERM

ip netns delete "${NSA}" >/dev/null 2>&1 || true
ip netns delete "${NSR}" >/dev/null 2>&1 || true
ip netns delete "${NSB}" >/dev/null 2>&1 || true

make_agent_config() {
  local path="$1"
  local underlay="$2"
  local wg_config="$3"
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

ip netns add "${NSA}"
ip netns add "${NSR}"
ip netns add "${NSB}"

ip link add wmea0 type veth peer name wmera0
ip link add wmeb0 type veth peer name wmerb0
ip link set wmea0 netns "${NSA}"
ip link set wmera0 netns "${NSR}"
ip link set wmeb0 netns "${NSB}"
ip link set wmerb0 netns "${NSR}"

ip -n "${NSA}" link set lo up
ip -n "${NSR}" link set lo up
ip -n "${NSB}" link set lo up
ip -n "${NSA}" link set wmea0 name under0
ip -n "${NSB}" link set wmeb0 name under0
ip -n "${NSR}" link set wmera0 name ra0
ip -n "${NSR}" link set wmerb0 name rb0

ip -n "${NSA}" addr add 192.0.2.1/24 dev under0
ip -n "${NSR}" addr add 192.0.2.254/24 dev ra0
ip -n "${NSB}" addr add 198.51.100.1/24 dev under0
ip -n "${NSR}" addr add 198.51.100.254/24 dev rb0
ip -n "${NSA}" link set under0 up
ip -n "${NSR}" link set ra0 up
ip -n "${NSB}" link set under0 up
ip -n "${NSR}" link set rb0 up

ip netns exec "${NSR}" sysctl -qw net.ipv4.ip_forward=1
ip -n "${NSA}" route add default via 192.0.2.254 dev under0
ip -n "${NSB}" route add default via 198.51.100.254 dev under0

wg genkey >"${TMPDIR}/a.key"
wg pubkey <"${TMPDIR}/a.key" >"${TMPDIR}/a.pub"
wg genkey >"${TMPDIR}/b.key"
wg pubkey <"${TMPDIR}/b.key" >"${TMPDIR}/b.pub"
chmod 0600 "${TMPDIR}/a.key" "${TMPDIR}/b.key"

A_PUB="$(cat "${TMPDIR}/a.pub")"
B_PUB="$(cat "${TMPDIR}/b.pub")"

ip -n "${NSA}" link add wg0 type wireguard
ip -n "${NSB}" link add wg0 type wireguard
ip netns exec "${NSA}" wg set wg0 private-key "${TMPDIR}/a.key" listen-port 31001 fwmark 0x10000001 peer "${B_PUB}" allowed-ips 10.77.0.2/32 endpoint 198.51.100.1:31002
ip netns exec "${NSB}" wg set wg0 private-key "${TMPDIR}/b.key" listen-port 31002 fwmark 0x10000002 peer "${A_PUB}" allowed-ips 10.77.0.1/32 endpoint 192.0.2.1:31001
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

timeout -s INT 12 ip netns exec "${NSR}" tcpdump -i ra0 -w "${TMPDIR}/ra.pcap" udp >/dev/null 2>"${TMPDIR}/tcpdump-ra.log" &
TCPDUMP_RA=$!
timeout -s INT 12 ip netns exec "${NSR}" tcpdump -i rb0 -w "${TMPDIR}/rb.pcap" udp >/dev/null 2>"${TMPDIR}/tcpdump-rb.log" &
TCPDUMP_RB=$!
sleep 1

ip netns exec "${NSA}" ping -c 3 -W 2 10.77.0.2 >/dev/null
ip netns exec "${NSB}" ping -c 3 -W 2 10.77.0.1 >/dev/null

wait "${TCPDUMP_RA}" || true
wait "${TCPDUMP_RB}" || true

python3 "${ROOT}/scripts/check-wg-pcap.py" \
  --forbid-standard \
  --require-mixed initiation,response,transport \
  "${TMPDIR}/ra.pcap" "${TMPDIR}/rb.pcap"

echo "netns WireGuard + eBPF smoke passed"
