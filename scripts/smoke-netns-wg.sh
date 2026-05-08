#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/bin/wg-mix-ebpf"
OUTER_FAMILY="${OUTER_FAMILY:-ipv4}"

if [[ "${OUTER_FAMILY}" != "ipv4" && "${OUTER_FAMILY}" != "ipv6" ]]; then
  echo "error: OUTER_FAMILY must be ipv4 or ipv6" >&2
  exit 1
fi

for cmd in ip wg ping tcpdump python3 timeout grep; do
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
PIN_ROOT="${PIN_ROOT:-/sys/fs/bpf}"
PIN_BASE="${PIN_ROOT}/wg-mix-ebpf-smoke-${RUN_ID}"
PINA="${PIN_BASE}/wg-mix-ebpf-${NSA}"
PINB="${PIN_BASE}/wg-mix-ebpf-${NSB}"
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
  if [[ "${KEEP_TMP_ON_FAIL:-0}" == "1" && "${status}" -ne 0 ]]; then
    echo "keeping smoke temp dir after failure: ${TMPDIR}" >&2
    return "${status}"
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
  rm -rf "${PIN_BASE}"
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

timeout -s INT 12 ip netns exec "${NSR}" tcpdump -i ra0 -w "${TMPDIR}/ra.pcap" udp >/dev/null 2>"${TMPDIR}/tcpdump-ra.log" &
TCPDUMP_RA=$!
timeout -s INT 12 ip netns exec "${NSR}" tcpdump -i rb0 -w "${TMPDIR}/rb.pcap" udp >/dev/null 2>"${TMPDIR}/tcpdump-rb.log" &
TCPDUMP_RB=$!
sleep 1

wait_ping "${NSA}" 10.77.0.2
wait_ping "${NSB}" 10.77.0.1

wait "${TCPDUMP_RA}" || true
wait "${TCPDUMP_RB}" || true

python3 "${ROOT}/scripts/check-wg-pcap.py" \
  --forbid-standard \
  --require-mixed initiation,response,transport \
  "${TMPDIR}/ra.pcap" "${TMPDIR}/rb.pcap"

run_agent_in_netns "${NSA}" "${PINA}" status --config "${TMPDIR}/agent-a.yaml" >"${TMPDIR}/status-a-after.json"
run_agent_in_netns "${NSB}" "${PINB}" status --config "${TMPDIR}/agent-b.yaml" >"${TMPDIR}/status-b-after.json"

python3 - "$TMPDIR/status-a-after.json" "$TMPDIR/status-b-after.json" <<'PY'
import json
import sys

required_zero = ("checksum_error", "skb_load_error", "skb_store_error")
required_positive = ("egress_rewrite_ok", "ingress_rewrite_ok")
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

echo "netns WireGuard + eBPF ${OUTER_FAMILY} smoke passed"
