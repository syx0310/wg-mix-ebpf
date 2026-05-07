#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/bin/wg-mix-ebpf"
BPF_OBJECT="${ROOT}/build/wg_mix_tc.o"

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
if [[ ! -f "${BPF_OBJECT}" ]]; then
  echo "error: missing BPF object: ${BPF_OBJECT}" >&2
  exit 1
fi

RUN_ID="${RUN_ID:-$(printf '%x' "$$")}"
NSA="wme${RUN_ID}a"
NSR="wme${RUN_ID}r"
NSB="wme${RUN_ID}b"
TMPDIR="$(mktemp -d /tmp/wg-mix-ebpf-smoke.XXXXXX)"
umask 077

cleanup() {
  set +e
  if ip netns list | awk '{print $1}' | grep -qx "${NSA}"; then
    ip netns exec "${NSA}" env WG_MIX_EBPF_OBJECT="${BPF_OBJECT}" "${BIN}" detach --config "${TMPDIR}/agent-a.yaml" >/dev/null 2>&1
  fi
  if ip netns list | awk '{print $1}' | grep -qx "${NSB}"; then
    ip netns exec "${NSB}" env WG_MIX_EBPF_OBJECT="${BPF_OBJECT}" "${BIN}" detach --config "${TMPDIR}/agent-b.yaml" >/dev/null 2>&1
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

ip netns exec "${NSA}" env WG_MIX_EBPF_OBJECT="${BPF_OBJECT}" "${BIN}" reload --config "${TMPDIR}/agent-a.yaml"
ip netns exec "${NSB}" env WG_MIX_EBPF_OBJECT="${BPF_OBJECT}" "${BIN}" reload --config "${TMPDIR}/agent-b.yaml"

timeout -s INT 12 ip netns exec "${NSR}" tcpdump -i ra0 -w "${TMPDIR}/ra.pcap" udp >/dev/null 2>"${TMPDIR}/tcpdump-ra.log" &
TCPDUMP_RA=$!
timeout -s INT 12 ip netns exec "${NSR}" tcpdump -i rb0 -w "${TMPDIR}/rb.pcap" udp >/dev/null 2>"${TMPDIR}/tcpdump-rb.log" &
TCPDUMP_RB=$!
sleep 1

ip netns exec "${NSA}" ping -c 3 -W 2 10.77.0.2 >/dev/null
ip netns exec "${NSB}" ping -c 3 -W 2 10.77.0.1 >/dev/null

wait "${TCPDUMP_RA}" || true
wait "${TCPDUMP_RB}" || true

python3 - "${TMPDIR}/ra.pcap" "${TMPDIR}/rb.pcap" <<'PY'
import struct
import sys

STANDARD = {
    b"\x01\x00\x00\x00",
    b"\x02\x00\x00\x00",
    b"\x03\x00\x00\x00",
    b"\x04\x00\x00\x00",
}
MIXED = {
    b"\xe6\xc2\x58\xf6",
    b"\xd0\xb1\x86\x06",
    b"\xe0\xe5\x5a\x07",
    b"\x6b\xf0\xdf\x13",
}

def parse_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise SystemExit(f"unsupported pcap magic in {path}: {magic!r}")
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0xffff
    if linktype != 1:
        raise SystemExit(f"unsupported linktype in {path}: {linktype}")
    off = 24
    words = []
    while off + 16 <= len(data):
        _sec, _usec, incl_len, _orig_len = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl_len]
        off += incl_len
        word = first_udp_payload_word(pkt)
        if word is not None:
            words.append(word)
    return words

def first_udp_payload_word(pkt):
    if len(pkt) < 14:
        return None
    eth_type = int.from_bytes(pkt[12:14], "big")
    off = 14
    for _ in range(2):
        if eth_type not in (0x8100, 0x88a8):
            break
        if len(pkt) < off + 4:
            return None
        eth_type = int.from_bytes(pkt[off + 2:off + 4], "big")
        off += 4
    if eth_type == 0x0800:
        if len(pkt) < off + 20:
            return None
        ihl = (pkt[off] & 0x0f) * 4
        if len(pkt) < off + ihl + 12 or pkt[off + 9] != 17:
            return None
        udp = off + ihl
    elif eth_type == 0x86DD:
        if len(pkt) < off + 40 or pkt[off + 6] != 17:
            return None
        udp = off + 40
    else:
        return None
    payload = udp + 8
    if len(pkt) < payload + 4:
        return None
    return pkt[payload:payload + 4]

words = []
for path in sys.argv[1:]:
    words.extend(parse_pcap(path))

standard = sum(1 for w in words if w in STANDARD)
mixed = sum(1 for w in words if w in MIXED)
print(f"pcap_udp_payload_words={len(words)} mixed_type_words={mixed} standard_type_words={standard}")
if mixed == 0:
    raise SystemExit("no mixed WireGuard type_word observed in router pcap")
if standard != 0:
    raise SystemExit("standard WireGuard type_word leaked in router pcap")
PY

echo "netns WireGuard + eBPF smoke passed"
