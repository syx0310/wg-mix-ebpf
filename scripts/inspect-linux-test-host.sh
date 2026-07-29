#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage:
  sudo scripts/inspect-linux-test-host.sh \
    --expected-address 192.168.10.82 \
    --interface ens33 \
    --peer-address 47.116.202.155

This script is read-only. It records host, interface, TC, BPF, WireGuard,
offload, routing, and project-specific nftables state.
EOF
}

EXPECTED_ADDRESS=""
INTERFACE=""
PEER_ADDRESS=""

while (($# > 0)); do
  case "$1" in
  --expected-address)
    (($# >= 2)) || {
      echo "error: --expected-address requires a value" >&2
      exit 2
    }
    EXPECTED_ADDRESS="$2"
    shift 2
    ;;
  --interface)
    (($# >= 2)) || {
      echo "error: --interface requires a value" >&2
      exit 2
    }
    INTERFACE="$2"
    shift 2
    ;;
  --peer-address)
    (($# >= 2)) || {
      echo "error: --peer-address requires a value" >&2
      exit 2
    }
    PEER_ADDRESS="$2"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "error: unknown argument: $1" >&2
    usage >&2
    exit 2
    ;;
  esac
done

[[ "${EXPECTED_ADDRESS}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || {
  echo "error: a literal IPv4 --expected-address is required" >&2
  exit 2
}
[[ "${PEER_ADDRESS}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || {
  echo "error: a literal IPv4 --peer-address is required" >&2
  exit 2
}
[[ "${INTERFACE}" =~ ^[[:alnum:]_.-]{1,64}$ ]] || {
  echo "error: invalid interface name" >&2
  exit 2
}
[[ "${EUID}" -eq 0 ]] || {
  echo "error: inspection must run as root through an explicitly reviewed sudo command" >&2
  exit 1
}

for command in bpftool ethtool find findmnt ip nft ss stat tc wg; do
  if ! command -v "${command}" >/dev/null; then
    printf 'required_command_missing=%s\n' "${command}"
  fi
done

if ! ip -o -4 address show dev "${INTERFACE}" |
  awk -v expected="${EXPECTED_ADDRESS}" '
    {
      split($4, address, "/")
      if (address[1] == expected) {
        found = 1
      }
    }
    END { exit !found }
  '; then
  echo "error: ${INTERFACE} does not own ${EXPECTED_ADDRESS}" >&2
  exit 1
fi

run_optional() {
  local label="$1"
  local rc
  shift

  printf '\nsection=%q\ncommand=' "${label}"
  printf ' %q' "$@"
  printf '\n'
  if ! command -v "$1" >/dev/null; then
    printf 'exit=127 missing_command=%q\n' "$1"
    return 0
  fi

  set +e
  "$@" 2>&1
  rc=$?
  set -e
  printf 'exit=%d\n' "${rc}"
}

printf 'timestamp=%s\n' "$(date --iso-8601=seconds)"
printf 'mode=read-only\n'
printf 'hostname=%s\n' "$(hostname)"
printf 'identity=%s\n' "$(id)"
printf 'expected_address=%s\n' "${EXPECTED_ADDRESS}"
printf 'interface=%s\n' "${INTERFACE}"
printf 'peer_address=%s\n' "${PEER_ADDRESS}"
printf 'kernel=%s\n' "$(uname -r)"
printf 'machine_id=%s\n' "$(< /etc/machine-id)"
printf 'boot_id=%s\n' "$(< /proc/sys/kernel/random/boot_id)"

run_optional "OS release" cat /etc/os-release
run_optional "interface details" ip -details -statistics link show dev "${INTERFACE}"
run_optional "interface IPv4 addresses" ip -4 address show dev "${INTERFACE}"
run_optional "interface IPv6 addresses" ip -6 address show dev "${INTERFACE}"
run_optional "interface sysfs target" readlink -f "/sys/class/net/${INTERFACE}"
run_optional "interface driver" ethtool -i "${INTERFACE}"
run_optional "interface features" ethtool -k "${INTERFACE}"
run_optional "interface statistics" ethtool -S "${INTERFACE}"
run_optional "route to peer" ip route get "${PEER_ADDRESS}"
run_optional "IPv4 routes" ip -4 route show table all
run_optional "IPv6 routes" ip -6 route show table all
run_optional "policy rules" ip rule show
run_optional "network namespaces" ip netns list
run_optional "UDP listeners" ss -H -lunp
run_optional "qdisc" tc -details -statistics qdisc show dev "${INTERFACE}"
run_optional "ingress filters" tc -details -statistics filter show dev "${INTERFACE}" ingress
run_optional "egress filters" tc -details -statistics filter show dev "${INTERFACE}" egress
run_optional "bpffs mount" findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS /sys/fs/bpf
run_optional "bpffs metadata" stat -c '%F %a %u:%g %n' /sys/fs/bpf
run_optional "bpffs top-level entries" \
  find /sys/fs/bpf -xdev -mindepth 1 -maxdepth 1 -printf '%y %p\n'
run_optional "project BPF entries" \
  find /sys/fs/bpf -xdev -mindepth 1 -maxdepth 4 -name '*wg-mix-ebpf*' -printf '%y %p\n'
run_optional "BPF programs" bpftool -j prog show
run_optional "BPF maps" bpftool -j map show
run_optional "BPF links" bpftool -j link show
run_optional "WireGuard status" wg show
run_optional "project nftables table" nft list table inet wg_mix_ebpf_guard

echo "inspection completed"
