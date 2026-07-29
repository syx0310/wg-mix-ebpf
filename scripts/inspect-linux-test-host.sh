#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage:
  sudo scripts/inspect-linux-test-host.sh \
    --expected-address 192.168.10.82 \
    --interface ens33 \
    --peer-address 47.116.202.155 \
    --expected-hostname ubuntu-2604-test \
    --expected-kernel 7.0.0-28-generic \
    --expected-machine-id 0123456789abcdef0123456789abcdef \
    [--allow-missing-bpftool]

This script is read-only. It records host, interface, TC, BPF, WireGuard,
offload, routing, and project-specific nftables state.
EOF
}

EXPECTED_ADDRESS=""
INTERFACE=""
PEER_ADDRESS=""
EXPECTED_HOSTNAME=""
EXPECTED_KERNEL=""
EXPECTED_MACHINE_ID=""
ALLOW_MISSING_BPFTOOL=0

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
  --expected-hostname)
    (($# >= 2)) || {
      echo "error: --expected-hostname requires a value" >&2
      exit 2
    }
    EXPECTED_HOSTNAME="$2"
    shift 2
    ;;
  --expected-kernel)
    (($# >= 2)) || {
      echo "error: --expected-kernel requires a value" >&2
      exit 2
    }
    EXPECTED_KERNEL="$2"
    shift 2
    ;;
  --expected-machine-id)
    (($# >= 2)) || {
      echo "error: --expected-machine-id requires a value" >&2
      exit 2
    }
    EXPECTED_MACHINE_ID="$2"
    shift 2
    ;;
  --allow-missing-bpftool)
    ALLOW_MISSING_BPFTOOL=1
    shift
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
[[ "${EXPECTED_HOSTNAME}" =~ ^[[:alnum:].-]{1,253}$ ]] || {
  echo "error: a literal --expected-hostname is required" >&2
  exit 2
}
[[ "${EXPECTED_KERNEL}" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[[:alnum:].+-]+$ ]] || {
  echo "error: a literal --expected-kernel is required" >&2
  exit 2
}
[[ "${EXPECTED_MACHINE_ID}" =~ ^[0-9a-f]{32}$ ]] || {
  echo "error: --expected-machine-id must be exactly 32 lowercase hex characters" >&2
  exit 2
}
[[ "${EUID}" -eq 0 ]] || {
  echo "error: inspection must run as root through an explicitly reviewed sudo command" >&2
  exit 1
}

for command in ethtool find findmnt grep ip nft ss stat tc wg; do
  command -v "${command}" >/dev/null || {
    printf 'error: required command is missing: %s\n' "${command}" >&2
    exit 1
  }
done
if ! command -v bpftool >/dev/null; then
  if ((ALLOW_MISSING_BPFTOOL)); then
    echo "unsupported_missing_command=bpftool"
  else
    echo "error: required command is missing: bpftool" >&2
    exit 1
  fi
fi

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

[[ "$(hostname)" == "${EXPECTED_HOSTNAME}" ]] || {
  echo "error: hostname identity mismatch" >&2
  exit 1
}
[[ "$(uname -r)" == "${EXPECTED_KERNEL}" ]] || {
  echo "error: kernel identity mismatch" >&2
  exit 1
}
[[ "$(< /etc/machine-id)" == "${EXPECTED_MACHINE_ID}" ]] || {
  echo "error: machine-id identity mismatch" >&2
  exit 1
}

declare -a INSPECTION_FAILURES=()

run_optional() {
  local label="$1"
  local rc
  shift

  printf '\nsection=%q\ncommand=' "${label}"
  printf ' %q' "$@"
  printf '\n'
  if ! command -v "$1" >/dev/null; then
    printf 'exit=127 missing_command=%q\n' "$1"
    INSPECTION_FAILURES+=("${label}:missing-command")
    return 0
  fi

  set +e
  "$@" 2>&1
  rc=$?
  set -e
  printf 'exit=%d\n' "${rc}"
  if ((rc != 0)); then
    INSPECTION_FAILURES+=("${label}:exit-${rc}")
  fi
}

printf 'timestamp=%s\n' "$(date --iso-8601=seconds)"
printf 'mode=read-only\n'
printf 'hostname=%s\n' "$(hostname)"
printf 'identity=%s\n' "$(id)"
printf 'expected_address=%s\n' "${EXPECTED_ADDRESS}"
printf 'interface=%s\n' "${INTERFACE}"
printf 'peer_address=%s\n' "${PEER_ADDRESS}"
printf 'kernel=%s\n' "$(uname -r)"
printf 'allow_missing_bpftool=%s\n' "${ALLOW_MISSING_BPFTOOL}"
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
if command -v bpftool >/dev/null; then
  run_optional "BPF programs" bpftool -j prog show
  run_optional "BPF maps" bpftool -j map show
  run_optional "BPF links" bpftool -j link show
fi
run_optional "WireGuard status" wg show
run_optional "nftables tables" nft list tables

nft_tables="$(nft list tables)"
if grep -Fxq 'table inet wg_mix_ebpf_guard' <<<"${nft_tables}"; then
  INSPECTION_FAILURES+=("unexpected-project-nftables-table")
fi

if ((${#INSPECTION_FAILURES[@]} > 0)); then
  printf 'inspection_failed=' >&2
  printf ' %q' "${INSPECTION_FAILURES[@]}" >&2
  printf '\n' >&2
  exit 1
fi

echo "inspection completed: all required sections passed"
