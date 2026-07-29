#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage:
  scripts/provision-ubuntu-test-host.sh --self-test-apt-gate

  scripts/provision-ubuntu-test-host.sh --check \
    --expected-address 192.168.10.82 \
    --expected-interface ens33 \
    --expected-hostname ubuntu-2604-test \
    --expected-kernel 7.0.0-28-generic \
    --expected-machine-id 0123456789abcdef0123456789abcdef

  sudo scripts/provision-ubuntu-test-host.sh --apply \
    --expected-address 192.168.10.82 \
    --expected-interface ens33 \
    --expected-hostname ubuntu-2604-test \
    --expected-kernel 7.0.0-28-generic \
    --expected-machine-id 0123456789abcdef0123456789abcdef

The check mode is read-only. Apply mode only updates APT metadata and installs
the fixed CLI/build package list below. It rejects any simulated upgrade or
removal and verifies that active/enabled service sets do not change. iperf3 is
installed from the same Ubuntu APT repositories as the build toolchain.
EOF
}

MODE=""
EXPECTED_ADDRESS=""
EXPECTED_INTERFACE=""
EXPECTED_HOSTNAME=""
EXPECTED_KERNEL=""
EXPECTED_MACHINE_ID=""

while (($# > 0)); do
  case "$1" in
  --self-test-apt-gate)
    [[ -z "${MODE}" ]] || {
      echo "error: select exactly one mode" >&2
      exit 2
    }
    MODE="self-test"
    shift
    ;;
  --check)
    [[ -z "${MODE}" ]] || {
      echo "error: select exactly one mode" >&2
      exit 2
    }
    MODE="check"
    shift
    ;;
  --apply)
    [[ -z "${MODE}" ]] || {
      echo "error: select exactly one mode" >&2
      exit 2
    }
    MODE="apply"
    shift
    ;;
  --expected-address)
    (($# >= 2)) || {
      echo "error: --expected-address requires a value" >&2
      exit 2
    }
    EXPECTED_ADDRESS="$2"
    shift 2
    ;;
  --expected-interface)
    (($# >= 2)) || {
      echo "error: --expected-interface requires a value" >&2
      exit 2
    }
    EXPECTED_INTERFACE="$2"
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

[[ -n "${MODE}" ]] || {
  echo "error: --self-test-apt-gate, --check, or --apply is required" >&2
  exit 2
}

apt_plan_has_forbidden_changes() {
  grep -Eq '^(Remv|Purg) |^Inst [^ ]+ \[[^]]+\]'
}

if [[ "${MODE}" == "self-test" ]]; then
  if printf '%s\n' 'Inst new-package (1.0 repository)' |
    apt_plan_has_forbidden_changes; then
    echo "error: fresh package install was rejected" >&2
    exit 1
  fi
  if ! printf '%s\n' 'Inst existing-package [1.0] (1.1 repository)' |
    apt_plan_has_forbidden_changes; then
    echo "error: package upgrade fixture was accepted" >&2
    exit 1
  fi
  if ! printf '%s\n' 'Remv existing-package [1.0]' |
    apt_plan_has_forbidden_changes; then
    echo "error: package removal fixture was accepted" >&2
    exit 1
  fi
  if ! printf '%s\n' 'Purg existing-package [1.0]' |
    apt_plan_has_forbidden_changes; then
    echo "error: package purge fixture was accepted" >&2
    exit 1
  fi
  echo "APT simulation gate self-test passed"
  exit 0
fi

[[ "${EXPECTED_ADDRESS}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || {
  echo "error: a literal IPv4 --expected-address is required" >&2
  exit 2
}
[[ "${EXPECTED_INTERFACE}" =~ ^[[:alnum:]_.-]{1,64}$ ]] || {
  echo "error: a literal --expected-interface is required" >&2
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

if ! ip -o -4 address show dev "${EXPECTED_INTERFACE}" |
  awk -v expected="${EXPECTED_ADDRESS}" '
    {
      split($4, address, "/")
      if (address[1] == expected) {
        found = 1
      }
    }
    END { exit !found }
  '; then
  echo "error: ${EXPECTED_INTERFACE} does not own ${EXPECTED_ADDRESS}" >&2
  exit 1
fi

[[ "$(hostname)" == "${EXPECTED_HOSTNAME}" ]] || {
  echo "error: hostname identity mismatch" >&2
  exit 1
}
[[ "$(< /etc/machine-id)" == "${EXPECTED_MACHINE_ID}" ]] || {
  echo "error: machine-id identity mismatch" >&2
  exit 1
}

# shellcheck source=/dev/null
. /etc/os-release

[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "26.04" ]] || {
  echo "error: expected Ubuntu 26.04, got ${ID:-unknown} ${VERSION_ID:-unknown}" >&2
  exit 1
}

KERNEL_RELEASE="$(uname -r)"
[[ "${KERNEL_RELEASE}" == "${EXPECTED_KERNEL}" ]] || {
  echo "error: expected kernel ${EXPECTED_KERNEL}, got ${KERNEL_RELEASE}" >&2
  exit 1
}

PACKAGES=(
  bpftool
  ca-certificates
  clang
  ethtool
  gcc
  git
  golang-go
  iproute2
  iperf3
  jq
  libbpf-dev
  linux-libc-dev
  llvm
  make
  nftables
  pkg-config
  python3
  shellcheck
  tcpdump
  wireguard-tools
)
EXPECTED_FRESH_MISSING=(
  clang
  gcc
  golang-go
  iperf3
  libbpf-dev
  llvm
  make
  pkg-config
  shellcheck
  wireguard-tools
)
EXPECTED_IPERF_ONLY_MISSING=(
  iperf3
)

printf 'timestamp=%s\n' "$(date --iso-8601=seconds)"
printf 'hostname=%s\n' "$(hostname)"
printf 'identity=%s\n' "$(id)"
printf 'expected_address=%s\n' "${EXPECTED_ADDRESS}"
printf 'expected_interface=%s\n' "${EXPECTED_INTERFACE}"
printf 'expected_hostname=%s\n' "${EXPECTED_HOSTNAME}"
printf 'expected_kernel=%s\n' "${EXPECTED_KERNEL}"
printf 'expected_machine_id=%s\n' "${EXPECTED_MACHINE_ID}"
printf 'os=%s %s\n' "${ID}" "${VERSION_ID}"
printf 'kernel=%s\n' "${KERNEL_RELEASE}"
printf 'mode=%s\n' "${MODE}"
printf 'packages='
printf ' %q' "${PACKAGES[@]}"
printf '\n'

missing=()
for package in "${PACKAGES[@]}"; do
  if ! dpkg-query -W -f='${db:Status-Abbrev}\n' "${package}" 2>/dev/null |
    grep -qx 'ii '; then
    missing+=("${package}")
  fi
done
printf 'missing_packages='
if ((${#missing[@]} > 0)); then
  printf ' %q' "${missing[@]}"
fi
printf '\n'
if ((${#missing[@]} > 0)); then
  if [[ "${missing[*]}" != "${EXPECTED_FRESH_MISSING[*]}" &&
    "${missing[*]}" != "${EXPECTED_IPERF_ONLY_MISSING[*]}" ]]; then
    printf 'error: package state drifted; allowed missing sets are fresh=' >&2
    printf ' %q' "${EXPECTED_FRESH_MISSING[@]}" >&2
    printf ' or post-toolchain=' >&2
    printf ' %q' "${EXPECTED_IPERF_ONLY_MISSING[@]}" >&2
    printf '\n' >&2
    exit 1
  fi
fi

if [[ "${MODE}" == "check" ]]; then
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: --apply must run as root through an explicitly reviewed sudo command" >&2
  exit 1
fi

for command in apt-get awk grep sort systemctl; do
  command -v "${command}" >/dev/null || {
    echo "error: required provisioning command is missing: ${command}" >&2
    exit 1
  }
done

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

service_snapshot() {
  {
    systemctl list-units --type=service --state=active \
      --no-legend --no-pager --plain |
      awk '{print "active " $1}'
    systemctl list-unit-files --type=service --state=enabled \
      --no-legend --no-pager |
      awk '{print "enabled " $1}'
  } | sort
}

run_logged_write() {
  local description="$1"
  local targets="$2"
  local status
  shift 2

  printf 'write_start timestamp=%s description=%q targets=%q argv=' \
    "$(date --iso-8601=seconds)" "${description}" "${targets}"
  printf ' %q' "$@"
  printf '\n'
  if "$@"; then
    status=0
  else
    status=$?
  fi
  printf 'write_finish timestamp=%s description=%q exit=%d\n' \
    "$(date --iso-8601=seconds)" "${description}" "${status}"
  return "${status}"
}

if ((${#missing[@]} == 0)); then
  echo "provisioning already satisfied; no writes performed"
  exit 0
fi

services_before="$(service_snapshot)"
run_logged_write \
  "refresh APT package metadata" \
  "/var/lib/apt/lists and /var/cache/apt" \
  apt-get update

simulation="$(
  apt-get --simulate --no-remove --no-upgrade --no-install-recommends \
    install "${missing[@]}"
)"
printf 'apt_simulation_begin\n%s\napt_simulation_end\n' "${simulation}"
if apt_plan_has_forbidden_changes <<<"${simulation}"; then
  echo "error: APT simulation includes a package removal or upgrade" >&2
  exit 1
fi

run_logged_write \
  "install fixed missing CLI/build packages" \
  "/var/lib/dpkg, /var/lib/apt, /var/cache/apt and package-owned files" \
  apt-get install -y --no-remove --no-upgrade --no-install-recommends \
  "${missing[@]}"

services_after="$(service_snapshot)"
if [[ "${services_after}" != "${services_before}" ]]; then
  printf 'services_before:\n%s\nservices_after:\n%s\n' \
    "${services_before}" "${services_after}" >&2
  echo "error: provisioning changed the active or enabled service set" >&2
  exit 1
fi

for package in "${missing[@]}"; do
  if ! dpkg-query -W -f='${db:Status-Abbrev}\n' "${package}" 2>/dev/null |
    grep -qx 'ii '; then
    echo "error: package was not installed successfully: ${package}" >&2
    exit 1
  fi
done

for command in bpftool clang ethtool gcc git go ip iperf3 jq make nft \
  python3 shellcheck tc tcpdump wg; do
  printf '%s=%s\n' "${command}" "$(command -v "${command}")"
done

go version
clang --version | sed -n '1p'
bpftool version
echo "provisioning completed"
