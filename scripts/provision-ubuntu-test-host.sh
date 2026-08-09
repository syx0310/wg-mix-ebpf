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

readonly SUPPORTED_KERNEL='7.0.0-28-generic'
readonly -a CLEAN_ENV=(
  /usr/bin/env -i
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  LC_ALL=C
)
readonly -a APT_COMMAND=(
  "${CLEAN_ENV[@]}" APT_LISTCHANGES_FRONTEND=none
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
  /usr/bin/apt-get
  -o Acquire::Retries=2 -o Acquire::http::Timeout=30
  -o Acquire::https::Timeout=30
  -o APT::Get::List-Cleanup=0
)
readonly -a APT_INSTALL_FLAGS=(--no-install-recommends --no-remove --no-upgrade)
readonly -a BPFTOOL_VERSION_COMMAND=(
  "${CLEAN_ENV[@]}" /usr/sbin/bpftool -V
)
readonly -a PACKAGES=(
  binutils
  bpftool
  ca-certificates
  clang
  dwarves
  ethtool
  gcc
  git
  golang-go
  iperf3
  iproute2
  iputils-ping
  jq
  kmod
  libbpf-dev
  libc6-dev
  "linux-headers-${SUPPORTED_KERNEL}"
  linux-libc-dev
  llvm
  make
  nftables
  pkg-config
  procps
  python3
  shellcheck
  tcpdump
  util-linux
  wireguard-tools
)

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
  "${CLEAN_ENV[@]}" /usr/bin/awk '
    function is_boot_package(package) {
      return package ~ /^(grub|initramfs-tools|linux-image-|linux-modules-|shim-signed|systemd-boot)/
    }
    $1 == "Remv" || $1 == "Purg" { unsafe = 1 }
    $1 == "Inst" {
      package = $2
      if ($0 ~ /^Inst [^ ]+ \[[^]]+\]/ || is_boot_package(package) ||
          $0 !~ /^Inst [^ ]+ \(/) {
        unsafe = 1
      } else {
        fresh[package] = 1
        saw_fresh = 1
      }
    }
    $1 == "Conf" {
      package = $2
      configured[package] = 1
      if (is_boot_package(package) || $0 !~ /^Conf [^ ]+ \(/) {
        unsafe = 1
      }
    }
    END {
      for (package in configured) {
        if (!(package in fresh)) unsafe = 1
      }
      if (!saw_fresh) unsafe = 1
      exit !unsafe
    }
  '
}

dpkg_status_has_pending_work() {
  "${CLEAN_ENV[@]}" /usr/bin/awk -F '\t' '
    {
      seen = 1
      status = $1
      if (NF != 2 || (status != "ii " && status != "hi " &&
          status != "rc " && status != "pn " && status != "un ")) {
        dirty = 1
      }
    }
    END { exit !(dirty || !seen) }
  '
}

run_required_probe() {
  "$@"
}

if [[ "${MODE}" == "self-test" ]]; then
  for fixture in 'Inst new-package (1.0 repository)' \
    'Inst linux-headers-7.0.0-28-generic (1.0 repository)' \
    $'Inst clang (1.0 repository)\nConf clang (1.0 repository)'; do
    if apt_plan_has_forbidden_changes <<<"${fixture}"; then
      echo "error: safe package fixture was rejected: ${fixture}" >&2
      exit 1
    fi
  done
  for fixture in 'Inst existing-package [1.0] (1.1 repository)' \
    'Remv existing-package [1.0]' 'Purg existing-package [1.0]' \
    'Inst grub-pc (1.0 repository)' \
    'Inst initramfs-tools-core (1.0 repository)' \
    'Inst linux-image-7.0.0-29-generic (1.0 repository)' \
    'Inst linux-modules-extra-7.0.0-29-generic (1.0 repository)' \
    'Inst shim-signed (1.0 repository)' \
    'Inst systemd-boot-efi (1.0 repository)' \
    'Conf existing-package (1.1 repository)' \
    'Conf grub-pc (1.0 repository)' \
    'Conf initramfs-tools-core (1.0 repository)' \
    'Conf linux-image-7.0.0-29-generic (1.0 repository)' \
    'Conf linux-modules-extra-7.0.0-29-generic (1.0 repository)' \
    'Conf shim-signed (1.0 repository)' \
    'Conf systemd-boot-efi (1.0 repository)' ''; do
    if ! apt_plan_has_forbidden_changes <<<"${fixture}"; then
      echo "error: unsafe package fixture was accepted: ${fixture}" >&2
      exit 1
    fi
  done
  if dpkg_status_has_pending_work <<< $'ii \tbase-files\nhi \theld-package\nrc \tremoved-package\npn \tpurged-package\nun \tunknown-package'; then
    echo 'error: stable dpkg status fixture was rejected' >&2
    exit 1
  fi
  for fixture in $'iU \tunpacked-package' $'iF \thalf-configured-package' \
    $'it \ttriggers-pending-package' $'iW \ttriggers-awaited-package' \
    $'iH \thalf-installed-package' $'iiR\treinst-required-package' \
    $'ri \tremove-pending-package' $'pi \tpurge-pending-package' \
    $'in \tinstall-pending-package' $'uc \tunknown-config-package' ''; do
    if ! dpkg_status_has_pending_work <<<"${fixture}"; then
      echo "error: incomplete dpkg status fixture was accepted: ${fixture}" >&2
      exit 1
    fi
  done
  if [[ "${BPFTOOL_VERSION_COMMAND[*]}" != \
    '/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/sbin/bpftool -V' ]]; then
    echo 'error: bpftool version probe argv drifted' >&2
    exit 1
  fi
  run_required_probe /usr/bin/true || {
    echo 'error: successful required probe was rejected' >&2
    exit 1
  }
  if run_required_probe /usr/bin/false; then
    echo 'error: failed required probe was accepted' >&2
    exit 1
  fi
  echo "APT/dpkg safety gate self-test passed"
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
[[ "${EXPECTED_KERNEL}" == "${SUPPORTED_KERNEL}" ]] || {
  echo "error: this locked provisioner only supports kernel ${SUPPORTED_KERNEL}" >&2
  exit 2
}
[[ "${EXPECTED_MACHINE_ID}" =~ ^[0-9a-f]{32}$ ]] || {
  echo "error: --expected-machine-id must be exactly 32 lowercase hex characters" >&2
  exit 2
}

for path in /usr/bin/apt-get /usr/bin/awk /usr/bin/date /usr/bin/dpkg-query \
  /usr/bin/env /usr/bin/grep /usr/bin/hostname /usr/bin/id /usr/bin/readlink \
  /usr/bin/sed /usr/bin/sort /usr/bin/stat /usr/bin/systemctl /usr/bin/uname \
  /usr/sbin/ip; do
  [[ -x "${path}" ]] || {
    echo "error: required fixed base command is missing: ${path}" >&2
    exit 1
  }
done

os_release_field() {
  "${CLEAN_ENV[@]}" /usr/bin/awk -F= -v key="$1" '
    $1 == key {
      value = $2
      sub(/^"/, "", value)
      sub(/"$/, "", value)
      print value
      found = 1
    }
    END { if (!found) exit 1 }
  ' /etc/os-release
}

if ! "${CLEAN_ENV[@]}" /usr/sbin/ip -o -4 address show dev "${EXPECTED_INTERFACE}" |
  "${CLEAN_ENV[@]}" /usr/bin/awk -v expected="${EXPECTED_ADDRESS}" '
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

HOSTNAME_VALUE="$("${CLEAN_ENV[@]}" /usr/bin/hostname)"
[[ "${HOSTNAME_VALUE}" == "${EXPECTED_HOSTNAME}" ]] || {
  echo "error: hostname identity mismatch" >&2
  exit 1
}
[[ "$(< /etc/machine-id)" == "${EXPECTED_MACHINE_ID}" ]] || {
  echo "error: machine-id identity mismatch" >&2
  exit 1
}

OS_ID="$(os_release_field ID)"
OS_VERSION="$(os_release_field VERSION_ID)"
[[ "${OS_ID}" == "ubuntu" && "${OS_VERSION}" == "26.04" ]] || {
  echo "error: expected Ubuntu 26.04, got ${OS_ID:-unknown} ${OS_VERSION:-unknown}" >&2
  exit 1
}

KERNEL_RELEASE="$("${CLEAN_ENV[@]}" /usr/bin/uname -r)"
[[ "${KERNEL_RELEASE}" == "${EXPECTED_KERNEL}" ]] || {
  echo "error: expected kernel ${EXPECTED_KERNEL}, got ${KERNEL_RELEASE}" >&2
  exit 1
}

package_is_installed() {
  local status
  status="$("${CLEAN_ENV[@]}" /usr/bin/dpkg-query -W \
    -f='${db:Status-Abbrev}' "$1" 2>/dev/null)" || return 1
  [[ "${status}" == 'ii ' || "${status}" == 'hi ' ]]
}

collect_missing_packages() {
  local package
  missing=()
  for package in "${PACKAGES[@]}"; do
    package_is_installed "${package}" || missing+=("${package}")
  done
}

quote_argv() {
  printf ' %q' "$@"
}

plan_command() {
  local label="$1"
  shift
  printf 'plan_command=%s argv=' "${label}"
  quote_argv "$@"
  printf '\n'
}

render_plan() {
  printf 'plan_packages_count=%d plan_packages=' "${#PACKAGES[@]}"
  quote_argv "${PACKAGES[@]}"
  printf '\n'
  printf '%s\n' \
    'write_scope=/var/lib/apt/lists /var/cache/apt (no explicit list/cache cleanup)' \
    'write_scope=/var/lib/dpkg /var/log/apt /var/log/dpkg.log /var/cache/debconf' \
    'write_scope=fixed-package-owned/generated files under /usr /etc /var/lib /lib/modules' \
    "write_scope=/usr/src/linux-headers-${SUPPORTED_KERNEL} and /lib/modules/${SUPPORTED_KERNEL}/build" \
    'excluded_write_scope=/etc/apt/sources.list /etc/apt/sources.list.d /boot bootloader initramfs running-kernel network-state'
  if ((${#missing[@]} > 0)); then
    plan_command A0 "${APT_COMMAND[@]}" update
    plan_command A1 "${APT_COMMAND[@]}" --simulate "${APT_INSTALL_FLAGS[@]}" \
      install "${missing[@]}"
    plan_command A2 "${APT_COMMAND[@]}" --assume-yes "${APT_INSTALL_FLAGS[@]}" \
      install "${missing[@]}"
  else
    printf 'plan_apt_commands=skipped reason=fixed-package-set-already-installed\n'
  fi
  printf 'postcheck=packages; executables; exact headers/build link; BTF; libbpf metadata; clang BPF target\n'
  printf 'plan_complete planned_commands_executed=0 writes=0 automatic_cleanup=0\n'
}

service_snapshot() {
  local active enabled
  active="$("${CLEAN_ENV[@]}" /usr/bin/systemctl list-units --type=service \
    --state=active --no-legend --no-pager --plain)" || return $?
  enabled="$("${CLEAN_ENV[@]}" /usr/bin/systemctl list-unit-files --type=service \
    --state=enabled,enabled-runtime --no-legend --no-pager)" || return $?
  active="$("${CLEAN_ENV[@]}" /usr/bin/awk 'NF {print "active " $1}' \
    <<<"${active}")" || return $?
  enabled="$("${CLEAN_ENV[@]}" /usr/bin/awk 'NF {print $2 " " $1}' \
    <<<"${enabled}")" || return $?
  printf '%s\n%s\n' "${active}" "${enabled}" |
    "${CLEAN_ENV[@]}" /usr/bin/sort
}

run_logged_write() {
  local description="$1" targets="$2" status
  shift 2
  printf 'write_start timestamp=%s description=%q targets=%q argv=' \
    "$(/usr/bin/date --iso-8601=seconds)" "${description}" "${targets}"
  quote_argv "$@"
  printf '\n'
  if "$@"; then
    status=0
  else
    status=$?
  fi
  printf 'write_finish timestamp=%s description=%q exit=%d\n' \
    "$(/usr/bin/date --iso-8601=seconds)" "${description}" "${status}"
  return "${status}"
}

run_logged_capture() {
  local destination="$1" description="$2" output status
  shift 2
  printf 'command_start timestamp=%s description=%q argv=' \
    "$(/usr/bin/date --iso-8601=seconds)" "${description}"
  quote_argv "$@"
  printf '\n'
  if output="$("$@" 2>&1)"; then
    status=0
  else
    status=$?
  fi
  printf 'command_finish timestamp=%s description=%q exit=%d\n' \
    "$(/usr/bin/date --iso-8601=seconds)" "${description}" "${status}"
  if ((status != 0)); then
    printf 'command_output_begin description=%q\n%s\ncommand_output_end\n' \
      "${description}" "${output}" >&2
  fi
  printf -v "${destination}" '%s' "${output}"
  return "${status}"
}

verify_clean_dpkg_state() {
  local states
  run_logged_capture states 'verify dpkg package states' \
    "${CLEAN_ENV[@]}" /usr/bin/dpkg-query -W \
    -f='${db:Status-Abbrev}\t${binary:Package}\n' || return $?
  if dpkg_status_has_pending_work <<<"${states}"; then
    echo 'error: dpkg has an unpacked, half-configured, trigger-pending, or otherwise incomplete package' >&2
    return 1
  fi
  printf 'verified_dpkg_state=clean\n'
}

verify_installed_toolchain() {
  local executable build_target clang_targets
  collect_missing_packages
  if ((${#missing[@]} > 0)); then
    printf 'error: fixed package set remains incomplete:' >&2
    quote_argv "${missing[@]}" >&2
    printf '\n' >&2
    return 1
  fi
  for executable in \
    /usr/bin/clang /usr/bin/gcc /usr/bin/git /usr/bin/go /usr/bin/iperf3 \
    /usr/bin/findmnt /usr/bin/jq /usr/bin/ld /usr/bin/llvm-config /usr/bin/make \
    /usr/bin/nsenter /usr/bin/objdump /usr/bin/pahole /usr/bin/ping \
    /usr/bin/pkg-config /usr/bin/python3 /usr/bin/readelf /usr/bin/shellcheck \
    /usr/bin/tcpdump /usr/bin/unshare /usr/bin/wg /usr/sbin/bpftool \
    /usr/sbin/ethtool /usr/sbin/insmod /usr/sbin/ip /usr/sbin/lsmod \
    /usr/sbin/nft /usr/sbin/rmmod /usr/sbin/sysctl /usr/sbin/tc; do
    [[ -x "${executable}" ]] || {
      echo "error: required executable is missing: ${executable}" >&2
      return 1
    }
  done
  if [[ ! -r /usr/include/bpf/bpf_helpers.h || ! -r /sys/kernel/btf/vmlinux ||
    ! -d "/usr/src/linux-headers-${SUPPORTED_KERNEL}" ]]; then
    echo 'error: libbpf headers, running-kernel BTF, or exact kernel headers are unavailable' >&2
    return 1
  fi
  build_target="$("${CLEAN_ENV[@]}" /usr/bin/readlink -e -- \
    "/lib/modules/${SUPPORTED_KERNEL}/build")" || return 1
  [[ "${build_target}" == "/usr/src/linux-headers-${SUPPORTED_KERNEL}" ]] || {
    echo "error: running-kernel build link resolves to ${build_target}" >&2
    return 1
  }
  "${CLEAN_ENV[@]}" /usr/bin/pkg-config --exists libbpf || return 1
  clang_targets="$("${CLEAN_ENV[@]}" /usr/bin/clang --print-targets)" || return 1
  if ! "${CLEAN_ENV[@]}" /usr/bin/grep -Eq \
    '(^|[[:space:]])bpf([[:space:]-]|$)' <<<"${clang_targets}"; then
    echo 'error: clang does not advertise the BPF target' >&2
    return 1
  fi
  "${CLEAN_ENV[@]}" /usr/bin/go version
  "${CLEAN_ENV[@]}" /usr/bin/clang --version | "${CLEAN_ENV[@]}" /usr/bin/sed -n '1p'
  "${BPFTOOL_VERSION_COMMAND[@]}" || {
    echo 'error: bpftool fixed version probe failed' >&2
    return 1
  }
  printf 'verified_header_dir=/usr/src/linux-headers-%s verified_build_link=%s verified_btf=/sys/kernel/btf/vmlinux\n' \
    "${SUPPORTED_KERNEL}" "${build_target}"
}

printf 'timestamp=%s\n' "$(/usr/bin/date --iso-8601=seconds)"
printf 'hostname=%s\n' "${HOSTNAME_VALUE}"
printf 'identity=%s\n' "$("${CLEAN_ENV[@]}" /usr/bin/id)"
printf 'expected_address=%s\n' "${EXPECTED_ADDRESS}"
printf 'expected_interface=%s\n' "${EXPECTED_INTERFACE}"
printf 'expected_hostname=%s\n' "${EXPECTED_HOSTNAME}"
printf 'expected_kernel=%s\n' "${EXPECTED_KERNEL}"
printf 'expected_machine_id=%s\n' "${EXPECTED_MACHINE_ID}"
printf 'os=%s %s\n' "${OS_ID}" "${OS_VERSION}"
printf 'kernel=%s\n' "${KERNEL_RELEASE}"
printf 'mode=%s\n' "${MODE}"
printf 'packages='
quote_argv "${PACKAGES[@]}"
printf '\n'

declare -a missing=()
collect_missing_packages
verify_clean_dpkg_state
printf 'missing_packages='
if ((${#missing[@]} > 0)); then
  quote_argv "${missing[@]}"
fi
printf '\n'
render_plan

if [[ "${MODE}" == "check" ]]; then
  if ((${#missing[@]} == 0)); then
    verify_installed_toolchain
  fi
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: --apply must run as root through an explicitly reviewed sudo command" >&2
  exit 1
fi

if ((${#missing[@]} == 0)); then
  verify_installed_toolchain
  echo "provisioning already satisfied; no writes performed"
  exit 0
fi

services_before="$(service_snapshot)"
run_logged_write \
  "refresh APT package metadata" \
  "/var/lib/apt/lists and /var/cache/apt" \
  "${APT_COMMAND[@]}" update

simulation=''
run_logged_capture simulation 'simulate fixed missing package installation' \
  "${APT_COMMAND[@]}" --simulate "${APT_INSTALL_FLAGS[@]}" \
  install "${missing[@]}"
printf 'apt_simulation_begin\n%s\napt_simulation_end\n' "${simulation}"
if apt_plan_has_forbidden_changes <<<"${simulation}"; then
  echo "error: APT simulation includes a package removal or upgrade" >&2
  exit 1
fi
run_logged_write \
  "install fixed missing CLI/build packages" \
  "/var/lib/dpkg, /var/lib/apt, /var/cache/apt and fixed-package-owned/generated files" \
  "${APT_COMMAND[@]}" --assume-yes "${APT_INSTALL_FLAGS[@]}" install \
  "${missing[@]}"

services_after="$(service_snapshot)"
if [[ "${services_after}" != "${services_before}" ]]; then
  printf 'services_before:\n%s\nservices_after:\n%s\n' \
    "${services_before}" "${services_after}" >&2
  echo "error: provisioning changed the active or enabled service set" >&2
  exit 1
fi

verify_installed_toolchain
echo "provisioning completed"
