#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' \
    'error: B82 production performance runner requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly STAGED_NAME="scripts/run-b82-production-performance-cell.sh"
readonly BIN_NAME="bin/wg-mix-ebpf"
readonly BASELINE_OBJECT_NAME="build/wg_mix_tc.o"
readonly FAKETCP_OBJECT_NAME="build/wg_mix_faketcp_experimental.o"
readonly FAKETCP_LEGACY_OBJECT_NAME="build/wg_mix_faketcp_legacy_515.o"
readonly IPERF_CHECKER_NAME="scripts/check-iperf3-tcp.py"
run_parent="${WG_MIX_EBPF_PERFORMANCE_RUN_PARENT-/var/tmp/wg-mix-ebpf-performance-tests}"
unset WG_MIX_EBPF_PERFORMANCE_RUN_PARENT
if [[ "${run_parent}" != "/var/tmp/wg-mix-ebpf-performance-tests" &&
  ! "${run_parent}" =~ ^/var/tmp/wg-mix-ebpf-performance-tests/[0-9a-f]{8}/children$ ]]; then
  echo "error: performance child run parent is outside the reviewed matrix scope" >&2
  exit 1
fi
readonly RUN_PARENT="${run_parent}"
readonly SHARED_RUN_TARGET="/run/wg-mix-ebpf"
readonly SHARED_VAR_TARGET="/var/lib/wg-mix-ebpf"
readonly SHARED_MAINTENANCE_TARGET="/run/.wg-mix-ebpf-daemon.lease.maintenance"
readonly DURATION=3
readonly REPETITIONS=3
readonly FAKETCP_HANDSHAKE_TIMEOUT='1s'
readonly FAKETCP_KEEPALIVE_INTERVAL='2s'
readonly FAKETCP_IDLE_TIMEOUT='6s'
readonly FAKETCP_RECOVERY_ATTEMPTS=15
readonly STREAMS=1
readonly MINIMUM_BYTES=1048576
readonly MAXIMUM_RETRANSMITS=2147483647
readonly MINIMUM_FAIRNESS=0.90
readonly KFUNC_MODULE="wg_mix_faketcp_checksum"
readonly KPROBE_MODULE="wg_mix_faketcp_checksum_kprobe"
readonly KPROBE_DEVICE="/dev/wg_mix_faketcp_checksum_kprobe"

PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB XOR_PASSWORD

if [[ "${EUID}" -ne 0 || "$(/usr/bin/id -g)" -ne 0 ]]; then
  echo "error: run the B82 production performance runner as root" >&2
  exit 1
fi

script_reference="${BASH_SOURCE[0]}"
if [[ "${script_reference}" == /* ]]; then
  script_path="${script_reference}"
elif [[ "${script_reference}" == "${STAGED_NAME}" ]]; then
  script_path="$(builtin pwd -P)/${STAGED_NAME}"
else
  echo "error: production performance runner path is not the fixed staged entry" >&2
  exit 1
fi
source_root="${script_path%/"${STAGED_NAME}"}"
if [[ ! "${source_root}" =~ ^/var/tmp/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]]; then
  echo "error: production performance runner must use a root-owned source stage" >&2
  exit 1
fi

artifact_root="${WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT-${source_root}}"
unset WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT
if [[ "${artifact_root}" != "${source_root}" &&
  ! "${artifact_root}" =~ ^/var/tmp/wg-mix-ebpf-performance-tests/[0-9a-f]{8}/artifacts$ ]]; then
  echo "error: performance artifact root is outside the reviewed matrix scope" >&2
  exit 1
fi
readonly ARTIFACT_ROOT="${artifact_root}"
readonly BIN="${ARTIFACT_ROOT}/${BIN_NAME}"
readonly BASELINE_OBJECT="${ARTIFACT_ROOT}/${BASELINE_OBJECT_NAME}"
readonly FAKETCP_OBJECT="${ARTIFACT_ROOT}/${FAKETCP_OBJECT_NAME}"
readonly FAKETCP_LEGACY_OBJECT="${ARTIFACT_ROOT}/${FAKETCP_LEGACY_OBJECT_NAME}"
readonly IPERF_CHECKER="${source_root}/${IPERF_CHECKER_NAME}"
readonly ARTIFACT_MANIFEST="${ARTIFACT_ROOT%/artifacts}/artifacts.v1"

validate_staged_regular() {
  local path="$1"
  local need_execute="$2"
  local metadata

  if [[ ! -f "${path}" || -L "${path}" ]]; then
    echo "error: staged file is missing or unsafe: ${path}" >&2
    return 1
  fi
  metadata="$(stat -c '%u:%g:%a:%h' -- "${path}")"
  if [[ ! "${metadata}" =~ ^0:0:([0-7]{3,4}):1$ ]]; then
    echo "error: staged file metadata is unsafe: ${path} (${metadata})" >&2
    return 1
  fi
  local mode="${BASH_REMATCH[1]}"
  if (((8#${mode} & 8#22) != 0)); then
    echo "error: staged file is group/world writable: ${path}" >&2
    return 1
  fi
  if [[ "${need_execute}" == "yes" ]] && (((8#${mode} & 8#111) == 0)); then
    echo "error: staged executable has no execute bit: ${path}" >&2
    return 1
  fi
}

validate_staged_regular "${script_path}" yes
validate_staged_regular "${BIN}" yes
validate_staged_regular "${BASELINE_OBJECT}" no
validate_staged_regular "${FAKETCP_OBJECT}" no
validate_staged_regular "${FAKETCP_LEGACY_OBJECT}" no
validate_staged_regular "${IPERF_CHECKER}" no

if [[ "${ARTIFACT_ROOT}" != "${source_root}" ]]; then
  if [[ ! -f "${ARTIFACT_MANIFEST}" || -L "${ARTIFACT_MANIFEST}" ||
    "$(stat -c '%u:%g:%a:%h' -- "${ARTIFACT_MANIFEST}")" != 0:0:600:1 ]]; then
    echo "error: frozen performance artifact manifest is unsafe" >&2
    exit 1
  fi
  python3 - "${ARTIFACT_MANIFEST}" "${ARTIFACT_ROOT}" <<'PY'
import hashlib
import pathlib
import re
import stat
import sys

manifest, root = map(pathlib.Path, sys.argv[1:])
raw = manifest.read_bytes()
if not raw.endswith(b"\n") or b"\0" in raw or b"\r" in raw:
    raise SystemExit("frozen performance artifact manifest is non-canonical")
rows = raw[:-1].decode("ascii", "strict").split("\n")
expected = [
    "bin/wg-mix-ebpf",
    "build/wg_mix_tc.o",
    "build/wg_mix_faketcp_experimental.o",
    "build/wg_mix_faketcp_legacy_515.o",
    "faketcp_checksum_kmod/wg_mix_faketcp_checksum.ko",
    "faketcp_checksum_kprobe_kmod/wg_mix_faketcp_checksum_kprobe.ko",
]
if rows[:1] != ["format=wg-mix-ebpf-performance-artifacts-v1"] or len(rows) != 7:
    raise SystemExit("frozen performance artifact manifest has the wrong schema")
for row, relative in zip(rows[1:], expected, strict=True):
    observed, separator, digest = row.partition("=")
    path = root / relative
    metadata = path.lstat()
    wanted_mode = 0o500 if relative == "bin/wg-mix-ebpf" else 0o400
    if (
        observed != relative
        or separator != "="
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or path.resolve(strict=True) != path
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != wanted_mode
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or hashlib.sha256(path.read_bytes()).hexdigest() != digest
    ):
        raise SystemExit(f"frozen performance artifact differs: {relative}")
PY
fi

validate_run_id() {
  [[ "$1" =~ ^[0-9a-f]{8}$ ]]
}

validate_root_directory() {
  local path="$1"
  local metadata
  [[ "${path}" == /* && "${path}" != "/" && -d "${path}" && ! -L "${path}" ]] || {
    echo "error: required root directory is missing or unsafe: ${path}" >&2
    return 1
  }
  metadata="$(stat -c '%u:%g:%a:%h' -- "${path}")"
  if [[ ! "${metadata}" =~ ^0:0:([0-7]{3,4}):[1-9][0-9]*$ ]]; then
    echo "error: required root directory metadata is unsafe: ${path} (${metadata})" >&2
    return 1
  fi
  local mode="${BASH_REMATCH[1]}"
  if (((8#${mode} & 8#22) != 0)); then
    echo "error: required root directory is group/world writable: ${path}" >&2
    return 1
  fi
}

endpoint_child() {
  local run_id=""
  local role=""
  local transport=""
  local endpoint_command resolved_endpoint_command

  shift
  while (($#)); do
    case "$1" in
      --run-id)
        (($# >= 2)) || return 2
        run_id="$2"
        shift 2
        ;;
      --role)
        (($# >= 2)) || return 2
        role="$2"
        shift 2
        ;;
      --transport)
        (($# >= 2)) || return 2
        transport="$2"
        shift 2
        ;;
      *)
        echo "error: unknown endpoint child argument: $1" >&2
        return 2
        ;;
    esac
  done
  if ! validate_run_id "${run_id}" || [[ ! "${role}" =~ ^(a|b)$ ]] ||
    [[ ! "${transport}" =~ ^(wireguard|udp|icmp|faketcp)$ ]]; then
    echo "error: invalid endpoint child identity" >&2
    return 2
  fi
  for endpoint_command in env ip mount stat awk grep; do
    resolved_endpoint_command="$(command -v "${endpoint_command}")" || {
      echo "error: missing endpoint command: ${endpoint_command}" >&2
      return 1
    }
    if [[ "${resolved_endpoint_command}" != /* ||
      ! -f "${resolved_endpoint_command}" || ! -x "${resolved_endpoint_command}" ]]; then
      echo "error: resolved endpoint command is unsafe: ${endpoint_command}=${resolved_endpoint_command}" >&2
      return 1
    fi
  done

  local run_root="${RUN_PARENT}/${run_id}"
  local endpoint_root="${run_root}/endpoint-${role}"
  local endpoint_run="${endpoint_root}/run"
  local endpoint_var="${endpoint_root}/var"
  local netns="wgp${run_id}${role}"
  local pin_path="/sys/fs/bpf/wg-mix-ebpf-performance-${run_id}-${role}"
  local current_mountns expected_netns current_netns

  validate_root_directory "${run_root}"
  validate_root_directory "${endpoint_root}"
  validate_root_directory "${endpoint_run}"
  validate_root_directory "${endpoint_var}"
  if [[ ! -f "${run_root}/owner" || -L "${run_root}/owner" ]] ||
    [[ "$(<"${run_root}/owner")" != "wg-mix-ebpf-performance:${run_id}" ]]; then
    echo "error: endpoint child ownership marker mismatch" >&2
    return 1
  fi
  if [[ ! "${WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS-}" =~ ^[1-9][0-9]*:[1-9][0-9]*$ ]]; then
    echo "error: endpoint child lacks a valid sealed parent mount namespace" >&2
    return 1
  fi
  current_mountns="$(stat -Lc '%d:%i' -- /proc/self/ns/mnt)"
  if [[ ! "${current_mountns}" =~ ^[1-9][0-9]*:[1-9][0-9]*$ ||
    "${current_mountns}" == "${WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS}" ]]; then
    echo "error: endpoint child did not enter a distinct mount namespace" >&2
    return 1
  fi
  if ! ip netns list | awk '{print $1}' | grep -Fxq -- "${netns}"; then
    echo "error: endpoint child network namespace is absent: ${netns}" >&2
    return 1
  fi
  expected_netns="$(stat -Lc '%d:%i' -- "/run/netns/${netns}")"
  current_netns="$(stat -Lc '%d:%i' -- /proc/self/ns/net)"
  if [[ ! "${expected_netns}" =~ ^[1-9][0-9]*:[1-9][0-9]*$ ||
    "${current_netns}" != "${expected_netns}" ]]; then
    echo "error: endpoint child did not enter its exact network namespace" >&2
    return 1
  fi

  printf 'ENDPOINT_MUTATION role=%s argv=' "${role}"
  printf '%q ' mount --bind "${endpoint_run}" "${SHARED_RUN_TARGET}"
  printf '\n'
  mount --bind "${endpoint_run}" "${SHARED_RUN_TARGET}"
  printf 'ENDPOINT_MUTATION role=%s argv=' "${role}"
  printf '%q ' mount --bind "${endpoint_var}" "${SHARED_VAR_TARGET}"
  printf '\n'
  mount --bind "${endpoint_var}" "${SHARED_VAR_TARGET}"
  printf 'ENDPOINT_MUTATION role=%s argv=' "${role}"
  printf '%q ' mount -t bpf -o mode=0700 bpf /sys/fs/bpf
  printf '\n'
  mount -t bpf -o mode=0700 bpf /sys/fs/bpf

  local daemon_environment=(
    "PATH=${SAFE_PATH}"
    "LC_ALL=C"
    "WG_MIX_EBPF_OBJECT=${BASELINE_OBJECT}"
    "WG_MIX_EBPF_PIN_PATH=${pin_path}"
    "WG_MIX_EBPF_FAKETCP_OBJECT=${FAKETCP_OBJECT}"
    "WG_MIX_EBPF_FAKETCP_LEGACY_515_OBJECT=${FAKETCP_LEGACY_OBJECT}"
  )
  printf 'ENDPOINT_DAEMON_EXEC role=%s netns=%s pin=%s argv=' \
    "${role}" "${netns}" "${pin_path}"
  printf '%q ' "${BIN}" run --config /run/wg-mix-ebpf/config.yaml \
    --run-dir /run/wg-mix-ebpf/runtime \
    --state-dir /var/lib/wg-mix-ebpf/state --shutdown-timeout 20s
  printf '\n'
  exec env -i "${daemon_environment[@]}" \
    "${BIN}" run --config /run/wg-mix-ebpf/config.yaml \
    --run-dir /run/wg-mix-ebpf/runtime \
    --state-dir /var/lib/wg-mix-ebpf/state --shutdown-timeout 20s
}

if [[ "${1-}" == "endpoint" ]]; then
  endpoint_child "$@"
  exit $?
fi

operation="${1-}"
if [[ ! "${operation}" =~ ^(run|restore)$ ]]; then
  echo "usage: ${STAGED_NAME} {run|restore} --run-id <8hex> --label <label> --transport <wireguard|udp|icmp|faketcp> --backend <none|tcx|classic_tc> --checksum-backend <none|kfunc|kprobe> --cipher <none|prefix|full> --max-bytes <value>" >&2
  exit 2
fi
shift

run_id=""
label=""
transport=""
backend=""
checksum_backend=""
cipher=""
max_bytes=""
while (($#)); do
  case "$1" in
    --run-id)
      (($# >= 2)) || exit 2
      run_id="$2"
      shift 2
      ;;
    --label)
      (($# >= 2)) || exit 2
      label="$2"
      shift 2
      ;;
    --transport)
      (($# >= 2)) || exit 2
      transport="$2"
      shift 2
      ;;
    --backend)
      (($# >= 2)) || exit 2
      backend="$2"
      shift 2
      ;;
    --checksum-backend)
      (($# >= 2)) || exit 2
      checksum_backend="$2"
      shift 2
      ;;
    --cipher)
      (($# >= 2)) || exit 2
      cipher="$2"
      shift 2
      ;;
    --max-bytes)
      (($# >= 2)) || exit 2
      max_bytes="$2"
      shift 2
      ;;
    *)
      echo "error: unknown production performance argument: $1" >&2
      exit 2
      ;;
  esac
done

if ! validate_run_id "${run_id}" ||
  [[ ! "${label}" =~ ^(wireguard-baseline|udp-(tcx|classic_tc)-(none|prefix-(4|16|64|128|256|512|1024|2048)|full-2048)|icmp-(tcx|classic_tc)-none|faketcp-(tcx|classic_tc)-(kfunc|kprobe)-(none|prefix-(4|16|64|128|256|512|1024|2048)|full-2048))$ ]] ||
  [[ ! "${transport}" =~ ^(wireguard|udp|icmp|faketcp)$ ]] ||
  [[ ! "${backend}" =~ ^(none|tcx|classic_tc)$ ]] ||
  [[ ! "${checksum_backend}" =~ ^(none|kfunc|kprobe)$ ]] ||
  [[ ! "${cipher}" =~ ^(none|prefix|full)$ ]] ||
  [[ ! "${max_bytes}" =~ ^(0|4|16|64|128|256|512|1024|2048)$ ]]; then
  echo "error: invalid production performance cell arguments" >&2
  exit 2
fi
if [[ "${transport}" == "wireguard" && ("${backend}" != "none" ||
  "${checksum_backend}" != "none" || "${cipher}" != "none" ||
  "${max_bytes}" != "0" || "${label}" != "wireguard-baseline") ]]; then
  echo "error: pure WireGuard permits only its exact BPF-free baseline cell" >&2
  exit 2
fi
if [[ "${transport}" == "udp" && ("${backend}" == "none" ||
  "${checksum_backend}" != "none") ]]; then
  echo "error: UDP requires an attachment backend and no checksum backend" >&2
  exit 2
fi
if [[ "${transport}" == "icmp" && ("${checksum_backend}" != "none" || "${cipher}" != "none" || "${max_bytes}" != "0") ]]; then
  echo "error: ICMP performance permits only the no-XOR sentinel" >&2
  exit 2
fi
if [[ "${transport}" == "faketcp" && ! "${checksum_backend}" =~ ^(kfunc|kprobe)$ ]]; then
  echo "error: FakeTCP production performance requires an exact checksum backend" >&2
  exit 2
fi
if [[ "${cipher}" == "full" && "${max_bytes}" != "2048" ]]; then
  echo "error: full-payload performance requires max_bytes=2048" >&2
  exit 2
fi
if [[ "${cipher}" == "none" && "${max_bytes}" != "0" ]]; then
  echo "error: no-XOR performance requires max_bytes=0 sentinel" >&2
  exit 2
fi
cell_shape="${cipher}"
[[ "${cipher}" == prefix ]] && cell_shape="prefix-${max_bytes}"
[[ "${cipher}" == full ]] && cell_shape="full-2048"
case "${transport}" in
  wireguard) expected_label=wireguard-baseline ;;
  udp) expected_label="udp-${backend}-${cell_shape}" ;;
  icmp) expected_label="icmp-${backend}-none" ;;
  faketcp) expected_label="faketcp-${backend}-${checksum_backend}-${cell_shape}" ;;
esac
if [[ "${label}" != "${expected_label}" ]]; then
  echo "error: performance label does not bind its exact cell arguments" >&2
  exit 2
fi
unset cell_shape expected_label
if [[ "${operation}" == "run" && "${transport}" == "faketcp" ]]; then
  if [[ "${checksum_backend}" == "kfunc" ]]; then
    if [[ ! -d "/sys/module/${KFUNC_MODULE}" || ! -r "/sys/kernel/btf/${KFUNC_MODULE}" ]]; then
      echo "error: FakeTCP kfunc requires the matrix-owned checksum module and BTF" >&2
      exit 1
    fi
  elif [[ ! -d "/sys/module/${KPROBE_MODULE}" || ! -c "${KPROBE_DEVICE}" ||
    -L "${KPROBE_DEVICE}" ||
    "$(stat -c '%u:%g:%a:%h' -- "${KPROBE_DEVICE}")" != 0:0:600:1 ]]; then
    echo "error: FakeTCP kprobe requires the matrix-owned bridge and character device" >&2
    exit 1
  fi
fi

for command_name in bash env cat sleep ip wg ping iperf3 python3 timeout tcpdump tc bpftool \
  unshare nsenter mount awk grep stat date sha256sum nft ss sysctl ps tee \
  readlink unlink mkdir uname; do
  if ! resolved_command="$(command -v "${command_name}")"; then
    echo "error: missing production performance command: ${command_name}" >&2
    exit 1
  fi
  # Ubuntu's alternatives-managed tools (notably awk and python3) are
  # commonly absolute symlinks.  The fixed root-owned PATH is the trust
  # boundary here; require the resolved entry to name an executable regular
  # file, while allowing the kernel to follow that system-managed symlink.
  if [[ "${resolved_command}" != /* || ! -f "${resolved_command}" ||
    ! -x "${resolved_command}" ]]; then
    echo "error: resolved production performance command is unsafe: ${command_name}=${resolved_command}" >&2
    exit 1
  fi
done
unset resolved_command

readonly RUN_ROOT="${RUN_PARENT}/${run_id}"
readonly EVIDENCE="${RUN_ROOT}/evidence"
readonly ENDPOINT_A="${RUN_ROOT}/endpoint-a"
readonly ENDPOINT_B="${RUN_ROOT}/endpoint-b"
readonly ENDPOINT_A_RUN="${ENDPOINT_A}/run"
readonly ENDPOINT_B_RUN="${ENDPOINT_B}/run"
readonly ENDPOINT_A_VAR="${ENDPOINT_A}/var"
readonly ENDPOINT_B_VAR="${ENDPOINT_B}/var"
readonly SECRETS="${RUN_ROOT}/secrets"
readonly NSA="wgp${run_id}a"
readonly NSR="wgp${run_id}r"
readonly NSB="wgp${run_id}b"
readonly VETH_A="wpa${run_id}"
readonly VETH_RA="wra${run_id}"
readonly VETH_B="wpb${run_id}"
readonly VETH_RB="wrb${run_id}"
readonly PORT_A=31001
readonly PORT_B=31002
readonly IPERF_PORT=5201

proof_value() {
  local key="$1"
  local path="$2"
  awk -F= -v wanted="${key}" \
    '$1 == wanted { count++; value = substr($0, length($1) + 2) }
     END { if (count != 1 || value == "") exit 79; print value }' "${path}"
}

validate_retained_run() {
  local expected_artifact=baseline
  [[ "${transport}" == wireguard ]] && expected_artifact=none
  [[ "${checksum_backend}" == kfunc ]] && expected_artifact=modern
  [[ "${checksum_backend}" == kprobe ]] && expected_artifact=legacy_515
  [[ -d "${RUN_PARENT}" && ! -L "${RUN_PARENT}" ]] || return 79
  validate_root_directory "${RUN_PARENT}"
  [[ -d "${RUN_ROOT}" && ! -L "${RUN_ROOT}" ]] || return 79
  validate_root_directory "${RUN_ROOT}"
  [[ -f "${RUN_ROOT}/owner" && ! -L "${RUN_ROOT}/owner" &&
    "$(stat -c '%u:%g:%a:%h' -- "${RUN_ROOT}/owner")" == "0:0:600:1" &&
    "$(<"${RUN_ROOT}/owner")" == "wg-mix-ebpf-performance:${run_id}" ]] || return 79
  [[ -f "${RUN_ROOT}/manifest" && ! -L "${RUN_ROOT}/manifest" &&
    "$(stat -c '%u:%g:%a:%h' -- "${RUN_ROOT}/manifest")" == "0:0:600:1" &&
    "$(proof_value format "${RUN_ROOT}/manifest")" == \
      "wg-mix-ebpf-b82-production-performance-v1" &&
    "$(proof_value run_id "${RUN_ROOT}/manifest")" == "${run_id}" &&
    "$(proof_value label "${RUN_ROOT}/manifest")" == "${label}" &&
    "$(proof_value transport "${RUN_ROOT}/manifest")" == "${transport}" &&
    "$(proof_value backend "${RUN_ROOT}/manifest")" == "${backend}" &&
    "$(proof_value checksum_backend "${RUN_ROOT}/manifest")" == "${checksum_backend}" &&
    "$(proof_value artifact "${RUN_ROOT}/manifest")" == "${expected_artifact}" &&
    "$(proof_value cipher "${RUN_ROOT}/manifest")" == "${cipher}" &&
    "$(proof_value max_bytes "${RUN_ROOT}/manifest")" == "${max_bytes}" &&
    "$(proof_value source_root "${RUN_ROOT}/manifest")" == "${source_root}" &&
    "$(proof_value baseline_object_sha256 "${RUN_ROOT}/manifest")" == \
      "$(sha256sum -- "${BASELINE_OBJECT}" | awk '{print $1}')" ]] || return 79
  if [[ "${transport}" == faketcp ]]; then
    [[ "$(proof_value faketcp_object_sha256 "${RUN_ROOT}/manifest")" == \
      "$(sha256sum -- "${FAKETCP_OBJECT}" | awk '{print $1}')" &&
      "$(proof_value faketcp_legacy_object_sha256 "${RUN_ROOT}/manifest")" == \
      "$(sha256sum -- "${FAKETCP_LEGACY_OBJECT}" | awk '{print $1}')" ]] || return 79
  fi
  [[ -d "${EVIDENCE}" && ! -L "${EVIDENCE}" ]] || return 79
  validate_root_directory "${EVIDENCE}"
}

restore_log() {
  printf 'timestamp=%s phase=%s argv=' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" \
    >>"${EVIDENCE}/restore-operations.log"
  shift
  printf '%q ' "$@" >>"${EVIDENCE}/restore-operations.log"
  printf '\n' >>"${EVIDENCE}/restore-operations.log"
}

namespace_present() {
  ip netns list | awk -v wanted="$1" '$1 == wanted { count++ } END { exit count != 1 }'
}

allowed_restore_executable() {
  local actual="$1"
  local candidate resolved
  [[ "${actual}" == "${BIN}" ]] && return 0
  [[ "${actual}" == "${script_path}" ]] && return 0
  for candidate in bash env cat sleep ip wg ping iperf3 python3 timeout tcpdump tc bpftool \
    unshare nsenter mount awk grep stat date sha256sum nft ss sysctl ps tee \
    readlink unlink; do
    resolved="$(readlink -e -- "$(command -v "${candidate}")")"
    [[ "${actual}" != "${resolved}" ]] || return 0
  done
  return 1
}

signal_namespace_processes() {
  local signal="$1"
  local netns="$2"
  local expected_inode pid actual_inode actual_executable
  expected_inode="$(stat -Lc '%d:%i' -- "/run/netns/${netns}")"
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 79
    [[ -d "/proc/${pid}" ]] || continue
    actual_inode="$(stat -Lc '%d:%i' -- "/proc/${pid}/ns/net")"
    actual_executable="$(readlink -e -- "/proc/${pid}/exe")"
    if [[ "${actual_inode}" != "${expected_inode}" ]] ||
      ! allowed_restore_executable "${actual_executable}"; then
      printf 'error: refusing to signal an unproved retained process: netns=%s pid=%s inode=%s exe=%s\n' \
        "${netns}" "${pid}" "${actual_inode}" "${actual_executable}" >&2
      return 79
    fi
    restore_log "process-${signal}" kill "-${signal}" "${pid}" \
      "netns=${netns}" "inode=${actual_inode}" "exe=${actual_executable}"
    kill "-${signal}" "${pid}"
  done < <(ip netns pids "${netns}")
}

wait_namespace_empty() {
  local netns="$1"
  local attempts="$2"
  local attempt remaining
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    remaining="$(ip netns pids "${netns}")"
    [[ -z "${remaining}" ]] && return 0
    sleep 0.1
  done
  return 1
}

remove_retained_secret() {
  local path="$1"
  [[ "${path}" == "${RUN_ROOT}/"* ]] || return 79
  [[ ! -e "${path}" && ! -L "${path}" ]] && return 0
  [[ -f "${path}" && ! -L "${path}" &&
    "$(stat -c '%u:%g:%a:%h' -- "${path}")" == "0:0:600:1" ]] || return 79
  restore_log secret-unlink unlink -- "${path}"
  unlink -- "${path}"
}

remove_retained_classic_journals() {
  local root path
  local -a paths=()
  for root in "${ENDPOINT_A_VAR}/pin-owners" "${ENDPOINT_B_VAR}/pin-owners"; do
    [[ ! -e "${root}" && ! -L "${root}" ]] && continue
    [[ -d "${root}" && ! -L "${root}" && "${root}" == "${RUN_ROOT}/"* ]] || return 79
    validate_root_directory "${root}"
    shopt -s nullglob
    paths=("${root}"/*.faketcp-classic.owner.json "${root}"/*.faketcp-classic.owner.next)
    shopt -u nullglob
    ((${#paths[@]} <= 4)) || return 79
    for path in "${paths[@]}"; do
      [[ "${path##*/}" =~ ^[0-9a-f]{64}\.faketcp-classic\.owner\.(json|next)$ &&
        -f "${path}" && ! -L "${path}" &&
        "$(stat -c '%u:%g:%a:%h' -- "${path}")" == "0:0:600:1" ]] || return 79
      restore_log classic-journal-unlink unlink -- "${path}"
      unlink -- "${path}"
    done
  done
}

restore_retained_run() {
  local netns remaining mountinfo
  validate_retained_run
  [[ ! -e "${RUN_ROOT}/complete" && ! -L "${RUN_ROOT}/complete" ]] || {
    echo "error: completed cells do not require failure restoration" >&2
    return 79
  }
  : >"${EVIDENCE}/restore-operations.log"
  # Endpoint daemons share the host lifecycle maintenance gate. Stop and reap
  # them one at a time so graceful shutdown cannot contend for that gate.
  # The router has no daemon and is stopped last.
  for netns in "${NSA}" "${NSB}" "${NSR}"; do
    namespace_present "${netns}" || continue
    signal_namespace_processes TERM "${netns}"
    if ! wait_namespace_empty "${netns}" 300; then
      signal_namespace_processes KILL "${netns}"
      wait_namespace_empty "${netns}" 50 || {
        remaining="$(ip netns pids "${netns}")"
        echo "error: retained namespace processes did not exit: ${netns}: ${remaining}" >&2
        return 1
      }
    fi
  done
  for netns in "${NSA}" "${NSB}" "${NSR}"; do
    namespace_present "${netns}" || continue
    restore_log netns-delete ip netns delete "${netns}"
    ip netns delete "${netns}"
  done
  remove_retained_secret "${ENDPOINT_A_RUN}/xor.key"
  remove_retained_secret "${ENDPOINT_B_RUN}/xor.key"
  remove_retained_secret "${ENDPOINT_A_RUN}/xor.key.next"
  remove_retained_secret "${ENDPOINT_B_RUN}/xor.key.next"
  remove_retained_classic_journals
  for netns in "${NSA}" "${NSR}" "${NSB}"; do
    if namespace_present "${netns}"; then
      echo "error: retained namespace remains after explicit restore: ${netns}" >&2
      return 1
    fi
  done
  mountinfo="$(</proc/self/mountinfo)"
  if [[ "${mountinfo}" == *"${RUN_ROOT}"* ]]; then
    echo "error: retained run path remains in the caller mount namespace" >&2
    return 1
  fi
  printf 'format=wg-mix-ebpf-b82-production-performance-restored-v1\nrun_id=%s\nmanifest_sha256=%s\nactive_resources=absent\nsensitive_files=absent\n' \
    "${run_id}" "$(sha256sum -- "${RUN_ROOT}/manifest" | awk '{print $1}')" \
    >"${RUN_ROOT}/restored"
  printf 'PERFORMANCE_PRODUCTION_CELL_RESTORE_COMPLETE run_id=%s root=%s timestamp=%s\n' \
    "${run_id}" "${RUN_ROOT}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

if [[ "${operation}" == "restore" ]]; then
  restore_retained_run
  exit 0
fi

if [[ ! -d "${RUN_PARENT}" ]]; then
  mkdir --mode=0700 -- "${RUN_PARENT}"
fi
validate_root_directory "${RUN_PARENT}"
if [[ -e "${RUN_PARENT}/${run_id}" || -L "${RUN_PARENT}/${run_id}" ]]; then
  echo "error: production performance run already exists: ${RUN_PARENT}/${run_id}" >&2
  exit 1
fi
maintenance_target_identity_before=not-used
if [[ "${transport}" != wireguard ]]; then
  for shared_target in "${SHARED_RUN_TARGET}" "${SHARED_VAR_TARGET}"; do
    if [[ ! -d "${shared_target}" ]]; then
      echo "error: reviewed mount target must be provisioned before the run: ${shared_target}" >&2
      exit 1
    fi
    validate_root_directory "${shared_target}"
  done
  if [[ -e "${SHARED_MAINTENANCE_TARGET}" || -L "${SHARED_MAINTENANCE_TARGET}" ]]; then
    if [[ ! -f "${SHARED_MAINTENANCE_TARGET}" || -L "${SHARED_MAINTENANCE_TARGET}" ||
      "$(stat -c '%u:%g:%a:%h' -- "${SHARED_MAINTENANCE_TARGET}")" != "0:0:600:1" ]]; then
      echo "error: global lifecycle maintenance target is unsafe: ${SHARED_MAINTENANCE_TARGET}" >&2
      exit 1
    fi
    maintenance_target_identity_before="$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "${SHARED_MAINTENANCE_TARGET}")"
    if ! python3 - "${SHARED_MAINTENANCE_TARGET}" <<'PY'
import fcntl
import os
import sys

fd = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
PY
    then
      echo "error: global lifecycle maintenance target is currently held" >&2
      exit 1
    fi
  else
    maintenance_target_identity_before=absent
  fi
fi

mkdir --mode=0700 -- "${RUN_ROOT}"
printf 'wg-mix-ebpf-performance:%s\n' "${run_id}" >"${RUN_ROOT}/owner"
mkdir --mode=0700 -- "${EVIDENCE}" "${SECRETS}" \
  "${ENDPOINT_A}" "${ENDPOINT_A_RUN}" "${ENDPOINT_A_VAR}" \
  "${ENDPOINT_B}" "${ENDPOINT_B_RUN}" "${ENDPOINT_B_VAR}"
mkdir --mode=0700 -- "${ENDPOINT_A_RUN}/runtime" "${ENDPOINT_A_VAR}/state" \
  "${ENDPOINT_B_RUN}/runtime" "${ENDPOINT_B_VAR}/state"

stage="initialized"
daemon_a_pid=""
daemon_b_pid=""
daemon_a_phase="daemon-a-start"
daemon_b_phase="daemon-b-start"
tcpdump_pid=""
iperf_server_pid=""

log_argv() {
  local phase="$1"
  shift
  printf 'timestamp=%s phase=%s argv=' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" \
    >>"${EVIDENCE}/operations.log"
  printf '%q ' "$@" >>"${EVIDENCE}/operations.log"
  printf '\n' >>"${EVIDENCE}/operations.log"
}

run_mutation() {
  local phase="$1"
  shift
  local status
  log_argv "${phase}" "$@"
  if "$@"; then
    status=0
  else
    status=$?
  fi
  printf 'timestamp=%s phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${status}" \
    >>"${EVIDENCE}/operations.log"
  return "${status}"
}

diagnostic_command() {
  local output="$1"
  local phase="$2"
  shift 2
  local status
  local restore_errexit=0
  [[ "$-" == *e* ]] && restore_errexit=1
  {
    printf 'timestamp=%s phase=%s argv=' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}"
    printf '%q ' "$@"
    printf '\n'
  } >>"${output}"
  set +e
  "$@" >>"${output}" 2>&1
  status=$?
  ((restore_errexit == 0)) || set -e
  printf 'timestamp=%s phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${status}" >>"${output}"
  return "${status}"
}

run_recorded_command() {
  local phase="$1"
  local stdout_path="$2"
  local stderr_path="$3"
  shift 3
  local metadata_path="${EVIDENCE}/${phase}.meta.log"
  local status

  {
    printf 'timestamp=%s event=start phase=%s argv=' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}"
    printf '%q ' "$@"
    printf '\nstdout=%s\nstderr=%s\n' "${stdout_path}" "${stderr_path}"
  } >"${metadata_path}"
  if "$@" >"${stdout_path}" 2>"${stderr_path}"; then
    status=0
  else
    status=$?
  fi
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${status}" \
    >>"${metadata_path}"
  return "${status}"
}

record_background_start() {
  local phase="$1"
  local stdout_path="$2"
  local stderr_path="$3"
  local pid="$4"
  shift 4
  {
    printf 'timestamp=%s event=start phase=%s pid=%s argv=' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${pid}"
    printf '%q ' "$@"
    printf '\nstdout=%s\nstderr=%s\n' "${stdout_path}" "${stderr_path}"
  } >"${EVIDENCE}/${phase}.meta.log"
}

record_background_finish() {
  local phase="$1"
  local status="$2"
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${status}" \
    >>"${EVIDENCE}/${phase}.meta.log"
}

capture_failure_evidence() {
  local output="${EVIDENCE}/failure-diagnostics.log"
  : >"${output}"
  diagnostic_command "${output}" host-uname uname -a
  diagnostic_command "${output}" host-netns ip netns list
  local exact_pid exact_label
  for exact_label in daemon-a daemon-b tcpdump iperf-server; do
    case "${exact_label}" in
      daemon-a) exact_pid="${daemon_a_pid}" ;;
      daemon-b) exact_pid="${daemon_b_pid}" ;;
      tcpdump) exact_pid="${tcpdump_pid}" ;;
      iperf-server) exact_pid="${iperf_server_pid}" ;;
    esac
    if [[ "${exact_pid}" =~ ^[1-9][0-9]*$ && -d "/proc/${exact_pid}" ]]; then
      diagnostic_command "${output}" "process-${exact_label}" \
        ps -p "${exact_pid}" -o pid=,ppid=,state=,lstart=,args=
    fi
  done
  local ns
  for ns in "${NSA}" "${NSR}" "${NSB}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq -- "${ns}"; then
      diagnostic_command "${output}" "${ns}-link" ip -details -statistics -n "${ns}" link show
      diagnostic_command "${output}" "${ns}-address" ip -n "${ns}" address show
      diagnostic_command "${output}" "${ns}-route" ip -n "${ns}" route show table all
      diagnostic_command "${output}" "${ns}-wg" ip netns exec "${ns}" wg show
      diagnostic_command "${output}" "${ns}-tc-qdisc" ip netns exec "${ns}" tc qdisc show
      diagnostic_command "${output}" "${ns}-tc-filter-ingress" ip netns exec "${ns}" tc filter show dev under0 ingress
      diagnostic_command "${output}" "${ns}-tc-filter-egress" ip netns exec "${ns}" tc filter show dev under0 egress
      diagnostic_command "${output}" "${ns}-bpf-net" ip netns exec "${ns}" bpftool net
    fi
  done
  local pid role
  for role in a b; do
    if [[ "${role}" == a ]]; then pid="${daemon_a_pid}"; else pid="${daemon_b_pid}"; fi
    if [[ "${pid}" =~ ^[1-9][0-9]*$ && -d "/proc/${pid}" ]]; then
      diagnostic_command "${output}" "daemon-${role}-mountinfo" \
        nsenter "--mount=/proc/${pid}/ns/mnt" -- cat /proc/self/mountinfo
      diagnostic_command "${output}" "daemon-${role}-bpf" \
        nsenter "--mount=/proc/${pid}/ns/mnt" "--net=/proc/${pid}/ns/net" -- bpftool net
    fi
  done
}

dump_complete_logs() {
  local path
  for path in "${EVIDENCE}"/*.log "${EVIDENCE}"/*.stderr \
    "${EVIDENCE}"/*.json "${ENDPOINT_A_RUN}/runtime/status.json" \
    "${ENDPOINT_B_RUN}/runtime/status.json"; do
    if [[ -f "${path}" && ! -L "${path}" ]]; then
      printf 'FULL_LOG_BEGIN path=%s\n' "${path}" >&2
      /bin/cat -- "${path}" >&2
      printf 'FULL_LOG_END path=%s\n' "${path}" >&2
    fi
  done
}

on_error() {
  local status="$1"
  local line="$2"
  trap - ERR INT TERM
  set +e
  printf 'PERFORMANCE_CELL_FAILURE run_id=%s label=%s stage=%s rc=%s line=%s timestamp=%s\n' \
    "${run_id}" "${label}" "${stage}" "${status}" "${line}" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2
  printf 'run_id=%s\nlabel=%s\nstage=%s\nrc=%s\nline=%s\n' \
    "${run_id}" "${label}" "${stage}" "${status}" "${line}" \
    >"${EVIDENCE}/failure-summary.txt"
  capture_failure_evidence
  dump_complete_logs
  printf 'FAILURE_RESOURCES_RETAINED run_id=%s run_root=%s netns=%s,%s,%s daemon_pids=%s,%s\n' \
    "${run_id}" "${RUN_ROOT}" "${NSA}" "${NSR}" "${NSB}" \
    "${daemon_a_pid:-none}" "${daemon_b_pid:-none}" >&2
  printf '%s\n' 'No automatic cleanup was attempted after the unexpected failure.' >&2
  exit "${status}"
}

on_signal() {
  local signal="$1"
  echo "error: received signal ${signal}" >&2
  return 130
}

trap 'on_error $? $LINENO' ERR
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

printf 'format=wg-mix-ebpf-b82-production-performance-v1\n' >"${RUN_ROOT}/manifest"
printf 'run_id=%s\nlabel=%s\ntransport=%s\nbackend=%s\ncipher=%s\nmax_bytes=%s\n' \
  "${run_id}" "${label}" "${transport}" "${backend}" "${cipher}" "${max_bytes}" \
  >>"${RUN_ROOT}/manifest"
artifact=baseline
[[ "${transport}" == wireguard ]] && artifact=none
[[ "${checksum_backend}" == kfunc ]] && artifact=modern
[[ "${checksum_backend}" == kprobe ]] && artifact=legacy_515
printf 'checksum_backend=%s\nartifact=%s\n' "${checksum_backend}" "${artifact}" \
  >>"${RUN_ROOT}/manifest"
maintenance_write=none
[[ "${transport}" == wireguard ]] || \
  maintenance_write="${SHARED_MAINTENANCE_TARGET}:shared-flock-owner-record-updates-or-create"
printf 'write_set=%s,%s,%s,%s,%s,%s,%s,%s\n' \
  "${RUN_ROOT}" "${NSA}" "${NSR}" "${NSB}" "${VETH_A}:${VETH_RA}" \
  "${VETH_B}:${VETH_RB}" "/sys/fs/bpf/wg-mix-ebpf-performance-${run_id}-{a,b}" \
  "${maintenance_write}" \
  >>"${RUN_ROOT}/manifest"
unset maintenance_write
printf 'source_root=%s\nbaseline_object_sha256=%s\n' "${source_root}" \
  "$(sha256sum -- "${BASELINE_OBJECT}" | awk '{print $1}')" >>"${RUN_ROOT}/manifest"
if [[ "${transport}" == "faketcp" ]]; then
  printf 'faketcp_object_sha256=%s\nfaketcp_legacy_object_sha256=%s\n' \
    "$(sha256sum -- "${FAKETCP_OBJECT}" | awk '{print $1}')" \
    "$(sha256sum -- "${FAKETCP_LEGACY_OBJECT}" | awk '{print $1}')" \
    >>"${RUN_ROOT}/manifest"
fi

make_wg_stub() {
  local path="$1"
  local port="$2"
  local mark="$3"
  cat >"${path}" <<EOF_WG
[Interface]
ListenPort = ${port}
FwMark = ${mark}
EOF_WG
}

make_agent_config() {
  local path="$1"
  local role="$2"
  local endpoint_run="$3"
  local transport_block=""
  local cipher_ref=""
  local cipher_block=""
  local runtime_checksum="${checksum_backend}"
  local runtime_attachment="${backend}"
  [[ "${runtime_checksum}" == none ]] && runtime_checksum=auto
  [[ "${runtime_attachment}" == none ]] && runtime_attachment=auto

  if [[ "${transport}" == "icmp" ]]; then
    if [[ "${role}" == "a" ]]; then
      transport_block=$'    transport:\n      mode: icmp\n      icmp:\n        role: client\n        id: 21249'
    else
      transport_block=$'    transport:\n      mode: icmp\n      icmp:\n        role: server'
    fi
  elif [[ "${transport}" == "faketcp" ]]; then
    transport_block="    transport:
      mode: faketcp
      faketcp:
        checksum_mode: partial-complete-reset-required
        ingress_mode: xdp-generic-exact
        handshake_timeout: ${FAKETCP_HANDSHAKE_TIMEOUT}
        keepalive_interval: ${FAKETCP_KEEPALIVE_INTERVAL}
        idle_timeout: ${FAKETCP_IDLE_TIMEOUT}"
  else
    transport_block=$'    transport:\n      mode: udp'
  fi
  if [[ "${cipher}" != "none" ]]; then
    cipher_ref="    cipher: xor-performance"
    local scope="wg-payload-prefix"
    [[ "${cipher}" == "full" ]] && scope="wg-payload-full"
    cipher_block="
ciphers:
  xor-performance:
    mode: xor
    auth: none
    scope: ${scope}
    key_derivation: wgmx-hkdf256-v1
    secret_file: /run/wg-mix-ebpf/xor.key
    key_len: 256
    max_bytes: ${max_bytes}
"
  fi

  cat >"${path}" <<EOF_CONFIG
version: 1
mode: transparent-typeword

underlays:
  - name: under0
    type: netdev

wireguards:
  - name: wg0
    config: /run/wg-mix-ebpf/wg.conf
    profile: mix-default
${cipher_ref}
${transport_block}

profiles:
  mix-default:
    preset: wireguard-mix-wire-values-v1
    index:
      mode: none
${cipher_block}
fwmark_policy:
  mode: config-required

startup_guard:
  mode: nft-temporary-drop
  egress:
    match: fwmark
  ingress:
    match: config-listen-port-if-present
    random_listen_port_behavior: best-effort

runtime:
  poll_interval: 30s
  attachment_backend: ${runtime_attachment}
  checksum_backend: ${runtime_checksum}
  require_nonzero_fwmark: true
  strict_runtime_fwmark: true
  allow_zero_fwmark_fallback: false

policy:
  managed_egress_map_miss: drop
  startup_fail_mode: fail_closed_for_managed_flows
EOF_CONFIG
  if [[ "${endpoint_run}" != "${ENDPOINT_A_RUN}" && "${endpoint_run}" != "${ENDPOINT_B_RUN}" ]]; then
    echo "error: unexpected endpoint config root" >&2
    return 1
  fi
}

make_wg_stub "${ENDPOINT_A_RUN}/wg.conf" "${PORT_A}" 0x10000001
make_wg_stub "${ENDPOINT_B_RUN}/wg.conf" "${PORT_B}" 0x10000002
make_agent_config "${ENDPOINT_A_RUN}/config.yaml" a "${ENDPOINT_A_RUN}"
make_agent_config "${ENDPOINT_B_RUN}/config.yaml" b "${ENDPOINT_B_RUN}"

if [[ "${cipher}" != "none" ]]; then
  xor_secret="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
  if [[ ! "${xor_secret}" =~ ^[A-Za-z0-9_-]{64}$ ]]; then
    echo "error: XOR secret generation failed" >&2
    exit 1
  fi
  printf '%s\n' "${xor_secret}" >"${ENDPOINT_A_RUN}/xor.key"
  printf '%s\n' "${xor_secret}" >"${ENDPOINT_B_RUN}/xor.key"
  unset xor_secret
  printf 'timestamp=%s phase=secret-write targets=[REDACTED] rc=0\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${EVIDENCE}/operations.log"
fi

private_a="$(wg genkey)"
private_b="$(wg genkey)"
public_a="$(printf '%s\n' "${private_a}" | wg pubkey)"
public_b="$(printf '%s\n' "${private_b}" | wg pubkey)"
if [[ ! "${private_a}" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ||
  ! "${private_b}" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ||
  ! "${public_a}" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ||
  ! "${public_b}" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]]; then
  echo "error: WireGuard key generation failed" >&2
  exit 1
fi

run_wg_set_private_key() {
  local phase="$1"
  local private_key="$2"
  shift 2
  local stdout_path="${EVIDENCE}/${phase}.stdout.log"
  local stderr_path="${EVIDENCE}/${phase}.stderr.log"
  local metadata_path="${EVIDENCE}/${phase}.meta.log"
  local status
  [[ "${private_key}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 79
  {
    printf 'timestamp=%s event=start phase=%s argv=' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}"
    printf '%q ' "$@"
    printf '\nstdin=ephemeral-private-key-pipe\nstdout=%s\nstderr=%s\n' \
      "${stdout_path}" "${stderr_path}"
  } >"${metadata_path}"
  if { printf '%s\n' "${private_key}"; } | (unset private_key; "$@") \
    >"${stdout_path}" 2>"${stderr_path}"; then
    status=0
  else
    status=$?
  fi
  unset private_key
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${status}" \
    >>"${metadata_path}"
  return "${status}"
}

stage="network-create"
run_mutation netns-add-a ip netns add "${NSA}"
run_mutation netns-add-router ip netns add "${NSR}"
run_mutation netns-add-b ip netns add "${NSB}"
run_mutation veth-add-a ip link add "${VETH_A}" type veth peer name "${VETH_RA}"
run_mutation veth-a-netns ip link set "${VETH_A}" netns "${NSA}"
run_mutation veth-ra-netns ip link set "${VETH_RA}" netns "${NSR}"
run_mutation veth-add-b ip link add "${VETH_B}" type veth peer name "${VETH_RB}"
run_mutation veth-b-netns ip link set "${VETH_B}" netns "${NSB}"
run_mutation veth-rb-netns ip link set "${VETH_RB}" netns "${NSR}"
run_mutation rename-a ip -n "${NSA}" link set "${VETH_A}" name under0
run_mutation rename-ra ip -n "${NSR}" link set "${VETH_RA}" name left0
run_mutation rename-b ip -n "${NSB}" link set "${VETH_B}" name under0
run_mutation rename-rb ip -n "${NSR}" link set "${VETH_RB}" name right0
for ns in "${NSA}" "${NSR}" "${NSB}"; do
  run_mutation "${ns}-lo-up" ip -n "${ns}" link set lo up
done
for spec in "${NSA}:under0" "${NSR}:left0" "${NSR}:right0" "${NSB}:under0"; do
  ns="${spec%%:*}"
  dev="${spec#*:}"
  run_mutation "${ns}-${dev}-mtu" ip -n "${ns}" link set "${dev}" mtu 2200
  run_mutation "${ns}-${dev}-up" ip -n "${ns}" link set "${dev}" up
done
run_mutation addr-a ip -n "${NSA}" address add 198.18.82.1/24 dev under0
run_mutation addr-ra ip -n "${NSR}" address add 198.18.82.254/24 dev left0
run_mutation addr-b ip -n "${NSB}" address add 198.19.82.1/24 dev under0
run_mutation addr-rb ip -n "${NSR}" address add 198.19.82.254/24 dev right0
run_mutation route-a ip -n "${NSA}" route add default via 198.18.82.254 dev under0
run_mutation route-b ip -n "${NSB}" route add default via 198.19.82.254 dev under0
diagnostic_command "${EVIDENCE}/router-ip-forward-before.log" router-ip-forward-before \
  ip netns exec "${NSR}" sysctl net.ipv4.ip_forward
run_mutation router-forward ip netns exec "${NSR}" sysctl -w net.ipv4.ip_forward=1

stage="wireguard-create"
run_mutation wg-add-a ip -n "${NSA}" link add wg0 type wireguard
run_mutation wg-add-b ip -n "${NSB}" link add wg0 type wireguard
run_wg_set_private_key wg-config-a "${private_a}" ip netns exec "${NSA}" wg set wg0 \
  private-key /dev/stdin listen-port "${PORT_A}" fwmark 0x10000001 \
  peer "${public_b}" allowed-ips 10.77.0.2/32 endpoint 198.19.82.1:${PORT_B} \
  persistent-keepalive 1
unset private_a
run_wg_set_private_key wg-config-b "${private_b}" ip netns exec "${NSB}" wg set wg0 \
  private-key /dev/stdin listen-port "${PORT_B}" fwmark 0x10000002 \
  peer "${public_a}" allowed-ips 10.77.0.1/32 endpoint 198.18.82.1:${PORT_A} \
  persistent-keepalive 1
unset private_b public_a public_b
run_mutation wg-addr-a ip -n "${NSA}" address add 10.77.0.1/24 dev wg0
run_mutation wg-addr-b ip -n "${NSB}" address add 10.77.0.2/24 dev wg0
run_mutation wg-mtu-a ip -n "${NSA}" link set wg0 mtu 1420
run_mutation wg-mtu-b ip -n "${NSB}" link set wg0 mtu 1420
run_mutation wg-up-a ip -n "${NSA}" link set wg0 up
run_mutation wg-up-b ip -n "${NSB}" link set wg0 up

wait_daemon_active() {
  local role="$1"
  local pid="$2"
  local status_path="$3"
  local attempt
  local state
  local status
  local background_phase="${daemon_a_phase}"
  [[ "${role}" == b ]] && background_phase="${daemon_b_phase}"
  for ((attempt = 1; attempt <= 300; attempt++)); do
    if [[ ! -d "/proc/${pid}" ]] ||
      ! state="$(ps -p "${pid}" -o state=)" || [[ "${state}" == Z* ]]; then
      if wait "${pid}"; then status=0; else status=$?; fi
      record_background_finish "${background_phase}" "${status}"
      echo "error: daemon ${role} exited before active status (rc=${status})" >&2
      return 1
    fi
    if [[ -f "${status_path}" && ! -L "${status_path}" ]] &&
      python3 - "${status_path}" "${pid}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
pid = int(sys.argv[2])
try:
    doc = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
if doc.get("state") != "active" or doc.get("pid") != pid or doc.get("last_error"):
    raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 0.1
  done
  echo "error: daemon ${role} did not become active in 30 seconds" >&2
  return 1
}

stage="daemon-start"
if [[ "${transport}" == "wireguard" ]]; then
  stage="wireguard-baseline-no-daemon"
else
parent_mountns="$(stat -Lc '%d:%i' -- /proc/self/ns/mnt)"
if [[ ! "${parent_mountns}" =~ ^[1-9][0-9]*:[1-9][0-9]*$ ]]; then
  echo "error: cannot seal parent mount namespace" >&2
  exit 1
fi
env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
  "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
  "WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=${ARTIFACT_ROOT}" \
  "WG_MIX_EBPF_PERFORMANCE_RUN_PARENT=${RUN_PARENT}" \
  ip netns exec "${NSA}" unshare --mount --propagation private \
  "${script_path}" endpoint \
  --run-id "${run_id}" --role a --transport "${transport}" \
  >"${EVIDENCE}/daemon-a.stdout.log" 2>"${EVIDENCE}/daemon-a.stderr.log" &
daemon_a_pid=$!
record_background_start daemon-a-start "${EVIDENCE}/daemon-a.stdout.log" \
  "${EVIDENCE}/daemon-a.stderr.log" "${daemon_a_pid}" \
  env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
  "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
  "WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=${ARTIFACT_ROOT}" \
  "WG_MIX_EBPF_PERFORMANCE_RUN_PARENT=${RUN_PARENT}" \
  ip netns exec "${NSA}" unshare --mount --propagation private \
  "${script_path}" endpoint \
  --run-id "${run_id}" --role a --transport "${transport}"
printf '%s\n' "${daemon_a_pid}" >"${RUN_ROOT}/daemon-a.pid"
wait_daemon_active a "${daemon_a_pid}" "${ENDPOINT_A_RUN}/runtime/status.json"

env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
  "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
  "WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=${ARTIFACT_ROOT}" \
  "WG_MIX_EBPF_PERFORMANCE_RUN_PARENT=${RUN_PARENT}" \
  ip netns exec "${NSB}" unshare --mount --propagation private \
  "${script_path}" endpoint \
  --run-id "${run_id}" --role b --transport "${transport}" \
  >"${EVIDENCE}/daemon-b.stdout.log" 2>"${EVIDENCE}/daemon-b.stderr.log" &
daemon_b_pid=$!
record_background_start daemon-b-start "${EVIDENCE}/daemon-b.stdout.log" \
  "${EVIDENCE}/daemon-b.stderr.log" "${daemon_b_pid}" \
  env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
  "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
  "WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=${ARTIFACT_ROOT}" \
  "WG_MIX_EBPF_PERFORMANCE_RUN_PARENT=${RUN_PARENT}" \
  ip netns exec "${NSB}" unshare --mount --propagation private \
  "${script_path}" endpoint \
  --run-id "${run_id}" --role b --transport "${transport}"
printf '%s\n' "${daemon_b_pid}" >"${RUN_ROOT}/daemon-b.pid"
wait_daemon_active b "${daemon_b_pid}" "${ENDPOINT_B_RUN}/runtime/status.json"
fi

run_endpoint_cli() {
  local role="$1"
  local pid="$2"
  local action="$3"
  local phase="$4"
  local stdout_path="$5"
  local stderr_path="$6"
  local command=(
    nsenter "--mount=/proc/${pid}/ns/mnt" "--net=/proc/${pid}/ns/net" --
    env -i "PATH=${SAFE_PATH}" "LC_ALL=C"
    "WG_MIX_EBPF_OBJECT=${BASELINE_OBJECT}"
    "WG_MIX_EBPF_PIN_PATH=/sys/fs/bpf/wg-mix-ebpf-performance-${run_id}-${role}"
    "WG_MIX_EBPF_FAKETCP_OBJECT=${FAKETCP_OBJECT}"
    "WG_MIX_EBPF_FAKETCP_LEGACY_515_OBJECT=${FAKETCP_LEGACY_OBJECT}"
    "${BIN}" "${action}" --config /run/wg-mix-ebpf/config.yaml
    --run-dir /run/wg-mix-ebpf/runtime --state-dir /var/lib/wg-mix-ebpf/state
  )
  run_recorded_command "${phase}" "${stdout_path}" "${stderr_path}" "${command[@]}"
}

validate_baseline_status() {
  local status_path="$1"
  local role="$2"
  python3 - "${status_path}" "${backend}" "${role}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
backend, role = sys.argv[2:]
document = json.loads(path.read_text(encoding="utf-8"))
if document.get("desired_error") or document.get("dataplane_error"):
    raise SystemExit(f"baseline daemon {role} status reports an error")
daemon = document.get("daemon")
if (
    not isinstance(daemon, dict)
    or daemon.get("state") != "active"
    or daemon.get("last_error")
):
    raise SystemExit(f"baseline daemon {role} is not healthy and active")
dataplane = document.get("dataplane")
if (
    not isinstance(dataplane, dict)
    or dataplane.get("map_error")
    or not isinstance(dataplane.get("active_generation"), int)
    or dataplane["active_generation"] <= 0
    or not isinstance(dataplane.get("abi_version"), int)
    or dataplane["abi_version"] <= 0
):
    raise SystemExit(f"baseline daemon {role} lacks a healthy dataplane status")
underlays = dataplane.get("underlays")
if not isinstance(underlays, list) or len(underlays) != 1:
    raise SystemExit(f"baseline daemon {role} does not report one exact underlay")
underlay = underlays[0]
if (
    underlay.get("name") != "under0"
    or underlay.get("ifname") != "under0"
    or not isinstance(underlay.get("ifindex"), int)
    or underlay["ifindex"] <= 0
    or underlay.get("error")
):
    raise SystemExit(f"baseline daemon {role} exact underlay identity is invalid")
filters = underlay.get("filters")
if (
    not underlay.get("ingress_attached")
    or not underlay.get("egress_attached")
    or not isinstance(filters, list)
    or len(filters) != 2
    or {item.get("direction") for item in filters} != {"ingress", "egress"}
    or any(item.get("backend") != backend for item in filters)
    or any(not isinstance(item.get("program_id"), int) or item["program_id"] <= 0 for item in filters)
):
    raise SystemExit(f"baseline daemon {role} attachment identity is incomplete")
if backend == "tcx":
    if any(
        not isinstance(item.get(key), int) or item[key] <= 0
        for item in filters
        for key in ("attach_type", "link_id")
    ) or len({item["link_id"] for item in filters}) != 2:
        raise SystemExit(f"baseline daemon {role} TCX link identity is incomplete")
else:
    if any(
        not isinstance(item.get(key), int) or item[key] <= 0
        for item in filters
        for key in ("handle", "priority")
    ) or {item["handle"] for item in filters} != {0x10001, 0x10002} or any(
        item["priority"] != 49152 for item in filters
    ):
        raise SystemExit(f"baseline daemon {role} classic TC identity is incomplete")
print(f"baseline_status=healthy role={role} attachment={backend} filters=2")
PY
}

validate_faketcp_status() {
  local status_path="$1"
  local identity_path="$2"
  local selected_object="${FAKETCP_OBJECT}"
  local object_variant="modern-kfunc"
  local module_name="${KFUNC_MODULE}"
  if [[ "${checksum_backend}" == "kprobe" ]]; then
    selected_object="${FAKETCP_LEGACY_OBJECT}"
    object_variant="legacy-515-kprobe"
    module_name="${KPROBE_MODULE}"
  fi
  local selected_sha256
  selected_sha256="$(sha256sum -- "${selected_object}" | awk '{print $1}')"
  python3 - "${status_path}" "${identity_path}" "${selected_object}" \
    "${selected_sha256}" "${backend}" "${checksum_backend}" \
    "${object_variant}" "${module_name}" <<'PY'
import json
import pathlib
import re
import sys

status_path = pathlib.Path(sys.argv[1])
identity_path = pathlib.Path(sys.argv[2])
expected_object = sys.argv[3]
expected_object_sha256 = sys.argv[4]
backend, checksum, object_variant, module_name = sys.argv[5:9]
doc = json.loads(status_path.read_text(encoding="utf-8"))
if doc.get("desired_error") or doc.get("dataplane_error"):
    raise SystemExit("FakeTCP composite status reports an error")
dataplane = doc.get("dataplane")
daemon = doc.get("daemon")
if (
    not isinstance(daemon, dict)
    or daemon.get("state") != "active"
    or daemon.get("last_error")
):
    raise SystemExit("daemon status is not healthy and active")
if (
    not isinstance(dataplane, dict)
    or dataplane.get("mode") != "faketcp"
    or dataplane.get("map_error")
    or not isinstance(dataplane.get("active_generation"), int)
    or dataplane["active_generation"] <= 0
    or not isinstance(dataplane.get("abi_version"), int)
    or dataplane["abi_version"] <= 0
):
    raise SystemExit("status does not report the production FakeTCP dataplane")
fake = dataplane.get("faketcp")
if not isinstance(fake, dict):
    raise SystemExit("status lacks FakeTCP owner detail")
expected_owner = "process-owned" if backend == "tcx" else "durable-classic-tc+process-owned-runtime"
if fake.get("owner_kind") != expected_owner or fake.get("healthy") is not True:
    raise SystemExit("FakeTCP owner is not healthy or has the wrong ownership kind")
if fake.get("barrier") != "open" or fake.get("error"):
    raise SystemExit("FakeTCP generation barrier is not healthy and open")
if not isinstance(fake.get("generation"), int) or fake["generation"] <= 0:
    raise SystemExit("FakeTCP generation is invalid")
if dataplane["active_generation"] != fake["generation"]:
    raise SystemExit("FakeTCP top-level active generation differs from the runtime owner")
if not re.fullmatch(r"[0-9a-f]{32}", str(fake.get("incarnation", ""))):
    raise SystemExit("FakeTCP incarnation is invalid")
if fake.get("object_source") != expected_object:
    raise SystemExit("FakeTCP status object source is not the reviewed staged object")
if fake.get("object_sha256") != expected_object_sha256:
    raise SystemExit("FakeTCP status object SHA-256 differs from the frozen object")
xdp = fake.get("xdp")
tcx = fake.get("tcx") or []
classic = fake.get("classic_tc") or []
if not isinstance(xdp, list) or len(xdp) != 1:
    raise SystemExit("FakeTCP must report exactly one XDP attachment")
if xdp[0].get("mode") != "generic":
    raise SystemExit("FakeTCP XDP mode is not exact generic")
underlays = dataplane.get("underlays") or []
if len(underlays) != 1 or not isinstance(underlays[0], dict):
    raise SystemExit("FakeTCP must report one exact underlay")
underlay = underlays[0]
if (
    underlay.get("name") != "under0"
    or underlay.get("ifname") != "under0"
    or not isinstance(underlay.get("ifindex"), int)
    or underlay["ifindex"] <= 0
    or underlay.get("error")
):
    raise SystemExit("FakeTCP exact underlay identity is unhealthy")
checksum_status = fake.get("checksum_backend") or {}
if (
    checksum_status.get("backend") != checksum
    or checksum_status.get("capability") != "full-gso-v1"
    or checksum_status.get("object_variant") != object_variant
    or checksum_status.get("module") != module_name
    or set(checksum_status.get("capabilities") or [])
    != {"checksum-state", "partial-reset", "pmtu", "udp-gso-to-tcp"}
):
    raise SystemExit("FakeTCP checksum backend identity is incomplete")
if checksum == "kprobe" and checksum_status.get("lease_held") is not True:
    raise SystemExit("FakeTCP kprobe runtime lease is not held")
if checksum == "kfunc" and checksum_status.get("lease_held") not in (None, False):
    raise SystemExit("FakeTCP kfunc unexpectedly reports a device lease")
if fake.get("attachment_backend") != backend:
    raise SystemExit("FakeTCP attachment backend differs from the requested backend")
if backend == "tcx":
    if len(tcx) != 2 or classic:
        raise SystemExit("FakeTCP TCX attachment set is not exact")
    if {item.get("direction") for item in tcx} != {"ingress", "egress"}:
        raise SystemExit("FakeTCP TCX directions are incomplete")
    if any(
        not isinstance(item.get(key), int) or item[key] <= 0
        for item in tcx
        for key in ("ifindex", "attach_type", "link_id", "program_id")
    ):
        raise SystemExit("FakeTCP TCX identity is incomplete")
    attachment = tcx
else:
    if len(classic) != 2 or tcx:
        raise SystemExit("FakeTCP classic TC attachment set is not exact")
    if {item.get("direction") for item in classic} != {"ingress", "egress"}:
        raise SystemExit("FakeTCP classic TC directions are incomplete")
    for item in classic:
        for key in ("ifindex", "parent", "handle", "priority", "program_id"):
            if not isinstance(item.get(key), int) or item[key] <= 0:
                raise SystemExit(f"FakeTCP classic TC {key} is invalid")
    if {item["handle"] for item in classic} != {0x10001, 0x10002} or any(
        item["priority"] != 49152 for item in classic
    ):
        raise SystemExit("FakeTCP classic TC durable slot identity is not fixed")
    attachment = classic
for item in xdp + attachment:
    if item.get("ifindex") != underlay["ifindex"]:
        raise SystemExit("FakeTCP attachment ifindex differs from the exact underlay")
    if item in xdp and (not isinstance(item.get("link_id"), int) or item["link_id"] <= 0):
        raise SystemExit("FakeTCP XDP link ID is invalid")
    if not isinstance(item.get("program_id"), int) or item["program_id"] <= 0:
        raise SystemExit("FakeTCP attachment program ID is invalid")
if backend == "tcx" and len({item["link_id"] for item in xdp + tcx}) != 3:
    raise SystemExit("FakeTCP exact TCX/XDP link IDs are not distinct")
if (
    underlay.get("xdp_attached") is not True
    or underlay.get("xdp_mode") != "generic"
    or underlay.get("xdp_link_id") != xdp[0]["link_id"]
    or underlay.get("xdp_program_id") != xdp[0]["program_id"]
):
    raise SystemExit("FakeTCP exact generic XDP underlay projection is incomplete")
filters = underlay.get("filters") or []
if (
    not underlay.get("ingress_attached")
    or not underlay.get("egress_attached")
    or len(filters) != 2
    or {item.get("direction") for item in filters} != {"ingress", "egress"}
    or any(item.get("backend") != backend for item in filters)
):
    raise SystemExit("FakeTCP TC underlay projection is incomplete")
by_direction = {item["direction"]: item for item in attachment}
projection_fields = (
    ("attach_type", "link_id", "program_id")
    if backend == "tcx"
    else ("handle", "priority", "program_id")
)
for item in filters:
    owner = by_direction[item["direction"]]
    if any(owner.get(key) != item.get(key) for key in projection_fields):
        raise SystemExit("FakeTCP TC underlay projection differs from owner identity")
identity = {
    "generation": fake["generation"],
    "incarnation": fake["incarnation"],
    "object_source": fake["object_source"],
    "object_sha256": fake["object_sha256"],
    "xdp": xdp,
    "attachment_backend": backend,
    "checksum_backend": checksum_status,
    "tcx": sorted(tcx, key=lambda item: item["direction"]),
    "classic_tc": sorted(classic, key=lambda item: item["direction"]),
}
identity_path.write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(
    f"faketcp_status=healthy owner_kind={expected_owner} barrier=open "
    f"generation={fake['generation']} xdp_links=1 attachment={backend} checksum={checksum}"
)
PY
}

compare_identity_equal() {
  local before="$1"
  local after="$2"
  python3 - "${before}" "${after}" <<'PY'
import json
import pathlib
import sys

before = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if before != after:
    raise SystemExit("FakeTCP exact process-owned identity changed unexpectedly")
print("faketcp_identity_stability=exact-unchanged")
PY
}

compare_identity_replaced() {
  local before="$1"
  local after="$2"
  python3 - "${before}" "${after}" <<'PY'
import json
import pathlib
import sys

before = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
before_links = {item["link_id"] for item in before["xdp"] + before["tcx"]}
after_links = {item["link_id"] for item in after["xdp"] + after["tcx"]}
before_programs = {
    item["program_id"]
    for item in before["xdp"] + before["tcx"] + before["classic_tc"]
}
after_programs = {
    item["program_id"]
    for item in after["xdp"] + after["tcx"] + after["classic_tc"]
}
if before["incarnation"] == after["incarnation"]:
    raise SystemExit("changed-key reload retained the old FakeTCP incarnation")
if before_links & after_links or before_programs & after_programs:
    raise SystemExit("changed-key reload overlapped old and replacement exact BPF IDs")
print("faketcp_identity_replacement=serial exact_identity=replaced")
PY
}

validate_classic_journal() {
  local role="$1"
  local identity_path="$2"
  local endpoint_var="${ENDPOINT_A_VAR}"
  [[ "${role}" == b ]] && endpoint_var="${ENDPOINT_B_VAR}"
  python3 - "${endpoint_var}/pin-owners" "${run_id}" "${role}" \
    "${identity_path}" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
run_id, role = sys.argv[2:4]
identity_path = pathlib.Path(sys.argv[4])
if not root.is_dir() or root.is_symlink():
    raise SystemExit(f"classic owner journal root is absent: {root}")
if not identity_path.is_file() or identity_path.is_symlink():
    raise SystemExit(f"classic status identity is absent: {identity_path}")
records = list(root.glob("*.faketcp-classic.owner.json"))
pending = list(root.glob("*.faketcp-classic.owner.next"))
if len(records) != 1 or pending:
    raise SystemExit(f"classic journal set is not one active/no-pending: {records=} {pending=}")
metadata = records[0].lstat()
if (
    records[0].is_symlink()
    or not records[0].is_file()
    or metadata.st_mode & 0o777 != 0o600
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or metadata.st_nlink != 1
):
    raise SystemExit("classic journal metadata is unsafe")
record = json.loads(records[0].read_text(encoding="utf-8"))
if record.get("version") != 1 or record.get("phase") != "active":
    raise SystemExit("classic journal is not active v1")
resource_key = str(record.get("resource_key", ""))
if (
    not re.fullmatch(r"[0-9a-f]{64}", resource_key)
    or records[0].name != f"{resource_key}.faketcp-classic.owner.json"
    or record.get("boot_id")
    != pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    or record.get("pin_basename")
    != f"wg-mix-ebpf-performance-{run_id}-{role}"
    or not isinstance(record.get("parent_device"), int)
    or record["parent_device"] <= 0
    or not isinstance(record.get("parent_inode"), int)
    or record["parent_inode"] <= 0
    or not isinstance(record.get("sequence"), int)
    or record["sequence"] <= 0
):
    raise SystemExit("classic journal resource/sequence identity is invalid")
if len(record.get("active_filters") or []) != 2:
    raise SystemExit("classic journal does not own exactly two filters")
identity = json.loads(identity_path.read_text(encoding="utf-8"))
if (
    record.get("generation") != identity.get("generation")
    or record.get("object_sha256") != identity.get("object_sha256")
):
    raise SystemExit("classic journal generation/object differs from live status")
active = sorted(record["active_filters"], key=lambda item: item["direction"])
status_filters = sorted(identity.get("classic_tc") or [], key=lambda item: item["direction"])
fields = ("ifindex", "direction", "parent", "handle", "priority", "program_id")
if (
    len(status_filters) != 2
    or [{key: item.get(key) for key in fields} for item in active]
    != [{key: item.get(key) for key in fields} for item in status_filters]
):
    raise SystemExit("classic journal filters differ from exact live status identity")
pin = str(record.get("pin_path", ""))
if pin != f"/sys/fs/bpf/wg-mix-ebpf-performance-{run_id}-{role}":
    raise SystemExit("classic journal pin scope differs from the cell")
print(f"classic_journal=active role={role} filters=2 record={records[0].name}")
PY
}

validate_no_classic_journal() {
  python3 - "${ENDPOINT_A_VAR}/pin-owners" "${ENDPOINT_B_VAR}/pin-owners" <<'PY'
import pathlib
import sys

for raw in sys.argv[1:]:
    root = pathlib.Path(raw)
    if not root.exists():
        continue
    if not root.is_dir() or root.is_symlink():
        raise SystemExit(f"unexpected FakeTCP classic journal root type: {root}")
    residual = list(root.glob("*.faketcp-classic.owner.json"))
    residual.extend(root.glob("*.faketcp-classic.owner.next"))
    if residual:
        raise SystemExit(f"TCX unexpectedly owns a FakeTCP classic journal: {residual}")
print("faketcp_classic_journal=absent attachment=tcx")
PY
}

stage="initial-status"
if [[ "${transport}" != "wireguard" ]]; then
  run_endpoint_cli a "${daemon_a_pid}" status status-a-initial \
    "${EVIDENCE}/status-a-initial.json" "${EVIDENCE}/status-a-initial.stderr"
  run_endpoint_cli b "${daemon_b_pid}" status status-b-initial \
    "${EVIDENCE}/status-b-initial.json" "${EVIDENCE}/status-b-initial.stderr"
fi

if [[ "${transport}" == "faketcp" ]]; then
  validate_faketcp_status "${EVIDENCE}/status-a-initial.json" \
    "${EVIDENCE}/identity-a-initial.json" | tee "${EVIDENCE}/status-a-initial-check.log"
  validate_faketcp_status "${EVIDENCE}/status-b-initial.json" \
    "${EVIDENCE}/identity-b-initial.json" | tee "${EVIDENCE}/status-b-initial-check.log"
  if [[ "${backend}" == "classic_tc" ]]; then
    validate_classic_journal a "${EVIDENCE}/identity-a-initial.json" \
      >"${EVIDENCE}/classic-journal-a-initial.log"
    validate_classic_journal b "${EVIDENCE}/identity-b-initial.json" \
      >"${EVIDENCE}/classic-journal-b-initial.log"
  else
    validate_no_classic_journal >"${EVIDENCE}/classic-journal-tcx-initial.log"
  fi

  stage="same-key-reload"
  run_endpoint_cli a "${daemon_a_pid}" reload reload-a-same-key \
    "${EVIDENCE}/reload-a-same-key.stdout.log" "${EVIDENCE}/reload-a-same-key.stderr.log"
  run_endpoint_cli b "${daemon_b_pid}" reload reload-b-same-key \
    "${EVIDENCE}/reload-b-same-key.stdout.log" "${EVIDENCE}/reload-b-same-key.stderr.log"
  run_endpoint_cli a "${daemon_a_pid}" status status-a-same-key \
    "${EVIDENCE}/status-a-same-key.json" "${EVIDENCE}/status-a-same-key.stderr"
  run_endpoint_cli b "${daemon_b_pid}" status status-b-same-key \
    "${EVIDENCE}/status-b-same-key.json" "${EVIDENCE}/status-b-same-key.stderr"
  validate_faketcp_status "${EVIDENCE}/status-a-same-key.json" \
    "${EVIDENCE}/identity-a-same-key.json" >"${EVIDENCE}/status-a-same-key-check.log"
  validate_faketcp_status "${EVIDENCE}/status-b-same-key.json" \
    "${EVIDENCE}/identity-b-same-key.json" >"${EVIDENCE}/status-b-same-key-check.log"
  compare_identity_equal "${EVIDENCE}/identity-a-initial.json" \
    "${EVIDENCE}/identity-a-same-key.json" | tee "${EVIDENCE}/same-key-a.log"
  compare_identity_equal "${EVIDENCE}/identity-b-initial.json" \
    "${EVIDENCE}/identity-b-same-key.json" | tee "${EVIDENCE}/same-key-b.log"
  if [[ "${backend}" == "classic_tc" ]]; then
    validate_classic_journal a "${EVIDENCE}/identity-a-same-key.json" \
      >"${EVIDENCE}/classic-journal-a-reloaded.log"
    validate_classic_journal b "${EVIDENCE}/identity-b-same-key.json" \
      >"${EVIDENCE}/classic-journal-b-reloaded.log"
  fi

  if [[ "${cipher}" != "none" ]]; then
    stage="changed-key-reload"
    next_xor_secret="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
    if [[ ! "${next_xor_secret}" =~ ^[A-Za-z0-9_-]{64}$ ]]; then
      echo "error: replacement XOR secret generation failed" >&2
      exit 1
    fi
    printf '%s\n' "${next_xor_secret}" >"${ENDPOINT_A_RUN}/xor.key.next"
    printf '%s\n' "${next_xor_secret}" >"${ENDPOINT_B_RUN}/xor.key.next"
    unset next_xor_secret
    printf 'timestamp=%s phase=changed-key-secret-write targets=[REDACTED] rc=0\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${EVIDENCE}/operations.log"
    run_mutation changed-key-secret-publish-a /bin/mv -- \
      "${ENDPOINT_A_RUN}/xor.key.next" "${ENDPOINT_A_RUN}/xor.key"
    run_mutation changed-key-secret-publish-b /bin/mv -- \
      "${ENDPOINT_B_RUN}/xor.key.next" "${ENDPOINT_B_RUN}/xor.key"

    run_endpoint_cli a "${daemon_a_pid}" reload reload-a-changed-key \
      "${EVIDENCE}/reload-a-changed-key.stdout.log" "${EVIDENCE}/reload-a-changed-key.stderr.log"
    run_endpoint_cli a "${daemon_a_pid}" status status-a-changed-key \
      "${EVIDENCE}/status-a-changed-key.json" "${EVIDENCE}/status-a-changed-key.stderr"
    validate_faketcp_status "${EVIDENCE}/status-a-changed-key.json" \
      "${EVIDENCE}/identity-a-changed-key.json" >"${EVIDENCE}/status-a-changed-key-check.log"
    compare_identity_replaced "${EVIDENCE}/identity-a-same-key.json" \
      "${EVIDENCE}/identity-a-changed-key.json" | tee "${EVIDENCE}/changed-key-a.log"

    run_endpoint_cli b "${daemon_b_pid}" reload reload-b-changed-key \
      "${EVIDENCE}/reload-b-changed-key.stdout.log" "${EVIDENCE}/reload-b-changed-key.stderr.log"
    run_endpoint_cli b "${daemon_b_pid}" status status-b-changed-key \
      "${EVIDENCE}/status-b-changed-key.json" "${EVIDENCE}/status-b-changed-key.stderr"
    validate_faketcp_status "${EVIDENCE}/status-b-changed-key.json" \
      "${EVIDENCE}/identity-b-changed-key.json" >"${EVIDENCE}/status-b-changed-key-check.log"
    compare_identity_replaced "${EVIDENCE}/identity-b-same-key.json" \
      "${EVIDENCE}/identity-b-changed-key.json" | tee "${EVIDENCE}/changed-key-b.log"
  fi
elif [[ "${transport}" != "wireguard" ]]; then
  validate_baseline_status "${EVIDENCE}/status-a-initial.json" a \
    >"${EVIDENCE}/status-a-initial-check.log"
  validate_baseline_status "${EVIDENCE}/status-b-initial.json" b \
    >"${EVIDENCE}/status-b-initial-check.log"
fi

stage="capture-and-connectivity"
ip netns exec "${NSR}" timeout --signal=INT --kill-after=5s 120 \
  tcpdump -U -nn -s 128 -c 512 -i any -w "${EVIDENCE}/outer.pcap" \
  >"${EVIDENCE}/tcpdump.stdout.log" 2>"${EVIDENCE}/tcpdump.stderr.log" &
tcpdump_pid=$!
record_background_start tcpdump-outer "${EVIDENCE}/tcpdump.stdout.log" \
  "${EVIDENCE}/tcpdump.stderr.log" "${tcpdump_pid}" \
  ip netns exec "${NSR}" timeout --signal=INT --kill-after=5s 120 \
  tcpdump -U -nn -s 128 -c 512 -i any -w "${EVIDENCE}/outer.pcap"
for attempt in 1 2 3 4 5; do
  [[ -s "${EVIDENCE}/tcpdump.stderr.log" ]] && break
  [[ ! -d "/proc/${tcpdump_pid}" ]] && break
  sleep 0.2
done
if [[ ! -d "/proc/${tcpdump_pid}" ]]; then
  if wait "${tcpdump_pid}"; then tcpdump_status=0; else tcpdump_status=$?; fi
  record_background_finish tcpdump-outer "${tcpdump_status}"
  tcpdump_pid=""
  echo "error: outer tcpdump exited before connectivity checks (rc=${tcpdump_status})" >&2
  exit 1
fi

wait_ping() {
  local ns="$1"
  local target="$2"
  local attempt
  for ((attempt = 1; attempt <= 10; attempt++)); do
    if run_recorded_command "ping-${ns}-attempt-${attempt}" \
      "${EVIDENCE}/ping-${ns}-attempt-${attempt}.stdout.log" \
      "${EVIDENCE}/ping-${ns}-attempt-${attempt}.stderr.log" \
      ip netns exec "${ns}" ping -c 1 -W 2 "${target}"; then
      return 0
    fi
    sleep 1
  done
  return 1
}
wait_ping "${NSA}" 10.77.0.2
wait_ping "${NSB}" 10.77.0.1

tcp_server_listening() {
  ip netns exec "${NSB}" ss -H -lnt "sport = :${IPERF_PORT}" |
    awk 'NR == 1 { found = 1 } END { exit !found }'
}

run_iperf_sample() {
  local direction="$1"
  local repetition="$2"
  local sample="${direction}-r${repetition}"
  local client_json="${EVIDENCE}/iperf-${sample}-client.json"
  local client_stderr="${EVIDENCE}/iperf-${sample}-client.stderr"
  local server_json="${EVIDENCE}/iperf-${sample}-server.json"
  local server_stderr="${EVIDENCE}/iperf-${sample}-server.stderr"
  local direction_args=()
  local attempt
  local ready=0
  local client_status=0
  local server_status=0

  case "${direction}" in
    forward) ;;
    reverse) direction_args=(-R) ;;
    bidir) direction_args=(--bidir) ;;
    *) return 2 ;;
  esac
  ip netns exec "${NSB}" timeout --signal=TERM --kill-after=3s 18 \
    iperf3 -s -1 -p "${IPERF_PORT}" -J >"${server_json}" 2>"${server_stderr}" &
  iperf_server_pid=$!
  record_background_start "iperf-${sample}-server" "${server_json}" \
    "${server_stderr}" "${iperf_server_pid}" ip netns exec "${NSB}" timeout \
    --signal=TERM --kill-after=3s 18 iperf3 -s -1 -p "${IPERF_PORT}" -J
  for ((attempt = 1; attempt <= 50; attempt++)); do
    if tcp_server_listening; then
      ready=1
      break
    fi
    [[ ! -d "/proc/${iperf_server_pid}" ]] && break
    sleep 0.1
  done
  if ((ready == 0)); then
    if wait "${iperf_server_pid}"; then server_status=0; else server_status=$?; fi
    record_background_finish "iperf-${sample}-server" "${server_status}"
    iperf_server_pid=""
    echo "error: iperf3 server did not listen for ${sample} (rc=${server_status})" >&2
    return 1
  fi

  if run_recorded_command "iperf-${sample}-client" "${client_json}" \
    "${client_stderr}" ip netns exec "${NSA}" timeout --signal=TERM \
    --kill-after=3s 18 iperf3 -c 10.77.0.2 -p "${IPERF_PORT}" \
    -t "${DURATION}" -P "${STREAMS}" "${direction_args[@]}" -J; then
    client_status=0
  else
    client_status=$?
  fi
  if wait "${iperf_server_pid}"; then
    server_status=0
  else
    server_status=$?
  fi
  record_background_finish "iperf-${sample}-server" "${server_status}"
  iperf_server_pid=""
  if ((client_status != 0 || server_status != 0)); then
    echo "error: iperf sample ${sample} failed client=${client_status} server=${server_status}" >&2
    return 1
  fi
  python3 "${IPERF_CHECKER}" "${client_json}" --direction "${direction}" \
    --streams "${STREAMS}" --minimum-bytes "${MINIMUM_BYTES}" \
    --maximum-retransmits "${MAXIMUM_RETRANSMITS}" \
    --minimum-fairness "${MINIMUM_FAIRNESS}" | tee "${EVIDENCE}/iperf-${sample}-check.log"
}

stage="iperf-matrix"
for direction in forward reverse bidir; do
  aggregate_paths=()
  for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
    run_iperf_sample "${direction}" "${repetition}"
    aggregate_paths+=("${EVIDENCE}/iperf-${direction}-r${repetition}-client.json")
  done
  python3 "${IPERF_CHECKER}" "${aggregate_paths[@]}" --direction "${direction}" \
    --streams "${STREAMS}" --minimum-bytes "${MINIMUM_BYTES}" \
    --maximum-retransmits "${MAXIMUM_RETRANSMITS}" \
    --minimum-fairness "${MINIMUM_FAIRNESS}" --aggregate |
    tee "${EVIDENCE}/iperf-${direction}-aggregate.log"
done

stage="post-status-and-capture"
if [[ "${transport}" == "faketcp" ]]; then
  # A daemon-side same-key reconcile calls the resident runtime health path.
  # For kprobe this re-queries the exact held device lease, including its
  # per-open errors/nmissed deltas and cookie continuity.  An unhealthy owner
  # may be rebuilt by the daemon, but the identity-stability proof below then
  # fails the cell instead of accepting a silently replaced generation.
  stage="post-traffic-health-reload"
  run_endpoint_cli a "${daemon_a_pid}" reload reload-a-after-traffic-health \
    "${EVIDENCE}/reload-a-after-traffic-health.stdout.log" \
    "${EVIDENCE}/reload-a-after-traffic-health.stderr.log"
  run_endpoint_cli b "${daemon_b_pid}" reload reload-b-after-traffic-health \
    "${EVIDENCE}/reload-b-after-traffic-health.stdout.log" \
    "${EVIDENCE}/reload-b-after-traffic-health.stderr.log"
fi
stage="post-status-and-capture"
if [[ "${transport}" != "wireguard" ]]; then
  run_endpoint_cli a "${daemon_a_pid}" status status-a-after-traffic \
    "${EVIDENCE}/status-a-after-traffic.json" "${EVIDENCE}/status-a-after-traffic.stderr"
  run_endpoint_cli b "${daemon_b_pid}" status status-b-after-traffic \
    "${EVIDENCE}/status-b-after-traffic.json" "${EVIDENCE}/status-b-after-traffic.stderr"
fi
if [[ "${transport}" == "faketcp" ]]; then
  validate_faketcp_status "${EVIDENCE}/status-a-after-traffic.json" \
    "${EVIDENCE}/identity-a-after-traffic.json" \
    >"${EVIDENCE}/status-a-after-traffic-check.log"
  validate_faketcp_status "${EVIDENCE}/status-b-after-traffic.json" \
    "${EVIDENCE}/identity-b-after-traffic.json" \
    >"${EVIDENCE}/status-b-after-traffic-check.log"
  identity_a_before_traffic="${EVIDENCE}/identity-a-same-key.json"
  identity_b_before_traffic="${EVIDENCE}/identity-b-same-key.json"
  if [[ "${cipher}" != "none" ]]; then
    identity_a_before_traffic="${EVIDENCE}/identity-a-changed-key.json"
    identity_b_before_traffic="${EVIDENCE}/identity-b-changed-key.json"
  fi
  compare_identity_equal "${identity_a_before_traffic}" \
    "${EVIDENCE}/identity-a-after-traffic.json" \
    >"${EVIDENCE}/identity-a-after-traffic-stability.log"
  compare_identity_equal "${identity_b_before_traffic}" \
    "${EVIDENCE}/identity-b-after-traffic.json" \
    >"${EVIDENCE}/identity-b-after-traffic-stability.log"
  if [[ "${backend}" == "classic_tc" ]]; then
    validate_classic_journal a "${EVIDENCE}/identity-a-after-traffic.json" \
      >"${EVIDENCE}/classic-journal-a-after-traffic.log"
    validate_classic_journal b "${EVIDENCE}/identity-b-after-traffic.json" \
      >"${EVIDENCE}/classic-journal-b-after-traffic.log"
  else
    validate_no_classic_journal >"${EVIDENCE}/classic-journal-tcx-after-traffic.log"
  fi
elif [[ "${transport}" != "wireguard" ]]; then
  validate_baseline_status "${EVIDENCE}/status-a-after-traffic.json" a \
    >"${EVIDENCE}/status-a-after-traffic-check.log"
  validate_baseline_status "${EVIDENCE}/status-b-after-traffic.json" b \
    >"${EVIDENCE}/status-b-after-traffic-check.log"
fi
run_recorded_command wg-a-after-traffic "${EVIDENCE}/wg-a-after-traffic.stdout.log" \
  "${EVIDENCE}/wg-a-after-traffic.stderr.log" ip netns exec "${NSA}" wg show
run_recorded_command wg-b-after-traffic "${EVIDENCE}/wg-b-after-traffic.stdout.log" \
  "${EVIDENCE}/wg-b-after-traffic.stderr.log" ip netns exec "${NSB}" wg show

if [[ -d "/proc/${tcpdump_pid}" ]]; then
  run_mutation tcpdump-stop kill -INT "${tcpdump_pid}"
fi
if wait "${tcpdump_pid}"; then
  tcpdump_status=0
else
  tcpdump_status=$?
fi
record_background_finish tcpdump-outer "${tcpdump_status}"
tcpdump_pid=""
if ((tcpdump_status != 0)); then
  echo "error: tcpdump capture failed with rc=${tcpdump_status}" >&2
  exit 1
fi
tcpdump -nn -r "${EVIDENCE}/outer.pcap" >"${EVIDENCE}/outer.txt" \
  2>"${EVIDENCE}/outer-read.stderr"
python3 - "${transport}" "${PORT_A}" "${PORT_B}" "${EVIDENCE}/outer.txt" \
  >"${EVIDENCE}/outer-validation.log" <<'PY'
import pathlib
import re
import sys

transport, port_a, port_b, raw_path = sys.argv[1:]
lines = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace").splitlines()
managed = [line for line in lines if f".{port_a}" in line or f".{port_b}" in line]
udp = [line for line in managed if " UDP," in line]
if transport == "icmp":
    if udp:
        raise SystemExit("unexpected raw WireGuard UDP packets in ICMP mode")
    expected = [line for line in lines if "ICMP echo request" in line or "ICMP echo reply" in line]
elif transport == "faketcp":
    if udp:
        raise SystemExit("unexpected raw WireGuard UDP packets in FakeTCP mode")
    expected = [line for line in managed if re.search(r"Flags \[[^]]+\]", line)]
else:
    expected = udp
if not expected:
    print(f"no {transport} outer packets were captured")
    raise SystemExit(1)
print(f"outer_transport={transport} matching_packets={len(expected)} raw_udp_packets={len(udp)}")
PY

if [[ "${transport}" == "faketcp" ]]; then
  if [[ "${backend}" == "classic_tc" ]]; then
    stage="classic-journal-recovery"
    identity_a_before_crash="${EVIDENCE}/identity-a-after-traffic.json"
    validate_classic_journal a "${identity_a_before_crash}" \
      >"${EVIDENCE}/classic-journal-a-before-crash.log"
    run_mutation daemon-a-crash-signal kill -KILL "${daemon_a_pid}"
    if wait "${daemon_a_pid}"; then
      crash_status=0
    else
      crash_status=$?
    fi
    record_background_finish daemon-a-start "${crash_status}"
    if ((crash_status != 137)); then
      echo "error: classic TC crash probe returned ${crash_status}, want 137" >&2
      exit 1
    fi
    daemon_a_pid=""
    env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
      "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
      "WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=${ARTIFACT_ROOT}" \
      "WG_MIX_EBPF_PERFORMANCE_RUN_PARENT=${RUN_PARENT}" \
      ip netns exec "${NSA}" unshare --mount --propagation private \
      "${script_path}" endpoint --run-id "${run_id}" --role a --transport "${transport}" \
      >"${EVIDENCE}/daemon-a-recovery.stdout.log" \
      2>"${EVIDENCE}/daemon-a-recovery.stderr.log" &
    daemon_a_pid=$!
    daemon_a_phase="daemon-a-recovery-start"
    record_background_start daemon-a-recovery-start \
      "${EVIDENCE}/daemon-a-recovery.stdout.log" \
      "${EVIDENCE}/daemon-a-recovery.stderr.log" "${daemon_a_pid}" \
      env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
      "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
      "WG_MIX_EBPF_PERFORMANCE_ARTIFACT_ROOT=${ARTIFACT_ROOT}" \
      "WG_MIX_EBPF_PERFORMANCE_RUN_PARENT=${RUN_PARENT}" \
      ip netns exec "${NSA}" unshare --mount --propagation private \
      "${script_path}" endpoint --run-id "${run_id}" --role a --transport "${transport}"
    printf '%s\n' "${daemon_a_pid}" >"${RUN_ROOT}/daemon-a.pid"
    wait_daemon_active a "${daemon_a_pid}" "${ENDPOINT_A_RUN}/runtime/status.json"
    run_endpoint_cli a "${daemon_a_pid}" status status-a-recovered \
      "${EVIDENCE}/status-a-recovered.json" "${EVIDENCE}/status-a-recovered.stderr"
    validate_faketcp_status "${EVIDENCE}/status-a-recovered.json" \
      "${EVIDENCE}/identity-a-recovered.json" \
      >"${EVIDENCE}/status-a-recovered-check.log"
    compare_identity_replaced "${identity_a_before_crash}" \
      "${EVIDENCE}/identity-a-recovered.json" \
      >"${EVIDENCE}/classic-crash-recovery-identity.log"
    validate_classic_journal a "${EVIDENCE}/identity-a-recovered.json" \
      >"${EVIDENCE}/classic-journal-a-recovered.log"
    recovered=0
    for ((attempt = 1; attempt <= FAKETCP_RECOVERY_ATTEMPTS; attempt++)); do
      if run_recorded_command "ping-a-after-classic-recovery-attempt-${attempt}" \
        "${EVIDENCE}/ping-a-after-classic-recovery-attempt-${attempt}.stdout.log" \
        "${EVIDENCE}/ping-a-after-classic-recovery-attempt-${attempt}.stderr.log" \
        ip netns exec "${NSA}" ping -c 1 -W 1 10.77.0.2; then
        recovered=1
        break
      fi
      sleep 1
    done
    ((recovered == 1)) || {
      echo "error: FakeTCP classic peer session did not recover within ${FAKETCP_RECOVERY_ATTEMPTS} attempts" >&2
      exit 1
    }
    run_recorded_command ping-a-after-classic-recovery \
      "${EVIDENCE}/ping-a-after-classic-recovery.stdout.log" \
      "${EVIDENCE}/ping-a-after-classic-recovery.stderr.log" \
      ip netns exec "${NSA}" ping -c 3 -W 2 10.77.0.2
  fi
  identity_a="${EVIDENCE}/identity-a-same-key.json"
  identity_b="${EVIDENCE}/identity-b-same-key.json"
  if [[ "${cipher}" != "none" ]]; then
    identity_a="${EVIDENCE}/identity-a-changed-key.json"
    identity_b="${EVIDENCE}/identity-b-changed-key.json"
  fi
  if [[ "${backend}" == "classic_tc" ]]; then
    identity_a="${EVIDENCE}/identity-a-recovered.json"
  fi
  python3 - "${daemon_a_pid}" "${identity_a}" "${daemon_b_pid}" "${identity_b}" \
    "${EVIDENCE}/owned-bpf-ids.json" "${checksum_backend}" "${KPROBE_DEVICE}" <<'PY'
import json
import pathlib
import re
import stat
import sys


def fdinfo_ids(pid: int) -> dict[str, list[int]]:
    result = {"map": set(), "prog": set(), "link": set()}
    root = pathlib.Path(f"/proc/{pid}/fdinfo")
    for entry in root.iterdir():
        try:
            text = entry.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for kind in result:
            match = re.search(rf"^{kind}_id:\s+([1-9][0-9]*)$", text, re.MULTILINE)
            if match:
                result[kind].add(int(match.group(1)))
    return {kind: sorted(values) for kind, values in result.items()}


document = {"endpoints": {}}
checksum = sys.argv[6]
lease_device = pathlib.Path(sys.argv[7])
lease_rdev = None
if checksum == "kprobe":
    lease_metadata = lease_device.lstat()
    if (
        lease_device.is_symlink()
        or not stat.S_ISCHR(lease_metadata.st_mode)
        or stat.S_IMODE(lease_metadata.st_mode) != 0o600
        or lease_metadata.st_uid != 0
        or lease_metadata.st_gid != 0
        or lease_metadata.st_nlink != 1
    ):
        raise SystemExit("kprobe lease device is not an exact character device")
    lease_rdev = lease_metadata.st_rdev
for role, pid_raw, identity_raw in (
    ("a", sys.argv[1], sys.argv[2]),
    ("b", sys.argv[3], sys.argv[4]),
):
    pid = int(pid_raw)
    identity = json.loads(pathlib.Path(identity_raw).read_text(encoding="utf-8"))
    observed = fdinfo_ids(pid)
    lease_fds = []
    for descriptor in pathlib.Path(f"/proc/{pid}/fd").iterdir():
        try:
            metadata = descriptor.stat()
        except OSError:
            continue
        if stat.S_ISCHR(metadata.st_mode) and metadata.st_rdev == lease_rdev:
            lease_fds.append(int(descriptor.name))
    if checksum == "kprobe" and len(lease_fds) != 1:
        raise SystemExit(
            f"endpoint {role} holds {len(lease_fds)} kprobe lease FDs, want exactly one"
        )
    if checksum != "kprobe" and lease_fds:
        raise SystemExit(f"endpoint {role} unexpectedly holds a kprobe lease FD")
    expected_links = {item["link_id"] for item in identity["xdp"] + identity["tcx"]}
    expected_programs = {
        item["program_id"]
        for item in identity["xdp"] + identity["tcx"] + identity["classic_tc"]
    }
    if not expected_links.issubset(set(observed["link"])):
        raise SystemExit(f"endpoint {role} exact link IDs are not process-owned FDs")
    runtime_programs = {item["program_id"] for item in identity["xdp"] + identity["tcx"]}
    if not runtime_programs.issubset(set(observed["prog"])):
        raise SystemExit(f"endpoint {role} runtime program IDs are not process-owned FDs")
    if not observed["map"]:
        raise SystemExit(f"endpoint {role} exposes no process-owned map FDs")
    document["endpoints"][role] = {
        "pid": pid,
        "ids": observed,
        "status_link_ids": sorted(expected_links),
        "status_program_ids": sorted(expected_programs),
        "kprobe_lease_fds": sorted(lease_fds),
    }
pathlib.Path(sys.argv[5]).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(
    f"faketcp_owned_ids=sealed runtime_links=exact programs=journal-or-fd "
    f"maps=fd-owned checksum={checksum} lease_fds=exact"
)
PY
fi

wait_pid_exit() {
  local pid="$1"
  local role="$2"
  local attempt
  local state
  for ((attempt = 1; attempt <= 300; attempt++)); do
    [[ ! -d "/proc/${pid}" ]] && return 0
    if ! state="$(ps -p "${pid}" -o state=)"; then
      return 0
    fi
    if [[ "${state}" == Z* ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "error: daemon ${role} did not exit within 30 seconds" >&2
  return 1
}

stop_daemon() {
  local role="$1"
  local pid="$2"
  local status
  local background_phase="${daemon_a_phase}"
  [[ "${role}" == b ]] && background_phase="${daemon_b_phase}"
  run_recorded_command "daemon-${role}-stop-signal" \
    "${EVIDENCE}/daemon-${role}-stop-signal.stdout.log" \
    "${EVIDENCE}/daemon-${role}-stop-signal.stderr.log" kill -TERM "${pid}"
  wait_pid_exit "${pid}" "${role}"
  if wait "${pid}"; then
    status=0
  else
    status=$?
  fi
  if ((status != 0)); then
    echo "error: daemon ${role} exited with rc=${status}" >&2
    return 1
  fi
  record_background_finish "${background_phase}" "${status}"
}

stage="daemon-stop"
if [[ "${transport}" != "wireguard" ]]; then
  stop_daemon a "${daemon_a_pid}"
  daemon_a_pid=""
  stop_daemon b "${daemon_b_pid}"
  daemon_b_pid=""
  /bin/cp -- "${ENDPOINT_A_RUN}/runtime/status.json" "${EVIDENCE}/status-a-final.json"
  /bin/cp -- "${ENDPOINT_B_RUN}/runtime/status.json" "${EVIDENCE}/status-b-final.json"
  python3 - "${EVIDENCE}/status-a-final.json" "${EVIDENCE}/status-b-final.json" \
  >"${EVIDENCE}/daemon-final-status-check.log" <<'PY'
import json
import pathlib
import sys

for role, raw_path in zip(("a", "b"), sys.argv[1:], strict=True):
    document = json.loads(pathlib.Path(raw_path).read_text(encoding="utf-8"))
    if document.get("state") != "stopped" or document.get("last_error"):
        raise SystemExit(f"daemon {role} final status is not a clean stop")
    print(f"daemon={role} final_state=stopped last_error=empty")
PY
fi

if [[ "${transport}" == "faketcp" ]]; then
  python3 - "${EVIDENCE}/owned-bpf-ids.json" \
    "${EVIDENCE}/exact-bpf-absence-after-stop.log" <<'PY'
import datetime
import json
import pathlib
import subprocess
import sys

source = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
output = pathlib.Path(sys.argv[2])
all_ids = {"link": set(), "prog": set(), "map": set()}
for endpoint in source["endpoints"].values():
    for kind in all_ids:
        all_ids[kind].update(endpoint["ids"][kind])
    all_ids["prog"].update(endpoint["status_program_ids"])
residual = []
with output.open("w", encoding="utf-8") as handle:
    for kind in ("link", "prog", "map"):
        argv = ["bpftool", "-j", kind, "show"]
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        completed = subprocess.run(argv, text=True, capture_output=True, check=False)
        finished = datetime.datetime.now(datetime.timezone.utc).isoformat()
        handle.write(
            f"timestamp={started} event=start kind={kind} argv={' '.join(argv)}\n"
        )
        handle.write(f"stdout_begin kind={kind}\n{completed.stdout}")
        handle.write(f"stdout_end kind={kind}\n")
        handle.write(f"stderr_begin kind={kind}\n{completed.stderr}")
        handle.write(f"stderr_end kind={kind}\n")
        handle.write(
            f"timestamp={finished} event=finish kind={kind} "
            f"rc={completed.returncode}\n"
        )
        if completed.returncode != 0:
            raise SystemExit(
                f"cannot inventory {kind} IDs after daemon stop: "
                f"rc={completed.returncode} stderr={completed.stderr!r}"
            )
        try:
            inventory = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid bpftool {kind} inventory JSON: {exc}") from exc
        if not isinstance(inventory, list):
            raise SystemExit(f"bpftool {kind} inventory is not a list")
        live_ids = set()
        for item in inventory:
            if not isinstance(item, dict) or not isinstance(item.get("id"), int):
                raise SystemExit(f"bpftool {kind} inventory has an invalid row")
            live_ids.add(item["id"])
        residual.extend((kind, object_id) for object_id in sorted(all_ids[kind] & live_ids))
if residual:
    raise SystemExit(f"process-owned BPF objects remain after daemon stop: {residual}")
print(
    "faketcp_stop_cleanup=complete exact_links_absent=1 "
    "exact_programs_absent=1 exact_maps_absent=1"
)
PY
  python3 - "${ENDPOINT_A_VAR}/pin-owners" "${ENDPOINT_B_VAR}/pin-owners" \
    >"${EVIDENCE}/classic-journal-absence-after-stop.log" <<'PY'
import pathlib
import sys

for raw in sys.argv[1:]:
    root = pathlib.Path(raw)
    if not root.exists():
        continue
    if not root.is_dir() or root.is_symlink():
        raise SystemExit(f"FakeTCP classic journal root type is unsafe: {root}")
    residual = list(root.iterdir())
    if residual:
        raise SystemExit(f"FakeTCP classic owner root is nonempty after clean stop: {residual}")
print("faketcp_classic_journal_absent_after_stop=1")
PY
fi

stage="attachment-cleanliness"
for ns in "${NSA}" "${NSB}"; do
  diagnostic_command "${EVIDENCE}/attachment-cleanliness.log" "${ns}-link" \
    ip -details -n "${ns}" link show dev under0
  diagnostic_command "${EVIDENCE}/attachment-cleanliness.log" "${ns}-qdisc" \
    ip netns exec "${ns}" tc qdisc show dev under0
  diagnostic_command "${EVIDENCE}/attachment-cleanliness.log" "${ns}-tc-ingress" \
    ip netns exec "${ns}" tc filter show dev under0 ingress
  diagnostic_command "${EVIDENCE}/attachment-cleanliness.log" "${ns}-tc-egress" \
    ip netns exec "${ns}" tc filter show dev under0 egress
  diagnostic_command "${EVIDENCE}/attachment-cleanliness.log" "${ns}-bpf-net" \
    ip netns exec "${ns}" bpftool net
  diagnostic_command "${EVIDENCE}/attachment-cleanliness.log" "${ns}-nft-ruleset" \
    ip netns exec "${ns}" nft list ruleset
done
python3 - "${EVIDENCE}/attachment-cleanliness.log" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
for forbidden in (
    "wg_mix_",
    "wg-mix-ebpf",
    "xdp/id",
    "tcx/ingress",
    "tcx/egress",
):
    if forbidden in text:
        raise SystemExit(f"residual BPF attachment marker: {forbidden}")
PY

stage="success-cleanup"
for ns in "${NSA}" "${NSR}" "${NSB}"; do
  remaining_pids="$(ip netns pids "${ns}")"
  if [[ -n "${remaining_pids}" ]]; then
    echo "error: run-owned namespace has retained processes before cleanup: ${ns}: ${remaining_pids}" >&2
    exit 1
  fi
done
run_mutation netns-delete-a ip netns delete "${NSA}"
run_mutation netns-delete-router ip netns delete "${NSR}"
run_mutation netns-delete-b ip netns delete "${NSB}"
for secret_path in "${ENDPOINT_A_RUN}/xor.key" "${ENDPOINT_B_RUN}/xor.key" \
  "${ENDPOINT_A_RUN}/xor.key.next" "${ENDPOINT_B_RUN}/xor.key.next"; do
  if [[ ! -e "${secret_path}" && ! -L "${secret_path}" ]]; then
    continue
  fi
  if [[ "${secret_path}" != "${RUN_ROOT}/"* || ! -f "${secret_path}" ||
    -L "${secret_path}" || "$(stat -c '%u:%g:%a:%h' -- "${secret_path}")" != 0:0:600:1 ]]; then
    echo "error: owned XOR secret path is unsafe: ${secret_path}" >&2
    exit 1
  fi
  run_mutation xor-secret-remove /bin/rm -- "${secret_path}"
done
if [[ -n "$(ip netns list | awk -v a="${NSA}" -v r="${NSR}" -v b="${NSB}" \
  '$1 == a || $1 == r || $1 == b { print $1 }')" ]]; then
  echo "error: run-owned network namespace remains after successful cleanup" >&2
  exit 1
fi
shopt -s nullglob
secret_inventory=("${SECRETS}"/*)
shopt -u nullglob
if ((${#secret_inventory[@]} != 0)); then
  echo "error: sensitive files remain in the run secret directory" >&2
  exit 1
fi
for secret_path in "${ENDPOINT_A_RUN}/xor.key" "${ENDPOINT_B_RUN}/xor.key" \
  "${ENDPOINT_A_RUN}/xor.key.next" "${ENDPOINT_B_RUN}/xor.key.next"; do
  [[ ! -e "${secret_path}" && ! -L "${secret_path}" ]] || {
    echo "error: endpoint XOR secret remains after successful cleanup: ${secret_path}" >&2
    exit 1
  }
done
if [[ "${transport}" != wireguard ]]; then
  if [[ ! -f "${SHARED_MAINTENANCE_TARGET}" || -L "${SHARED_MAINTENANCE_TARGET}" ||
    "$(stat -c '%u:%g:%a:%h' -- "${SHARED_MAINTENANCE_TARGET}")" != "0:0:600:1" ]]; then
    echo "error: global lifecycle maintenance gate is absent or unsafe after endpoint runs" >&2
    exit 1
  fi
  maintenance_target_identity_after="$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "${SHARED_MAINTENANCE_TARGET}")"
  if [[ "${maintenance_target_identity_before}" != absent &&
    "${maintenance_target_identity_after}" != "${maintenance_target_identity_before}" ]]; then
    echo "error: global lifecycle maintenance gate identity changed across endpoint runs" >&2
    exit 1
  fi
  python3 - "${SHARED_MAINTENANCE_TARGET}" \
    "${maintenance_target_identity_before}" "${maintenance_target_identity_after}" \
    >"${EVIDENCE}/maintenance-target-after.log" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
owner = json.loads(path.read_text(encoding="utf-8"))
if (
    set(owner) - {"pid", "action", "config_path", "run_dir"}
    or not isinstance(owner.get("pid"), int)
    or owner["pid"] <= 0
    or not isinstance(owner.get("action"), str)
    or not owner["action"]
):
    raise SystemExit("global lifecycle maintenance gate owner record is malformed")
print(f"maintenance_target={path}")
print(f"identity_before={sys.argv[2]}")
print(f"identity_after={sys.argv[3]}")
result = "created-secured-file" if sys.argv[2] == "absent" else "same-secured-file"
print(f"result={result} owner_record=valid")
PY
fi

if [[ "${transport}" == "wireguard" ]]; then
  : >"${RUN_ROOT}/daemon-a.pid"
  : >"${RUN_ROOT}/daemon-b.pid"
fi
printf 'format=wg-mix-ebpf-b82-production-performance-complete-v1\nrun_id=%s\nmanifest_sha256=%s\nactive_resources=absent\nsensitive_files=absent\n' \
  "${run_id}" "$(sha256sum -- "${RUN_ROOT}/manifest" | awk '{print $1}')" \
  >"${RUN_ROOT}/complete"
trap - ERR INT TERM
printf 'PERFORMANCE_PRODUCTION_CELL_COMPLETE run_id=%s label=%s transport=%s backend=%s checksum_backend=%s artifact=%s cipher=%s max_bytes=%s repetitions=%s duration_seconds=%s samples=9 evidence=%s timestamp=%s\n' \
  "${run_id}" "${label}" "${transport}" "${backend}" "${checksum_backend}" \
  "${artifact}" "${cipher}" "${max_bytes}" \
  "${REPETITIONS}" "${DURATION}" "${EVIDENCE}" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
