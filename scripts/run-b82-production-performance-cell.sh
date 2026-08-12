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
readonly IPERF_CHECKER_NAME="scripts/check-iperf3-tcp.py"
readonly RUN_PARENT="/run/wg-mix-ebpf-performance-tests"
readonly SHARED_RUN_TARGET="/run/wg-mix-ebpf"
readonly SHARED_VAR_TARGET="/var/lib/wg-mix-ebpf"
readonly SHARED_MAINTENANCE_TARGET="/run/.wg-mix-ebpf-daemon.lease.maintenance"
readonly DURATION=3
readonly REPETITIONS=3
readonly STREAMS=1
readonly MINIMUM_BYTES=1048576
readonly MAXIMUM_RETRANSMITS=0
readonly MINIMUM_FAIRNESS=0.90

PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB XOR_PASSWORD

if [[ "${EUID}" -ne 0 || "${EGID}" -ne 0 ]]; then
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
if [[ ! "${source_root}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]]; then
  echo "error: production performance runner must use a root-owned source stage" >&2
  exit 1
fi

readonly BIN="${source_root}/${BIN_NAME}"
readonly BASELINE_OBJECT="${source_root}/${BASELINE_OBJECT_NAME}"
readonly FAKETCP_OBJECT="${source_root}/${FAKETCP_OBJECT_NAME}"
readonly IPERF_CHECKER="${source_root}/${IPERF_CHECKER_NAME}"

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
validate_staged_regular "${IPERF_CHECKER}" no

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
    [[ ! "${transport}" =~ ^(icmp|faketcp)$ ]]; then
    echo "error: invalid endpoint child identity" >&2
    return 2
  fi

  local run_root="${RUN_PARENT}/${run_id}"
  local endpoint_root="${run_root}/endpoint-${role}"
  local endpoint_run="${endpoint_root}/run"
  local endpoint_var="${endpoint_root}/var"
  local endpoint_maintenance="${endpoint_root}/maintenance.gate"
  local netns="wgp${run_id}${role}"
  local pin_path="/sys/fs/bpf/wg-mix-ebpf-performance-${run_id}-${role}"
  local current_mountns

  validate_root_directory "${run_root}"
  validate_root_directory "${endpoint_root}"
  validate_root_directory "${endpoint_run}"
  validate_root_directory "${endpoint_var}"
  if [[ ! -f "${endpoint_maintenance}" || -L "${endpoint_maintenance}" ||
    "$(stat -c '%u:%g:%a:%h' -- "${endpoint_maintenance}")" != "0:0:600:1" ]]; then
    echo "error: endpoint child maintenance gate is unsafe" >&2
    return 1
  fi
  if [[ ! -f "${run_root}/owner" || -L "${run_root}/owner" ]] ||
    [[ "$(<"${run_root}/owner")" != "wg-mix-ebpf-performance:${run_id}" ]]; then
    echo "error: endpoint child ownership marker mismatch" >&2
    return 1
  fi
  if [[ "${WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS-}" == "" ]]; then
    echo "error: endpoint child lacks sealed parent mount namespace" >&2
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

  printf 'ENDPOINT_MUTATION role=%s argv=' "${role}"
  printf '%q ' mount --bind "${endpoint_run}" "${SHARED_RUN_TARGET}"
  printf '\n'
  mount --bind "${endpoint_run}" "${SHARED_RUN_TARGET}"
  printf 'ENDPOINT_MUTATION role=%s argv=' "${role}"
  printf '%q ' mount --bind "${endpoint_var}" "${SHARED_VAR_TARGET}"
  printf '\n'
  mount --bind "${endpoint_var}" "${SHARED_VAR_TARGET}"
  printf 'ENDPOINT_MUTATION role=%s argv=' "${role}"
  printf '%q ' mount --bind "${endpoint_maintenance}" "${SHARED_MAINTENANCE_TARGET}"
  printf '\n'
  mount --bind "${endpoint_maintenance}" "${SHARED_MAINTENANCE_TARGET}"
  printf 'ENDPOINT_MUTATION role=%s argv=' "${role}"
  printf '%q ' mount -t bpf -o mode=0700 bpf /sys/fs/bpf
  printf '\n'
  mount -t bpf -o mode=0700 bpf /sys/fs/bpf

  local daemon_environment=(
    "PATH=${SAFE_PATH}"
    "LC_ALL=C"
    "WG_MIX_EBPF_OBJECT=${BASELINE_OBJECT}"
    "WG_MIX_EBPF_PIN_PATH=${pin_path}"
  )
  if [[ "${transport}" == "faketcp" ]]; then
    daemon_environment+=("WG_MIX_EBPF_FAKETCP_OBJECT=${FAKETCP_OBJECT}")
  fi
  printf 'ENDPOINT_DAEMON_EXEC role=%s netns=%s pin=%s argv=' \
    "${role}" "${netns}" "${pin_path}"
  printf '%q ' "${BIN}" run --config /run/wg-mix-ebpf/config.yaml \
    --run-dir /run/wg-mix-ebpf/runtime \
    --state-dir /var/lib/wg-mix-ebpf/state --shutdown-timeout 20s
  printf '\n'
  exec ip netns exec "${netns}" env -i "${daemon_environment[@]}" \
    "${BIN}" run --config /run/wg-mix-ebpf/config.yaml \
    --run-dir /run/wg-mix-ebpf/runtime \
    --state-dir /var/lib/wg-mix-ebpf/state --shutdown-timeout 20s
}

if [[ "${1-}" == "endpoint" ]]; then
  endpoint_child "$@"
  exit $?
fi

if [[ "${1-}" != "run" ]]; then
  echo "usage: ${STAGED_NAME} run --run-id <8hex> --label <label> --transport <icmp|faketcp> --backend <tcx|classic_tc> --cipher <none|prefix|full> --max-bytes <value>" >&2
  exit 2
fi
shift

run_id=""
label=""
transport=""
backend=""
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
  [[ ! "${label}" =~ ^(icmp-(tcx|classic_tc)-baseline|faketcp-tcx-(baseline|prefix-(4|16|64|128|256|512|1024|2048)|full-2048))$ ]] ||
  [[ ! "${transport}" =~ ^(icmp|faketcp)$ ]] ||
  [[ ! "${backend}" =~ ^(tcx|classic_tc)$ ]] ||
  [[ ! "${cipher}" =~ ^(none|prefix|full)$ ]] ||
  [[ ! "${max_bytes}" =~ ^(4|16|64|128|256|512|1024|2048)$ ]]; then
  echo "error: invalid production performance cell arguments" >&2
  exit 2
fi
if [[ "${transport}" == "icmp" && ("${cipher}" != "none" || "${max_bytes}" != "4") ]]; then
  echo "error: ICMP performance permits only the no-XOR sentinel" >&2
  exit 2
fi
if [[ "${transport}" == "faketcp" && "${backend}" != "tcx" ]]; then
  echo "error: FakeTCP production performance requires TCX" >&2
  exit 2
fi
if [[ "${cipher}" == "full" && "${max_bytes}" != "2048" ]]; then
  echo "error: full-payload performance requires max_bytes=2048" >&2
  exit 2
fi
if [[ "${cipher}" == "none" && "${max_bytes}" != "4" ]]; then
  echo "error: no-XOR performance requires max_bytes=4 sentinel" >&2
  exit 2
fi
if [[ "${transport}" == "faketcp" ]]; then
  validate_staged_regular "${FAKETCP_OBJECT}" no
  if [[ ! -d /sys/module/wg_mix_faketcp_checksum ||
    ! -r /sys/kernel/btf/wg_mix_faketcp_checksum ]]; then
    echo "error: FakeTCP requires the administrator-provisioned wg_mix_faketcp_checksum module and BTF" >&2
    exit 1
  fi
fi

for command_name in ip wg ping iperf3 python3 timeout tcpdump tc bpftool \
  unshare nsenter mount awk grep stat date sha256sum nft ss sysctl ps tee; do
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

if [[ ! -d "${RUN_PARENT}" ]]; then
  mkdir --mode=0700 -- "${RUN_PARENT}"
fi
validate_root_directory "${RUN_PARENT}"
if [[ -e "${RUN_PARENT}/${run_id}" || -L "${RUN_PARENT}/${run_id}" ]]; then
  echo "error: production performance run already exists: ${RUN_PARENT}/${run_id}" >&2
  exit 1
fi
for shared_target in "${SHARED_RUN_TARGET}" "${SHARED_VAR_TARGET}"; do
  if [[ ! -d "${shared_target}" ]]; then
    echo "error: reviewed mount target must be provisioned before the run: ${shared_target}" >&2
    exit 1
  fi
  validate_root_directory "${shared_target}"
done
if [[ ! -f "${SHARED_MAINTENANCE_TARGET}" || -L "${SHARED_MAINTENANCE_TARGET}" ||
  "$(stat -c '%u:%g:%a:%h' -- "${SHARED_MAINTENANCE_TARGET}")" != "0:0:600:1" ]]; then
  echo "error: global lifecycle maintenance target is missing or unsafe: ${SHARED_MAINTENANCE_TARGET}" >&2
  exit 1
fi
maintenance_target_stat_before="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "${SHARED_MAINTENANCE_TARGET}")"
maintenance_target_sha_before="$(sha256sum -- "${SHARED_MAINTENANCE_TARGET}" | awk '{print $1}')"
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

mkdir --mode=0700 -- "${RUN_ROOT}"
printf 'wg-mix-ebpf-performance:%s\n' "${run_id}" >"${RUN_ROOT}/owner"
mkdir --mode=0700 -- "${EVIDENCE}" "${SECRETS}" \
  "${ENDPOINT_A}" "${ENDPOINT_A_RUN}" "${ENDPOINT_A_VAR}" \
  "${ENDPOINT_B}" "${ENDPOINT_B_RUN}" "${ENDPOINT_B_VAR}"
mkdir --mode=0700 -- "${ENDPOINT_A_RUN}/runtime" "${ENDPOINT_A_VAR}/state" \
  "${ENDPOINT_B_RUN}/runtime" "${ENDPOINT_B_VAR}/state"
: >"${ENDPOINT_A}/maintenance.gate"
: >"${ENDPOINT_B}/maintenance.gate"

stage="initialized"
daemon_a_pid=""
daemon_b_pid=""
tcpdump_pid=""
iperf_server_pid=""
teardown_complete=0

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
printf 'write_set=%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
  "${RUN_ROOT}" "${NSA}" "${NSR}" "${NSB}" "${VETH_A}:${VETH_RA}" \
  "${VETH_B}:${VETH_RB}" "/sys/fs/bpf/wg-mix-ebpf-performance-${run_id}-{a,b}" \
  "${ENDPOINT_A}/maintenance.gate->${SHARED_MAINTENANCE_TARGET}" \
  "${ENDPOINT_B}/maintenance.gate->${SHARED_MAINTENANCE_TARGET}" \
  >>"${RUN_ROOT}/manifest"
printf 'source_root=%s\nbaseline_object_sha256=%s\n' "${source_root}" \
  "$(sha256sum -- "${BASELINE_OBJECT}" | awk '{print $1}')" >>"${RUN_ROOT}/manifest"
if [[ "${transport}" == "faketcp" ]]; then
  printf 'faketcp_object_sha256=%s\n' \
    "$(sha256sum -- "${FAKETCP_OBJECT}" | awk '{print $1}')" >>"${RUN_ROOT}/manifest"
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

  if [[ "${transport}" == "icmp" ]]; then
    if [[ "${role}" == "a" ]]; then
      transport_block=$'    transport:\n      mode: icmp\n      icmp:\n        role: client\n        id: 21249'
    else
      transport_block=$'    transport:\n      mode: icmp\n      icmp:\n        role: server'
    fi
  else
    transport_block=$'    transport:\n      mode: faketcp\n      faketcp:\n        checksum_mode: partial-complete-reset-required\n        ingress_mode: xdp-generic-exact'
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
  attachment_backend: ${backend}
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
printf '%s\n' "${private_a}" >"${SECRETS}/private-a"
printf '%s\n' "${private_b}" >"${SECRETS}/private-b"
unset private_a private_b

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
run_mutation wg-config-a ip netns exec "${NSA}" wg set wg0 \
  private-key "${SECRETS}/private-a" listen-port "${PORT_A}" fwmark 0x10000001 \
  peer "${public_b}" allowed-ips 10.77.0.2/32 endpoint 198.19.82.1:${PORT_B} \
  persistent-keepalive 1
run_mutation wg-config-b ip netns exec "${NSB}" wg set wg0 \
  private-key "${SECRETS}/private-b" listen-port "${PORT_B}" fwmark 0x10000002 \
  peer "${public_a}" allowed-ips 10.77.0.1/32 endpoint 198.18.82.1:${PORT_A} \
  persistent-keepalive 1
unset public_a public_b
run_mutation private-key-remove-a /bin/rm -- "${SECRETS}/private-a"
run_mutation private-key-remove-b /bin/rm -- "${SECRETS}/private-b"
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
  for ((attempt = 1; attempt <= 300; attempt++)); do
    if [[ ! -d "/proc/${pid}" ]] ||
      ! state="$(ps -p "${pid}" -o state=)" || [[ "${state}" == Z* ]]; then
      if wait "${pid}"; then status=0; else status=$?; fi
      record_background_finish "daemon-${role}-start" "${status}"
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
parent_mountns="$(stat -Lc '%d:%i' -- /proc/self/ns/mnt)"
if [[ ! "${parent_mountns}" =~ ^[1-9][0-9]*:[1-9][0-9]*$ ]]; then
  echo "error: cannot seal parent mount namespace" >&2
  exit 1
fi
env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
  "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
  unshare --mount --propagation private "${script_path}" endpoint \
  --run-id "${run_id}" --role a --transport "${transport}" \
  >"${EVIDENCE}/daemon-a.stdout.log" 2>"${EVIDENCE}/daemon-a.stderr.log" &
daemon_a_pid=$!
record_background_start daemon-a-start "${EVIDENCE}/daemon-a.stdout.log" \
  "${EVIDENCE}/daemon-a.stderr.log" "${daemon_a_pid}" \
  env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
  "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
  unshare --mount --propagation private "${script_path}" endpoint \
  --run-id "${run_id}" --role a --transport "${transport}"
printf '%s\n' "${daemon_a_pid}" >"${RUN_ROOT}/daemon-a.pid"

env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
  "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
  unshare --mount --propagation private "${script_path}" endpoint \
  --run-id "${run_id}" --role b --transport "${transport}" \
  >"${EVIDENCE}/daemon-b.stdout.log" 2>"${EVIDENCE}/daemon-b.stderr.log" &
daemon_b_pid=$!
record_background_start daemon-b-start "${EVIDENCE}/daemon-b.stdout.log" \
  "${EVIDENCE}/daemon-b.stderr.log" "${daemon_b_pid}" \
  env -i "PATH=${SAFE_PATH}" "LC_ALL=C" \
  "WG_MIX_EBPF_PERFORMANCE_PARENT_MOUNTNS=${parent_mountns}" \
  unshare --mount --propagation private "${script_path}" endpoint \
  --run-id "${run_id}" --role b --transport "${transport}"
printf '%s\n' "${daemon_b_pid}" >"${RUN_ROOT}/daemon-b.pid"
wait_daemon_active a "${daemon_a_pid}" "${ENDPOINT_A_RUN}/runtime/status.json"
wait_daemon_active b "${daemon_b_pid}" "${ENDPOINT_B_RUN}/runtime/status.json"

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
    "${BIN}" "${action}" --config /run/wg-mix-ebpf/config.yaml
    --run-dir /run/wg-mix-ebpf/runtime --state-dir /var/lib/wg-mix-ebpf/state
  )
  run_recorded_command "${phase}" "${stdout_path}" "${stderr_path}" "${command[@]}"
}

validate_faketcp_status() {
  local status_path="$1"
  local identity_path="$2"
  python3 - "${status_path}" "${identity_path}" "${FAKETCP_OBJECT}" <<'PY'
import json
import pathlib
import re
import sys

status_path = pathlib.Path(sys.argv[1])
identity_path = pathlib.Path(sys.argv[2])
expected_object = sys.argv[3]
doc = json.loads(status_path.read_text(encoding="utf-8"))
dataplane = doc.get("dataplane")
if not isinstance(dataplane, dict) or dataplane.get("mode") != "faketcp":
    raise SystemExit("status does not report the production FakeTCP dataplane")
fake = dataplane.get("faketcp")
if not isinstance(fake, dict):
    raise SystemExit("status lacks FakeTCP owner detail")
if fake.get("owner_kind") != "process-owned" or fake.get("healthy") is not True:
    raise SystemExit("FakeTCP owner is not healthy/process-owned")
if fake.get("barrier") != "open" or fake.get("error"):
    raise SystemExit("FakeTCP generation barrier is not healthy and open")
if not isinstance(fake.get("generation"), int) or fake["generation"] <= 0:
    raise SystemExit("FakeTCP generation is invalid")
if not re.fullmatch(r"[0-9a-f]{32}", str(fake.get("incarnation", ""))):
    raise SystemExit("FakeTCP incarnation is invalid")
if fake.get("object_source") != expected_object:
    raise SystemExit("FakeTCP status object source is not the reviewed staged object")
if not re.fullmatch(r"[0-9a-f]{64}", str(fake.get("object_sha256", ""))):
    raise SystemExit("FakeTCP object SHA-256 is invalid")
xdp = fake.get("xdp")
tcx = fake.get("tcx")
if not isinstance(xdp, list) or len(xdp) != 1:
    raise SystemExit("FakeTCP must report exactly one XDP attachment")
if not isinstance(tcx, list) or len(tcx) != 2:
    raise SystemExit("FakeTCP must report exactly two TCX attachments")
if xdp[0].get("mode") != "generic":
    raise SystemExit("FakeTCP XDP mode is not exact generic")
directions = {item.get("direction") for item in tcx}
if directions != {"ingress", "egress"}:
    raise SystemExit("FakeTCP TCX directions are incomplete")
for item in xdp + tcx:
    if not isinstance(item.get("ifindex"), int) or item["ifindex"] <= 0:
        raise SystemExit("FakeTCP attachment ifindex is invalid")
    if not isinstance(item.get("link_id"), int) or item["link_id"] <= 0:
        raise SystemExit("FakeTCP attachment link ID is invalid")
    if not isinstance(item.get("program_id"), int) or item["program_id"] <= 0:
        raise SystemExit("FakeTCP attachment program ID is invalid")
if len({item["link_id"] for item in xdp + tcx}) != 3:
    raise SystemExit("FakeTCP exact link IDs are not distinct")
identity = {
    "generation": fake["generation"],
    "incarnation": fake["incarnation"],
    "object_source": fake["object_source"],
    "object_sha256": fake["object_sha256"],
    "xdp": xdp,
    "tcx": sorted(tcx, key=lambda item: item["direction"]),
}
identity_path.write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(
    "faketcp_status=healthy owner_kind=process-owned barrier=open "
    f"generation={fake['generation']} xdp_links=1 tcx_links=2"
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
    raise SystemExit("same-key reload replaced the exact process-owned FakeTCP identity")
print("faketcp_same_key_reload=noop exact_identity=unchanged")
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
before_programs = {item["program_id"] for item in before["xdp"] + before["tcx"]}
after_programs = {item["program_id"] for item in after["xdp"] + after["tcx"]}
if before["incarnation"] == after["incarnation"]:
    raise SystemExit("changed-key reload retained the old FakeTCP incarnation")
if before_links & after_links or before_programs & after_programs:
    raise SystemExit("changed-key reload overlapped old and replacement exact BPF IDs")
print("faketcp_changed_key_reload=serial-replacement exact_identity=replaced")
PY
}

stage="initial-status"
run_endpoint_cli a "${daemon_a_pid}" status status-a-initial \
  "${EVIDENCE}/status-a-initial.json" "${EVIDENCE}/status-a-initial.stderr"
run_endpoint_cli b "${daemon_b_pid}" status status-b-initial \
  "${EVIDENCE}/status-b-initial.json" "${EVIDENCE}/status-b-initial.stderr"

if [[ "${transport}" == "faketcp" ]]; then
  validate_faketcp_status "${EVIDENCE}/status-a-initial.json" \
    "${EVIDENCE}/identity-a-initial.json" | tee "${EVIDENCE}/status-a-initial-check.log"
  validate_faketcp_status "${EVIDENCE}/status-b-initial.json" \
    "${EVIDENCE}/identity-b-initial.json" | tee "${EVIDENCE}/status-b-initial-check.log"

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
fi

stage="capture-and-connectivity"
ip netns exec "${NSR}" timeout --signal=INT --kill-after=5s 120 \
  tcpdump -U -nn -i any -w "${EVIDENCE}/outer.pcap" \
  >"${EVIDENCE}/tcpdump.stdout.log" 2>"${EVIDENCE}/tcpdump.stderr.log" &
tcpdump_pid=$!
record_background_start tcpdump-outer "${EVIDENCE}/tcpdump.stdout.log" \
  "${EVIDENCE}/tcpdump.stderr.log" "${tcpdump_pid}" \
  ip netns exec "${NSR}" timeout --signal=INT --kill-after=5s 120 \
  tcpdump -U -nn -i any -w "${EVIDENCE}/outer.pcap"
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
run_endpoint_cli a "${daemon_a_pid}" status status-a-after-traffic \
  "${EVIDENCE}/status-a-after-traffic.json" "${EVIDENCE}/status-a-after-traffic.stderr"
run_endpoint_cli b "${daemon_b_pid}" status status-b-after-traffic \
  "${EVIDENCE}/status-b-after-traffic.json" "${EVIDENCE}/status-b-after-traffic.stderr"
run_recorded_command wg-a-after-traffic "${EVIDENCE}/wg-a-after-traffic.stdout.log" \
  "${EVIDENCE}/wg-a-after-traffic.stderr.log" ip netns exec "${NSA}" wg show
run_recorded_command wg-b-after-traffic "${EVIDENCE}/wg-b-after-traffic.stdout.log" \
  "${EVIDENCE}/wg-b-after-traffic.stderr.log" ip netns exec "${NSB}" wg show

run_mutation tcpdump-stop kill -INT "${tcpdump_pid}"
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
if udp:
    print("unexpected raw WireGuard UDP packets:")
    print("\n".join(udp))
    raise SystemExit(1)
if transport == "icmp":
    expected = [line for line in lines if "ICMP echo request" in line or "ICMP echo reply" in line]
else:
    expected = [line for line in managed if re.search(r"Flags \[[^]]+\]", line)]
if not expected:
    print(f"no {transport} outer packets were captured")
    raise SystemExit(1)
print(f"outer_transport={transport} matching_packets={len(expected)} raw_udp_packets=0")
PY

if [[ "${transport}" == "faketcp" ]]; then
  identity_a="${EVIDENCE}/identity-a-same-key.json"
  identity_b="${EVIDENCE}/identity-b-same-key.json"
  if [[ "${cipher}" != "none" ]]; then
    identity_a="${EVIDENCE}/identity-a-changed-key.json"
    identity_b="${EVIDENCE}/identity-b-changed-key.json"
  fi
  python3 - "${daemon_a_pid}" "${identity_a}" "${daemon_b_pid}" "${identity_b}" \
    "${EVIDENCE}/owned-bpf-ids.json" <<'PY'
import json
import pathlib
import re
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
for role, pid_raw, identity_raw in (
    ("a", sys.argv[1], sys.argv[2]),
    ("b", sys.argv[3], sys.argv[4]),
):
    pid = int(pid_raw)
    identity = json.loads(pathlib.Path(identity_raw).read_text(encoding="utf-8"))
    observed = fdinfo_ids(pid)
    expected_links = {item["link_id"] for item in identity["xdp"] + identity["tcx"]}
    expected_programs = {item["program_id"] for item in identity["xdp"] + identity["tcx"]}
    if not expected_links.issubset(set(observed["link"])):
        raise SystemExit(f"endpoint {role} exact link IDs are not process-owned FDs")
    if not expected_programs.issubset(set(observed["prog"])):
        raise SystemExit(f"endpoint {role} exact program IDs are not process-owned FDs")
    if not observed["map"]:
        raise SystemExit(f"endpoint {role} exposes no process-owned map FDs")
    document["endpoints"][role] = {
        "pid": pid,
        "ids": observed,
        "status_link_ids": sorted(expected_links),
        "status_program_ids": sorted(expected_programs),
    }
pathlib.Path(sys.argv[5]).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print("faketcp_process_owned_ids=sealed links=exact programs=exact maps=fd-owned")
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
  record_background_finish "daemon-${role}-start" "${status}"
}

stage="daemon-stop"
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
residual = []
with output.open("w", encoding="utf-8") as handle:
    for kind in ("link", "prog", "map"):
        for object_id in sorted(all_ids[kind]):
            argv = ["bpftool", "-j", kind, "show", "id", str(object_id)]
            started = datetime.datetime.now(datetime.timezone.utc).isoformat()
            completed = subprocess.run(argv, text=True, capture_output=True, check=False)
            finished = datetime.datetime.now(datetime.timezone.utc).isoformat()
            handle.write(
                f"timestamp={started} event=start kind={kind} id={object_id} "
                f"argv={' '.join(argv)}\n"
            )
            handle.write(f"stdout_begin kind={kind} id={object_id}\n{completed.stdout}")
            handle.write(f"stdout_end kind={kind} id={object_id}\n")
            handle.write(f"stderr_begin kind={kind} id={object_id}\n{completed.stderr}")
            handle.write(f"stderr_end kind={kind} id={object_id}\n")
            handle.write(
                f"timestamp={finished} event=finish kind={kind} id={object_id} "
                f"rc={completed.returncode}\n"
            )
            if completed.returncode == 0:
                residual.append((kind, object_id))
if residual:
    raise SystemExit(f"process-owned BPF objects remain after daemon stop: {residual}")
print(
    "faketcp_stop_cleanup=complete exact_links_absent=1 "
    "exact_programs_absent=1 exact_maps_absent=1"
)
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
run_mutation netns-delete-a ip netns delete "${NSA}"
run_mutation netns-delete-router ip netns delete "${NSR}"
run_mutation netns-delete-b ip netns delete "${NSB}"
if [[ "${cipher}" != "none" ]]; then
  for secret_path in "${ENDPOINT_A_RUN}/xor.key" "${ENDPOINT_B_RUN}/xor.key"; do
    if [[ "${secret_path}" != "${RUN_ROOT}/"* || ! -f "${secret_path}" || -L "${secret_path}" ]]; then
      echo "error: owned XOR secret path is unsafe: ${secret_path}" >&2
      exit 1
    fi
    run_mutation xor-secret-remove /bin/rm -- "${secret_path}"
  done
fi
if [[ -n "$(ip netns list | awk -v a="${NSA}" -v r="${NSR}" -v b="${NSB}" \
  '$1 == a || $1 == r || $1 == b { print $1 }')" ]]; then
  echo "error: run-owned network namespace remains after successful cleanup" >&2
  exit 1
fi
if [[ -n "$(stat -c '%n' -- "${SECRETS}"/* 2>"${EVIDENCE}/secret-inventory.stderr")" ]]; then
  echo "error: sensitive files remain in the run secret directory" >&2
  exit 1
fi
maintenance_target_stat_after="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' -- "${SHARED_MAINTENANCE_TARGET}")"
maintenance_target_sha_after="$(sha256sum -- "${SHARED_MAINTENANCE_TARGET}" | awk '{print $1}')"
if [[ "${maintenance_target_stat_after}" != "${maintenance_target_stat_before}" ||
  "${maintenance_target_sha_after}" != "${maintenance_target_sha_before}" ]]; then
  echo "error: global lifecycle maintenance target changed across isolated endpoint runs" >&2
  exit 1
fi
printf 'maintenance_target=%s\nstat_before=%s\nstat_after=%s\nsha256_before=%s\nsha256_after=%s\nresult=unchanged\n' \
  "${SHARED_MAINTENANCE_TARGET}" "${maintenance_target_stat_before}" \
  "${maintenance_target_stat_after}" "${maintenance_target_sha_before}" \
  "${maintenance_target_sha_after}" >"${EVIDENCE}/maintenance-target-after.log"

teardown_complete=1
printf 'format=wg-mix-ebpf-b82-production-performance-complete-v1\nrun_id=%s\nmanifest_sha256=%s\nactive_resources=absent\nsensitive_files=absent\n' \
  "${run_id}" "$(sha256sum -- "${RUN_ROOT}/manifest" | awk '{print $1}')" \
  >"${RUN_ROOT}/complete"
trap - ERR INT TERM
printf 'PERFORMANCE_PRODUCTION_CELL_COMPLETE run_id=%s label=%s transport=%s backend=%s cipher=%s repetitions=%s duration_seconds=%s samples=9 evidence=%s timestamp=%s\n' \
  "${run_id}" "${label}" "${transport}" "${backend}" "${cipher}" \
  "${REPETITIONS}" "${DURATION}" "${EVIDENCE}" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
