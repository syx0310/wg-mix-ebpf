#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  printf '%s\n' 'error: root-netns-cell requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly RUN_PARENT='/var/tmp/wg-mix-ebpf-faketcp-backends-v1'
readonly NETNS_PARENT='/run/netns'
readonly SHARED_RUN='/run/wg-mix-ebpf'
readonly SHARED_VAR='/var/lib/wg-mix-ebpf'
readonly SHARED_MAINTENANCE='/run/.wg-mix-ebpf-daemon.lease.maintenance'
readonly KFUNC_MODULE='wg_mix_faketcp_checksum'
readonly KPROBE_MODULE='wg_mix_faketcp_checksum_kprobe'
readonly KPROBE_DEVICE='/dev/wg_mix_faketcp_checksum_kprobe'
readonly FAKETCP_SESSION_CAPACITY=2048
readonly FAKETCP_MAX_HALF_OPEN_SESSIONS=256
readonly FAKETCP_MAX_HALF_OPEN_PER_SOURCE=32
readonly FAKETCP_SYN_RATE_INTERVAL='100ms'
readonly FAKETCP_SYN_BURST=64
readonly FAKETCP_SYN_BURST_PER_SOURCE=8
readonly FAKETCP_SYN_SOURCE_LEDGER_CAPACITY=512
readonly FAKETCP_SYN_SOURCE_LEDGER_TTL='5m'
readonly FAKETCP_MAX_PENDING_FLOWS=128
readonly FAKETCP_MAX_PENDING_PACKETS_PER_FLOW=2
readonly FAKETCP_MAX_PENDING_BYTES=131072
readonly FAKETCP_HANDSHAKE_TIMEOUT='5s'
readonly FAKETCP_KEEPALIVE_INTERVAL='20s'
readonly FAKETCP_IDLE_TIMEOUT='2m'
PATH="${SAFE_PATH}"; LC_ALL=C; export PATH LC_ALL
IFS=$' \t\n'; umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD PYTHONHOME PYTHONPATH

validate_run_id() { [[ "$1" =~ ^[0-9a-f]{8}$ ]]; }

endpoint_child() {
  local source='' run_id='' role=''
  shift
  while (($#)); do
    (($# >= 2)) || return 64
    case "$1" in
      --source) source="$2" ;;
      --run-id) run_id="$2" ;;
      --role) role="$2" ;;
      *) return 64 ;;
    esac
    shift 2
  done
  [[ "${source}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]] || return 65
  validate_run_id "${run_id}" || return 65
  [[ "${role}" =~ ^(a|b)$ ]] || return 65
  local root="${RUN_PARENT}/${run_id}" endpoint="${RUN_PARENT}/${run_id}/endpoint-${role}"
  local artifacts="${root}/artifacts"
  local run="${endpoint}/run" var="${endpoint}/var" gate="${endpoint}/maintenance.gate"
  local netns="f${run_id}${role}" pin="/sys/fs/bpf/wg-mix-ebpf-faketcp-${run_id}-${role}"
  local netns_target="${NETNS_PARENT}/${netns}" expected_netns actual_netns
  [[ -d "${root}" && ! -L "${root}" && -f "${root}/owner.v1" &&
    "$(<"${root}/owner.v1")" == wg-mix-ebpf-faketcp-backends-v1:${run_id}:* ]] || return 79
  for path in "${endpoint}" "${run}" "${var}"; do
    [[ -d "${path}" && ! -L "${path}" && "$(stat -Lc '%u:%g:%a:%F' -- "${path}")" == '0:0:700:directory' ]] || return 79
  done
  [[ -f "${gate}" && ! -L "${gate}" && "$(stat -Lc '%u:%g:%a:%h' -- "${gate}")" == '0:0:600:1' ]] || return 79
  [[ -e "${netns_target}" && ! -L "${netns_target}" ]] || return 79
  expected_netns="$(stat -Lc '%d:%i' -- "${netns_target}")" || return 79
  actual_netns="$(stat -Lc '%d:%i' -- /proc/self/ns/net)" || return 79
  [[ "${actual_netns}" == "${expected_netns}" ]] || return 79
  mount --bind "${run}" "${SHARED_RUN}"
  mount --bind "${var}" "${SHARED_VAR}"
  mount --bind "${gate}" "${SHARED_MAINTENANCE}"
  mount -t bpf -o mode=0700 bpf /sys/fs/bpf
  exec env -i PATH="${SAFE_PATH}" LC_ALL=C \
    WG_MIX_EBPF_OBJECT="${artifacts}/wg_mix_tc.o" \
    WG_MIX_EBPF_FAKETCP_OBJECT="${artifacts}/wg_mix_faketcp_experimental.o" \
    WG_MIX_EBPF_FAKETCP_LEGACY_515_OBJECT="${artifacts}/wg_mix_faketcp_legacy_515.o" \
    WG_MIX_EBPF_PIN_PATH="${pin}" \
    "${artifacts}/wg-mix-ebpf" run --config /run/wg-mix-ebpf/config.yaml \
    --run-dir /run/wg-mix-ebpf/runtime --state-dir /var/lib/wg-mix-ebpf/state \
    --shutdown-timeout 20s
}

if [[ "${1-}" == endpoint ]]; then endpoint_child "$@"; exit $?; fi

MODE='' SOURCE='' COMMIT='' RUN_ID='' LABEL='' WG_COUNT='' ATTACHMENT_BACKEND=''
CHECKSUM_BACKEND='' BINARY='' BASELINE_OBJECT='' MODERN_OBJECT='' LEGACY_OBJECT=''
SELECTED_OBJECT='' MODULE_OBJECT='' MODULE_LEASE_ID='' XOR_MODE='' GSO_MODE=''
parse_args() {
  (($# >= 1)) || return 64
  MODE="$1"; shift
  case "${MODE}" in run|restore) ;; *) return 64 ;; esac
  while (($#)); do
    (($# >= 2)) || return 64
    case "$1" in
      --source) SOURCE="$2" ;;
      --commit) COMMIT="$2" ;;
      --run-id) RUN_ID="$2" ;;
      --label) LABEL="$2" ;;
      --wg-count) WG_COUNT="$2" ;;
      --attachment-backend) ATTACHMENT_BACKEND="$2" ;;
      --checksum-backend) CHECKSUM_BACKEND="$2" ;;
      --binary) BINARY="$2" ;;
      --baseline-object) BASELINE_OBJECT="$2" ;;
      --modern-object) MODERN_OBJECT="$2" ;;
      --legacy-object) LEGACY_OBJECT="$2" ;;
      --selected-object) SELECTED_OBJECT="$2" ;;
      --module-object) MODULE_OBJECT="$2" ;;
      --module-lease-id) MODULE_LEASE_ID="$2" ;;
      --xor) XOR_MODE="$2" ;;
      --gso) GSO_MODE="$2" ;;
      *) return 64 ;;
    esac
    shift 2
  done
  [[ "${SOURCE}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ &&
    "${COMMIT}" =~ ^[0-9a-f]{40}$ && "${RUN_ID}" =~ ^[0-9a-f]{8}$ &&
    "${LABEL}" =~ ^[a-z0-9_-]{1,96}$ && "${WG_COUNT}" =~ ^(1|2|4)$ &&
    "${ATTACHMENT_BACKEND}" =~ ^(tcx|classic_tc)$ &&
    "${CHECKSUM_BACKEND}" =~ ^(kfunc|kprobe)$ &&
    "${MODULE_LEASE_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{8}$ &&
    "${XOR_MODE}" =~ ^(none|prefix|full)$ && "${GSO_MODE}" =~ ^(off|on)$ ]] || return 65
}
parse_rc=0
parse_args "$@" || parse_rc=$?
if ((parse_rc != 0)); then exit "${parse_rc}"; fi

stage_id_value="${SOURCE#'/run/wg-mix-ebpf-source-stages/'}"
stage_id_value="${stage_id_value%'/source'}"
readonly STAGE_ID="${stage_id_value}"
readonly STAGE_ROOT="/run/wg-mix-ebpf-source-stages/${STAGE_ID}"
readonly ROOT="${RUN_PARENT}/${RUN_ID}"
readonly EVIDENCE="${ROOT}/evidence"
readonly ARTIFACT_ROOT="${ROOT}/artifacts"
readonly MANIFEST="${ROOT}/manifest.v1"
readonly OWNER="${ROOT}/owner.v1" NSA="f${RUN_ID}a" NSR="f${RUN_ID}r" NSB="f${RUN_ID}b"
readonly VA="va${RUN_ID:0:6}" VRA="ra${RUN_ID:0:6}"
readonly VB="vb${RUN_ID:0:6}" VRB="rb${RUN_ID:0:6}"
readonly ENDPOINT_A="${ROOT}/endpoint-a" ENDPOINT_B="${ROOT}/endpoint-b"
readonly RUN_A="${ENDPOINT_A}/run" RUN_B="${ENDPOINT_B}/run"
readonly BIN="${BINARY}"
readonly GO_CACHE="${STAGE_ROOT}/go-cache" GO_MOD_CACHE="${STAGE_ROOT}/go-mod-cache"
readonly GO_PATH="${STAGE_ROOT}/go-path" GO_TMP="${STAGE_ROOT}/go-tmp"
readonly -a GO_OFFLINE_ENV=(
  /usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C CGO_ENABLED=0 GOENV=off
  GOFLAGS=-mod=readonly GOTOOLCHAIN=local 'GOVCS=*:off'
  GOCACHE="${GO_CACHE}" GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}"
  GOTMPDIR="${GO_TMP}" TMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on
  GOPROXY=off GOSUMDB=off
)
DAEMON_A_PID='' DAEMON_B_PID='' TCPDUMP_PID='' IPERF_PID=''

[[ "${MODULE_LEASE_ID}" == "${STAGE_ID}-${RUN_ID}" &&
  "${BINARY}" == "${ARTIFACT_ROOT}/wg-mix-ebpf" &&
  "${BASELINE_OBJECT}" == "${ARTIFACT_ROOT}/wg_mix_tc.o" &&
  "${MODERN_OBJECT}" == "${ARTIFACT_ROOT}/wg_mix_faketcp_experimental.o" &&
  "${LEGACY_OBJECT}" == "${ARTIFACT_ROOT}/wg_mix_faketcp_legacy_515.o" ]] || exit 65
if [[ "${CHECKSUM_BACKEND}" == kfunc ]]; then
  [[ "${SELECTED_OBJECT}" == "${MODERN_OBJECT}" &&
    "${MODULE_OBJECT}" == "${ARTIFACT_ROOT}/faketcp_checksum_kmod/${KFUNC_MODULE}.ko" ]] || exit 65
else
  [[ "${SELECTED_OBJECT}" == "${LEGACY_OBJECT}" &&
    "${MODULE_OBJECT}" == "${ARTIFACT_ROOT}/faketcp_checksum_kprobe_kmod/${KPROBE_MODULE}.ko" ]] || exit 65
fi

log_command() {
  local phase="$1"; shift
  local out="${EVIDENCE}/${phase}.stdout.log" err="${EVIDENCE}/${phase}.stderr.log" rc
  {
    printf 'timestamp=%s event=start phase=%s argv=' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}"
    printf '%q ' "$@"; printf '\nstdout=%s\nstderr=%s\n' "${out}" "${err}"
  } >>"${EVIDENCE}/operations.log"
  if "$@" >"${out}" 2>"${err}"; then rc=0; else rc=$?; fi
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${rc}" >>"${EVIDENCE}/operations.log"
  return "${rc}"
}

private_key_value_to_pipe() {
  local private_key="$1"
  [[ $# -eq 1 && "${private_key}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 79
  printf '%s\n' "${private_key}"
}

log_command_private_key_stdin() {
  local phase="$1" private_key="$2"; shift 2
  local out="${EVIDENCE}/${phase}.stdout.log" err="${EVIDENCE}/${phase}.stderr.log"
  local rc
  {
    printf 'timestamp=%s event=start phase=%s argv=' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}"
    printf '%q ' "$@"
    printf '\nstdin=ephemeral-private-key-pipe\nstdout=%s\nstderr=%s\n' "${out}" "${err}"
  } >>"${EVIDENCE}/operations.log"
  : >"${out}"
  : >"${err}"
  if [[ ! "${private_key}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    printf 'private key input failed the WireGuard key-shape gate\n' >>"${err}"
    rc=79
  # An exec-triggered AppArmor/LSM transition can deny wg when it reopens
  # /dev/stdin backed by a regular key file. Generate keys only in shell memory
  # and let only an anonymous pipe cross into ip/wg.
  elif {
    (private_key_value_to_pipe "${private_key}") |
      (unset private_key; "$@")
  } >"${out}" 2>>"${err}"; then
    rc=0
  else
    rc=$?
  fi
  unset private_key
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${rc}" >>"${EVIDENCE}/operations.log"
  return "${rc}"
}

module_name() { [[ "${CHECKSUM_BACKEND}" == kfunc ]] && printf '%s' "${KFUNC_MODULE}" || printf '%s' "${KPROBE_MODULE}"; }
module_object() {
  printf '%s' "${MODULE_OBJECT}"
}

receipt_value() {
  local key="$1" path="$2"
  awk -F= -v wanted="${key}" '
    $1 == wanted { count++; value=substr($0, length($1)+2) }
    END { if (count != 1 || value == "") exit 1; print value }
  ' "${path}"
}

validate_restore_identity() {
  [[ "${EUID}" -eq 0 && "$(id -g)" -eq 0 &&
    -d "${RUN_PARENT}" && ! -L "${RUN_PARENT}" &&
    "$(readlink -e -- "${RUN_PARENT}")" == "${RUN_PARENT}" &&
    "$(stat -Lc '%u:%g:%a:%F' -- "${RUN_PARENT}")" == '0:0:700:directory' &&
    -d "${ROOT}" && ! -L "${ROOT}" &&
    "$(readlink -e -- "${ROOT}")" == "${ROOT}" &&
    "$(stat -Lc '%u:%g:%a:%F' -- "${ROOT}")" == '0:0:700:directory' &&
    -d "${EVIDENCE}" && ! -L "${EVIDENCE}" &&
    "$(readlink -e -- "${EVIDENCE}")" == "${EVIDENCE}" &&
    "$(stat -Lc '%u:%g:%a:%F' -- "${EVIDENCE}")" == '0:0:700:directory' &&
    -f "${OWNER}" && ! -L "${OWNER}" &&
    "$(stat -Lc '%u:%g:%a:%h:%F' -- "${OWNER}")" == '0:0:600:1:regular file' &&
    "$(<"${OWNER}")" == "wg-mix-ebpf-faketcp-backends-v1:${RUN_ID}:${COMMIT}" &&
    -f "${MANIFEST}" && ! -L "${MANIFEST}" &&
    "$(stat -Lc '%u:%g:%a:%h:%F' -- "${MANIFEST}")" == '0:0:600:1:regular file' &&
    "$(receipt_value format "${MANIFEST}")" == 'wg-mix-ebpf-b82-faketcp-backends-v1' &&
    "$(receipt_value run_id "${MANIFEST}")" == "${RUN_ID}" &&
    "$(receipt_value commit "${MANIFEST}")" == "${COMMIT}" &&
    "$(receipt_value stage_id "${MANIFEST}")" == "${STAGE_ID}" &&
    "$(receipt_value wg_count "${MANIFEST}")" == "${WG_COUNT}" &&
    "$(receipt_value attachment "${MANIFEST}")" == "${ATTACHMENT_BACKEND}" &&
    "$(receipt_value checksum "${MANIFEST}")" == "${CHECKSUM_BACKEND}" &&
    "$(receipt_value xor "${MANIFEST}")" == "${XOR_MODE}" &&
    "$(receipt_value gso "${MANIFEST}")" == "${GSO_MODE}" &&
    "$(receipt_value module_lease_id "${MANIFEST}")" == "${MODULE_LEASE_ID}" ]] || return 79
}

stop_exact_pid() {
  local role="$1" pid_file pid netns expected_inode actual_inode status
  local process_state wait_status
  pid_file="${ROOT}/daemon-${role}.pid"
  [[ -f "${pid_file}" && ! -L "${pid_file}" ]] || return 0
  pid="$(<"${pid_file}")"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 79
  [[ -d "/proc/${pid}" ]] || return 0
  netns="${NSA}"; [[ "${role}" == b ]] && netns="${NSB}"
  [[ -e "/run/netns/${netns}" ]] || return 79
  expected_inode="$(stat -Lc '%d:%i' -- "/run/netns/${netns}")"
  actual_inode="$(stat -Lc '%d:%i' -- "/proc/${pid}/ns/net")"
  if [[ "${expected_inode}" != "${actual_inode}" ||
    "$(readlink -e -- "/proc/${pid}/exe")" != "${BIN}" ]]; then
    printf 'timestamp=%s event=skip-foreign-pid role=%s pid=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${role}" "${pid}" \
      >>"${EVIDENCE}/operations.log"
    return 0
  fi
  kill -TERM "${pid}"
  for _ in {1..200}; do
    [[ ! -d "/proc/${pid}" ]] && return 0
    process_state="$(ps -p "${pid}" -o state=)"
    if [[ "${process_state}" == Z* ]]; then
      if wait "${pid}"; then wait_status=0; else wait_status=$?; fi
      printf 'timestamp=%s event=reap role=%s pid=%s rc=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${role}" "${pid}" "${wait_status}" \
        >>"${EVIDENCE}/operations.log"
      return 0
    fi
    sleep 0.1
  done
  kill -KILL "${pid}"
  for _ in {1..50}; do [[ ! -d "/proc/${pid}" ]] && return 0; sleep 0.1; done
  status=1
  return "${status}"
}

capture_identity_matches() {
  local receipt="${ROOT}/tcpdump-owned.v1" pid="$1" expected_pid expected_boot
  local expected_start expected_netns expected_exe actual_start actual_netns actual_exe
  [[ -f "${receipt}" && ! -L "${receipt}" && -d "/proc/${pid}" ]] || return 1
  expected_pid="$(receipt_value pid "${receipt}")"
  expected_boot="$(receipt_value boot_id "${receipt}")"
  expected_start="$(receipt_value start_ticks "${receipt}")"
  expected_netns="$(receipt_value netns_inode "${receipt}")"
  expected_exe="$(receipt_value executable "${receipt}")"
  actual_start="$(awk '{print $22}' "/proc/${pid}/stat")"
  actual_netns="$(stat -Lc '%d:%i' -- "/proc/${pid}/ns/net")"
  actual_exe="$(readlink -e -- "/proc/${pid}/exe")"
  [[ "${expected_pid}" == "${pid}" &&
    "${expected_boot}" == "$(</proc/sys/kernel/random/boot_id)" &&
    "${expected_start}" == "${actual_start}" &&
    "${expected_netns}" == "${actual_netns}" &&
    "${expected_exe}" == "${actual_exe}" ]]
}

remove_legacy_private_key_residue() {
  local path name role index entry root_device path_device inventory
  local -a allowed_names=() residue_paths=() residue_labels=()
  root_device="$(stat -Lc '%d' -- "${ROOT}")" || return 79
  for ((index=0; index<WG_COUNT; index++)); do
    allowed_names+=("key-a-${index}" "key-b-${index}")
  done

  # A bounded read-only inventory rejects names outside the fixed allowlist.
  if inventory="$(find "${ROOT}" -xdev -mindepth 1 -maxdepth 1 \
    -name 'key-*' -printf '%f\n')"; then
    :
  else
    printf 'legacy_private_key_residue_preflight=inventory-failed\n' \
      >>"${EVIDENCE}/operations.log"
    return 79
  fi
  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    case " ${allowed_names[*]} " in
      *" ${name} "*) ;;
      *)
        printf 'legacy_private_key_residue_preflight=unexpected-key-entry\n' \
          >>"${EVIDENCE}/operations.log"
        return 79
        ;;
    esac
  done <<<"${inventory}"
  unset inventory

  # Construct every possible delete target exactly and preflight all present
  # candidates before removing any of them.  No glob contributes a target.
  for ((index=0; index<WG_COUNT; index++)); do
    for role in a b; do
      name="key-${role}-${index}"
      path="${ROOT}/${name}"
      [[ -e "${path}" || -L "${path}" ]] || continue
      if [[ ! -f "${path}" || -L "${path}" ||
        "$(readlink -e -- "${path}")" != "${path}" ]]; then
        printf 'legacy_private_key_residue_preflight=identity-failed label=%s\n' \
          "${name}" >>"${EVIDENCE}/operations.log"
        return 79
      fi
      if entry="$(stat -Lc '%u:%g:%a:%h:%s:%F' -- "${path}")"; then
        :
      else
        printf 'legacy_private_key_residue_preflight=stat-failed label=%s\n' \
          "${name}" >>"${EVIDENCE}/operations.log"
        return 79
      fi
      if [[ "${entry}" != '0:0:600:1:45:regular file' ]]; then
        printf 'legacy_private_key_residue_preflight=metadata-failed label=%s\n' \
          "${name}" >>"${EVIDENCE}/operations.log"
        return 79
      fi
      path_device="$(stat -Lc '%d' -- "${path}")" || return 79
      if [[ "${path_device}" != "${root_device}" ]]; then
        printf 'legacy_private_key_residue_preflight=filesystem-failed label=%s\n' \
          "${name}" >>"${EVIDENCE}/operations.log"
        return 79
      fi
      residue_paths+=("${path}")
      residue_labels+=("${name}")
    done
  done

  for ((index=0; index<${#residue_paths[@]}; index++)); do
    log_command "restore-legacy-${residue_labels[index]}" \
      /usr/bin/unlink -- "${residue_paths[index]}"
  done
  for path in "${residue_paths[@]}"; do
    [[ ! -e "${path}" && ! -L "${path}" ]] || return 1
  done
}

remove_xor_secret_residue() {
  local role path parent entry parent_device path_device index
  local -a residue_paths=() residue_labels=()
  for role in a b; do
    if [[ "${role}" == a ]]; then parent="${RUN_A}"; else parent="${RUN_B}"; fi
    path="${parent}/xor.key"
    [[ -e "${path}" || -L "${path}" ]] || continue
    if [[ "${XOR_MODE}" == none ]]; then
      printf 'xor_secret_residue_preflight=unexpected-for-none label=endpoint-%s\n' \
        "${role}" >>"${EVIDENCE}/operations.log"
      return 79
    fi
    if [[ ! -d "${parent}" || -L "${parent}" ||
      "$(readlink -e -- "${parent}")" != "${parent}" ||
      "$(stat -Lc '%u:%g:%a:%F' -- "${parent}")" != '0:0:700:directory' ||
      ! -f "${path}" || -L "${path}" ||
      "$(readlink -e -- "${path}")" != "${path}" ]]; then
      printf 'xor_secret_residue_preflight=identity-failed label=endpoint-%s\n' \
        "${role}" >>"${EVIDENCE}/operations.log"
      return 79
    fi
    entry="$(stat -Lc '%u:%g:%a:%h:%s:%F' -- "${path}")" || return 79
    if [[ "${entry}" != '0:0:600:1:65:regular file' ]]; then
      printf 'xor_secret_residue_preflight=metadata-failed label=endpoint-%s\n' \
        "${role}" >>"${EVIDENCE}/operations.log"
      return 79
    fi
    parent_device="$(stat -Lc '%d' -- "${parent}")" || return 79
    path_device="$(stat -Lc '%d' -- "${path}")" || return 79
    if [[ "${path_device}" != "${parent_device}" ]]; then
      printf 'xor_secret_residue_preflight=filesystem-failed label=endpoint-%s\n' \
        "${role}" >>"${EVIDENCE}/operations.log"
      return 79
    fi
    residue_paths+=("${path}")
    residue_labels+=("endpoint-${role}")
  done

  for ((index=0; index<${#residue_paths[@]}; index++)); do
    log_command "restore-xor-secret-${residue_labels[index]}" \
      /usr/bin/unlink -- "${residue_paths[index]}"
  done
  for path in "${residue_paths[@]}"; do
    [[ ! -e "${path}" && ! -L "${path}" ]] || return 1
  done
}

restore_resources() {
  validate_restore_identity
  remove_legacy_private_key_residue
  stop_exact_pid a
  stop_exact_pid b
  remove_xor_secret_residue
  if [[ -f "${ROOT}/tcpdump.pid" && ! -L "${ROOT}/tcpdump.pid" ]]; then
    local capture_pid
    capture_pid="$(<"${ROOT}/tcpdump.pid")"
    [[ "${capture_pid}" =~ ^[1-9][0-9]*$ ]] || return 79
    if [[ -d "/proc/${capture_pid}" ]]; then
      if capture_identity_matches "${capture_pid}"; then
        kill -INT "${capture_pid}"
        for _ in {1..100}; do
          [[ ! -d "/proc/${capture_pid}" ]] && break
          sleep 0.1
        done
        [[ ! -d "/proc/${capture_pid}" ]] || return 1
      else
        printf 'timestamp=%s event=skip-foreign-pid role=tcpdump pid=%s\n' \
          "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${capture_pid}" \
          >>"${EVIDENCE}/operations.log"
      fi
    fi
  fi
  local ns
  for ns in "${NSA}" "${NSR}" "${NSB}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq -- "${ns}"; then
      log_command "restore-netns-${ns}" ip netns delete "${ns}"
    fi
  done
  if [[ -f "${ROOT}/module-owned.v1" && ! -L "${ROOT}/module-owned.v1" ]]; then
    local receipt="${ROOT}/module-owned.v1" owned_name owned_boot owned_object
    local owned_sha owned_srcversion owned_text owned_lease current_srcversion current_text
    owned_name="$(receipt_value module "${receipt}")"
    owned_boot="$(receipt_value boot_id "${receipt}")"
    owned_object="$(receipt_value object "${receipt}")"
    owned_sha="$(receipt_value object_sha256 "${receipt}")"
    owned_srcversion="$(receipt_value srcversion "${receipt}")"
    owned_text="$(receipt_value text_address "${receipt}")"
    owned_lease="$(receipt_value lease_id "${receipt}")"
    [[ "${owned_name}" == "$(module_name)" && "${owned_boot}" == "$(</proc/sys/kernel/random/boot_id)" &&
      "${owned_object}" == "$(module_object)" && -f "${owned_object}" && ! -L "${owned_object}" &&
      "$(sha256sum -- "${owned_object}" | awk '{print $1}')" == "${owned_sha}" &&
      "${owned_lease}" == "${MODULE_LEASE_ID}" ]] || return 79
    if [[ -d "/sys/module/${owned_name}" ]]; then
      [[ -r "/sys/module/${owned_name}/srcversion" &&
        -r "/sys/module/${owned_name}/sections/.text" ]] || return 79
      current_srcversion="$(<"/sys/module/${owned_name}/srcversion")"
      current_text="$(<"/sys/module/${owned_name}/sections/.text")"
      [[ "${current_srcversion}" == "${owned_srcversion}" &&
        "${current_text}" == "${owned_text}" ]] || return 79
      if [[ "${CHECKSUM_BACKEND}" == kfunc ]]; then
        [[ -r "/sys/module/${owned_name}/parameters/lease_id" &&
          "$(<"/sys/module/${owned_name}/parameters/lease_id")" == "${MODULE_LEASE_ID}" ]] || return 79
      fi
      log_command restore-module rmmod "${owned_name}"
    fi
  fi
  for ns in "${NSA}" "${NSR}" "${NSB}"; do
    ! ip netns list | awk '{print $1}' | grep -Fxq -- "${ns}" || return 1
  done
  [[ ! -d "/sys/fs/bpf/wg-mix-ebpf-faketcp-${RUN_ID}-a" &&
    ! -d "/sys/fs/bpf/wg-mix-ebpf-faketcp-${RUN_ID}-b" ]] || return 1
  printf 'restored=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"${ROOT}/restored.v1"
}

if [[ "${MODE}" == restore ]]; then restore_resources; exit $?; fi

[[ "${EUID}" -eq 0 && "$(id -g)" -eq 0 && -d "${ROOT}" && ! -L "${ROOT}" &&
  -d "${EVIDENCE}" && ! -L "${EVIDENCE}" && -f "${OWNER}" && ! -L "${OWNER}" &&
  "$(<"${OWNER}")" == "wg-mix-ebpf-faketcp-backends-v1:${RUN_ID}:${COMMIT}" ]] || exit 79
[[ -d "${ARTIFACT_ROOT}" && ! -L "${ARTIFACT_ROOT}" &&
  "$(stat -Lc '%u:%g:%a:%F' -- "${ARTIFACT_ROOT}")" == '0:0:700:directory' ]] || exit 79
for required in "${BIN}" "${BASELINE_OBJECT}" "${MODERN_OBJECT}" "${LEGACY_OBJECT}" \
  "${SELECTED_OBJECT}" "${MODULE_OBJECT}"; do
  [[ -f "${required}" && ! -L "${required}" &&
    "$(readlink -e -- "${required}")" == "${required}" ]] || exit 79
done
for cache in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
  [[ -d "${cache}" && ! -L "${cache}" &&
    "$(stat -Lc '%u:%g:%a:%F' -- "${cache}")" == '0:0:700:directory' ]] || exit 79
done

printf 'hostname=%s\nkernel=%s\nboot_id=%s\ncommit=%s\n' "$(hostname)" "$(uname -r)" \
  "$(</proc/sys/kernel/random/boot_id)" "${COMMIT}" >"${EVIDENCE}/host.log"
log_command same-tuple-router-test "${GO_OFFLINE_ENV[@]}" /usr/bin/go -C "${SOURCE}" \
  test ./internal/faketcp \
  -run '^(TestEngineRouterDispatchesEqualNetworkTupleBySessionWGID|TestEngineRouterKeepsEqualAndDifferentPoliciesIndependent)$' -count=1

MOD_NAME="$(module_name)"; MOD_OBJECT="$(module_object)"
[[ -f "${MOD_OBJECT}" && ! -L "${MOD_OBJECT}" ]] || exit 1
MOD_BUILT_SRCVERSION="$(modinfo -F srcversion -- "${MOD_OBJECT}")"
[[ -n "${MOD_BUILT_SRCVERSION}" ]] || exit 1
if [[ ! -d "/sys/module/${MOD_NAME}" ]]; then
  if [[ "${CHECKSUM_BACKEND}" == kfunc ]]; then
    log_command module-load insmod "${MOD_OBJECT}" "lease_id=${MODULE_LEASE_ID}"
  else
    log_command module-load insmod "${MOD_OBJECT}"
  fi
  [[ -r "/sys/module/${MOD_NAME}/srcversion" &&
    -r "/sys/module/${MOD_NAME}/sections/.text" ]] || exit 1
  MOD_SRCVERSION="$(<"/sys/module/${MOD_NAME}/srcversion")"
  MOD_TEXT="$(<"/sys/module/${MOD_NAME}/sections/.text")"
  [[ -n "${MOD_SRCVERSION}" && "${MOD_TEXT}" =~ ^0x[0-9a-fA-F]+$ ]] || exit 1
  if [[ "${CHECKSUM_BACKEND}" == kfunc ]]; then
    [[ -r "/sys/module/${MOD_NAME}/parameters/lease_id" &&
      "$(<"/sys/module/${MOD_NAME}/parameters/lease_id")" == "${MODULE_LEASE_ID}" ]] || exit 1
  fi
  printf 'format=wg-mix-ebpf-faketcp-backends-module-v1\nmodule=%s\nboot_id=%s\nobject=%s\nobject_sha256=%s\nsrcversion=%s\ntext_address=%s\nlease_id=%s\n' \
    "${MOD_NAME}" "$(</proc/sys/kernel/random/boot_id)" "${MOD_OBJECT}" \
    "$(sha256sum -- "${MOD_OBJECT}" | awk '{print $1}')" "${MOD_SRCVERSION}" "${MOD_TEXT}" \
    "${MODULE_LEASE_ID}" \
    >"${ROOT}/module-owned.v1"
else
  [[ -r "/sys/module/${MOD_NAME}/srcversion" &&
    -r "/sys/module/${MOD_NAME}/sections/.text" ]] || exit 1
  MOD_SRCVERSION="$(<"/sys/module/${MOD_NAME}/srcversion")"
  MOD_TEXT="$(<"/sys/module/${MOD_NAME}/sections/.text")"
  [[ "${MOD_SRCVERSION}" == "${MOD_BUILT_SRCVERSION}" &&
    "${MOD_TEXT}" =~ ^0x[0-9a-fA-F]+$ ]] || exit 1
  if [[ "${CHECKSUM_BACKEND}" == kprobe ]]; then
    [[ -c "${KPROBE_DEVICE}" && ! -L "${KPROBE_DEVICE}" ]] || exit 1
  fi
  printf 'format=wg-mix-ebpf-faketcp-backends-preexisting-module-v1\nmodule=%s\nboot_id=%s\nobject=%s\nobject_sha256=%s\nsrcversion=%s\ntext_address=%s\n' \
    "${MOD_NAME}" "$(</proc/sys/kernel/random/boot_id)" "${MOD_OBJECT}" \
    "$(sha256sum -- "${MOD_OBJECT}" | awk '{print $1}')" "${MOD_SRCVERSION}" \
    "${MOD_TEXT}" >"${ROOT}/module-preexisting.v1"
fi

mkdir --mode=0700 -- "${ENDPOINT_A}" "${ENDPOINT_B}" "${RUN_A}" "${RUN_B}" \
  "${ENDPOINT_A}/var" "${ENDPOINT_B}/var" "${RUN_A}/runtime" "${RUN_B}/runtime"
: >"${ENDPOINT_A}/maintenance.gate"; : >"${ENDPOINT_B}/maintenance.gate"
chmod 0600 "${ENDPOINT_A}/maintenance.gate" "${ENDPOINT_B}/maintenance.gate"

wg_listen_port() {
  local role="$1" index="$2" offset=0
  [[ "${role}" == b ]] && offset=100
  printf '%s' "$((31000 + index + offset))"
}

wg_fwmark() {
  local role="$1" index="$2" offset=0
  [[ "${role}" == b ]] && offset=$((0x10000))
  printf '0x%x' "$((0x11000000 + index + offset))"
}

write_config() {
  local role="$1" target="$2" index port mark
  {
    printf 'version: 1\nmode: transparent-typeword\n\nunderlays:\n  - name: under0\n    type: netdev\n\nwireguards:\n'
    for ((index=0; index<WG_COUNT; index++)); do
      port="$(wg_listen_port "${role}" "${index}")"
      mark="$(wg_fwmark "${role}" "${index}")"
      printf '  - name: wg%s\n    config: /run/wg-mix-ebpf/wg%s.conf\n    profile: mix-default\n' "${index}" "${index}"
      [[ "${XOR_MODE}" == none ]] || printf '    cipher: xor-cell\n'
      printf '    transport:\n      mode: faketcp\n      faketcp:\n        checksum_mode: partial-complete-reset-required\n        ingress_mode: xdp-generic-exact\n'
      printf '        session_capacity: %s\n        max_half_open_sessions: %s\n        max_half_open_per_source: %s\n        syn_rate_interval: %s\n        syn_burst: %s\n        syn_burst_per_source: %s\n        syn_source_ledger_capacity: %s\n        syn_source_ledger_ttl: %s\n        max_pending_flows: %s\n        max_pending_packets_per_flow: %s\n        max_pending_bytes: %s\n        handshake_timeout: %s\n        keepalive_interval: %s\n        idle_timeout: %s\n' \
        "${FAKETCP_SESSION_CAPACITY}" "${FAKETCP_MAX_HALF_OPEN_SESSIONS}" \
        "${FAKETCP_MAX_HALF_OPEN_PER_SOURCE}" "${FAKETCP_SYN_RATE_INTERVAL}" \
        "${FAKETCP_SYN_BURST}" "${FAKETCP_SYN_BURST_PER_SOURCE}" \
        "${FAKETCP_SYN_SOURCE_LEDGER_CAPACITY}" "${FAKETCP_SYN_SOURCE_LEDGER_TTL}" \
        "${FAKETCP_MAX_PENDING_FLOWS}" "${FAKETCP_MAX_PENDING_PACKETS_PER_FLOW}" \
        "${FAKETCP_MAX_PENDING_BYTES}" "${FAKETCP_HANDSHAKE_TIMEOUT}" \
        "${FAKETCP_KEEPALIVE_INTERVAL}" "${FAKETCP_IDLE_TIMEOUT}"
      printf '[Interface]\nListenPort = %s\nFwMark = %s\n' "${port}" "${mark}" >"${target}/wg${index}.conf"
    done
    printf '\nprofiles:\n  mix-default:\n    preset: wireguard-mix-wire-values-v1\n    index:\n      mode: none\n'
    if [[ "${XOR_MODE}" != none ]]; then
      local scope='wg-payload-prefix' max=128
      [[ "${XOR_MODE}" == full ]] && { scope='wg-payload-full'; max=2048; }
      printf '\nciphers:\n  xor-cell:\n    mode: xor\n    auth: none\n    scope: %s\n    key_derivation: wgmx-hkdf256-v1\n    secret_file: /run/wg-mix-ebpf/xor.key\n    key_len: 256\n    max_bytes: %s\n' "${scope}" "${max}"
    fi
    printf '\nfwmark_policy:\n  mode: config-required\nstartup_guard:\n  mode: nft-temporary-drop\n  egress:\n    match: fwmark\n  ingress:\n    match: config-listen-port-if-present\n    random_listen_port_behavior: best-effort\nruntime:\n  poll_interval: 30s\n  attachment_backend: %s\n  checksum_backend: %s\n  require_nonzero_fwmark: true\n  strict_runtime_fwmark: true\n  allow_zero_fwmark_fallback: false\npolicy:\n  managed_egress_map_miss: drop\n  startup_fail_mode: fail_closed_for_managed_flows\n' "${ATTACHMENT_BACKEND}" "${CHECKSUM_BACKEND}"
  } >"${target}/config.yaml"
}
write_config a "${RUN_A}"; write_config b "${RUN_B}"
if [[ "${XOR_MODE}" != none ]]; then
  XOR_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  printf '%s\n' "${XOR_SECRET}" >"${RUN_A}/xor.key"; printf '%s\n' "${XOR_SECRET}" >"${RUN_B}/xor.key"
  unset XOR_SECRET
fi

log_command netns-a ip netns add "${NSA}"
log_command netns-r ip netns add "${NSR}"
log_command netns-b ip netns add "${NSB}"
log_command veth-a ip link add "${VA}" type veth peer name "${VRA}"
log_command veth-b ip link add "${VB}" type veth peer name "${VRB}"
log_command va-ns ip link set "${VA}" netns "${NSA}"
log_command vra-ns ip link set "${VRA}" netns "${NSR}"
log_command vb-ns ip link set "${VB}" netns "${NSB}"
log_command vrb-ns ip link set "${VRB}" netns "${NSR}"
log_command rename-a ip -n "${NSA}" link set "${VA}" name under0
log_command rename-ra ip -n "${NSR}" link set "${VRA}" name left0
log_command rename-b ip -n "${NSB}" link set "${VB}" name under0
log_command rename-rb ip -n "${NSR}" link set "${VRB}" name right0
for spec in "${NSA}:under0" "${NSR}:left0" "${NSR}:right0" "${NSB}:under0"; do
  ns="${spec%%:*}"; dev="${spec#*:}"
  log_command "${ns}-${dev}-mtu" ip -n "${ns}" link set "${dev}" mtu 2200
  log_command "${ns}-${dev}-up" ip -n "${ns}" link set "${dev}" up
done
for ns in "${NSA}" "${NSR}" "${NSB}"; do log_command "${ns}-lo" ip -n "${ns}" link set lo up; done
log_command addr-a ip -n "${NSA}" address add 198.18.82.1/24 dev under0
log_command addr-ra ip -n "${NSR}" address add 198.18.82.254/24 dev left0
log_command addr-b ip -n "${NSB}" address add 198.19.82.1/24 dev under0
log_command addr-rb ip -n "${NSR}" address add 198.19.82.254/24 dev right0
log_command route-a ip -n "${NSA}" route add default via 198.18.82.254 dev under0
log_command route-b ip -n "${NSB}" route add default via 198.19.82.254 dev under0
log_command forward ip netns exec "${NSR}" sysctl -w net.ipv4.ip_forward=1

for ((index=0; index<WG_COUNT; index++)); do
  key_a="$(wg genkey)"; key_b="$(wg genkey)"
  pub_a="$(private_key_value_to_pipe "${key_a}" | wg pubkey)"
  pub_b="$(private_key_value_to_pipe "${key_b}" | wg pubkey)"
  port_a="$(wg_listen_port a "${index}")"; port_b="$(wg_listen_port b "${index}")"
  mark_a="$(wg_fwmark a "${index}")"; mark_b="$(wg_fwmark b "${index}")"
  third=$((10 + index)); tunnel_a="10.82.${third}.1"; tunnel_b="10.82.${third}.2"
  log_command "wg-add-a-${index}" ip -n "${NSA}" link add "wg${index}" type wireguard
  log_command "wg-add-b-${index}" ip -n "${NSB}" link add "wg${index}" type wireguard
  if log_command_private_key_stdin "wg-set-a-${index}" "${key_a}" ip netns exec "${NSA}" wg set "wg${index}" private-key /dev/stdin listen-port "${port_a}" fwmark "${mark_a}" peer "${pub_b}" allowed-ips "${tunnel_b}/32" endpoint "198.19.82.1:${port_b}" persistent-keepalive 1; then
    :
  else
    rc=$?; unset key_a key_b; exit "${rc}"
  fi
  unset key_a
  if log_command_private_key_stdin "wg-set-b-${index}" "${key_b}" ip netns exec "${NSB}" wg set "wg${index}" private-key /dev/stdin listen-port "${port_b}" fwmark "${mark_b}" peer "${pub_a}" allowed-ips "${tunnel_a}/32" endpoint "198.18.82.1:${port_a}" persistent-keepalive 1; then
    :
  else
    rc=$?; unset key_b; exit "${rc}"
  fi
  unset key_b
  log_command "wg-addr-a-${index}" ip -n "${NSA}" address add "${tunnel_a}/30" dev "wg${index}"
  log_command "wg-addr-b-${index}" ip -n "${NSB}" address add "${tunnel_b}/30" dev "wg${index}"
  log_command "wg-mtu-a-${index}" ip -n "${NSA}" link set "wg${index}" mtu 1420
  log_command "wg-mtu-b-${index}" ip -n "${NSB}" link set "wg${index}" mtu 1420
  log_command "wg-up-a-${index}" ip -n "${NSA}" link set "wg${index}" up
  log_command "wg-up-b-${index}" ip -n "${NSB}" link set "wg${index}" up
done

start_daemon() {
  local role="$1" log_role pid netns
  log_role="${role}"
  netns="${NSA}"; [[ "${role}" == b ]] && netns="${NSB}"
  /usr/bin/env -i PATH="${SAFE_PATH}" LC_ALL=C ip netns exec "${netns}" \
    unshare --mount --propagation private /bin/bash -p "$0" endpoint \
    --source "${SOURCE}" --run-id "${RUN_ID}" --role "${role}" \
    >"${EVIDENCE}/daemon-${log_role}.stdout.log" 2>"${EVIDENCE}/daemon-${log_role}.stderr.log" &
  pid=$!
  printf '%s\n' "${pid}" >"${ROOT}/daemon-${role}.pid"
  printf 'timestamp=%s event=start phase=daemon-%s pid=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${role}" "${pid}" >>"${EVIDENCE}/operations.log"
  [[ "${role}" == a ]] && DAEMON_A_PID="${pid}" || DAEMON_B_PID="${pid}"
}

wait_active() {
  local role="$1" pid="$2" run="${RUN_A}" status_path daemon_status
  [[ "${role}" == b ]] && run="${RUN_B}"
  status_path="${run}/runtime/status.json"
  for _ in {1..300}; do
    if [[ ! -d "/proc/${pid}" ]]; then
      if wait "${pid}"; then daemon_status=0; else daemon_status=$?; fi
      printf 'timestamp=%s event=early-exit role=%s pid=%s rc=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${role}" "${pid}" "${daemon_status}" \
        >>"${EVIDENCE}/operations.log"
      return 1
    fi
    if [[ -f "${status_path}" ]] && python3 - "${status_path}" "${pid}" <<'PY'
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text())
raise SystemExit(0 if d.get("state")=="active" and d.get("pid")==int(sys.argv[2]) and not d.get("last_error") else 1)
PY
    then return 0; fi
    sleep 0.1
  done
  return 1
}

start_daemon a; start_daemon b
wait_active a "${DAEMON_A_PID}"; wait_active b "${DAEMON_B_PID}"

run_cli() {
  local role="$1" action="$2" phase="$3" pid="${DAEMON_A_PID}"
  [[ "${role}" == b ]] && pid="${DAEMON_B_PID}"
  log_command "${phase}" nsenter "--mount=/proc/${pid}/ns/mnt" "--net=/proc/${pid}/ns/net" -- \
    env -i PATH="${SAFE_PATH}" LC_ALL=C WG_MIX_EBPF_OBJECT="${BASELINE_OBJECT}" \
    WG_MIX_EBPF_FAKETCP_OBJECT="${MODERN_OBJECT}" \
    WG_MIX_EBPF_FAKETCP_LEGACY_515_OBJECT="${LEGACY_OBJECT}" \
    WG_MIX_EBPF_PIN_PATH="/sys/fs/bpf/wg-mix-ebpf-faketcp-${RUN_ID}-${role}" \
    "${BIN}" "${action}" --config /run/wg-mix-ebpf/config.yaml \
    --run-dir /run/wg-mix-ebpf/runtime --state-dir /var/lib/wg-mix-ebpf/state
}
run_cli a status status-a-initial; run_cli b status status-b-initial

validate_status() {
  local path="$1"
  local object_variant='modern-kfunc' module_name="${KFUNC_MODULE}"
  if [[ "${CHECKSUM_BACKEND}" == kprobe ]]; then
    object_variant='legacy-515-kprobe'; module_name="${KPROBE_MODULE}"
  fi
  python3 - "${path}" "${WG_COUNT}" "${ATTACHMENT_BACKEND}" \
    "${CHECKSUM_BACKEND}" "${object_variant}" "${module_name}" \
    "${FAKETCP_SESSION_CAPACITY}" "${FAKETCP_MAX_HALF_OPEN_SESSIONS}" \
    "${FAKETCP_SYN_SOURCE_LEDGER_CAPACITY}" "${FAKETCP_MAX_PENDING_FLOWS}" \
    "${FAKETCP_MAX_PENDING_BYTES}" <<'PY'
import json, pathlib, sys
d=json.loads(pathlib.Path(sys.argv[1]).read_text())
count,attach,checksum,variant,module=int(sys.argv[2]),sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6]
desired=d.get("desired") or {}
wireguards=desired.get("wireguards") or []
if len(wireguards) != count or {wg.get("id") for wg in wireguards}!=set(range(1,count+1)): raise SystemExit("desired WireGuard identity/count mismatch")
quota_fields=("faketcp_session_capacity","faketcp_max_half_open_sessions","faketcp_syn_source_ledger_capacity","faketcp_max_pending_flows","faketcp_max_pending_bytes")
expected_quotas=dict(zip(quota_fields,map(int,sys.argv[7:12])))
for wg in wireguards:
    actual={field:int(wg.get(field,0)) for field in quota_fields}
    if actual!=expected_quotas: raise SystemExit(f"explicit FakeTCP quota mismatch wg={wg.get('name')} actual={actual} expected={expected_quotas}")
dp=d.get("dataplane") or {}
f=dp.get("faketcp") or {}
if dp.get("mode")!="faketcp" or not f.get("healthy") or f.get("barrier")!="open": raise SystemExit("FakeTCP is not healthy/open")
if f.get("attachment_backend")!=attach: raise SystemExit("attachment backend mismatch")
xdp=f.get("xdp") or []
if len(xdp)!=1 or xdp[0].get("mode")!="generic" or not xdp[0].get("ifindex") or not xdp[0].get("link_id") or not xdp[0].get("program_id"): raise SystemExit("exact generic XDP identity missing")
c=f.get("checksum_backend") or {}
if c.get("backend")!=checksum or c.get("capability")!="full-gso-v1" or c.get("object_variant")!=variant or c.get("module")!=module: raise SystemExit("checksum backend identity mismatch")
if checksum=="kprobe" and not c.get("lease_held"): raise SystemExit("kprobe lease is not held")
if attach=="tcx":
    tc=f.get("tcx") or []
    if len(tc)!=2 or {v.get("direction") for v in tc}!={"ingress","egress"} or any(not v.get(k) for v in tc for k in ("ifindex","attach_type","link_id","program_id")): raise SystemExit("TCX identity incomplete")
else:
    classic=f.get("classic_tc") or []
    filters=[v for u in dp.get("underlays") or [] for v in u.get("filters") or [] if v.get("backend")=="classic_tc"]
    if len(classic)!=2 or {v.get("direction") for v in classic}!={"ingress","egress"} or any(not v.get(k) for v in classic for k in ("ifindex","parent","handle","priority","program_id")): raise SystemExit("classic TC identity incomplete")
    if len(filters)!=2 or {v.get("direction") for v in filters}!={"ingress","egress"} or any(not v.get(k) for v in filters for k in ("handle","priority","program_id")): raise SystemExit("classic TC underlay projection incomplete")
print(f"status=healthy wg_count={count} xdp=exact-generic attachment={attach} checksum={checksum}")
PY
}
validate_status "${EVIDENCE}/status-a-initial.stdout.log" >"${EVIDENCE}/status-a-validation.log"
validate_status "${EVIDENCE}/status-b-initial.stdout.log" >"${EVIDENCE}/status-b-validation.log"

ip netns exec "${NSR}" tcpdump -U -nn -i any -w "${EVIDENCE}/outer.pcap" \
  >"${EVIDENCE}/tcpdump.stdout.log" 2>"${EVIDENCE}/tcpdump.stderr.log" &
TCPDUMP_PID=$!; printf '%s\n' "${TCPDUMP_PID}" >"${ROOT}/tcpdump.pid"
for _ in {1..50}; do
  [[ -d "/proc/${TCPDUMP_PID}" && -e "/run/netns/${NSR}" ]] || { sleep 0.02; continue; }
  capture_exe="$(readlink -e -- "/proc/${TCPDUMP_PID}/exe")"
  capture_netns="$(stat -Lc '%d:%i' -- "/proc/${TCPDUMP_PID}/ns/net")"
  router_netns="$(stat -Lc '%d:%i' -- "/run/netns/${NSR}")"
  [[ "${capture_exe}" == "$(readlink -e -- "$(command -v tcpdump)")" &&
    "${capture_netns}" == "${router_netns}" ]] && break
  sleep 0.02
done
[[ "${capture_exe:-}" == "$(readlink -e -- "$(command -v tcpdump)")" &&
  "${capture_netns:-}" == "${router_netns:-unset}" ]] || exit 1
printf 'format=wg-mix-ebpf-faketcp-tcpdump-owner-v1\npid=%s\nboot_id=%s\nstart_ticks=%s\nnetns_inode=%s\nexecutable=%s\n' \
  "${TCPDUMP_PID}" "$(</proc/sys/kernel/random/boot_id)" \
  "$(awk '{print $22}' "/proc/${TCPDUMP_PID}/stat")" "${capture_netns}" "${capture_exe}" \
  >"${ROOT}/tcpdump-owned.v1"
sleep 1
for ((index=0; index<WG_COUNT; index++)); do
  third=$((10 + index)); target="10.82.${third}.2"; local_ip="10.82.${third}.1"; port=$((5201 + index))
  log_command "ping-wg-${index}" ip netns exec "${NSA}" ping -I "wg${index}" -c 3 -W 2 "${target}"
  ip netns exec "${NSB}" timeout --signal=TERM --kill-after=3s 15 iperf3 -s -1 -B "${target}" -p "${port}" -J \
    >"${EVIDENCE}/iperf-${index}-server.json" 2>"${EVIDENCE}/iperf-${index}-server.stderr.log" &
  IPERF_PID=$!; sleep 0.4
  streams=1; [[ "${GSO_MODE}" == on ]] && streams=4
  log_command "iperf-${index}-client" ip netns exec "${NSA}" timeout --signal=TERM --kill-after=3s 15 \
    iperf3 -c "${target}" -B "${local_ip}" -p "${port}" -t 2 -P "${streams}" -J
  wait "${IPERF_PID}"; IPERF_PID=''
done

concurrent_pids=()
for ((index=0; index<WG_COUNT; index++)); do
  third=$((10 + index))
  ip netns exec "${NSA}" ping -I "wg${index}" -c 5 -W 2 "10.82.${third}.2" \
    >"${EVIDENCE}/ping-concurrent-${index}.stdout.log" \
    2>"${EVIDENCE}/ping-concurrent-${index}.stderr.log" &
  concurrent_pids+=("$!")
  printf 'timestamp=%s event=start phase=ping-concurrent-%s pid=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${index}" "${concurrent_pids[-1]}" \
    >>"${EVIDENCE}/operations.log"
done
concurrent_failed=0
for ((index=0; index<WG_COUNT; index++)); do
  if wait "${concurrent_pids[index]}"; then concurrent_rc=0; else concurrent_rc=$?; fi
  printf 'timestamp=%s event=finish phase=ping-concurrent-%s pid=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${index}" "${concurrent_pids[index]}" \
    "${concurrent_rc}" >>"${EVIDENCE}/operations.log"
  ((concurrent_rc == 0)) || concurrent_failed=1
done
((concurrent_failed == 0)) || exit 1

run_cli a status status-a-after-traffic
run_cli b status status-b-after-traffic
validate_status "${EVIDENCE}/status-a-after-traffic.stdout.log" >"${EVIDENCE}/status-a-after-traffic-validation.log"
validate_status "${EVIDENCE}/status-b-after-traffic.stdout.log" >"${EVIDENCE}/status-b-after-traffic-validation.log"
if [[ "${GSO_MODE}" == on ]]; then
  python3 - "${EVIDENCE}/status-a-initial.stdout.log" \
    "${EVIDENCE}/status-a-after-traffic.stdout.log" >"${EVIDENCE}/gso-validation.log" <<'PY'
import json, pathlib, sys
before=json.loads(pathlib.Path(sys.argv[1]).read_text()).get("dataplane",{}).get("stats",{})
after=json.loads(pathlib.Path(sys.argv[2]).read_text()).get("dataplane",{}).get("stats",{})
keys=("egress_gso_managed_seen","egress_gso_rewrite_ok")
deltas={key:int(after.get(key,0))-int(before.get(key,0)) for key in keys}
if any(value <= 0 for value in deltas.values()):
    raise SystemExit(f"outer GSO was requested but not proven: {deltas}")
print("gso=proven " + " ".join(f"{key}_delta={value}" for key,value in deltas.items()))
PY
fi

kill -INT "${TCPDUMP_PID}"
if wait "${TCPDUMP_PID}"; then capture_rc=0; else capture_rc=$?; fi
TCPDUMP_PID=''; [[ "${capture_rc}" -eq 0 ]] || exit 1
log_command pcap-read tcpdump -nn -r "${EVIDENCE}/outer.pcap"
python3 - "${EVIDENCE}/pcap-read.stdout.log" "${WG_COUNT}" >"${EVIDENCE}/pcap-validation.log" <<'PY'
import pathlib, re, sys
lines=pathlib.Path(sys.argv[1]).read_text(errors="replace").splitlines()
count=int(sys.argv[2]); ports={str(31000+i) for i in range(count)}|{str(31100+i) for i in range(count)}
managed=[line for line in lines if any(f".{p}" in line for p in ports)]
udp=[line for line in managed if " UDP," in line]
tcp=[line for line in managed if re.search(r"Flags \[[^]]+\]", line)]
if udp or not tcp: raise SystemExit(f"outer validation failed raw_udp={len(udp)} fake_tcp={len(tcp)}")
print(f"outer=faketcp packets={len(tcp)} raw_wireguard_udp=0")
PY

run_cli a reload reload-a-same-key; run_cli b reload reload-b-same-key
run_cli a status status-a-reloaded; run_cli b status status-b-reloaded
validate_status "${EVIDENCE}/status-a-reloaded.stdout.log" >"${EVIDENCE}/status-a-reloaded-validation.log"
validate_status "${EVIDENCE}/status-b-reloaded.stdout.log" >"${EVIDENCE}/status-b-reloaded-validation.log"

# Exercise resident failure recovery. The exact endpoint-A PID is killed; the
# netns and (for classic TC) durable filter journal remain for the replacement.
kill -KILL "${DAEMON_A_PID}"
if wait "${DAEMON_A_PID}"; then exit 1; else crash_rc=$?; fi
[[ "${crash_rc}" -eq 137 ]] || exit 1
DAEMON_A_PID=''; printf 'expected_crash_rc=%s\n' "${crash_rc}" >"${EVIDENCE}/daemon-a-crash.log"
start_daemon a; wait_active a "${DAEMON_A_PID}"
run_cli a status status-a-recovered
validate_status "${EVIDENCE}/status-a-recovered.stdout.log" >"${EVIDENCE}/status-a-recovered-validation.log"
for ((index=0; index<WG_COUNT; index++)); do
  third=$((10 + index))
  log_command "ping-after-recovery-${index}" ip netns exec "${NSA}" \
    ping -I "wg${index}" -c 3 -W 2 "10.82.${third}.2"
done

# Read the process-owned session map through exact map IDs. This confirms that
# real traffic established every WGID and that the new key's reserved bytes
# remain zero. The same-tuple EngineRouter test above covers deliberately equal
# address/port tuples which a real WireGuard socket configuration cannot bind.
python3 - "${DAEMON_A_PID}" "${WG_COUNT}" >"${EVIDENCE}/session-key-validation.log" <<'PY'
import json, pathlib, re, subprocess, sys
pid,count=int(sys.argv[1]),int(sys.argv[2]); ids=[]
for entry in pathlib.Path(f"/proc/{pid}/fdinfo").iterdir():
    try: text=entry.read_text()
    except OSError: continue
    m=re.search(r"^map_id:\s+([1-9][0-9]*)$", text, re.M)
    if m: ids.append(int(m.group(1)))
session=None
for mid in sorted(set(ids)):
    info=subprocess.run(["bpftool","-j","map","show","id",str(mid)],text=True,capture_output=True)
    if info.returncode: continue
    doc=json.loads(info.stdout)
    if doc.get("key") == 32 and doc.get("value") == 80 and str(doc.get("name","")).startswith("faketcp_session"):
        session=mid; break
if session is None: raise SystemExit("cannot find exact process-owned session map")
dump=subprocess.run(["bpftool","-j","map","dump","id",str(session)],text=True,capture_output=True)
if dump.returncode: raise SystemExit(dump.stderr)
wgids=set()
for row in json.loads(dump.stdout):
    raw=row.get("key")
    if isinstance(raw,list): key=bytes(int(x,16) if isinstance(x,str) else x for x in raw)
    elif isinstance(raw,dict) and "bytes" in raw: key=bytes(raw["bytes"])
    else: continue
    if len(key)!=32 or key[28:32]!=b"\0"*4: raise SystemExit("session key ABI/reserved bytes mismatch")
    wgids.add(int.from_bytes(key[24:28],sys.byteorder))
expected=set(range(1,count+1))
if not expected.issubset(wgids): raise SystemExit(f"session WGIDs {sorted(wgids)} do not cover {sorted(expected)}")
print(f"session_map_id={session} key_size=32 reserved_zero=1 wgids={sorted(wgids)}")
PY

printf 'cell_result=PASS_READY_FOR_RESTORE run_id=%s wg_count=%s attachment=%s checksum=%s xor=%s gso=%s\n' \
  "${RUN_ID}" "${WG_COUNT}" "${ATTACHMENT_BACKEND}" "${CHECKSUM_BACKEND}" "${XOR_MODE}" "${GSO_MODE}"
