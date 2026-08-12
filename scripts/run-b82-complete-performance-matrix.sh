#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' \
    'error: B82 performance matrix requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly STAGED_NAME="scripts/run-b82-complete-performance-matrix.sh"
readonly LAUNCHER_NAME="scripts/run-smoke-netns-wg-private-mountns.sh"
readonly PRODUCTION_RUNNER_NAME="scripts/run-b82-production-performance-cell.sh"
readonly RUN_PARENT="/run/wg-mix-ebpf-performance-tests"
readonly MODULE_NAME="wg_mix_faketcp_checksum"
readonly MODULE_SYSFS="/sys/module/wg_mix_faketcp_checksum"
readonly MODULE_BTF="/sys/kernel/btf/wg_mix_faketcp_checksum"
PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB XOR_PASSWORD

if [[ "${EUID}" -ne 0 || "${EGID}" -ne 0 ]]; then
  echo "error: run the B82 performance matrix as root" >&2
  exit 1
fi
operation="run"
requested_matrix_id=""
if (($# != 0)); then
  if (($# == 3)) && [[ "$1" == "cleanup-module" && "$2" == "--run-id" &&
    "$3" =~ ^[0-9a-f]{8}$ ]]; then
    operation="cleanup-module"
    requested_matrix_id="$3"
  else
    echo "usage: ${STAGED_NAME} [cleanup-module --run-id <8hex>]" >&2
    exit 2
  fi
fi

script_reference="${BASH_SOURCE[0]}"
if [[ "${script_reference}" == /* ]]; then
  script_path="${script_reference}"
elif [[ "${script_reference}" == "${STAGED_NAME}" ]]; then
  script_path="$(builtin pwd -P)/${STAGED_NAME}"
else
  echo "error: matrix path is not the fixed staged entry" >&2
  exit 1
fi
source_root="${script_path%/"${STAGED_NAME}"}"
if [[ ! "${source_root}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]]; then
  echo "error: matrix must run from a root-owned source stage" >&2
  exit 1
fi
launcher="${source_root}/${LAUNCHER_NAME}"
production_runner="${source_root}/${PRODUCTION_RUNNER_NAME}"
module_object="${source_root}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
source_stage_id="${source_root#"/run/wg-mix-ebpf-source-stages/"}"
source_stage_id="${source_stage_id%%/*}"
if [[ ! "${source_stage_id}" =~ ^[0-9a-f]{8}$ ]]; then
  echo "error: cannot derive the reviewed source stage ID" >&2
  exit 1
fi
for executable in "${script_path}" "${launcher}" "${production_runner}"; do
  if [[ ! -f "${executable}" || -L "${executable}" || ! -x "${executable}" ||
    "$(stat -c '%u:%g:%a:%h' -- "${executable}")" != "0:0:700:1" ]]; then
    echo "error: staged performance executable is unsafe: ${executable}" >&2
    exit 1
  fi
done

if [[ "${operation}" == "cleanup-module" ]]; then
  matrix_id="${requested_matrix_id}"
  xor_secret=""
else
  matrix_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"
  xor_secret="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
fi
if [[ ! "${matrix_id}" =~ ^[0-9a-f]{8}$ ||
  ("${operation}" == "run" && ! "${xor_secret}" =~ ^[A-Za-z0-9_-]{40,64}$) ]]; then
  echo "error: failed to generate matrix identity or XOR secret" >&2
  exit 1
fi

readonly MATRIX_ROOT="${RUN_PARENT}/${matrix_id}"
readonly MATRIX_EVIDENCE="${MATRIX_ROOT}/evidence"
readonly MODULE_LOCK="${RUN_PARENT}/checksum-module-lease.v1.lock"
readonly MODULE_INTENT="${MATRIX_ROOT}/checksum-module-intent.v1"
readonly MODULE_OWNED="${MATRIX_ROOT}/checksum-module-owned.v1"
readonly MODULE_UNLOADED="${MATRIX_ROOT}/checksum-module-unloaded.v1"
readonly MODULE_LEASE_ID="${source_stage_id}-${matrix_id}"

matrix_logged() {
  local phase="$1"
  shift
  local stdout_path="${MATRIX_EVIDENCE}/${phase}.stdout.log"
  local stderr_path="${MATRIX_EVIDENCE}/${phase}.stderr.log"
  local metadata_path="${MATRIX_EVIDENCE}/${phase}.meta.log"
  local status
  {
    printf 'timestamp=%s event=start phase=%s argv=' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}"
    printf '%q ' "$@"
    printf '\nstdout=%s\nstderr=%s\n' "${stdout_path}" "${stderr_path}"
  } >"${metadata_path}"
  if "$@" >"${stdout_path}" 2>"${stderr_path}"; then status=0; else status=$?; fi
  printf 'timestamp=%s event=finish phase=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${phase}" "${status}" >>"${metadata_path}"
  return "${status}"
}

module_live_identity() {
  local live_lease live_srcversion live_refcount
  [[ -d "${MODULE_SYSFS}" && -f "${MODULE_SYSFS}/parameters/lease_id" &&
    -f "${MODULE_SYSFS}/srcversion" && -f "${MODULE_BTF}" ]] || return 1
  live_lease="$(<"${MODULE_SYSFS}/parameters/lease_id")"
  live_srcversion="$(<"${MODULE_SYSFS}/srcversion")"
  live_srcversion="${live_srcversion^^}"
  live_refcount="$(awk -v name="${MODULE_NAME}" '$1 == name {print $3}' /proc/modules)"
  [[ "${live_lease}" == "${MODULE_LEASE_ID}" &&
    "${live_srcversion}" == "${module_srcversion}" &&
    "${live_refcount}" =~ ^[0-9]+$ ]] || return 1
  printf 'sysfs=%s\nparameter=%s\nsrcversion=%s\nbtf=%s\nbtf_sha256=%s\nlease_id=%s\nrefcount=%s\n' \
    "$(stat -Lc '%d:%i' -- "${MODULE_SYSFS}")" \
    "$(stat -Lc '%d:%i' -- "${MODULE_SYSFS}/parameters/lease_id")" \
    "${live_srcversion}" "$(stat -Lc '%d:%i' -- "${MODULE_BTF}")" \
    "$(sha256sum -- "${MODULE_BTF}" | awk '{print $1}')" \
    "${live_lease}" "${live_refcount}"
}

matrix_failure() {
  local status="$1"
  local line="$2"
  trap - ERR INT TERM
  set +e
  unset xor_secret
  printf 'PERFORMANCE_MATRIX_FAILURE matrix_id=%s line=%s rc=%s timestamp=%s\n' \
    "${matrix_id}" "${line}" "${status}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2
  printf 'run_id=%s\nline=%s\nrc=%s\nmodule_lease_id=%s\n' \
    "${matrix_id}" "${line}" "${status}" "${MODULE_LEASE_ID}" \
    >"${MATRIX_EVIDENCE}/failure-summary.log"
  {
    printf 'timestamp=%s module=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${MODULE_NAME}"
    if [[ -d "${MODULE_SYSFS}" ]]; then
      printf 'module_state=present\n'
      /bin/cat -- "${MODULE_SYSFS}/parameters/lease_id"
      /bin/cat -- "${MODULE_SYSFS}/srcversion"
      awk -v name="${MODULE_NAME}" '$1 == name {print}' /proc/modules
      stat -Lc 'btf=%d:%i:%u:%g:%a:%h:%s' -- "${MODULE_BTF}"
      sha256sum -- "${MODULE_BTF}"
    else
      printf 'module_state=absent\n'
    fi
  } >"${MATRIX_EVIDENCE}/failure-module-diagnostics.log" 2>&1
  printf 'MATRIX_FAILURE_RESOURCES_RETAINED matrix_id=%s root=%s module=%s lease_id=%s\n' \
    "${matrix_id}" "${MATRIX_ROOT}" "${MODULE_NAME}" "${MODULE_LEASE_ID}" >&2
  printf '%s\n' 'No automatic module unload or evidence cleanup was attempted.' >&2
  exit "${status}"
}

receipt_value() {
  local key="$1"
  local path="$2"
  awk -F= -v key="${key}" '
    $1 == key { count++; print substr($0, length(key) + 2) }
    END { if (count != 1) exit 79 }
  ' "${path}"
}

cleanup_owned_module() {
  local intent_stage intent_boot intent_commit intent_module intent_sha
  local intent_srcversion intent_lease live_btf live_btf_sha owned_btf owned_btf_sha
  local refcount owned_sha reason

  if [[ ! -d "${RUN_PARENT}" || -L "${RUN_PARENT}" ||
    "$(stat -c '%u:%g:%a' -- "${RUN_PARENT}")" != "0:0:700" ||
    ! -d "${MATRIX_ROOT}" || -L "${MATRIX_ROOT}" ||
    "$(stat -c '%u:%g:%a' -- "${MATRIX_ROOT}")" != "0:0:700" ||
    ! -d "${MATRIX_EVIDENCE}" || -L "${MATRIX_EVIDENCE}" ||
    "$(<"${MATRIX_ROOT}/owner")" != "wg-mix-ebpf-performance:${matrix_id}" ]]; then
    echo "error: matrix cleanup ownership root is invalid" >&2
    return 1
  fi
  if [[ ! -f "${MODULE_INTENT}" || -L "${MODULE_INTENT}" ||
    "$(stat -c '%u:%g:%a:%h' -- "${MODULE_INTENT}")" != "0:0:600:1" ]]; then
    echo "error: matrix cleanup receipt is unsafe: ${MODULE_INTENT}" >&2
    return 1
  fi
  intent_stage="$(receipt_value source_stage_id "${MODULE_INTENT}")"
  intent_boot="$(receipt_value boot_id "${MODULE_INTENT}")"
  intent_commit="$(receipt_value commit "${MODULE_INTENT}")"
  intent_module="$(receipt_value module "${MODULE_INTENT}")"
  intent_sha="$(receipt_value ko_sha256 "${MODULE_INTENT}")"
  intent_srcversion="$(receipt_value srcversion "${MODULE_INTENT}")"
  intent_lease="$(receipt_value lease_id "${MODULE_INTENT}")"
  if [[ "$(receipt_value format "${MODULE_INTENT}")" != \
      "wg-mix-ebpf-b82-performance-module-intent-v1" ||
    "$(receipt_value run_id "${MODULE_INTENT}")" != "${matrix_id}" ||
    "${intent_stage}" != "${source_stage_id}" ||
    "${intent_boot}" != "$(</proc/sys/kernel/random/boot_id)" ||
    "${intent_commit}" != "$(/usr/bin/git -C "${source_root}" rev-parse --verify 'HEAD^{commit}')" ||
    "${intent_module}" != "${MODULE_NAME}" ||
    "${intent_lease}" != "${MODULE_LEASE_ID}" ||
    ! "${intent_sha}" =~ ^[0-9a-f]{64}$ ||
    ! "${intent_srcversion}" =~ ^[0-9A-F]{8,64}$ ||
    ! -f "${module_object}" || -L "${module_object}" ||
    "$(sha256sum -- "${module_object}" | awk '{print $1}')" != "${intent_sha}" ||
    "$(/usr/sbin/modinfo -F srcversion -- "${module_object}" | tr '[:lower:]' '[:upper:]')" != "${intent_srcversion}" ]]; then
    echo "error: matrix cleanup intent identity mismatch" >&2
    return 1
  fi
  module_srcversion="${intent_srcversion}"
  if [[ ! -f "${MODULE_LOCK}" || -L "${MODULE_LOCK}" ||
    "$(stat -c '%u:%g:%a:%h' -- "${MODULE_LOCK}")" != "0:0:600:1" ]]; then
    echo "error: matrix cleanup module lock is unsafe" >&2
    return 1
  fi
  exec {module_lock_fd}<>"${MODULE_LOCK}"
  matrix_logged cleanup-module-lock /usr/bin/flock --exclusive --nonblock "${module_lock_fd}"

  if [[ -f "${MODULE_UNLOADED}" && ! -L "${MODULE_UNLOADED}" ]]; then
    if [[ -d "${MODULE_SYSFS}" ||
      "$(receipt_value format "${MODULE_UNLOADED}")" != \
        "wg-mix-ebpf-b82-performance-module-unloaded-v1" ||
      "$(receipt_value run_id "${MODULE_UNLOADED}")" != "${matrix_id}" ||
      "$(receipt_value lease_id "${MODULE_UNLOADED}")" != "${MODULE_LEASE_ID}" ||
      "$(receipt_value intent_sha256 "${MODULE_UNLOADED}")" != \
        "$(sha256sum -- "${MODULE_INTENT}" | awk '{print $1}')" ]]; then
      echo "error: reentrant module cleanup receipt mismatch" >&2
      return 1
    fi
    printf 'PERFORMANCE_MODULE_CLEANUP_COMPLETE matrix_id=%s state=already-absent receipt=%s\n' \
      "${matrix_id}" "${MODULE_UNLOADED}"
    return 0
  fi

  owned_sha="absent"
  reason="intent-no-live"
  if [[ -d "${MODULE_SYSFS}" ]]; then
    live_btf="$(stat -Lc '%d:%i' -- "${MODULE_BTF}")"
    live_btf_sha="$(sha256sum -- "${MODULE_BTF}" | awk '{print $1}')"
    refcount="$(awk -v name="${MODULE_NAME}" '$1 == name {print $3}' /proc/modules)"
    if [[ "$(<"${MODULE_SYSFS}/parameters/lease_id")" != "${MODULE_LEASE_ID}" ||
      "$(tr '[:lower:]' '[:upper:]' <"${MODULE_SYSFS}/srcversion")" != "${intent_srcversion}" ||
      "${refcount}" != "0" ]]; then
      echo "error: live module identity/refcount no longer matches its owned receipt" >&2
      return 1
    fi
    if [[ -f "${MODULE_OWNED}" && ! -L "${MODULE_OWNED}" ]]; then
      if [[ "$(stat -c '%u:%g:%a:%h' -- "${MODULE_OWNED}")" != "0:0:600:1" ||
        "$(receipt_value format "${MODULE_OWNED}")" != \
          "wg-mix-ebpf-b82-performance-module-owned-v1" ||
        "$(receipt_value run_id "${MODULE_OWNED}")" != "${matrix_id}" ||
        "$(receipt_value intent_sha256 "${MODULE_OWNED}")" != \
          "$(sha256sum -- "${MODULE_INTENT}" | awk '{print $1}')" ||
        "$(receipt_value ko_sha256 "${MODULE_OWNED}")" != "${intent_sha}" ||
        "$(receipt_value lease_id "${MODULE_OWNED}")" != "${MODULE_LEASE_ID}" ]]; then
        echo "error: live module owned receipt is invalid" >&2
        return 1
      fi
      owned_btf="$(receipt_value btf "${MODULE_OWNED}")"
      owned_btf_sha="$(receipt_value btf_sha256 "${MODULE_OWNED}")"
      if [[ "${live_btf}" != "${owned_btf}" || "${live_btf_sha}" != "${owned_btf_sha}" ]]; then
        echo "error: live module BTF identity changed from its owned receipt" >&2
        return 1
      fi
      owned_sha="$(sha256sum -- "${MODULE_OWNED}" | awk '{print $1}')"
      reason="owned-live-unloaded"
    else
      reason="recovered-unreceipted-live"
    fi
    matrix_logged cleanup-module-unload /usr/sbin/rmmod "${MODULE_NAME}"
    [[ ! -e "${MODULE_SYSFS}" && ! -e "${MODULE_BTF}" ]]
  elif [[ -f "${MODULE_OWNED}" && ! -L "${MODULE_OWNED}" ]]; then
    owned_sha="$(sha256sum -- "${MODULE_OWNED}" | awk '{print $1}')"
    reason="owned-already-absent"
  fi
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-performance-module-unloaded-v1' \
    "run_id=${matrix_id}" "lease_id=${MODULE_LEASE_ID}" \
    "intent_sha256=$(sha256sum -- "${MODULE_INTENT}" | awk '{print $1}')" \
    "owned_receipt_sha256=${owned_sha}" "reason=${reason}" 'state=unloaded' \
    >"${MODULE_UNLOADED}"
  printf 'PERFORMANCE_MODULE_CLEANUP_COMPLETE matrix_id=%s state=absent receipt=%s\n' \
    "${matrix_id}" "${MODULE_UNLOADED}"
}

if [[ "${operation}" == "cleanup-module" ]]; then
  trap 'matrix_failure $? $LINENO' ERR
  trap 'matrix_failure 130 $LINENO' INT TERM
  cleanup_owned_module
  trap - ERR INT TERM
  exit 0
fi

if [[ ! -d "${RUN_PARENT}" ]]; then
  mkdir --mode=0700 -- "${RUN_PARENT}"
fi
if [[ -L "${RUN_PARENT}" || ! -d "${RUN_PARENT}" ||
  "$(stat -c '%u:%g:%a' -- "${RUN_PARENT}")" != "0:0:700" ||
  -e "${MATRIX_ROOT}" || -L "${MATRIX_ROOT}" ]]; then
  echo "error: performance matrix evidence root is unsafe" >&2
  exit 1
fi
mkdir --mode=0700 -- "${MATRIX_ROOT}" "${MATRIX_EVIDENCE}"
printf 'wg-mix-ebpf-performance:%s\n' "${matrix_id}" >"${MATRIX_ROOT}/owner"
printf '%s\n' \
  'format=wg-mix-ebpf-b82-performance-matrix-v1' \
  'kind=matrix' \
  "run_id=${matrix_id}" \
  "source_stage_id=${source_stage_id}" \
  "module=${MODULE_NAME}" \
  "module_lease_id=${MODULE_LEASE_ID}" \
  'cells=33' 'samples=297' \
  "write_set=${MATRIX_ROOT},${MODULE_LOCK}:shared-advisory,${MODULE_NAME}:temporary" \
  >"${MATRIX_ROOT}/manifest"

trap 'matrix_failure $? $LINENO' ERR
trap 'matrix_failure 130 $LINENO' INT TERM

if [[ ! -e "${MODULE_LOCK}" && ! -L "${MODULE_LOCK}" ]]; then
  (set -o noclobber; : >"${MODULE_LOCK}")
  chmod 0600 -- "${MODULE_LOCK}"
fi
if [[ ! -f "${MODULE_LOCK}" || -L "${MODULE_LOCK}" ||
  "$(stat -c '%u:%g:%a:%h' -- "${MODULE_LOCK}")" != "0:0:600:1" ]]; then
  echo "error: performance checksum module lease lock is unsafe" >&2
  exit 1
fi
exec {module_lock_fd}<>"${MODULE_LOCK}"
matrix_logged module-lock /usr/bin/flock --exclusive --nonblock "${module_lock_fd}"

matrix_logged module-build /usr/bin/timeout --signal=TERM --kill-after=30s 10m \
  /usr/bin/make --no-print-directory -C "${source_root}" build-faketcp-checksum-kmod
if [[ ! -f "${module_object}" || -L "${module_object}" ]] ||
  [[ ! "$(stat -c '%u:%g:%a:%h' -- "${module_object}")" =~ ^0:0:(600|644):1$ ]]; then
  echo "error: built checksum module object is unsafe" >&2
  exit 1
fi
module_sha256="$(sha256sum -- "${module_object}" | awk '{print $1}')"
module_srcversion="$(/usr/sbin/modinfo -F srcversion -- "${module_object}")"
module_srcversion="${module_srcversion^^}"
boot_id="$(</proc/sys/kernel/random/boot_id)"
commit="$(/usr/bin/git -C "${source_root}" rev-parse --verify 'HEAD^{commit}')"
if [[ ! "${module_sha256}" =~ ^[0-9a-f]{64}$ ||
  ! "${module_srcversion}" =~ ^[0-9A-F]{8,64}$ ||
  ! "${boot_id}" =~ ^[0-9a-f-]{36}$ || ! "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: checksum module build identity is invalid" >&2
  exit 1
fi
printf '%s\n' \
  'format=wg-mix-ebpf-b82-performance-module-intent-v1' \
  "run_id=${matrix_id}" "source_stage_id=${source_stage_id}" "boot_id=${boot_id}" \
  "commit=${commit}" "module=${MODULE_NAME}" "ko_sha256=${module_sha256}" \
  "srcversion=${module_srcversion}" "lease_id=${MODULE_LEASE_ID}" \
  "lock=${MODULE_LOCK}" 'state=prepared' >"${MODULE_INTENT}"
if [[ -e "${MODULE_SYSFS}" || -L "${MODULE_SYSFS}" ||
  -e "${MODULE_BTF}" || -L "${MODULE_BTF}" ]]; then
  echo "error: checksum module/BTF preexists before the owned matrix load" >&2
  exit 1
fi
matrix_logged module-load /usr/sbin/insmod "${module_object}" "lease_id=${MODULE_LEASE_ID}"
module_identity="$(module_live_identity)"
printf '%s\n' \
  'format=wg-mix-ebpf-b82-performance-module-owned-v1' \
  "run_id=${matrix_id}" "intent_sha256=$(sha256sum -- "${MODULE_INTENT}" | awk '{print $1}')" \
  "ko_sha256=${module_sha256}" "${module_identity}" 'state=owned' >"${MODULE_OWNED}"

run_udp_cell() {
  local label="$1"
  local dataplane_mode="$2"
  local backend="$3"
  local xor_mode="$4"
  local scope="$5"
  local max_bytes="$6"
  local status=0
  local common_environment=(
    "DATAPLANE_MODE=${dataplane_mode}"
    "ATTACHMENT_BACKEND=${backend}"
    "OUTER_FAMILY=ipv4"
    "INITIAL_CAPTURE_TIMEOUT=8"
    "UNDERLAY_MTU=2200"
    "WG_MTU=2000"
    "TCP_CHECKS=enforce"
    "TCP_MTUS=1420"
    "TCP_STREAMS=1"
    "TCP_DIRECTIONS=forward reverse bidir"
    "TCP_DURATION=3"
    "TCP_REPETITIONS=3"
    "TCP_MIN_BYTES=1048576"
    "TCP_MAX_RETRANSMITS=0"
    "TCP_MIN_FAIRNESS=0.90"
    "TCP_CAPTURE_PACKETS=128"
    "TCP_INNER_GSO_CHECKS=report"
    "TCP_OUTER_GSO_CHECKS=observe"
    "XOR_SCOPE=${scope}"
    "XOR_MAX_BYTES=${max_bytes}"
  )

  if [[ ! "${label}" =~ ^(wireguard|tcx|classic_tc)-(baseline|prefix-(4|16|64|128|256|512|1024|2048)|full-2048)$ ||
    ! "${dataplane_mode}" =~ ^(ebpf|wireguard)$ ||
    ! "${backend}" =~ ^(auto|tcx|classic_tc)$ ||
    ! "${xor_mode}" =~ ^(off|on)$ ||
    ! "${scope}" =~ ^wg-payload-(prefix|full)$ ||
    ! "${max_bytes}" =~ ^(4|16|64|128|256|512|1024|2048)$ ]]; then
    echo "error: invalid fixed performance cell: ${label}" >&2
    return 1
  fi
  printf 'PERFORMANCE_CELL_START matrix_id=%s label=%s timestamp=%s\n' \
    "${matrix_id}" "${label}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "${xor_mode}" == "on" ]]; then
    if XOR_PASSWORD="${xor_secret}" /usr/bin/env "${common_environment[@]}" \
      /usr/bin/bash -p "${launcher}"; then
      status=0
    else
      status=$?
    fi
  else
    if /usr/bin/env -u XOR_PASSWORD "${common_environment[@]}" \
      /usr/bin/bash -p "${launcher}"; then
      status=0
    else
      status=$?
    fi
  fi
  printf 'PERFORMANCE_CELL_FINISH matrix_id=%s label=%s rc=%s timestamp=%s\n' \
    "${matrix_id}" "${label}" "${status}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  return "${status}"
}

run_production_cell() {
  local label="$1"
  local transport="$2"
  local backend="$3"
  local cipher="$4"
  local max_bytes="$5"
  local cell_run_id
  local status=0

  if [[ ! "${label}" =~ ^(icmp-(tcx|classic_tc)-baseline|faketcp-tcx-(baseline|prefix-(4|16|64|128|256|512|1024|2048)|full-2048))$ ]] ||
    [[ ! "${transport}" =~ ^(icmp|faketcp)$ ]] ||
    [[ ! "${backend}" =~ ^(tcx|classic_tc)$ ]] ||
    [[ ! "${cipher}" =~ ^(none|prefix|full)$ ]] ||
    [[ ! "${max_bytes}" =~ ^(4|16|64|128|256|512|1024|2048)$ ]]; then
    echo "error: invalid fixed production performance cell: ${label}" >&2
    return 1
  fi
  cell_run_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"
  if [[ ! "${cell_run_id}" =~ ^[0-9a-f]{8}$ ]]; then
    echo "error: failed to generate production performance run ID" >&2
    return 1
  fi
  printf 'PERFORMANCE_CELL_START matrix_id=%s cell_run_id=%s label=%s timestamp=%s\n' \
    "${matrix_id}" "${cell_run_id}" "${label}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if /usr/bin/bash -p "${production_runner}" run \
    --run-id "${cell_run_id}" --label "${label}" --transport "${transport}" \
    --backend "${backend}" --cipher "${cipher}" --max-bytes "${max_bytes}"; then
    status=0
  else
    status=$?
  fi
  printf 'PERFORMANCE_CELL_FINISH matrix_id=%s cell_run_id=%s label=%s rc=%s timestamp=%s\n' \
    "${matrix_id}" "${cell_run_id}" "${label}" "${status}" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  return "${status}"
}

printf 'PERFORMANCE_MATRIX_START matrix_id=%s cells=33 repetitions=3 duration_seconds=3 timestamp=%s\n' \
  "${matrix_id}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_udp_cell wireguard-baseline wireguard auto off wg-payload-prefix 4
run_udp_cell tcx-baseline ebpf tcx off wg-payload-prefix 4
run_udp_cell classic_tc-baseline ebpf classic_tc off wg-payload-prefix 4
for max_bytes in 4 16 64 128 256 512 1024 2048; do
  run_udp_cell "tcx-prefix-${max_bytes}" ebpf tcx on wg-payload-prefix "${max_bytes}"
  run_udp_cell "classic_tc-prefix-${max_bytes}" ebpf classic_tc on wg-payload-prefix "${max_bytes}"
done
run_udp_cell tcx-full-2048 ebpf tcx on wg-payload-full 2048
run_udp_cell classic_tc-full-2048 ebpf classic_tc on wg-payload-full 2048
run_production_cell icmp-tcx-baseline icmp tcx none 4
run_production_cell icmp-classic_tc-baseline icmp classic_tc none 4
run_production_cell faketcp-tcx-baseline faketcp tcx none 4
for max_bytes in 4 16 64 128 256 512 1024 2048; do
  run_production_cell "faketcp-tcx-prefix-${max_bytes}" faketcp tcx prefix "${max_bytes}"
done
run_production_cell faketcp-tcx-full-2048 faketcp tcx full 2048
unset xor_secret
module_identity_after="$(module_live_identity)"
if [[ "${module_identity_after}" != "${module_identity}" ||
  "$(receipt_value refcount "${MODULE_OWNED}")" != "0" ]]; then
  echo "error: checksum module live identity/refcount changed before matrix restore" >&2
  exit 1
fi
matrix_logged module-unload /usr/sbin/rmmod "${MODULE_NAME}"
if [[ -e "${MODULE_SYSFS}" || -L "${MODULE_SYSFS}" ||
  -e "${MODULE_BTF}" || -L "${MODULE_BTF}" ]]; then
  echo "error: checksum module/BTF remains after successful matrix restore" >&2
  exit 1
fi
printf '%s\n' \
  'format=wg-mix-ebpf-b82-performance-module-unloaded-v1' \
  "run_id=${matrix_id}" "lease_id=${MODULE_LEASE_ID}" \
  "intent_sha256=$(sha256sum -- "${MODULE_INTENT}" | awk '{print $1}')" \
  "owned_receipt_sha256=$(sha256sum -- "${MODULE_OWNED}" | awk '{print $1}')" \
  'reason=owned-live-unloaded' 'state=unloaded' >"${MODULE_UNLOADED}"
printf 'format=wg-mix-ebpf-b82-production-performance-complete-v1\nrun_id=%s\nmanifest_sha256=%s\nactive_resources=absent\nsensitive_files=absent\n' \
  "${matrix_id}" "$(sha256sum -- "${MATRIX_ROOT}/manifest" | awk '{print $1}')" \
  >"${MATRIX_ROOT}/complete"
trap - ERR INT TERM
printf 'PERFORMANCE_MATRIX_COMPLETE matrix_id=%s cells=33 samples=297 timestamp=%s\n' \
  "${matrix_id}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
