#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' 'error: legacy performance module recovery requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly RUN_PARENT='/run/wg-mix-ebpf-performance-tests'
readonly MODULE_NAME='wg_mix_faketcp_checksum'
readonly MODULE_SYSFS="/sys/module/${MODULE_NAME}"
readonly MODULE_BTF="/sys/kernel/btf/${MODULE_NAME}"
readonly MODULE_LOCK="${RUN_PARENT}/checksum-module-lease.v1.lock"
PATH="${SAFE_PATH}"; LC_ALL=C; IFS=$' \t\n'; umask 077
export PATH LC_ALL
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB

stop() {
  printf 'LEGACY_PERFORMANCE_MODULE_RECOVERY_STOP reason=%s rc=%s\n' "$1" "${2:-79}" >&2
  exit "${2:-79}"
}

[[ "${EUID}" -eq 0 && "$(id -g)" -eq 0 ]] || stop root 1
[[ $# -eq 2 && "$1" == --run-id && "$2" =~ ^[0-9a-f]{8}$ ]] || stop arguments 2
readonly RUN_ID="$2"
readonly RUN_ROOT="${RUN_PARENT}/${RUN_ID}"
readonly EVIDENCE="${RUN_ROOT}/evidence"
readonly OWNER="${RUN_ROOT}/owner"
readonly MANIFEST="${RUN_ROOT}/manifest"
readonly INTENT="${RUN_ROOT}/checksum-module-intent.v1"
readonly OWNED="${RUN_ROOT}/checksum-module-owned.v1"
readonly UNLOADED="${RUN_ROOT}/checksum-module-unloaded.v1"

script_path="${BASH_SOURCE[0]}"
[[ "${script_path}" =~ ^/var/tmp/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source/scripts/recover-b82-performance-module-v1\.sh$ ]] ||
  stop script-path
[[ -f "${script_path}" && ! -L "${script_path}" && -x "${script_path}" &&
  "$(stat -c '%u:%g:%a:%h' -- "${script_path}")" =~ ^0:0:([0-7]{3,4}):1$ ]] ||
  stop script-shape

value() {
  local key="$1" path="$2"
  awk -F= -v key="${key}" '
    $1 == key { count++; print substr($0, length(key) + 2) }
    END { if (count != 1) exit 79 }
  ' "${path}"
}

exact_file() {
  local path="$1" mode="$2"
  [[ -f "${path}" && ! -L "${path}" &&
    "$(stat -c '%u:%g:%a:%h' -- "${path}")" == "0:0:${mode}:1" ]]
}

validate_records() {
  [[ -d "${RUN_PARENT}" && ! -L "${RUN_PARENT}" &&
    "$(stat -c '%u:%g:%a' -- "${RUN_PARENT}")" == 0:0:700 &&
    -d "${RUN_ROOT}" && ! -L "${RUN_ROOT}" &&
    "$(stat -c '%u:%g:%a' -- "${RUN_ROOT}")" == 0:0:700 &&
    -d "${EVIDENCE}" && ! -L "${EVIDENCE}" &&
    "$(stat -c '%u:%g:%a' -- "${EVIDENCE}")" == 0:0:700 ]] || return 1
  exact_file "${OWNER}" 600 && exact_file "${MANIFEST}" 600 &&
    exact_file "${INTENT}" 600 && exact_file "${OWNED}" 600 || return 1
  [[ "$(<"${OWNER}")" == "wg-mix-ebpf-performance:${RUN_ID}" &&
    "$(value format "${MANIFEST}")" == wg-mix-ebpf-b82-performance-matrix-v1 &&
    "$(value kind "${MANIFEST}")" == matrix &&
    "$(value run_id "${MANIFEST}")" == "${RUN_ID}" &&
    "$(value cells "${MANIFEST}")" == 33 &&
    "$(value samples "${MANIFEST}")" == 297 &&
    "$(value format "${INTENT}")" == wg-mix-ebpf-b82-performance-module-intent-v1 &&
    "$(value run_id "${INTENT}")" == "${RUN_ID}" &&
    "$(value boot_id "${INTENT}")" == "$(< /proc/sys/kernel/random/boot_id)" &&
    "$(value module "${INTENT}")" == "${MODULE_NAME}" &&
    "$(value lock "${INTENT}")" == "${MODULE_LOCK}" &&
    "$(value format "${OWNED}")" == wg-mix-ebpf-b82-performance-module-owned-v1 &&
    "$(value run_id "${OWNED}")" == "${RUN_ID}" &&
    "$(value intent_sha256 "${OWNED}")" == "$(sha256sum -- "${INTENT}" | awk '{print $1}')" &&
    "$(value ko_sha256 "${OWNED}")" == "$(value ko_sha256 "${INTENT}")" ]] || return 1

  STAGE_ID="$(value source_stage_id "${INTENT}")"
  COMMIT="$(value commit "${INTENT}")"
  SRCVERSION="$(value srcversion "${INTENT}")"
  LEASE_ID="$(value lease_id "${INTENT}")"
  INTENT_SHA="$(sha256sum -- "${INTENT}" | awk '{print $1}')"
  OWNED_SHA="$(sha256sum -- "${OWNED}" | awk '{print $1}')"
  [[ "${STAGE_ID}" =~ ^[0-9a-f]{8}$ && "${COMMIT}" =~ ^[0-9a-f]{40}$ &&
    "${SRCVERSION}" =~ ^[0-9A-F]{8,64}$ &&
    "${LEASE_ID}" == "${STAGE_ID}-${RUN_ID}" &&
    "$(value source_stage_id "${MANIFEST}")" == "${STAGE_ID}" &&
    "$(value module "${MANIFEST}")" == "${MODULE_NAME}" &&
    "$(value module_lease_id "${MANIFEST}")" == "${LEASE_ID}" &&
    "$(value write_set "${MANIFEST}")" == "${RUN_ROOT},${MODULE_LOCK}:shared-advisory,${MODULE_NAME}:temporary" &&
    "$(value lease_id "${OWNED}")" == "${LEASE_ID}" &&
    "$(value srcversion "${OWNED}")" == "${SRCVERSION}" &&
    "$(value refcount "${OWNED}")" == 0 ]] || return 1
}

validate_live() {
  local refcount
  [[ -d "${MODULE_SYSFS}" && ! -L "${MODULE_SYSFS}" &&
    -f "${MODULE_SYSFS}/parameters/lease_id" && ! -L "${MODULE_SYSFS}/parameters/lease_id" &&
    -f "${MODULE_SYSFS}/srcversion" && ! -L "${MODULE_SYSFS}/srcversion" &&
    -f "${MODULE_BTF}" && ! -L "${MODULE_BTF}" ]] || return 1
  refcount="$(awk -v name="${MODULE_NAME}" '$1 == name {print $3}' /proc/modules)"
  [[ "${refcount}" == 0 &&
    "$(<"${MODULE_SYSFS}/parameters/lease_id")" == "${LEASE_ID}" &&
    "$(tr '[:lower:]' '[:upper:]' <"${MODULE_SYSFS}/srcversion")" == "${SRCVERSION}" &&
    "$(stat -Lc '%d:%i' -- "${MODULE_SYSFS}")" == "$(value sysfs "${OWNED}")" &&
    "$(stat -Lc '%d:%i' -- "${MODULE_SYSFS}/parameters/lease_id")" == "$(value parameter "${OWNED}")" &&
    "$(stat -Lc '%d:%i' -- "${MODULE_BTF}")" == "$(value btf "${OWNED}")" &&
    "$(sha256sum -- "${MODULE_BTF}" | awk '{print $1}')" == "$(value btf_sha256 "${OWNED}")" ]] || return 1
}

validate_unloaded() {
  exact_file "${UNLOADED}" 600 && [[ ! -e "${MODULE_SYSFS}" && ! -e "${MODULE_BTF}" &&
    "$(value format "${UNLOADED}")" == wg-mix-ebpf-b82-performance-module-unloaded-v1 &&
    "$(value run_id "${UNLOADED}")" == "${RUN_ID}" &&
    "$(value lease_id "${UNLOADED}")" == "${LEASE_ID}" &&
    "$(value intent_sha256 "${UNLOADED}")" == "${INTENT_SHA}" &&
    "$(value owned_receipt_sha256 "${UNLOADED}")" == "${OWNED_SHA}" ]]
}

validate_records || stop records
exact_file "${MODULE_LOCK}" 600 || stop lock
exec {lock_fd}<>"${MODULE_LOCK}"
/usr/bin/flock --exclusive --nonblock "${lock_fd}" || stop lock-busy
validate_records || stop records-after-lock

if [[ -e "${UNLOADED}" || -L "${UNLOADED}" ]]; then
  validate_unloaded || stop unloaded-receipt
  printf 'LEGACY_PERFORMANCE_MODULE_RECOVERY_COMPLETE run_id=%s state=already-absent\n' "${RUN_ID}"
  exit 0
fi

state=already-absent
if [[ -e "${MODULE_SYSFS}" || -e "${MODULE_BTF}" ]]; then
  validate_live || stop live-identity
  state=owned-live-unloaded
fi
printf 'LEGACY_PERFORMANCE_MODULE_RECOVERY_PREFLIGHT host=%s boot_id=%s run_id=%s module=%s lease_id=%s srcversion=%s state=%s\n' \
  "$(hostname)" "$(< /proc/sys/kernel/random/boot_id)" "${RUN_ID}" \
  "${MODULE_NAME}" "${LEASE_ID}" "${SRCVERSION}" "${state}"

if [[ "${state}" == owned-live-unloaded ]]; then
  printf 'timestamp=%s event=start argv=/usr/sbin/rmmod\ %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${MODULE_NAME}" \
    >"${EVIDENCE}/recovery-module-unload.meta.log"
  if /usr/sbin/rmmod "${MODULE_NAME}" \
      >"${EVIDENCE}/recovery-module-unload.stdout.log" \
      2>"${EVIDENCE}/recovery-module-unload.stderr.log"; then
    unload_rc=0
  else
    unload_rc=$?
  fi
  printf 'timestamp=%s event=finish rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${unload_rc}" \
    >>"${EVIDENCE}/recovery-module-unload.meta.log"
  [[ "${unload_rc}" -eq 0 ]] || stop rmmod "${unload_rc}"
fi
[[ ! -e "${MODULE_SYSFS}" && ! -e "${MODULE_BTF}" ]] || stop post-unload

receipt_tmp="$(mktemp "${RUN_ROOT}/.checksum-module-unloaded.recovery.XXXXXX")"
chmod 0600 -- "${receipt_tmp}"
printf '%s\n' \
  'format=wg-mix-ebpf-b82-performance-module-unloaded-v1' \
  "run_id=${RUN_ID}" "lease_id=${LEASE_ID}" \
  "intent_sha256=${INTENT_SHA}" "owned_receipt_sha256=${OWNED_SHA}" \
  "reason=${state}" 'state=unloaded' >"${receipt_tmp}"
[[ "$(stat -c '%u:%g:%a:%h' -- "${receipt_tmp}")" == 0:0:600:1 ]] || stop receipt-temp
mv -T -- "${receipt_tmp}" "${UNLOADED}"
validate_unloaded || stop receipt-final
printf 'LEGACY_PERFORMANCE_MODULE_RECOVERY_COMPLETE run_id=%s state=absent receipt=%s\n' \
  "${RUN_ID}" "${UNLOADED}"
