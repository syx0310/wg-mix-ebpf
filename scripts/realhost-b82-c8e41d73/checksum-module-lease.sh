#!/usr/bin/env bash
# Source-only shared ownership contract for the c8e41d73 checksum module.
# Callers provide audited command/write/fail callbacks and hold the returned
# flock file descriptor until their process has completed restoration.

readonly C8_CHECKSUM_MODULE_RUN_ID='c8e41d73'
readonly C8_CHECKSUM_MODULE_NAME='wg_mix_faketcp_checksum'
readonly C8_CHECKSUM_MODULE_PARAMETER='lease_id'
readonly C8_CHECKSUM_MODULE_STAGE_ROOT='/run/wg-mix-ebpf-source-stages/c8e41d73'
readonly C8_CHECKSUM_MODULE_LOCK="${C8_CHECKSUM_MODULE_STAGE_ROOT}/checksum-module-lease.v1.lock"
readonly C8_CHECKSUM_MODULE_CENTRAL_OBJECT="${C8_CHECKSUM_MODULE_STAGE_ROOT}/source/build/faketcp_checksum_kmod/${C8_CHECKSUM_MODULE_NAME}.ko"
readonly C8_CHECKSUM_MODULE_CENTRAL_RESOURCE_ID='6bd913ac'
readonly C8_CHECKSUM_MODULE_ROUTED_RESOURCE_ID='5b8d30f1'
readonly C8_CHECKSUM_MODULE_STANDALONE_ROOT='/run/wg-mix-ebpf-source-stages/a19f7c2e'
readonly C8_CHECKSUM_MODULE_STANDALONE_RESOURCE_ID='d34b8e65'
readonly C8_CHECKSUM_MODULE_STANDALONE_OBJECT="${C8_CHECKSUM_MODULE_STANDALONE_ROOT}/source/build/faketcp_checksum_kmod/${C8_CHECKSUM_MODULE_NAME}.ko"
readonly C8_CHECKSUM_MODULE_STANDALONE_EVIDENCE="${C8_CHECKSUM_MODULE_STANDALONE_ROOT}/veth-evidence-${C8_CHECKSUM_MODULE_STANDALONE_RESOURCE_ID}"
readonly C8_CHECKSUM_MODULE_FRESH_ROOT='/run/wg-mix-ebpf-faketcp-verifier/fresh-c8e41d73'
readonly C8_CHECKSUM_MODULE_FRESH_RESOURCE_ID='f3e5c8a1'
readonly C8_CHECKSUM_MODULE_FRESH_OBJECT="${C8_CHECKSUM_MODULE_FRESH_ROOT}/source/build/faketcp_checksum_kmod/${C8_CHECKSUM_MODULE_NAME}.ko"
readonly C8_CHECKSUM_MODULE_FRESH_EVIDENCE="${C8_CHECKSUM_MODULE_FRESH_ROOT}/evidence"
readonly C8_CHECKSUM_MODULE_SYSFS="/sys/module/${C8_CHECKSUM_MODULE_NAME}"
readonly C8_CHECKSUM_MODULE_BTF="/sys/kernel/btf/${C8_CHECKSUM_MODULE_NAME}"

C8_CHECKSUM_MODULE_LOCK_FD=''
C8_CHECKSUM_MODULE_LOCK_IDENTITY=''
C8_CHECKSUM_MODULE_RESOURCE_ID=''
C8_CHECKSUM_MODULE_COMMIT=''
C8_CHECKSUM_MODULE_BOOT_ID=''
C8_CHECKSUM_MODULE_EVIDENCE_ROOT=''
C8_CHECKSUM_MODULE_OBJECT=''
C8_CHECKSUM_MODULE_OBJECT_SHA256=''
C8_CHECKSUM_MODULE_SRCVERSION=''
C8_CHECKSUM_MODULE_LEASE_ID=''
C8_CHECKSUM_MODULE_INTENT=''
C8_CHECKSUM_MODULE_OWNED=''
C8_CHECKSUM_MODULE_UNLOADED=''
C8_CHECKSUM_MODULE_LIVE_SYSFS=''
C8_CHECKSUM_MODULE_LIVE_PARAMETER=''
C8_CHECKSUM_MODULE_LIVE_SRCVERSION=''
C8_CHECKSUM_MODULE_LIVE_BTF=''
C8_CHECKSUM_MODULE_LIVE_BTF_SHA256=''

c8_checksum_module_valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ && ! "$1" =~ ^0{64}$ && ! "$1" =~ ^f{64}$ ]]
}

c8_checksum_module_sha_file() {
  local line
  line="$(/usr/bin/sha256sum -- "$1")" || return $?
  line="${line%% *}"
  c8_checksum_module_valid_sha256 "${line}" || return 65
  printf '%s\n' "${line}"
}

c8_checksum_module_sha_text() {
  local line
  line="$(printf '%s\n' "$1" | /usr/bin/sha256sum)" || return $?
  line="${line%% *}"
  c8_checksum_module_valid_sha256 "${line}" || return 65
  printf '%s\n' "${line}"
}

c8_checksum_module_stop() {
  local reason="$1" rc="${2:-79}"
  if [[ "$(type -t c8_checksum_module_fail)" == function ]]; then
    c8_checksum_module_fail "${reason}" "${rc}"
    return $?
  fi
  printf 'C8_CHECKSUM_MODULE_STOP reason=%s rc=%s\n' "${reason}" "${rc}" >&2
  return "${rc}"
}

c8_checksum_module_require_callbacks() {
  [[ "$(type -t c8_checksum_module_run)" == function &&
    "$(type -t c8_checksum_module_write)" == function &&
    "$(type -t c8_checksum_module_fail)" == function ]]
}

c8_checksum_module_require_root_regular() {
  local path="$1" mode="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || return 79
  [[ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${path}")" == "0:0:${mode}:1:regular file" ]]
}

c8_checksum_module_scope_allowed() {
  local object="$1" evidence_root="$2" resource_id="$3"
  case "${resource_id}" in
    "${C8_CHECKSUM_MODULE_CENTRAL_RESOURCE_ID}")
      [[ "${object}" == "${C8_CHECKSUM_MODULE_CENTRAL_OBJECT}" &&
        "${evidence_root}" == "${C8_CHECKSUM_MODULE_STAGE_ROOT}/realhost-v6-${resource_id}" ]]
      ;;
    "${C8_CHECKSUM_MODULE_ROUTED_RESOURCE_ID}")
      [[ "${object}" == "${C8_CHECKSUM_MODULE_CENTRAL_OBJECT}" &&
        "${evidence_root}" == "${C8_CHECKSUM_MODULE_STAGE_ROOT}/routed-evidence-${resource_id}" ]]
      ;;
    "${C8_CHECKSUM_MODULE_STANDALONE_RESOURCE_ID}")
      [[ "${object}" == "${C8_CHECKSUM_MODULE_STANDALONE_OBJECT}" &&
        "${evidence_root}" == "${C8_CHECKSUM_MODULE_STANDALONE_EVIDENCE}" ]]
      ;;
    "${C8_CHECKSUM_MODULE_FRESH_RESOURCE_ID}")
      [[ "${object}" == "${C8_CHECKSUM_MODULE_FRESH_OBJECT}" &&
        "${evidence_root}" == "${C8_CHECKSUM_MODULE_FRESH_EVIDENCE}" ]]
      ;;
    *) return 65 ;;
  esac
}

c8_checksum_module_require_evidence_root() {
  local shape
  c8_checksum_module_scope_allowed "${C8_CHECKSUM_MODULE_OBJECT}" \
    "${C8_CHECKSUM_MODULE_EVIDENCE_ROOT}" "${C8_CHECKSUM_MODULE_RESOURCE_ID}" || return $?
  [[ -d "${C8_CHECKSUM_MODULE_EVIDENCE_ROOT}" &&
    ! -L "${C8_CHECKSUM_MODULE_EVIDENCE_ROOT}" ]] || return 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${C8_CHECKSUM_MODULE_EVIDENCE_ROOT}")" || return $?
  [[ "${shape}" == '0:0:700:directory' ]]
}

c8_checksum_module_configure() {
  local run_id="$1" resource_id="$2" commit="$3" boot_id="$4"
  local evidence_root="$5" object="$6" object_sha256="$7" actual_sha srcversion object_shape
  c8_checksum_module_require_callbacks || return 79
  [[ "${run_id}" == "${C8_CHECKSUM_MODULE_RUN_ID}" &&
    "${resource_id}" =~ ^[0-9a-f]{8}$ &&
    "${commit}" =~ ^[0-9a-f]{40}$ &&
    ! "${commit}" =~ ^0{40}$ && ! "${commit}" =~ ^f{40}$ &&
    "${boot_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 65
  c8_checksum_module_scope_allowed "${object}" "${evidence_root}" "${resource_id}" || return $?
  c8_checksum_module_valid_sha256 "${object_sha256}" || return 65

  C8_CHECKSUM_MODULE_RESOURCE_ID="${resource_id}"
  C8_CHECKSUM_MODULE_COMMIT="${commit}"
  C8_CHECKSUM_MODULE_BOOT_ID="${boot_id}"
  C8_CHECKSUM_MODULE_EVIDENCE_ROOT="${evidence_root}"
  C8_CHECKSUM_MODULE_OBJECT="${object}"
  C8_CHECKSUM_MODULE_OBJECT_SHA256="${object_sha256}"
  C8_CHECKSUM_MODULE_LEASE_ID="${run_id}-${resource_id}"
  C8_CHECKSUM_MODULE_INTENT="${evidence_root}/checksum-module-intent.v1"
  C8_CHECKSUM_MODULE_OWNED="${evidence_root}/checksum-module-owned.v1"
  C8_CHECKSUM_MODULE_UNLOADED="${evidence_root}/checksum-module-unloaded.v1"

  c8_checksum_module_require_evidence_root || return $?
  [[ -f "${object}" && ! -L "${object}" ]] || return 79
  object_shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${object}")" || return $?
  [[ "${object_shape}" == '0:0:600:1:regular file' ||
    "${object_shape}" == '0:0:644:1:regular file' ]] || return 79
  actual_sha="$(c8_checksum_module_sha_file "${object}")" || return $?
  [[ "${actual_sha}" == "${object_sha256}" ]] || return 79
  srcversion="$(/usr/sbin/modinfo -F srcversion -- "${object}")" || return $?
  srcversion="${srcversion^^}"
  [[ "${srcversion}" =~ ^[0-9A-F]{8,64}$ ]] || return 79
  C8_CHECKSUM_MODULE_SRCVERSION="${srcversion}"
}

c8_checksum_module_acquire() {
  local label="$1" shape rc
  c8_checksum_module_require_callbacks || c8_checksum_module_stop 'callbacks' 79 || return $?
  c8_checksum_module_require_root_regular "${C8_CHECKSUM_MODULE_LOCK}" 600 ||
    c8_checksum_module_stop 'lock-shape' 79 || return $?
  exec {C8_CHECKSUM_MODULE_LOCK_FD}<>"${C8_CHECKSUM_MODULE_LOCK}" ||
    c8_checksum_module_stop 'lock-open' 75 || return $?
  c8_checksum_module_run "${label}" "${C8_CHECKSUM_MODULE_LOCK}" \
    /usr/bin/flock --exclusive --nonblock "${C8_CHECKSUM_MODULE_LOCK_FD}"
  rc=$?
  ((rc == 0)) || c8_checksum_module_stop 'lock-busy' "${rc}" || return $?
  shape="$(/usr/bin/stat -Lc '%d:%i' -- "/proc/self/fd/${C8_CHECKSUM_MODULE_LOCK_FD}")" ||
    c8_checksum_module_stop 'lock-fd-stat' 79 || return $?
  C8_CHECKSUM_MODULE_LOCK_IDENTITY="$(/usr/bin/stat -Lc '%d:%i' -- "${C8_CHECKSUM_MODULE_LOCK}")" ||
    c8_checksum_module_stop 'lock-path-stat' 79 || return $?
  [[ "${shape}" == "${C8_CHECKSUM_MODULE_LOCK_IDENTITY}" ]] ||
    c8_checksum_module_stop 'lock-identity' 79 || return $?
}

c8_checksum_module_require_lock() {
  local fd_shape path_shape
  [[ "${C8_CHECKSUM_MODULE_LOCK_FD}" =~ ^[1-9][0-9]*$ ]] || return 79
  fd_shape="$(/usr/bin/stat -Lc '%d:%i' -- "/proc/self/fd/${C8_CHECKSUM_MODULE_LOCK_FD}")" || return $?
  path_shape="$(/usr/bin/stat -Lc '%d:%i' -- "${C8_CHECKSUM_MODULE_LOCK}")" || return $?
  [[ "${fd_shape}" == "${C8_CHECKSUM_MODULE_LOCK_IDENTITY}" && "${path_shape}" == "${fd_shape}" ]] || return 79
  /usr/bin/flock --exclusive --nonblock "${C8_CHECKSUM_MODULE_LOCK_FD}"
}

c8_checksum_module_render_intent() {
  printf '%s\n' \
    'format=wg-mix-ebpf-c8-checksum-module-intent-v1' \
    "run_id=${C8_CHECKSUM_MODULE_RUN_ID}" \
    "resource_id=${C8_CHECKSUM_MODULE_RESOURCE_ID}" \
    "boot_id=${C8_CHECKSUM_MODULE_BOOT_ID}" \
    "commit=${C8_CHECKSUM_MODULE_COMMIT}" \
    "module=${C8_CHECKSUM_MODULE_NAME}" \
    "ko_sha256=${C8_CHECKSUM_MODULE_OBJECT_SHA256}" \
    "srcversion=${C8_CHECKSUM_MODULE_SRCVERSION}" \
    "lease_id=${C8_CHECKSUM_MODULE_LEASE_ID}" \
    "lock=${C8_CHECKSUM_MODULE_LOCK},identity=${C8_CHECKSUM_MODULE_LOCK_IDENTITY}" \
    "btf=${C8_CHECKSUM_MODULE_BTF},required=1" \
    'ownership=exact-insmod-rc0-only' 'state=prepared'
}

c8_checksum_module_render_owned() {
  local intent_sha
  intent_sha="$(c8_checksum_module_sha_file "${C8_CHECKSUM_MODULE_INTENT}")" || return $?
  printf '%s\n' \
    'format=wg-mix-ebpf-c8-checksum-module-owned-v1' \
    "run_id=${C8_CHECKSUM_MODULE_RUN_ID}" \
    "resource_id=${C8_CHECKSUM_MODULE_RESOURCE_ID}" \
    "boot_id=${C8_CHECKSUM_MODULE_BOOT_ID}" \
    "commit=${C8_CHECKSUM_MODULE_COMMIT}" \
    "module=${C8_CHECKSUM_MODULE_NAME}" \
    "ko_sha256=${C8_CHECKSUM_MODULE_OBJECT_SHA256}" \
    "srcversion=${C8_CHECKSUM_MODULE_SRCVERSION}" \
    "lease_id=${C8_CHECKSUM_MODULE_LEASE_ID}" \
    "intent_sha256=${intent_sha}" \
    "sysfs_generation=${C8_CHECKSUM_MODULE_LIVE_SYSFS}" \
    "parameter_generation=${C8_CHECKSUM_MODULE_LIVE_PARAMETER}" \
    "btf_generation=${C8_CHECKSUM_MODULE_LIVE_BTF}" \
    "btf_sha256=${C8_CHECKSUM_MODULE_LIVE_BTF_SHA256}" \
    'ownership=exact-insmod-rc0' 'state=owned'
}

c8_checksum_module_render_unloaded() {
  local reason="$1" owned_sha="$2" generation_sha="$3" intent_sha
  intent_sha="$(c8_checksum_module_sha_file "${C8_CHECKSUM_MODULE_INTENT}")" || return $?
  printf '%s\n' \
    'format=wg-mix-ebpf-c8-checksum-module-unloaded-v1' \
    "run_id=${C8_CHECKSUM_MODULE_RUN_ID}" \
    "resource_id=${C8_CHECKSUM_MODULE_RESOURCE_ID}" \
    "boot_id=${C8_CHECKSUM_MODULE_BOOT_ID}" \
    "commit=${C8_CHECKSUM_MODULE_COMMIT}" \
    "module=${C8_CHECKSUM_MODULE_NAME}" \
    "lease_id=${C8_CHECKSUM_MODULE_LEASE_ID}" \
    "intent_sha256=${intent_sha}" \
    "owned_receipt_sha256=${owned_sha}" \
    "generation_sha256=${generation_sha}" \
    "reason=${reason}" 'state=unloaded'
}

c8_checksum_module_phase_matches() {
  local path="$1" expected="$2"
  c8_checksum_module_require_root_regular "${path}" 600 || return 79
  [[ "$(/usr/bin/cat -- "${path}")" == "${expected}" ]]
}

c8_checksum_module_live_present() {
  [[ -d "${C8_CHECKSUM_MODULE_SYSFS}" ]]
}

c8_checksum_module_read_live() {
  local lease mode srcversion
  c8_checksum_module_live_present || return 1
  [[ -f "${C8_CHECKSUM_MODULE_SYSFS}/parameters/${C8_CHECKSUM_MODULE_PARAMETER}" &&
    -f "${C8_CHECKSUM_MODULE_SYSFS}/srcversion" &&
    -f "${C8_CHECKSUM_MODULE_BTF}" ]] || return 79
  mode="$(/usr/bin/stat -Lc '%a:%F' -- "${C8_CHECKSUM_MODULE_SYSFS}/parameters/${C8_CHECKSUM_MODULE_PARAMETER}")" || return $?
  [[ "${mode}" == '444:regular file' ]] || return 79
  lease="$(/usr/bin/cat -- "${C8_CHECKSUM_MODULE_SYSFS}/parameters/${C8_CHECKSUM_MODULE_PARAMETER}")" || return $?
  srcversion="$(/usr/bin/cat -- "${C8_CHECKSUM_MODULE_SYSFS}/srcversion")" || return $?
  srcversion="${srcversion^^}"
  [[ "${lease}" == "${C8_CHECKSUM_MODULE_LEASE_ID}" &&
    "${srcversion}" == "${C8_CHECKSUM_MODULE_SRCVERSION}" ]] || return 79
  C8_CHECKSUM_MODULE_LIVE_SYSFS="$(/usr/bin/stat -Lc '%d:%i' -- "${C8_CHECKSUM_MODULE_SYSFS}")" || return $?
  C8_CHECKSUM_MODULE_LIVE_PARAMETER="$(/usr/bin/stat -Lc '%d:%i' -- "${C8_CHECKSUM_MODULE_SYSFS}/parameters/${C8_CHECKSUM_MODULE_PARAMETER}")" || return $?
  C8_CHECKSUM_MODULE_LIVE_SRCVERSION="${srcversion}"
  C8_CHECKSUM_MODULE_LIVE_BTF="$(/usr/bin/stat -Lc '%d:%i' -- "${C8_CHECKSUM_MODULE_BTF}")" || return $?
  C8_CHECKSUM_MODULE_LIVE_BTF_SHA256="$(c8_checksum_module_sha_file "${C8_CHECKSUM_MODULE_BTF}")" || return $?
}

c8_checksum_module_live_binding() {
  printf 'sysfs=%s;parameter=%s;srcversion=%s;btf=%s;btf_sha256=%s;lease_id=%s\n' \
    "${C8_CHECKSUM_MODULE_LIVE_SYSFS}" "${C8_CHECKSUM_MODULE_LIVE_PARAMETER}" \
    "${C8_CHECKSUM_MODULE_LIVE_SRCVERSION}" "${C8_CHECKSUM_MODULE_LIVE_BTF}" \
    "${C8_CHECKSUM_MODULE_LIVE_BTF_SHA256}" "${C8_CHECKSUM_MODULE_LEASE_ID}"
}

c8_checksum_module_validate_owned_receipt() {
  local -a lines=()
  c8_checksum_module_require_root_regular "${C8_CHECKSUM_MODULE_OWNED}" 600 || return 79
  mapfile -t lines <"${C8_CHECKSUM_MODULE_OWNED}" || return $?
  ((${#lines[@]} == 16)) || return 79
  [[ "${lines[0]}" == 'format=wg-mix-ebpf-c8-checksum-module-owned-v1' &&
    "${lines[1]}" == "run_id=${C8_CHECKSUM_MODULE_RUN_ID}" &&
    "${lines[2]}" == "resource_id=${C8_CHECKSUM_MODULE_RESOURCE_ID}" &&
    "${lines[3]}" == "boot_id=${C8_CHECKSUM_MODULE_BOOT_ID}" &&
    "${lines[4]}" == "commit=${C8_CHECKSUM_MODULE_COMMIT}" &&
    "${lines[5]}" == "module=${C8_CHECKSUM_MODULE_NAME}" &&
    "${lines[6]}" == "ko_sha256=${C8_CHECKSUM_MODULE_OBJECT_SHA256}" &&
    "${lines[7]}" == "srcversion=${C8_CHECKSUM_MODULE_SRCVERSION}" &&
    "${lines[8]}" == "lease_id=${C8_CHECKSUM_MODULE_LEASE_ID}" &&
    "${lines[9]}" =~ ^intent_sha256=[0-9a-f]{64}$ &&
    "${lines[10]}" =~ ^sysfs_generation=[0-9]+:[0-9]+$ &&
    "${lines[11]}" =~ ^parameter_generation=[0-9]+:[0-9]+$ &&
    "${lines[12]}" =~ ^btf_generation=[0-9]+:[0-9]+$ &&
    "${lines[13]}" =~ ^btf_sha256=[0-9a-f]{64}$ &&
    "${lines[14]}" == 'ownership=exact-insmod-rc0' && "${lines[15]}" == 'state=owned' ]] || return 79
  [[ "${lines[9]#*=}" == "$(c8_checksum_module_sha_file "${C8_CHECKSUM_MODULE_INTENT}")" ]]
}

c8_checksum_module_validate_unloaded_receipt() {
  local -a lines=()
  c8_checksum_module_require_root_regular "${C8_CHECKSUM_MODULE_UNLOADED}" 600 || return 79
  mapfile -t lines <"${C8_CHECKSUM_MODULE_UNLOADED}" || return $?
  ((${#lines[@]} == 12)) || return 79
  [[ "${lines[0]}" == 'format=wg-mix-ebpf-c8-checksum-module-unloaded-v1' &&
    "${lines[1]}" == "run_id=${C8_CHECKSUM_MODULE_RUN_ID}" &&
    "${lines[2]}" == "resource_id=${C8_CHECKSUM_MODULE_RESOURCE_ID}" &&
    "${lines[3]}" == "boot_id=${C8_CHECKSUM_MODULE_BOOT_ID}" &&
    "${lines[4]}" == "commit=${C8_CHECKSUM_MODULE_COMMIT}" &&
    "${lines[5]}" == "module=${C8_CHECKSUM_MODULE_NAME}" &&
    "${lines[6]}" == "lease_id=${C8_CHECKSUM_MODULE_LEASE_ID}" &&
    "${lines[7]}" =~ ^intent_sha256=[0-9a-f]{64}$ &&
    ("${lines[8]}" == 'owned_receipt_sha256=absent' || "${lines[8]}" =~ ^owned_receipt_sha256=[0-9a-f]{64}$) &&
    ("${lines[9]}" == 'generation_sha256=absent' || "${lines[9]}" =~ ^generation_sha256=[0-9a-f]{64}$) &&
    "${lines[10]}" =~ ^reason=(load-not-observed|recovered-unreceipted-live|owned-live-unloaded|owned-already-absent)$ &&
    "${lines[11]}" == 'state=unloaded' &&
    "${lines[7]#*=}" == "$(c8_checksum_module_sha_file "${C8_CHECKSUM_MODULE_INTENT}")" ]]
}

c8_checksum_module_classify() {
  local intent="$1" owned="$2" unloaded="$3" live="$4"
  [[ "${intent}${owned}${unloaded}${live}" =~ ^[01]{4}$ ]] || return 64
  case "${intent}${owned}${unloaded}${live}" in
    0000) printf '00-clean\n' ;;
    1000) printf '00-intent-no-live\n' ;;
    1001) printf '10-unreceipted-live\n' ;;
    1101) printf '11-owned-live\n' ;;
    1100) printf '01-owned-live-absent\n' ;;
    1010 | 1110) printf '00-restored\n' ;;
    *) return 79 ;;
  esac
}

c8_checksum_module_marker_flag() {
  if [[ -e "$1" || -L "$1" ]]; then printf '1\n'; else printf '0\n'; fi
}

c8_checksum_module_current_state() {
  local intent owned unloaded live=0
  intent="$(c8_checksum_module_marker_flag "${C8_CHECKSUM_MODULE_INTENT}")" || return $?
  owned="$(c8_checksum_module_marker_flag "${C8_CHECKSUM_MODULE_OWNED}")" || return $?
  unloaded="$(c8_checksum_module_marker_flag "${C8_CHECKSUM_MODULE_UNLOADED}")" || return $?
  if c8_checksum_module_live_present; then live=1; fi
  c8_checksum_module_classify "${intent}" "${owned}" "${unloaded}" "${live}"
}

c8_checksum_module_validate_restore_state() {
  local state expected
  state="$(c8_checksum_module_current_state)" || return $?
  case "${state}" in
    00-clean) ;;
    00-intent-no-live | 10-unreceipted-live | 11-owned-live | 01-owned-live-absent | 00-restored)
      expected="$(c8_checksum_module_render_intent)" || return $?
      c8_checksum_module_phase_matches "${C8_CHECKSUM_MODULE_INTENT}" "${expected}" || return 79
      ;;
    *) return 79 ;;
  esac
  case "${state}" in
    10-unreceipted-live) c8_checksum_module_read_live || return 79 ;;
    11-owned-live)
      c8_checksum_module_read_live || return 79
      expected="$(c8_checksum_module_render_owned)" || return $?
      c8_checksum_module_phase_matches "${C8_CHECKSUM_MODULE_OWNED}" "${expected}" || return 79
      ;;
    01-owned-live-absent) c8_checksum_module_validate_owned_receipt || return 79 ;;
    00-restored)
      if [[ -e "${C8_CHECKSUM_MODULE_OWNED}" || -L "${C8_CHECKSUM_MODULE_OWNED}" ]]; then
        c8_checksum_module_validate_owned_receipt || return 79
      fi
      c8_checksum_module_validate_unloaded_receipt || return 79
      ;;
  esac
  printf '%s\n' "${state}"
}

c8_checksum_module_load() {
  local prefix="$1" state expected rc
  c8_checksum_module_require_lock || c8_checksum_module_stop 'load-without-lock' 79 || return $?
  c8_checksum_module_require_evidence_root || c8_checksum_module_stop 'load-evidence-root' 79 || return $?
  state="$(c8_checksum_module_current_state)" || c8_checksum_module_stop 'load-state' 79 || return $?
  case "${state}" in
    11-owned-live)
      expected="$(c8_checksum_module_render_intent)" || c8_checksum_module_stop 'intent-render' 79 || return $?
      c8_checksum_module_phase_matches "${C8_CHECKSUM_MODULE_INTENT}" "${expected}" || c8_checksum_module_stop 'intent-drift' 79 || return $?
      c8_checksum_module_read_live || c8_checksum_module_stop 'owned-live-identity' 79 || return $?
      expected="$(c8_checksum_module_render_owned)" || c8_checksum_module_stop 'owned-render' 79 || return $?
      c8_checksum_module_phase_matches "${C8_CHECKSUM_MODULE_OWNED}" "${expected}" || c8_checksum_module_stop 'owned-drift' 79 || return $?
      return
      ;;
    00-clean) ;;
    *) c8_checksum_module_stop "load-requires-restore:${state}" 79; return $? ;;
  esac

  c8_checksum_module_run "${prefix}.pre" "${C8_CHECKSUM_MODULE_NAME}" \
    /usr/bin/test ! -e "${C8_CHECKSUM_MODULE_SYSFS}"
  rc=$?
  ((rc == 0)) || c8_checksum_module_stop 'module-preexists' "${rc}" || return $?
  expected="$(c8_checksum_module_render_intent)" || c8_checksum_module_stop 'intent-render' 79 || return $?
  c8_checksum_module_write "${C8_CHECKSUM_MODULE_INTENT}" "${expected}" ||
    c8_checksum_module_stop 'intent-write' $? || return $?
  c8_checksum_module_run "${prefix}.intent-baseline" "${C8_CHECKSUM_MODULE_NAME}" \
    /usr/bin/test ! -e "${C8_CHECKSUM_MODULE_SYSFS}"
  rc=$?
  ((rc == 0)) || c8_checksum_module_stop 'module-appeared-after-intent' "${rc}" || return $?
  c8_checksum_module_run "${prefix}.load" "${C8_CHECKSUM_MODULE_NAME}" \
    /usr/sbin/insmod "${C8_CHECKSUM_MODULE_OBJECT}" \
    "${C8_CHECKSUM_MODULE_PARAMETER}=${C8_CHECKSUM_MODULE_LEASE_ID}"
  rc=$?
  ((rc == 0)) || c8_checksum_module_stop 'insmod-not-owned' "${rc}" || return $?
  c8_checksum_module_read_live || c8_checksum_module_stop 'load-generation' 79 || return $?
  expected="$(c8_checksum_module_render_owned)" || c8_checksum_module_stop 'owned-render' 79 || return $?
  c8_checksum_module_write "${C8_CHECKSUM_MODULE_OWNED}" "${expected}" ||
    c8_checksum_module_stop 'owned-write' $? || return $?
}

c8_checksum_module_restore() {
  local prefix="$1" state expected before after refcount rc
  local owned_sha='absent' generation_sha='absent' reason
  c8_checksum_module_require_lock || c8_checksum_module_stop 'restore-without-lock' 79 || return $?
  c8_checksum_module_require_evidence_root || c8_checksum_module_stop 'restore-evidence-root' 79 || return $?
  state="$(c8_checksum_module_validate_restore_state)" || c8_checksum_module_stop 'restore-state' 79 || return $?
  case "${state}" in
    00-clean) return ;;
    00-restored) return ;;
    00-intent-no-live | 10-unreceipted-live | 11-owned-live | 01-owned-live-absent) ;;
    *) c8_checksum_module_stop "restore-invalid-state:${state}" 79; return $? ;;
  esac

  case "${state}" in
    00-intent-no-live) reason='load-not-observed' ;;
    01-owned-live-absent)
      c8_checksum_module_validate_owned_receipt || c8_checksum_module_stop 'restore-owned-receipt' 79 || return $?
      owned_sha="$(c8_checksum_module_sha_file "${C8_CHECKSUM_MODULE_OWNED}")" || c8_checksum_module_stop 'restore-owned-sha' 79 || return $?
      reason='owned-already-absent'
      ;;
    10-unreceipted-live | 11-owned-live)
      c8_checksum_module_read_live || c8_checksum_module_stop 'restore-live-identity' 79 || return $?
      before="$(c8_checksum_module_live_binding)" || c8_checksum_module_stop 'restore-live-binding' 79 || return $?
      if [[ "${state}" == '11-owned-live' ]]; then
        expected="$(c8_checksum_module_render_owned)" || c8_checksum_module_stop 'restore-owned-render' 79 || return $?
        c8_checksum_module_phase_matches "${C8_CHECKSUM_MODULE_OWNED}" "${expected}" || c8_checksum_module_stop 'restore-owned-drift' 79 || return $?
        owned_sha="$(c8_checksum_module_sha_file "${C8_CHECKSUM_MODULE_OWNED}")" || c8_checksum_module_stop 'restore-owned-sha' 79 || return $?
        reason='owned-live-unloaded'
      else
        reason='recovered-unreceipted-live'
      fi
      refcount="$(/usr/bin/awk -v name="${C8_CHECKSUM_MODULE_NAME}" '$1 == name {print $1 ":" $3}' /proc/modules)" ||
        c8_checksum_module_stop 'restore-refcount-read' 79 || return $?
      [[ "${refcount}" == "${C8_CHECKSUM_MODULE_NAME}:0" ]] || c8_checksum_module_stop 'restore-refcount' 79 || return $?
      c8_checksum_module_read_live || c8_checksum_module_stop 'restore-live-recheck' 79 || return $?
      after="$(c8_checksum_module_live_binding)" || c8_checksum_module_stop 'restore-live-rebinding' 79 || return $?
      [[ "${after}" == "${before}" ]] || c8_checksum_module_stop 'restore-generation-changed' 79 || return $?
      generation_sha="$(c8_checksum_module_sha_text "${before}")" || c8_checksum_module_stop 'restore-generation-sha' 79 || return $?
      c8_checksum_module_run "${prefix}.unload" "${C8_CHECKSUM_MODULE_NAME}" \
        /usr/sbin/rmmod "${C8_CHECKSUM_MODULE_NAME}"
      rc=$?
      ((rc == 0)) || c8_checksum_module_stop 'rmmod' "${rc}" || return $?
      if c8_checksum_module_live_present; then
        c8_checksum_module_stop 'module-remains' 79
        return $?
      fi
      ;;
  esac
  expected="$(c8_checksum_module_render_unloaded "${reason}" "${owned_sha}" "${generation_sha}")" ||
    c8_checksum_module_stop 'unloaded-render' 79 || return $?
  c8_checksum_module_write "${C8_CHECKSUM_MODULE_UNLOADED}" "${expected}" ||
    c8_checksum_module_stop 'unloaded-write' $? || return $?
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' 'checksum-module-lease.sh is a source-only library' >&2
  exit 64
fi
