#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly CONTROLLER_RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly GATE_ID='fresh-c8e41d73'
readonly EXPECTED_CONTROLLER_SOURCE="/run/wg-mix-ebpf-source-stages/${CONTROLLER_RUN_ID}/source"
readonly EXPECTED_MANIFEST="/run/wg-mix-ebpf-source-bootstrap-${CONTROLLER_RUN_ID}/package-manifest.v1"
readonly EXPECTED_BUNDLE="/run/wg-mix-ebpf-source-bootstrap-${CONTROLLER_RUN_ID}/source-${PACKAGE_ID}.bundle"
readonly STAGING_PREFIX='/run/wg-mix-ebpf-faketcp-verifier'
readonly STAGE_ROOT="${STAGING_PREFIX}/${GATE_ID}"
readonly INTAKE_ROOT="${STAGE_ROOT}/package"
readonly SNAPSHOT_MANIFEST="${INTAKE_ROOT}/package-manifest.v1"
readonly SNAPSHOT_BUNDLE="${INTAKE_ROOT}/source-${PACKAGE_ID}.bundle"
readonly SOURCE="${STAGE_ROOT}/source"
readonly EVIDENCE_ROOT="${STAGE_ROOT}/evidence"
readonly GO_CACHE="${STAGE_ROOT}/go-cache"
readonly GO_MOD_CACHE="${STAGE_ROOT}/go-mod-cache"
readonly GO_PATH="${STAGE_ROOT}/go-path"
readonly GO_TMP="${STAGE_ROOT}/go-tmp"
readonly GO_HOME="${STAGE_ROOT}/go-home"
readonly XDG_CACHE="${STAGE_ROOT}/xdg-cache"
readonly XDG_CONFIG="${STAGE_ROOT}/xdg-config"
readonly AUDIT_LOG="${EVIDENCE_ROOT}/audit.log"
readonly OWNER_PHASE="${EVIDENCE_ROOT}/phase-owner.v1"
readonly HOST_PHASE="${EVIDENCE_ROOT}/phase-host.v1"
readonly BPF_BASELINE_PHASE="${EVIDENCE_ROOT}/phase-bpf-baseline.v1"
readonly BUILD_PHASE="${EVIDENCE_ROOT}/phase-build.v1"
readonly HISTORY_PHASE="${EVIDENCE_ROOT}/phase-history.v1"
readonly VERIFIER_PHASE="${EVIDENCE_ROOT}/phase-verifier.v1"
readonly TEST_RUN_PHASE="${EVIDENCE_ROOT}/phase-test-run.v1"
readonly COMPLETE_PHASE="${EVIDENCE_ROOT}/phase-complete.v1"
readonly RESTORE_INTENT_PHASE="${EVIDENCE_ROOT}/phase-restore-intent.v1"
readonly RESTORED_PHASE="${EVIDENCE_ROOT}/phase-restored.v1"
readonly FILESYSTEM_PHASE="${EVIDENCE_ROOT}/phase-filesystem-retained.v1"
readonly HISTORY_OBJECTS="${EVIDENCE_ROOT}/S4.objects.out"
readonly HISTORY_ROOTS="${EVIDENCE_ROOT}/S4.roots.out"
readonly BASELINE_OBJECT="${SOURCE}/build/wg_mix_tc.o"
readonly EXPERIMENTAL_OBJECT="${SOURCE}/build/wg_mix_faketcp_experimental.o"
readonly BINARY="${SOURCE}/bin/wg-mix-ebpf"
readonly LAUNCHER="${SOURCE}/bin/faketcp-verifier-launcher-linux-amd64"
readonly RUNNER="${SOURCE}/scripts/run-faketcp-verifier-only.py"
readonly MODULE_NAME='wg_mix_faketcp_checksum'
readonly MODULE_OBJECT="${SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
readonly MODULE_RESOURCE_ID='f3e5c8a1'
readonly MODULE_LEASE_ID="${CONTROLLER_RUN_ID}-${MODULE_RESOURCE_ID}"
readonly MODULE_LEASE_LOCK="/run/wg-mix-ebpf-source-stages/${CONTROLLER_RUN_ID}/checksum-module-lease.v1.lock"
readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-${CONTROLLER_RUN_ID}/checksum-module-lease.sh"
readonly MODULE_LEASE_HELPER="${EXPECTED_CONTROLLER_SOURCE}/${MODULE_LEASE_HELPER_RELATIVE}"
readonly MODULE_INTENT="${EVIDENCE_ROOT}/checksum-module-intent.v1"
readonly MODULE_OWNED="${EVIDENCE_ROOT}/checksum-module-owned.v1"
readonly MODULE_UNLOADED="${EVIDENCE_ROOT}/checksum-module-unloaded.v1"
readonly RESERVED_PIN="/sys/fs/bpf/wg-mix-ebpf-${GATE_ID}"
readonly SELF_FROM_SOURCE="scripts/realhost-b82-${CONTROLLER_RUN_ID}/root-fresh-verifier-gate.sh"
readonly EXPECTED_HOSTNAME='ubuntu-2604-test'
readonly EXPECTED_KERNEL='7.0.0-28-generic'
readonly EXPECTED_MACHINE_ID='9db3fb717cc74974b2a6b243d67f67b9'
readonly STATE_SCHEMA='owner,host,bpf-baseline,history,build,module-lease,verifier,test-run,complete,restore-intent,restored,filesystem-retained'

readonly -a GIT_ENV=(
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0
  /usr/bin/git --no-pager --no-replace-objects
  -c core.attributesFile=/dev/null -c core.fsmonitor=false
  -c core.hooksPath=/dev/null
)
readonly -a GO_ENV=(
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
  CGO_ENABLED=0 GO=/usr/bin/go CLANG=/usr/bin/clang
  GOCACHE="${GO_CACHE}" GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}"
  GOTMPDIR="${GO_TMP}" TMPDIR="${GO_TMP}"
  HOME="${GO_HOME}" XDG_CACHE_HOME="${XDG_CACHE}" XDG_CONFIG_HOME="${XDG_CONFIG}"
  GOENV=off GOFLAGS= GOWORK=off GO111MODULE=on GOTOOLCHAIN=local
  GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOVCS=off GOTELEMETRY=off
)

MODE=''
CONTROLLER_SOURCE=''
COMMIT=''
MANIFEST=''
MANIFEST_SHA256=''
BUNDLE=''
BUNDLE_SHA256=''
INTEGRATION_REF=''
HISTORY_VERIFICATION=''
HISTORY_COMMIT_COUNT=''
HISTORY_ROOTS_SHA256=''
HISTORY_OBJECTS_SHA256=''
FORMAT=''
MANIFEST_RUN_ID=''
MANIFEST_PACKAGE_ID=''
MANIFEST_COMMIT=''
BUNDLE_NAME=''
MANIFEST_BUNDLE_SHA256=''
MANIFEST_REMOTE_SOURCE=''
MANIFEST_TARGET_HOST=''
MANIFEST_TARGET_HOSTNAME=''
MANIFEST_TARGET_KERNEL=''
MANIFEST_TARGET_MACHINE_ID=''
MANIFEST_MODULE_LEASE_HELPER_PATH=''
MANIFEST_MODULE_LEASE_HELPER_BLOB=''
MANIFEST_MODULE_LEASE_HELPER_SHA256=''
MANIFEST_ROOT_FRESH_PATH=''
MANIFEST_ROOT_FRESH_BLOB=''
MANIFEST_ROOT_FRESH_SHA256=''
MANIFEST_FD=''
BUNDLE_FD=''
MANIFEST_FILE_IDENTITY=''
BUNDLE_FILE_IDENTITY=''
SNAPSHOT_MANIFEST_IDENTITY=''
SNAPSHOT_BUNDLE_IDENTITY=''
BOOT_ID=''
INITIAL_NETNS=''
SELF_SHA256=''
SELF_BLOB=''
MODULE_LEASE_HELPER_SHA256=''
MODULE_LEASE_HELPER_BLOB=''
BASELINE_SHA256=''
EXPERIMENTAL_SHA256=''
BINARY_SHA256=''
LAUNCHER_SHA256=''
RUNNER_SHA256=''
MODULE_SHA256=''
MODULE_SRCVERSION=''
VMLINUX_BTF_SHA256=''
BPFFS_IDENTITY=''
STEP_RC=125
STEP_LOG=''
CONVERGENCE_OUTPUT=''
OP_TARGET=''
declare -a OP_ARGV=()
declare -a BOOTSTRAP_AUDIT=()

usage() {
  printf '%s\n' \
    "usage: $0 {plan|run|restore}" \
    "  --controller-source ${EXPECTED_CONTROLLER_SOURCE}" \
    '  --commit 40-lowercase-hex' \
    "  --manifest ${EXPECTED_MANIFEST} --manifest-sha256 64-lowercase-hex" \
    "  --bundle ${EXPECTED_BUNDLE} --bundle-sha256 64-lowercase-hex" >&2
}

fail() {
  printf 'B82_FRESH_VERIFIER_STOP mode=%s gate_id=%s reason=%s rc=%s evidence=%s; no automatic cleanup\n' \
    "${MODE:-unparsed}" "${GATE_ID}" "$1" "${2:-125}" "${EVIDENCE_ROOT}" >&2
  exit "${2:-125}"
}

valid_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ && ! "$1" =~ ^0{40}$ && ! "$1" =~ ^f{40}$ ]]
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ && ! "$1" =~ ^0{64}$ && ! "$1" =~ ^f{64}$ ]]
}

parse_arguments() {
  (($# == 13)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in plan | run | restore) ;; *) usage; return 64 ;; esac
  [[ "$1" == '--controller-source' && "$3" == '--commit' &&
    "$5" == '--manifest' && "$7" == '--manifest-sha256' &&
    "$9" == '--bundle' && "${11}" == '--bundle-sha256' ]] || return 64
  CONTROLLER_SOURCE="$2"
  COMMIT="$4"
  MANIFEST="$6"
  MANIFEST_SHA256="$8"
  BUNDLE="${10}"
  BUNDLE_SHA256="${12}"
  [[ "${CONTROLLER_SOURCE}" == "${EXPECTED_CONTROLLER_SOURCE}" &&
    "${MANIFEST}" == "${EXPECTED_MANIFEST}" &&
    "${BUNDLE}" == "${EXPECTED_BUNDLE}" ]] || return 65
  valid_commit "${COMMIT}" && valid_sha256 "${MANIFEST_SHA256}" &&
    valid_sha256 "${BUNDLE_SHA256}"
}

quote_argv() { printf '%q ' "$@"; }

utc_now() { /bin/date -u '+%Y-%m-%dT%H:%M:%SZ'; }

sha256_file() {
  local line
  line="$(/usr/bin/sha256sum -- "$1")" || return $?
  line="${line%% *}"
  valid_sha256 "${line}" || return 65
  printf '%s\n' "${line}"
}

read_manifest_field() {
  local expected="$1" destination="$2" key value extra
  IFS=$'\t' read -r -u "${MANIFEST_FD}" key value extra || return 65
  [[ "${key}" == "${expected}" && -n "${value}" && -z "${extra}" &&
    "${value}" != *$'\t'* && "${value}" != *$'\n'* ]] || return 65
  [[ "${destination}" == discard ]] || printf -v "${destination}" '%s' "${value}"
}

load_manifest_once() {
  local unexpected
  exec {MANIFEST_FD}<"${SNAPSHOT_MANIFEST}" || return 66
  read_manifest_field format FORMAT &&
    read_manifest_field run_id MANIFEST_RUN_ID &&
    read_manifest_field package_id MANIFEST_PACKAGE_ID &&
    read_manifest_field integration_ref INTEGRATION_REF &&
    read_manifest_field integration_commit MANIFEST_COMMIT &&
    read_manifest_field bundle_name BUNDLE_NAME &&
    read_manifest_field bundle_sha256 MANIFEST_BUNDLE_SHA256 &&
    read_manifest_field history_verification HISTORY_VERIFICATION &&
    read_manifest_field history_commit_count HISTORY_COMMIT_COUNT &&
    read_manifest_field history_roots_sha256 HISTORY_ROOTS_SHA256 &&
    read_manifest_field history_objects_sha256 HISTORY_OBJECTS_SHA256 &&
    read_manifest_field wg_state discard &&
    read_manifest_field wg_interface discard &&
    read_manifest_field wg_local_address discard &&
    read_manifest_field wg_peer_address discard &&
    read_manifest_field local_repository discard &&
    read_manifest_field local_package_dir discard &&
    read_manifest_field remote_package_dir discard &&
    read_manifest_field remote_source MANIFEST_REMOTE_SOURCE &&
    read_manifest_field target_user discard &&
    read_manifest_field target_host MANIFEST_TARGET_HOST &&
    read_manifest_field target_hostname MANIFEST_TARGET_HOSTNAME &&
    read_manifest_field target_kernel MANIFEST_TARGET_KERNEL &&
    read_manifest_field target_machine_id MANIFEST_TARGET_MACHINE_ID &&
    read_manifest_field target_interface discard &&
    read_manifest_field peer_address discard &&
    read_manifest_field peer_port discard &&
    read_manifest_field soak_seconds discard &&
    read_manifest_field session_seconds discard &&
    read_manifest_field bind_final_package_sh_path discard &&
    read_manifest_field bind_final_package_sh_blob discard &&
    read_manifest_field bind_final_package_sh_sha256 discard &&
    read_manifest_field controller_sh_path discard &&
    read_manifest_field controller_sh_blob discard &&
    read_manifest_field controller_sh_sha256 discard &&
    read_manifest_field locked_transport_exp_path discard &&
    read_manifest_field locked_transport_exp_blob discard &&
    read_manifest_field locked_transport_exp_sha256 discard &&
    read_manifest_field root_matrix_n_r_sh_path discard &&
    read_manifest_field root_matrix_n_r_sh_blob discard &&
    read_manifest_field root_matrix_n_r_sh_sha256 discard &&
    read_manifest_field check_realhost_iperf_py_path discard &&
    read_manifest_field check_realhost_iperf_py_blob discard &&
    read_manifest_field check_realhost_iperf_py_sha256 discard &&
    read_manifest_field test_hermetic_matrix_sh_path discard &&
    read_manifest_field test_hermetic_matrix_sh_blob discard &&
    read_manifest_field test_hermetic_matrix_sh_sha256 discard &&
    read_manifest_field test_matrix_static_py_path discard &&
    read_manifest_field test_matrix_static_py_blob discard &&
    read_manifest_field test_matrix_static_py_sha256 discard &&
    read_manifest_field checksum_module_lease_sh_path MANIFEST_MODULE_LEASE_HELPER_PATH &&
    read_manifest_field checksum_module_lease_sh_blob MANIFEST_MODULE_LEASE_HELPER_BLOB &&
    read_manifest_field checksum_module_lease_sh_sha256 MANIFEST_MODULE_LEASE_HELPER_SHA256 &&
    read_manifest_field root_fresh_verifier_gate_sh_path MANIFEST_ROOT_FRESH_PATH &&
    read_manifest_field root_fresh_verifier_gate_sh_blob MANIFEST_ROOT_FRESH_BLOB &&
    read_manifest_field root_fresh_verifier_gate_sh_sha256 MANIFEST_ROOT_FRESH_SHA256 &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_path discard &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_blob discard &&
    read_manifest_field test_hermetic_fresh_verifier_gate_sh_sha256 discard &&
    read_manifest_field test_fresh_verifier_gate_static_py_path discard &&
    read_manifest_field test_fresh_verifier_gate_static_py_blob discard &&
    read_manifest_field test_fresh_verifier_gate_static_py_sha256 discard &&
    read_manifest_field prepare_stage_root_sh_path discard &&
    read_manifest_field prepare_stage_root_sh_blob discard &&
    read_manifest_field prepare_stage_root_sh_sha256 discard &&
    read_manifest_field provision_ubuntu_test_host_sh_path discard &&
    read_manifest_field provision_ubuntu_test_host_sh_blob discard &&
    read_manifest_field provision_ubuntu_test_host_sh_sha256 discard || {
      exec {MANIFEST_FD}<&-
      return 65
    }
  if IFS= read -r -u "${MANIFEST_FD}" unexpected; then
    exec {MANIFEST_FD}<&-
    return 65
  fi
  exec {MANIFEST_FD}<&-
}

phase_value() {
  /usr/bin/awk -F '=' -v wanted="$2" '
    BEGIN { count = 0; invalid = 0 }
    $1 == wanted {
      count++
      if (NF != 2 || $2 == "") invalid = 1
      value = $2
    }
    END {
      if (count != 1 || invalid) exit 65
      print value
    }
  ' "$1"
}

file_identity() {
  /usr/bin/stat -Lc '%d:%i:%s:%Y:%Z:%u:%g:%a:%h:%F' -- "$1"
}

git_fixed() { "${GIT_ENV[@]}" "$@"; }

require_tools() {
  local tool
  local -a tools=(
    /bin/bash /bin/date
    /usr/bin/awk /usr/bin/cat /usr/bin/chmod /usr/bin/cmp /usr/bin/env
    /usr/bin/findmnt /usr/bin/flock /usr/bin/git /usr/bin/go /usr/bin/grep /usr/bin/hostname
    /usr/bin/jq /usr/bin/make /usr/bin/mkdir /usr/bin/readlink /usr/bin/dmesg
    /usr/bin/sha256sum /usr/bin/shellcheck /usr/bin/stat /usr/bin/tee
    /usr/bin/test /usr/bin/timeout /usr/bin/uname
    /usr/bin/clang /usr/bin/gcc
    /usr/sbin/bpftool /usr/sbin/insmod /usr/sbin/modinfo /usr/sbin/rmmod
  )
  for tool in "${tools[@]}"; do
    [[ -x "${tool}" ]] || fail "missing-tool:${tool}" 69
  done
}

validate_root_owned_file() {
  local path="$1" expected_mode="$2" canonical shape
  canonical="$(/usr/bin/readlink -e -- "${path}")" || return 66
  [[ "${canonical}" == "${path}" && ! -L "${path}" ]] || return 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${path}")" || return 66
  [[ "${shape}" == "0:0:${expected_mode}:1:regular file" ]]
}

validate_controller_source() {
  local canonical shape head dirty self_path committed_blob helper_path
  canonical="$(/usr/bin/readlink -e -- "${CONTROLLER_SOURCE}")" || return 66
  [[ "${canonical}" == "${EXPECTED_CONTROLLER_SOURCE}" && -d "${CONTROLLER_SOURCE}" &&
    ! -L "${CONTROLLER_SOURCE}" ]] || return 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${CONTROLLER_SOURCE}")" || return 66
  [[ "${shape}" == '0:0:700:directory' ]] || return 79
  head="$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse --verify HEAD)" || return 66
  [[ "${head}" == "${COMMIT}" ]] || return 79
  dirty="$(git_fixed -C "${CONTROLLER_SOURCE}" status --porcelain=v1 \
    --untracked-files=all --ignore-submodules=none)" || return 66
  [[ -z "${dirty}" ]] || return 79
  self_path="$(/usr/bin/readlink -e -- "$0")" || return 66
  [[ "${self_path}" == "${CONTROLLER_SOURCE}/${SELF_FROM_SOURCE}" ]] || return 79
  validate_root_owned_file "${self_path}" 700 || return $?
  SELF_BLOB="$(git_fixed -C "${CONTROLLER_SOURCE}" hash-object -- "${self_path}")" || return 66
  committed_blob="$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse \
    "${COMMIT}:${SELF_FROM_SOURCE}")" || return 66
  [[ "${SELF_BLOB}" == "${committed_blob}" ]] || return 79
  SELF_SHA256="$(sha256_file "${self_path}")" || return $?
  helper_path="$(/usr/bin/readlink -e -- "${MODULE_LEASE_HELPER}")" || return 66
  [[ "${helper_path}" == "${MODULE_LEASE_HELPER}" ]] || return 79
  validate_root_owned_file "${helper_path}" 700 || return $?
  MODULE_LEASE_HELPER_BLOB="$(git_fixed -C "${CONTROLLER_SOURCE}" hash-object -- \
    "${helper_path}")" || return 66
  committed_blob="$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse \
    "${COMMIT}:${MODULE_LEASE_HELPER_RELATIVE}")" || return 66
  [[ "${MODULE_LEASE_HELPER_BLOB}" == "${committed_blob}" ]] || return 79
  MODULE_LEASE_HELPER_SHA256="$(sha256_file "${helper_path}")" || return $?
}

load_module_lease_helper() {
  # shellcheck source=checksum-module-lease.sh
  source "${MODULE_LEASE_HELPER}" || return $?
  [[ "${C8_CHECKSUM_MODULE_RUN_ID}" == "${CONTROLLER_RUN_ID}" &&
    "${C8_CHECKSUM_MODULE_NAME}" == "${MODULE_NAME}" &&
    "${C8_CHECKSUM_MODULE_LOCK}" == "${MODULE_LEASE_LOCK}" &&
    "${C8_CHECKSUM_MODULE_FRESH_RESOURCE_ID}" == "${MODULE_RESOURCE_ID}" &&
    "${C8_CHECKSUM_MODULE_FRESH_OBJECT}" == "${MODULE_OBJECT}" &&
    "${C8_CHECKSUM_MODULE_FRESH_EVIDENCE}" == "${EVIDENCE_ROOT}" ]] || return 79
}

hold_input_files() {
  local manifest_fd_path bundle_fd_path
  validate_root_owned_file "${MANIFEST}" 600 || return $?
  validate_root_owned_file "${BUNDLE}" 600 || return $?
  exec {MANIFEST_FD}<"${MANIFEST}" || return 66
  exec {BUNDLE_FD}<"${BUNDLE}" || {
    exec {MANIFEST_FD}<&-
    return 66
  }
  manifest_fd_path="/proc/self/fd/${MANIFEST_FD}"
  bundle_fd_path="/proc/self/fd/${BUNDLE_FD}"
  MANIFEST_FILE_IDENTITY="$(file_identity "${manifest_fd_path}")" || return 66
  BUNDLE_FILE_IDENTITY="$(file_identity "${bundle_fd_path}")" || return 66
  [[ "$(file_identity "${MANIFEST}")" == "${MANIFEST_FILE_IDENTITY}" &&
    "$(file_identity "${BUNDLE}")" == "${BUNDLE_FILE_IDENTITY}" &&
    "$(sha256_file "${manifest_fd_path}")" == "${MANIFEST_SHA256}" &&
    "$(sha256_file "${bundle_fd_path}")" == "${BUNDLE_SHA256}" ]] || return 79
}

validate_snapshot_contract() {
  local bundle_head
  validate_root_owned_file "${SNAPSHOT_MANIFEST}" 600 || return $?
  validate_root_owned_file "${SNAPSHOT_BUNDLE}" 600 || return $?
  SNAPSHOT_MANIFEST_IDENTITY="$(file_identity "${SNAPSHOT_MANIFEST}")" || return 66
  SNAPSHOT_BUNDLE_IDENTITY="$(file_identity "${SNAPSHOT_BUNDLE}")" || return 66
  [[ "$(sha256_file "${SNAPSHOT_MANIFEST}")" == "${MANIFEST_SHA256}" &&
    "$(sha256_file "${SNAPSHOT_BUNDLE}")" == "${BUNDLE_SHA256}" ]] || return 79
  load_manifest_once || return $?
  [[ "${FORMAT}" == 'wg-mix-ebpf-b82-v6-package-v2' &&
    "${MANIFEST_RUN_ID}" == "${CONTROLLER_RUN_ID}" &&
    "${MANIFEST_PACKAGE_ID}" == "${PACKAGE_ID}" &&
    "${MANIFEST_COMMIT}" == "${COMMIT}" &&
    "${BUNDLE_NAME}" == "source-${PACKAGE_ID}.bundle" &&
    "${MANIFEST_BUNDLE_SHA256}" == "${BUNDLE_SHA256}" &&
    "${HISTORY_VERIFICATION}" == 'isolated-unbundle-rev-list-fsck-v1' &&
    "${HISTORY_COMMIT_COUNT}" =~ ^[1-9][0-9]*$ &&
    "${MANIFEST_REMOTE_SOURCE}" == "${EXPECTED_CONTROLLER_SOURCE}" &&
    "${MANIFEST_TARGET_HOST}" == '192.168.10.82' &&
    "${MANIFEST_TARGET_HOSTNAME}" == "${EXPECTED_HOSTNAME}" &&
    "${MANIFEST_TARGET_KERNEL}" == "${EXPECTED_KERNEL}" &&
    "${MANIFEST_TARGET_MACHINE_ID}" == "${EXPECTED_MACHINE_ID}" &&
    "${MANIFEST_MODULE_LEASE_HELPER_PATH}" == "${MODULE_LEASE_HELPER_RELATIVE}" &&
    "${MANIFEST_MODULE_LEASE_HELPER_BLOB}" == "${MODULE_LEASE_HELPER_BLOB}" &&
    "${MANIFEST_MODULE_LEASE_HELPER_SHA256}" == "${MODULE_LEASE_HELPER_SHA256}" &&
    "${MANIFEST_ROOT_FRESH_PATH}" == "${SELF_FROM_SOURCE}" &&
    "${MANIFEST_ROOT_FRESH_BLOB}" == "${SELF_BLOB}" &&
    "${MANIFEST_ROOT_FRESH_SHA256}" == "${SELF_SHA256}" ]] || return 79
  valid_sha256 "${HISTORY_ROOTS_SHA256}" && valid_sha256 "${HISTORY_OBJECTS_SHA256}" || return 65
  [[ "${INTEGRATION_REF}" =~ ^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}$ &&
    "${INTEGRATION_REF}" != *'..'* && "${INTEGRATION_REF}" != *'//' ]] || return 65
  git_fixed -C "${CONTROLLER_SOURCE}" bundle verify "${SNAPSHOT_BUNDLE}" || return 76
  bundle_head="$(git_fixed -C "${CONTROLLER_SOURCE}" bundle list-heads \
    "${SNAPSHOT_BUNDLE}" "${INTEGRATION_REF}")" || return 76
  [[ "${bundle_head}" == "${COMMIT} ${INTEGRATION_REF}" ]]
}

validate_host() {
  local actual bpffs_mount bpffs_shape btf_shape
  ((EUID == 0)) || return 77
  actual="$(/usr/bin/hostname)" || return 66
  [[ "${actual}" == "${EXPECTED_HOSTNAME}" ]] || return 79
  actual="$(/usr/bin/uname -r)" || return 66
  [[ "${actual}" == "${EXPECTED_KERNEL}" ]] || return 79
  actual="$(/usr/bin/uname -m)" || return 66
  [[ "${actual}" == 'x86_64' ]] || return 79
  /usr/bin/grep -Fx -- 'ID=ubuntu' /etc/os-release || return 79
  /usr/bin/grep -Fx -- 'VERSION_ID="26.04"' /etc/os-release || return 79
  actual="$(/usr/bin/cat -- /etc/machine-id)" || return 66
  [[ "${actual}" == "${EXPECTED_MACHINE_ID}" ]] || return 79
  BOOT_ID="$(/usr/bin/cat -- /proc/sys/kernel/random/boot_id)" || return 66
  [[ "${BOOT_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 79
  INITIAL_NETNS="$(/usr/bin/readlink -- /proc/self/ns/net)" || return 66
  [[ "${INITIAL_NETNS}" =~ ^net:\[[1-9][0-9]*\]$ ]] || return 79
  bpffs_mount="$(/usr/bin/findmnt -n -T /sys/fs/bpf -o TARGET,FSTYPE)" || return 66
  [[ "${bpffs_mount}" == '/sys/fs/bpf bpf' ]] || return 79
  bpffs_shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F:%d:%i' -- /sys/fs/bpf)" || return 66
  [[ "${bpffs_shape}" =~ ^0:0:700:directory:[0-9]+:[0-9]+$ ]] || return 79
  BPFFS_IDENTITY="${bpffs_shape}"
  [[ "$(/usr/bin/readlink -e -- /sys/kernel/btf/vmlinux)" == '/sys/kernel/btf/vmlinux' ]] || return 79
  btf_shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- /sys/kernel/btf/vmlinux)" || return 66
  [[ "${btf_shape}" == '0:0:444:1:regular file' ]] || return 79
  VMLINUX_BTF_SHA256="$(sha256_file /sys/kernel/btf/vmlinux)" || return $?
  actual="$(/usr/bin/readlink -e -- "/lib/modules/${EXPECTED_KERNEL}/build")" || return 66
  [[ "${actual}" == "/usr/src/linux-headers-${EXPECTED_KERNEL}" ]] || return 79
  [[ ! -e "${RESERVED_PIN}" && ! -L "${RESERVED_PIN}" ]] || return 78
}

validate_module_absent() {
  [[ ! -e "/sys/module/${MODULE_NAME}" && ! -L "/sys/module/${MODULE_NAME}" ]]
}

validate_inputs() {
  require_tools
  validate_controller_source || fail 'controller-source' $?
  load_module_lease_helper || fail 'module-lease-helper' $?
  validate_host || fail 'host-identity' $?
  hold_input_files || fail 'manifest-bundle-hold' $?
}

bootstrap_audit_line() {
  local event="$1" label="$2" target="$3" rc="$4" rendered="$5" timestamp line
  timestamp="$(utc_now)" || return $?
  printf -v line 'utc=%q event=%q step=%q target=%q rc=%q argv=%q' \
    "${timestamp}" "${event}" "${label}" "${target}" "${rc}" "${rendered}"
  BOOTSTRAP_AUDIT+=("${line}")
  printf 'B82_FRESH_VERIFIER_BOOTSTRAP %s\n' "${line}"
}

bootstrap_step() {
  local label="$1" target="$2" rendered rc
  shift 2
  rendered="$(quote_argv "$@")" || return $?
  bootstrap_audit_line start "${label}" "${target}" not-run "${rendered}" || return $?
  "$@"
  rc=$?
  bootstrap_audit_line finish "${label}" "${target}" "${rc}" "${rendered}" || return $?
  return "${rc}"
}

ensure_prefix_and_stage() {
  local canonical shape
  if [[ -e "${STAGING_PREFIX}" || -L "${STAGING_PREFIX}" ]]; then
    [[ -d "${STAGING_PREFIX}" && ! -L "${STAGING_PREFIX}" ]] || fail 'staging-prefix-shape' 79
  else
    bootstrap_step B0.prefix "${STAGING_PREFIX}" /usr/bin/mkdir --mode=0700 -- \
      "${STAGING_PREFIX}" || fail 'staging-prefix-create' $?
  fi
  canonical="$(/usr/bin/readlink -e -- "${STAGING_PREFIX}")" || fail 'staging-prefix-canonical'
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${STAGING_PREFIX}")" || fail 'staging-prefix-stat'
  [[ "${canonical}" == "${STAGING_PREFIX}" && "${shape}" == '0:0:700:directory' ]] ||
    fail 'staging-prefix-identity' 79
  [[ ! -e "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] || fail 'stage-preexists' 73
  bootstrap_step B1.stage "${STAGE_ROOT}" /usr/bin/mkdir --mode=0700 -- \
    "${STAGE_ROOT}" || fail 'stage-create' $?
  bootstrap_step B2.intake "${INTAKE_ROOT}" /usr/bin/mkdir --mode=0700 -- \
    "${INTAKE_ROOT}" || fail 'intake-create' $?
  bootstrap_step B3.evidence "${EVIDENCE_ROOT}" /usr/bin/mkdir --mode=0700 -- \
    "${EVIDENCE_ROOT}" || fail 'evidence-create' $?
}

bootstrap_snapshot_file() {
  local label="$1" descriptor="$2" destination="$3" rendered source rc
  source="/proc/self/fd/${descriptor}"
  rendered="shell-builtin: noclobber copy held ${source} to ${destination}"
  bootstrap_audit_line start "${label}" "${destination}" not-run "${rendered}" || return $?
  set -o noclobber
  /usr/bin/cat -- "${source}" >"${destination}"
  rc=$?
  set +o noclobber
  bootstrap_audit_line finish "${label}" "${destination}" "${rc}" "${rendered}" || return $?
  return "${rc}"
}

snapshot_held_inputs() {
  local manifest_fd_path="/proc/self/fd/${MANIFEST_FD}"
  local bundle_fd_path="/proc/self/fd/${BUNDLE_FD}"
  [[ "$(file_identity "${manifest_fd_path}")" == "${MANIFEST_FILE_IDENTITY}" &&
    "$(file_identity "${bundle_fd_path}")" == "${BUNDLE_FILE_IDENTITY}" ]] ||
    fail 'held-input-identity-drift' 79
  bootstrap_snapshot_file B4.manifest-snapshot "${MANIFEST_FD}" "${SNAPSHOT_MANIFEST}" ||
    fail 'manifest-snapshot' $?
  bootstrap_snapshot_file B5.bundle-snapshot "${BUNDLE_FD}" "${SNAPSHOT_BUNDLE}" ||
    fail 'bundle-snapshot' $?
  [[ "$(file_identity "${manifest_fd_path}")" == "${MANIFEST_FILE_IDENTITY}" &&
    "$(file_identity "${bundle_fd_path}")" == "${BUNDLE_FILE_IDENTITY}" &&
    "$(sha256_file "${manifest_fd_path}")" == "${MANIFEST_SHA256}" &&
    "$(sha256_file "${bundle_fd_path}")" == "${BUNDLE_SHA256}" ]] ||
    fail 'held-input-content-drift' 79
  exec {MANIFEST_FD}<&-
  exec {BUNDLE_FD}<&-
  validate_snapshot_contract || fail 'snapshot-contract' $?
}

create_audit_log() {
  local rc rendered timestamp
  rendered="shell-builtin: noclobber write bootstrap audit to ${AUDIT_LOG}"
  bootstrap_audit_line start B6.audit "${AUDIT_LOG}" not-run "${rendered}" || fail 'audit-bootstrap-start'
  set -o noclobber
  printf '%s\n' "${BOOTSTRAP_AUDIT[@]}" >"${AUDIT_LOG}"
  rc=$?
  set +o noclobber
  bootstrap_audit_line finish B6.audit "${AUDIT_LOG}" "${rc}" "${rendered}" || fail 'audit-bootstrap-finish'
  ((rc == 0)) || fail 'audit-create' "${rc}"
  timestamp="$(utc_now)" || fail 'audit-created-time'
  printf 'utc=%q event=%q step=%q target=%q rc=%q argv=%q\n' \
    "${timestamp}" finish B6.audit "${AUDIT_LOG}" 0 "${rendered}" >>"${AUDIT_LOG}" ||
    fail 'audit-finish-persist'
}

audit_line() {
  local event="$1" label="$2" target="$3" rc="$4" rendered="$5" timestamp
  local -a statuses
  [[ -f "${AUDIT_LOG}" && ! -L "${AUDIT_LOG}" &&
    "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${AUDIT_LOG}")" == '0:0:600:1:regular file' ]] || return 79
  timestamp="$(utc_now)" || return $?
  printf 'utc=%q event=%q step=%q target=%q rc=%q argv=%q\n' \
    "${timestamp}" "${event}" "${label}" "${target}" "${rc}" "${rendered}" |
    /usr/bin/tee -a "${AUDIT_LOG}"
  statuses=("${PIPESTATUS[@]}")
  ((${#statuses[@]} == 2 && statuses[0] == 0 && statuses[1] == 0))
}

run_step() {
  local label="$1" target="$2" rendered evidence_rendered create_rendered create_rc
  local -a statuses
  shift 2
  [[ "${label}" =~ ^[A-Z][A-Za-z0-9_.-]{0,95}$ ]] || fail "step-label:${label}" 65
  STEP_LOG="${EVIDENCE_ROOT}/${label}.out"
  [[ ! -e "${STEP_LOG}" && ! -L "${STEP_LOG}" ]] || fail "step-output-exists:${label}" 78
  rendered="$(quote_argv "$@")" || fail "step-render:${label}"
  create_rendered="shell-builtin: noclobber create ${STEP_LOG}"
  audit_line start "${label}.evidence-create" "${STEP_LOG}" not-run "${create_rendered}" ||
    fail "audit-evidence-create-start:${label}"
  set -o noclobber
  : >"${STEP_LOG}"
  create_rc=$?
  set +o noclobber
  audit_line finish "${label}.evidence-create" "${STEP_LOG}" "${create_rc}" "${create_rendered}" ||
    fail "audit-evidence-create-finish:${label}"
  ((create_rc == 0)) || fail "step-evidence-create:${label}" "${create_rc}"
  [[ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${STEP_LOG}")" == \
    '0:0:600:1:regular file' ]] || fail "step-evidence-identity:${label}" 79
  evidence_rendered="$(quote_argv /usr/bin/tee -a "${STEP_LOG}")" || fail "step-evidence-render:${label}"
  audit_line start "${label}" "${target}" not-run "${rendered}" || fail "audit-start:${label}"
  audit_line start "${label}.evidence" "${STEP_LOG}" not-run "${evidence_rendered}" ||
    fail "audit-evidence-start:${label}"
  "$@" 2>&1 | /usr/bin/tee -a "${STEP_LOG}"
  statuses=("${PIPESTATUS[@]}")
  ((${#statuses[@]} == 2)) || fail "step-pipeline:${label}"
  STEP_RC="${statuses[0]}"
  audit_line finish "${label}" "${target}" "${STEP_RC}" "${rendered}" || fail "audit-finish:${label}"
  audit_line finish "${label}.evidence" "${STEP_LOG}" "${statuses[1]}" "${evidence_rendered}" ||
    fail "audit-evidence-finish:${label}"
  ((statuses[1] == 0)) || fail "step-evidence-write:${label}" "${statuses[1]}"
}

write_phase() {
  local path="$1" rendered rc
  shift
  [[ "${path}" == "${EVIDENCE_ROOT}/"* && "${path#${EVIDENCE_ROOT}/}" != */* ]] ||
    fail "phase-scope:${path}" 65
  [[ ! -e "${path}" && ! -L "${path}" ]] || fail "phase-exists:${path}" 78
  rendered="$(quote_argv shell-builtin printf '%s\\n' "$@")>$(quote_argv "${path}")" ||
    fail "phase-render:${path}"
  audit_line start phase-write "${path}" not-run "${rendered}" || fail "phase-audit-start:${path}"
  set -o noclobber
  printf '%s\n' "$@" >"${path}"
  rc=$?
  set +o noclobber
  audit_line finish phase-write "${path}" "${rc}" "${rendered}" || fail "phase-audit-finish:${path}"
  ((rc == 0)) || fail "phase-write:${path}" "${rc}"
}

c8_checksum_module_fail() {
  fail "module-lease:$1" "${2:-79}"
}

run_module_lease_argv() {
  local label="$1" target="$2" rendered rc
  local -a statuses
  shift 2
  rendered="$(quote_argv "$@")" || fail "module-lease-render:${label}"
  audit_line start "${label}" "${target}" not-run "${rendered}" ||
    fail "module-lease-audit-start:${label}"
  "$@" 2>&1 | /usr/bin/tee -a "${AUDIT_LOG}"
  statuses=("${PIPESTATUS[@]}")
  ((${#statuses[@]} == 2)) || fail "module-lease-pipeline:${label}"
  rc="${statuses[0]}"
  audit_line finish "${label}" "${target}" "${rc}" "${rendered}" ||
    fail "module-lease-audit-finish:${label}"
  ((statuses[1] == 0)) || fail "module-lease-output:${label}" "${statuses[1]}"
  return "${rc}"
}

c8_checksum_module_run() { run_module_lease_argv "$@"; }

c8_checksum_module_write() {
  local path="$1" payload="$2"
  case "${path}" in
    "${MODULE_INTENT}" | "${MODULE_OWNED}" | "${MODULE_UNLOADED}") ;;
    *) fail "module-lease-write-scope:${path}" 78 ;;
  esac
  write_phase "${path}" "${payload}"
}

ensure_phase() {
  local path="$1" expected actual
  shift
  expected="$(printf '%s\n' "$@")" || fail "phase-render-expected:${path}"
  if [[ -e "${path}" || -L "${path}" ]]; then
    validate_root_owned_file "${path}" 600 || fail "phase-replay-identity:${path}" $?
    actual="$(/usr/bin/cat -- "${path}")" || fail "phase-replay-read:${path}"
    [[ "${actual}" == "${expected}" ]] || fail "phase-replay-mismatch:${path}" 79
    return
  fi
  write_phase "${path}" "$@"
}

run_convergent_operation() {
  local label="$1" operation="$2" rendered rc
  build_argv "${operation}" || fail "convergence-operation:${operation}" $?
  rendered="$(quote_argv "${OP_ARGV[@]}")" || fail "convergence-render:${label}"
  audit_line start "${label}" "${OP_TARGET}" not-run "${rendered}" ||
    fail "convergence-audit-start:${label}"
  CONVERGENCE_OUTPUT="$("${OP_ARGV[@]}" 2>&1)"
  rc=$?
  audit_line output "${label}" "${OP_TARGET}" "${rc}" "${CONVERGENCE_OUTPUT}" ||
    fail "convergence-audit-output:${label}"
  audit_line finish "${label}" "${OP_TARGET}" "${rc}" "${rendered}" ||
    fail "convergence-audit-finish:${label}"
  ((rc == 0)) || {
    printf '%s\n' "${CONVERGENCE_OUTPUT}" >&2
    fail "${label}:rc=${rc}" "${rc}"
  }
}

assert_bpf_baseline_convergent() {
  local label="$1" expected
  run_convergent_operation "${label}.progs" snapshot-progs
  expected="$(/usr/bin/cat -- "${EVIDENCE_ROOT}/A.progs.out")" || fail 'restore-progs-baseline-read'
  [[ "${CONVERGENCE_OUTPUT}" == "${expected}" ]] || fail "${label}:program-drift" 79
  run_convergent_operation "${label}.maps" snapshot-maps
  expected="$(/usr/bin/cat -- "${EVIDENCE_ROOT}/A.maps.out")" || fail 'restore-maps-baseline-read'
  [[ "${CONVERGENCE_OUTPUT}" == "${expected}" ]] || fail "${label}:map-drift" 79
  run_convergent_operation "${label}.links" snapshot-links
  expected="$(/usr/bin/cat -- "${EVIDENCE_ROOT}/A.links.out")" || fail 'restore-links-baseline-read'
  [[ "${CONVERGENCE_OUTPUT}" == "${expected}" ]] || fail "${label}:link-drift" 79
  run_convergent_operation "${label}.kwarn" snapshot-kernel-warnings
  expected="$(/usr/bin/cat -- "${EVIDENCE_ROOT}/A.kwarn.out")" || fail 'restore-warning-baseline-read'
  [[ "${CONVERGENCE_OUTPUT}" == "${expected}" ]] || fail "${label}:kernel-warning-drift" 79
  run_convergent_operation "${label}.pin" reserved-pin-absent
}

build_argv() {
  local operation="$1"
  OP_TARGET="${operation}"
  OP_ARGV=()
  case "${operation}" in
    source-clone)
      OP_TARGET="${SOURCE}"
      OP_ARGV=("${GIT_ENV[@]}" clone --no-local --no-checkout --single-branch
        --branch "${INTEGRATION_REF#refs/heads/}" -- "${SNAPSHOT_BUNDLE}" "${SOURCE}")
      ;;
    source-checkout)
      OP_TARGET="${SOURCE}"
      OP_ARGV=("${GIT_ENV[@]}" -C "${SOURCE}" checkout --detach "${COMMIT}")
      ;;
    source-shallow)
      OP_TARGET="${SOURCE}"
      OP_ARGV=("${GIT_ENV[@]}" -C "${SOURCE}" rev-parse --is-shallow-repository)
      ;;
    history-count)
      OP_TARGET="${COMMIT}"
      OP_ARGV=("${GIT_ENV[@]}" -C "${SOURCE}" rev-list --count "${COMMIT}")
      ;;
    history-roots)
      OP_TARGET="${COMMIT}"
      OP_ARGV=("${GIT_ENV[@]}" -C "${SOURCE}" rev-list --max-parents=0 --reverse "${COMMIT}")
      ;;
    history-objects)
      OP_TARGET="${COMMIT}"
      OP_ARGV=("${GIT_ENV[@]}" -C "${SOURCE}" rev-list --parents --objects
        --missing=print "${COMMIT}")
      ;;
    history-fsck)
      OP_TARGET="${COMMIT}"
      OP_ARGV=("${GIT_ENV[@]}" -C "${SOURCE}" fsck --full --strict --no-dangling "${COMMIT}")
      ;;
    cache-mkdir) OP_TARGET="${GO_CACHE}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_CACHE}") ;;
    mod-cache-mkdir) OP_TARGET="${GO_MOD_CACHE}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_MOD_CACHE}") ;;
    go-path-mkdir) OP_TARGET="${GO_PATH}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_PATH}") ;;
    go-tmp-mkdir) OP_TARGET="${GO_TMP}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_TMP}") ;;
    go-home-mkdir) OP_TARGET="${GO_HOME}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_HOME}") ;;
    xdg-cache-mkdir) OP_TARGET="${XDG_CACHE}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${XDG_CACHE}") ;;
    xdg-config-mkdir) OP_TARGET="${XDG_CONFIG}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${XDG_CONFIG}") ;;
    lint-script)
      OP_TARGET="${SOURCE}/${SELF_FROM_SOURCE}"
      OP_ARGV=(/usr/bin/shellcheck --norc --shell=bash -- "${SOURCE}/${SELF_FROM_SOURCE}")
      ;;
    build)
      OP_TARGET="${SOURCE}"
      OP_ARGV=("${GO_ENV[@]}" /usr/bin/timeout --signal=TERM --kill-after=30s 30m
        /usr/bin/make --no-print-directory -C "${SOURCE}"
        build-faketcp-checksum-kmod build-faketcp-verifier-launcher-linux-amd64
        build test-bpf-object-manifests)
      ;;
    binary-version)
      OP_TARGET="${BINARY}"
      OP_ARGV=(/usr/bin/timeout --signal=TERM --kill-after=5s 30s "${BINARY}" version --json)
      ;;
    tool-go) OP_TARGET='go-version'; OP_ARGV=(/usr/bin/go version) ;;
    tool-clang) OP_TARGET='clang-version'; OP_ARGV=(/usr/bin/clang --version) ;;
    tool-bpftool) OP_TARGET='bpftool-version'; OP_ARGV=(/usr/sbin/bpftool -V) ;;
    tool-gcc) OP_TARGET='gcc-version'; OP_ARGV=(/usr/bin/gcc --version) ;;
    tool-git) OP_TARGET='git-version'; OP_ARGV=(/usr/bin/git --version) ;;
    tool-make) OP_TARGET='make-version'; OP_ARGV=(/usr/bin/make --version) ;;
    snapshot-progs) OP_TARGET='kernel-bpf-programs'; OP_ARGV=(/usr/sbin/bpftool -j prog show) ;;
    snapshot-maps) OP_TARGET='kernel-bpf-maps'; OP_ARGV=(/usr/sbin/bpftool -j map show) ;;
    snapshot-links) OP_TARGET='kernel-bpf-links'; OP_ARGV=(/usr/sbin/bpftool -j link show) ;;
    snapshot-kernel-warnings)
      OP_TARGET='kernel-warning-log'
      OP_ARGV=(/usr/bin/dmesg --level=emerg,alert,crit,err,warn --color=never)
      ;;
    reserved-pin-absent) OP_TARGET="${RESERVED_PIN}"; OP_ARGV=(/usr/bin/test ! -e "${RESERVED_PIN}") ;;
    verifier)
      OP_TARGET="${EXPERIMENTAL_OBJECT}"
      OP_ARGV=(/usr/bin/timeout --signal=TERM --kill-after=10s 3m "${LAUNCHER}"
        --runner "${RUNNER}" --runner-sha256 "${RUNNER_SHA256}"
        --staging-root "${STAGE_ROOT}"
        --binary "${BINARY}" --binary-sha256 "${BINARY_SHA256}"
        --object "${EXPERIMENTAL_OBJECT}" --object-sha256 "${EXPERIMENTAL_SHA256}")
      ;;
    packet-test-run)
      OP_TARGET="${EXPERIMENTAL_OBJECT}"
      OP_ARGV=("${GO_ENV[@]}" WG_MIX_FAKETCP_PACKET_TEST_OBJECT="${EXPERIMENTAL_OBJECT}"
        /usr/bin/timeout --signal=TERM --kill-after=10s 4m
        /usr/bin/go -C "${SOURCE}" test ./internal/dataplane
        -run '^TestFakeTCPBPFPacketProbe$' -count=1 -timeout=3m -v)
      ;;
    *) return 64 ;;
  esac
}

plan_operation() {
  local label="$1" operation="$2"
  build_argv "${operation}" || fail "plan-operation:${operation}" $?
  printf '%s operation=%s target=%q argv=' "${label}" "${operation}" "${OP_TARGET}"
  quote_argv "${OP_ARGV[@]}"
  printf '\n'
}

plan_module_lock() {
  local label="$1"
  printf '%s operation=shared-module-lock target=%q helper=%q argv=' \
    "${label}" "${MODULE_LEASE_LOCK}" "${MODULE_LEASE_HELPER}"
  quote_argv /usr/bin/flock --exclusive --nonblock MODULE_LEASE_FD
  printf '\n'
}

plan_module_load() {
  printf 'M.pre operation=shared-module-precondition target=%q helper=c8_checksum_module_load argv=' \
    "${MODULE_NAME}"
  quote_argv /usr/bin/test ! -e "/sys/module/${MODULE_NAME}"
  printf '\nM.intent-baseline operation=shared-module-precondition target=%q helper=c8_checksum_module_load argv=' \
    "${MODULE_NAME}"
  quote_argv /usr/bin/test ! -e "/sys/module/${MODULE_NAME}"
  printf '\nM.load operation=shared-module-load target=%q helper=c8_checksum_module_load argv=' \
    "${MODULE_NAME}"
  quote_argv /usr/sbin/insmod "${MODULE_OBJECT}" "lease_id=${MODULE_LEASE_ID}"
  printf '\n'
}

plan_module_restore() {
  printf 'EXPLICIT_RESTORE_ONLY.R.module operation=shared-module-restore target=%q helper=c8_checksum_module_restore argv=' \
    "${MODULE_NAME}"
  quote_argv /usr/sbin/rmmod "${MODULE_NAME}"
  printf '\n'
}

run_operation() {
  local label="$1" operation="$2"
  build_argv "${operation}" || fail "run-operation:${operation}" $?
  run_step "${label}" "${OP_TARGET}" "${OP_ARGV[@]}"
  ((STEP_RC == 0)) || fail "${label}:rc=${STEP_RC}" "${STEP_RC}"
}

render_plan() {
  local spec label operation
  INTEGRATION_REF='refs/heads/REVIEWED_INTEGRATION_REF'
  RUNNER_SHA256='RUNTIME_RUNNER_SHA256'
  BINARY_SHA256='RUNTIME_BINARY_SHA256'
  EXPERIMENTAL_SHA256='RUNTIME_EXPERIMENTAL_OBJECT_SHA256'
  printf 'B82_FRESH_VERIFIER_PLAN_ONLY gate_id=%s commit=%s manifest_sha256=%s bundle_sha256=%s state_schema=%s\n' \
    "${GATE_ID}" "${COMMIT}" "${MANIFEST_SHA256}" "${BUNDLE_SHA256}" "${STATE_SCHEMA}"
  printf 'B0.prefix operation=mkdir-if-absent target=%q argv=' "${STAGING_PREFIX}"
  quote_argv /usr/bin/mkdir --mode=0700 -- "${STAGING_PREFIX}"
  printf '\n'
  printf 'B1.stage operation=fresh-stage-create target=%q argv=' "${STAGE_ROOT}"
  quote_argv /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}"
  printf '\n'
  printf 'B2.intake operation=intake-create target=%q argv=' "${INTAKE_ROOT}"
  quote_argv /usr/bin/mkdir --mode=0700 -- "${INTAKE_ROOT}"
  printf '\n'
  printf 'B3.evidence operation=evidence-create target=%q argv=' "${EVIDENCE_ROOT}"
  quote_argv /usr/bin/mkdir --mode=0700 -- "${EVIDENCE_ROOT}"
  printf '\n'
  printf 'B4.manifest-snapshot operation=held-fd-noclobber-copy source=/proc/self/fd/HELD_MANIFEST_FD target=%q sha256=%s\n' \
    "${SNAPSHOT_MANIFEST}" "${MANIFEST_SHA256}"
  printf 'B5.bundle-snapshot operation=held-fd-noclobber-copy source=/proc/self/fd/HELD_BUNDLE_FD target=%q sha256=%s\n' \
    "${SNAPSHOT_BUNDLE}" "${BUNDLE_SHA256}"
  plan_module_lock L0
  printf 'L1.module-absent operation=shared-module-precondition target=%q argv=' "${MODULE_NAME}"
  quote_argv /usr/bin/test ! -e "/sys/module/${MODULE_NAME}"
  printf '\n'
  for spec in \
    'S0.clone|source-clone' 'S1.checkout|source-checkout' \
    'S4.shallow|source-shallow' 'S4.count|history-count' \
    'S4.roots|history-roots' 'S4.objects|history-objects' 'S4.fsck|history-fsck' \
    'S2.cache|cache-mkdir' 'S2.mod-cache|mod-cache-mkdir' \
    'S2.go-path|go-path-mkdir' 'S2.go-tmp|go-tmp-mkdir' \
    'S2.go-home|go-home-mkdir' 'S2.xdg-cache|xdg-cache-mkdir' \
    'S2.xdg-config|xdg-config-mkdir' \
    'S3.lint|lint-script' \
    'H.go|tool-go' 'H.clang|tool-clang' 'H.bpftool|tool-bpftool' \
    'H.gcc|tool-gcc' 'H.git|tool-git' 'H.make|tool-make' \
    'A.progs|snapshot-progs' 'A.maps|snapshot-maps' 'A.links|snapshot-links' \
    'A.kwarn|snapshot-kernel-warnings' \
    'A.pin|reserved-pin-absent' 'B.build|build' 'B.version|binary-version' \
    'M.shared|shared-module-load-plan' 'M.kwarn|snapshot-kernel-warnings' 'V.load|verifier' \
    'V.progs|snapshot-progs' 'V.maps|snapshot-maps' 'V.links|snapshot-links' \
    'V.kwarn|snapshot-kernel-warnings' \
    'V.pin|reserved-pin-absent' 'T.run|packet-test-run' \
    'T.progs|snapshot-progs' 'T.maps|snapshot-maps' 'T.links|snapshot-links' \
    'T.kwarn|snapshot-kernel-warnings' \
    'T.pin|reserved-pin-absent'; do
    IFS='|' read -r label operation <<<"${spec}"
    if [[ "${operation}" == 'shared-module-load-plan' ]]; then
      plan_module_load
    else
      plan_operation "${label}" "${operation}"
    fi
  done
  plan_operation EXPLICIT_RESTORE_ONLY.R.pre-kwarn snapshot-kernel-warnings
  plan_module_lock EXPLICIT_RESTORE_ONLY.R.lease
  plan_module_restore
  plan_operation EXPLICIT_RESTORE_ONLY.R.progs snapshot-progs
  plan_operation EXPLICIT_RESTORE_ONLY.R.maps snapshot-maps
  plan_operation EXPLICIT_RESTORE_ONLY.R.links snapshot-links
  plan_operation EXPLICIT_RESTORE_ONLY.R.kwarn snapshot-kernel-warnings
  plan_operation EXPLICIT_RESTORE_ONLY.R.pin reserved-pin-absent
  printf 'B82_FRESH_VERIFIER_WRITE_SET stage=%s intake=%s snapshot_manifest=%s snapshot_bundle=%s source=%s evidence=%s go_cache=%s go_mod_cache=%s go_path=%s go_tmp=%s go_home=%s xdg_cache=%s xdg_config=%s transient_bpf=unpinned reserved_pin=%s module=%s shared_lock=%s:advisory-only lease_id=%s module_receipts=%s,%s,%s retained=1 automatic_cleanup=0 network_state_mutations=0 dependency_fetch=proxy-only\n' \
    "${STAGE_ROOT}" "${INTAKE_ROOT}" "${SNAPSHOT_MANIFEST}" "${SNAPSHOT_BUNDLE}" \
    "${SOURCE}" "${EVIDENCE_ROOT}" "${GO_CACHE}" "${GO_MOD_CACHE}" \
    "${GO_PATH}" "${GO_TMP}" "${GO_HOME}" "${XDG_CACHE}" "${XDG_CONFIG}" \
    "${RESERVED_PIN}" "${MODULE_NAME}" "${MODULE_LEASE_LOCK}" "${MODULE_LEASE_ID}" \
    "${MODULE_INTENT}" "${MODULE_OWNED}" "${MODULE_UNLOADED}"
  printf 'B82_FRESH_VERIFIER_PLAN_COMPLETE commands_are_review_templates=1 no_commands_executed=1 credential_read=0 network_state_mutations=0 capability_bits_changed=0\n'
}

create_fresh_source() {
  local head dirty spec label operation missing_rc count roots_sha objects_sha
  for spec in 'S0.clone|source-clone' 'S1.checkout|source-checkout'; do
    IFS='|' read -r label operation <<<"${spec}"
    run_operation "${label}" "${operation}"
  done
  run_operation S4.shallow source-shallow
  /usr/bin/grep -Fxq -- false "${EVIDENCE_ROOT}/S4.shallow.out" ||
    fail 'fresh-source-shallow' 76
  run_operation S4.count history-count
  count="$(/usr/bin/cat -- "${EVIDENCE_ROOT}/S4.count.out")" || fail 'history-count-read'
  [[ "${count}" == "${HISTORY_COMMIT_COUNT}" ]] || fail 'history-count-mismatch' 76
  run_operation S4.roots history-roots
  roots_sha="$(sha256_file "${HISTORY_ROOTS}")" || fail 'history-roots-sha'
  [[ "${roots_sha}" == "${HISTORY_ROOTS_SHA256}" && -s "${HISTORY_ROOTS}" ]] ||
    fail 'history-roots-mismatch' 76
  run_operation S4.objects history-objects
  /usr/bin/grep -E '^\?' -- "${HISTORY_OBJECTS}"
  missing_rc=$?
  case "${missing_rc}" in
    1) ;;
    0) fail 'history-object-missing' 76 ;;
    *) fail 'history-object-evidence' "${missing_rc}" ;;
  esac
  objects_sha="$(sha256_file "${HISTORY_OBJECTS}")" || fail 'history-objects-sha'
  [[ "${objects_sha}" == "${HISTORY_OBJECTS_SHA256}" ]] || fail 'history-objects-mismatch' 76
  run_operation S4.fsck history-fsck
  write_phase "${HISTORY_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-history-v1' "gate_id=${GATE_ID}" \
    "commit=${COMMIT}" 'repository_shallow=false' \
    "history_verification=${HISTORY_VERIFICATION}" \
    "history_commit_count=${HISTORY_COMMIT_COUNT}" \
    "history_roots_sha256=${roots_sha}" "history_objects_sha256=${objects_sha}" \
    'strict_fsck=passed'
  for spec in 'S2.cache|cache-mkdir' 'S2.mod-cache|mod-cache-mkdir' \
    'S2.go-path|go-path-mkdir' 'S2.go-tmp|go-tmp-mkdir' \
    'S2.go-home|go-home-mkdir' 'S2.xdg-cache|xdg-cache-mkdir' \
    'S2.xdg-config|xdg-config-mkdir'; do
    IFS='|' read -r label operation <<<"${spec}"
    run_operation "${label}" "${operation}"
  done
  head="$(git_fixed -C "${SOURCE}" rev-parse --verify HEAD)" || fail 'fresh-source-head'
  [[ "${head}" == "${COMMIT}" ]] || fail 'fresh-source-head-mismatch' 79
  dirty="$(git_fixed -C "${SOURCE}" status --porcelain=v1 --untracked-files=all \
    --ignore-submodules=none)" || fail 'fresh-source-status'
  [[ -z "${dirty}" ]] || fail 'fresh-source-dirty' 79
  [[ "$(git_fixed -C "${SOURCE}" rev-parse "${COMMIT}:${SELF_FROM_SOURCE}")" == \
    "$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse "${COMMIT}:${SELF_FROM_SOURCE}")" ]] ||
    fail 'fresh-source-script-identity' 79
}

capture_bpf_baseline() {
  local links_sha maps_sha progs_sha warnings_sha
  run_operation A.progs snapshot-progs
  run_operation A.maps snapshot-maps
  run_operation A.links snapshot-links
  run_operation A.kwarn snapshot-kernel-warnings
  run_operation A.pin reserved-pin-absent
  progs_sha="$(sha256_file "${EVIDENCE_ROOT}/A.progs.out")" || fail 'baseline-progs-sha'
  maps_sha="$(sha256_file "${EVIDENCE_ROOT}/A.maps.out")" || fail 'baseline-maps-sha'
  links_sha="$(sha256_file "${EVIDENCE_ROOT}/A.links.out")" || fail 'baseline-links-sha'
  warnings_sha="$(sha256_file "${EVIDENCE_ROOT}/A.kwarn.out")" || fail 'baseline-warnings-sha'
  write_phase "${BPF_BASELINE_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-bpf-baseline-v1' "gate_id=${GATE_ID}" \
    "programs_sha256=${progs_sha}" "maps_sha256=${maps_sha}" \
    "links_sha256=${links_sha}" "kernel_warnings_sha256=${warnings_sha}" \
    "reserved_pin=${RESERVED_PIN}" 'reserved_pin_state=absent'
}

assert_bpf_baseline() {
  local prefix="$1"
  local warning_baseline="${2:-M.kwarn}"
  run_operation "${prefix}.progs" snapshot-progs
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A.progs.out" "${EVIDENCE_ROOT}/${prefix}.progs.out" ||
    fail "${prefix}:program-drift" 79
  run_operation "${prefix}.maps" snapshot-maps
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A.maps.out" "${EVIDENCE_ROOT}/${prefix}.maps.out" ||
    fail "${prefix}:map-drift" 79
  run_operation "${prefix}.links" snapshot-links
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A.links.out" "${EVIDENCE_ROOT}/${prefix}.links.out" ||
    fail "${prefix}:link-drift" 79
  run_operation "${prefix}.kwarn" snapshot-kernel-warnings
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/${warning_baseline}.out" \
    "${EVIDENCE_ROOT}/${prefix}.kwarn.out" ||
    fail "${prefix}:kernel-warning-drift" 79
  run_operation "${prefix}.pin" reserved-pin-absent
}

capture_tool_versions() {
  local spec label operation
  for spec in 'H.go|tool-go' 'H.clang|tool-clang' 'H.bpftool|tool-bpftool' \
    'H.gcc|tool-gcc' 'H.git|tool-git' 'H.make|tool-make'; do
    IFS='|' read -r label operation <<<"${spec}"
    run_operation "${label}" "${operation}"
  done
}

build_fresh_artifacts() {
  local path version_commit version_embedded
  run_operation S3.lint lint-script
  run_operation B.build build
  for path in "${BASELINE_OBJECT}" "${EXPERIMENTAL_OBJECT}" "${BINARY}" \
    "${LAUNCHER}" "${RUNNER}" "${MODULE_OBJECT}"; do
    [[ -f "${path}" && ! -L "${path}" ]] || fail "artifact-shape:${path}" 79
  done
  BASELINE_SHA256="$(sha256_file "${BASELINE_OBJECT}")" || fail 'baseline-object-sha'
  EXPERIMENTAL_SHA256="$(sha256_file "${EXPERIMENTAL_OBJECT}")" || fail 'experimental-object-sha'
  BINARY_SHA256="$(sha256_file "${BINARY}")" || fail 'binary-sha'
  LAUNCHER_SHA256="$(sha256_file "${LAUNCHER}")" || fail 'launcher-sha'
  RUNNER_SHA256="$(sha256_file "${RUNNER}")" || fail 'runner-sha'
  MODULE_SHA256="$(sha256_file "${MODULE_OBJECT}")" || fail 'module-sha'
  MODULE_SRCVERSION="$(/usr/sbin/modinfo -F srcversion "${MODULE_OBJECT}")" || fail 'module-srcversion'
  [[ "${MODULE_SRCVERSION}" =~ ^[0-9A-F]{8,64}$ ]] || fail 'module-srcversion-shape' 79
  run_operation B.version binary-version
  version_commit="$(/usr/bin/jq -er '.source_commit' "${EVIDENCE_ROOT}/B.version.out")" ||
    fail 'binary-version-source'
  version_embedded="$(/usr/bin/jq -er '.embedded_bpf_object_sha256' \
    "${EVIDENCE_ROOT}/B.version.out")" || fail 'binary-version-object'
  [[ "${version_commit}" == "${COMMIT}" && "${version_embedded}" == "${BASELINE_SHA256}" ]] ||
    fail 'binary-version-binding' 79
  write_phase "${BUILD_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-build-v1' "gate_id=${GATE_ID}" \
    "commit=${COMMIT}" "manifest_sha256=${MANIFEST_SHA256}" "bundle_sha256=${BUNDLE_SHA256}" \
    "baseline_object=${BASELINE_OBJECT}" "baseline_sha256=${BASELINE_SHA256}" \
    "experimental_object=${EXPERIMENTAL_OBJECT}" "experimental_sha256=${EXPERIMENTAL_SHA256}" \
    "binary=${BINARY}" "binary_sha256=${BINARY_SHA256}" \
    "launcher=${LAUNCHER}" "launcher_sha256=${LAUNCHER_SHA256}" \
    "runner=${RUNNER}" "runner_sha256=${RUNNER_SHA256}" \
    "module_object=${MODULE_OBJECT}" "module_sha256=${MODULE_SHA256}" \
    "module_srcversion=${MODULE_SRCVERSION}" 'fresh_caches=1' 'manifest_contract=passed'
}

load_shared_module() {
  local module_warning_sha
  c8_checksum_module_configure "${CONTROLLER_RUN_ID}" "${MODULE_RESOURCE_ID}" \
    "${COMMIT}" "${BOOT_ID}" "${EVIDENCE_ROOT}" "${MODULE_OBJECT}" "${MODULE_SHA256}" ||
    fail 'module-lease-configure' $?
  [[ "${C8_CHECKSUM_MODULE_LEASE_ID}" == "${MODULE_LEASE_ID}" &&
    "${C8_CHECKSUM_MODULE_SRCVERSION}" == "${MODULE_SRCVERSION}" ]] ||
    fail 'module-lease-binding' 79
  c8_checksum_module_load M || fail 'module-lease-load' $?
  run_operation M.kwarn snapshot-kernel-warnings
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A.kwarn.out" "${EVIDENCE_ROOT}/M.kwarn.out" ||
    fail 'module-load-kernel-warning-delta' 79
  module_warning_sha="$(sha256_file "${EVIDENCE_ROOT}/M.kwarn.out")" ||
    fail 'module-warning-sha'
  [[ "${module_warning_sha}" == \
    "$(phase_value "${BPF_BASELINE_PHASE}" kernel_warnings_sha256)" ]] ||
    fail 'module-warning-phase-drift' 79
}

run_verifier_and_test_run() {
  [[ "$(sha256_file "${EXPERIMENTAL_OBJECT}")" == "${EXPERIMENTAL_SHA256}" &&
    "$(sha256_file "${BINARY}")" == "${BINARY_SHA256}" &&
    "$(sha256_file "${LAUNCHER}")" == "${LAUNCHER_SHA256}" &&
    "$(sha256_file "${RUNNER}")" == "${RUNNER_SHA256}" ]] || fail 'verifier-artifact-drift' 79
  run_operation V.load verifier
  [[ "$(sha256_file "${EXPERIMENTAL_OBJECT}")" == "${EXPERIMENTAL_SHA256}" ]] ||
    fail 'verifier-object-post-drift' 79
  assert_bpf_baseline V
  write_phase "${VERIFIER_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-load-v1' "gate_id=${GATE_ID}" \
    "experimental_sha256=${EXPERIMENTAL_SHA256}" "binary_sha256=${BINARY_SHA256}" \
    "launcher_sha256=${LAUNCHER_SHA256}" "runner_sha256=${RUNNER_SHA256}" \
    'manifest_contract=passed' 'verifier_load=passed' 'persistent_bpf_delta=zero'
  run_operation T.run packet-test-run
  /usr/bin/grep -F -- '--- SKIP:' "${EVIDENCE_ROOT}/T.run.out"
  case "$?" in
    1) ;;
    0) fail 'test-run-reported-unsupported' 79 ;;
    *) fail 'test-run-skip-evidence-read' 79 ;;
  esac
  [[ "$(sha256_file "${EXPERIMENTAL_OBJECT}")" == "${EXPERIMENTAL_SHA256}" ]] ||
    fail 'test-run-object-post-drift' 79
  assert_bpf_baseline T
  write_phase "${TEST_RUN_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-test-run-v1' "gate_id=${GATE_ID}" \
    "experimental_sha256=${EXPERIMENTAL_SHA256}" \
    'test=TestFakeTCPBPFPacketProbe' 'bpf_prog_test_run=passed' \
    'persistent_bpf_delta=zero' "reserved_pin=${RESERVED_PIN}" 'reserved_pin_state=absent'
}

run_gate() {
  validate_inputs
  ensure_prefix_and_stage
  snapshot_held_inputs
  create_audit_log
  c8_checksum_module_acquire L0 || fail 'module-lease-acquire' $?
  c8_checksum_module_run L1.module-absent "${MODULE_NAME}" \
    /usr/bin/test ! -e "/sys/module/${MODULE_NAME}" || fail 'module-preexists' $?
  validate_module_absent || fail 'module-preexists-shape' 78
  write_phase "${OWNER_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-owner-v1' "gate_id=${GATE_ID}" \
    "state_schema=${STATE_SCHEMA}" "commit=${COMMIT}" \
    "manifest_sha256=${MANIFEST_SHA256}" "bundle_sha256=${BUNDLE_SHA256}" \
    "snapshot_manifest=${SNAPSHOT_MANIFEST}" \
    "snapshot_manifest_identity=${SNAPSHOT_MANIFEST_IDENTITY}" \
    "snapshot_bundle=${SNAPSHOT_BUNDLE}" \
    "snapshot_bundle_identity=${SNAPSHOT_BUNDLE_IDENTITY}" \
    "history_commit_count=${HISTORY_COMMIT_COUNT}" \
    "history_roots_sha256=${HISTORY_ROOTS_SHA256}" \
    "history_objects_sha256=${HISTORY_OBJECTS_SHA256}" \
    "controller_source=${CONTROLLER_SOURCE}" "controller_script_sha256=${SELF_SHA256}" \
    "module_lease_helper=${MODULE_LEASE_HELPER}" \
    "module_lease_helper_sha256=${MODULE_LEASE_HELPER_SHA256}" \
    "module_lease_lock=${MODULE_LEASE_LOCK}" \
    "module_lease_lock_identity=${C8_CHECKSUM_MODULE_LOCK_IDENTITY}" \
    "module_lease_id=${MODULE_LEASE_ID}" \
    "boot_id=${BOOT_ID}" "initial_netns=${INITIAL_NETNS}" 'failure_policy=retain'
  create_fresh_source
  capture_tool_versions
  write_phase "${HOST_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-host-v1' "gate_id=${GATE_ID}" \
    'os_id=ubuntu' 'os_version=26.04' "kernel=${EXPECTED_KERNEL}" \
    "hostname=${EXPECTED_HOSTNAME}" "vmlinux_btf_sha256=${VMLINUX_BTF_SHA256}" \
    "bpffs_identity=${BPFFS_IDENTITY}" "reserved_pin=${RESERVED_PIN}" \
    'reserved_pin_state=absent'
  capture_bpf_baseline
  build_fresh_artifacts
  load_shared_module
  run_verifier_and_test_run
  write_phase "${COMPLETE_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-complete-v1' "gate_id=${GATE_ID}" \
    "commit=${COMMIT}" "experimental_sha256=${EXPERIMENTAL_SHA256}" \
    "module=${MODULE_NAME}" "module_lease_id=${MODULE_LEASE_ID}" \
    'module_state=shared-owned-loaded' \
    'verifier_load=passed' 'bpf_prog_test_run=passed' 'restore_required=1'
  printf 'B82_FRESH_VERIFIER_RUN_COMPLETE gate_id=%s commit=%s evidence=%s module=%s restore_required=1 automatic_cleanup=0\n' \
    "${GATE_ID}" "${COMMIT}" "${EVIDENCE_ROOT}" "${MODULE_NAME}"
}

validate_restore_state() {
  local canonical shape owner_commit owner_manifest owner_bundle path
  require_tools
  validate_controller_source || fail 'restore-controller-source' $?
  load_module_lease_helper || fail 'restore-module-lease-helper' $?
  hold_input_files || fail 'restore-manifest-bundle-hold' $?
  exec {MANIFEST_FD}<&-
  exec {BUNDLE_FD}<&-
  validate_snapshot_contract || fail 'restore-snapshot-contract' $?
  ((EUID == 0)) || fail 'restore-root-required' 77
  [[ "$(/usr/bin/hostname)" == "${EXPECTED_HOSTNAME}" &&
    "$(/usr/bin/uname -r)" == "${EXPECTED_KERNEL}" ]] || fail 'restore-host-identity' 79
  canonical="$(/usr/bin/readlink -e -- "${STAGE_ROOT}")" || fail 'restore-stage-canonical'
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${STAGE_ROOT}")" || fail 'restore-stage-stat'
  [[ "${canonical}" == "${STAGE_ROOT}" && "${shape}" == '0:0:700:directory' ]] ||
    fail 'restore-stage-identity' 79
  for path in "${AUDIT_LOG}" "${OWNER_PHASE}" "${BPF_BASELINE_PHASE}" \
    "${HISTORY_PHASE}" "${BUILD_PHASE}" \
    "${SNAPSHOT_MANIFEST}" "${SNAPSHOT_BUNDLE}" \
    "${HISTORY_ROOTS}" "${HISTORY_OBJECTS}" \
    "${EVIDENCE_ROOT}/A.progs.out" "${EVIDENCE_ROOT}/A.maps.out" \
    "${EVIDENCE_ROOT}/A.links.out" "${EVIDENCE_ROOT}/A.kwarn.out"; do
    validate_root_owned_file "${path}" 600 || fail "restore-evidence-identity:${path}" $?
  done
  owner_commit="$(phase_value "${OWNER_PHASE}" commit)" || fail 'restore-owner-commit'
  owner_manifest="$(phase_value "${OWNER_PHASE}" manifest_sha256)" || fail 'restore-owner-manifest'
  owner_bundle="$(phase_value "${OWNER_PHASE}" bundle_sha256)" || fail 'restore-owner-bundle'
  [[ "${owner_commit}" == "${COMMIT}" && "${owner_manifest}" == "${MANIFEST_SHA256}" &&
    "${owner_bundle}" == "${BUNDLE_SHA256}" &&
    "$(phase_value "${OWNER_PHASE}" snapshot_manifest)" == "${SNAPSHOT_MANIFEST}" &&
    "$(phase_value "${OWNER_PHASE}" snapshot_manifest_identity)" == "${SNAPSHOT_MANIFEST_IDENTITY}" &&
    "$(phase_value "${OWNER_PHASE}" snapshot_bundle)" == "${SNAPSHOT_BUNDLE}" &&
    "$(phase_value "${OWNER_PHASE}" snapshot_bundle_identity)" == "${SNAPSHOT_BUNDLE_IDENTITY}" &&
    "$(phase_value "${OWNER_PHASE}" history_commit_count)" == "${HISTORY_COMMIT_COUNT}" &&
    "$(phase_value "${OWNER_PHASE}" history_roots_sha256)" == "${HISTORY_ROOTS_SHA256}" &&
    "$(phase_value "${OWNER_PHASE}" history_objects_sha256)" == "${HISTORY_OBJECTS_SHA256}" &&
    "$(phase_value "${OWNER_PHASE}" module_lease_helper)" == "${MODULE_LEASE_HELPER}" &&
    "$(phase_value "${OWNER_PHASE}" module_lease_helper_sha256)" == "${MODULE_LEASE_HELPER_SHA256}" &&
    "$(phase_value "${OWNER_PHASE}" module_lease_lock)" == "${MODULE_LEASE_LOCK}" &&
    "$(phase_value "${OWNER_PHASE}" module_lease_id)" == "${MODULE_LEASE_ID}" &&
    "$(phase_value "${OWNER_PHASE}" boot_id)" == "$(/usr/bin/cat /proc/sys/kernel/random/boot_id)" &&
    "$(phase_value "${OWNER_PHASE}" initial_netns)" == "$(/usr/bin/readlink /proc/self/ns/net)" ]] ||
    fail 'restore-owner-binding' 79
  MODULE_SHA256="$(phase_value "${BUILD_PHASE}" module_sha256)" || fail 'restore-module-sha'
  MODULE_SRCVERSION="$(phase_value "${BUILD_PHASE}" module_srcversion)" || fail 'restore-module-srcversion'
  [[ "$(sha256_file "${MODULE_OBJECT}")" == "${MODULE_SHA256}" &&
    "$(phase_value "${BUILD_PHASE}" module_srcversion)" == "${MODULE_SRCVERSION}" ]] ||
    fail 'restore-module-artifact-binding' 79
  [[ "$(sha256_file "${EVIDENCE_ROOT}/A.progs.out")" == \
      "$(phase_value "${BPF_BASELINE_PHASE}" programs_sha256)" &&
    "$(sha256_file "${EVIDENCE_ROOT}/A.maps.out")" == \
      "$(phase_value "${BPF_BASELINE_PHASE}" maps_sha256)" &&
    "$(sha256_file "${EVIDENCE_ROOT}/A.links.out")" == \
      "$(phase_value "${BPF_BASELINE_PHASE}" links_sha256)" &&
    "$(sha256_file "${EVIDENCE_ROOT}/A.kwarn.out")" == \
      "$(phase_value "${BPF_BASELINE_PHASE}" kernel_warnings_sha256)" ]] ||
    fail 'restore-bpf-baseline-binding' 79
  [[ "$(sha256_file "${HISTORY_ROOTS}")" == "${HISTORY_ROOTS_SHA256}" &&
    "$(sha256_file "${HISTORY_OBJECTS}")" == "${HISTORY_OBJECTS_SHA256}" &&
    "$(phase_value "${HISTORY_PHASE}" format)" == \
      'wg-mix-ebpf-b82-fresh-verifier-history-v1' &&
    "$(phase_value "${HISTORY_PHASE}" gate_id)" == "${GATE_ID}" &&
    "$(phase_value "${HISTORY_PHASE}" commit)" == "${COMMIT}" &&
    "$(phase_value "${HISTORY_PHASE}" repository_shallow)" == 'false' &&
    "$(phase_value "${HISTORY_PHASE}" history_verification)" == "${HISTORY_VERIFICATION}" &&
    "$(phase_value "${HISTORY_PHASE}" history_commit_count)" == "${HISTORY_COMMIT_COUNT}" &&
    "$(phase_value "${HISTORY_PHASE}" history_roots_sha256)" == "${HISTORY_ROOTS_SHA256}" &&
    "$(phase_value "${HISTORY_PHASE}" history_objects_sha256)" == "${HISTORY_OBJECTS_SHA256}" &&
    "$(phase_value "${HISTORY_PHASE}" strict_fsck)" == 'passed' ]] ||
    fail 'restore-history-binding' 79
}

restore_gate() {
  local baseline_phase_sha owner_boot owner_lock_identity already_restored=0
  validate_restore_state
  c8_checksum_module_acquire R.lease || fail 'restore-module-lease-acquire' $?
  owner_lock_identity="$(phase_value "${OWNER_PHASE}" module_lease_lock_identity)" ||
    fail 'restore-module-lease-lock-owner'
  [[ "${C8_CHECKSUM_MODULE_LOCK_IDENTITY}" == "${owner_lock_identity}" ]] ||
    fail 'restore-module-lease-lock-drift' 79
  c8_checksum_module_configure "${CONTROLLER_RUN_ID}" "${MODULE_RESOURCE_ID}" \
    "${COMMIT}" "$(phase_value "${OWNER_PHASE}" boot_id)" "${EVIDENCE_ROOT}" \
    "${MODULE_OBJECT}" "${MODULE_SHA256}" || fail 'restore-module-lease-configure' $?
  [[ "${C8_CHECKSUM_MODULE_LEASE_ID}" == "${MODULE_LEASE_ID}" &&
    "${C8_CHECKSUM_MODULE_SRCVERSION}" == "${MODULE_SRCVERSION}" ]] ||
    fail 'restore-module-lease-binding' 79
  owner_boot="$(phase_value "${OWNER_PHASE}" boot_id)" || fail 'restore-intent-boot'
  baseline_phase_sha="$(sha256_file "${BPF_BASELINE_PHASE}")" || fail 'restore-intent-baseline-sha'
  ensure_phase "${RESTORE_INTENT_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-restore-intent-v1' "gate_id=${GATE_ID}" \
    "commit=${COMMIT}" "boot_id=${owner_boot}" \
    "module=${MODULE_NAME}" "module_sha256=${MODULE_SHA256}" \
    "module_srcversion=${MODULE_SRCVERSION}" "module_lease_id=${MODULE_LEASE_ID}" \
    "module_lease_lock=${MODULE_LEASE_LOCK}" \
    "module_lease_lock_identity=${C8_CHECKSUM_MODULE_LOCK_IDENTITY}" \
    "module_lease_helper_sha256=${MODULE_LEASE_HELPER_SHA256}" \
    'reverse_helper=c8_checksum_module_restore' \
    "bpf_baseline_sha256=${baseline_phase_sha}" 'state=restoring'
  if [[ -e "${RESTORED_PHASE}" || -L "${RESTORED_PHASE}" ]]; then
    ensure_phase "${RESTORED_PHASE}" \
      'format=wg-mix-ebpf-b82-fresh-verifier-restored-v1' "gate_id=${GATE_ID}" \
      "commit=${COMMIT}" "module=${MODULE_NAME}" 'module_state=absent' \
      'persistent_bpf_delta=zero' "reserved_pin=${RESERVED_PIN}" 'reserved_pin_state=absent'
    already_restored=1
  fi
  c8_checksum_module_restore R.module || fail 'restore-module-lease' $?
  validate_module_absent || fail 'restore-module-remains' 79
  assert_bpf_baseline_convergent R.final
  ensure_phase "${RESTORED_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-restored-v1' "gate_id=${GATE_ID}" \
    "commit=${COMMIT}" "module=${MODULE_NAME}" 'module_state=absent' \
    'persistent_bpf_delta=zero' "reserved_pin=${RESERVED_PIN}" 'reserved_pin_state=absent'
  ensure_phase "${FILESYSTEM_PHASE}" \
    'format=wg-mix-ebpf-b82-fresh-verifier-filesystem-v1' "gate_id=${GATE_ID}" \
    "stage=${STAGE_ROOT}" "evidence=${EVIDENCE_ROOT}" 'state=retained' 'automatic_cleanup=0'
  printf 'B82_FRESH_VERIFIER_RESTORE_COMPLETE gate_id=%s module=%s state=absent evidence=%s filesystem_retained=1 already_restored=%s\n' \
    "${GATE_ID}" "${MODULE_NAME}" "${EVIDENCE_ROOT}" "${already_restored}"
}

main() {
  parse_arguments "$@" || fail 'arguments' $?
  case "${MODE}" in
    plan) render_plan ;;
    run) run_gate ;;
    restore) restore_gate ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
