#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly EVIDENCE_ID='6bd913ac'
readonly EXPECTED_SOURCE="/run/wg-mix-ebpf-source-stages/${RUN_ID}/source"
readonly EXPECTED_BUNDLE="/home/siyixuan/wg-mix-ebpf-test/unpriv-${PACKAGE_ID}/source-${PACKAGE_ID}.bundle"
readonly STAGE_ROOT="/run/wg-mix-ebpf-source-stages/${RUN_ID}"
readonly EVIDENCE_ROOT="${STAGE_ROOT}/realhost-v6-${EVIDENCE_ID}"
readonly OWNER_MARKER="${EVIDENCE_ROOT}/owner.v1"
readonly AUDIT_LOG="${EVIDENCE_ROOT}/audit.log"
readonly NIC_STATE="${EVIDENCE_ROOT}/nic-original.v1"
readonly NETNS_STATE="${EVIDENCE_ROOT}/initial-netns.v1"
readonly VETH_STATE="${EVIDENCE_ROOT}/veth-owned.v1"
readonly MODULE_INTENT="${EVIDENCE_ROOT}/checksum-module-intent.v1"
readonly MODULE_LOADED="${EVIDENCE_ROOT}/checksum-module-owned.v1"
readonly MODULE_UNLOADED="${EVIDENCE_ROOT}/checksum-module-unloaded.v1"
readonly RESTORED_MARKER="${EVIDENCE_ROOT}/restored.v1"
readonly PIN_PATH="/sys/fs/bpf/wg-mix-ebpf-${RUN_ID}-tcx"
readonly TCX_RUNTIME_ROOT="${EVIDENCE_ROOT}/tcx-runtime"
readonly SCOPED_RESTORE_TEST_NAME='TestScopedRealNICDataplaneRestoreIntegration'
readonly SCOPED_CONTRACT_TEST_NAME='TestScopedRealNICContextIsolationContract'
readonly VETH_A='wgc8e41a'
readonly VETH_B='wgc8e41b'
readonly VETH_A_ALIAS="wg-mix-ebpf:${RUN_ID}:a"
readonly VETH_B_ALIAS="wg-mix-ebpf:${RUN_ID}:b"
readonly MODULE_NAME='wg_mix_faketcp_checksum'
readonly MODULE_OBJECT="${EXPECTED_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-${RUN_ID}/checksum-module-lease.sh"
readonly MODULE_LEASE_HELPER="${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_RELATIVE}"
readonly MODULE_LEASE_LOCK="${STAGE_ROOT}/checksum-module-lease.v1.lock"
readonly MODULE_LEASE_ID="${RUN_ID}-${EVIDENCE_ID}"
readonly PHYSICAL_INTERFACE_LOCK='/run/wg-mix-ebpf-realnic-physical-interface.v1.lock'
readonly PHYSICAL_INTERFACE_LOCK_INTERFACE='ens33'
readonly EXPECTED_HOSTNAME='ubuntu-2604-test'
readonly EXPECTED_KERNEL='7.0.0-28-generic'
readonly EXPECTED_MACHINE_ID='9db3fb717cc74974b2a6b243d67f67b9'
readonly EXPECTED_INTERFACE='ens33'
readonly EXPECTED_PEER='47.116.202.155'
readonly EXPECTED_PEER_PORT='5201'
readonly EXPECTED_SOAK_SECONDS='3600'
readonly EXPECTED_SESSION_SECONDS='300'

MODE=''
SOURCE=''
COMMIT=''
BUNDLE=''
BUNDLE_SHA256=''
INTERFACE=''
PEER_ADDRESS=''
PEER_PORT=''
SOAK_SECONDS=''
SESSION_SECONDS=''
WG_INTERFACE=''
WG_LOCAL_ADDRESS=''
WG_PEER_ADDRESS=''
RESTORE_CELL=''
STEP_RC=125
STEP_LOG=''
ORIGINAL_BOOT_ID=''
ORIGINAL_IFINDEX=''
ORIGINAL_MAC=''
ORIGINAL_MTU=''
VETH_A_IFINDEX=''
VETH_B_IFINDEX=''
INITIAL_NETNS=''
PHYSICAL_INTERFACE_LOCK_FD=''

readonly -a FEATURE_NAMES=(
  rx-checksumming
  tx-checksumming
  generic-segmentation-offload
  generic-receive-offload
  tcp-segmentation-offload
  tx-udp-segmentation
  rx-udp-gro-forwarding
)

usage() {
  printf '%s\n' \
    "usage: $0 {plan|run|restore} --source ${EXPECTED_SOURCE} --commit 40hex" \
    "  --bundle ${EXPECTED_BUNDLE} --bundle-sha256 64hex" \
    "  --interface ${EXPECTED_INTERFACE} --peer-address ${EXPECTED_PEER}" \
    "  --peer-port ${EXPECTED_PEER_PORT} --soak-seconds ${EXPECTED_SOAK_SECONDS}" \
    "  --session-seconds ${EXPECTED_SESSION_SECONDS}" \
    '  --wg-interface IFNAME --wg-local-address IPV4 --wg-peer-address IPV4' \
    '  --restore-cell {none|tcx|original|all-on|all-off|tx-path|rx-path|mtu1492|mtu1500|soak}' >&2
}

fail() {
  local reason="$1"
  local rc="${2:-125}"
  printf 'REALHOST_V6_STOP run_id=%s reason=%s rc=%s evidence=%s; no automatic teardown\n' \
    "${RUN_ID}" "${reason}" "${rc}" "${EVIDENCE_ROOT}" >&2
  exit "${rc}"
}

valid_commit() {
  local value="$1"
  [[ "${value}" =~ ^[0-9a-f]{40}$ &&
    ! "${value}" =~ ^0{40}$ && ! "${value}" =~ ^f{40}$ ]]
}

valid_sha256() {
  local value="$1"
  [[ "${value}" =~ ^[0-9a-f]{64}$ &&
    ! "${value}" =~ ^0{64}$ && ! "${value}" =~ ^f{64}$ ]]
}

valid_interface_name() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ &&
    "${value}" != '.' && "${value}" != '..' ]]
}

valid_unicast_ipv4() {
  local value="$1"
  local first second third fourth extra octet number
  IFS=. read -r first second third fourth extra <<<"${value}"
  [[ -z "${extra}" && -n "${first}" && -n "${second}" &&
    -n "${third}" && -n "${fourth}" ]] || return 1
  [[ "${value}" == "${first}.${second}.${third}.${fourth}" ]] || return 1
  for octet in "${first}" "${second}" "${third}" "${fourth}"; do
    [[ "${octet}" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    number=$((10#${octet}))
    ((number <= 255)) || return 1
  done
  number=$((10#${first}))
  ((number >= 1 && number <= 223 && number != 127)) || return 1
  [[ "${value}" != '255.255.255.255' ]]
}

parse_arguments() {
  (($# >= 1)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in
    plan | run | restore) ;;
    *) usage; return 64 ;;
  esac
  while (($# > 0)); do
    (($# >= 2)) || { usage; return 64; }
    case "$1" in
      --source) SOURCE="$2" ;;
      --commit) COMMIT="$2" ;;
      --bundle) BUNDLE="$2" ;;
      --bundle-sha256) BUNDLE_SHA256="$2" ;;
      --interface) INTERFACE="$2" ;;
      --peer-address) PEER_ADDRESS="$2" ;;
      --peer-port) PEER_PORT="$2" ;;
      --soak-seconds) SOAK_SECONDS="$2" ;;
      --session-seconds) SESSION_SECONDS="$2" ;;
      --wg-interface) WG_INTERFACE="$2" ;;
      --wg-local-address) WG_LOCAL_ADDRESS="$2" ;;
      --wg-peer-address) WG_PEER_ADDRESS="$2" ;;
      --restore-cell) RESTORE_CELL="$2" ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  [[ "${SOURCE}" == "${EXPECTED_SOURCE}" ]] || return 65
  [[ "${BUNDLE}" == "${EXPECTED_BUNDLE}" ]] || return 65
  [[ "${INTERFACE}" == "${EXPECTED_INTERFACE}" ]] || return 65
  [[ "${PEER_ADDRESS}" == "${EXPECTED_PEER}" ]] || return 65
  [[ "${PEER_PORT}" == "${EXPECTED_PEER_PORT}" ]] || return 65
  [[ "${SOAK_SECONDS}" == "${EXPECTED_SOAK_SECONDS}" ]] || return 65
  [[ "${SESSION_SECONDS}" == "${EXPECTED_SESSION_SECONDS}" ]] || return 65
  valid_commit "${COMMIT}" || return 65
  valid_sha256 "${BUNDLE_SHA256}" || return 65
  valid_interface_name "${WG_INTERFACE}" &&
  [[
    "${WG_INTERFACE}" != "${INTERFACE}" && "${WG_INTERFACE}" != "${VETH_A}" &&
    "${WG_INTERFACE}" != "${VETH_B}" ]] || return 65
  valid_unicast_ipv4 "${WG_LOCAL_ADDRESS}" || return 65
  valid_unicast_ipv4 "${WG_PEER_ADDRESS}" || return 65
  [[ "${WG_LOCAL_ADDRESS}" != "${WG_PEER_ADDRESS}" ]] || return 65
  case "${MODE}:${RESTORE_CELL}" in
    plan:none | run:none | restore:none | restore:tcx | restore:original | restore:all-on | restore:all-off | \
      restore:tx-path | restore:rx-path | restore:mtu1492 | restore:mtu1500 | restore:soak) ;;
    *) return 65 ;;
  esac
}

quote_argv() {
  printf '%q ' "$@"
}

plan_command() {
  local label="$1"
  shift
  printf '%s argv=' "${label}"
  quote_argv "$@"
  printf '\n'
}

render_plan() {
  local cell
  local -a common=(
    --source "${SOURCE}"
    --commit "${COMMIT}"
    --bundle "${BUNDLE}"
    --bundle-sha256 "${BUNDLE_SHA256}"
    --interface "${INTERFACE}"
    --peer-address "${PEER_ADDRESS}"
    --peer-port "${PEER_PORT}"
    --soak-seconds "${SOAK_SECONDS}"
    --session-seconds "${SESSION_SECONDS}"
    --wg-interface "${WG_INTERFACE}"
    --wg-local-address "${WG_LOCAL_ADDRESS}"
    --wg-peer-address "${WG_PEER_ADDRESS}"
  )
  printf 'REALHOST_V6_PLAN_ONLY run_id=%s package_id=%s evidence_id=%s commit=%s bundle_sha256=%s\n' \
    "${RUN_ID}" "${PACKAGE_ID}" "${EVIDENCE_ID}" "${COMMIT}" "${BUNDLE_SHA256}"
  printf '%s\n' \
    'REALHOST_V6_FORWARD_AUTHORITY state=retired replacement=realnic-acceptance' \
    'REALHOST_V6_PLAN_SCOPE restore-only=1 network-writes-executed=0 filesystem-writes-executed=0'
  printf 'REALHOST_V6_PHYSICAL_INTERFACE_LOCK path=%s interface=%s shape=root:root:600:1:0:regular-file order=physical-interface-before-checksum-module\n' \
    "${PHYSICAL_INTERFACE_LOCK}" "${PHYSICAL_INTERFACE_LOCK_INTERFACE}"
  for cell in tcx original all-on all-off tx-path rx-path mtu1492 mtu1500 soak; do
    plan_command "restore-${cell}" /bin/bash -p \
      "${SOURCE}/scripts/realhost-b82-${RUN_ID}/root-matrix-n-r.sh" restore \
      "${common[@]}" --restore-cell "${cell}"
  done
  printf 'REALHOST_V6_PLAN_COMPLETE restore_entries=9 no_commands_executed=1\n'
}

utc_now() {
  /bin/date -u '+%Y-%m-%dT%H:%M:%SZ'
}

audit_line() {
  local event="$1"
  local step="$2"
  local target="$3"
  local rc="$4"
  local rendered="$5"
  local timestamp
  timestamp="$(utc_now)" || return $?
  [[ "${timestamp}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 79
  printf 'utc=%q event=%q step=%q target=%q rc=%q argv=%q\n' \
    "${timestamp}" "${event}" "${step}" "${target}" "${rc}" "${rendered}" |
    /usr/bin/tee -a "${AUDIT_LOG}"
  local -a status=("${PIPESTATUS[@]}")
  ((${#status[@]} == 2 && status[0] == 0 && status[1] == 0))
}

run_step() {
  local step="$1"
  local target="$2"
  local rendered evidence_rendered
  local -a status
  shift 2
  STEP_LOG="${EVIDENCE_ROOT}/${step}.out"
  [[ "${step}" =~ ^[A-Z][A-Za-z0-9_.-]{0,95}$ ]] || fail "invalid-step:${step}" 64
  [[ ! -e "${STEP_LOG}" && ! -L "${STEP_LOG}" ]] || fail "step-output-exists:${step}" 78
  rendered="$(quote_argv "$@")" || fail "render:${step}"
  evidence_rendered="$(quote_argv /usr/bin/tee "${STEP_LOG}")" || fail "render-evidence:${step}"
  audit_line start "${step}" "${target}" not-run "${rendered}" || fail "audit-start:${step}"
  audit_line start "${step}.evidence" "${STEP_LOG}" not-run "${evidence_rendered}" ||
    fail "audit-evidence-start:${step}"
  "$@" 2>&1 | /usr/bin/tee "${STEP_LOG}"
  status=("${PIPESTATUS[@]}")
  ((${#status[@]} == 2)) || fail "pipeline-status:${step}"
  STEP_RC="${status[0]}"
  audit_line finish "${step}" "${target}" "${STEP_RC}" "${rendered}" || fail "audit-finish:${step}"
  audit_line finish "${step}.evidence" "${STEP_LOG}" "${status[1]}" "${evidence_rendered}" ||
    fail "audit-evidence-finish:${step}"
  ((status[1] == 0)) || fail "evidence-write:${step}:rc=${status[1]}" "${status[1]}"
}

require_zero() {
  local step="$1"
  ((STEP_RC == 0)) || fail "${step}:rc=${STEP_RC}" "${STEP_RC}"
}

write_once() {
  local path="$1"
  local step rendered rc
  shift
  [[ "${path}" == "${EVIDENCE_ROOT}/"* && "${path#${EVIDENCE_ROOT}/}" != */* ]] ||
    fail "write-scope:${path}" 65
  [[ ! -e "${path}" && ! -L "${path}" ]] || fail "write-exists:${path}" 78
  step="write-$(/usr/bin/basename -- "${path}")"
  rendered="$(quote_argv shell-builtin printf '%s\n' "$@")>$(quote_argv "${path}")" ||
    fail "render-write:${path}"
  audit_line start "${step}" "${path}" not-run "${rendered}" || fail "audit-write-start:${path}"
  set -o noclobber
  printf '%s\n' "$@" >"${path}"
  rc=$?
  set +o noclobber
  audit_line finish "${step}" "${path}" "${rc}" "${rendered}" || fail "audit-write-finish:${path}"
  ((rc == 0)) || fail "write:${path}:rc=${rc}" "${rc}"
}

require_tooling() {
  local path
  local -a tools=(
    /bin/bash /bin/date
    /usr/bin/awk /usr/bin/basename /usr/bin/cat /usr/bin/cmp /usr/bin/env
    /usr/bin/git /usr/bin/go /usr/bin/grep /usr/bin/hostname
    /usr/bin/flock /usr/bin/readlink /usr/bin/sha256sum /usr/bin/stat /usr/bin/tee
    /usr/bin/test /usr/bin/timeout /usr/bin/uname
    /usr/sbin/bpftool /usr/sbin/ethtool /usr/sbin/ip /usr/sbin/modinfo
    /usr/sbin/lsmod /usr/sbin/rmmod /usr/sbin/tc
  )
  for path in "${tools[@]}"; do
    [[ -x "${path}" ]] || fail "missing-tool:${path}" 69
  done
}

require_physical_interface_lock() {
  [[ "${INTERFACE}" == "${PHYSICAL_INTERFACE_LOCK_INTERFACE}" ]] || fail 'physical-interface-lock-scope' 79
  [[ -f "${PHYSICAL_INTERFACE_LOCK}" && ! -L "${PHYSICAL_INTERFACE_LOCK}" ]] ||
    fail 'physical-interface-lock-shape' 79
  [[ "$(/usr/bin/stat -Lc '%U:%G:%a:%h:%s:%F' -- "${PHYSICAL_INTERFACE_LOCK}")" == \
    'root:root:600:1:0:regular file' ]] || fail 'physical-interface-lock-metadata' 79
}

acquire_physical_interface_lock() {
  local descriptor_shape path_identity descriptor_identity
  require_physical_interface_lock
  exec {PHYSICAL_INTERFACE_LOCK_FD}<>"${PHYSICAL_INTERFACE_LOCK}" ||
    fail 'physical-interface-lock-open' 79
  descriptor_shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%s:%F' -- \
    "/proc/self/fd/${PHYSICAL_INTERFACE_LOCK_FD}")" || fail 'physical-interface-lock-fd-stat' 79
  [[ "${descriptor_shape}" == 'root:root:600:1:0:regular file' ]] ||
    fail 'physical-interface-lock-fd-metadata' 79
  path_identity="$(/usr/bin/stat -Lc '%d:%i' -- "${PHYSICAL_INTERFACE_LOCK}")" ||
    fail 'physical-interface-lock-path-identity' 79
  descriptor_identity="$(/usr/bin/stat -Lc '%d:%i' -- "/proc/self/fd/${PHYSICAL_INTERFACE_LOCK_FD}")" ||
    fail 'physical-interface-lock-fd-identity' 79
  [[ "${path_identity}" == "${descriptor_identity}" ]] || fail 'physical-interface-lock-replaced' 79
  /usr/bin/flock --exclusive --nonblock "${PHYSICAL_INTERFACE_LOCK_FD}" ||
    fail 'physical-interface-authority-busy' 78
  require_physical_interface_lock
  [[ "$(/usr/bin/stat -Lc '%d:%i' -- "${PHYSICAL_INTERFACE_LOCK}")" == "${descriptor_identity}" ]] ||
    fail 'physical-interface-lock-replaced-after-acquire' 79
}

read_single_line() {
  local path="$1"
  local value
  value="$(/usr/bin/cat -- "${path}")" || return $?
  [[ -n "${value}" && "${value}" != *$'\n'* ]] || return 79
  printf '%s\n' "${value}"
}

validate_common_identity() {
  local actual canonical sha_line head dirty stage_stat bundle_stat
  ((EUID == 0)) || fail 'root-required' 77
  canonical="$(/usr/bin/readlink -e -- "${STAGE_ROOT}")" || fail 'stage-canonical'
  [[ "${canonical}" == "${STAGE_ROOT}" ]] || fail 'stage-path-changed' 79
  stage_stat="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${STAGE_ROOT}")" || fail 'stage-stat'
  [[ "${stage_stat}" == '0:0:700:directory' ]] || fail 'stage-shape' 79
  canonical="$(/usr/bin/readlink -e -- "${SOURCE}")" || fail 'source-canonical'
  [[ "${canonical}" == "${EXPECTED_SOURCE}" ]] || fail 'source-path-changed' 79
  canonical="$(/usr/bin/readlink -e -- "${BUNDLE}")" || fail 'bundle-canonical'
  [[ "${canonical}" == "${EXPECTED_BUNDLE}" ]] || fail 'bundle-path-changed' 79
  bundle_stat="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${BUNDLE}")" || fail 'bundle-stat'
  [[ "${bundle_stat}" == 'siyixuan:siyixuan:600:1:regular file' ]] || fail 'bundle-shape' 79
  sha_line="$(/usr/bin/sha256sum -- "${BUNDLE}")" || fail 'bundle-hash'
  [[ "${sha_line}" == "${BUNDLE_SHA256}  ${BUNDLE}" ]] || fail 'bundle-hash-mismatch' 79
  head="$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git --no-pager --no-replace-objects -c core.attributesFile=/dev/null \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null -C "${SOURCE}" \
    rev-parse --verify HEAD)" || fail 'source-head'
  [[ "${head}" == "${COMMIT}" ]] || fail 'source-head-mismatch' 79
  dirty="$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/git --no-pager --no-replace-objects -c core.attributesFile=/dev/null \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null -C "${SOURCE}" \
    status --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || fail 'source-status'
  [[ -z "${dirty}" ]] || fail 'source-dirty' 79
  actual="$(/usr/bin/hostname)" || fail 'hostname-read'
  [[ "${actual}" == "${EXPECTED_HOSTNAME}" ]] || fail 'hostname-mismatch' 79
  actual="$(/usr/bin/uname -r)" || fail 'kernel-read'
  [[ "${actual}" == "${EXPECTED_KERNEL}" ]] || fail 'kernel-mismatch' 79
  actual="$(read_single_line /etc/machine-id)" || fail 'machine-id-read'
  [[ "${actual}" == "${EXPECTED_MACHINE_ID}" ]] || fail 'machine-id-mismatch' 79
  [[ -f "${MODULE_LEASE_HELPER}" && ! -L "${MODULE_LEASE_HELPER}" ]] ||
    fail 'module-lease-helper-shape' 79
}

load_checksum_module_helper() {
  # shellcheck source=checksum-module-lease.sh
  source "${MODULE_LEASE_HELPER}" || fail 'module-lease-helper-source' $?
  [[ "${C8_CHECKSUM_MODULE_LOCK}" == "${MODULE_LEASE_LOCK}" ]] ||
    fail 'module-lease-helper-lock-contract' 79
}

run_module_lease_argv() {
  local label="$1" target="$2" rendered rc
  local -a status
  shift 2
  rendered="$(quote_argv "$@")" || fail "module-lease-render:${label}"
  audit_line start "${label}" "${target}" not-run "${rendered}" || fail "module-lease-audit-start:${label}"
  "$@" 2>&1 | /usr/bin/tee -a "${AUDIT_LOG}"
  status=("${PIPESTATUS[@]}")
  ((${#status[@]} == 2)) || fail "module-lease-pipeline:${label}"
  rc="${status[0]}"
  audit_line finish "${label}" "${target}" "${rc}" "${rendered}" || fail "module-lease-audit-finish:${label}"
  ((status[1] == 0)) || fail "module-lease-output:${label}" "${status[1]}"
  return "${rc}"
}

c8_checksum_module_run() {
  run_module_lease_argv "$@"
}

c8_checksum_module_write() {
  write_once "$1" "$2"
}

c8_checksum_module_fail() {
  fail "checksum-module-lease:$1" "$2"
}

configure_checksum_module_lease() {
  local module_sha
  module_sha="$(c8_checksum_module_sha_file "${MODULE_OBJECT}")" || fail 'module-lease-object-sha' $?
  c8_checksum_module_configure "${RUN_ID}" "${EVIDENCE_ID}" "${COMMIT}" \
    "${ORIGINAL_BOOT_ID}" "${EVIDENCE_ROOT}" "${MODULE_OBJECT}" "${module_sha}" ||
    fail 'module-lease-configure' $?
  [[ "${C8_CHECKSUM_MODULE_LEASE_ID}" == "${MODULE_LEASE_ID}" &&
    "${C8_CHECKSUM_MODULE_INTENT}" == "${MODULE_INTENT}" &&
    "${C8_CHECKSUM_MODULE_OWNED}" == "${MODULE_LOADED}" &&
    "${C8_CHECKSUM_MODULE_UNLOADED}" == "${MODULE_UNLOADED}" ]] ||
    fail 'module-lease-binding-contract' 79
}

feature_line() {
  local source="$1"
  local feature="$2"
  /usr/bin/awk -v key="${feature}:" '$1 == key {print $2 " " ($3 == "[fixed]" ? "fixed" : "mutable")}' "${source}"
}

current_interface_identity() {
  local ifindex mac
  ifindex="$(read_single_line "/sys/class/net/${INTERFACE}/ifindex")" || return $?
  mac="$(read_single_line "/sys/class/net/${INTERFACE}/address")" || return $?
  [[ "${ifindex}" == "${ORIGINAL_IFINDEX}" && "${mac}" == "${ORIGINAL_MAC}" ]]
}

feature_original() {
  local feature="$1"
  /usr/bin/awk -v wanted="${feature}" '
    $1 == "feature=" wanted {
      split($2, value, "="); split($3, mutability, "=");
      print value[2] " " mutability[2]
    }
  ' "${NIC_STATE}"
}

set_feature() {
  local step="$1" feature="$2" desired="$3"
  local original current
  original="$(feature_original "${feature}")" || fail "original-feature:${feature}"
  [[ -n "${original}" ]] || fail "missing-original-feature:${feature}" 79
  if [[ "${original}" == 'unsupported unsupported' || "${original}" == *' fixed' ]]; then
    audit_line unsupported "${step}" "${feature}" 0 "feature immutable or unavailable" || fail "audit:${step}"
    return 0
  fi
  run_step "${step}" "${INTERFACE}:${feature}" /usr/sbin/ethtool -K "${INTERFACE}" "${feature}" "${desired}"
  require_zero "${step}"
  run_step "${step}.verify" "${INTERFACE}:${feature}" /usr/sbin/ethtool -k "${INTERFACE}"
  require_zero "${step}.verify"
  current="$(feature_line "${STEP_LOG}" "${feature}")" || fail "verify-feature:${feature}"
  [[ "${current}" == "${desired} mutable" ]] || fail "feature-not-applied:${feature}" 79
}

verify_full_feature_restore() {
  local prefix="$1"
  run_step "${prefix}.all-features" "${INTERFACE}" /usr/sbin/ethtool -k "${INTERFACE}"
  require_zero "${prefix}.all-features"
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A7.out" "${STEP_LOG}" ||
    fail "${prefix}:complete-offload-state-drift" 79
}

restore_nic_state() {
  local prefix="$1"
  local feature original desired mutability
  current_interface_identity || fail "${prefix}:interface-identity" 79
  for feature in "${FEATURE_NAMES[@]}"; do
    original="$(feature_original "${feature}")" || fail "${prefix}:feature-read:${feature}"
    read -r desired mutability <<<"${original}"
    if [[ "${desired}" == 'unsupported' && "${mutability}" == 'unsupported' ]]; then
      continue
    fi
    [[ "${desired}" =~ ^(on|off)$ && "${mutability}" =~ ^(fixed|mutable)$ ]] ||
      fail "${prefix}:feature-record:${feature}" 79
    if [[ "${mutability}" == 'mutable' ]]; then
      set_feature "${prefix}.${feature}" "${feature}" "${desired}"
    fi
  done
  run_step "${prefix}.mtu" "${INTERFACE}" /usr/sbin/ip link set dev "${INTERFACE}" mtu "${ORIGINAL_MTU}"
  require_zero "${prefix}.mtu"
  current_interface_identity || fail "${prefix}:post-identity" 79
  [[ "$(read_single_line "/sys/class/net/${INTERFACE}/mtu")" == "${ORIGINAL_MTU}" ]] ||
    fail "${prefix}:mtu-not-restored" 79
  verify_full_feature_restore "${prefix}"
}

go_test_exists() {
  local step="$1" name="$2"
  run_step "${step}.list" "${name}" /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${STAGE_ROOT}/go-cache-realhost" GOENV=off GOFLAGS= \
    GOMODCACHE="${STAGE_ROOT}/go-mod-cache-realhost" GOPATH="${STAGE_ROOT}/go-path-realhost" \
    GOTMPDIR="${STAGE_ROOT}/go-tmp-realhost" GOWORK=off GO111MODULE=on TMPDIR="${STAGE_ROOT}/go-tmp-realhost" \
    /usr/bin/timeout --signal=TERM --kill-after=10s 5m /usr/bin/go -C "${SOURCE}" \
    test ./internal/dataplane -list "^${name}$"
  require_zero "${step}.list"
  /usr/bin/grep -Fxq -- "${name}" "${STEP_LOG}" || fail "missing-integration-test:${name}" 79
}

verify_owned_veth() {
  local name="$1" expected_ifindex="$2" expected_alias="$3"
  local ifindex alias
  ifindex="$(read_single_line "/sys/class/net/${name}/ifindex")" || return $?
  alias="$(read_single_line "/sys/class/net/${name}/ifalias")" || return $?
  [[ "${ifindex}" == "${expected_ifindex}" && "${alias}" == "${expected_alias}" ]]
}

delete_owned_veth() {
  local prefix="${1:-O9}"
  verify_owned_veth "${VETH_A}" "${VETH_A_IFINDEX}" "${VETH_A_ALIAS}" || fail 'veth-a-ownership-changed' 79
  verify_owned_veth "${VETH_B}" "${VETH_B_IFINDEX}" "${VETH_B_ALIAS}" || fail 'veth-b-ownership-changed' 79
  run_step "${prefix}" "${VETH_A}" /usr/sbin/ip link delete dev "${VETH_A}"
  require_zero "${prefix}"
  run_step "${prefix}.verify-a" "${VETH_A}" /usr/sbin/ip link show dev "${VETH_A}"
  ((STEP_RC == 1)) || fail "veth-a-delete-verify:rc=${STEP_RC}" 79
  run_step "${prefix}.verify-b" "${VETH_B}" /usr/sbin/ip link show dev "${VETH_B}"
  ((STEP_RC == 1)) || fail "veth-b-delete-verify:rc=${STEP_RC}" 79
  write_once "${EVIDENCE_ROOT}/veth-deleted.v1" "run_id=${RUN_ID}" 'status=deleted'
}

restore_exact_tcx_lifecycle() {
  [[ -d "${TCX_RUNTIME_ROOT}" && ! -L "${TCX_RUNTIME_ROOT}" ]] || fail 'tcx-runtime-missing' 79
  [[ -f "${VETH_STATE}" && ! -L "${VETH_STATE}" ]] || fail 'tcx-veth-state-missing' 79
  VETH_A_IFINDEX="$(/usr/bin/awk -F= '$1 == "a_ifindex" {print $2}' "${VETH_STATE}")" ||
    fail 'tcx-restore-veth-a'
  VETH_B_IFINDEX="$(/usr/bin/awk -F= '$1 == "b_ifindex" {print $2}' "${VETH_STATE}")" ||
    fail 'tcx-restore-veth-b'
  [[ "${VETH_A_IFINDEX}" =~ ^[1-9][0-9]*$ && "${VETH_B_IFINDEX}" =~ ^[1-9][0-9]*$ ]] ||
    fail 'tcx-restore-veth-ifindex' 79
  verify_owned_veth "${VETH_A}" "${VETH_A_IFINDEX}" "${VETH_A_ALIAS}" || fail 'tcx-veth-a-changed' 79
  verify_owned_veth "${VETH_B}" "${VETH_B_IFINDEX}" "${VETH_B_ALIAS}" || fail 'tcx-veth-b-changed' 79
  go_test_exists Z.tcx-contract TestBPFFSPinLifecycleIntegration
  run_step Z.tcx-restore exact-tcx-restore /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${STAGE_ROOT}/go-cache-realhost" GOENV=off GOFLAGS= \
    GOMODCACHE="${STAGE_ROOT}/go-mod-cache-realhost" GOPATH="${STAGE_ROOT}/go-path-realhost" \
    GOTMPDIR="${STAGE_ROOT}/go-tmp-realhost" GOWORK=off GO111MODULE=on TMPDIR="${STAGE_ROOT}/go-tmp-realhost" \
    WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1 \
    WG_MIX_EBPF_TEST_OBJECT_PATH="${SOURCE}/build/wg_mix_tc.o" \
    WG_MIX_EBPF_TEST_PIN_PATH="${PIN_PATH}" WG_MIX_EBPF_TEST_IFINDEX="${VETH_A_IFINDEX}" \
    WG_MIX_EBPF_TEST_RUNTIME_ROOT="${TCX_RUNTIME_ROOT}" \
    WG_MIX_EBPF_TEST_PIN_LOCK_ROOT="${TCX_RUNTIME_ROOT}/locks" \
    WG_MIX_EBPF_TEST_PIN_OWNER_ROOT="${TCX_RUNTIME_ROOT}/owners" \
    WG_MIX_EBPF_TEST_INITIAL_NETNS="${INITIAL_NETNS}" \
    WG_MIX_EBPF_TEST_ACTION=restore WG_MIX_EBPF_TEST_FAILURE_POLICY=retain \
    /usr/bin/timeout --signal=TERM --kill-after=10s 5m /usr/bin/go -C "${SOURCE}" \
    test ./internal/dataplane -run '^TestBPFFSPinLifecycleIntegration$' -count=1 -timeout=4m -v
  require_zero Z.tcx-restore
  /usr/bin/grep -Fqx -- 'SCOPED_BPFFS_RESTORE_COMPLETE restored=1' "${STEP_LOG}" ||
    fail 'scoped-bpffs-restore-marker' 79
  run_step Z.tcx-pin "${PIN_PATH}" /usr/bin/test ! -e "${PIN_PATH}"
  require_zero Z.tcx-pin
  run_step Z.tcx-links bpf-links /usr/sbin/bpftool -j link show
  require_zero Z.tcx-links
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A13.out" "${STEP_LOG}" || fail 'tcx-restore-link-drift' 79
}

unload_checksum_module() {
  local prefix="${1:-O8}"
  c8_checksum_module_restore "${prefix}"
}

scoped_cell_valid() {
  case "$1" in
    original | all-on | all-off | tx-path | rx-path | mtu1492 | mtu1500 | soak) return 0 ;;
    *) return 1 ;;
  esac
}

scoped_root_for_cell() {
  scoped_cell_valid "$1" || return 64
  printf '%s/scoped-realnic-%s\n' "${EVIDENCE_ROOT}" "$1"
}

scoped_pin_for_cell() {
  scoped_cell_valid "$1" || return 64
  printf '/sys/fs/bpf/wg-mix-ebpf-%s-nic-%s\n' "${RUN_ID}" "$1"
}

require_scoped_realnic_contract() {
  local prefix="$1" name step=1
  for name in "${SCOPED_CONTRACT_TEST_NAME}" "${SCOPED_RESTORE_TEST_NAME}"; do
    go_test_exists "${prefix}.contract${step}" "${name}"
    ((step++))
  done
  run_step "${prefix}.contract-run" scoped-context-contract /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${STAGE_ROOT}/go-cache-realhost" GOENV=off GOFLAGS= \
    GOMODCACHE="${STAGE_ROOT}/go-mod-cache-realhost" GOPATH="${STAGE_ROOT}/go-path-realhost" \
    GOTMPDIR="${STAGE_ROOT}/go-tmp-realhost" GOWORK=off GO111MODULE=on TMPDIR="${STAGE_ROOT}/go-tmp-realhost" \
    /usr/bin/timeout --signal=TERM --kill-after=10s 3m /usr/bin/go -C "${SOURCE}" \
    test ./internal/dataplane -run "^${SCOPED_CONTRACT_TEST_NAME}$" -count=1 -timeout=2m -v
  require_zero "${prefix}.contract-run"
}

verify_scoped_kernel_restored() {
  local prefix="$1" cell="$2" pin
  pin="$(scoped_pin_for_cell "${cell}")" || fail "scoped-pin:${cell}" 64
  run_step "${prefix}.pin" "${pin}" /usr/bin/test ! -e "${pin}"
  require_zero "${prefix}.pin"
  run_step "${prefix}.netns" initial-netns /usr/bin/readlink -- /proc/self/ns/net
  require_zero "${prefix}.netns"
  [[ "$(/usr/bin/awk 'NF {print}' "${STEP_LOG}")" == "${INITIAL_NETNS}" ]] ||
    fail "${prefix}:netns-drift" 79
  current_interface_identity || fail "${prefix}:interface-identity" 79
  run_step "${prefix}.links" bpf-links /usr/sbin/bpftool -j link show
  require_zero "${prefix}.links"
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A13.out" "${STEP_LOG}" || fail "${prefix}:bpf-link-drift" 79
  run_step "${prefix}.qdisc" "${INTERFACE}" /usr/sbin/tc -j qdisc show dev "${INTERFACE}"
  require_zero "${prefix}.qdisc"
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A10.out" "${STEP_LOG}" || fail "${prefix}:qdisc-drift" 79
  run_step "${prefix}.ingress" "${INTERFACE}" /usr/sbin/tc -j filter show dev "${INTERFACE}" ingress
  require_zero "${prefix}.ingress"
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A11.out" "${STEP_LOG}" || fail "${prefix}:ingress-drift" 79
  run_step "${prefix}.egress" "${INTERFACE}" /usr/sbin/tc -j filter show dev "${INTERFACE}" egress
  require_zero "${prefix}.egress"
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A12.out" "${STEP_LOG}" || fail "${prefix}:egress-drift" 79
}

run_scoped_realnic_restore() {
  local cell="$1" scope pin
  scope="$(scoped_root_for_cell "${cell}")" || fail "restore-scope:${cell}" 64
  pin="$(scoped_pin_for_cell "${cell}")" || fail "restore-pin:${cell}" 64
  [[ -d "${scope}" && ! -L "${scope}" ]] || fail "restore-scope-missing:${cell}" 79
  run_step "Z.${cell}.scoped-restore" "${SCOPED_RESTORE_TEST_NAME}" /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${STAGE_ROOT}/go-cache-realhost" GOENV=off GOFLAGS= \
    GOMODCACHE="${STAGE_ROOT}/go-mod-cache-realhost" GOPATH="${STAGE_ROOT}/go-path-realhost" \
    GOTMPDIR="${STAGE_ROOT}/go-tmp-realhost" GOWORK=off GO111MODULE=on TMPDIR="${STAGE_ROOT}/go-tmp-realhost" \
    WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION=1 \
    WG_MIX_EBPF_SCOPED_REALNIC_ACTION=restore WG_MIX_EBPF_SCOPED_REALNIC_RUN_ID="${RUN_ID}" \
    WG_MIX_EBPF_SCOPED_REALNIC_CELL="${cell}" \
    WG_MIX_EBPF_SCOPED_REALNIC_SOURCE_COMMIT="${COMMIT}" \
    WG_MIX_EBPF_SCOPED_REALNIC_BUNDLE_SHA256="${BUNDLE_SHA256}" \
    WG_MIX_EBPF_SCOPED_REALNIC_OBJECT="${SOURCE}/build/wg_mix_tc.o" \
    WG_MIX_EBPF_SCOPED_REALNIC_ROOT="${scope}" \
    WG_MIX_EBPF_SCOPED_REALNIC_STATE_ROOT="${scope}/state" \
    WG_MIX_EBPF_SCOPED_REALNIC_LEASE_ROOT="${scope}/lease" \
    WG_MIX_EBPF_SCOPED_REALNIC_OWNER_ROOT="${scope}/owners" \
    WG_MIX_EBPF_SCOPED_REALNIC_EVIDENCE_ROOT="${scope}/evidence" \
    WG_MIX_EBPF_SCOPED_REALNIC_PIN_PATH="${pin}" \
    WG_MIX_EBPF_SCOPED_REALNIC_INITIAL_NETNS="${INITIAL_NETNS}" \
    WG_MIX_EBPF_SCOPED_REALNIC_INTERFACE="${INTERFACE}" \
    WG_MIX_EBPF_SCOPED_REALNIC_INTERFACE_IFINDEX="${ORIGINAL_IFINDEX}" \
    WG_MIX_EBPF_SCOPED_REALNIC_INTERFACE_MAC="${ORIGINAL_MAC}" \
    WG_MIX_EBPF_SCOPED_REALNIC_WG_INTERFACE="${WG_INTERFACE}" \
    WG_MIX_EBPF_SCOPED_REALNIC_WG_LOCAL_ADDRESS="${WG_LOCAL_ADDRESS}" \
    WG_MIX_EBPF_SCOPED_REALNIC_WG_PEER_ADDRESS="${WG_PEER_ADDRESS}" \
    WG_MIX_EBPF_SCOPED_REALNIC_PEER_PORT="${PEER_PORT}" \
    WG_MIX_EBPF_SCOPED_REALNIC_TC_ATTACH=tcx \
    WG_MIX_EBPF_SCOPED_REALNIC_FAILURE_POLICY=retain \
    /usr/bin/timeout --signal=TERM --kill-after=30s 15m /usr/bin/go -C "${SOURCE}" \
    test ./internal/dataplane -run "^${SCOPED_RESTORE_TEST_NAME}$" -count=1 -timeout=14m -v
  require_zero "Z.${cell}.scoped-restore"
  /usr/bin/grep -Fqx -- "SCOPED_REALNIC_RESTORE_COMPLETE cell=${cell} restored=1" "${STEP_LOG}" ||
    fail "scoped-restore-marker:${cell}" 79
  verify_scoped_kernel_restored "Z.${cell}.restored" "${cell}"
}

verify_all_scoped_pins_absent() {
  local cell pin
  for cell in original all-on all-off tx-path rx-path mtu1492 mtu1500 soak; do
    pin="$(scoped_pin_for_cell "${cell}")" || fail "final-scoped-pin:${cell}" 64
    run_step "Z.pin-${cell}" "${pin}" /usr/bin/test ! -e "${pin}"
    require_zero "Z.pin-${cell}"
  done
}

validate_owner_marker() {
  local expected actual current_boot
  [[ -f "${OWNER_MARKER}" && ! -L "${OWNER_MARKER}" ]] || fail 'owner-marker-missing' 79
  expected="$(printf '%s\n' \
    'format=wg-mix-ebpf-realhost-v6-owner-v1' \
    "run_id=${RUN_ID}" "package_id=${PACKAGE_ID}" "evidence_id=${EVIDENCE_ID}" \
    "commit=${COMMIT}" "bundle_sha256=${BUNDLE_SHA256}" \
    "boot_id=$(read_single_line /proc/sys/kernel/random/boot_id)" \
    "source=${SOURCE}" "interface=${INTERFACE}")" || fail 'owner-expected-render'
  actual="$(/usr/bin/cat -- "${OWNER_MARKER}")" || fail 'owner-marker-read'
  [[ "${actual}" == "${expected}" ]] || fail 'owner-marker-mismatch' 79
  current_boot="$(read_single_line /proc/sys/kernel/random/boot_id)" || fail 'restore-boot-id'
  ORIGINAL_BOOT_ID="${current_boot}"
  ORIGINAL_IFINDEX="$(/usr/bin/awk -F= '$1 == "ifindex" {print $2}' "${NIC_STATE}")" || fail 'restore-ifindex'
  ORIGINAL_MAC="$(/usr/bin/awk -F= '$1 == "mac" {print $2}' "${NIC_STATE}")" || fail 'restore-mac'
  ORIGINAL_MTU="$(/usr/bin/awk -F= '$1 == "mtu" {print $2}' "${NIC_STATE}")" || fail 'restore-mtu'
  [[ -f "${NETNS_STATE}" && ! -L "${NETNS_STATE}" ]] || fail 'restore-netns-state' 79
  INITIAL_NETNS="$(/usr/bin/awk -F= '$1 == "initial_netns" {print $2}' "${NETNS_STATE}")" ||
    fail 'restore-netns-read'
  [[ "${ORIGINAL_IFINDEX}" =~ ^[1-9][0-9]*$ &&
    "${ORIGINAL_MAC}" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ &&
    "${ORIGINAL_MTU}" =~ ^[0-9]{4,5}$ &&
    "${INITIAL_NETNS}" =~ ^net:\[[1-9][0-9]*\]$ ]] || fail 'restore-nic-state-invalid' 79
}

restore_after_failure() {
  acquire_physical_interface_lock
  validate_common_identity
  load_checksum_module_helper
  validate_owner_marker
  c8_checksum_module_acquire L0.restore
  if [[ -e "${MODULE_INTENT}" || -L "${MODULE_INTENT}" ||
    -e "${MODULE_LOADED}" || -L "${MODULE_LOADED}" ||
    -e "${MODULE_UNLOADED}" || -L "${MODULE_UNLOADED}" ||
    -e "/sys/module/${MODULE_NAME}" ]]; then
    configure_checksum_module_lease
  fi
  [[ ! -e "${RESTORED_MARKER}" && ! -L "${RESTORED_MARKER}" ]] || fail 'already-restored' 78
  if [[ "${RESTORE_CELL}" == 'tcx' ]]; then
    require_scoped_realnic_contract Z.contract
    restore_exact_tcx_lifecycle
  elif [[ "${RESTORE_CELL}" != 'none' ]]; then
    require_scoped_realnic_contract Z.contract
    run_scoped_realnic_restore "${RESTORE_CELL}"
  fi
  verify_all_scoped_pins_absent
  if [[ -e "${PIN_PATH}" || -L "${PIN_PATH}" ]]; then
    run_step Z0 "${PIN_PATH}" /usr/bin/ls -la -- "${PIN_PATH}"
    require_zero Z0
    fail 'exact-bpf-pin-remains-manual-code-owned-detach-required' 79
  fi
  if [[ -e "${MODULE_INTENT}" || -L "${MODULE_INTENT}" ||
    -e "${MODULE_LOADED}" || -L "${MODULE_LOADED}" ||
    -e "${MODULE_UNLOADED}" || -L "${MODULE_UNLOADED}" ||
    -e "/sys/module/${MODULE_NAME}" ]]; then
    unload_checksum_module Z.module
  fi
  if [[ -f "${VETH_STATE}" && ! -f "${EVIDENCE_ROOT}/veth-deleted.v1" ]]; then
    VETH_A_IFINDEX="$(/usr/bin/awk -F= '$1 == "a_ifindex" {print $2}' "${VETH_STATE}")" || fail 'restore-veth-a'
    VETH_B_IFINDEX="$(/usr/bin/awk -F= '$1 == "b_ifindex" {print $2}' "${VETH_STATE}")" || fail 'restore-veth-b'
    [[ "${VETH_A_IFINDEX}" =~ ^[1-9][0-9]*$ && "${VETH_B_IFINDEX}" =~ ^[1-9][0-9]*$ ]] ||
      fail 'restore-veth-state-invalid' 79
    delete_owned_veth Z.veth
  fi
  restore_nic_state Z.restore
  run_step Z.links-restored bpf-links /usr/sbin/bpftool -j link show
  require_zero Z.links-restored
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A13.out" "${STEP_LOG}" || fail 'restore-bpf-link-drift' 79
  write_once "${RESTORED_MARKER}" "run_id=${RUN_ID}" 'state=restored' "utc=$(utc_now)"
  printf 'REALHOST_V6_RESTORE_COMPLETE run_id=%s evidence=%s\n' "${RUN_ID}" "${EVIDENCE_ROOT}"
}

parse_arguments "$@"
parse_rc=$?
((parse_rc == 0)) || fail "arguments:rc=${parse_rc}" "${parse_rc}"

if [[ "${MODE}" == 'run' ]]; then
  fail 'legacy-forward-authority-retired-use-realnic-acceptance' 78
elif [[ "${MODE}" == 'plan' ]]; then
  render_plan
  exit 0
fi

require_tooling
case "${MODE}" in
  restore) restore_after_failure ;;
  *) fail 'unreachable-mode' 64 ;;
esac
