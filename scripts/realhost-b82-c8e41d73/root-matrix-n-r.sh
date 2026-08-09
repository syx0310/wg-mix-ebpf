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
readonly MODULE_INTENT="${EVIDENCE_ROOT}/module-load-intent.v1"
readonly MODULE_LOADED="${EVIDENCE_ROOT}/module-loaded.v1"
readonly MODULE_UNLOADED="${EVIDENCE_ROOT}/module-unloaded.v1"
readonly COMPLETED_MARKER="${EVIDENCE_ROOT}/completed.v1"
readonly RESTORED_MARKER="${EVIDENCE_ROOT}/restored.v1"
readonly PIN_PATH="/sys/fs/bpf/wg-mix-ebpf-${RUN_ID}-tcx"
readonly TCX_RUNTIME_ROOT="${EVIDENCE_ROOT}/tcx-runtime"
readonly SCOPED_TEST_NAME='TestScopedRealNICDataplaneActiveIntegration'
readonly SCOPED_RESTORE_TEST_NAME='TestScopedRealNICDataplaneRestoreIntegration'
readonly SCOPED_CONTRACT_TEST_NAME='TestScopedRealNICContextIsolationContract'
readonly VETH_A='wgc8e41a'
readonly VETH_B='wgc8e41b'
readonly VETH_A_ALIAS="wg-mix-ebpf:${RUN_ID}:a"
readonly VETH_B_ALIAS="wg-mix-ebpf:${RUN_ID}:b"
readonly MODULE_NAME='wg_mix_faketcp_checksum'
readonly SOAK_WINDOWS=12
readonly MATRIX_TRAFFIC_SECONDS=30
readonly MATRIX_PASSES=2
readonly MATRIX_OUTER_TIMEOUT_SECONDS=1500
readonly MATRIX_GO_TIMEOUT_SECONDS=1440
readonly MTU_TRAFFIC_SECONDS=30
readonly MTU_PASSES=2
readonly MTU_OUTER_TIMEOUT_SECONDS=600
readonly MTU_GO_TIMEOUT_SECONDS=540
readonly SOAK_OUTER_TIMEOUT_SECONDS=4500
readonly SOAK_GO_TIMEOUT_SECONDS=4440
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
declare -a BOOTSTRAP_AUDIT_LINES=()

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
  local streams direction cell selector
  printf 'REALHOST_V6_PLAN_ONLY run_id=%s package_id=%s evidence_id=%s commit=%s bundle_sha256=%s\n' \
    "${RUN_ID}" "${PACKAGE_ID}" "${EVIDENCE_ID}" "${COMMIT}" "${BUNDLE_SHA256}"
  printf 'REALHOST_V6_PLAN_ENDPOINTS bare=%s:%s active_wg=%s:%s->%s:%s\n' \
    "${PEER_ADDRESS}" "${PEER_PORT}" "${WG_INTERFACE}" "${WG_LOCAL_ADDRESS}" \
    "${WG_PEER_ADDRESS}" "${PEER_PORT}"
  plan_command B0 /usr/bin/mkdir --mode=0700 -- "${EVIDENCE_ROOT}"
  plan_command B1 shell-builtin noclobber-create-and-persist-bootstrap-audit "${AUDIT_LOG}"
  plan_command A1 /usr/bin/hostname
  plan_command A2 /usr/bin/uname -r
  plan_command A3 /usr/bin/cat /etc/machine-id
  plan_command A4 /usr/sbin/ip -j address show dev "${INTERFACE}"
  for selector in public-key listen-port fwmark peers endpoints allowed-ips latest-handshakes transfer; do
    plan_command "A16-wg-${selector}" /usr/bin/wg show "${WG_INTERFACE}" "${selector}"
  done
  plan_command N0 /usr/bin/go -C "${SOURCE}" test ./internal/dataplane \
    -run '^TestBPFFSPinLifecycleIntegration$' -count=1
  plan_command N1 /usr/sbin/ip link add "${VETH_A}" type veth peer name "${VETH_B}"
  plan_command N2 /usr/sbin/ip link set dev "${VETH_A}" alias "${VETH_A_ALIAS}"
  plan_command N3 /usr/sbin/ip link set dev "${VETH_B}" alias "${VETH_B_ALIAS}"
  plan_command N4 /usr/sbin/ip link set dev "${VETH_A}" up
  plan_command N5 /usr/sbin/ip link set dev "${VETH_B}" up
  plan_command N6 /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1 \
    WG_MIX_EBPF_TEST_OBJECT_PATH="${SOURCE}/build/wg_mix_tc.o" \
    WG_MIX_EBPF_TEST_PIN_PATH="${PIN_PATH}" \
    WG_MIX_EBPF_TEST_IFINDEX=RUNTIME_VETH_IFINDEX \
    WG_MIX_EBPF_TEST_RUNTIME_ROOT="${TCX_RUNTIME_ROOT}" \
    WG_MIX_EBPF_TEST_PIN_LOCK_ROOT="${TCX_RUNTIME_ROOT}/locks" \
    WG_MIX_EBPF_TEST_PIN_OWNER_ROOT="${TCX_RUNTIME_ROOT}/owners" \
    WG_MIX_EBPF_TEST_INITIAL_NETNS=EXACT_INITIAL_NETNS \
    WG_MIX_EBPF_TEST_ACTION=run \
    WG_MIX_EBPF_TEST_FAILURE_POLICY=retain \
    /usr/bin/go -C "${SOURCE}" test ./internal/dataplane \
    -run '^TestBPFFSPinLifecycleIntegration$' -count=1 -timeout=2m
  plan_command O1 /usr/bin/make --no-print-directory -C "${SOURCE}" \
    build-bpf build-faketcp-experimental-bpf build-faketcp-checksum-kmod build
  plan_command O2 /usr/sbin/insmod "${SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
  plan_command O3 "${SOURCE}/bin/wg-mix-ebpf" bpf-load-test \
    --experimental-faketcp --object "${SOURCE}/build/wg_mix_faketcp_experimental.o" --json
  plan_command O4 /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    WG_MIX_FAKETCP_PACKET_TEST_OBJECT="${SOURCE}/build/wg_mix_faketcp_experimental.o" \
    /usr/bin/go -C "${SOURCE}" test ./internal/dataplane \
    -run '^TestFakeTCPBPFPacketProbe$' -count=1 -timeout=3m
  for label in \
    TestExperimentalFakeTCPRealHostLifecycleIntegration \
    TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration \
    TestBaselineExperimentalRealHostMutualExclusionIntegration; do
    plan_command "O-${label}" /usr/bin/env -i \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
      WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION=1 \
      WG_MIX_FAKETCP_REALHOST_OBJECT="${SOURCE}/build/wg_mix_faketcp_experimental.o" \
      WG_MIX_FAKETCP_REALHOST_BASELINE_OBJECT="${SOURCE}/build/wg_mix_tc.o" \
      WG_MIX_FAKETCP_REALHOST_IFINDEX=RUNTIME_VETH_IFINDEX \
      WG_MIX_FAKETCP_REALHOST_PEER_IFINDEX=RUNTIME_PEER_IFINDEX \
      WG_MIX_FAKETCP_REALHOST_XDP_MODE=generic \
      WG_MIX_FAKETCP_REALHOST_RUN_ID="${RUN_ID}" \
      /usr/bin/go -C "${SOURCE}" test ./internal/dataplane \
      -run "^${label}$" -count=1 -timeout=5m
  done
  plan_command O8 /usr/sbin/rmmod "${MODULE_NAME}"
  plan_command O9 /usr/sbin/ip link delete dev "${VETH_A}"
  plan_command P-scoped-contract /usr/bin/go -C "${SOURCE}" test ./internal/dataplane \
    -run "^${SCOPED_CONTRACT_TEST_NAME}$" -count=1
  for cell in original all-on all-off tx-path rx-path; do
    plan_command "P-${cell}-features" /usr/sbin/ethtool -K "${INTERFACE}" REVIEWED_CELL_VALUES
    for streams in 1 4 16; do
      for direction in forward reverse bidir; do
        case "${direction}" in
          forward)
            plan_command "P-${cell}-p${streams}-${direction}" /usr/bin/timeout \
              --signal=TERM --kill-after=10s 50s /usr/bin/iperf3 \
              -c "${PEER_ADDRESS}" -p "${PEER_PORT}" --connect-timeout 5000 \
              --json --omit 2 -t 30 -P "${streams}"
            ;;
          reverse)
            plan_command "P-${cell}-p${streams}-${direction}" /usr/bin/timeout \
              --signal=TERM --kill-after=10s 50s /usr/bin/iperf3 \
              -c "${PEER_ADDRESS}" -p "${PEER_PORT}" --connect-timeout 5000 \
              --json --omit 2 -t 30 -P "${streams}" -R
            ;;
          bidir)
            plan_command "P-${cell}-p${streams}-${direction}" /usr/bin/timeout \
              --signal=TERM --kill-after=10s 50s /usr/bin/iperf3 \
              -c "${PEER_ADDRESS}" -p "${PEER_PORT}" --connect-timeout 5000 \
              --json --omit 2 -t 30 -P "${streams}" --bidir
            ;;
        esac
      done
    done
  done
  plan_command Q1 /usr/sbin/ip link set dev "${INTERFACE}" mtu 1492
  plan_command Q2 /usr/bin/ping -4 -I "${INTERFACE}" -M do -c 3 -W 2 -s 1464 "${PEER_ADDRESS}"
  plan_command Q3 /usr/bin/ping -4 -I "${INTERFACE}" -M do -c 1 -W 2 -s 1465 "${PEER_ADDRESS}"
  plan_command Q4 /usr/sbin/ip link set dev "${INTERFACE}" mtu 1500
  plan_command P-scoped-active /usr/bin/env -i \
    WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION=1 \
    WG_MIX_EBPF_SCOPED_REALNIC_STATE_ROOT=RUN_OWNED_CELL_STATE \
    WG_MIX_EBPF_SCOPED_REALNIC_LEASE_ROOT=RUN_OWNED_CELL_LEASE \
    WG_MIX_EBPF_SCOPED_REALNIC_OWNER_ROOT=RUN_OWNED_CELL_OWNER \
    WG_MIX_EBPF_SCOPED_REALNIC_PIN_PATH=RUN_OWNED_CELL_BPFFS_PIN \
    WG_MIX_EBPF_SCOPED_REALNIC_INITIAL_NETNS=EXACT_INITIAL_NETNS \
    WG_MIX_EBPF_SCOPED_REALNIC_TC_ATTACH=tcx \
    WG_MIX_EBPF_SCOPED_REALNIC_TYPEWORD_MODE=identity \
    WG_MIX_EBPF_SCOPED_REALNIC_FAILURE_POLICY=retain \
    /usr/bin/go -C "${SOURCE}" test ./internal/dataplane \
    -run "^${SCOPED_TEST_NAME}$" -count=1
  printf 'R-scoped-soak windows=%s session_seconds=%s total_seconds=%s monitor_samples=360\n' \
    "${SOAK_WINDOWS}" "${SESSION_SECONDS}" "$((SOAK_WINDOWS * SESSION_SECONDS))"
  plan_command R-restore /usr/sbin/ethtool -K "${INTERFACE}" EXACT_ORIGINAL_VALUES
  plan_command R-full-offload-snapshot /usr/sbin/ethtool -k "${INTERFACE}"
  plan_command R-full-offload-compare /usr/bin/cmp -s "${EVIDENCE_ROOT}/A7.out" EXACT_RESTORED_FEATURE_SNAPSHOT
  plan_command R-mtu /usr/sbin/ip link set dev "${INTERFACE}" mtu EXACT_ORIGINAL_MTU
  plan_command Z-scoped-restore /usr/bin/env -i \
    WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION=1 \
    WG_MIX_EBPF_SCOPED_REALNIC_ACTION=restore \
    /usr/bin/go -C "${SOURCE}" test ./internal/dataplane \
    -run "^${SCOPED_RESTORE_TEST_NAME}$" -count=1
  printf '%s\n' \
    'P-faketcp-physical-e2e classification=not-covered reason=read-only-peer-has-no-reviewed-faketcp-dataplane' \
    'P-xor-physical-e2e classification=not-covered reason=read-only-peer-has-no-reviewed-shared-cipher'
  printf 'REALHOST_V6_PLAN_COMPLETE commands_are_review_templates=1 no_commands_executed=1\n'
}

utc_now() {
  /bin/date -u '+%Y-%m-%dT%H:%M:%SZ'
}

bootstrap_audit_line() {
  local event="$1" step="$2" target="$3" rc="$4" rendered="$5"
  local timestamp line
  timestamp="$(utc_now)" || return $?
  [[ "${timestamp}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 79
  printf -v line 'utc=%q event=%q step=%q target=%q rc=%q argv=%q' \
    "${timestamp}" "${event}" "${step}" "${target}" "${rc}" "${rendered}"
  BOOTSTRAP_AUDIT_LINES+=("${line}")
  printf 'REALHOST_V6_BOOTSTRAP_AUDIT %s\n' "${line}"
}

bootstrap_run_step() {
  local step="$1" target="$2" rendered rc
  shift 2
  rendered="$(quote_argv "$@")" || return $?
  bootstrap_audit_line start "${step}" "${target}" not-run "${rendered}" || return $?
  "$@"
  rc=$?
  bootstrap_audit_line finish "${step}" "${target}" "${rc}" "${rendered}" || return $?
  return "${rc}"
}

create_bootstrap_audit_log() {
  local rendered rc persist_rc finish_line last_index
  rendered="shell-builtin: noclobber create ${AUDIT_LOG}; persist bootstrap start/finish records"
  bootstrap_audit_line start B1.audit-create "${AUDIT_LOG}" not-run "${rendered}" || return $?
  set -o noclobber
  printf '%s\n' "${BOOTSTRAP_AUDIT_LINES[@]}" >"${AUDIT_LOG}"
  rc=$?
  set +o noclobber
  bootstrap_audit_line finish B1.audit-create "${AUDIT_LOG}" "${rc}" "${rendered}" || return $?
  ((rc == 0)) || return "${rc}"
  last_index=$((${#BOOTSTRAP_AUDIT_LINES[@]} - 1))
  finish_line="${BOOTSTRAP_AUDIT_LINES[${last_index}]}"
  printf '%s\n' "${finish_line}" >>"${AUDIT_LOG}"
  persist_rc=$?
  if ((persist_rc != 0)); then
    bootstrap_audit_line finish B1.audit-persist "${AUDIT_LOG}" "${persist_rc}" \
      'shell-builtin: append audit-create finish record' || return $?
    return "${persist_rc}"
  fi
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
    /usr/bin/git /usr/bin/go /usr/bin/grep /usr/bin/hostname /usr/bin/iperf3
    /usr/bin/jq /usr/bin/ls /usr/bin/make /usr/bin/mkdir /usr/bin/ping /usr/bin/python3
    /usr/bin/readlink /usr/bin/sha256sum /usr/bin/stat /usr/bin/tee
    /usr/bin/test /usr/bin/timeout /usr/bin/uname /usr/bin/wg
    /usr/sbin/bpftool /usr/sbin/ethtool /usr/sbin/insmod /usr/sbin/ip
    /usr/sbin/lsmod /usr/sbin/nft /usr/sbin/rmmod /usr/sbin/tc
  )
  for path in "${tools[@]}"; do
    [[ -x "${path}" ]] || fail "missing-tool:${path}" 69
  done
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
}

create_evidence_root() {
  local rc
  [[ ! -e "${EVIDENCE_ROOT}" && ! -L "${EVIDENCE_ROOT}" ]] || fail 'evidence-exists' 78
  bootstrap_run_step B0.evidence-create "${EVIDENCE_ROOT}" \
    /usr/bin/mkdir --mode=0700 -- "${EVIDENCE_ROOT}"
  rc=$?
  ((rc == 0)) || fail "evidence-create:rc=${rc}" "${rc}"
  [[ -d "${EVIDENCE_ROOT}" && ! -L "${EVIDENCE_ROOT}" ]] || fail 'evidence-shape' 79
  create_bootstrap_audit_log
  rc=$?
  ((rc == 0)) || fail "audit-create:rc=${rc}" "${rc}"
  ORIGINAL_BOOT_ID="$(read_single_line /proc/sys/kernel/random/boot_id)" || fail 'boot-id-read'
  [[ "${ORIGINAL_BOOT_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
    fail 'boot-id-invalid' 79
  write_once "${OWNER_MARKER}" \
    'format=wg-mix-ebpf-realhost-v6-owner-v1' \
    "run_id=${RUN_ID}" "package_id=${PACKAGE_ID}" "evidence_id=${EVIDENCE_ID}" \
    "commit=${COMMIT}" "bundle_sha256=${BUNDLE_SHA256}" \
    "boot_id=${ORIGINAL_BOOT_ID}" "source=${SOURCE}" "interface=${INTERFACE}"
}

snapshot_host() {
  INITIAL_NETNS="$(/usr/bin/readlink -- /proc/self/ns/net)" || fail 'initial-netns-read'
  [[ "${INITIAL_NETNS}" =~ ^net:\[[1-9][0-9]*\]$ ]] || fail 'initial-netns-invalid' 79
  write_once "${NETNS_STATE}" "run_id=${RUN_ID}" "initial_netns=${INITIAL_NETNS}"
  run_step A1 hostname /usr/bin/hostname; require_zero A1
  run_step A2 kernel /usr/bin/uname -r; require_zero A2
  run_step A3 machine-id /usr/bin/cat /etc/machine-id; require_zero A3
  run_step A4 interface-address /usr/sbin/ip -j address show dev "${INTERFACE}"; require_zero A4
  run_step A5 interface-link /usr/sbin/ip -d -j link show dev "${INTERFACE}"; require_zero A5
  run_step A6 interface-driver /usr/sbin/ethtool -i "${INTERFACE}"; require_zero A6
  run_step A7 interface-features /usr/sbin/ethtool -k "${INTERFACE}"; require_zero A7
  run_step A8 interface-stats /usr/sbin/ethtool -S "${INTERFACE}"; require_zero A8
  run_step A9 route-peer /usr/sbin/ip -j route get "${PEER_ADDRESS}"; require_zero A9
  /usr/bin/jq -e --arg dev "${INTERFACE}" \
    'length == 1 and .[0].dev == $dev' "${STEP_LOG}" >/dev/stdout || fail 'peer-route-not-interface' 79
  run_step A10 tc-qdisc /usr/sbin/tc -j qdisc show dev "${INTERFACE}"; require_zero A10
  run_step A11 tc-ingress /usr/sbin/tc -j filter show dev "${INTERFACE}" ingress; require_zero A11
  run_step A12 tc-egress /usr/sbin/tc -j filter show dev "${INTERFACE}" egress; require_zero A12
  run_step A13 bpf-links /usr/sbin/bpftool -j link show; require_zero A13
  run_step A14 bpf-programs /usr/sbin/bpftool -j prog show; require_zero A14
  run_step A15 bpf-maps /usr/sbin/bpftool -j map show; require_zero A15
  run_step A16.wg-public-keys wireguard /usr/bin/wg show "${WG_INTERFACE}" public-key; require_zero A16.wg-public-keys
  run_step A16.wg-listen-ports wireguard /usr/bin/wg show "${WG_INTERFACE}" listen-port; require_zero A16.wg-listen-ports
  run_step A16.wg-fwmarks wireguard /usr/bin/wg show "${WG_INTERFACE}" fwmark; require_zero A16.wg-fwmarks
  run_step A16.wg-peers wireguard /usr/bin/wg show "${WG_INTERFACE}" peers; require_zero A16.wg-peers
  run_step A16.wg-endpoints wireguard /usr/bin/wg show "${WG_INTERFACE}" endpoints; require_zero A16.wg-endpoints
  run_step A16.wg-allowed-ips wireguard /usr/bin/wg show "${WG_INTERFACE}" allowed-ips; require_zero A16.wg-allowed-ips
  run_step A16.wg-handshakes wireguard /usr/bin/wg show "${WG_INTERFACE}" latest-handshakes; require_zero A16.wg-handshakes
  run_step A16.wg-transfer wireguard /usr/bin/wg show "${WG_INTERFACE}" transfer; require_zero A16.wg-transfer
  run_step A17 nftables /usr/sbin/nft -j list ruleset; require_zero A17
  run_step A18 modules /usr/sbin/lsmod; require_zero A18
  run_step A19 wg-interface /usr/sbin/ip -d -j link show dev "${WG_INTERFACE}"; require_zero A19
  run_step A20 wg-address /usr/sbin/ip -j address show dev "${WG_INTERFACE}"; require_zero A20
  /usr/bin/jq -e --arg address "${WG_LOCAL_ADDRESS}" \
    'length == 1 and any(.[0].addr_info[]?; .family == "inet" and .local == $address)' \
    "${STEP_LOG}" >/dev/stdout || fail 'wg-local-address-mismatch' 79
  run_step A21 wg-route /usr/sbin/ip -j route get "${WG_PEER_ADDRESS}" from "${WG_LOCAL_ADDRESS}"
  require_zero A21
  /usr/bin/jq -e --arg dev "${WG_INTERFACE}" \
    'length == 1 and .[0].dev == $dev' "${STEP_LOG}" >/dev/stdout || fail 'wg-peer-route-mismatch' 79
  run_step A22 wg-peer-public-keys /usr/bin/wg show "${WG_INTERFACE}" peers; require_zero A22
  [[ -s "${STEP_LOG}" ]] || fail 'wg-interface-has-no-peer' 79
  ORIGINAL_IFINDEX="$(read_single_line "/sys/class/net/${INTERFACE}/ifindex")" || fail 'ifindex-read'
  [[ "${ORIGINAL_IFINDEX}" =~ ^[1-9][0-9]*$ ]] || fail 'ifindex-invalid' 79
  ORIGINAL_MAC="$(read_single_line "/sys/class/net/${INTERFACE}/address")" || fail 'mac-read'
  [[ "${ORIGINAL_MAC}" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ ]] || fail 'mac-invalid' 79
  ORIGINAL_MTU="$(read_single_line "/sys/class/net/${INTERFACE}/mtu")" || fail 'mtu-read'
  [[ "${ORIGINAL_MTU}" == '1500' ]] || fail 'unexpected-original-mtu' 79
}

feature_line() {
  local source="$1"
  local feature="$2"
  /usr/bin/awk -v key="${feature}:" '$1 == key {print $2 " " ($3 == "[fixed]" ? "fixed" : "mutable")}' "${source}"
}

capture_nic_state() {
  local feature value state line
  local -a records=(
    'format=wg-mix-ebpf-nic-state-v1'
    "interface=${INTERFACE}"
    "ifindex=${ORIGINAL_IFINDEX}"
    "mac=${ORIGINAL_MAC}"
    "mtu=${ORIGINAL_MTU}"
  )
  [[ ! -e "${NIC_STATE}" && ! -L "${NIC_STATE}" ]] || fail 'nic-state-exists' 78
  for feature in "${FEATURE_NAMES[@]}"; do
    line="$(feature_line "${EVIDENCE_ROOT}/A7.out" "${feature}")" || fail "feature-parse:${feature}"
    if [[ -z "${line}" ]]; then
      case "${feature}" in
        tx-udp-segmentation | rx-udp-gro-forwarding)
          records+=("feature=${feature} value=unsupported mutability=unsupported")
          continue
          ;;
        *) fail "required-feature-absent:${feature}" 79 ;;
      esac
    fi
    read -r value state <<<"${line}"
    [[ "${value}" =~ ^(on|off)$ && "${state}" =~ ^(fixed|mutable)$ ]] ||
      fail "feature-state-invalid:${feature}" 79
    records+=("feature=${feature} value=${value} mutability=${state}")
  done
  write_once "${NIC_STATE}" "${records[@]}"
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

apply_feature_cell() {
  local cell="$1"
  local policy="${cell%-soak}"
  local feature desired
  restore_nic_state "P.${cell}.baseline"
  for feature in "${FEATURE_NAMES[@]}"; do
    case "${policy}:${feature}" in
      original:*) continue ;;
      all-on:*) desired=on ;;
      all-off:*) desired=off ;;
      tx-path:tx-checksumming | tx-path:generic-segmentation-offload | \
      tx-path:tcp-segmentation-offload | tx-path:tx-udp-segmentation) desired=on ;;
      tx-path:*) desired=off ;;
      rx-path:rx-checksumming | rx-path:generic-receive-offload | \
      rx-path:rx-udp-gro-forwarding) desired=on ;;
      rx-path:*) desired=off ;;
      *) fail "unknown-feature-cell:${cell}:${feature}" 64 ;;
    esac
    set_feature "P.${cell}.${feature}" "${feature}" "${desired}"
  done
  run_step "P.${cell}.snapshot" "${INTERFACE}" /usr/sbin/ethtool -k "${INTERFACE}"
  require_zero "P.${cell}.snapshot"
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

build_artifacts() {
  run_step O1 build-artifacts /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    CGO_ENABLED=0 GO=/usr/bin/go CLANG=/usr/bin/clang \
    GOCACHE="${STAGE_ROOT}/go-cache-realhost" GOENV=off GOFLAGS= \
    GOMODCACHE="${STAGE_ROOT}/go-mod-cache-realhost" GOPATH="${STAGE_ROOT}/go-path-realhost" \
    GOTMPDIR="${STAGE_ROOT}/go-tmp-realhost" GOWORK=off GO111MODULE=on TMPDIR="${STAGE_ROOT}/go-tmp-realhost" \
    /usr/bin/timeout --signal=TERM --kill-after=30s 30m /usr/bin/make \
    --no-print-directory -C "${SOURCE}" build-bpf build-faketcp-experimental-bpf \
    build-faketcp-checksum-kmod build test-bpf-object-manifests
  require_zero O1
  run_step O1.hash artifacts /usr/bin/sha256sum -- \
    "${SOURCE}/bin/wg-mix-ebpf" "${SOURCE}/build/wg_mix_tc.o" \
    "${SOURCE}/build/wg_mix_faketcp_experimental.o" \
    "${SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko" \
    "${SOURCE}/scripts/realhost-b82-${RUN_ID}/check-realhost-iperf.py"
  require_zero O1.hash
}

create_owned_veth() {
  run_step N1.pre-a "${VETH_A}" /usr/sbin/ip link show dev "${VETH_A}"
  ((STEP_RC == 1)) || fail "veth-a-preexists:rc=${STEP_RC}" 79
  run_step N1.pre-b "${VETH_B}" /usr/sbin/ip link show dev "${VETH_B}"
  ((STEP_RC == 1)) || fail "veth-b-preexists:rc=${STEP_RC}" 79
  [[ ! -e "${PIN_PATH}" && ! -L "${PIN_PATH}" ]] || fail 'tcx-pin-preexists' 79
  run_step N1 "${VETH_A}:${VETH_B}" /usr/sbin/ip link add "${VETH_A}" type veth peer name "${VETH_B}"
  require_zero N1
  run_step N2 "${VETH_A}" /usr/sbin/ip link set dev "${VETH_A}" alias "${VETH_A_ALIAS}"
  require_zero N2
  run_step N3 "${VETH_B}" /usr/sbin/ip link set dev "${VETH_B}" alias "${VETH_B_ALIAS}"
  require_zero N3
  run_step N4 "${VETH_A}" /usr/sbin/ip link set dev "${VETH_A}" up
  require_zero N4
  run_step N5 "${VETH_B}" /usr/sbin/ip link set dev "${VETH_B}" up
  require_zero N5
  VETH_A_IFINDEX="$(read_single_line "/sys/class/net/${VETH_A}/ifindex")" || fail 'veth-a-ifindex'
  VETH_B_IFINDEX="$(read_single_line "/sys/class/net/${VETH_B}/ifindex")" || fail 'veth-b-ifindex'
  [[ "${VETH_A_IFINDEX}" =~ ^[1-9][0-9]*$ && "${VETH_B_IFINDEX}" =~ ^[1-9][0-9]*$ ]] ||
    fail 'veth-ifindex-invalid' 79
  write_once "${VETH_STATE}" 'format=wg-mix-ebpf-realhost-veth-v1' \
    "run_id=${RUN_ID}" "a=${VETH_A}" "a_ifindex=${VETH_A_IFINDEX}" "a_alias=${VETH_A_ALIAS}" \
    "b=${VETH_B}" "b_ifindex=${VETH_B_IFINDEX}" "b_alias=${VETH_B_ALIAS}"
  run_step N5.links-before bpf-links /usr/sbin/bpftool -j link show
  require_zero N5.links-before
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

run_exact_tcx_lifecycle() {
  go_test_exists N6 TestBPFFSPinLifecycleIntegration
  run_step N6.runtime-pre "${TCX_RUNTIME_ROOT}" /usr/bin/test ! -e "${TCX_RUNTIME_ROOT}"
  require_zero N6.runtime-pre
  run_step N7 exact-tcx-lifecycle /usr/bin/env -i \
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
    WG_MIX_EBPF_TEST_ACTION=run \
    WG_MIX_EBPF_TEST_FAILURE_POLICY=retain \
    /usr/bin/timeout --signal=TERM --kill-after=10s 3m /usr/bin/go -C "${SOURCE}" \
    test ./internal/dataplane -run '^TestBPFFSPinLifecycleIntegration$' -count=1 -timeout=2m
  require_zero N7
  /usr/bin/grep -Fqx -- 'SCOPED_BPFFS_COMPLETE restored=1' "${STEP_LOG}" ||
    fail 'scoped-bpffs-completion-marker' 79
  run_step N8 "${PIN_PATH}" /usr/bin/test ! -e "${PIN_PATH}"
  require_zero N8
  run_step N9 links-after-tcx /usr/sbin/bpftool -j link show
  require_zero N9
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/N5.links-before.out" "${STEP_LOG}" || fail 'tcx-link-leak' 79
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

load_checksum_module() {
  run_step O2.pre "${MODULE_NAME}" /usr/bin/test ! -e "/sys/module/${MODULE_NAME}"
  require_zero O2.pre
  local ko_sha
  ko_sha="$(/usr/bin/sha256sum -- "${SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko")" || fail 'module-sha'
  ko_sha="${ko_sha%% *}"
  valid_sha256 "${ko_sha}" || fail 'module-sha-invalid' 79
  write_once "${MODULE_INTENT}" 'format=wg-mix-ebpf-module-intent-v1' \
    "run_id=${RUN_ID}" "module=${MODULE_NAME}" "ko_sha256=${ko_sha}" 'state=loading'
  run_step O2 "${MODULE_NAME}" /usr/sbin/insmod \
    "${SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
  require_zero O2
  run_step O2.verify "${MODULE_NAME}" /usr/bin/test -d "/sys/module/${MODULE_NAME}"
  require_zero O2.verify
  write_once "${MODULE_LOADED}" "run_id=${RUN_ID}" "module=${MODULE_NAME}" 'state=loaded'
}

unload_checksum_module() {
  local prefix="${1:-O8}"
  [[ -f "${MODULE_LOADED}" && ! -L "${MODULE_LOADED}" ]] || fail 'module-owner-marker-missing' 79
  run_step "${prefix}" "${MODULE_NAME}" /usr/sbin/rmmod "${MODULE_NAME}"
  require_zero "${prefix}"
  run_step "${prefix}.verify" "${MODULE_NAME}" /usr/bin/test ! -e "/sys/module/${MODULE_NAME}"
  require_zero "${prefix}.verify"
  write_once "${MODULE_UNLOADED}" "run_id=${RUN_ID}" "module=${MODULE_NAME}" 'state=unloaded'
}

run_faketcp_tests() {
  local name step
  run_step O3 faketcp-verifier /usr/bin/timeout --signal=TERM --kill-after=10s 3m \
    "${SOURCE}/bin/wg-mix-ebpf" bpf-load-test --experimental-faketcp \
    --object "${SOURCE}/build/wg_mix_faketcp_experimental.o" --json
  require_zero O3
  go_test_exists O4 TestFakeTCPBPFPacketProbe
  run_step O5 faketcp-packet-probe /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${STAGE_ROOT}/go-cache-realhost" GOENV=off GOFLAGS= \
    GOMODCACHE="${STAGE_ROOT}/go-mod-cache-realhost" GOPATH="${STAGE_ROOT}/go-path-realhost" \
    GOTMPDIR="${STAGE_ROOT}/go-tmp-realhost" GOWORK=off GO111MODULE=on TMPDIR="${STAGE_ROOT}/go-tmp-realhost" \
    WG_MIX_FAKETCP_PACKET_TEST_OBJECT="${SOURCE}/build/wg_mix_faketcp_experimental.o" \
    /usr/bin/timeout --signal=TERM --kill-after=10s 4m /usr/bin/go -C "${SOURCE}" \
    test ./internal/dataplane -run '^TestFakeTCPBPFPacketProbe$' -count=1 -timeout=3m -v
  require_zero O5
  step=6
  for name in \
    TestExperimentalFakeTCPRealHostLifecycleIntegration \
    TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration \
    TestBaselineExperimentalRealHostMutualExclusionIntegration; do
    go_test_exists "O${step}" "${name}"
    run_step "O${step}.run" "${name}" /usr/bin/env -i \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
      GOCACHE="${STAGE_ROOT}/go-cache-realhost" GOENV=off GOFLAGS= \
      GOMODCACHE="${STAGE_ROOT}/go-mod-cache-realhost" GOPATH="${STAGE_ROOT}/go-path-realhost" \
      GOTMPDIR="${STAGE_ROOT}/go-tmp-realhost" GOWORK=off GO111MODULE=on TMPDIR="${STAGE_ROOT}/go-tmp-realhost" \
      WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION=1 \
      WG_MIX_FAKETCP_REALHOST_OBJECT="${SOURCE}/build/wg_mix_faketcp_experimental.o" \
      WG_MIX_FAKETCP_REALHOST_BASELINE_OBJECT="${SOURCE}/build/wg_mix_tc.o" \
      WG_MIX_FAKETCP_REALHOST_IFINDEX="${VETH_A_IFINDEX}" \
      WG_MIX_FAKETCP_REALHOST_PEER_IFINDEX="${VETH_B_IFINDEX}" \
      WG_MIX_FAKETCP_REALHOST_XDP_MODE=generic WG_MIX_FAKETCP_REALHOST_RUN_ID="${RUN_ID}" \
      /usr/bin/timeout --signal=TERM --kill-after=10s 6m /usr/bin/go -C "${SOURCE}" \
      test ./internal/dataplane -run "^${name}$" -count=1 -timeout=5m -v
    require_zero "O${step}.run"
    run_step "O${step}.links" bpf-links /usr/sbin/bpftool -j link show
    require_zero "O${step}.links"
    /usr/bin/cmp -s "${EVIDENCE_ROOT}/N5.links-before.out" "${STEP_LOG}" ||
      fail "faketcp-link-leak:${name}" 79
    ((step++))
  done
  run_step O9.pin "${PIN_PATH}" /usr/bin/test ! -e "${PIN_PATH}"
  require_zero O9.pin
}

check_iperf() {
  local step="$1" direction="$2" streams="$3" expected_seconds="$4"
  run_step "${step}.check" "${STEP_LOG}" /usr/bin/python3 -I \
    "${SOURCE}/scripts/realhost-b82-${RUN_ID}/check-realhost-iperf.py" one "${STEP_LOG}" \
    --direction "${direction}" --streams "${streams}" --minimum-bytes 1048576 \
    --minimum-fairness 0.90 --maximum-retransmit-rate 0.0001 \
    --expected-seconds "${expected_seconds}" --maximum-duration-deviation 0.5 \
    --minimum-delivery-ratio 0.99
  require_zero "${step}.check"
}

run_iperf_cell() {
  local cell="$1" streams direction step json_path
  local -a direction_args=()
  for streams in 1 4 16; do
    for direction in forward reverse bidir; do
      direction_args=()
      case "${direction}" in
        forward) ;;
        reverse) direction_args=(-R) ;;
        bidir) direction_args=(--bidir) ;;
        *) fail "iperf-direction:${direction}" 64 ;;
      esac
      step="P.${cell}.bare.p${streams}.${direction}"
      run_step "${step}" "${PEER_ADDRESS}:${PEER_PORT}" /usr/bin/timeout \
        --signal=TERM --kill-after=10s 50s /usr/bin/iperf3 \
        -c "${PEER_ADDRESS}" -p "${PEER_PORT}" --connect-timeout 5000 \
        --json --omit 2 -t 30 -P "${streams}" "${direction_args[@]}"
      require_zero "${step}"
      json_path="${STEP_LOG}"
      check_iperf "${step}" "${direction}" "${streams}" 30
      [[ "${json_path}" == "${EVIDENCE_ROOT}/${step}.out" ]] || fail "iperf-log-path:${step}" 79
    done
  done
}

preflight_peer() {
  run_step P0 "${PEER_ADDRESS}:${PEER_PORT}" /usr/bin/timeout \
    --signal=TERM --kill-after=10s 15s /usr/bin/iperf3 \
    -c "${PEER_ADDRESS}" -p "${PEER_PORT}" --connect-timeout 5000 \
    --json --omit 1 -t 1 -P 1
  require_zero P0
  check_iperf P0 forward 1 1
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
  for name in "${SCOPED_CONTRACT_TEST_NAME}" "${SCOPED_TEST_NAME}" "${SCOPED_RESTORE_TEST_NAME}"; do
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

run_scoped_realnic_test() {
  local cell="$1" profile="$2" timeout_outer="$3" timeout_go="$4"
  local scope pin traffic_seconds passes streams directions windows minimum_seconds
  scope="$(scoped_root_for_cell "${cell}")" || fail "scoped-root:${cell}" 64
  pin="$(scoped_pin_for_cell "${cell}")" || fail "scoped-pin:${cell}" 64
  [[ "${profile}" == 'matrix' || "${profile}" == 'mtu' || "${profile}" == 'soak' ]] ||
    fail "scoped-profile:${profile}" 64
  [[ "${timeout_outer}" =~ ^[1-9][0-9]*$ && "${timeout_go}" =~ ^[1-9][0-9]*$ ]] ||
    fail "scoped-timeout:${profile}" 64
  case "${profile}" in
    matrix)
      traffic_seconds="${MATRIX_TRAFFIC_SECONDS}"
      passes="${MATRIX_PASSES}"
      streams=1,4,16
      directions=forward,reverse,bidir
      windows=1
      minimum_seconds=$((3 * 3 * traffic_seconds * passes))
      ;;
    mtu)
      traffic_seconds="${MTU_TRAFFIC_SECONDS}"
      passes="${MTU_PASSES}"
      streams=4
      directions=bidir
      windows=1
      minimum_seconds=$((traffic_seconds * passes))
      ;;
    soak)
      traffic_seconds="${SESSION_SECONDS}"
      passes=1
      streams=4
      directions=bidir
      windows="${SOAK_WINDOWS}"
      minimum_seconds=$((traffic_seconds * windows))
      ;;
  esac
  ((timeout_go >= minimum_seconds + 60 && timeout_outer >= timeout_go + 30)) ||
    fail "scoped-time-budget:${profile}:minimum=${minimum_seconds}" 64
  run_step "P.${cell}.scope-pre" "${scope}" /usr/bin/test ! -e "${scope}"
  require_zero "P.${cell}.scope-pre"
  run_step "P.${cell}.pin-pre" "${pin}" /usr/bin/test ! -e "${pin}"
  require_zero "P.${cell}.pin-pre"
  run_step "P.${cell}.scoped-active" "${SCOPED_TEST_NAME}" /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${STAGE_ROOT}/go-cache-realhost" GOENV=off GOFLAGS= \
    GOMODCACHE="${STAGE_ROOT}/go-mod-cache-realhost" GOPATH="${STAGE_ROOT}/go-path-realhost" \
    GOTMPDIR="${STAGE_ROOT}/go-tmp-realhost" GOWORK=off GO111MODULE=on TMPDIR="${STAGE_ROOT}/go-tmp-realhost" \
    WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION=1 \
    WG_MIX_EBPF_SCOPED_REALNIC_ACTION=run WG_MIX_EBPF_SCOPED_REALNIC_RUN_ID="${RUN_ID}" \
    WG_MIX_EBPF_SCOPED_REALNIC_CELL="${cell}" WG_MIX_EBPF_SCOPED_REALNIC_PROFILE="${profile}" \
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
    WG_MIX_EBPF_SCOPED_REALNIC_IPERF_CHECKER="${SOURCE}/scripts/realhost-b82-${RUN_ID}/check-realhost-iperf.py" \
    WG_MIX_EBPF_SCOPED_REALNIC_TC_ATTACH=tcx \
    WG_MIX_EBPF_SCOPED_REALNIC_TYPEWORD_MODE=identity \
    WG_MIX_EBPF_SCOPED_REALNIC_TRANSPORT=udp WG_MIX_EBPF_SCOPED_REALNIC_CIPHER=none \
    WG_MIX_EBPF_SCOPED_REALNIC_FAILURE_POLICY=retain \
    WG_MIX_EBPF_SCOPED_REALNIC_STREAMS="${streams}" \
    WG_MIX_EBPF_SCOPED_REALNIC_DIRECTIONS="${directions}" \
    WG_MIX_EBPF_SCOPED_REALNIC_PASSES="${passes}" \
    WG_MIX_EBPF_SCOPED_REALNIC_SESSION_SECONDS="${traffic_seconds}" \
    WG_MIX_EBPF_SCOPED_REALNIC_SOAK_SECONDS="${SOAK_SECONDS}" \
    WG_MIX_EBPF_SCOPED_REALNIC_SOAK_WINDOWS="${windows}" \
    WG_MIX_EBPF_SCOPED_REALNIC_PING_INTERVAL_SECONDS=1 \
    WG_MIX_EBPF_SCOPED_REALNIC_MONITOR_INTERVAL_SECONDS=10 \
    WG_MIX_EBPF_SCOPED_REALNIC_MONITOR_SAMPLES=360 \
    /usr/bin/timeout --signal=TERM --kill-after=30s "${timeout_outer}s" \
    /usr/bin/go -C "${SOURCE}" test ./internal/dataplane \
    -run "^${SCOPED_TEST_NAME}$" -count=1 -timeout="${timeout_go}s" -v
  require_zero "P.${cell}.scoped-active"
  /usr/bin/grep -Fqx -- "SCOPED_REALNIC_COMPLETE cell=${cell} restored=1" "${STEP_LOG}" ||
    fail "scoped-completion-marker:${cell}" 79
  verify_scoped_kernel_restored "P.${cell}.restored" "${cell}"
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

run_nic_matrix() {
  local cell
  for cell in original all-on all-off tx-path rx-path; do
    apply_feature_cell "${cell}"
    run_iperf_cell "${cell}"
    run_scoped_realnic_test "${cell}" matrix \
      "${MATRIX_OUTER_TIMEOUT_SECONDS}" "${MATRIX_GO_TIMEOUT_SECONDS}"
    run_step "P.${cell}.stats" "${INTERFACE}" /usr/sbin/ethtool -S "${INTERFACE}"
    require_zero "P.${cell}.stats"
  done
  restore_nic_state P.matrix.restore
  audit_line not-covered P.peer-mutation "${PEER_ADDRESS}" 0 \
    'peer offload and MTU mutation prohibited; endpoint traffic only' || fail 'audit-peer-not-covered'
  audit_line not-covered P.faketcp-physical-e2e "${WG_PEER_ADDRESS}" 0 \
    'read-only peer has no reviewed FakeTCP dataplane; veth XDP/TCX coverage is not physical e2e' ||
    fail 'audit-faketcp-physical-not-covered'
  audit_line not-covered P.xor-physical-e2e "${WG_PEER_ADDRESS}" 0 \
    'read-only peer has no reviewed shared XOR cipher; passthrough WG active control only' ||
    fail 'audit-xor-physical-not-covered'
}

run_mtu_boundaries() {
  restore_nic_state Q.baseline
  run_step Q1 "${INTERFACE}" /usr/sbin/ip link set dev "${INTERFACE}" mtu 1492
  require_zero Q1
  [[ "$(read_single_line "/sys/class/net/${INTERFACE}/mtu")" == '1492' ]] || fail 'Q1:mtu-not-applied' 79
  run_step Q2 mtu-positive /usr/bin/ping -4 -I "${INTERFACE}" -M do -c 3 -W 2 -s 1464 "${PEER_ADDRESS}"
  require_zero Q2
  run_step Q3 mtu-negative /usr/bin/ping -4 -I "${INTERFACE}" -M do -c 1 -W 2 -s 1465 "${PEER_ADDRESS}"
  ((STEP_RC != 0)) || fail 'Q3:oversize-unexpected-success' 79
  run_scoped_realnic_test mtu1492 mtu \
    "${MTU_OUTER_TIMEOUT_SECONDS}" "${MTU_GO_TIMEOUT_SECONDS}"
  restore_nic_state Q.restore
  run_step Q4 mtu1500-positive /usr/bin/ping -4 -I "${INTERFACE}" -M do -c 3 -W 2 -s 1472 "${PEER_ADDRESS}"
  require_zero Q4
  run_step Q5 mtu1500-negative /usr/bin/ping -4 -I "${INTERFACE}" -M do -c 1 -W 2 -s 1473 "${PEER_ADDRESS}"
  ((STEP_RC != 0)) || fail 'Q5:oversize-unexpected-success' 79
  run_scoped_realnic_test mtu1500 mtu \
    "${MTU_OUTER_TIMEOUT_SECONDS}" "${MTU_GO_TIMEOUT_SECONDS}"
}

run_soak() {
  apply_feature_cell all-on-soak
  run_scoped_realnic_test soak soak \
    "${SOAK_OUTER_TIMEOUT_SECONDS}" "${SOAK_GO_TIMEOUT_SECONDS}"
  restore_nic_state R.restore
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
  validate_common_identity
  validate_owner_marker
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
  if [[ -f "${MODULE_LOADED}" && ! -f "${MODULE_UNLOADED}" ]]; then
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

run_all() {
  validate_common_identity
  [[ ! -e "${PIN_PATH}" && ! -L "${PIN_PATH}" ]] || fail 'pin-path-preexists' 79
  [[ ! -e "/sys/module/${MODULE_NAME}" ]] || fail 'checksum-module-preexists' 79
  create_evidence_root
  run_step U1 "${STAGE_ROOT}/go-cache-realhost" /usr/bin/test ! -e "${STAGE_ROOT}/go-cache-realhost"
  require_zero U1
  run_step U2 "${STAGE_ROOT}/go-cache-realhost" /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}/go-cache-realhost"
  require_zero U2
  run_step U3 "${STAGE_ROOT}/go-mod-cache-realhost" /usr/bin/test ! -e "${STAGE_ROOT}/go-mod-cache-realhost"
  require_zero U3
  run_step U4 "${STAGE_ROOT}/go-mod-cache-realhost" /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}/go-mod-cache-realhost"
  require_zero U4
  run_step U5 "${STAGE_ROOT}/go-path-realhost" /usr/bin/test ! -e "${STAGE_ROOT}/go-path-realhost"
  require_zero U5
  run_step U6 "${STAGE_ROOT}/go-path-realhost" /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}/go-path-realhost"
  require_zero U6
  run_step U7 "${STAGE_ROOT}/go-tmp-realhost" /usr/bin/test ! -e "${STAGE_ROOT}/go-tmp-realhost"
  require_zero U7
  run_step U8 "${STAGE_ROOT}/go-tmp-realhost" /usr/bin/mkdir --mode=0700 -- "${STAGE_ROOT}/go-tmp-realhost"
  require_zero U8
  snapshot_host
  capture_nic_state
  preflight_peer
  build_artifacts
  require_scoped_realnic_contract P
  create_owned_veth
  run_exact_tcx_lifecycle
  load_checksum_module
  run_faketcp_tests
  unload_checksum_module
  delete_owned_veth
  run_nic_matrix
  run_mtu_boundaries
  run_soak
  restore_nic_state Z.final
  run_step Z0.tcx-pin "${PIN_PATH}" /usr/bin/test ! -e "${PIN_PATH}"
  require_zero Z0.tcx-pin
  verify_all_scoped_pins_absent
  run_step Z1 links-final /usr/sbin/bpftool -j link show
  require_zero Z1
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A13.out" "${STEP_LOG}" || fail 'final-bpf-link-drift' 79
  run_step Z2 qdisc-final /usr/sbin/tc -j qdisc show dev "${INTERFACE}"
  require_zero Z2
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A10.out" "${STEP_LOG}" || fail 'final-qdisc-drift' 79
  run_step Z3 ingress-final /usr/sbin/tc -j filter show dev "${INTERFACE}" ingress
  require_zero Z3
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A11.out" "${STEP_LOG}" || fail 'final-ingress-drift' 79
  run_step Z4 egress-final /usr/sbin/tc -j filter show dev "${INTERFACE}" egress
  require_zero Z4
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A12.out" "${STEP_LOG}" || fail 'final-egress-drift' 79
  run_step Z5 programs-final /usr/sbin/bpftool -j prog show
  require_zero Z5
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A14.out" "${STEP_LOG}" || fail 'final-bpf-program-drift' 79
  run_step Z6 maps-final /usr/sbin/bpftool -j map show
  require_zero Z6
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A15.out" "${STEP_LOG}" || fail 'final-bpf-map-drift' 79
  run_step Z7 modules-final /usr/sbin/lsmod
  require_zero Z7
  /usr/bin/cmp -s "${EVIDENCE_ROOT}/A18.out" "${STEP_LOG}" || fail 'final-module-drift' 79
  write_once "${COMPLETED_MARKER}" "run_id=${RUN_ID}" "commit=${COMMIT}" 'state=complete' "utc=$(utc_now)"
  printf 'REALHOST_V6_COMPLETE run_id=%s commit=%s evidence=%s\n' "${RUN_ID}" "${COMMIT}" "${EVIDENCE_ROOT}"
}

parse_arguments "$@"
parse_rc=$?
((parse_rc == 0)) || fail "arguments:rc=${parse_rc}" "${parse_rc}"

if [[ "${MODE}" == 'plan' ]]; then
  render_plan
  exit 0
fi

require_tooling
case "${MODE}" in
  run) run_all ;;
  restore) restore_after_failure ;;
  *) fail 'unreachable-mode' 64 ;;
esac
