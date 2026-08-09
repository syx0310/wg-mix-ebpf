#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly CONTROLLER_RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly VETH_RUN_ID='a19f7c2e'
readonly RESOURCE_ID='d34b8e65'
readonly STAGES_ROOT='/run/wg-mix-ebpf-source-stages'
readonly EXPECTED_CONTROLLER_SOURCE="${STAGES_ROOT}/${CONTROLLER_RUN_ID}/source"
readonly EXPECTED_BUNDLE="/home/siyixuan/wg-mix-ebpf-test/unpriv-${PACKAGE_ID}/source-${PACKAGE_ID}.bundle"
readonly VETH_STAGE_ROOT="${STAGES_ROOT}/${VETH_RUN_ID}"
readonly ROOT_BUNDLE="${VETH_STAGE_ROOT}/source-${PACKAGE_ID}-${RESOURCE_ID}.bundle"
readonly VETH_SOURCE="${VETH_STAGE_ROOT}/source"
readonly EVIDENCE_ROOT="${VETH_STAGE_ROOT}/veth-evidence-${RESOURCE_ID}"
readonly OWNER_MARKER="${EVIDENCE_ROOT}/owner.v1"
readonly AUDIT_LOG="${EVIDENCE_ROOT}/audit.log"
readonly SNAPSHOT_READY="${EVIDENCE_ROOT}/snapshot-ready.v1"
readonly VETH_INTENT="${EVIDENCE_ROOT}/veth-intent.v1"
readonly VETH_CREATED="${EVIDENCE_ROOT}/veth-created.v1"
readonly VETH_OWNED="${EVIDENCE_ROOT}/veth-owned.v1"
readonly VETH_DELETED="${EVIDENCE_ROOT}/veth-deleted.v1"
readonly TCX_INTENT="${EVIDENCE_ROOT}/tcx-intent.v1"
readonly TCX_COMPLETED="${EVIDENCE_ROOT}/tcx-completed.v1"
readonly TCX_RESTORED="${EVIDENCE_ROOT}/tcx-restored.v1"
readonly MODULE_INTENT="${EVIDENCE_ROOT}/module-intent.v1"
readonly MODULE_LOADED="${EVIDENCE_ROOT}/module-loaded.v1"
readonly MODULE_UNLOADED="${EVIDENCE_ROOT}/module-unloaded.v1"
readonly COMPLETED_MARKER="${EVIDENCE_ROOT}/completed.v1"
readonly RESTORED_MARKER="${EVIDENCE_ROOT}/restored.v1"
readonly PIN_PATH="/sys/fs/bpf/wg-mix-ebpf-${VETH_RUN_ID}-tcx"
readonly TCX_RUNTIME_ROOT="${EVIDENCE_ROOT}/tcx-runtime"
readonly GO_CACHE="${VETH_STAGE_ROOT}/go-cache"
readonly GO_MOD_CACHE="${VETH_STAGE_ROOT}/go-mod-cache"
readonly GO_PATH="${VETH_STAGE_ROOT}/go-path"
readonly GO_TMP="${VETH_STAGE_ROOT}/go-tmp-realhost"
readonly VETH_A="wg${VETH_RUN_ID:0:5}a"
readonly VETH_B="wg${VETH_RUN_ID:0:5}b"
readonly VETH_A_ALIAS="wg-mix-ebpf:${VETH_RUN_ID}:a"
readonly VETH_B_ALIAS="wg-mix-ebpf:${VETH_RUN_ID}:b"
readonly MODULE_NAME='wg_mix_faketcp_checksum'
readonly EXPECTED_HOSTNAME='ubuntu-2604-test'
readonly EXPECTED_KERNEL='7.0.0-28-generic'
readonly EXPECTED_MACHINE_ID='9db3fb717cc74974b2a6b243d67f67b9'
readonly READ_ONLY_INTERFACE='ens33'
readonly READ_ONLY_PEER='47.116.202.155'
readonly SELF_PATH_FROM_ROOT="scripts/realhost-b82-${CONTROLLER_RUN_ID}/root-veth-n-r.sh"

readonly -a OFFLOAD_TESTS=(
  TestFakeTCPRealHostVirtioNetHeaderEncoding
  TestFakeTCPRealHostGSOOutputMatcher
  TestFakeTCPRealHostGSOProbeIsolationContract
)
readonly -a REALHOST_TESTS=(
  TestExperimentalFakeTCPRealHostLifecycleIntegration
  TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration
  TestBaselineExperimentalRealHostMutualExclusionIntegration
)
readonly -a GIT_COMMAND=(
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0
  /usr/bin/git --no-pager --no-replace-objects
  -c core.attributesFile=/dev/null -c core.fsmonitor=false
  -c core.hooksPath=/dev/null
)

MODE=''
CONTROLLER_SOURCE=''
COMMIT=''
BUNDLE=''
BUNDLE_SHA256=''
WG_STATE=''
STEP_RC=125
STEP_LOG=''
INITIAL_NETNS=''
ORIGINAL_BOOT_ID=''
VETH_A_IFINDEX=''
VETH_B_IFINDEX=''
VETH_A_MAC=''
VETH_B_MAC=''
declare -a BOOTSTRAP_AUDIT_LINES=()

usage() {
  printf '%s\n' \
    "usage: $0 {plan|run|restore} --controller-source ${EXPECTED_CONTROLLER_SOURCE}" \
    '  --commit 40-lowercase-hex' \
    "  --bundle ${EXPECTED_BUNDLE} --bundle-sha256 64-lowercase-hex" \
    '  --wg-state absent' >&2
}

fail() {
  printf 'B82_VETH_V6_STOP run_id=%s resource_id=%s reason=%s rc=%s evidence=%s; no automatic teardown\n' \
    "${VETH_RUN_ID}" "${RESOURCE_ID}" "$1" "${2:-125}" "${EVIDENCE_ROOT}" >&2
  exit "${2:-125}"
}

valid_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ && ! "$1" =~ ^0{40}$ && ! "$1" =~ ^f{40}$ ]]
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ && ! "$1" =~ ^0{64}$ && ! "$1" =~ ^f{64}$ ]]
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
      --controller-source) CONTROLLER_SOURCE="$2" ;;
      --commit) COMMIT="$2" ;;
      --bundle) BUNDLE="$2" ;;
      --bundle-sha256) BUNDLE_SHA256="$2" ;;
      --wg-state) WG_STATE="$2" ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  [[ "${CONTROLLER_SOURCE}" == "${EXPECTED_CONTROLLER_SOURCE}" &&
    "${BUNDLE}" == "${EXPECTED_BUNDLE}" && "${WG_STATE}" == 'absent' ]] || return 65
  valid_commit "${COMMIT}" || return 65
  valid_sha256 "${BUNDLE_SHA256}" || return 65
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
  local name
  printf 'B82_VETH_V6_PLAN_ONLY controller_run_id=%s run_id=%s resource_id=%s commit=%s bundle_sha256=%s\n' \
    "${CONTROLLER_RUN_ID}" "${VETH_RUN_ID}" "${RESOURCE_ID}" "${COMMIT}" "${BUNDLE_SHA256}"
  printf 'B82_VETH_V6_SCOPE wg_state=absent wg_active_scoped=not-covered pass=0 raw_ens33=not-covered raw_ens33_pass=0 peer_47=read-only peer_access=0\n'
  plan_command B0 /usr/bin/mkdir --mode=0700 -- "${VETH_STAGE_ROOT}"
  plan_command B1 /usr/bin/mkdir --mode=0700 -- "${EVIDENCE_ROOT}"
  plan_command B2 shell-builtin noclobber-create-audit-owner-and-exact-state-markers "${EVIDENCE_ROOT}"
  plan_command S0.copy /usr/bin/timeout --signal=TERM --kill-after=10s 2m \
    /usr/bin/cp --no-clobber --no-preserve=mode,ownership,timestamps -- "${BUNDLE}" "${ROOT_BUNDLE}"
  plan_command S0.mode /usr/bin/chmod 0600 "${ROOT_BUNDLE}"
  plan_command S0.hash /usr/bin/sha256sum -- "${ROOT_BUNDLE}"
  plan_command S0.verify "${GIT_COMMAND[@]}" -C "${CONTROLLER_SOURCE}" bundle verify "${ROOT_BUNDLE}"
  plan_command S1 "${GIT_COMMAND[@]}" clone --no-local --no-checkout -- "${ROOT_BUNDLE}" "${VETH_SOURCE}"
  plan_command S2 "${GIT_COMMAND[@]}" -C "${VETH_SOURCE}" checkout --detach "${COMMIT}"
  plan_command S3.cache /usr/bin/mkdir --mode=0700 -- "${GO_CACHE}"
  plan_command S3.mod-cache /usr/bin/mkdir --mode=0700 -- "${GO_MOD_CACHE}"
  plan_command S3.go-path /usr/bin/mkdir --mode=0700 -- "${GO_PATH}"
  plan_command S3.tmp /usr/bin/mkdir --mode=0700 -- "${GO_TMP}"
  plan_command A.netns /usr/bin/readlink /proc/self/ns/net
  plan_command A.interface /usr/sbin/ip -d -j link show dev "${READ_ONLY_INTERFACE}"
  plan_command A.features /usr/sbin/ethtool -k "${READ_ONLY_INTERFACE}"
  plan_command A.qdisc /usr/sbin/tc -j qdisc show dev "${READ_ONLY_INTERFACE}"
  plan_command A.ingress /usr/sbin/tc -j filter show dev "${READ_ONLY_INTERFACE}" ingress
  plan_command A.egress /usr/sbin/tc -j filter show dev "${READ_ONLY_INTERFACE}" egress
  plan_command A.peer-route /usr/sbin/ip -j route get "${READ_ONLY_PEER}"
  plan_command A.wg /usr/bin/wg show interfaces
  plan_command A.links /usr/sbin/bpftool -j link show
  plan_command A.programs /usr/sbin/bpftool -j prog show
  plan_command A.maps /usr/sbin/bpftool -j map show
  plan_command A.modules /usr/sbin/lsmod
  plan_command O.build /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GO=/usr/bin/go CLANG=/usr/bin/clang GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= \
    GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" GOTMPDIR="${GO_TMP}" \
    GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    /usr/bin/make --no-print-directory \
    -C "${VETH_SOURCE}" build-bpf build-faketcp-experimental-bpf \
    build-faketcp-checksum-kmod build test-bpf-object-manifests
  plan_command N.add /usr/sbin/ip link add "${VETH_A}" type veth peer name "${VETH_B}"
  plan_command N.alias-a /usr/sbin/ip link set dev "${VETH_A}" alias "${VETH_A_ALIAS}"
  plan_command N.alias-b /usr/sbin/ip link set dev "${VETH_B}" alias "${VETH_B_ALIAS}"
  plan_command N.up-a /usr/sbin/ip link set dev "${VETH_A}" up
  plan_command N.up-b /usr/sbin/ip link set dev "${VETH_B}" up
  plan_command T.tcx /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
    GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1 \
    WG_MIX_EBPF_TEST_OBJECT_PATH="${VETH_SOURCE}/build/wg_mix_tc.o" \
    WG_MIX_EBPF_TEST_PIN_PATH="${PIN_PATH}" WG_MIX_EBPF_TEST_IFINDEX=RUNTIME_VETH_IFINDEX \
    WG_MIX_EBPF_TEST_RUNTIME_ROOT="${TCX_RUNTIME_ROOT}" \
    WG_MIX_EBPF_TEST_PIN_LOCK_ROOT="${TCX_RUNTIME_ROOT}/locks" \
    WG_MIX_EBPF_TEST_PIN_OWNER_ROOT="${TCX_RUNTIME_ROOT}/owners" \
    WG_MIX_EBPF_TEST_INITIAL_NETNS=EXACT_INITIAL_NETNS \
    WG_MIX_EBPF_TEST_ACTION=run WG_MIX_EBPF_TEST_FAILURE_POLICY=retain \
    /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane \
    -run '^TestBPFFSPinLifecycleIntegration$' -count=1 -timeout=2m -v
  plan_command M.load /usr/sbin/insmod \
    "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
  plan_command F.verifier "${VETH_SOURCE}/bin/wg-mix-ebpf" bpf-load-test \
    --experimental-faketcp --object "${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" --json
  plan_command F.packet-probe /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
    GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    WG_MIX_FAKETCP_PACKET_TEST_OBJECT="${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" \
    /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane \
    -run '^TestFakeTCPBPFPacketProbe$' -count=1 -timeout=3m -v
  for name in "${OFFLOAD_TESTS[@]}"; do
    plan_command "F.offload-${name}" /usr/bin/env -i \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
      GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
      GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
      /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane \
      -run "^${name}$" -count=1 -timeout=2m -v
  done
  for name in "${REALHOST_TESTS[@]}"; do
    plan_command "F.realhost-${name}" /usr/bin/env -i \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
      GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
      GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
      WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION=1 \
      WG_MIX_FAKETCP_REALHOST_OBJECT="${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" \
      WG_MIX_FAKETCP_REALHOST_BASELINE_OBJECT="${VETH_SOURCE}/build/wg_mix_tc.o" \
      WG_MIX_FAKETCP_REALHOST_IFINDEX=RUNTIME_VETH_IFINDEX \
      WG_MIX_FAKETCP_REALHOST_PEER_IFINDEX=RUNTIME_PEER_IFINDEX \
      WG_MIX_FAKETCP_REALHOST_XDP_MODE=generic WG_MIX_FAKETCP_REALHOST_RUN_ID="${VETH_RUN_ID}" \
      /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane \
      -run "^${name}$" -count=1 -timeout=5m -v
  done
  plan_command M.unload /usr/sbin/rmmod "${MODULE_NAME}"
  plan_command N.delete /usr/sbin/ip link delete dev "${VETH_A}"
  plan_command R.tcx /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
    GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1 \
    WG_MIX_EBPF_TEST_OBJECT_PATH="${VETH_SOURCE}/build/wg_mix_tc.o" \
    WG_MIX_EBPF_TEST_PIN_PATH="${PIN_PATH}" WG_MIX_EBPF_TEST_IFINDEX=OWNED_VETH_IFINDEX \
    WG_MIX_EBPF_TEST_RUNTIME_ROOT="${TCX_RUNTIME_ROOT}" \
    WG_MIX_EBPF_TEST_PIN_LOCK_ROOT="${TCX_RUNTIME_ROOT}/locks" \
    WG_MIX_EBPF_TEST_PIN_OWNER_ROOT="${TCX_RUNTIME_ROOT}/owners" \
    WG_MIX_EBPF_TEST_INITIAL_NETNS=OWNER_MARKER_NETNS \
    WG_MIX_EBPF_TEST_ACTION=restore WG_MIX_EBPF_TEST_FAILURE_POLICY=retain \
    /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane \
    -run '^TestBPFFSPinLifecycleIntegration$' -count=1 -timeout=4m -v
  plan_command R.module /usr/sbin/rmmod "${MODULE_NAME}"
  plan_command R.veth /usr/sbin/ip link delete dev "${VETH_A}"
  plan_command Z.netns /usr/bin/readlink /proc/self/ns/net
  plan_command Z.links /usr/sbin/bpftool -j link show
  plan_command Z.programs /usr/sbin/bpftool -j prog show
  plan_command Z.maps /usr/sbin/bpftool -j map show
  plan_command Z.modules /usr/sbin/lsmod
  printf 'B82_VETH_V6_WRITE_SET stage=%s evidence=%s source=%s root_bundle=%s pin=%s veth=%s,%s module=%s retained=1\n' \
    "${VETH_STAGE_ROOT}" "${EVIDENCE_ROOT}" "${VETH_SOURCE}" "${ROOT_BUNDLE}" \
    "${PIN_PATH}" "${VETH_A}" "${VETH_B}" "${MODULE_NAME}"
  printf 'B82_VETH_V6_PLAN_COMPLETE commands_are_review_templates=1 no_commands_executed=1 credential_read=0 network_operations=0 capability_bits_changed=0\n'
}

utc_now() {
  /bin/date -u '+%Y-%m-%dT%H:%M:%SZ'
}

bootstrap_audit_line() {
  local event="$1" step="$2" target="$3" rc="$4" rendered="$5" timestamp line
  timestamp="$(utc_now)" || return $?
  [[ "${timestamp}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 79
  printf -v line 'utc=%q event=%q step=%q target=%q rc=%q argv=%q' \
    "${timestamp}" "${event}" "${step}" "${target}" "${rc}" "${rendered}"
  BOOTSTRAP_AUDIT_LINES+=("${line}")
  printf 'B82_VETH_V6_BOOTSTRAP_AUDIT %s\n' "${line}"
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
  bootstrap_audit_line start B2.audit-create "${AUDIT_LOG}" not-run "${rendered}" || return $?
  set -o noclobber
  printf '%s\n' "${BOOTSTRAP_AUDIT_LINES[@]}" >"${AUDIT_LOG}"
  rc=$?
  set +o noclobber
  bootstrap_audit_line finish B2.audit-create "${AUDIT_LOG}" "${rc}" "${rendered}" || return $?
  ((rc == 0)) || return "${rc}"
  last_index=$((${#BOOTSTRAP_AUDIT_LINES[@]} - 1))
  finish_line="${BOOTSTRAP_AUDIT_LINES[${last_index}]}"
  printf '%s\n' "${finish_line}" >>"${AUDIT_LOG}"
  persist_rc=$?
  ((persist_rc == 0))
}

audit_line() {
  local event="$1" step="$2" target="$3" rc="$4" rendered="$5" timestamp
  local -a status
  timestamp="$(utc_now)" || return $?
  [[ "${timestamp}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 79
  printf 'utc=%q event=%q step=%q target=%q rc=%q argv=%q\n' \
    "${timestamp}" "${event}" "${step}" "${target}" "${rc}" "${rendered}" |
    /usr/bin/tee -a "${AUDIT_LOG}"
  status=("${PIPESTATUS[@]}")
  ((${#status[@]} == 2 && status[0] == 0 && status[1] == 0))
}

run_step() {
  local step="$1" target="$2" rendered evidence_rendered
  local -a status
  shift 2
  [[ "${step}" =~ ^[A-Z][A-Za-z0-9_.-]{0,95}$ ]] || fail "invalid-step:${step}" 64
  STEP_LOG="${EVIDENCE_ROOT}/${step}.out"
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
  ((STEP_RC == 0)) || fail "$1:rc=${STEP_RC}" "${STEP_RC}"
}

write_once() {
  local path="$1" step rendered rc
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

read_single_line() {
  local value
  value="$(/usr/bin/cat -- "$1")" || return $?
  [[ -n "${value}" && "${value}" != *$'\n'* ]] || return 79
  printf '%s\n' "${value}"
}

read_optional_line() {
  local value
  value="$(/usr/bin/cat -- "$1")" || return $?
  [[ "${value}" != *$'\n'* ]] || return 79
  printf '%s\n' "${value}"
}

directory_identity() {
  /usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%F' -- "$1"
}

git_fixed() {
  "${GIT_COMMAND[@]}" "$@"
}

require_tooling() {
  local path
  local -a tools=(
    /bin/bash /bin/date
    /usr/bin/awk /usr/bin/basename /usr/bin/cat /usr/bin/chmod /usr/bin/cmp /usr/bin/cp /usr/bin/env
    /usr/bin/clang /usr/bin/git /usr/bin/go /usr/bin/grep /usr/bin/hostname /usr/bin/ls
    /usr/bin/make /usr/bin/mkdir /usr/bin/readlink /usr/bin/sha256sum
    /usr/bin/stat /usr/bin/tee /usr/bin/test /usr/bin/timeout /usr/bin/uname /usr/bin/wg
    /usr/sbin/bpftool /usr/sbin/ethtool /usr/sbin/insmod /usr/sbin/ip
    /usr/sbin/lsmod /usr/sbin/modinfo /usr/sbin/rmmod /usr/sbin/tc
  )
  for path in "${tools[@]}"; do
    [[ -x "${path}" ]] || fail "missing-tool:${path}" 69
  done
}

validate_controller_identity() {
  local canonical shape head dirty actual self_path actual_sha committed_sha
  ((EUID == 0)) || fail 'root-required' 77
  canonical="$(/usr/bin/readlink -e -- "${STAGES_ROOT}")" || fail 'stages-root-canonical'
  [[ "${canonical}" == "${STAGES_ROOT}" ]] || fail 'stages-root-path-changed' 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${STAGES_ROOT}")" || fail 'stages-root-stat'
  [[ "${shape}" == '0:0:700:directory' ]] || fail 'stages-root-shape' 79
  canonical="$(/usr/bin/readlink -e -- "${CONTROLLER_SOURCE}")" || fail 'controller-source-canonical'
  [[ "${canonical}" == "${EXPECTED_CONTROLLER_SOURCE}" ]] || fail 'controller-source-path-changed' 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${CONTROLLER_SOURCE}")" || fail 'controller-source-stat'
  [[ "${shape}" == '0:0:700:directory' ]] || fail 'controller-source-shape' 79
  head="$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse --verify HEAD)" || fail 'controller-source-head'
  [[ "${head}" == "${COMMIT}" ]] || fail 'controller-source-head-mismatch' 79
  dirty="$(git_fixed -C "${CONTROLLER_SOURCE}" status --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" ||
    fail 'controller-source-status'
  [[ -z "${dirty}" ]] || fail 'controller-source-dirty' 79
  self_path="${CONTROLLER_SOURCE}/${SELF_PATH_FROM_ROOT}"
  [[ "$0" == /* && "$0" == "${self_path}" ]] || fail 'runner-invocation-path' 79
  [[ -f "$0" && ! -L "$0" ]] || fail 'runner-invocation-shape' 79
  canonical="$(/usr/bin/readlink -e -- "$0")" || fail 'runner-self-canonical'
  [[ "${canonical}" == "${self_path}" ]] || fail 'runner-self-path-changed' 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "$0")" || fail 'runner-self-stat'
  [[ "${shape}" == '0:0:700:1:regular file' ]] || fail 'runner-self-metadata' 79
  actual="$(git_fixed -C "${CONTROLLER_SOURCE}" hash-object -- "${self_path}")" || fail 'runner-self-blob'
  [[ "${actual}" == "$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse "${COMMIT}:${SELF_PATH_FROM_ROOT}")" ]] ||
    fail 'runner-self-identity' 79
  actual_sha="$(/usr/bin/sha256sum -- "$0")" || fail 'runner-self-sha256'
  actual_sha="${actual_sha%% *}"
  committed_sha="$(git_fixed -C "${CONTROLLER_SOURCE}" show "${COMMIT}:${SELF_PATH_FROM_ROOT}" |
    /usr/bin/sha256sum)" || fail 'runner-committed-sha256'
  committed_sha="${committed_sha%% *}"
  valid_sha256 "${actual_sha}" && valid_sha256 "${committed_sha}" || fail 'runner-sha256-shape' 79
  [[ "${actual_sha}" == "${committed_sha}" ]] || fail 'runner-sha256-mismatch' 79
  actual="$(/usr/bin/hostname)" || fail 'hostname-read'
  [[ "${actual}" == "${EXPECTED_HOSTNAME}" ]] || fail 'hostname-mismatch' 79
  actual="$(/usr/bin/uname -r)" || fail 'kernel-read'
  [[ "${actual}" == "${EXPECTED_KERNEL}" ]] || fail 'kernel-mismatch' 79
  actual="$(read_single_line /etc/machine-id)" || fail 'machine-id-read'
  [[ "${actual}" == "${EXPECTED_MACHINE_ID}" ]] || fail 'machine-id-mismatch' 79
}

validate_package_bundle() {
  local canonical shape sha_line
  canonical="$(/usr/bin/readlink -e -- "${BUNDLE}")" || fail 'bundle-canonical'
  [[ "${canonical}" == "${EXPECTED_BUNDLE}" ]] || fail 'bundle-path-changed' 79
  shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${BUNDLE}")" || fail 'bundle-stat'
  [[ "${shape}" == 'siyixuan:siyixuan:600:1:regular file' ]] || fail 'bundle-shape' 79
  sha_line="$(/usr/bin/sha256sum -- "${BUNDLE}")" || fail 'bundle-hash'
  [[ "${sha_line}" == "${BUNDLE_SHA256}  ${BUNDLE}" ]] || fail 'bundle-hash-mismatch' 79
}

create_run_roots() {
  local rc
  [[ ! -e "${VETH_STAGE_ROOT}" && ! -L "${VETH_STAGE_ROOT}" ]] || fail 'veth-stage-exists' 78
  bootstrap_run_step B0.stage-create "${VETH_STAGE_ROOT}" \
    /usr/bin/mkdir --mode=0700 -- "${VETH_STAGE_ROOT}"
  rc=$?
  ((rc == 0)) || fail "veth-stage-create:rc=${rc}" "${rc}"
  bootstrap_run_step B1.evidence-create "${EVIDENCE_ROOT}" \
    /usr/bin/mkdir --mode=0700 -- "${EVIDENCE_ROOT}"
  rc=$?
  ((rc == 0)) || fail "evidence-create:rc=${rc}" "${rc}"
  create_bootstrap_audit_log || fail 'audit-create' $?
  ORIGINAL_BOOT_ID="$(read_single_line /proc/sys/kernel/random/boot_id)" || fail 'boot-id-read'
  INITIAL_NETNS="$(/usr/bin/readlink -- /proc/self/ns/net)" || fail 'initial-netns-read'
  [[ "${ORIGINAL_BOOT_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
    "${INITIAL_NETNS}" =~ ^net:\[[1-9][0-9]*\]$ ]] || fail 'initial-host-identity' 79
  write_once "${OWNER_MARKER}" \
    'format=wg-mix-ebpf-b82-veth-owner-v1' \
    "controller_run_id=${CONTROLLER_RUN_ID}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" \
    "commit=${COMMIT}" "bundle_sha256=${BUNDLE_SHA256}" "boot_id=${ORIGINAL_BOOT_ID}" \
    "initial_netns=${INITIAL_NETNS}" "stage_root=${VETH_STAGE_ROOT}" \
    "stage_identity=$(directory_identity "${VETH_STAGE_ROOT}")" \
    "evidence_identity=$(directory_identity "${EVIDENCE_ROOT}")"
}

validate_owner_marker() {
  local expected actual current_boot current_netns
  [[ -f "${OWNER_MARKER}" && ! -L "${OWNER_MARKER}" ]] || fail 'owner-marker-missing' 79
  current_boot="$(read_single_line /proc/sys/kernel/random/boot_id)" || fail 'restore-boot-id'
  current_netns="$(/usr/bin/readlink -- /proc/self/ns/net)" || fail 'restore-netns'
  expected="$(printf '%s\n' \
    'format=wg-mix-ebpf-b82-veth-owner-v1' \
    "controller_run_id=${CONTROLLER_RUN_ID}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" \
    "commit=${COMMIT}" "bundle_sha256=${BUNDLE_SHA256}" "boot_id=${current_boot}" \
    "initial_netns=${current_netns}" "stage_root=${VETH_STAGE_ROOT}" \
    "stage_identity=$(directory_identity "${VETH_STAGE_ROOT}")" \
    "evidence_identity=$(directory_identity "${EVIDENCE_ROOT}")")" || fail 'owner-expected-render'
  actual="$(/usr/bin/cat -- "${OWNER_MARKER}")" || fail 'owner-marker-read'
  [[ "${actual}" == "${expected}" ]] || fail 'owner-marker-mismatch' 79
  ORIGINAL_BOOT_ID="${current_boot}"
  INITIAL_NETNS="${current_netns}"
}

validate_veth_source() {
  local canonical shape sha_line head dirty staged_blob controller_blob
  canonical="$(/usr/bin/readlink -e -- "${VETH_SOURCE}")" || fail 'veth-source-canonical'
  [[ "${canonical}" == "${VETH_SOURCE}" ]] || fail 'veth-source-path-changed' 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${VETH_SOURCE}")" || fail 'veth-source-stat'
  [[ "${shape}" == '0:0:700:directory' ]] || fail 'veth-source-shape' 79
  [[ -f "${ROOT_BUNDLE}" && ! -L "${ROOT_BUNDLE}" ]] || fail 'root-bundle-file-shape' 79
  canonical="$(/usr/bin/readlink -e -- "${ROOT_BUNDLE}")" || fail 'root-bundle-canonical'
  [[ "${canonical}" == "${ROOT_BUNDLE}" ]] || fail 'root-bundle-path-changed' 79
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${ROOT_BUNDLE}")" || fail 'root-bundle-stat'
  [[ "${shape}" == '0:0:600:1:regular file' ]] || fail 'root-bundle-shape' 79
  sha_line="$(/usr/bin/sha256sum -- "${ROOT_BUNDLE}")" || fail 'root-bundle-hash'
  [[ "${sha_line}" == "${BUNDLE_SHA256}  ${ROOT_BUNDLE}" ]] || fail 'root-bundle-hash-mismatch' 79
  head="$(git_fixed -C "${VETH_SOURCE}" rev-parse --verify HEAD)" || fail 'veth-source-head'
  [[ "${head}" == "${COMMIT}" ]] || fail 'veth-source-head-mismatch' 79
  dirty="$(git_fixed -C "${VETH_SOURCE}" status --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" ||
    fail 'veth-source-status'
  [[ -z "${dirty}" ]] || fail 'veth-source-dirty' 79
  staged_blob="$(git_fixed -C "${VETH_SOURCE}" rev-parse "${COMMIT}:${SELF_PATH_FROM_ROOT}")" ||
    fail 'staged-runner-blob'
  controller_blob="$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse "${COMMIT}:${SELF_PATH_FROM_ROOT}")" ||
    fail 'controller-runner-blob'
  [[ "${staged_blob}" == "${controller_blob}" ]] || fail 'staged-runner-identity' 79
}

stage_source() {
  local name step sha_line shape
  [[ ! -e "${ROOT_BUNDLE}" && ! -L "${ROOT_BUNDLE}" ]] || fail 'root-bundle-preexists' 78
  run_step S0.copy "${ROOT_BUNDLE}" /usr/bin/timeout --signal=TERM --kill-after=10s 2m \
    /usr/bin/cp --no-clobber --no-preserve=mode,ownership,timestamps -- "${BUNDLE}" "${ROOT_BUNDLE}"
  require_zero S0.copy
  run_step S0.mode "${ROOT_BUNDLE}" /usr/bin/chmod 0600 "${ROOT_BUNDLE}"
  require_zero S0.mode
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${ROOT_BUNDLE}")" || fail 'root-bundle-stat'
  [[ "${shape}" == '0:0:600:1:regular file' ]] || fail 'root-bundle-shape' 79
  sha_line="$(/usr/bin/sha256sum -- "${ROOT_BUNDLE}")" || fail 'root-bundle-hash'
  [[ "${sha_line}" == "${BUNDLE_SHA256}  ${ROOT_BUNDLE}" ]] || fail 'root-bundle-hash-mismatch' 79
  run_step S0.bundle-verify bundle "${GIT_COMMAND[@]}" -C "${CONTROLLER_SOURCE}" \
    bundle verify "${ROOT_BUNDLE}"
  require_zero S0.bundle-verify
  run_step S1.clone "${VETH_SOURCE}" "${GIT_COMMAND[@]}" clone --no-local --no-checkout -- \
    "${ROOT_BUNDLE}" "${VETH_SOURCE}"
  require_zero S1.clone
  run_step S2.checkout "${VETH_SOURCE}" "${GIT_COMMAND[@]}" -C "${VETH_SOURCE}" \
    checkout --detach "${COMMIT}"
  require_zero S2.checkout
  validate_veth_source
  for name in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
    step="S3.$(/usr/bin/basename -- "${name}")"
    run_step "${step}" "${name}" /usr/bin/mkdir --mode=0700 -- "${name}"
    require_zero "${step}"
  done
}

snapshot_host() {
  run_step A.hostname hostname /usr/bin/hostname; require_zero A.hostname
  run_step A.kernel kernel /usr/bin/uname -r; require_zero A.kernel
  run_step A.machine machine-id /usr/bin/cat /etc/machine-id; require_zero A.machine
  run_step A.netns netns /usr/bin/readlink /proc/self/ns/net; require_zero A.netns
  /usr/bin/grep -Fqx -- "${INITIAL_NETNS}" "${STEP_LOG}" || fail 'snapshot-netns-drift' 79
  run_step A.interface "${READ_ONLY_INTERFACE}" /usr/sbin/ip -d -j link show dev "${READ_ONLY_INTERFACE}"
  require_zero A.interface
  run_step A.features "${READ_ONLY_INTERFACE}" /usr/sbin/ethtool -k "${READ_ONLY_INTERFACE}"
  require_zero A.features
  run_step A.qdisc "${READ_ONLY_INTERFACE}" /usr/sbin/tc -j qdisc show dev "${READ_ONLY_INTERFACE}"
  require_zero A.qdisc
  run_step A.ingress "${READ_ONLY_INTERFACE}" /usr/sbin/tc -j filter show dev "${READ_ONLY_INTERFACE}" ingress
  require_zero A.ingress
  run_step A.egress "${READ_ONLY_INTERFACE}" /usr/sbin/tc -j filter show dev "${READ_ONLY_INTERFACE}" egress
  require_zero A.egress
  run_step A.peer-route "${READ_ONLY_PEER}" /usr/sbin/ip -j route get "${READ_ONLY_PEER}"
  require_zero A.peer-route
  run_step A.wg wireguard /usr/bin/wg show interfaces; require_zero A.wg
  [[ ! -s "${STEP_LOG}" ]] || fail 'wireguard-topology-not-absent' 79
  run_step A.links bpf-links /usr/sbin/bpftool -j link show; require_zero A.links
  run_step A.programs bpf-programs /usr/sbin/bpftool -j prog show; require_zero A.programs
  run_step A.maps bpf-maps /usr/sbin/bpftool -j map show; require_zero A.maps
  run_step A.modules modules /usr/sbin/lsmod; require_zero A.modules
  write_once "${SNAPSHOT_READY}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" 'state=ready'
}

build_artifacts() {
  run_step O.build build-artifacts /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GO=/usr/bin/go CLANG=/usr/bin/clang GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= \
    GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" GOTMPDIR="${GO_TMP}" \
    GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    /usr/bin/timeout --signal=TERM --kill-after=30s 30m /usr/bin/make \
    --no-print-directory -C "${VETH_SOURCE}" build-bpf build-faketcp-experimental-bpf \
    build-faketcp-checksum-kmod build test-bpf-object-manifests
  require_zero O.build
  run_step O.hash artifacts /usr/bin/sha256sum -- \
    "${VETH_SOURCE}/bin/wg-mix-ebpf" "${VETH_SOURCE}/build/wg_mix_tc.o" \
    "${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" \
    "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
  require_zero O.hash
}

read_veth_identity() {
  VETH_A_IFINDEX="$(read_single_line "/sys/class/net/${VETH_A}/ifindex")" || return $?
  VETH_B_IFINDEX="$(read_single_line "/sys/class/net/${VETH_B}/ifindex")" || return $?
  VETH_A_MAC="$(read_single_line "/sys/class/net/${VETH_A}/address")" || return $?
  VETH_B_MAC="$(read_single_line "/sys/class/net/${VETH_B}/address")" || return $?
  [[ "${VETH_A_IFINDEX}" =~ ^[1-9][0-9]*$ && "${VETH_B_IFINDEX}" =~ ^[1-9][0-9]*$ &&
    "${VETH_A_MAC}" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ &&
    "${VETH_B_MAC}" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ ]] || return 79
}

create_owned_veth() {
  run_step N.pre-a "${VETH_A}" /usr/sbin/ip link show dev "${VETH_A}"
  ((STEP_RC == 1)) || fail "veth-a-preexists:rc=${STEP_RC}" 79
  run_step N.pre-b "${VETH_B}" /usr/sbin/ip link show dev "${VETH_B}"
  ((STEP_RC == 1)) || fail "veth-b-preexists:rc=${STEP_RC}" 79
  [[ ! -e "${PIN_PATH}" && ! -L "${PIN_PATH}" ]] || fail 'tcx-pin-preexists' 79
  write_once "${VETH_INTENT}" 'format=wg-mix-ebpf-b82-veth-intent-v1' \
    "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${ORIGINAL_BOOT_ID}" \
    "netns=${INITIAL_NETNS}" "a=${VETH_A}" "b=${VETH_B}" 'state=creating'
  run_step N.add "${VETH_A}:${VETH_B}" /usr/sbin/ip link add "${VETH_A}" type veth peer name "${VETH_B}"
  require_zero N.add
  read_veth_identity || fail 'veth-created-identity' $?
  write_once "${VETH_CREATED}" 'format=wg-mix-ebpf-b82-veth-created-v1' \
    "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "a=${VETH_A}" \
    "a_ifindex=${VETH_A_IFINDEX}" "a_mac=${VETH_A_MAC}" "b=${VETH_B}" \
    "b_ifindex=${VETH_B_IFINDEX}" "b_mac=${VETH_B_MAC}"
  run_step N.alias-a "${VETH_A}" /usr/sbin/ip link set dev "${VETH_A}" alias "${VETH_A_ALIAS}"
  require_zero N.alias-a
  run_step N.alias-b "${VETH_B}" /usr/sbin/ip link set dev "${VETH_B}" alias "${VETH_B_ALIAS}"
  require_zero N.alias-b
  run_step N.up-a "${VETH_A}" /usr/sbin/ip link set dev "${VETH_A}" up; require_zero N.up-a
  run_step N.up-b "${VETH_B}" /usr/sbin/ip link set dev "${VETH_B}" up; require_zero N.up-b
  write_once "${VETH_OWNED}" 'format=wg-mix-ebpf-b82-veth-owned-v1' \
    "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "a_ifindex=${VETH_A_IFINDEX}" \
    "a_alias=${VETH_A_ALIAS}" "b_ifindex=${VETH_B_IFINDEX}" "b_alias=${VETH_B_ALIAS}" 'state=owned'
}

load_veth_state() {
  local expected actual
  [[ -f "${VETH_CREATED}" && ! -L "${VETH_CREATED}" ]] || fail 'veth-created-marker-missing' 79
  VETH_A_IFINDEX="$(/usr/bin/awk -F= '$1 == "a_ifindex" {print $2}' "${VETH_CREATED}")" || fail 'veth-a-ifindex-marker'
  VETH_B_IFINDEX="$(/usr/bin/awk -F= '$1 == "b_ifindex" {print $2}' "${VETH_CREATED}")" || fail 'veth-b-ifindex-marker'
  VETH_A_MAC="$(/usr/bin/awk -F= '$1 == "a_mac" {print $2}' "${VETH_CREATED}")" || fail 'veth-a-mac-marker'
  VETH_B_MAC="$(/usr/bin/awk -F= '$1 == "b_mac" {print $2}' "${VETH_CREATED}")" || fail 'veth-b-mac-marker'
  [[ "${VETH_A_IFINDEX}" =~ ^[1-9][0-9]*$ && "${VETH_B_IFINDEX}" =~ ^[1-9][0-9]*$ &&
    "${VETH_A_MAC}" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ &&
    "${VETH_B_MAC}" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ ]] || fail 'veth-created-marker-values' 79
  expected="$(printf '%s\n' 'format=wg-mix-ebpf-b82-veth-created-v1' \
    "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "a=${VETH_A}" \
    "a_ifindex=${VETH_A_IFINDEX}" "a_mac=${VETH_A_MAC}" "b=${VETH_B}" \
    "b_ifindex=${VETH_B_IFINDEX}" "b_mac=${VETH_B_MAC}")" || fail 'veth-created-expected'
  actual="$(/usr/bin/cat -- "${VETH_CREATED}")" || fail 'veth-created-read'
  [[ "${actual}" == "${expected}" ]] || fail 'veth-created-marker-mismatch' 79
}

verify_created_veth() {
  local a_alias b_alias a_iflink b_iflink expected actual
  [[ "$(read_single_line "/sys/class/net/${VETH_A}/ifindex")" == "${VETH_A_IFINDEX}" &&
    "$(read_single_line "/sys/class/net/${VETH_B}/ifindex")" == "${VETH_B_IFINDEX}" &&
    "$(read_single_line "/sys/class/net/${VETH_A}/address")" == "${VETH_A_MAC}" &&
    "$(read_single_line "/sys/class/net/${VETH_B}/address")" == "${VETH_B_MAC}" ]] || return 79
  a_iflink="$(read_single_line "/sys/class/net/${VETH_A}/iflink")" || return $?
  b_iflink="$(read_single_line "/sys/class/net/${VETH_B}/iflink")" || return $?
  [[ "${a_iflink}" == "${VETH_B_IFINDEX}" && "${b_iflink}" == "${VETH_A_IFINDEX}" ]] || return 79
  a_alias="$(read_optional_line "/sys/class/net/${VETH_A}/ifalias")" || return $?
  b_alias="$(read_optional_line "/sys/class/net/${VETH_B}/ifalias")" || return $?
  [[ -z "${a_alias}" || "${a_alias}" == "${VETH_A_ALIAS}" ]] || return 79
  [[ -z "${b_alias}" || "${b_alias}" == "${VETH_B_ALIAS}" ]] || return 79
  if [[ -f "${VETH_OWNED}" && ! -L "${VETH_OWNED}" ]]; then
    expected="$(printf '%s\n' 'format=wg-mix-ebpf-b82-veth-owned-v1' \
      "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "a_ifindex=${VETH_A_IFINDEX}" \
      "a_alias=${VETH_A_ALIAS}" "b_ifindex=${VETH_B_IFINDEX}" "b_alias=${VETH_B_ALIAS}" \
      'state=owned')" || return $?
    actual="$(/usr/bin/cat -- "${VETH_OWNED}")" || return $?
    [[ "${actual}" == "${expected}" ]] || return 79
    [[ "${a_alias}" == "${VETH_A_ALIAS}" && "${b_alias}" == "${VETH_B_ALIAS}" ]] || return 79
  fi
}

delete_owned_veth() {
  local prefix="$1"
  load_veth_state
  verify_created_veth || fail 'veth-ownership-changed' 79
  run_step "${prefix}.delete" "${VETH_A}" /usr/sbin/ip link delete dev "${VETH_A}"
  require_zero "${prefix}.delete"
  run_step "${prefix}.verify-a" "${VETH_A}" /usr/sbin/ip link show dev "${VETH_A}"
  ((STEP_RC == 1)) || fail "veth-a-delete-verify:rc=${STEP_RC}" 79
  run_step "${prefix}.verify-b" "${VETH_B}" /usr/sbin/ip link show dev "${VETH_B}"
  ((STEP_RC == 1)) || fail "veth-b-delete-verify:rc=${STEP_RC}" 79
  write_once "${VETH_DELETED}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" 'state=deleted'
}

go_test_exists() {
  local step="$1" name="$2"
  run_step "${step}.list" "${name}" /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
    GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    /usr/bin/timeout --signal=TERM --kill-after=10s 5m /usr/bin/go -C "${VETH_SOURCE}" \
    test ./internal/dataplane -list "^${name}$"
  require_zero "${step}.list"
  /usr/bin/grep -Fxq -- "${name}" "${STEP_LOG}" || fail "missing-integration-test:${name}" 79
}

run_exact_tcx_lifecycle() {
  go_test_exists T.contract TestBPFFSPinLifecycleIntegration
  write_once "${TCX_INTENT}" 'format=wg-mix-ebpf-b82-veth-tcx-intent-v1' \
    "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "pin=${PIN_PATH}" \
    "runtime=${TCX_RUNTIME_ROOT}" "ifindex=${VETH_A_IFINDEX}" 'state=running'
  run_step T.run exact-tcx-lifecycle /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
    GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1 \
    WG_MIX_EBPF_TEST_OBJECT_PATH="${VETH_SOURCE}/build/wg_mix_tc.o" \
    WG_MIX_EBPF_TEST_PIN_PATH="${PIN_PATH}" WG_MIX_EBPF_TEST_IFINDEX="${VETH_A_IFINDEX}" \
    WG_MIX_EBPF_TEST_RUNTIME_ROOT="${TCX_RUNTIME_ROOT}" \
    WG_MIX_EBPF_TEST_PIN_LOCK_ROOT="${TCX_RUNTIME_ROOT}/locks" \
    WG_MIX_EBPF_TEST_PIN_OWNER_ROOT="${TCX_RUNTIME_ROOT}/owners" \
    WG_MIX_EBPF_TEST_INITIAL_NETNS="${INITIAL_NETNS}" \
    WG_MIX_EBPF_TEST_ACTION=run WG_MIX_EBPF_TEST_FAILURE_POLICY=retain \
    /usr/bin/timeout --signal=TERM --kill-after=10s 3m /usr/bin/go -C "${VETH_SOURCE}" \
    test ./internal/dataplane -run '^TestBPFFSPinLifecycleIntegration$' -count=1 -timeout=2m -v
  require_zero T.run
  /usr/bin/grep -Fqx -- 'SCOPED_BPFFS_COMPLETE restored=1' "${STEP_LOG}" || fail 'tcx-completion-marker' 79
  [[ ! -e "${PIN_PATH}" && ! -L "${PIN_PATH}" ]] || fail 'tcx-pin-remains' 79
  write_once "${TCX_COMPLETED}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" 'state=restored'
  assert_bpf_baseline T.after
}

restore_exact_tcx_lifecycle() {
  local expected actual
  [[ -d "${TCX_RUNTIME_ROOT}" && ! -L "${TCX_RUNTIME_ROOT}" ]] || fail 'tcx-runtime-missing' 79
  load_veth_state
  verify_created_veth || fail 'tcx-veth-identity' 79
  expected="$(printf '%s\n' 'format=wg-mix-ebpf-b82-veth-tcx-intent-v1' \
    "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "pin=${PIN_PATH}" \
    "runtime=${TCX_RUNTIME_ROOT}" "ifindex=${VETH_A_IFINDEX}" 'state=running')" || fail 'tcx-intent-expected'
  actual="$(/usr/bin/cat -- "${TCX_INTENT}")" || fail 'tcx-intent-read'
  [[ "${actual}" == "${expected}" ]] || fail 'tcx-intent-mismatch' 79
  go_test_exists R.tcx-contract TestBPFFSPinLifecycleIntegration
  run_step R.tcx exact-tcx-restore /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
    GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1 \
    WG_MIX_EBPF_TEST_OBJECT_PATH="${VETH_SOURCE}/build/wg_mix_tc.o" \
    WG_MIX_EBPF_TEST_PIN_PATH="${PIN_PATH}" WG_MIX_EBPF_TEST_IFINDEX="${VETH_A_IFINDEX}" \
    WG_MIX_EBPF_TEST_RUNTIME_ROOT="${TCX_RUNTIME_ROOT}" \
    WG_MIX_EBPF_TEST_PIN_LOCK_ROOT="${TCX_RUNTIME_ROOT}/locks" \
    WG_MIX_EBPF_TEST_PIN_OWNER_ROOT="${TCX_RUNTIME_ROOT}/owners" \
    WG_MIX_EBPF_TEST_INITIAL_NETNS="${INITIAL_NETNS}" \
    WG_MIX_EBPF_TEST_ACTION=restore WG_MIX_EBPF_TEST_FAILURE_POLICY=retain \
    /usr/bin/timeout --signal=TERM --kill-after=10s 5m /usr/bin/go -C "${VETH_SOURCE}" \
    test ./internal/dataplane -run '^TestBPFFSPinLifecycleIntegration$' -count=1 -timeout=4m -v
  require_zero R.tcx
  /usr/bin/grep -Fqx -- 'SCOPED_BPFFS_RESTORE_COMPLETE restored=1' "${STEP_LOG}" || fail 'tcx-restore-marker' 79
  [[ ! -e "${PIN_PATH}" && ! -L "${PIN_PATH}" ]] || fail 'tcx-restore-pin-remains' 79
  write_once "${TCX_RESTORED}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" 'state=restored'
}

load_checksum_module() {
  local ko_sha expected_srcversion actual_srcversion
  [[ ! -e "/sys/module/${MODULE_NAME}" ]] || fail 'checksum-module-preexists' 79
  ko_sha="$(/usr/bin/sha256sum -- "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko")" || fail 'module-sha'
  ko_sha="${ko_sha%% *}"
  valid_sha256 "${ko_sha}" || fail 'module-sha-invalid' 79
  expected_srcversion="$(/usr/sbin/modinfo -F srcversion -- "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko")" ||
    fail 'module-srcversion'
  [[ "${expected_srcversion}" =~ ^[0-9A-F]{8,64}$ ]] || fail 'module-srcversion-invalid' 79
  write_once "${MODULE_INTENT}" 'format=wg-mix-ebpf-b82-veth-module-intent-v1' \
    "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "module=${MODULE_NAME}" \
    "ko_sha256=${ko_sha}" "srcversion=${expected_srcversion}" 'state=loading'
  run_step M.load "${MODULE_NAME}" /usr/sbin/insmod \
    "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
  require_zero M.load
  actual_srcversion="$(read_single_line "/sys/module/${MODULE_NAME}/srcversion")" || fail 'loaded-module-srcversion'
  [[ "${actual_srcversion}" == "${expected_srcversion}" ]] || fail 'loaded-module-identity' 79
  write_once "${MODULE_LOADED}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" \
    "module=${MODULE_NAME}" "ko_sha256=${ko_sha}" "srcversion=${expected_srcversion}" 'state=loaded'
}

unload_checksum_module() {
  local prefix="$1" expected_srcversion actual_srcversion ko_sha actual expected current_ko_line
  [[ -f "${MODULE_LOADED}" && ! -L "${MODULE_LOADED}" ]] || fail 'module-loaded-marker-missing' 79
  expected_srcversion="$(/usr/bin/awk -F= '$1 == "srcversion" {print $2}' "${MODULE_LOADED}")" || fail 'module-marker-srcversion'
  ko_sha="$(/usr/bin/awk -F= '$1 == "ko_sha256" {print $2}' "${MODULE_LOADED}")" || fail 'module-marker-sha256'
  [[ "${expected_srcversion}" =~ ^[0-9A-F]{8,64}$ ]] || fail 'module-marker-srcversion-invalid' 79
  valid_sha256 "${ko_sha}" || fail 'module-marker-sha256-invalid' 79
  expected="$(printf '%s\n' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" \
    "module=${MODULE_NAME}" "ko_sha256=${ko_sha}" "srcversion=${expected_srcversion}" 'state=loaded')" ||
    fail 'module-loaded-expected'
  actual="$(/usr/bin/cat -- "${MODULE_LOADED}")" || fail 'module-loaded-read'
  [[ "${actual}" == "${expected}" ]] || fail 'module-loaded-marker-mismatch' 79
  current_ko_line="$(/usr/bin/sha256sum -- "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko")" ||
    fail 'module-object-hash-read'
  [[ "${current_ko_line}" == "${ko_sha}  ${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko" ]] ||
    fail 'module-object-hash-drift' 79
  actual_srcversion="$(read_single_line "/sys/module/${MODULE_NAME}/srcversion")" || fail 'module-current-srcversion'
  [[ "${actual_srcversion}" == "${expected_srcversion}" ]] || fail 'module-current-identity' 79
  run_step "${prefix}.unload" "${MODULE_NAME}" /usr/sbin/rmmod "${MODULE_NAME}"
  require_zero "${prefix}.unload"
  run_step "${prefix}.verify" "${MODULE_NAME}" /usr/bin/test ! -e "/sys/module/${MODULE_NAME}"
  require_zero "${prefix}.verify"
  write_once "${MODULE_UNLOADED}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" 'state=unloaded'
}

run_faketcp_tests() {
  local name step=1
  run_step F.verifier faketcp-verifier /usr/bin/timeout --signal=TERM --kill-after=10s 3m \
    "${VETH_SOURCE}/bin/wg-mix-ebpf" bpf-load-test --experimental-faketcp \
    --object "${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" --json
  require_zero F.verifier
  assert_bpf_baseline F.verifier-after
  go_test_exists F.packet-contract TestFakeTCPBPFPacketProbe
  run_step F.packet faketcp-packet-probe /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
    GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
    GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
    WG_MIX_FAKETCP_PACKET_TEST_OBJECT="${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" \
    /usr/bin/timeout --signal=TERM --kill-after=10s 4m /usr/bin/go -C "${VETH_SOURCE}" \
    test ./internal/dataplane -run '^TestFakeTCPBPFPacketProbe$' -count=1 -timeout=3m -v
  require_zero F.packet
  assert_bpf_baseline F.packet-after
  for name in "${OFFLOAD_TESTS[@]}"; do
    go_test_exists "F.offload${step}" "${name}"
    run_step "F.offload${step}.run" "${name}" /usr/bin/env -i \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
      GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
      GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
      /usr/bin/timeout --signal=TERM --kill-after=10s 3m /usr/bin/go -C "${VETH_SOURCE}" \
      test ./internal/dataplane -run "^${name}$" -count=1 -timeout=2m -v
    require_zero "F.offload${step}.run"
    ((step++))
  done
  step=1
  for name in "${REALHOST_TESTS[@]}"; do
    go_test_exists "F.realhost${step}" "${name}"
    run_step "F.realhost${step}.run" "${name}" /usr/bin/env -i \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 \
      GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" \
      GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" \
      WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION=1 \
      WG_MIX_FAKETCP_REALHOST_OBJECT="${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" \
      WG_MIX_FAKETCP_REALHOST_BASELINE_OBJECT="${VETH_SOURCE}/build/wg_mix_tc.o" \
      WG_MIX_FAKETCP_REALHOST_IFINDEX="${VETH_A_IFINDEX}" \
      WG_MIX_FAKETCP_REALHOST_PEER_IFINDEX="${VETH_B_IFINDEX}" \
      WG_MIX_FAKETCP_REALHOST_XDP_MODE=generic WG_MIX_FAKETCP_REALHOST_RUN_ID="${VETH_RUN_ID}" \
      /usr/bin/timeout --signal=TERM --kill-after=10s 6m /usr/bin/go -C "${VETH_SOURCE}" \
      test ./internal/dataplane -run "^${name}$" -count=1 -timeout=5m -v
    require_zero "F.realhost${step}.run"
    assert_bpf_baseline "F.realhost${step}.after"
    ((step++))
  done
}

compare_snapshot() {
  local prefix="$1" baseline="$2"
  shift 2
  run_step "${prefix}.snapshot" "${baseline}" "$@"
  require_zero "${prefix}.snapshot"
  run_step "${prefix}.compare" "${baseline}" /usr/bin/cmp -s "${EVIDENCE_ROOT}/${baseline}.out" \
    "${EVIDENCE_ROOT}/${prefix}.snapshot.out"
  require_zero "${prefix}.compare"
}

assert_bpf_baseline() {
  local prefix="$1"
  compare_snapshot "${prefix}.links" A.links /usr/sbin/bpftool -j link show
  compare_snapshot "${prefix}.programs" A.programs /usr/sbin/bpftool -j prog show
  compare_snapshot "${prefix}.maps" A.maps /usr/sbin/bpftool -j map show
}

verify_final_state() {
  local prefix="$1" current_netns
  current_netns="$(/usr/bin/readlink -- /proc/self/ns/net)" || fail "${prefix}:netns-read"
  [[ "${current_netns}" == "${INITIAL_NETNS}" ]] || fail "${prefix}:netns-drift" 79
  [[ ! -e "${PIN_PATH}" && ! -L "${PIN_PATH}" ]] || fail "${prefix}:pin-remains" 79
  [[ ! -e "/sys/module/${MODULE_NAME}" ]] || fail "${prefix}:module-remains" 79
  run_step "${prefix}.veth-a" "${VETH_A}" /usr/sbin/ip link show dev "${VETH_A}"
  ((STEP_RC == 1)) || fail "${prefix}:veth-a-remains:rc=${STEP_RC}" 79
  run_step "${prefix}.veth-b" "${VETH_B}" /usr/sbin/ip link show dev "${VETH_B}"
  ((STEP_RC == 1)) || fail "${prefix}:veth-b-remains:rc=${STEP_RC}" 79
  assert_bpf_baseline "${prefix}.bpf"
  compare_snapshot "${prefix}.modules" A.modules /usr/sbin/lsmod
  compare_snapshot "${prefix}.interface" A.interface /usr/sbin/ip -d -j link show dev "${READ_ONLY_INTERFACE}"
  compare_snapshot "${prefix}.features" A.features /usr/sbin/ethtool -k "${READ_ONLY_INTERFACE}"
  compare_snapshot "${prefix}.qdisc" A.qdisc /usr/sbin/tc -j qdisc show dev "${READ_ONLY_INTERFACE}"
  compare_snapshot "${prefix}.ingress" A.ingress /usr/sbin/tc -j filter show dev "${READ_ONLY_INTERFACE}" ingress
  compare_snapshot "${prefix}.egress" A.egress /usr/sbin/tc -j filter show dev "${READ_ONLY_INTERFACE}" egress
  compare_snapshot "${prefix}.wg" A.wg /usr/bin/wg show interfaces
}

run_all() {
  validate_controller_identity
  validate_package_bundle
  create_run_roots
  stage_source
  snapshot_host
  build_artifacts
  create_owned_veth
  run_exact_tcx_lifecycle
  load_checksum_module
  run_faketcp_tests
  unload_checksum_module F.module
  delete_owned_veth F.veth
  verify_final_state Z
  write_once "${COMPLETED_MARKER}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" \
    "commit=${COMMIT}" 'state=complete' "utc=$(utc_now)"
  write_once "${RESTORED_MARKER}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" \
    'state=restored' "utc=$(utc_now)"
  printf 'B82_VETH_V6_CLASSIFICATION wg_active_scoped=not-covered pass=0 raw_ens33=not-covered raw_ens33_pass=0 peer_47=read-only capability_bits_changed=0\n'
  printf 'B82_VETH_V6_COMPLETE run_id=%s resource_id=%s commit=%s evidence=%s restored=1\n' \
    "${VETH_RUN_ID}" "${RESOURCE_ID}" "${COMMIT}" "${EVIDENCE_ROOT}"
}

restore_after_failure() {
  validate_controller_identity
  validate_owner_marker
  if [[ -f "${RESTORED_MARKER}" && ! -L "${RESTORED_MARKER}" ]]; then
    verify_final_state R.idempotent
    printf 'B82_VETH_V6_RESTORE_COMPLETE run_id=%s resource_id=%s evidence=%s already_restored=1\n' \
      "${VETH_RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
    return 0
  fi
  [[ -f "${SNAPSHOT_READY}" && ! -L "${SNAPSHOT_READY}" ]] || {
    [[ ! -e "${VETH_INTENT}" && ! -e "${TCX_INTENT}" && ! -e "${MODULE_INTENT}" ]] ||
      fail 'snapshot-missing-with-mutation-intent' 79
    write_once "${RESTORED_MARKER}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" \
      'state=filesystem-only-retained' "utc=$(utc_now)"
    printf 'B82_VETH_V6_RESTORE_COMPLETE run_id=%s resource_id=%s evidence=%s filesystem_only=1\n' \
      "${VETH_RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
    return 0
  }
  validate_veth_source
  if [[ -f "${TCX_INTENT}" && ! -f "${TCX_COMPLETED}" && ! -f "${TCX_RESTORED}" ]]; then
    if [[ -d "${TCX_RUNTIME_ROOT}" && ! -L "${TCX_RUNTIME_ROOT}" ]]; then
      restore_exact_tcx_lifecycle
    elif [[ -e "${PIN_PATH}" || -L "${PIN_PATH}" ]]; then
      fail 'tcx-runtime-missing-with-pin' 79
    fi
  fi
  if [[ -f "${MODULE_LOADED}" && ! -f "${MODULE_UNLOADED}" ]]; then
    unload_checksum_module R.module
  elif [[ -f "${MODULE_INTENT}" && ! -f "${MODULE_LOADED}" && -e "/sys/module/${MODULE_NAME}" ]]; then
    fail 'module-loaded-without-ownership-marker' 79
  fi
  if [[ -f "${VETH_CREATED}" && ! -f "${VETH_DELETED}" ]]; then
    delete_owned_veth R.veth
  elif [[ -f "${VETH_INTENT}" && ! -f "${VETH_CREATED}" ]] &&
    { [[ -e "/sys/class/net/${VETH_A}" ]] || [[ -e "/sys/class/net/${VETH_B}" ]]; }; then
    fail 'veth-created-without-identity-marker' 79
  fi
  verify_final_state R.final
  write_once "${RESTORED_MARKER}" "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" \
    'state=restored' "utc=$(utc_now)"
  printf 'B82_VETH_V6_CLASSIFICATION wg_active_scoped=not-covered pass=0 raw_ens33=not-covered raw_ens33_pass=0 peer_47=read-only capability_bits_changed=0\n'
  printf 'B82_VETH_V6_RESTORE_COMPLETE run_id=%s resource_id=%s evidence=%s already_restored=0\n' \
    "${VETH_RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
}

parse_arguments "$@"
parse_rc=$?
((parse_rc == 0)) || fail "arguments:rc=${parse_rc}" "${parse_rc}"

if [[ "${MODE}" == 'plan' ]]; then
  render_plan
  exit 0
fi

((EUID == 0)) || fail 'root-required' 77
require_tooling
case "${MODE}" in
  run) run_all ;;
  restore) restore_after_failure ;;
  *) fail 'unreachable-mode' 64 ;;
esac
