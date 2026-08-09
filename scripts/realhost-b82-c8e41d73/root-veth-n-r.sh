#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly CONTROLLER_RUN_ID='c8e41d73'
readonly PACKAGE_ID='4f2a9b61'
readonly VETH_RUN_ID='a19f7c2e'
readonly RESOURCE_ID='d34b8e65'
readonly STATE_SCHEMA='owner,baseline,mutation-plan,veth,tcx,module-lease,cleanup-intent,restored|filesystem-retained'
readonly STAGES_ROOT='/run/wg-mix-ebpf-source-stages'
readonly EXPECTED_CONTROLLER_SOURCE="${STAGES_ROOT}/${CONTROLLER_RUN_ID}/source"
readonly EXPECTED_BUNDLE="/home/siyixuan/wg-mix-ebpf-test/unpriv-${PACKAGE_ID}/source-${PACKAGE_ID}.bundle"
readonly VETH_STAGE_ROOT="${STAGES_ROOT}/${VETH_RUN_ID}"
readonly ROOT_BUNDLE="${VETH_STAGE_ROOT}/source-${PACKAGE_ID}-${RESOURCE_ID}.bundle"
readonly VETH_SOURCE="${VETH_STAGE_ROOT}/source"
readonly EVIDENCE_ROOT="${VETH_STAGE_ROOT}/veth-evidence-${RESOURCE_ID}"
readonly AUDIT_LOG="${EVIDENCE_ROOT}/audit.log"
readonly OWNER_PHASE="${EVIDENCE_ROOT}/phase-owner.v1"
readonly BASELINE_PHASE="${EVIDENCE_ROOT}/phase-baseline.v1"
readonly MUTATION_PHASE="${EVIDENCE_ROOT}/phase-mutation-plan.v1"
readonly VETH_PHASE="${EVIDENCE_ROOT}/phase-veth.v1"
readonly TCX_PHASE="${EVIDENCE_ROOT}/phase-tcx.v1"
readonly MODULE_INTENT="${EVIDENCE_ROOT}/checksum-module-intent.v1"
readonly MODULE_OWNED="${EVIDENCE_ROOT}/checksum-module-owned.v1"
readonly MODULE_UNLOADED="${EVIDENCE_ROOT}/checksum-module-unloaded.v1"
readonly CLEANUP_PHASE="${EVIDENCE_ROOT}/phase-cleanup-intent.v1"
readonly RESTORED_PHASE="${EVIDENCE_ROOT}/phase-restored.v1"
readonly FILESYSTEM_PHASE="${EVIDENCE_ROOT}/phase-filesystem-retained.v1"
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
readonly VETH_A_MAC='02:a1:9f:7c:2e:0a'
readonly VETH_B_MAC='02:a1:9f:7c:2e:0b'
readonly MODULE_NAME='wg_mix_faketcp_checksum'
readonly MODULE_OBJECT="${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-${CONTROLLER_RUN_ID}/checksum-module-lease.sh"
readonly MODULE_LEASE_HELPER="${EXPECTED_CONTROLLER_SOURCE}/${MODULE_LEASE_HELPER_RELATIVE}"
readonly MODULE_LEASE_LOCK="${STAGES_ROOT}/${CONTROLLER_RUN_ID}/checksum-module-lease.v1.lock"
readonly MODULE_LEASE_ID="${CONTROLLER_RUN_ID}-${RESOURCE_ID}"
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
readonly -a GO_ENV=(
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0
  GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS=
  GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" GOTMPDIR="${GO_TMP}"
  GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}"
)
readonly -a BASELINE_SPECS=(
  'hostname|snapshot:hostname' 'kernel|snapshot:kernel' 'machine|snapshot:machine'
  'netns|snapshot:netns' 'interface|snapshot:interface' 'features|snapshot:features'
  'qdisc|snapshot:qdisc' 'ingress|snapshot:ingress' 'egress|snapshot:egress'
  'peer-route|snapshot:peer-route' 'wg|snapshot:wg' 'links|snapshot:links'
  'programs|snapshot:programs' 'maps|snapshot:maps' 'modules|snapshot:modules'
)
readonly -a FINAL_SPECS=(
  'interface|snapshot:interface' 'features|snapshot:features'
  'qdisc|snapshot:qdisc' 'ingress|snapshot:ingress' 'egress|snapshot:egress'
  'wg|snapshot:wg' 'links|snapshot:links' 'programs|snapshot:programs'
  'maps|snapshot:maps' 'modules|snapshot:modules'
)

MODE=''
CONTROLLER_SOURCE=''
COMMIT=''
BUNDLE=''
BUNDLE_SHA256=''
WG_STATE=''
STEP_RC=125
STEP_LOG=''
CONVERGENCE_OUTPUT=''
INITIAL_NETNS=''
ORIGINAL_BOOT_ID=''
VETH_A_IFINDEX=''
VETH_B_IFINDEX=''
VETH_A_SYSFS_IDENTITY=''
VETH_B_SYSFS_IDENTITY=''
MODULE_SHA256=''
MODULE_SRCVERSION=''
OP_TARGET=''
declare -a OP_ARGV=()
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
  local seen_source=0 seen_commit=0 seen_bundle=0 seen_bundle_sha=0 seen_wg=0
  (($# >= 1)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in plan | run | restore) ;; *) usage; return 64 ;; esac
  while (($# > 0)); do
    (($# >= 2)) || { usage; return 64; }
    case "$1" in
      --controller-source)
        ((seen_source == 0)) || return 65
        seen_source=1; CONTROLLER_SOURCE="$2"
        ;;
      --commit)
        ((seen_commit == 0)) || return 65
        seen_commit=1; COMMIT="$2"
        ;;
      --bundle)
        ((seen_bundle == 0)) || return 65
        seen_bundle=1; BUNDLE="$2"
        ;;
      --bundle-sha256)
        ((seen_bundle_sha == 0)) || return 65
        seen_bundle_sha=1; BUNDLE_SHA256="$2"
        ;;
      --wg-state)
        ((seen_wg == 0)) || return 65
        seen_wg=1; WG_STATE="$2"
        ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  ((seen_source == 1 && seen_commit == 1 && seen_bundle == 1 && seen_bundle_sha == 1 && seen_wg == 1)) || return 65
  [[ "${CONTROLLER_SOURCE}" == "${EXPECTED_CONTROLLER_SOURCE}" &&
    "${BUNDLE}" == "${EXPECTED_BUNDLE}" && "${WG_STATE}" == 'absent' ]] || return 65
  valid_commit "${COMMIT}" || return 65
  valid_sha256 "${BUNDLE_SHA256}" || return 65
}

quote_argv() { printf '%q ' "$@"; }

valid_test_name() {
  local wanted="$1" name
  for name in TestBPFFSPinLifecycleIntegration TestFakeTCPBPFPacketProbe \
    "${OFFLOAD_TESTS[@]}" "${REALHOST_TESTS[@]}"; do
    [[ "${wanted}" == "${name}" ]] && return 0
  done
  return 1
}

build_argv() {
  local operation="$1" name action outer inner
  OP_TARGET="${operation}"
  OP_ARGV=()
  case "${operation}" in
    stage-mkdir) OP_TARGET="${VETH_STAGE_ROOT}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${VETH_STAGE_ROOT}") ;;
    evidence-mkdir) OP_TARGET="${EVIDENCE_ROOT}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${EVIDENCE_ROOT}") ;;
    bundle-copy) OP_TARGET="${ROOT_BUNDLE}"; OP_ARGV=(/usr/bin/timeout --signal=TERM --kill-after=10s 2m /usr/bin/cp --no-clobber --no-preserve=mode,ownership,timestamps -- "${BUNDLE}" "${ROOT_BUNDLE}") ;;
    bundle-mode) OP_TARGET="${ROOT_BUNDLE}"; OP_ARGV=(/usr/bin/chmod 0600 "${ROOT_BUNDLE}") ;;
    bundle-verify) OP_TARGET="${ROOT_BUNDLE}"; OP_ARGV=("${GIT_COMMAND[@]}" -C "${CONTROLLER_SOURCE}" bundle verify "${ROOT_BUNDLE}") ;;
    source-clone) OP_TARGET="${VETH_SOURCE}"; OP_ARGV=("${GIT_COMMAND[@]}" clone --no-local --no-checkout -- "${ROOT_BUNDLE}" "${VETH_SOURCE}") ;;
    source-checkout) OP_TARGET="${VETH_SOURCE}"; OP_ARGV=("${GIT_COMMAND[@]}" -C "${VETH_SOURCE}" checkout --detach "${COMMIT}") ;;
    cache-mkdir) OP_TARGET="${GO_CACHE}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_CACHE}") ;;
    mod-cache-mkdir) OP_TARGET="${GO_MOD_CACHE}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_MOD_CACHE}") ;;
    go-path-mkdir) OP_TARGET="${GO_PATH}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_PATH}") ;;
    go-tmp-mkdir) OP_TARGET="${GO_TMP}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_TMP}") ;;
    snapshot:hostname) OP_ARGV=(/usr/bin/hostname) ;;
    snapshot:kernel) OP_ARGV=(/usr/bin/uname -r) ;;
    snapshot:machine) OP_ARGV=(/usr/bin/cat /etc/machine-id) ;;
    snapshot:netns) OP_ARGV=(/usr/bin/readlink /proc/self/ns/net) ;;
    snapshot:interface) OP_TARGET="${READ_ONLY_INTERFACE}"; OP_ARGV=(/usr/sbin/ip -d -j link show dev "${READ_ONLY_INTERFACE}") ;;
    snapshot:features) OP_TARGET="${READ_ONLY_INTERFACE}"; OP_ARGV=(/usr/sbin/ethtool -k "${READ_ONLY_INTERFACE}") ;;
    snapshot:qdisc) OP_TARGET="${READ_ONLY_INTERFACE}"; OP_ARGV=(/usr/sbin/tc -j qdisc show dev "${READ_ONLY_INTERFACE}") ;;
    snapshot:ingress) OP_TARGET="${READ_ONLY_INTERFACE}"; OP_ARGV=(/usr/sbin/tc -j filter show dev "${READ_ONLY_INTERFACE}" ingress) ;;
    snapshot:egress) OP_TARGET="${READ_ONLY_INTERFACE}"; OP_ARGV=(/usr/sbin/tc -j filter show dev "${READ_ONLY_INTERFACE}" egress) ;;
    snapshot:peer-route) OP_TARGET="${READ_ONLY_PEER}"; OP_ARGV=(/usr/sbin/ip -j route get "${READ_ONLY_PEER}") ;;
    snapshot:wg) OP_ARGV=(/usr/bin/wg show interfaces) ;;
    snapshot:links) OP_ARGV=(/usr/sbin/bpftool -j link show) ;;
    snapshot:programs) OP_ARGV=(/usr/sbin/bpftool -j prog show) ;;
    snapshot:maps) OP_ARGV=(/usr/sbin/bpftool -j map show) ;;
    snapshot:modules) OP_ARGV=(/usr/sbin/lsmod) ;;
    build) OP_ARGV=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C CGO_ENABLED=0 GO=/usr/bin/go CLANG=/usr/bin/clang GOCACHE="${GO_CACHE}" GOENV=off GOFLAGS= GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}" GOTMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on TMPDIR="${GO_TMP}" /usr/bin/timeout --signal=TERM --kill-after=30s 30m /usr/bin/make --no-print-directory -C "${VETH_SOURCE}" build-bpf build-faketcp-experimental-bpf build-faketcp-checksum-kmod build test-bpf-object-manifests) ;;
    veth-show-a) OP_TARGET="${VETH_A}"; OP_ARGV=(/usr/sbin/ip link show dev "${VETH_A}") ;;
    veth-show-b) OP_TARGET="${VETH_B}"; OP_ARGV=(/usr/sbin/ip link show dev "${VETH_B}") ;;
    veth-add) OP_TARGET="${VETH_A}:${VETH_B}"; OP_ARGV=(/usr/sbin/ip link add "${VETH_A}" address "${VETH_A_MAC}" type veth peer name "${VETH_B}" address "${VETH_B_MAC}") ;;
    veth-alias-a) OP_TARGET="${VETH_A}"; OP_ARGV=(/usr/sbin/ip link set dev "${VETH_A}" alias "${VETH_A_ALIAS}") ;;
    veth-alias-b) OP_TARGET="${VETH_B}"; OP_ARGV=(/usr/sbin/ip link set dev "${VETH_B}" alias "${VETH_B_ALIAS}") ;;
    veth-up-a) OP_TARGET="${VETH_A}"; OP_ARGV=(/usr/sbin/ip link set dev "${VETH_A}" up) ;;
    veth-up-b) OP_TARGET="${VETH_B}"; OP_ARGV=(/usr/sbin/ip link set dev "${VETH_B}" up) ;;
    veth-delete) OP_TARGET="${VETH_A}"; OP_ARGV=(/usr/sbin/ip link delete dev "${VETH_A}") ;;
    veth-delete-b) OP_TARGET="${VETH_B}"; OP_ARGV=(/usr/sbin/ip link delete dev "${VETH_B}") ;;
    list:*) name="${operation#list:}"; valid_test_name "${name}" || return 64; OP_TARGET="${name}"; OP_ARGV=("${GO_ENV[@]}" /usr/bin/timeout --signal=TERM --kill-after=10s 5m /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane -list "^${name}$") ;;
    tcx-run | tcx-restore)
      action=run; outer=3m; inner=2m
      [[ "${operation}" == tcx-restore ]] && { action=restore; outer=5m; inner=4m; }
      OP_TARGET="exact-tcx-${action}"
      OP_ARGV=("${GO_ENV[@]}" WG_MIX_EBPF_RUN_BPFFS_INTEGRATION=1 WG_MIX_EBPF_TEST_OBJECT_PATH="${VETH_SOURCE}/build/wg_mix_tc.o" WG_MIX_EBPF_TEST_PIN_PATH="${PIN_PATH}" WG_MIX_EBPF_TEST_IFINDEX="${VETH_A_IFINDEX}" WG_MIX_EBPF_TEST_RUNTIME_ROOT="${TCX_RUNTIME_ROOT}" WG_MIX_EBPF_TEST_PIN_LOCK_ROOT="${TCX_RUNTIME_ROOT}/locks" WG_MIX_EBPF_TEST_PIN_OWNER_ROOT="${TCX_RUNTIME_ROOT}/owners" WG_MIX_EBPF_TEST_INITIAL_NETNS="${INITIAL_NETNS}" WG_MIX_EBPF_TEST_ACTION="${action}" WG_MIX_EBPF_TEST_FAILURE_POLICY=retain /usr/bin/timeout --signal=TERM --kill-after=10s "${outer}" /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane -run '^TestBPFFSPinLifecycleIntegration$' -count=1 -timeout="${inner}" -v)
      ;;
    verifier) OP_ARGV=(/usr/bin/timeout --signal=TERM --kill-after=10s 3m "${VETH_SOURCE}/bin/wg-mix-ebpf" bpf-load-test --experimental-faketcp --object "${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" --json) ;;
    packet-probe) OP_ARGV=("${GO_ENV[@]}" WG_MIX_FAKETCP_PACKET_TEST_OBJECT="${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" /usr/bin/timeout --signal=TERM --kill-after=10s 4m /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane -run '^TestFakeTCPBPFPacketProbe$' -count=1 -timeout=3m -v) ;;
    offload:*) name="${operation#offload:}"; valid_test_name "${name}" || return 64; OP_TARGET="${name}"; OP_ARGV=("${GO_ENV[@]}" /usr/bin/timeout --signal=TERM --kill-after=10s 3m /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane -run "^${name}$" -count=1 -timeout=2m -v) ;;
    realhost:*) name="${operation#realhost:}"; valid_test_name "${name}" || return 64; OP_TARGET="${name}"; OP_ARGV=("${GO_ENV[@]}" WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION=1 WG_MIX_FAKETCP_REALHOST_OBJECT="${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o" WG_MIX_FAKETCP_REALHOST_BASELINE_OBJECT="${VETH_SOURCE}/build/wg_mix_tc.o" WG_MIX_FAKETCP_REALHOST_IFINDEX="${VETH_A_IFINDEX}" WG_MIX_FAKETCP_REALHOST_PEER_IFINDEX="${VETH_B_IFINDEX}" WG_MIX_FAKETCP_REALHOST_XDP_MODE=generic WG_MIX_FAKETCP_REALHOST_RUN_ID="${VETH_RUN_ID}" /usr/bin/timeout --signal=TERM --kill-after=10s 6m /usr/bin/go -C "${VETH_SOURCE}" test ./internal/dataplane -run "^${name}$" -count=1 -timeout=5m -v) ;;
    *) return 64 ;;
  esac
}

plan_operation() {
  local label="$1" operation="$2"
  build_argv "${operation}" || fail "plan-builder:${operation}" $?
  printf '%s operation=%s target=%q argv=' "${label}" "${operation}" "${OP_TARGET}"
  quote_argv "${OP_ARGV[@]}"
  printf '\n'
}

render_plan() {
  local spec label operation name
  VETH_A_IFINDEX='OWNED_VETH_A_IFINDEX'
  VETH_B_IFINDEX='OWNED_VETH_B_IFINDEX'
  INITIAL_NETNS='OWNER_MARKER_NETNS'
  printf 'B82_VETH_V6_PLAN_ONLY controller_run_id=%s run_id=%s resource_id=%s commit=%s bundle_sha256=%s state_schema=%s\n' "${CONTROLLER_RUN_ID}" "${VETH_RUN_ID}" "${RESOURCE_ID}" "${COMMIT}" "${BUNDLE_SHA256}" "${STATE_SCHEMA}"
  printf 'B82_VETH_V6_SCOPE wg_state=absent wg_active_scoped=not-covered pass=0 raw_ens33=not-covered raw_ens33_pass=0 peer_47=read-only peer_access=0\n'
  for spec in 'B0|stage-mkdir' 'B1|evidence-mkdir' 'S0.copy|bundle-copy' 'S0.mode|bundle-mode' 'S0.verify|bundle-verify' 'S1|source-clone' 'S2|source-checkout' 'S3.cache|cache-mkdir' 'S3.mod-cache|mod-cache-mkdir' 'S3.go-path|go-path-mkdir' 'S3.tmp|go-tmp-mkdir'; do
    IFS='|' read -r label operation <<<"${spec}"; plan_operation "${label}" "${operation}"
  done
  printf 'L0 operation=shared-module-lock target=%q helper=%q argv=' "${MODULE_LEASE_LOCK}" "${MODULE_LEASE_HELPER}"
  quote_argv /usr/bin/flock --exclusive --nonblock MODULE_LEASE_FD
  printf '\n'
  for spec in "${BASELINE_SPECS[@]}"; do IFS='|' read -r label operation <<<"${spec}"; plan_operation "A.${label}" "${operation}"; done
  plan_operation O.build build
  for spec in 'N.pre-a|veth-show-a' 'N.pre-b|veth-show-b' 'N.add|veth-add' 'N.alias-a|veth-alias-a' 'N.alias-b|veth-alias-b' 'N.up-a|veth-up-a' 'N.up-b|veth-up-b'; do IFS='|' read -r label operation <<<"${spec}"; plan_operation "${label}" "${operation}"; done
  plan_operation T.run tcx-run
  printf 'M.load operation=shared-module-load target=%q helper=c8_checksum_module_load argv=' "${MODULE_NAME}"
  quote_argv /usr/sbin/insmod "${MODULE_OBJECT}" "lease_id=${MODULE_LEASE_ID}"
  printf '\n'
  for name in TestFakeTCPBPFPacketProbe "${OFFLOAD_TESTS[@]}" "${REALHOST_TESTS[@]}"; do plan_operation "C.${name}" "list:${name}"; done
  plan_operation F.verifier verifier
  plan_operation F.packet packet-probe
  for name in "${OFFLOAD_TESTS[@]}"; do plan_operation "F.${name}" "offload:${name}"; done
  for name in "${REALHOST_TESTS[@]}"; do plan_operation "F.${name}" "realhost:${name}"; done
  plan_operation R.tcx tcx-restore
  printf 'R.module operation=shared-module-restore target=%q helper=c8_checksum_module_restore argv=' "${MODULE_NAME}"
  quote_argv /usr/sbin/rmmod "${MODULE_NAME}"
  printf '\n'
  plan_operation R.veth-a veth-delete
  plan_operation R.veth-b veth-delete-b
  for spec in "${FINAL_SPECS[@]}"; do IFS='|' read -r label operation <<<"${spec}"; plan_operation "Z.${label}" "${operation}"; done
  printf 'B82_VETH_V6_WRITE_SET stage=%s evidence=%s source=%s root_bundle=%s pin=%s shared_lock=%s:advisory-only veth=%s,%s module=%s lease_id=%s module_receipts=%s,%s,%s phases=%s retained=1\n' "${VETH_STAGE_ROOT}" "${EVIDENCE_ROOT}" "${VETH_SOURCE}" "${ROOT_BUNDLE}" "${PIN_PATH}" "${MODULE_LEASE_LOCK}" "${VETH_A}" "${VETH_B}" "${MODULE_NAME}" "${MODULE_LEASE_ID}" "${MODULE_INTENT}" "${MODULE_OWNED}" "${MODULE_UNLOADED}" "${STATE_SCHEMA}"
  printf 'B82_VETH_V6_PLAN_COMPLETE argv_builder=shared commands_are_review_templates=1 no_commands_executed=1 credential_read=0 network_operations=0 capability_bits_changed=0\n'
}

utc_now() { /bin/date -u '+%Y-%m-%dT%H:%M:%SZ'; }

bootstrap_audit_line() {
  local event="$1" step="$2" target="$3" rc="$4" rendered="$5" timestamp line
  timestamp="$(utc_now)" || return $?
  printf -v line 'utc=%q event=%q step=%q target=%q rc=%q argv=%q' "${timestamp}" "${event}" "${step}" "${target}" "${rc}" "${rendered}"
  BOOTSTRAP_AUDIT_LINES+=("${line}")
  printf 'B82_VETH_V6_BOOTSTRAP_AUDIT %s\n' "${line}"
}

bootstrap_operation() {
  local label="$1" operation="$2" rendered rc
  build_argv "${operation}" || return $?
  rendered="$(quote_argv "${OP_ARGV[@]}")" || return $?
  bootstrap_audit_line start "${label}" "${OP_TARGET}" not-run "${rendered}" || return $?
  "${OP_ARGV[@]}"; rc=$?
  bootstrap_audit_line finish "${label}" "${OP_TARGET}" "${rc}" "${rendered}" || return $?
  return "${rc}"
}

create_audit_log() {
  local rc
  set -o noclobber
  printf '%s\n' "${BOOTSTRAP_AUDIT_LINES[@]}" >"${AUDIT_LOG}"; rc=$?
  set +o noclobber
  ((rc == 0))
}

audit_line() {
  local event="$1" step="$2" target="$3" rc="$4" rendered="$5" timestamp
  local -a status
  [[ -f "${AUDIT_LOG}" && ! -L "${AUDIT_LOG}" && "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${AUDIT_LOG}")" == '0:0:600:1:regular file' ]] || return 79
  timestamp="$(utc_now)" || return $?
  printf 'utc=%q event=%q step=%q target=%q rc=%q argv=%q\n' "${timestamp}" "${event}" "${step}" "${target}" "${rc}" "${rendered}" | /usr/bin/tee -a "${AUDIT_LOG}"
  status=("${PIPESTATUS[@]}")
  ((${#status[@]} == 2 && status[0] == 0 && status[1] == 0))
}

run_step() {
  local label="$1" target="$2" rendered evidence_rendered
  local -a status
  shift 2
  STEP_LOG="${EVIDENCE_ROOT}/${label}.out"
  [[ "${label}" =~ ^[A-Z][A-Za-z0-9_.-]{0,95}$ && ! -e "${STEP_LOG}" && ! -L "${STEP_LOG}" ]] || fail "step-output:${label}" 78
  rendered="$(quote_argv "$@")" || fail "render:${label}"
  evidence_rendered="$(quote_argv /usr/bin/tee "${STEP_LOG}")" || fail "render-evidence:${label}"
  audit_line start "${label}" "${target}" not-run "${rendered}" || fail "audit-start:${label}"
  audit_line start "${label}.evidence" "${STEP_LOG}" not-run "${evidence_rendered}" || fail "audit-evidence:${label}"
  "$@" 2>&1 | /usr/bin/tee "${STEP_LOG}"; status=("${PIPESTATUS[@]}")
  ((${#status[@]} == 2)) || fail "pipeline:${label}"
  STEP_RC="${status[0]}"
  audit_line finish "${label}" "${target}" "${STEP_RC}" "${rendered}" || fail "audit-finish:${label}"
  audit_line finish "${label}.evidence" "${STEP_LOG}" "${status[1]}" "${evidence_rendered}" || fail "audit-evidence-finish:${label}"
  ((status[1] == 0)) || fail "evidence-write:${label}" "${status[1]}"
}

run_operation() {
  local label="$1" operation="$2" expected="${3:-0}"
  build_argv "${operation}" || fail "operation-builder:${operation}" $?
  run_step "${label}" "${OP_TARGET}" "${OP_ARGV[@]}"
  ((STEP_RC == expected)) || fail "${label}:rc=${STEP_RC}:expected=${expected}" 79
}

run_convergent_operation() {
  local label="$1" operation="$2" rendered rc
  build_argv "${operation}" || fail "convergence-builder:${operation}" $?
  rendered="$(quote_argv "${OP_ARGV[@]}")" || fail "convergence-render:${label}"
  audit_line start "${label}" "${OP_TARGET}" not-run "${rendered}" || fail "convergence-audit-start:${label}"
  CONVERGENCE_OUTPUT="$("${OP_ARGV[@]}" 2>&1)"; rc=$?
  audit_line output "${label}" "${OP_TARGET}" "${rc}" "${CONVERGENCE_OUTPUT}" || fail "convergence-audit-output:${label}"
  audit_line finish "${label}" "${OP_TARGET}" "${rc}" "${rendered}" || fail "convergence-audit-finish:${label}"
  ((rc == 0)) || { printf '%s\n' "${CONVERGENCE_OUTPUT}" >&2; fail "${label}:rc=${rc}" "${rc}"; }
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

capture_operation() {
  local label="$1" operation="$2" rendered output rc
  build_argv "${operation}" || fail "capture-builder:${operation}" $?
  rendered="$(quote_argv "${OP_ARGV[@]}")" || fail "capture-render:${label}"
  audit_line start "${label}" "${OP_TARGET}" not-run "${rendered}" >&2 || fail "capture-audit-start:${label}"
  output="$("${OP_ARGV[@]}" 2>&1)"; rc=$?
  audit_line finish "${label}" "${OP_TARGET}" "${rc}" "${rendered}" >&2 || fail "capture-audit-finish:${label}"
  ((rc == 0)) || { printf '%s\n' "${output}" >&2; fail "${label}:rc=${rc}" "${rc}"; }
  printf '%s' "${output}"
}

write_noclobber_evidence() {
  local path="$1" rc
  shift
  [[ "${path}" == "${EVIDENCE_ROOT}/"* && "${path#${EVIDENCE_ROOT}/}" != */* &&
    ! -e "${path}" && ! -L "${path}" ]] || fail "evidence-write-scope:${path}" 78
  audit_line start evidence-write "${path}" not-run "shell-builtin:noclobber" || fail 'evidence-audit-start'
  set -o noclobber
  printf '%s\n' "$@" >"${path}"; rc=$?
  set +o noclobber
  audit_line finish evidence-write "${path}" "${rc}" "shell-builtin:noclobber" || fail 'evidence-audit-finish'
  ((rc == 0)) || fail "evidence-write:${path}" "${rc}"
}

write_phase() {
  local path="$1"
  shift
  [[ "${path}" == "${EVIDENCE_ROOT}/phase-"* && "${path#${EVIDENCE_ROOT}/}" != */* ]] ||
    fail "phase-write-scope:${path}" 78
  write_noclobber_evidence "${path}" "$@"
}

c8_checksum_module_write() {
  local path="$1"
  case "${path}" in
    "${MODULE_INTENT}" | "${MODULE_OWNED}" | "${MODULE_UNLOADED}") ;;
    *) fail "module-lease-write-scope:${path}" 78 ;;
  esac
  write_noclobber_evidence "$1" "$2"
}

c8_checksum_module_fail() {
  fail "checksum-module-lease:$1" "$2"
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

sha256_file() {
  local line
  line="$(/usr/bin/sha256sum -- "$1")" || return $?
  line="${line%% *}"
  valid_sha256 "${line}" || return 79
  printf '%s\n' "${line}"
}

file_sha_or_absent() {
  if [[ -f "$1" && ! -L "$1" ]]; then sha256_file "$1"; else printf 'absent\n'; fi
}

directory_identity() { /usr/bin/stat -Lc '%d:%i:%u:%g:%a:%F' -- "$1"; }
git_fixed() { "${GIT_COMMAND[@]}" "$@"; }

validate_evidence_file() {
  local path="$1" label="$2"
  [[ -f "${path}" && ! -L "${path}" && "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${path}")" == '0:0:600:1:regular file' ]] || fail "evidence-shape:${label}" 79
}

validate_optional_evidence_file() {
  local path="$1" label="$2"
  if [[ -e "${path}" || -L "${path}" ]]; then validate_evidence_file "${path}" "${label}"; fi
}

validate_evidence_shapes() {
  local path label
  validate_evidence_file "${AUDIT_LOG}" audit
  validate_evidence_file "${OWNER_PHASE}" owner
  for path in "${BASELINE_PHASE}" "${MUTATION_PHASE}" "${VETH_PHASE}" "${TCX_PHASE}" \
    "${MODULE_INTENT}" "${MODULE_OWNED}" "${MODULE_UNLOADED}" \
    "${CLEANUP_PHASE}" "${RESTORED_PHASE}" "${FILESYSTEM_PHASE}"; do
    label="${path#${EVIDENCE_ROOT}/}"
    validate_optional_evidence_file "${path}" "${label}"
  done
}

require_tooling() {
  local path
  local -a tools=(/bin/bash /bin/date /usr/bin/awk /usr/bin/basename /usr/bin/cat /usr/bin/chmod /usr/bin/clang /usr/bin/cmp /usr/bin/cp /usr/bin/env /usr/bin/flock /usr/bin/git /usr/bin/go /usr/bin/grep /usr/bin/hostname /usr/bin/make /usr/bin/mkdir /usr/bin/readlink /usr/bin/sha256sum /usr/bin/stat /usr/bin/tee /usr/bin/test /usr/bin/timeout /usr/bin/uname /usr/bin/wg /usr/sbin/bpftool /usr/sbin/ethtool /usr/sbin/insmod /usr/sbin/ip /usr/sbin/lsmod /usr/sbin/modinfo /usr/sbin/rmmod /usr/sbin/tc)
  for path in "${tools[@]}"; do [[ -x "${path}" ]] || fail "missing-tool:${path}" 69; done
}

validate_controller_identity() {
  local canonical shape head dirty actual self_path actual_blob commit_blob actual_sha commit_sha
  canonical="$(/usr/bin/readlink -e -- "${STAGES_ROOT}")" || fail 'stages-root-canonical'
  [[ "${canonical}" == "${STAGES_ROOT}" && "$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${STAGES_ROOT}")" == '0:0:700:directory' ]] || fail 'stages-root-shape' 79
  canonical="$(/usr/bin/readlink -e -- "${CONTROLLER_SOURCE}")" || fail 'controller-source-canonical'
  [[ "${canonical}" == "${EXPECTED_CONTROLLER_SOURCE}" && "$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${CONTROLLER_SOURCE}")" == '0:0:700:directory' ]] || fail 'controller-source-shape' 79
  head="$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse --verify HEAD)" || fail 'controller-source-head'
  dirty="$(git_fixed -C "${CONTROLLER_SOURCE}" status --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || fail 'controller-source-status'
  [[ "${head}" == "${COMMIT}" && -z "${dirty}" ]] || fail 'controller-source-identity' 79
  self_path="${CONTROLLER_SOURCE}/${SELF_PATH_FROM_ROOT}"
  [[ "$0" == /* && "$0" == "${self_path}" && -f "$0" && ! -L "$0" ]] || fail 'runner-invocation-path' 79
  canonical="$(/usr/bin/readlink -e -- "$0")" || fail 'runner-self-canonical'
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "$0")" || fail 'runner-self-stat'
  [[ "${canonical}" == "${self_path}" && "${shape}" == '0:0:700:1:regular file' ]] || fail 'runner-self-metadata' 79
  actual_blob="$(git_fixed -C "${CONTROLLER_SOURCE}" hash-object -- "$0")" || fail 'runner-self-blob'
  commit_blob="$(git_fixed -C "${CONTROLLER_SOURCE}" rev-parse "${COMMIT}:${SELF_PATH_FROM_ROOT}")" || fail 'runner-commit-blob'
  actual_sha="$(sha256_file "$0")" || fail 'runner-self-sha'
  commit_sha="$(git_fixed -C "${CONTROLLER_SOURCE}" show "${COMMIT}:${SELF_PATH_FROM_ROOT}" | /usr/bin/sha256sum)" || fail 'runner-commit-sha'
  commit_sha="${commit_sha%% *}"
  [[ "${actual_blob}" == "${commit_blob}" && "${actual_sha}" == "${commit_sha}" ]] || fail 'runner-self-content' 79
  [[ -f "${MODULE_LEASE_HELPER}" && ! -L "${MODULE_LEASE_HELPER}" ]] ||
    fail 'module-lease-helper-shape' 79
  actual="$(/usr/bin/hostname)"; [[ "${actual}" == "${EXPECTED_HOSTNAME}" ]] || fail 'hostname-mismatch' 79
  actual="$(/usr/bin/uname -r)"; [[ "${actual}" == "${EXPECTED_KERNEL}" ]] || fail 'kernel-mismatch' 79
  actual="$(read_single_line /etc/machine-id)"; [[ "${actual}" == "${EXPECTED_MACHINE_ID}" ]] || fail 'machine-id-mismatch' 79
}

load_checksum_module_helper() {
  # shellcheck source=checksum-module-lease.sh
  source "${MODULE_LEASE_HELPER}" || fail 'module-lease-helper-source' $?
  [[ "${C8_CHECKSUM_MODULE_LOCK}" == "${MODULE_LEASE_LOCK}" &&
    "${C8_CHECKSUM_MODULE_STANDALONE_RESOURCE_ID}" == "${RESOURCE_ID}" &&
    "${C8_CHECKSUM_MODULE_STANDALONE_OBJECT}" == "${MODULE_OBJECT}" &&
    "${C8_CHECKSUM_MODULE_STANDALONE_EVIDENCE}" == "${EVIDENCE_ROOT}" ]] ||
    fail 'module-lease-helper-binding-contract' 79
}

configure_checksum_module_lease() {
  c8_checksum_module_configure "${CONTROLLER_RUN_ID}" "${RESOURCE_ID}" "${COMMIT}" \
    "${ORIGINAL_BOOT_ID}" "${EVIDENCE_ROOT}" "${MODULE_OBJECT}" "${MODULE_SHA256}" ||
    fail 'module-lease-configure' $?
  [[ "${C8_CHECKSUM_MODULE_LEASE_ID}" == "${MODULE_LEASE_ID}" &&
    "${C8_CHECKSUM_MODULE_INTENT}" == "${MODULE_INTENT}" &&
    "${C8_CHECKSUM_MODULE_OWNED}" == "${MODULE_OWNED}" &&
    "${C8_CHECKSUM_MODULE_UNLOADED}" == "${MODULE_UNLOADED}" ]] ||
    fail 'module-lease-receipt-contract' 79
}

validate_package_bundle() {
  local canonical shape
  canonical="$(/usr/bin/readlink -e -- "${BUNDLE}")" || fail 'bundle-canonical'
  shape="$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${BUNDLE}")" || fail 'bundle-stat'
  [[ "${canonical}" == "${EXPECTED_BUNDLE}" && "${shape}" == 'siyixuan:siyixuan:600:1:regular file' && "$(sha256_file "${BUNDLE}")" == "${BUNDLE_SHA256}" ]] || fail 'bundle-identity' 79
}

create_roots() {
  [[ ! -e "${VETH_STAGE_ROOT}" && ! -L "${VETH_STAGE_ROOT}" ]] || fail 'veth-stage-exists' 78
  bootstrap_operation B0 stage-mkdir || fail 'stage-create' $?
  bootstrap_operation B1 evidence-mkdir || fail 'evidence-create' $?
  create_audit_log || fail 'audit-create' $?
  ORIGINAL_BOOT_ID="$(read_single_line /proc/sys/kernel/random/boot_id)" || fail 'boot-id'
  INITIAL_NETNS="$(/usr/bin/readlink /proc/self/ns/net)" || fail 'netns'
  write_phase "${OWNER_PHASE}" 'format=wg-mix-ebpf-b82-veth-owner-v2' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "commit=${COMMIT}" "bundle_sha256=${BUNDLE_SHA256}" "boot_id=${ORIGINAL_BOOT_ID}" "initial_netns=${INITIAL_NETNS}" "stage=${VETH_STAGE_ROOT}" "stage_identity=$(directory_identity "${VETH_STAGE_ROOT}")" "evidence=${EVIDENCE_ROOT}" "evidence_identity=$(directory_identity "${EVIDENCE_ROOT}")"
}

validate_owner() {
  local expected actual current_boot current_netns
  validate_evidence_file "${OWNER_PHASE}" owner
  current_boot="$(read_single_line /proc/sys/kernel/random/boot_id)" || fail 'owner-boot'
  current_netns="$(/usr/bin/readlink /proc/self/ns/net)" || fail 'owner-netns'
  expected="$(printf '%s\n' 'format=wg-mix-ebpf-b82-veth-owner-v2' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "commit=${COMMIT}" "bundle_sha256=${BUNDLE_SHA256}" "boot_id=${current_boot}" "initial_netns=${current_netns}" "stage=${VETH_STAGE_ROOT}" "stage_identity=$(directory_identity "${VETH_STAGE_ROOT}")" "evidence=${EVIDENCE_ROOT}" "evidence_identity=$(directory_identity "${EVIDENCE_ROOT}")")"
  actual="$(/usr/bin/cat "${OWNER_PHASE}")" || fail 'owner-read'
  [[ "${actual}" == "${expected}" ]] || fail 'owner-mismatch' 79
  ORIGINAL_BOOT_ID="${current_boot}"; INITIAL_NETNS="${current_netns}"
}

stage_source() {
  local name operation label shape head dirty
  run_operation S0.copy bundle-copy; run_operation S0.mode bundle-mode
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' "${ROOT_BUNDLE}")" || fail 'root-bundle-stat'
  [[ "${shape}" == '0:0:600:1:regular file' && "$(sha256_file "${ROOT_BUNDLE}")" == "${BUNDLE_SHA256}" ]] || fail 'root-bundle-identity' 79
  run_operation S0.verify bundle-verify; run_operation S1 source-clone; run_operation S2 source-checkout
  for name in cache mod-cache go-path go-tmp; do
    case "${name}" in cache) operation=cache-mkdir ;; mod-cache) operation=mod-cache-mkdir ;; go-path) operation=go-path-mkdir ;; go-tmp) operation=go-tmp-mkdir ;; esac
    label="S3.${name}"; run_operation "${label}" "${operation}"
  done
  head="$(git_fixed -C "${VETH_SOURCE}" rev-parse HEAD)" || fail 'source-head'
  dirty="$(git_fixed -C "${VETH_SOURCE}" status --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || fail 'source-status'
  [[ "${head}" == "${COMMIT}" && -z "${dirty}" ]] || fail 'source-identity' 79
}

validate_staged_source() {
  local canonical shape bundle_shape head dirty
  canonical="$(/usr/bin/readlink -e "${VETH_SOURCE}")" || fail 'staged-source-canonical'
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%F' "${VETH_SOURCE}")" || fail 'staged-source-stat'
  head="$(git_fixed -C "${VETH_SOURCE}" rev-parse HEAD)" || fail 'staged-source-head'
  dirty="$(git_fixed -C "${VETH_SOURCE}" status --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || fail 'staged-source-status'
  bundle_shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${ROOT_BUNDLE}")" || fail 'staged-bundle-stat'
  [[ "${canonical}" == "${VETH_SOURCE}" && "${shape}" == '0:0:700:directory' && "${head}" == "${COMMIT}" && -z "${dirty}" && -f "${ROOT_BUNDLE}" && ! -L "${ROOT_BUNDLE}" && "${bundle_shape}" == '0:0:600:1:regular file' && "$(sha256_file "${ROOT_BUNDLE}")" == "${BUNDLE_SHA256}" ]] || fail 'staged-source-identity' 79
}

baseline_sha() { sha256_file "${EVIDENCE_ROOT}/A.$1.out"; }

render_baseline() {
  printf '%s\n' 'format=wg-mix-ebpf-b82-veth-baseline-v2' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${ORIGINAL_BOOT_ID}" "initial_netns=${INITIAL_NETNS}" "links_sha256=$(baseline_sha links)" "programs_sha256=$(baseline_sha programs)" "maps_sha256=$(baseline_sha maps)" "modules_sha256=$(baseline_sha modules)" "interface_sha256=$(baseline_sha interface)" "features_sha256=$(baseline_sha features)" "qdisc_sha256=$(baseline_sha qdisc)" "ingress_sha256=$(baseline_sha ingress)" "egress_sha256=$(baseline_sha egress)" "wg_sha256=$(baseline_sha wg)"
}

validate_baseline() {
  local expected actual
  [[ -f "${BASELINE_PHASE}" && ! -L "${BASELINE_PHASE}" ]] || fail 'baseline-missing' 79
  expected="$(render_baseline)" || fail 'baseline-render'
  actual="$(/usr/bin/cat "${BASELINE_PHASE}")" || fail 'baseline-read'
  [[ "${actual}" == "${expected}" ]] || fail 'baseline-mismatch' 79
}

snapshot_baseline() {
  local spec label operation
  [[ ! -e "${PIN_PATH}" && ! -e "/sys/module/${MODULE_NAME}" ]] || fail 'baseline-project-resource-preexists' 79
  run_operation A.pre-a veth-show-a 1; run_operation A.pre-b veth-show-b 1
  for spec in "${BASELINE_SPECS[@]}"; do IFS='|' read -r label operation <<<"${spec}"; run_operation "A.${label}" "${operation}"; done
  /usr/bin/grep -Fqx "${INITIAL_NETNS}" "${EVIDENCE_ROOT}/A.netns.out" || fail 'baseline-netns' 79
  [[ ! -s "${EVIDENCE_ROOT}/A.wg.out" ]] || fail 'wireguard-not-absent' 79
  write_phase "${BASELINE_PHASE}" "$(render_baseline)"
}

render_mutation_plan() {
  printf '%s\n' 'format=wg-mix-ebpf-b82-veth-mutation-plan-v2' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${ORIGINAL_BOOT_ID}" "netns=${INITIAL_NETNS}" "veth_a=${VETH_A}" "veth_a_mac=${VETH_A_MAC}" "veth_a_alias=${VETH_A_ALIAS}" "veth_b=${VETH_B}" "veth_b_mac=${VETH_B_MAC}" "veth_b_alias=${VETH_B_ALIAS}" "pin=${PIN_PATH}" "runtime=${TCX_RUNTIME_ROOT}" "baseline_object_sha256=$(sha256_file "${VETH_SOURCE}/build/wg_mix_tc.o")" "experimental_object_sha256=$(sha256_file "${VETH_SOURCE}/build/wg_mix_faketcp_experimental.o")" "module=${MODULE_NAME}" "module_sha256=${MODULE_SHA256}" "module_srcversion=${MODULE_SRCVERSION}"
}

validate_mutation_plan() {
  local expected actual
  [[ -f "${MUTATION_PHASE}" && ! -L "${MUTATION_PHASE}" ]] || fail 'mutation-plan-missing' 79
  MODULE_SHA256="$(sha256_file "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko")" || fail 'module-sha'
  MODULE_SRCVERSION="$(/usr/sbin/modinfo -F srcversion "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko")" || fail 'module-srcversion'
  [[ "${MODULE_SRCVERSION}" =~ ^[0-9A-F]{8,64}$ ]] || fail 'module-srcversion-shape' 79
  expected="$(render_mutation_plan)" || fail 'mutation-plan-render'
  actual="$(/usr/bin/cat "${MUTATION_PHASE}")" || fail 'mutation-plan-read'
  [[ "${actual}" == "${expected}" ]] || fail 'mutation-plan-mismatch' 79
  configure_checksum_module_lease
}

prepare_mutation_plan() {
  MODULE_SHA256="$(sha256_file "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko")" || fail 'module-sha'
  MODULE_SRCVERSION="$(/usr/sbin/modinfo -F srcversion "${VETH_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko")" || fail 'module-srcversion'
  [[ "${MODULE_SRCVERSION}" =~ ^[0-9A-F]{8,64}$ ]] || fail 'module-srcversion-shape' 79
  write_phase "${MUTATION_PHASE}" "$(render_mutation_plan)"
  configure_checksum_module_lease
}

veth_presence() {
  local a=0 b=0
  [[ -e "/sys/class/net/${VETH_A}" ]] && a=1
  [[ -e "/sys/class/net/${VETH_B}" ]] && b=1
  printf '%s%s\n' "${a}" "${b}"
}

veth_sysfs_identity() {
  local name="$1" canonical
  canonical="$(/usr/bin/readlink -e -- "/sys/class/net/${name}")" || return $?
  [[ "${canonical}" == "/sys/devices/virtual/net/${name}" && -d "${canonical}" && ! -L "${canonical}" ]] || return 79
  /usr/bin/stat -Lc '%d:%i:%u:%g' -- "${canonical}"
}

verify_veth() {
  local allow_partial="$1" expected_a="${2:-}" expected_b="${3:-}" expected_a_sysfs="${4:-}" expected_b_sysfs="${5:-}"
  local a_index b_index a_sysfs b_sysfs a_link b_link a_mac b_mac a_alias b_alias
  a_index="$(read_single_line "/sys/class/net/${VETH_A}/ifindex")" || return $?
  b_index="$(read_single_line "/sys/class/net/${VETH_B}/ifindex")" || return $?
  a_sysfs="$(veth_sysfs_identity "${VETH_A}")" || return $?
  b_sysfs="$(veth_sysfs_identity "${VETH_B}")" || return $?
  a_link="$(read_single_line "/sys/class/net/${VETH_A}/iflink")" || return $?
  b_link="$(read_single_line "/sys/class/net/${VETH_B}/iflink")" || return $?
  a_mac="$(read_single_line "/sys/class/net/${VETH_A}/address")" || return $?
  b_mac="$(read_single_line "/sys/class/net/${VETH_B}/address")" || return $?
  a_alias="$(read_optional_line "/sys/class/net/${VETH_A}/ifalias")" || return $?
  b_alias="$(read_optional_line "/sys/class/net/${VETH_B}/ifalias")" || return $?
  [[ "${a_index}" =~ ^[1-9][0-9]*$ && "${b_index}" =~ ^[1-9][0-9]*$ ]] || return 79
  if [[ -n "${expected_a}" || -n "${expected_b}" ]]; then
    [[ -n "${expected_a}" && -n "${expected_b}" && -n "${expected_a_sysfs}" && -n "${expected_b_sysfs}" ]] || return 79
    [[ "${a_index}" == "${expected_a}" && "${b_index}" == "${expected_b}" ]] || return 80
    [[ "${a_sysfs}" == "${expected_a_sysfs}" && "${b_sysfs}" == "${expected_b_sysfs}" ]] || return 81
  fi
  [[ "${a_link}" == "${b_index}" && "${b_link}" == "${a_index}" && "${a_mac}" == "${VETH_A_MAC}" && "${b_mac}" == "${VETH_B_MAC}" ]] || return 79
  if [[ "${allow_partial}" == 1 ]]; then
    [[ -z "${a_alias}" || "${a_alias}" == "${VETH_A_ALIAS}" ]] || return 79
    [[ -z "${b_alias}" || "${b_alias}" == "${VETH_B_ALIAS}" ]] || return 79
  else
    [[ "${a_alias}" == "${VETH_A_ALIAS}" && "${b_alias}" == "${VETH_B_ALIAS}" ]] || return 79
  fi
  VETH_A_IFINDEX="${a_index}"; VETH_B_IFINDEX="${b_index}"
  VETH_A_SYSFS_IDENTITY="${a_sysfs}"; VETH_B_SYSFS_IDENTITY="${b_sysfs}"
}

verify_veth_endpoint() {
  local side="$1" expected_index="$2" expected_sysfs="$3" allow_partial="$4"
  local name expected_mac expected_alias live_index live_sysfs live_mac live_alias
  case "${side}" in
    a) name="${VETH_A}"; expected_mac="${VETH_A_MAC}"; expected_alias="${VETH_A_ALIAS}" ;;
    b) name="${VETH_B}"; expected_mac="${VETH_B_MAC}"; expected_alias="${VETH_B_ALIAS}" ;;
    *) return 79 ;;
  esac
  live_index="$(read_single_line "/sys/class/net/${name}/ifindex")" || return $?
  live_sysfs="$(veth_sysfs_identity "${name}")" || return $?
  live_mac="$(read_single_line "/sys/class/net/${name}/address")" || return $?
  live_alias="$(read_optional_line "/sys/class/net/${name}/ifalias")" || return $?
  [[ "${live_index}" =~ ^[1-9][0-9]*$ && "${live_index}" == "${expected_index}" ]] || return 80
  [[ "${live_sysfs}" == "${expected_sysfs}" ]] || return 81
  [[ "${live_mac}" == "${expected_mac}" ]] || return 79
  if [[ "${allow_partial}" == 1 ]]; then
    [[ -z "${live_alias}" || "${live_alias}" == "${expected_alias}" ]] || return 79
  else
    [[ "${live_alias}" == "${expected_alias}" ]] || return 79
  fi
}

require_receipted_veth_pair() {
  local allow_partial="$1" label="$2" rc
  verify_veth "${allow_partial}" "${VETH_A_IFINDEX}" "${VETH_B_IFINDEX}" "${VETH_A_SYSFS_IDENTITY}" "${VETH_B_SYSFS_IDENTITY}"; rc=$?
  ((rc != 80)) || fail "${label}:ifindex-drift" 79
  ((rc != 81)) || fail "${label}:kernel-identity-drift" 79
  ((rc == 0)) || fail "${label}:identity-drift" 79
}

require_receipted_veth_endpoint() {
  local side="$1" label="$2" rc
  case "${side}" in
    a) verify_veth_endpoint a "${VETH_A_IFINDEX}" "${VETH_A_SYSFS_IDENTITY}" 1; rc=$? ;;
    b) verify_veth_endpoint b "${VETH_B_IFINDEX}" "${VETH_B_SYSFS_IDENTITY}" 1; rc=$? ;;
    *) fail "${label}:endpoint" 79 ;;
  esac
  ((rc != 80)) || fail "${label}:ifindex-drift" 79
  ((rc != 81)) || fail "${label}:kernel-identity-drift" 79
  ((rc == 0)) || fail "${label}:identity-drift" 79
}

render_veth_phase() {
  printf '%s\n' 'format=wg-mix-ebpf-b82-veth-resource-v3' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "a=${VETH_A}" "a_ifindex=${VETH_A_IFINDEX}" "a_sysfs_identity=${VETH_A_SYSFS_IDENTITY}" "a_mac=${VETH_A_MAC}" "a_alias=${VETH_A_ALIAS}" "b=${VETH_B}" "b_ifindex=${VETH_B_IFINDEX}" "b_sysfs_identity=${VETH_B_SYSFS_IDENTITY}" "b_mac=${VETH_B_MAC}" "b_alias=${VETH_B_ALIAS}"
}

ensure_veth_phase() {
  local expected actual presence
  presence="$(veth_presence)"
  if [[ -f "${VETH_PHASE}" && ! -L "${VETH_PHASE}" ]]; then
    VETH_A_IFINDEX="$(/usr/bin/awk -F= '$1 == "a_ifindex" {print $2}' "${VETH_PHASE}")"
    VETH_B_IFINDEX="$(/usr/bin/awk -F= '$1 == "b_ifindex" {print $2}' "${VETH_PHASE}")"
    VETH_A_SYSFS_IDENTITY="$(/usr/bin/awk -F= '$1 == "a_sysfs_identity" {print $2}' "${VETH_PHASE}")"
    VETH_B_SYSFS_IDENTITY="$(/usr/bin/awk -F= '$1 == "b_sysfs_identity" {print $2}' "${VETH_PHASE}")"
    expected="$(render_veth_phase)"; actual="$(/usr/bin/cat "${VETH_PHASE}")"
    [[ "${VETH_A_IFINDEX}" =~ ^[1-9][0-9]*$ && "${VETH_B_IFINDEX}" =~ ^[1-9][0-9]*$ && "${VETH_A_SYSFS_IDENTITY}" =~ ^[0-9]+:[0-9]+:0:0$ && "${VETH_B_SYSFS_IDENTITY}" =~ ^[0-9]+:[0-9]+:0:0$ && "${expected}" == "${actual}" ]] || fail 'veth-phase-mismatch' 79
    case "${presence}" in
      11) require_receipted_veth_pair 1 veth-phase ;;
      00) [[ -f "${CLEANUP_PHASE}" && ! -L "${CLEANUP_PHASE}" ]] || fail 'veth-missing-before-cleanup-intent' 79 ;;
      10) [[ -f "${CLEANUP_PHASE}" && ! -L "${CLEANUP_PHASE}" ]] || fail 'partial-veth-before-cleanup-intent' 79; require_receipted_veth_endpoint a veth-phase-a ;;
      01) [[ -f "${CLEANUP_PHASE}" && ! -L "${CLEANUP_PHASE}" ]] || fail 'partial-veth-before-cleanup-intent' 79; require_receipted_veth_endpoint b veth-phase-b ;;
      *) fail 'veth-presence-shape' 79 ;;
    esac
    return
  fi
  case "${presence}" in
    00) return ;;
    11) verify_veth 1 || fail 'unreceipted-veth-identity' 79; write_phase "${VETH_PHASE}" "$(render_veth_phase)" ;;
    *) fail 'partial-veth-pair' 79 ;;
  esac
}

create_veth() {
  run_operation N.pre-a veth-show-a 1; run_operation N.pre-b veth-show-b 1
  run_operation N.add veth-add
  ensure_veth_phase
  require_receipted_veth_pair 1 N.alias-a-pre; run_operation N.alias-a veth-alias-a
  require_receipted_veth_pair 1 N.alias-b-pre; run_operation N.alias-b veth-alias-b
  require_receipted_veth_pair 0 N.up-a-pre; run_operation N.up-a veth-up-a
  require_receipted_veth_pair 0 N.up-b-pre; run_operation N.up-b veth-up-b
  require_receipted_veth_pair 0 veth-final
}

render_tcx_phase() { printf '%s\n' 'format=wg-mix-ebpf-b82-veth-tcx-v2' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "pin=${PIN_PATH}" "runtime=${TCX_RUNTIME_ROOT}" "outcome=$1"; }

validate_internal_tcx_receipt() {
  local receipt="$1" journal="${TCX_RUNTIME_ROOT}/bpffs-journal.v1.json" shape
  [[ -f "${receipt}" && ! -L "${receipt}" && -f "${journal}" && ! -L "${journal}" ]] || return 1
  shape="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' "${receipt}")" || return $?
  [[ "${shape}" == '0:0:600:1:regular file' ]] || return 79
  /usr/bin/cmp -s "${journal}" "${receipt}"
}

validate_tcx_phase() {
  local outcome expected actual
  outcome="$(/usr/bin/awk -F= '$1 == "outcome" {print $2}' "${TCX_PHASE}")"
  [[ "${outcome}" =~ ^(not-started|run-restored|explicit-restored)$ ]] || fail 'tcx-outcome' 79
  expected="$(render_tcx_phase "${outcome}")"; actual="$(/usr/bin/cat "${TCX_PHASE}")"
  [[ "${expected}" == "${actual}" ]] || fail 'tcx-phase-mismatch' 79
}

compare_baseline() {
  local label="$1" operation="$2" baseline="$3" actual expected
  actual="$(capture_operation "${label}" "${operation}")" || return $?
  expected="$(/usr/bin/cat "${EVIDENCE_ROOT}/A.${baseline}.out")" || fail "baseline-read:${baseline}"
  [[ "${actual}" == "${expected}" ]] || { printf 'B82_VETH_V6_DRIFT label=%s\n' "${label}" >&2; return 79; }
}

assert_bpf_baseline() {
  compare_baseline "$1.links" snapshot:links links || fail "$1:links-drift" 79
  compare_baseline "$1.programs" snapshot:programs programs || fail "$1:programs-drift" 79
  compare_baseline "$1.maps" snapshot:maps maps || fail "$1:maps-drift" 79
}

run_tcx() {
  require_receipted_veth_pair 0 T.pre
  run_operation C.tcx-list list:TestBPFFSPinLifecycleIntegration
  /usr/bin/grep -Fxq TestBPFFSPinLifecycleIntegration "${STEP_LOG}" || fail 'tcx-test-definition' 79
  run_operation T.run tcx-run
  /usr/bin/grep -Fqx 'SCOPED_BPFFS_COMPLETE restored=1' "${STEP_LOG}" || fail 'tcx-completion' 79
  validate_internal_tcx_receipt "${TCX_RUNTIME_ROOT}/bpffs-restored.v1.json" || fail 'tcx-internal-run-receipt' 79
  [[ ! -e "${PIN_PATH}" ]] || fail 'tcx-pin-remains' 79
  assert_bpf_baseline T.after
  write_phase "${TCX_PHASE}" "$(render_tcx_phase run-restored)"
}

converge_tcx() {
  if [[ -f "${TCX_PHASE}" && ! -L "${TCX_PHASE}" ]]; then validate_tcx_phase; [[ ! -e "${PIN_PATH}" ]] || fail 'tcx-receipted-pin' 79; assert_bpf_baseline R.tcx-receipted; return; fi
  if [[ ! -e "${TCX_RUNTIME_ROOT}" && ! -e "${PIN_PATH}" ]]; then assert_bpf_baseline R.tcx-not-started; write_phase "${TCX_PHASE}" "$(render_tcx_phase not-started)"; return; fi
  [[ -d "${TCX_RUNTIME_ROOT}" && ! -L "${TCX_RUNTIME_ROOT}" ]] || fail 'tcx-runtime-shape' 79
  if validate_internal_tcx_receipt "${TCX_RUNTIME_ROOT}/bpffs-restored.v1.json"; then
    [[ ! -e "${PIN_PATH}" ]] || fail 'tcx-run-receipt-pin' 79; assert_bpf_baseline R.tcx-run-cut; write_phase "${TCX_PHASE}" "$(render_tcx_phase run-restored)"; return
  fi
  if validate_internal_tcx_receipt "${TCX_RUNTIME_ROOT}/bpffs-explicit-restore.v1.json"; then
    [[ ! -e "${PIN_PATH}" ]] || fail 'tcx-restore-receipt-pin' 79; assert_bpf_baseline R.tcx-restore-cut; write_phase "${TCX_PHASE}" "$(render_tcx_phase explicit-restored)"; return
  fi
  ensure_veth_phase
  [[ -f "${VETH_PHASE}" ]] || fail 'tcx-restore-without-veth' 79
  run_convergent_operation R.tcx tcx-restore
  /usr/bin/grep -Fqx 'SCOPED_BPFFS_RESTORE_COMPLETE restored=1' <<<"${CONVERGENCE_OUTPUT}" || fail 'tcx-explicit-completion' 79
  validate_internal_tcx_receipt "${TCX_RUNTIME_ROOT}/bpffs-explicit-restore.v1.json" || fail 'tcx-internal-restore-receipt' 79
  [[ ! -e "${PIN_PATH}" ]] || fail 'tcx-explicit-pin' 79; assert_bpf_baseline R.tcx-after
  write_phase "${TCX_PHASE}" "$(render_tcx_phase explicit-restored)"
}

load_module() {
  local state
  c8_checksum_module_load M.load || fail 'module-lease-load' $?
  state="$(c8_checksum_module_validate_restore_state)" || fail 'module-lease-load-state' $?
  [[ "${state}" == '11-owned-live' ]] || fail "module-lease-load-state:${state}" 79
}

run_faketcp_tests() {
  local name index=1
  for name in TestFakeTCPBPFPacketProbe "${OFFLOAD_TESTS[@]}" "${REALHOST_TESTS[@]}"; do
    run_operation "C.test${index}" "list:${name}"
    /usr/bin/grep -Fxq "${name}" "${STEP_LOG}" || fail "missing-test:${name}" 79
    ((index++))
  done
  run_operation F.verifier verifier; assert_bpf_baseline F.verifier-after
  run_operation F.packet packet-probe; assert_bpf_baseline F.packet-after
  index=1
  for name in "${OFFLOAD_TESTS[@]}"; do run_operation "F.offload${index}" "offload:${name}"; ((index++)); done
  index=1
  for name in "${REALHOST_TESTS[@]}"; do require_receipted_veth_pair 0 "F.realhost${index}-pre"; run_operation "F.realhost${index}" "realhost:${name}"; assert_bpf_baseline "F.realhost${index}-after"; ((index++)); done
}

render_cleanup_intent() {
  printf '%s\n' 'format=wg-mix-ebpf-b82-veth-cleanup-v3' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${ORIGINAL_BOOT_ID}" "netns=${INITIAL_NETNS}" "mutation_sha256=$(file_sha_or_absent "${MUTATION_PHASE}")" "veth_sha256=$(file_sha_or_absent "${VETH_PHASE}")" "tcx_sha256=$(file_sha_or_absent "${TCX_PHASE}")" "module_intent_sha256=$(file_sha_or_absent "${MODULE_INTENT}")" "module_owned_sha256=$(file_sha_or_absent "${MODULE_OWNED}")" "pin=${PIN_PATH}" "runtime=${TCX_RUNTIME_ROOT}" "veth_a=${VETH_A}" "veth_b=${VETH_B}" "module=${MODULE_NAME}" "lease_id=${MODULE_LEASE_ID}"
}

ensure_cleanup_intent() {
  local expected actual
  expected="$(render_cleanup_intent)"
  if [[ -f "${CLEANUP_PHASE}" && ! -L "${CLEANUP_PHASE}" ]]; then actual="$(/usr/bin/cat "${CLEANUP_PHASE}")"; [[ "${actual}" == "${expected}" ]] || fail 'cleanup-intent-mismatch' 79; else write_phase "${CLEANUP_PHASE}" "${expected}"; fi
}

validate_cleanup_intent() {
  [[ -f "${CLEANUP_PHASE}" && ! -L "${CLEANUP_PHASE}" ]] || fail 'cleanup-intent-missing' 79
  ensure_cleanup_intent
}

converge_module_absent() {
  local state
  c8_checksum_module_restore R.module || fail 'module-lease-restore' $?
  state="$(c8_checksum_module_validate_restore_state)" || fail 'module-lease-restored-state' $?
  [[ "${state}" == '00-clean' || "${state}" == '00-restored' ]] ||
    fail "module-lease-restored-state:${state}" 79
}

converge_veth_absent() {
  local presence
  ensure_veth_phase; presence="$(veth_presence)"
  if [[ -f "${VETH_PHASE}" ]]; then
    case "${presence}" in
      11) require_receipted_veth_pair 1 cleanup-veth; run_convergent_operation R.veth veth-delete ;;
      10) require_receipted_veth_endpoint a cleanup-veth-a; run_convergent_operation R.veth veth-delete ;;
      01) require_receipted_veth_endpoint b cleanup-veth-b; run_convergent_operation R.veth-peer veth-delete-b ;;
      00) ;;
      *) fail 'cleanup-veth-presence-shape' 79 ;;
    esac
    [[ "$(veth_presence)" == 00 ]] || fail 'veth-remove-incomplete' 79
  else
    [[ "${presence}" == 00 ]] || fail 'unowned-veth-present' 79
  fi
}

validate_terminal_phase() {
  local path="$1" state="$2" timestamp expected actual
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  timestamp="$(/usr/bin/awk -F= '$1 == "utc" {print $2}' "${path}")"
  [[ "${timestamp}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || fail 'terminal-timestamp' 79
  expected="$(printf '%s\n' 'format=wg-mix-ebpf-b82-veth-terminal-v2' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" "state=${state}" "utc=${timestamp}")"
  actual="$(/usr/bin/cat "${path}")"
  [[ "${actual}" == "${expected}" ]] || fail 'terminal-mismatch' 79
}

verify_final_state() {
  local spec label operation current
  current="$(capture_operation "$1.netns" snapshot:netns)"
  [[ "${current}" == "${INITIAL_NETNS}" && ! -e "${PIN_PATH}" && ! -e "/sys/module/${MODULE_NAME}" && "$(veth_presence)" == 00 ]] || fail "$1:owned-resource-drift" 79
  for spec in "${FINAL_SPECS[@]}"; do IFS='|' read -r label operation <<<"${spec}"; compare_baseline "$1.${label}" "${operation}" "${label}" || fail "$1:${label}-drift" 79; done
}

validate_completed_chain() {
  local module_state
  validate_baseline
  validate_staged_source
  if [[ -f "${MUTATION_PHASE}" && ! -L "${MUTATION_PHASE}" ]]; then
    validate_mutation_plan
    ensure_veth_phase
    [[ -f "${TCX_PHASE}" && ! -L "${TCX_PHASE}" ]] || fail 'completed-tcx-phase-missing' 79
    validate_tcx_phase
    [[ ! -e "${PIN_PATH}" ]] || fail 'completed-tcx-pin-remains' 79
    module_state="$(c8_checksum_module_validate_restore_state)" || fail 'completed-module-state' $?
    [[ "${module_state}" == '00-clean' || "${module_state}" == '00-restored' ]] ||
      fail "completed-module-state:${module_state}" 79
  else
    [[ ! -e "${MUTATION_PHASE}" && ! -e "${VETH_PHASE}" && ! -e "${TCX_PHASE}" &&
      ! -e "${MODULE_INTENT}" && ! -e "${MODULE_OWNED}" && ! -e "${MODULE_UNLOADED}" &&
      ! -e "${PIN_PATH}" && ! -e "/sys/module/${MODULE_NAME}" &&
      "$(veth_presence)" == 00 ]] || fail 'completed-resource-without-mutation-plan' 79
  fi
  validate_cleanup_intent
  assert_bpf_baseline R.completed-bpf
}

converge_restore() {
  validate_evidence_shapes
  if validate_terminal_phase "${RESTORED_PHASE}" restored; then
    [[ ! -e "${FILESYSTEM_PHASE}" ]] || fail 'dual-terminal-state' 79
    validate_completed_chain
    verify_final_state R.already
    printf 'B82_VETH_V6_RESTORE_COMPLETE run_id=%s resource_id=%s already_restored=1 full_restore=1\n' "${VETH_RUN_ID}" "${RESOURCE_ID}"
    return
  fi
  [[ ! -e "${RESTORED_PHASE}" ]] || fail 'invalid-restored-phase' 79
  if [[ ! -e "${BASELINE_PHASE}" ]]; then
    [[ ! -e "${MUTATION_PHASE}" && ! -e "${VETH_PHASE}" && ! -e "${TCX_PHASE}" &&
      ! -e "${MODULE_INTENT}" && ! -e "${MODULE_OWNED}" && ! -e "${MODULE_UNLOADED}" &&
      ! -e "${CLEANUP_PHASE}" ]] ||
      fail 'filesystem-terminal-with-mutation' 79
    if ! validate_terminal_phase "${FILESYSTEM_PHASE}" filesystem-retained; then
      [[ ! -e "${FILESYSTEM_PHASE}" ]] || fail 'invalid-filesystem-phase' 79
      write_phase "${FILESYSTEM_PHASE}" 'format=wg-mix-ebpf-b82-veth-terminal-v2' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" 'state=filesystem-retained' "utc=$(utc_now)"
    fi
    printf 'B82_VETH_V6_RESTORE_COMPLETE run_id=%s resource_id=%s filesystem_only=1 full_restore=0 retained=1\n' "${VETH_RUN_ID}" "${RESOURCE_ID}"
    return
  fi
  [[ ! -e "${FILESYSTEM_PHASE}" ]] || fail 'filesystem-phase-with-baseline' 79
  validate_baseline
  validate_staged_source
  if [[ -f "${MUTATION_PHASE}" ]]; then validate_mutation_plan; ensure_veth_phase; converge_tcx; else
    [[ ! -e "${VETH_PHASE}" && ! -e "${TCX_PHASE}" && ! -e "${MODULE_INTENT}" &&
      ! -e "${MODULE_OWNED}" && ! -e "${MODULE_UNLOADED}" &&
      ! -e "${PIN_PATH}" && ! -e "/sys/module/${MODULE_NAME}" && "$(veth_presence)" == 00 ]] ||
      fail 'resource-without-mutation-plan' 79
  fi
  ensure_cleanup_intent
  converge_module_absent
  converge_veth_absent
  assert_bpf_baseline R.cleanup-bpf
  verify_final_state R.final
  write_phase "${RESTORED_PHASE}" 'format=wg-mix-ebpf-b82-veth-terminal-v2' "run_id=${VETH_RUN_ID}" "resource_id=${RESOURCE_ID}" 'state=restored' "utc=$(utc_now)"
  printf 'B82_VETH_V6_CLASSIFICATION wg_active_scoped=not-covered pass=0 raw_ens33=not-covered raw_ens33_pass=0 peer_47=read-only capability_bits_changed=0\n'
  printf 'B82_VETH_V6_RESTORE_COMPLETE run_id=%s resource_id=%s already_restored=0 full_restore=1 evidence=%s\n' "${VETH_RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
}

run_all() {
  validate_controller_identity; load_checksum_module_helper; validate_package_bundle; create_roots
  c8_checksum_module_acquire L0.run
  stage_source; snapshot_baseline
  run_operation O.build build
  prepare_mutation_plan
  create_veth
  run_tcx
  load_module
  run_faketcp_tests
  converge_restore
  printf 'B82_VETH_V6_COMPLETE run_id=%s resource_id=%s commit=%s evidence=%s restored=1\n' "${VETH_RUN_ID}" "${RESOURCE_ID}" "${COMMIT}" "${EVIDENCE_ROOT}"
}

restore_all() {
  validate_controller_identity
  load_checksum_module_helper
  [[ -d "${VETH_STAGE_ROOT}" && ! -L "${VETH_STAGE_ROOT}" && -d "${EVIDENCE_ROOT}" && ! -L "${EVIDENCE_ROOT}" ]] || fail 'restore-root-shape' 79
  validate_owner
  c8_checksum_module_acquire L0.restore
  converge_restore
}

parse_arguments "$@"; parse_rc=$?
((parse_rc == 0)) || fail "arguments:rc=${parse_rc}" "${parse_rc}"
if [[ "${MODE}" == plan ]]; then render_plan; exit 0; fi
((EUID == 0)) || fail 'root-required' 77
require_tooling
case "${MODE}" in run) run_all ;; restore) restore_all ;; *) fail 'unreachable-mode' 64 ;; esac
