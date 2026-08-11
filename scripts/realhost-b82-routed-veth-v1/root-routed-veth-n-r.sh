#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='c8e41d73'
readonly RESOURCE_ID='5b8d30f1'
readonly STATE_SCHEMA='owner,baseline,operation-intent,dependency-intent,artifact-intent,artifacts,dependency-preflight,veth-intent,veth,address,route,neighbor,offload,module-intent,module,tested,cleanup-intent,restored'
readonly STAGE_ROOT="/run/wg-mix-ebpf-source-stages/${RUN_ID}"
readonly EXPECTED_SOURCE="${STAGE_ROOT}/source"
readonly EVIDENCE_ROOT="${STAGE_ROOT}/routed-evidence-${RESOURCE_ID}"
readonly GO_CACHE="${EVIDENCE_ROOT}/go-cache"
readonly GO_MOD_CACHE="${EVIDENCE_ROOT}/go-mod-cache"
readonly GO_PATH="${EVIDENCE_ROOT}/go-path"
readonly GO_TMP="${EVIDENCE_ROOT}/go-tmp"
readonly RUNTIME_TEMP="${STAGE_ROOT}/go-tmp-realhost-${RESOURCE_ID}"
readonly AUDIT_LOG="${EVIDENCE_ROOT}/audit.log"
readonly OWNER_PHASE="${EVIDENCE_ROOT}/phase-owner.v1"
readonly BASELINE_PHASE="${EVIDENCE_ROOT}/phase-baseline.v1"
readonly OPERATION_PHASE="${EVIDENCE_ROOT}/phase-operation-intent.v1"
readonly DEPENDENCY_INTENT_PHASE="${EVIDENCE_ROOT}/phase-dependency-intent.v1"
readonly ARTIFACT_INTENT_PHASE="${EVIDENCE_ROOT}/phase-artifact-intent.v1"
readonly ARTIFACT_PHASE="${EVIDENCE_ROOT}/phase-artifacts.v1"
readonly DEPENDENCY_PHASE="${EVIDENCE_ROOT}/phase-dependency-preflight.v1"
readonly VETH_INTENT_PHASE="${EVIDENCE_ROOT}/phase-veth-intent.v1"
readonly VETH_PHASE="${EVIDENCE_ROOT}/phase-veth.v1"
readonly ADDRESS_PHASE="${EVIDENCE_ROOT}/phase-address.v1"
readonly ROUTE_PHASE="${EVIDENCE_ROOT}/phase-route.v1"
readonly NEIGHBOR_PHASE="${EVIDENCE_ROOT}/phase-neighbor.v1"
readonly OFFLOAD_PHASE="${EVIDENCE_ROOT}/phase-offload.v1"
readonly MODULE_INTENT_PHASE="${EVIDENCE_ROOT}/checksum-module-intent.v1"
readonly MODULE_PHASE="${EVIDENCE_ROOT}/checksum-module-owned.v1"
readonly MODULE_UNLOADED_PHASE="${EVIDENCE_ROOT}/checksum-module-unloaded.v1"
readonly TESTED_PHASE="${EVIDENCE_ROOT}/phase-tested.v1"
readonly CLEANUP_PHASE="${EVIDENCE_ROOT}/phase-cleanup-intent.v1"
readonly RESTORED_PHASE="${EVIDENCE_ROOT}/phase-restored.v1"
readonly BPF_LINK_BASELINE="${EVIDENCE_ROOT}/baseline-bpf-links.json"
readonly OFFLOAD_BASELINE_A="${EVIDENCE_ROOT}/baseline-offload-a.txt"
readonly PREFLIGHT_BINARY="${EVIDENCE_ROOT}/dataplane-preflight.test"

readonly VETH_A="wg${RESOURCE_ID:0:5}a"
readonly VETH_B="wg${RESOURCE_ID:0:5}b"
readonly VETH_A_ALIAS="wg-mix-ebpf:${RUN_ID}:${RESOURCE_ID}:a"
readonly VETH_B_ALIAS="wg-mix-ebpf:${RUN_ID}:${RESOURCE_ID}:b"
readonly VETH_A_MAC='02:5b:8d:30:f1:0a'
readonly VETH_B_MAC='02:5b:8d:30:f1:0b'
readonly LOCAL_IPV4='198.18.82.1'
readonly REMOTE_IPV4='198.18.82.2'
readonly PREFIX_BITS='32'
readonly ROUTE_MTU='1500'
readonly MODULE_NAME='wg_mix_faketcp_checksum'
readonly ARTIFACT_ROOT="${EXPECTED_SOURCE}/build"
readonly EXPERIMENTAL_OBJECT="${EXPECTED_SOURCE}/build/wg_mix_faketcp_experimental.o"
readonly BASELINE_OBJECT="${EXPECTED_SOURCE}/build/wg_mix_tc.o"
readonly MODULE_OBJECT="${EXPECTED_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
readonly MODULE_LEASE_HELPER_RELATIVE="scripts/realhost-b82-c8e41d73/checksum-module-lease.sh"
readonly MODULE_LEASE_HELPER="${EXPECTED_SOURCE}/${MODULE_LEASE_HELPER_RELATIVE}"
readonly MODULE_LEASE_LOCK="${STAGE_ROOT}/checksum-module-lease.v1.lock"
readonly MODULE_LEASE_ID="${RUN_ID}-${RESOURCE_ID}"
readonly SELF_RELATIVE='scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh'
readonly SEAM_RELATIVE='scripts/realhost-b82-routed-veth-v1/controller-seam.sh'
readonly ROUTED_CONTRACT_RELATIVE='internal/dataplane/faketcp_routed_realhost_contract_test.go'
readonly ROUTED_TEST_RELATIVE='internal/dataplane/faketcp_routed_realhost_linux_test.go'
readonly NEGATIVE_TEST_RELATIVE='internal/dataplane/faketcp_realhost_linux_test.go'
readonly GSO_KFUNC_RELATIVE='kernel/faketcp_checksum/wg_mix_faketcp_checksum.c'
readonly NEGATIVE_TEST='TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration'
readonly PREFLIGHT_CONTRACT_TEST='TestFakeTCPRealHostRoutedHarnessSelectedBinaryContract'
readonly -a POSITIVE_TESTS=(
  TestFakeTCPRealHostRoutedIPHdrInclNone
  TestFakeTCPRealHostRoutedUDPSocketPartial
  TestFakeTCPRealHostRoutedUDPSegmentGSO
)
readonly EXPECTED_HOSTNAME='ubuntu-2604-test'
readonly EXPECTED_MACHINE_ID='9db3fb717cc74974b2a6b243d67f67b9'
readonly EXPECTED_KERNEL_RELEASE='7.0.0-28-generic'
readonly KERNEL_BUILD="/lib/modules/${EXPECTED_KERNEL_RELEASE}/build"
readonly KERNEL_BUILD_CANONICAL="/usr/src/linux-headers-${EXPECTED_KERNEL_RELEASE}"
readonly VMLINUX_BTF='/sys/kernel/btf/vmlinux'

MODE=''
SOURCE=''
COMMIT=''
EXPERIMENTAL_SHA256=''
BASELINE_SHA256=''
MODULE_SHA256=''
MODULE_SRCVERSION=''
MODULE_VERMAGIC=''
VMLINUX_BTF_SHA256=''
ARTIFACT_STATE=''
INITIAL_NETNS=''
BOOT_ID=''
VETH_A_IFINDEX=''
VETH_B_IFINDEX=''
VETH_A_SYSFS=''
VETH_B_SYSFS=''
OP_TARGET=''
declare -a OP_ARGV=()
declare -a BOOTSTRAP_AUDIT_LINES=()

readonly -a GO_COMMON_ENV=(
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
  CGO_ENABLED=0 GOENV=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local
  'GOVCS=*:off'
  GOCACHE="${GO_CACHE}" GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}"
  GOTMPDIR="${GO_TMP}" TMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on
)
readonly -a GO_DOWNLOAD_ENV=(
  "${GO_COMMON_ENV[@]}" GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
)
readonly -a GO_OFFLINE_ENV=(
  "${GO_COMMON_ENV[@]}" GOPROXY=off GOSUMDB=off
)
readonly -a GIT_COMMAND=(
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0
  /usr/bin/git --no-pager --no-replace-objects
  -c core.attributesFile=/dev/null -c core.fsmonitor=false
  -c core.hooksPath=/dev/null
)

usage() {
  printf '%s\n' \
    "usage: $0 {plan|run|restore} --source ${EXPECTED_SOURCE}" \
    '  --commit 40-lowercase-hex' >&2
}

fail() {
  printf 'B82_ROUTED_VETH_STOP run_id=%s resource_id=%s mode=%s reason=%s rc=%s evidence=%s; no automatic teardown\n' \
    "${RUN_ID}" "${RESOURCE_ID}" "${MODE:-unparsed}" "$1" "${2:-125}" "${EVIDENCE_ROOT}" >&2
  exit "${2:-125}"
}

valid_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ && ! "$1" =~ ^0{40}$ && ! "$1" =~ ^f{40}$ ]]
}

valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ && ! "$1" =~ ^0{64}$ && ! "$1" =~ ^f{64}$ ]]
}

parse_arguments() {
  local seen_source=0 seen_commit=0
  (($# >= 1)) || { usage; return 64; }
  MODE="$1"
  shift
  case "${MODE}" in plan | run | restore) ;; *) usage; return 64 ;; esac
  while (($# > 0)); do
    (($# >= 2)) || { usage; return 64; }
    case "$1" in
      --source)
        ((seen_source == 0)) || return 65
        seen_source=1; SOURCE="$2"
        ;;
      --commit)
        ((seen_commit == 0)) || return 65
        seen_commit=1; COMMIT="$2"
        ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  ((seen_source == 1 && seen_commit == 1)) || return 65
  [[ "${SOURCE}" == "${EXPECTED_SOURCE}" ]] || return 65
  valid_commit "${COMMIT}" || return 65
}

quote_argv() { printf '%q ' "$@"; }

valid_test_name() {
  local wanted="$1" name
  [[ "${wanted}" == "${NEGATIVE_TEST}" ]] && return 0
  for name in "${POSITIVE_TESTS[@]}"; do
    [[ "${wanted}" == "${name}" ]] && return 0
  done
  return 1
}

valid_preflight_test_name() {
  [[ "$1" == "${PREFLIGHT_CONTRACT_TEST}" ]] || valid_test_name "$1"
}

# Every external operation which can mutate state or execute a test is built
# here. Callers never concatenate a shell command, use eval, or add free-form
# remote argv.
build_argv() {
  local operation="$1" name
  OP_TARGET="${operation}"
  OP_ARGV=()
  case "${operation}" in
    evidence-mkdir) OP_TARGET="${EVIDENCE_ROOT}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${EVIDENCE_ROOT}") ;;
    go-cache-mkdir) OP_TARGET="${GO_CACHE}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_CACHE}") ;;
    go-mod-cache-mkdir) OP_TARGET="${GO_MOD_CACHE}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_MOD_CACHE}") ;;
    go-path-mkdir) OP_TARGET="${GO_PATH}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_PATH}") ;;
    go-tmp-mkdir) OP_TARGET="${GO_TMP}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${GO_TMP}") ;;
    runtime-temp-mkdir) OP_TARGET="${RUNTIME_TEMP}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${RUNTIME_TEMP}") ;;
    bpf-links) OP_TARGET='global-bpf-links'; OP_ARGV=(/usr/sbin/bpftool -j link show) ;;
    preflight-mod-download) OP_TARGET="${GO_MOD_CACHE}"; OP_ARGV=("${GO_DOWNLOAD_ENV[@]}" /usr/bin/timeout --signal=TERM --kill-after=10s 10m /usr/bin/go -C "${SOURCE}" mod download all) ;;
    preflight-mod-verify) OP_TARGET="${GO_MOD_CACHE}"; OP_ARGV=("${GO_OFFLINE_ENV[@]}" /usr/bin/timeout --signal=TERM --kill-after=10s 5m /usr/bin/go -C "${SOURCE}" mod verify) ;;
    artifact-build)
      OP_TARGET="${ARTIFACT_ROOT}"
      OP_ARGV=("${GO_OFFLINE_ENV[@]}" GO=/usr/bin/go CLANG=/usr/bin/clang
        BPF_OBJECT="${BASELINE_OBJECT}"
        FAKETCP_EXPERIMENTAL_BPF_OBJECT="${EXPERIMENTAL_OBJECT}"
        FAKETCP_CHECKSUM_KMOD_SOURCE="${SOURCE}/kernel/faketcp_checksum"
        FAKETCP_CHECKSUM_KMOD_OUTPUT="${SOURCE}/build/faketcp_checksum_kmod"
        FAKETCP_CHECKSUM_KMOD_OBJECT="${MODULE_OBJECT}"
        KERNEL_RELEASE="${EXPECTED_KERNEL_RELEASE}" KERNEL_BUILD="${KERNEL_BUILD}"
        /usr/bin/timeout --signal=TERM --kill-after=30s 30m
        /usr/bin/make --no-print-directory -C "${SOURCE}"
        build-faketcp-checksum-kmod test-bpf-object-manifests)
      ;;
    artifact-mode) OP_TARGET="${EXPERIMENTAL_OBJECT}:${BASELINE_OBJECT}:${MODULE_OBJECT}"; OP_ARGV=(/usr/bin/chmod 0600 -- "${EXPERIMENTAL_OBJECT}" "${BASELINE_OBJECT}" "${MODULE_OBJECT}") ;;
    preflight-build) OP_TARGET="${PREFLIGHT_BINARY}"; OP_ARGV=("${GO_OFFLINE_ENV[@]}" /usr/bin/timeout --signal=TERM --kill-after=10s 10m /usr/bin/go -C "${SOURCE}" test -c -o "${PREFLIGHT_BINARY}" ./internal/dataplane) ;;
    veth-add) OP_TARGET="${VETH_A}:${VETH_B}"; OP_ARGV=(/usr/sbin/ip link add "${VETH_A}" address "${VETH_A_MAC}" type veth peer name "${VETH_B}" address "${VETH_B_MAC}") ;;
    veth-alias-a) OP_TARGET="${VETH_A}"; OP_ARGV=(/usr/sbin/ip link set dev "${VETH_A}" alias "${VETH_A_ALIAS}") ;;
    veth-alias-b) OP_TARGET="${VETH_B}"; OP_ARGV=(/usr/sbin/ip link set dev "${VETH_B}" alias "${VETH_B_ALIAS}") ;;
    veth-up-a) OP_TARGET="${VETH_A}"; OP_ARGV=(/usr/sbin/ip link set dev "${VETH_A}" up) ;;
    veth-up-b) OP_TARGET="${VETH_B}"; OP_ARGV=(/usr/sbin/ip link set dev "${VETH_B}" up) ;;
    address-add) OP_TARGET="${VETH_A}:${LOCAL_IPV4}/${PREFIX_BITS}"; OP_ARGV=(/usr/sbin/ip -4 address add "${LOCAL_IPV4}/${PREFIX_BITS}" dev "${VETH_A}" scope global) ;;
    route-add) OP_TARGET="${REMOTE_IPV4}/${PREFIX_BITS}"; OP_ARGV=(/usr/sbin/ip -4 route add "${REMOTE_IPV4}/${PREFIX_BITS}" dev "${VETH_A}" src "${LOCAL_IPV4}" mtu "${ROUTE_MTU}" proto static scope link) ;;
    neighbor-add) OP_TARGET="${VETH_A}:${REMOTE_IPV4}"; OP_ARGV=(/usr/sbin/ip -4 neigh add "${REMOTE_IPV4}" lladdr "${VETH_B_MAC}" nud permanent dev "${VETH_A}") ;;
    offload-show-a) OP_TARGET="${VETH_A}"; OP_ARGV=(/usr/sbin/ethtool -k "${VETH_A}") ;;
    offload-tso-off) OP_TARGET="${VETH_A}:tso=off"; OP_ARGV=(/usr/sbin/ethtool -K "${VETH_A}" tso off) ;;
    offload-tso-restore) OP_TARGET="${VETH_A}:tso=on"; OP_ARGV=(/usr/sbin/ethtool -K "${VETH_A}" tso on) ;;
    list:*)
      name="${operation#list:}"; valid_preflight_test_name "${name}" || return 64
      OP_TARGET="${name}"
      OP_ARGV=(/usr/bin/timeout --signal=TERM --kill-after=10s 1m "${PREFLIGHT_BINARY}" -test.list "^${name}$")
      ;;
    preflight-contract)
      OP_TARGET="${PREFLIGHT_CONTRACT_TEST}"
      OP_ARGV=(/usr/bin/timeout --signal=TERM --kill-after=10s 1m "${PREFLIGHT_BINARY}" -test.run "^${PREFLIGHT_CONTRACT_TEST}$" -test.count=1 -test.timeout=30s -test.v)
      ;;
    test:*)
      name="${operation#test:}"; valid_test_name "${name}" || return 64
      OP_TARGET="${name}"
      OP_ARGV=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TMPDIR="${RUNTIME_TEMP}" WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION=1 WG_MIX_FAKETCP_REALHOST_OBJECT="${EXPERIMENTAL_OBJECT}" WG_MIX_FAKETCP_REALHOST_BASELINE_OBJECT="${BASELINE_OBJECT}" WG_MIX_FAKETCP_REALHOST_IFINDEX="${VETH_A_IFINDEX}" WG_MIX_FAKETCP_REALHOST_PEER_IFINDEX="${VETH_B_IFINDEX}" WG_MIX_FAKETCP_REALHOST_XDP_MODE=generic WG_MIX_FAKETCP_REALHOST_RUN_ID="${RUN_ID}" WG_MIX_FAKETCP_REALHOST_RESOURCE_ID="${RESOURCE_ID}" WG_MIX_FAKETCP_ROUTED_LOCAL_IPV4="${LOCAL_IPV4}" WG_MIX_FAKETCP_ROUTED_REMOTE_IPV4="${REMOTE_IPV4}" WG_MIX_FAKETCP_ROUTED_PREFIX_BITS="${PREFIX_BITS}" WG_MIX_FAKETCP_ROUTED_ROUTE_MTU="${ROUTE_MTU}" /usr/bin/timeout --signal=TERM --kill-after=10s 3m "${PREFLIGHT_BINARY}" -test.run "^${name}$" -test.count=1 -test.timeout=2m -test.v)
      ;;
    neighbor-delete) OP_TARGET="${VETH_A}:${REMOTE_IPV4}"; OP_ARGV=(/usr/sbin/ip -4 neigh del "${REMOTE_IPV4}" lladdr "${VETH_B_MAC}" nud permanent dev "${VETH_A}") ;;
    route-delete) OP_TARGET="${REMOTE_IPV4}/${PREFIX_BITS}"; OP_ARGV=(/usr/sbin/ip -4 route del "${REMOTE_IPV4}/${PREFIX_BITS}" dev "${VETH_A}" src "${LOCAL_IPV4}" mtu "${ROUTE_MTU}" proto static scope link) ;;
    address-delete) OP_TARGET="${VETH_A}:${LOCAL_IPV4}/${PREFIX_BITS}"; OP_ARGV=(/usr/sbin/ip -4 address del "${LOCAL_IPV4}/${PREFIX_BITS}" dev "${VETH_A}" scope global) ;;
    veth-delete) OP_TARGET="${VETH_A}"; OP_ARGV=(/usr/sbin/ip link delete dev "${VETH_A}") ;;
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
  local name
  VETH_A_IFINDEX='OWNED_VETH_A_IFINDEX'
  VETH_B_IFINDEX='OWNED_VETH_B_IFINDEX'
  printf 'B82_ROUTED_VETH_PLAN_ONLY run_id=%s resource_id=%s commit=%s state_schema=%s\n' \
    "${RUN_ID}" "${RESOURCE_ID}" "${COMMIT}" "${STATE_SCHEMA}"
  printf 'B82_ROUTED_VETH_TOPOLOGY netns=initial veth=%s,%s sender=%s/%s peer=%s/unnumbered route=%s/%s mtu=%s neighbor=%s no_external_peer=1\n' \
    "${VETH_A}" "${VETH_B}" "${LOCAL_IPV4}" "${PREFIX_BITS}" "${VETH_B}" \
    "${REMOTE_IPV4}" "${PREFIX_BITS}" "${ROUTE_MTU}" "${VETH_B_MAC}"
  plan_operation B0 evidence-mkdir
  printf 'L0 operation=shared-module-lock target=%q helper=%q argv=' "${MODULE_LEASE_LOCK}" "${MODULE_LEASE_HELPER}"
  quote_argv /usr/bin/flock --exclusive --nonblock MODULE_LEASE_FD
  printf '\n'
  plan_operation A.bpf bpf-links
  plan_operation C0 go-cache-mkdir
  plan_operation C1 go-mod-cache-mkdir
  plan_operation C2 go-path-mkdir
  plan_operation C3 go-tmp-mkdir
  plan_operation P0 preflight-mod-download
  plan_operation P1 preflight-mod-verify
  printf 'P.artifact-intent operation=artifact-intent target=%q argv=internal:noclobber-phase-0600\n' "${ARTIFACT_INTENT_PHASE}"
  plan_operation P.artifact-build artifact-build
  plan_operation P.artifact-mode artifact-mode
  printf 'P.artifact-receipt operation=artifact-receipt target=%q argv=internal:noclobber-phase-0600\n' "${ARTIFACT_PHASE}"
  plan_operation P2 preflight-build
  for name in "${PREFLIGHT_CONTRACT_TEST}" "${NEGATIVE_TEST}" "${POSITIVE_TESTS[@]}"; do
    plan_operation "P.${name}" "list:${name}"
  done
  plan_operation P.contract preflight-contract
  plan_operation B1 runtime-temp-mkdir
  for spec in \
    'N0|veth-add' 'N1|veth-alias-a' 'N2|veth-alias-b' \
    'N3|veth-up-a' 'N4|veth-up-b' 'N5|address-add' \
    'N6|route-add' 'N7|neighbor-add' 'N8|offload-show-a' \
    'N9|offload-tso-off'; do
    IFS='|' read -r label operation <<<"${spec}"
    plan_operation "${label}" "${operation}"
  done
  printf 'M0 operation=shared-module-load target=%q helper=c8_checksum_module_load argv=' "${MODULE_NAME}"
  quote_argv /usr/sbin/insmod "${MODULE_OBJECT}" "lease_id=${MODULE_LEASE_ID}"
  printf '\n'
  for name in "${NEGATIVE_TEST}" "${POSITIVE_TESTS[@]}"; do
    plan_operation "T.${name}" "test:${name}"
  done
  plan_operation R0 bpf-links
  printf 'R1 operation=shared-module-restore target=%q helper=c8_checksum_module_restore argv=' "${MODULE_NAME}"
  quote_argv /usr/sbin/rmmod "${MODULE_NAME}"
  printf '\n'
  for spec in \
    'R2|offload-tso-restore' \
    'R3|neighbor-delete' 'R4|route-delete' 'R5|address-delete' \
    'R6|veth-delete' 'R7|bpf-links'; do
    IFS='|' read -r label operation <<<"${spec}"
    plan_operation "${label}" "${operation}"
  done
  printf 'B82_ROUTED_VETH_WRITE_SET filesystem=%s,%s,%s,%s,%s,%s,%s,%s shared_lock=%s:advisory-only network=veth:%s,%s,address:%s/%s,route:%s/%s,neighbor:%s,offload:%s:tso module=%s,lease_id:%s bpf=transient-unpinned-test-owned evidence_retained=1\n' \
    "${EVIDENCE_ROOT}" "${PREFLIGHT_BINARY}" "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}" "${RUNTIME_TEMP}" \
    "${ARTIFACT_ROOT}" \
    "${MODULE_LEASE_LOCK}" "${VETH_A}" "${VETH_B}" "${LOCAL_IPV4}" "${PREFIX_BITS}" "${REMOTE_IPV4}" \
    "${PREFIX_BITS}" "${REMOTE_IPV4}" "${VETH_A}" "${MODULE_NAME}" "${MODULE_LEASE_ID}"
  printf 'B82_ROUTED_VETH_RESTORE_ORDER cleanup-intent,bpf-baseline,module,offload,neighbor,route,address,veth,bpf-baseline,restored retryable=1 exact_reverse=1\n'
  printf 'B82_ROUTED_VETH_COVERAGE af_packet=none,partial,gso:route-unknown-negative routed=iphdrincl-none,udp-partial,udp-segment-gso:positive capability_bits_changed=0\n'
  printf 'B82_ROUTED_VETH_PLAN_COMPLETE commands_are_review_templates=1 preflight_before_host_mutation=1 network_downloads=bounded-go-module-proxy-only no_commands_executed=1 credential_read=0 remote_connections=0 network_operations=0\n'
}

utc_now() { /bin/date -u '+%Y-%m-%dT%H:%M:%SZ'; }

require_root_regular() {
  local path="$1" mode="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || return 79
  [[ "$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${path}")" == "0:0:${mode}:1:regular file" ]]
}

require_root_directory() {
  local path="$1"
  [[ -d "${path}" && ! -L "${path}" ]] || return 79
  [[ "$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${path}")" == '0:0:700:directory' ]]
}

require_root_test_binary() {
  local path="$1" identity
  [[ -f "${path}" && ! -L "${path}" ]] || return 79
  identity="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${path}")" || return $?
  [[ "${identity}" == '0:0:700:1:regular file' ||
    "${identity}" == '0:0:755:1:regular file' ]]
}

sha256_file() {
  local line
  line="$(/usr/bin/sha256sum -- "$1")" || return $?
  line="${line%% *}"
  valid_sha256 "${line}" || return 65
  printf '%s\n' "${line}"
}

audit_line() {
  local event="$1" step="$2" target="$3" rc="$4" rendered="$5" timestamp
  require_root_regular "${AUDIT_LOG}" 600 || return 79
  timestamp="$(utc_now)" || return $?
  printf 'utc=%q event=%q step=%q target=%q rc=%q argv=%q\n' \
    "${timestamp}" "${event}" "${step}" "${target}" "${rc}" "${rendered}" >>"${AUDIT_LOG}"
}

run_audited_argv() {
  local label="$1" target="$2" rendered rc
  local -a status
  shift 2
  rendered="$(quote_argv "$@")" || fail "render:${label}"
  audit_line start "${label}" "${target}" not-run "${rendered}" || fail "audit-start:${label}"
  "$@" 2>&1 | /usr/bin/tee -a "${AUDIT_LOG}"
  status=("${PIPESTATUS[@]}")
  ((${#status[@]} == 2)) || fail "pipeline:${label}"
  rc="${status[0]}"
  audit_line finish "${label}" "${target}" "${rc}" "${rendered}" || fail "audit-finish:${label}"
  ((status[1] == 0)) || fail "audit-output:${label}" "${status[1]}"
  return "${rc}"
}

run_operation() {
  local label="$1" operation="$2"
  build_argv "${operation}" || fail "operation-builder:${operation}" $?
  run_audited_argv "${label}" "${OP_TARGET}" "${OP_ARGV[@]}"
}

c8_checksum_module_run() {
  run_audited_argv "$@"
}

c8_checksum_module_write() {
  write_phase "$1" "$2"
}

c8_checksum_module_fail() {
  fail "checksum-module-lease:$1" "$2"
}

capture_operation() {
  local label="$1" operation="$2" destination="$3" rendered output rc
  [[ ! -e "${destination}" && ! -L "${destination}" ]] || return 73
  build_argv "${operation}" || fail "capture-builder:${operation}" $?
  rendered="$(quote_argv "${OP_ARGV[@]}")" || fail "capture-render:${label}"
  audit_line start "${label}" "${OP_TARGET}" not-run "${rendered}" || fail "capture-audit-start:${label}"
  output="$("${OP_ARGV[@]}" 2>&1)"; rc=$?
  printf '%s\n' "${output}" | /usr/bin/tee -a "${AUDIT_LOG}"
  ((PIPESTATUS[0] == 0 && PIPESTATUS[1] == 0)) || fail "capture-output:${label}"
  audit_line finish "${label}" "${OP_TARGET}" "${rc}" "${rendered}" || fail "capture-audit-finish:${label}"
  ((rc == 0)) || return "${rc}"
  set -o noclobber
  printf '%s\n' "${output}" >"${destination}"; rc=$?
  set +o noclobber
  if ((rc == 0)); then /usr/bin/chmod 0600 "${destination}"; rc=$?; fi
  audit_line capture-write "${label}" "${destination}" "${rc}" 'internal:noclobber-capture-0600' || return $?
  ((rc == 0)) || return "${rc}"
  require_root_regular "${destination}" 600
}

write_phase() {
  local path="$1" payload="$2" rc
  [[ ! -e "${path}" && ! -L "${path}" ]] || return 73
  audit_line start state-write "${path}" not-run 'internal:noclobber-phase-0600' || return $?
  set -o noclobber
  printf '%s\n' "${payload}" >"${path}"; rc=$?
  set +o noclobber
  if ((rc == 0)); then /usr/bin/chmod 0600 "${path}"; rc=$?; fi
  audit_line finish state-write "${path}" "${rc}" 'internal:noclobber-phase-0600' || return $?
  ((rc == 0)) || return "${rc}"
  require_root_regular "${path}" 600
}

render_owner() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-owner-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" \
    "netns=${INITIAL_NETNS}" "source=${SOURCE}" "commit=${COMMIT}"
}

render_baseline() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-baseline-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" \
    "netns=${INITIAL_NETNS}" 'dependency_caches=absent' 'runtime_temp=absent' \
    'veth=absent' 'address=absent' 'route=absent' \
    'neighbor=absent' 'module=absent' \
    "bpf_links_sha256=$(sha256_file "${BPF_LINK_BASELINE}")"
}

render_operation_intent() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-operation-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" \
    "source=${SOURCE}" "commit=${COMMIT}" \
    "dependency_caches=${GO_CACHE},${GO_MOD_CACHE},${GO_PATH},${GO_TMP}" \
    'dependency_producer=bounded-go-module-proxy-then-offline,mode=readonly' \
    "artifact_intent=${ARTIFACT_INTENT_PHASE}" "artifact_receipt=${ARTIFACT_PHASE}" \
    "artifacts=${BASELINE_OBJECT},${EXPERIMENTAL_OBJECT},${MODULE_OBJECT}" \
    "preflight_binary=${PREFLIGHT_BINARY}" \
    "runtime_temp=${RUNTIME_TEMP},baseline=absent,operation=create,owner=0:0,mode=0700,restore=retained" \
    "veth=${VETH_A},${VETH_B}" "address=${LOCAL_IPV4}/${PREFIX_BITS}" \
    "route=${REMOTE_IPV4}/${PREFIX_BITS},src=${LOCAL_IPV4},mtu=${ROUTE_MTU}" \
    "neighbor=${REMOTE_IPV4},lladdr=${VETH_B_MAC}" \
    "offload=${VETH_A},tso:on->off->on" "module=${MODULE_NAME}" \
    'reverse=module,offload,neighbor,route,address,veth'
}

render_dependency_intent() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-dependency-intent-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" \
    "go_cache=${GO_CACHE},owner=0:0,mode=0700,operation=create" \
    "go_mod_cache=${GO_MOD_CACHE},owner=0:0,mode=0700,operation=create" \
    "go_path=${GO_PATH},owner=0:0,mode=0700,operation=create" \
    "go_tmp=${GO_TMP},owner=0:0,mode=0700,operation=create" \
    'producer=go-mod-download-all' 'producer_proxy=https://proxy.golang.org' \
    'consumer_proxy=off' 'go_mod=readonly' 'restore=retained'
}

render_dependency_preflight() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-dependency-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "commit=${COMMIT}" \
    "binary=${PREFLIGHT_BINARY}" "binary_sha256=$(sha256_file "${PREFLIGHT_BINARY}")" \
    "go_cache=${GO_CACHE},identity=$(directory_binding "${GO_CACHE}")" \
    "go_mod_cache=${GO_MOD_CACHE},identity=$(directory_binding "${GO_MOD_CACHE}")" \
    "go_path=${GO_PATH},identity=$(directory_binding "${GO_PATH}")" \
    "go_tmp=${GO_TMP},identity=$(directory_binding "${GO_TMP}")" \
    "artifact_receipt_sha256=$(sha256_file "${ARTIFACT_PHASE}")" \
    'module_cache_produced=1' 'module_cache_verified=1' \
    'producer_proxy=https://proxy.golang.org' 'consumer_proxy=off' 'go_mod=readonly' \
    "contract_test=${PREFLIGHT_CONTRACT_TEST}:passed" \
    "tests=${NEGATIVE_TEST},${POSITIVE_TESTS[*]}"
}

source_tree() {
  "${GIT_COMMAND[@]}" -C "${SOURCE}" rev-parse --verify "${COMMIT}^{tree}"
}

makefile_blob() {
  "${GIT_COMMAND[@]}" -C "${SOURCE}" rev-parse "${COMMIT}:Makefile"
}

artifact_identity() {
  /usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%F' -- "$1"
}

load_build_input_identity() {
  local btf_identity
  [[ -f "${SOURCE}/Makefile" && ! -L "${SOURCE}/Makefile" ]] || return 79
  [[ "$(/usr/bin/readlink -e -- "${KERNEL_BUILD}")" == "${KERNEL_BUILD_CANONICAL}" ]] || return 79
  [[ "$(/usr/bin/readlink -e -- "${VMLINUX_BTF}")" == "${VMLINUX_BTF}" ]] || return 79
  btf_identity="$(artifact_identity "${VMLINUX_BTF}")" || return $?
  [[ "${btf_identity}" =~ ^[0-9]+:[0-9]+:0:0:444:1:regular\ file$ ]] || return 79
  VMLINUX_BTF_SHA256="$(sha256_file "${VMLINUX_BTF}")" || return $?
  valid_sha256 "${VMLINUX_BTF_SHA256}"
}

render_artifact_intent() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-artifact-intent-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "commit=${COMMIT}" \
    "tree=$(source_tree)" "makefile_blob=$(makefile_blob)" \
    "makefile_sha256=$(sha256_file "${SOURCE}/Makefile")" \
    "kernel_release=${EXPECTED_KERNEL_RELEASE}" "kernel_build=${KERNEL_BUILD}" \
    "kernel_build_canonical=${KERNEL_BUILD_CANONICAL}" \
    "vmlinux_btf=${VMLINUX_BTF}" "vmlinux_btf_identity=$(artifact_identity "${VMLINUX_BTF}")" \
    "vmlinux_btf_sha256=${VMLINUX_BTF_SHA256}" \
    'producer=/usr/bin/make:build-faketcp-checksum-kmod,test-bpf-object-manifests' \
    'producer_network=off' \
    "artifact_root=${ARTIFACT_ROOT}" 'artifact_root_baseline=absent' \
    "baseline_path=${BASELINE_OBJECT}" "experimental_path=${EXPERIMENTAL_OBJECT}" \
    "module_path=${MODULE_OBJECT}" 'retry=intent-only-reject'
}

load_artifact_identity() {
  local path identity status_normal status_all
  require_root_directory "${ARTIFACT_ROOT}" || return 79
  for path in "${BASELINE_OBJECT}" "${EXPERIMENTAL_OBJECT}" "${MODULE_OBJECT}"; do
    [[ -f "${path}" && ! -L "${path}" ]] || return 79
    identity="$(artifact_identity "${path}")" || return $?
    [[ "${identity}" =~ ^[0-9]+:[0-9]+:0:0:600:1:regular\ file$ ]] || return 79
  done
  BASELINE_SHA256="$(sha256_file "${BASELINE_OBJECT}")" || return $?
  EXPERIMENTAL_SHA256="$(sha256_file "${EXPERIMENTAL_OBJECT}")" || return $?
  MODULE_SHA256="$(sha256_file "${MODULE_OBJECT}")" || return $?
  valid_sha256 "${BASELINE_SHA256}" && valid_sha256 "${EXPERIMENTAL_SHA256}" &&
    valid_sha256 "${MODULE_SHA256}" || return 79
  MODULE_SRCVERSION="$(/usr/sbin/modinfo -F srcversion "${MODULE_OBJECT}")" || return $?
  MODULE_SRCVERSION="${MODULE_SRCVERSION^^}"
  [[ "${MODULE_SRCVERSION}" =~ ^[0-9A-F]{8,64}$ ]] || return 79
  MODULE_VERMAGIC="$(/usr/sbin/modinfo -F vermagic "${MODULE_OBJECT}")" || return $?
  [[ "${MODULE_VERMAGIC}" == "${EXPECTED_KERNEL_RELEASE} "* &&
    "${MODULE_VERMAGIC}" != *$'\n'* && "${MODULE_VERMAGIC}" != *$'\r'* ]] || return 79
  status_normal="$("${GIT_COMMAND[@]}" -C "${SOURCE}" status --porcelain=v1 \
    --untracked-files=normal --ignore-submodules=none)" || return $?
  status_all="$("${GIT_COMMAND[@]}" -C "${SOURCE}" status --porcelain=v1 \
    --untracked-files=all --ignore-submodules=none)" || return $?
  [[ -z "${status_normal}" && -z "${status_all}" ]]
}

render_artifact_receipt() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-artifacts-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "commit=${COMMIT}" \
    "tree=$(source_tree)" "makefile_blob=$(makefile_blob)" \
    "makefile_sha256=$(sha256_file "${SOURCE}/Makefile")" \
    "kernel_release=${EXPECTED_KERNEL_RELEASE}" "kernel_build=${KERNEL_BUILD}" \
    "kernel_build_canonical=${KERNEL_BUILD_CANONICAL}" \
    "vmlinux_btf=${VMLINUX_BTF}" "vmlinux_btf_identity=$(artifact_identity "${VMLINUX_BTF}")" \
    "vmlinux_btf_sha256=${VMLINUX_BTF_SHA256}" \
    "intent_sha256=$(sha256_file "${ARTIFACT_INTENT_PHASE}")" \
    "artifact_root=${ARTIFACT_ROOT}" \
    "artifact_root_identity=$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%F' -- "${ARTIFACT_ROOT}")" \
    "baseline_path=${BASELINE_OBJECT}" "baseline_identity=$(artifact_identity "${BASELINE_OBJECT}")" \
    "baseline_sha256=${BASELINE_SHA256}" \
    "experimental_path=${EXPERIMENTAL_OBJECT}" \
    "experimental_identity=$(artifact_identity "${EXPERIMENTAL_OBJECT}")" \
    "experimental_sha256=${EXPERIMENTAL_SHA256}" \
    "module_path=${MODULE_OBJECT}" "module_identity=$(artifact_identity "${MODULE_OBJECT}")" \
    "module_sha256=${MODULE_SHA256}" "module_srcversion=${MODULE_SRCVERSION}" \
    "module_vermagic=${MODULE_VERMAGIC}"
}

validate_artifact_receipt() {
  local expected
  load_build_input_identity || return $?
  phase_matches "${ARTIFACT_INTENT_PHASE}" "$(render_artifact_intent)" || return 79
  load_artifact_identity || return $?
  expected="$(render_artifact_receipt)" || return $?
  phase_matches "${ARTIFACT_PHASE}" "${expected}"
}

classify_artifact_retry_state() {
  local intent_present=0 receipt_present=0
  [[ ! -e "${ARTIFACT_INTENT_PHASE}" && ! -L "${ARTIFACT_INTENT_PHASE}" ]] || intent_present=1
  [[ ! -e "${ARTIFACT_PHASE}" && ! -L "${ARTIFACT_PHASE}" ]] || receipt_present=1
  if ((receipt_present)); then
    ((intent_present)) || fail 'artifact-receipt-without-intent-preflight' 79
    [[ -f "${ARTIFACT_INTENT_PHASE}" && ! -L "${ARTIFACT_INTENT_PHASE}" &&
      -f "${ARTIFACT_PHASE}" && ! -L "${ARTIFACT_PHASE}" ]] ||
      fail 'artifact-receipt-shape-preflight' 79
    validate_artifact_receipt || fail 'artifact-receipt-drift-preflight' 79
    return
  fi
  if ((intent_present)); then
    [[ -f "${ARTIFACT_INTENT_PHASE}" && ! -L "${ARTIFACT_INTENT_PHASE}" ]] ||
      fail 'artifact-intent-shape-preflight' 79
    load_build_input_identity || fail 'artifact-intent-build-input-preflight' 79
    phase_matches "${ARTIFACT_INTENT_PHASE}" "$(render_artifact_intent)" ||
      fail 'artifact-intent-drift-preflight' 79
    fail 'artifact-intent-without-receipt-preflight' 78
  fi
  [[ ! -e "${ARTIFACT_ROOT}" && ! -L "${ARTIFACT_ROOT}" ]] ||
    fail 'artifact-root-without-intent-preflight' 79
}

ensure_artifacts() {
  load_build_input_identity || fail 'artifact-build-input-identity' $?
  if [[ -e "${ARTIFACT_PHASE}" || -L "${ARTIFACT_PHASE}" ]]; then
    validate_artifact_receipt || fail 'artifact-receipt-drift' 79
    return
  fi
  [[ ! -L "${ARTIFACT_PHASE}" ]] || fail 'artifact-receipt-symlink' 79
  if [[ -e "${ARTIFACT_INTENT_PHASE}" || -L "${ARTIFACT_INTENT_PHASE}" ]]; then
    phase_matches "${ARTIFACT_INTENT_PHASE}" "$(render_artifact_intent)" ||
      fail 'artifact-intent-drift' 79
    fail 'artifact-intent-without-receipt' 78
  fi
  [[ ! -e "${ARTIFACT_ROOT}" && ! -L "${ARTIFACT_ROOT}" ]] ||
    fail 'artifact-root-preexists' 79
  write_phase "${ARTIFACT_INTENT_PHASE}" "$(render_artifact_intent)" ||
    fail 'artifact-intent-write' $?
  run_operation P.artifact-build artifact-build || fail 'artifact-build' $?
  run_operation P.artifact-mode artifact-mode || fail 'artifact-mode' $?
  load_artifact_identity || fail 'artifact-identity' $?
  write_phase "${ARTIFACT_PHASE}" "$(render_artifact_receipt)" ||
    fail 'artifact-receipt-write' $?
  validate_artifact_receipt || fail 'artifact-receipt-postwrite' $?
}

render_veth_intent() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-veth-intent-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" \
    'operation=create' 'baseline=both-names-absent' \
    "a=${VETH_A},${VETH_A_MAC},alias-empty-to-${VETH_A_ALIAS}" \
    "b=${VETH_B},${VETH_B_MAC},alias-empty-to-${VETH_B_ALIAS}" \
    'unreceipted-reconcile=exact-pair-and-empty-or-owned-alias-only'
}

render_veth() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-veth-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" \
    'ownership=create-intent' 'reuse=exact-receipt-only' \
    "a=${VETH_A},${VETH_A_IFINDEX},${VETH_A_SYSFS},${VETH_A_MAC},${VETH_A_ALIAS}" \
    "b=${VETH_B},${VETH_B_IFINDEX},${VETH_B_SYSFS},${VETH_B_MAC},${VETH_B_ALIAS}"
}

render_fixed_phase() {
  local kind="$1" detail="$2"
  printf '%s\n' "format=wg-mix-ebpf-b82-routed-${kind}-v1" \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "${detail}"
}

phase_matches() {
  local path="$1" expected="$2"
  require_root_regular "${path}" 600 || return 79
  [[ "$(/usr/bin/cat -- "${path}")" == "${expected}" ]]
}

verify_source_identity() {
  local head mapped self_blob actual_blob status line
  [[ "$EUID" == 0 ]] || fail 'root-required' 77
  [[ "$(/usr/bin/hostname)" == "${EXPECTED_HOSTNAME}" ]] || fail 'hostname' 77
  [[ "$(/usr/bin/cat /etc/machine-id)" == "${EXPECTED_MACHINE_ID}" ]] || fail 'machine-id' 77
  [[ "$(/usr/bin/uname -r)" == "${EXPECTED_KERNEL_RELEASE}" ]] || fail 'kernel-release' 77
  INITIAL_NETNS="$(/usr/bin/readlink /proc/self/ns/net)" || fail 'self-netns'
  [[ "${INITIAL_NETNS}" == "$(/usr/bin/readlink /proc/1/ns/net)" && "${INITIAL_NETNS}" == net:\[*\] ]] || fail 'initial-netns' 77
  BOOT_ID="$(/usr/bin/cat /proc/sys/kernel/random/boot_id)" || fail 'boot-id'
  [[ "${BOOT_ID}" =~ ^[0-9a-f-]{36}$ ]] || fail 'boot-id-format' 77
  require_root_directory "${STAGE_ROOT}" || fail 'stage-root-identity' 79
  [[ -d "${SOURCE}/.git" && ! -L "${SOURCE}" ]] || fail 'source-identity' 79
  head="$("${GIT_COMMAND[@]}" -C "${SOURCE}" rev-parse --verify 'HEAD^{commit}')" || fail 'source-head'
  [[ "${head}" == "${COMMIT}" ]] || fail 'source-commit' 79
  "${GIT_COMMAND[@]}" -C "${SOURCE}" diff --quiet "${COMMIT}" -- || fail 'tracked-worktree-drift' 79
  "${GIT_COMMAND[@]}" -C "${SOURCE}" diff --cached --quiet "${COMMIT}" -- || fail 'index-drift' 79
  status="$("${GIT_COMMAND[@]}" -C "${SOURCE}" status --porcelain=v1 --untracked-files=all)" || fail 'source-status'
  while IFS= read -r line; do
    [[ -z "${line}" || "${line}" == '?? build/'* ]] || fail 'untracked-source-input' 79
  done <<<"${status}"
  for relative in "${SELF_RELATIVE}" "${SEAM_RELATIVE}" "${MODULE_LEASE_HELPER_RELATIVE}" \
    "${ROUTED_CONTRACT_RELATIVE}" "${ROUTED_TEST_RELATIVE}" \
    "${NEGATIVE_TEST_RELATIVE}" "${GSO_KFUNC_RELATIVE}"; do
    mapped="$("${GIT_COMMAND[@]}" -C "${SOURCE}" rev-parse "${COMMIT}:${relative}")" || fail "mapped-blob:${relative}"
    actual_blob="$("${GIT_COMMAND[@]}" -C "${SOURCE}" hash-object -- "${SOURCE}/${relative}")" || fail "actual-blob:${relative}"
    [[ "${mapped}" == "${actual_blob}" ]] || fail "blob-drift:${relative}" 79
  done
  self_blob="$(/usr/bin/readlink -e -- "$0")" || fail 'self-canonical'
  [[ "${self_blob}" == "${SOURCE}/${SELF_RELATIVE}" ]] || fail 'self-path' 79
  for literal in \
    'AF_PACKET fixture as negative evidence only' \
    'fakeTCPRealHostStatMTUReject: 3' \
    'fakeTCPRealHostMTURouteUnknownAuditKey: 3'; do
    [[ "$(/usr/bin/grep -Fc -- "${literal}" "${SOURCE}/${NEGATIVE_TEST_RELATIVE}")" == 1 ]] || fail 'negative-source-contract' 78
  done
  for literal in \
    'if (!skb_valid_dst(skb))' \
    'if (READ_ONCE(dst->dev) != device)' \
    'route_mtu = dst_mtu(dst)'; do
    [[ "$(/usr/bin/grep -Fc -- "${literal}" "${SOURCE}/${GSO_KFUNC_RELATIVE}")" == 1 ]] || fail 'routed-pmtu-source-contract' 78
  done
}

load_checksum_module_helper() {
  # verify_source_identity binds this dynamic path to the clean committed source.
  # shellcheck disable=SC1090,SC1091
  source "${MODULE_LEASE_HELPER}" || fail 'module-lease-helper-source' $?
  [[ "${C8_CHECKSUM_MODULE_LOCK}" == "${MODULE_LEASE_LOCK}" ]] ||
    fail 'module-lease-helper-lock-contract' 79
}

configure_checksum_module_lease() {
  c8_checksum_module_configure "${RUN_ID}" "${RESOURCE_ID}" "${COMMIT}" "${BOOT_ID}" \
    "${EVIDENCE_ROOT}" "${MODULE_OBJECT}" "${MODULE_SHA256}" || fail 'module-lease-configure' $?
  [[ "${C8_CHECKSUM_MODULE_LEASE_ID}" == "${MODULE_LEASE_ID}" &&
    "${C8_CHECKSUM_MODULE_INTENT}" == "${MODULE_INTENT_PHASE}" &&
    "${C8_CHECKSUM_MODULE_OWNED}" == "${MODULE_PHASE}" &&
    "${C8_CHECKSUM_MODULE_UNLOADED}" == "${MODULE_UNLOADED_PHASE}" ]] ||
    fail 'module-lease-binding-contract' 79
}

ensure_directory() {
  local label="$1" operation="$2" path="$3" rendered rc timestamp line
  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    build_argv "${operation}" || fail "directory-builder:${operation}"
    rendered="$(quote_argv "${OP_ARGV[@]}")" || fail "directory-render:${label}"
    timestamp="$(utc_now)" || fail "directory-start-time:${label}"
    line="utc=${timestamp} event=start step=bootstrap-${label} target=${path} rc=not-run argv=${rendered}"
    BOOTSTRAP_AUDIT_LINES+=("${line}")
    printf 'B82_ROUTED_VETH_BOOTSTRAP %s\n' "${line}"
    "${OP_ARGV[@]}"; rc=$?
    timestamp="$(utc_now)" || fail "directory-finish-time:${label}"
    line="utc=${timestamp} event=finish step=bootstrap-${label} target=${path} rc=${rc} argv=${rendered}"
    BOOTSTRAP_AUDIT_LINES+=("${line}")
    printf 'B82_ROUTED_VETH_BOOTSTRAP %s\n' "${line}"
    ((rc == 0)) || fail "directory-create:${label}" "${rc}"
  fi
  require_root_directory "${path}" || fail "directory-identity:${label}" 79
}

bootstrap_evidence() {
  local rc line
  ensure_directory evidence evidence-mkdir "${EVIDENCE_ROOT}"
  if [[ ! -e "${AUDIT_LOG}" && ! -L "${AUDIT_LOG}" ]]; then
    line="utc=$(utc_now) event=start step=bootstrap-audit target=${AUDIT_LOG} rc=not-run argv=internal:noclobber-audit-0600"
    BOOTSTRAP_AUDIT_LINES+=("${line}")
    printf 'B82_ROUTED_VETH_BOOTSTRAP %s\n' "${line}"
    set -o noclobber
    : >"${AUDIT_LOG}"; rc=$?
    set +o noclobber
    if ((rc == 0)); then /usr/bin/chmod 0600 "${AUDIT_LOG}"; rc=$?; fi
    line="utc=$(utc_now) event=finish step=bootstrap-audit target=${AUDIT_LOG} rc=${rc} argv=internal:noclobber-audit-0600"
    BOOTSTRAP_AUDIT_LINES+=("${line}")
    printf 'B82_ROUTED_VETH_BOOTSTRAP %s\n' "${line}"
    ((rc == 0)) || fail 'audit-create' "${rc}"
  fi
  require_root_regular "${AUDIT_LOG}" 600 || fail 'audit-identity' 79
  if ((${#BOOTSTRAP_AUDIT_LINES[@]} > 0)); then
    printf '%s\n' "${BOOTSTRAP_AUDIT_LINES[@]}" >>"${AUDIT_LOG}" || fail 'bootstrap-audit-flush'
    BOOTSTRAP_AUDIT_LINES=()
  fi
}

ensure_owner() {
  local expected
  expected="$(render_owner)" || fail 'owner-render'
  if [[ -f "${OWNER_PHASE}" ]]; then
    phase_matches "${OWNER_PHASE}" "${expected}" || fail 'owner-drift' 79
    return
  fi
  write_phase "${OWNER_PHASE}" "${expected}" || fail 'owner-write' $?
}

require_names_absent() {
  [[ ! -e "/sys/class/net/${VETH_A}" && ! -L "/sys/class/net/${VETH_A}" &&
    ! -e "/sys/class/net/${VETH_B}" && ! -L "/sys/class/net/${VETH_B}" ]] || return 1
}

ensure_baseline() {
  local expected conflicts
  if [[ -f "${BASELINE_PHASE}" ]]; then
    expected="$(render_baseline)" || fail 'baseline-render'
    phase_matches "${BASELINE_PHASE}" "${expected}" || fail 'baseline-drift' 79
    return
  fi
  [[ ! -f "${OPERATION_PHASE}" ]] || fail 'operation-without-baseline' 79
  for path in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
    [[ ! -e "${path}" && ! -L "${path}" ]] || fail "dependency-cache-preexists:${path}" 79
  done
  [[ ! -e "${PREFLIGHT_BINARY}" && ! -L "${PREFLIGHT_BINARY}" ]] || fail 'preflight-binary-preexists' 79
  [[ ! -e "${RUNTIME_TEMP}" && ! -L "${RUNTIME_TEMP}" ]] || fail 'runtime-temp-preexists' 79
  require_names_absent || fail 'veth-name-preexists' 79
  [[ ! -d "/sys/module/${MODULE_NAME}" ]] || fail 'module-preexists' 79
  conflicts="$(/usr/sbin/ip -4 -j address show to "${LOCAL_IPV4}/${PREFIX_BITS}")" || fail 'address-conflict-probe'
  [[ "${conflicts}" == '[]' ]] || fail 'address-conflict' 79
  conflicts="$(/usr/sbin/ip -4 -j route show table all exact "${REMOTE_IPV4}/${PREFIX_BITS}")" || fail 'route-conflict-probe'
  [[ "${conflicts}" == '[]' ]] || fail 'route-conflict' 79
  capture_operation A.bpf bpf-links "${BPF_LINK_BASELINE}" || fail 'bpf-baseline-capture' $?
  expected="$(render_baseline)" || fail 'baseline-render'
  write_phase "${BASELINE_PHASE}" "${expected}" || fail 'baseline-write' $?
}

ensure_operation_intent() {
  local expected
  expected="$(render_operation_intent)" || fail 'operation-render'
  if [[ -f "${OPERATION_PHASE}" ]]; then
    phase_matches "${OPERATION_PHASE}" "${expected}" || fail 'operation-drift' 79
    return
  fi
  write_phase "${OPERATION_PHASE}" "${expected}" || fail 'operation-write' $?
}

ensure_dependency_directory() {
  local label="$1" operation="$2" path="$3"
  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    run_operation "${label}" "${operation}" || fail "dependency-directory-create:${label}" $?
  fi
  require_root_directory "${path}" || fail "dependency-directory-identity:${label}" 79
}

ensure_dependency_intent() {
  local expected path
  expected="$(render_dependency_intent)" || fail 'dependency-intent-render'
  if [[ -f "${DEPENDENCY_INTENT_PHASE}" ]]; then
    phase_matches "${DEPENDENCY_INTENT_PHASE}" "${expected}" || fail 'dependency-intent-drift' 79
    return
  fi
  for path in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
    [[ ! -e "${path}" && ! -L "${path}" ]] || fail "dependency-cache-without-intent:${path}" 79
  done
  [[ ! -e "${PREFLIGHT_BINARY}" && ! -L "${PREFLIGHT_BINARY}" ]] || fail 'preflight-binary-without-intent' 79
  write_phase "${DEPENDENCY_INTENT_PHASE}" "${expected}" || fail 'dependency-intent-write' $?
}

ensure_dependency_preflight() {
  local name expected output
  if [[ -f "${DEPENDENCY_PHASE}" ]]; then
    validate_dependency_preflight || fail 'preflight-phase-drift' 79
    return
  fi
  ensure_dependency_intent
  ensure_dependency_directory C0 go-cache-mkdir "${GO_CACHE}"
  ensure_dependency_directory C1 go-mod-cache-mkdir "${GO_MOD_CACHE}"
  ensure_dependency_directory C2 go-path-mkdir "${GO_PATH}"
  ensure_dependency_directory C3 go-tmp-mkdir "${GO_TMP}"
  run_operation P0 preflight-mod-download || fail 'dependency-module-download' $?
  run_operation P1 preflight-mod-verify || fail 'dependency-module-verification' $?
  ensure_artifacts
  if [[ ! -e "${PREFLIGHT_BINARY}" && ! -L "${PREFLIGHT_BINARY}" ]]; then
    run_operation P2 preflight-build || fail 'dependency-build-preflight' $?
  fi
  require_root_test_binary "${PREFLIGHT_BINARY}" || fail 'preflight-binary-identity' 79
  for name in "${PREFLIGHT_CONTRACT_TEST}" "${NEGATIVE_TEST}" "${POSITIVE_TESTS[@]}"; do
    output="$(run_operation "P.${name}" "list:${name}")" || fail "dependency-test-list:${name}" $?
    [[ "$(printf '%s\n' "${output}" | /usr/bin/grep -Fxc -- "${name}")" == 1 ]] || fail "dependency-test-definition:${name}" 79
  done
  run_operation P.contract preflight-contract || fail 'dependency-contract-preflight' $?
  expected="$(render_dependency_preflight)" || fail 'preflight-render'
  write_phase "${DEPENDENCY_PHASE}" "${expected}" || fail 'preflight-phase-write' $?
}

ensure_runtime_temp() {
  if [[ ! -e "${RUNTIME_TEMP}" && ! -L "${RUNTIME_TEMP}" ]]; then
    run_operation B1 runtime-temp-mkdir || fail 'runtime-temp-create' $?
  fi
  require_root_directory "${RUNTIME_TEMP}" || fail 'runtime-temp-identity' 79
}

validate_dependency_preflight() {
  local expected
  phase_matches "${DEPENDENCY_INTENT_PHASE}" "$(render_dependency_intent)" || return 79
  validate_artifact_receipt || return $?
  for path in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
    require_root_directory "${path}" || return 79
  done
  require_root_test_binary "${PREFLIGHT_BINARY}" || return 79
  expected="$(render_dependency_preflight)" || return $?
  phase_matches "${DEPENDENCY_PHASE}" "${expected}"
}

ensure_veth_intent() {
  local expected
  expected="$(render_veth_intent)" || fail 'veth-intent-render'
  if [[ -f "${VETH_INTENT_PHASE}" ]]; then
    phase_matches "${VETH_INTENT_PHASE}" "${expected}" || fail 'veth-intent-drift' 79
    return
  fi
  require_names_absent || fail 'veth-name-appeared-before-intent' 79
  write_phase "${VETH_INTENT_PHASE}" "${expected}" || fail 'veth-intent-write' $?
}

sysfs_identity() {
  local name="$1" target
  target="$(/usr/bin/readlink -e -- "/sys/class/net/${name}")" || return $?
  [[ "${target}" == /sys/devices/* ]] || return 79
  /usr/bin/stat -Lc '%d:%i' -- "${target}"
}

read_veth_receipt() {
  local format run resource ownership reuse a b extra
  require_root_regular "${VETH_PHASE}" 600 || return 79
  {
    IFS='=' read -r _ format
    IFS='=' read -r _ run
    IFS='=' read -r _ resource
    IFS='=' read -r _ ownership
    IFS='=' read -r _ reuse
    IFS='=' read -r _ a
    IFS='=' read -r _ b
    IFS= read -r extra
  } <"${VETH_PHASE}"
  [[ "${format}" == 'wg-mix-ebpf-b82-routed-veth-v1' && "${run}" == "${RUN_ID}" &&
    "${resource}" == "${RESOURCE_ID}" && "${ownership}" == 'create-intent' &&
    "${reuse}" == 'exact-receipt-only' && -z "${extra}" ]] || return 79
  IFS=',' read -r name VETH_A_IFINDEX VETH_A_SYSFS mac alias <<<"${a}"
  [[ "${name}" == "${VETH_A}" && "${mac}" == "${VETH_A_MAC}" && "${alias}" == "${VETH_A_ALIAS}" ]] || return 79
  IFS=',' read -r name VETH_B_IFINDEX VETH_B_SYSFS mac alias <<<"${b}"
  [[ "${name}" == "${VETH_B}" && "${mac}" == "${VETH_B_MAC}" && "${alias}" == "${VETH_B_ALIAS}" ]] || return 79
  [[ "${VETH_A_IFINDEX}" =~ ^[1-9][0-9]*$ && "${VETH_B_IFINDEX}" =~ ^[1-9][0-9]*$ &&
    "${VETH_A_IFINDEX}" != "${VETH_B_IFINDEX}" && "${VETH_A_SYSFS}" =~ ^[0-9]+:[0-9]+$ &&
    "${VETH_B_SYSFS}" =~ ^[0-9]+:[0-9]+$ ]]
}

unreceipted_veth_pair_matches() {
  local a_if b_if a_alias b_alias expected
  expected="$(render_veth_intent)" || return $?
  phase_matches "${VETH_INTENT_PHASE}" "${expected}" || return 79
  [[ -d "/sys/class/net/${VETH_A}" && -d "/sys/class/net/${VETH_B}" ]] || return 1
  a_if="$(/usr/bin/cat "/sys/class/net/${VETH_A}/ifindex")" || return $?
  b_if="$(/usr/bin/cat "/sys/class/net/${VETH_B}/ifindex")" || return $?
  a_alias="$(/usr/bin/cat "/sys/class/net/${VETH_A}/ifalias")" || return $?
  b_alias="$(/usr/bin/cat "/sys/class/net/${VETH_B}/ifalias")" || return $?
  [[ "$(/usr/bin/cat "/sys/class/net/${VETH_A}/iflink")" == "${b_if}" &&
    "$(/usr/bin/cat "/sys/class/net/${VETH_B}/iflink")" == "${a_if}" &&
    "$(/usr/bin/cat "/sys/class/net/${VETH_A}/address")" == "${VETH_A_MAC}" &&
    "$(/usr/bin/cat "/sys/class/net/${VETH_B}/address")" == "${VETH_B_MAC}" ]] || return 79
  [[ -z "${a_alias}" || "${a_alias}" == "${VETH_A_ALIAS}" ]] || return 78
  [[ -z "${b_alias}" || "${b_alias}" == "${VETH_B_ALIAS}" ]] || return 78
}

claim_veth_alias() {
  local label="$1" operation="$2" name="$3" expected="$4" current
  current="$(/usr/bin/cat "/sys/class/net/${name}/ifalias")" || fail "${label}-read"
  if [[ -z "${current}" ]]; then
    run_operation "${label}" "${operation}" || fail "${label}-set" $?
  elif [[ "${current}" != "${expected}" ]]; then
    fail "${label}-foreign" 79
  fi
  [[ "$(/usr/bin/cat "/sys/class/net/${name}/ifalias")" == "${expected}" ]] || fail "${label}-postcondition" 79
}

verify_veth_pair() {
  local a_if b_if a_link b_link
  [[ -d "/sys/class/net/${VETH_A}" && -d "/sys/class/net/${VETH_B}" ]] || return 1
  a_if="$(/usr/bin/cat "/sys/class/net/${VETH_A}/ifindex")" || return $?
  b_if="$(/usr/bin/cat "/sys/class/net/${VETH_B}/ifindex")" || return $?
  a_link="$(/usr/bin/cat "/sys/class/net/${VETH_A}/iflink")" || return $?
  b_link="$(/usr/bin/cat "/sys/class/net/${VETH_B}/iflink")" || return $?
  [[ "${a_link}" == "${b_if}" && "${b_link}" == "${a_if}" &&
    "$(/usr/bin/cat "/sys/class/net/${VETH_A}/address")" == "${VETH_A_MAC}" &&
    "$(/usr/bin/cat "/sys/class/net/${VETH_B}/address")" == "${VETH_B_MAC}" &&
    "$(/usr/bin/cat "/sys/class/net/${VETH_A}/ifalias")" == "${VETH_A_ALIAS}" &&
    "$(/usr/bin/cat "/sys/class/net/${VETH_B}/ifalias")" == "${VETH_B_ALIAS}" ]] || return 1
  if [[ -n "${VETH_A_IFINDEX}" ]]; then
    [[ "${a_if}" == "${VETH_A_IFINDEX}" && "${b_if}" == "${VETH_B_IFINDEX}" &&
      "$(sysfs_identity "${VETH_A}")" == "${VETH_A_SYSFS}" &&
      "$(sysfs_identity "${VETH_B}")" == "${VETH_B_SYSFS}" ]] || return 1
  fi
  /usr/sbin/ip -j link show dev "${VETH_A}" | /usr/bin/jq -e 'length == 1 and (.[0].flags | index("UP")) != null' >/dev/stdout || return $?
  /usr/sbin/ip -j link show dev "${VETH_B}" | /usr/bin/jq -e 'length == 1 and (.[0].flags | index("UP")) != null' >/dev/stdout
}

ensure_veth_phase() {
  local expected current_a current_b
  if [[ -f "${VETH_PHASE}" ]]; then
    ensure_veth_intent
    read_veth_receipt || fail 'veth-receipt' 79
    verify_veth_pair || fail 'veth-identity' 79
    expected="$(render_veth)" || fail 'veth-render'
    phase_matches "${VETH_PHASE}" "${expected}" || fail 'veth-phase-drift' 79
    return
  fi
  ensure_veth_intent
  if require_names_absent; then
    run_operation N0 veth-add || fail 'veth-add' $?
  fi
  unreceipted_veth_pair_matches || fail 'unreceipted-veth-identity-or-foreign-alias' $?
  current_a="$(/usr/bin/cat "/sys/class/net/${VETH_A}/ifindex")" || fail 'veth-a-ifindex'
  current_b="$(/usr/bin/cat "/sys/class/net/${VETH_B}/ifindex")" || fail 'veth-b-ifindex'
  claim_veth_alias N1 veth-alias-a "${VETH_A}" "${VETH_A_ALIAS}"
  claim_veth_alias N2 veth-alias-b "${VETH_B}" "${VETH_B_ALIAS}"
  /usr/sbin/ip -j link show dev "${VETH_A}" | /usr/bin/jq -e '.[0].flags | index("UP") != null' >/dev/stdout
  if ((PIPESTATUS[0] != 0 || PIPESTATUS[1] != 0)); then run_operation N3 veth-up-a || fail 'veth-up-a' $?; fi
  /usr/sbin/ip -j link show dev "${VETH_B}" | /usr/bin/jq -e '.[0].flags | index("UP") != null' >/dev/stdout
  if ((PIPESTATUS[0] != 0 || PIPESTATUS[1] != 0)); then run_operation N4 veth-up-b || fail 'veth-up-b' $?; fi
  VETH_A_IFINDEX="${current_a}"; VETH_B_IFINDEX="${current_b}"
  VETH_A_SYSFS="$(sysfs_identity "${VETH_A}")" || fail 'veth-a-sysfs'
  VETH_B_SYSFS="$(sysfs_identity "${VETH_B}")" || fail 'veth-b-sysfs'
  verify_veth_pair || fail 'veth-postcondition' 79
  expected="$(render_veth)" || fail 'veth-render'
  write_phase "${VETH_PHASE}" "${expected}" || fail 'veth-phase-write' $?
}

address_matches() {
  /usr/sbin/ip -4 -j address show dev "${VETH_A}" | /usr/bin/jq -e \
    --arg local "${LOCAL_IPV4}" --argjson prefix "${PREFIX_BITS}" \
    'length == 1 and ([.[0].addr_info[] | select(.family == "inet")] | length) == 1 and .[0].addr_info[0].local == $local and .[0].addr_info[0].prefixlen == $prefix and .[0].addr_info[0].scope == "global"' >/dev/stdout
}

ensure_address_phase() {
  local expected existing
  expected="$(render_fixed_phase address "address=${LOCAL_IPV4}/${PREFIX_BITS},ifindex=${VETH_A_IFINDEX}")" || fail 'address-render'
  if [[ -f "${ADDRESS_PHASE}" ]]; then
    phase_matches "${ADDRESS_PHASE}" "${expected}" || fail 'address-phase-drift' 79
    address_matches || fail 'address-identity' 79
    return
  fi
  existing="$(/usr/sbin/ip -4 -j address show dev "${VETH_A}")" || fail 'address-probe'
  if [[ "${existing}" == *'"family":"inet"'* ]]; then
    address_matches || fail 'address-unreceipted-drift' 79
  else
    run_operation N5 address-add || fail 'address-add' $?
    address_matches || fail 'address-postcondition' 79
  fi
  write_phase "${ADDRESS_PHASE}" "${expected}" || fail 'address-phase-write' $?
}

route_matches() {
  /usr/sbin/ip -4 -j route show table main exact "${REMOTE_IPV4}/${PREFIX_BITS}" | /usr/bin/jq -e \
    --arg dst "${REMOTE_IPV4}/${PREFIX_BITS}" --arg dev "${VETH_A}" \
    --arg src "${LOCAL_IPV4}" --argjson mtu "${ROUTE_MTU}" \
    'length == 1 and .[0].dst == $dst and .[0].dev == $dev and .[0].prefsrc == $src and .[0].protocol == "static" and .[0].scope == "link" and .[0].metrics.mtu == $mtu' >/dev/stdout
}

ensure_route_phase() {
  local expected existing
  expected="$(render_fixed_phase route "route=${REMOTE_IPV4}/${PREFIX_BITS},ifindex=${VETH_A_IFINDEX},src=${LOCAL_IPV4},mtu=${ROUTE_MTU},proto=static,scope=link")" || fail 'route-render'
  if [[ -f "${ROUTE_PHASE}" ]]; then
    phase_matches "${ROUTE_PHASE}" "${expected}" || fail 'route-phase-drift' 79
    route_matches || fail 'route-identity' 79
    return
  fi
  existing="$(/usr/sbin/ip -4 -j route show table main exact "${REMOTE_IPV4}/${PREFIX_BITS}")" || fail 'route-probe'
  if [[ "${existing}" != '[]' ]]; then route_matches || fail 'route-unreceipted-drift' 79
  else run_operation N6 route-add || fail 'route-add' $?; route_matches || fail 'route-postcondition' 79; fi
  write_phase "${ROUTE_PHASE}" "${expected}" || fail 'route-phase-write' $?
}

neighbor_matches() {
  /usr/sbin/ip -4 -j neigh show to "${REMOTE_IPV4}" dev "${VETH_A}" | /usr/bin/jq -e \
    --arg dst "${REMOTE_IPV4}" --arg dev "${VETH_A}" --arg lladdr "${VETH_B_MAC}" \
    'length == 1 and .[0].dst == $dst and .[0].dev == $dev and .[0].lladdr == $lladdr and .[0].state == ["PERMANENT"]' >/dev/stdout
}

ensure_neighbor_phase() {
  local expected existing
  expected="$(render_fixed_phase neighbor "neighbor=${REMOTE_IPV4},ifindex=${VETH_A_IFINDEX},lladdr=${VETH_B_MAC},state=PERMANENT")" || fail 'neighbor-render'
  if [[ -f "${NEIGHBOR_PHASE}" ]]; then
    phase_matches "${NEIGHBOR_PHASE}" "${expected}" || fail 'neighbor-phase-drift' 79
    neighbor_matches || fail 'neighbor-identity' 79
    return
  fi
  existing="$(/usr/sbin/ip -4 -j neigh show to "${REMOTE_IPV4}" dev "${VETH_A}")" || fail 'neighbor-probe'
  if [[ "${existing}" != '[]' ]]; then neighbor_matches || fail 'neighbor-unreceipted-drift' 79
  else run_operation N7 neighbor-add || fail 'neighbor-add' $?; neighbor_matches || fail 'neighbor-postcondition' 79; fi
  write_phase "${NEIGHBOR_PHASE}" "${expected}" || fail 'neighbor-phase-write' $?
}

feature_file_is_exact() {
  local path="$1" feature="$2" state="$3"
  [[ "$(/usr/bin/grep -Fxc -- "${feature}: ${state}" "${path}")" == 1 ]]
}

feature_text_is_exact() {
  local payload="$1" feature="$2" state="$3"
  [[ "$(printf '%s\n' "${payload}" | /usr/bin/grep -Fxc -- "${feature}: ${state}")" == 1 ]]
}

offload_live_matches_desired() {
  local live
  live="$(run_operation N8.live offload-show-a)" || return $?
  feature_text_is_exact "${live}" 'tcp-segmentation-offload' off &&
    feature_text_is_exact "${live}" 'tx-checksumming' on &&
    feature_text_is_exact "${live}" 'tx-udp-segmentation' on
}

ensure_offload_phase() {
  local expected baseline_sha live
  if [[ ! -f "${OFFLOAD_BASELINE_A}" ]]; then
    capture_operation N8.baseline offload-show-a "${OFFLOAD_BASELINE_A}" || fail 'offload-baseline-capture' $?
  fi
  require_root_regular "${OFFLOAD_BASELINE_A}" 600 || fail 'offload-baseline-identity' 79
  feature_file_is_exact "${OFFLOAD_BASELINE_A}" 'tcp-segmentation-offload' on || fail 'offload-baseline-tso' 78
  feature_file_is_exact "${OFFLOAD_BASELINE_A}" 'tx-checksumming' on || fail 'offload-baseline-checksum' 78
  feature_file_is_exact "${OFFLOAD_BASELINE_A}" 'tx-udp-segmentation' on || fail 'offload-baseline-udp-segment' 78
  baseline_sha="$(sha256_file "${OFFLOAD_BASELINE_A}")" || fail 'offload-baseline-sha'
  expected="$(render_fixed_phase offload "ifindex=${VETH_A_IFINDEX},baseline_sha256=${baseline_sha},tso=off,tx-checksumming=on,tx-udp-segmentation=on")" || fail 'offload-render'
  if [[ -f "${OFFLOAD_PHASE}" ]]; then
    phase_matches "${OFFLOAD_PHASE}" "${expected}" || fail 'offload-phase-drift' 79
    offload_live_matches_desired || fail 'offload-identity' 79
    return
  fi
  if ! offload_live_matches_desired; then
    live="$(run_operation N8.before offload-show-a)" || fail 'offload-live-read' $?
    [[ "${live}" == "$(/usr/bin/cat -- "${OFFLOAD_BASELINE_A}")" ]] || fail 'offload-unreceipted-drift' 79
    run_operation N9 offload-tso-off || fail 'offload-tso-off' $?
    offload_live_matches_desired || fail 'offload-postcondition' 79
  fi
  write_phase "${OFFLOAD_PHASE}" "${expected}" || fail 'offload-phase-write' $?
}

ensure_module_phase() {
  c8_checksum_module_load M0 || fail 'module-lease-load' $?
}

render_tested() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-tested-v1' "run_id=${RUN_ID}" \
    "resource_id=${RESOURCE_ID}" \
    "negative=${NEGATIVE_TEST}:route-unknown-none,partial,gso" \
    "positive=${POSITIVE_TESTS[*]}" 'result=passed'
}

run_tests() {
  local name expected
  expected="$(render_tested)" || fail 'tested-render'
  if [[ -f "${TESTED_PHASE}" ]]; then
    phase_matches "${TESTED_PHASE}" "${expected}" || fail 'tested-phase-drift' 79
    return
  fi
  for name in "${NEGATIVE_TEST}" "${POSITIVE_TESTS[@]}"; do
    run_operation "T.${name}" "test:${name}" || fail "test-run:${name}" $?
  done
  write_phase "${TESTED_PHASE}" "${expected}" || fail 'tested-phase-write' $?
}

assert_bpf_links_baseline() {
  local live
  live="$(run_operation R.bpf bpf-links)" || fail 'bpf-live-read' $?
  [[ "${live}" == "$(/usr/bin/cat -- "${BPF_LINK_BASELINE}")" ]] || fail 'bpf-link-drift' 79
}

render_cleanup_intent() {
  local owner baseline operation dependency_intent artifact_intent artifacts dependency
  local veth_intent veth address route
  local go_cache go_mod_cache go_path go_tmp runtime_temp neighbor offload_baseline offload
  local module_intent module tested
  owner="$(sha256_file "${OWNER_PHASE}")" || return $?
  baseline="$(sha256_file "${BASELINE_PHASE}")" || return $?
  operation="$(sha256_file "${OPERATION_PHASE}")" || return $?
  dependency_intent="$(phase_binding "${DEPENDENCY_INTENT_PHASE}")" || return $?
  artifact_intent="$(phase_binding "${ARTIFACT_INTENT_PHASE}")" || return $?
  artifacts="$(phase_binding "${ARTIFACT_PHASE}")" || return $?
  dependency="$(phase_binding "${DEPENDENCY_PHASE}")" || return $?
  go_cache="$(directory_binding "${GO_CACHE}")" || return $?
  go_mod_cache="$(directory_binding "${GO_MOD_CACHE}")" || return $?
  go_path="$(directory_binding "${GO_PATH}")" || return $?
  go_tmp="$(directory_binding "${GO_TMP}")" || return $?
  runtime_temp="$(directory_binding "${RUNTIME_TEMP}")" || return $?
  veth_intent="$(phase_binding "${VETH_INTENT_PHASE}")" || return $?
  veth="$(phase_binding "${VETH_PHASE}")" || return $?
  address="$(phase_binding "${ADDRESS_PHASE}")" || return $?
  route="$(phase_binding "${ROUTE_PHASE}")" || return $?
  neighbor="$(phase_binding "${NEIGHBOR_PHASE}")" || return $?
  offload_baseline="$(phase_binding "${OFFLOAD_BASELINE_A}")" || return $?
  offload="$(phase_binding "${OFFLOAD_PHASE}")" || return $?
  module_intent="$(phase_binding "${MODULE_INTENT_PHASE}")" || return $?
  module="$(phase_binding "${MODULE_PHASE}")" || return $?
  tested="$(phase_binding "${TESTED_PHASE}")" || return $?
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-cleanup-v1' "run_id=${RUN_ID}" \
    "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" "netns=${INITIAL_NETNS}" \
    "owner_sha256=${owner}" "baseline_sha256=${baseline}" \
    "operation_sha256=${operation}" "dependency_intent=${dependency_intent}" \
    "artifact_intent=${artifact_intent}" "artifacts=${artifacts}" "dependency=${dependency}" \
    "dependency_caches=${go_cache},${go_mod_cache},${go_path},${go_tmp}" \
    "runtime_temp=${runtime_temp}" \
    "veth_intent=${veth_intent}" "veth=${veth}" "address=${address}" \
    "route=${route}" "neighbor=${neighbor}" \
    "offload_baseline=${offload_baseline}" "offload=${offload}" \
    "module_intent=${module_intent}" "module=${module}" "tested=${tested}" \
    'reverse=module,offload,neighbor,route,address,veth'
}

directory_binding() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    require_root_directory "${path}" || return 79
    /usr/bin/stat -Lc '%d:%i' -- "${path}"
    return
  fi
  printf 'absent\n'
}

phase_binding() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    require_root_regular "${path}" 600 || return 79
    sha256_file "${path}"
    return
  fi
  printf 'absent\n'
}

ensure_cleanup_intent() {
  local expected
  expected="$(render_cleanup_intent)" || fail 'cleanup-render'
  if [[ -f "${CLEANUP_PHASE}" ]]; then
    phase_matches "${CLEANUP_PHASE}" "${expected}" || fail 'cleanup-intent-drift' 79
    return
  fi
  write_phase "${CLEANUP_PHASE}" "${expected}" || fail 'cleanup-intent-write' $?
}

restore_module() {
  c8_checksum_module_restore R1 || fail 'module-lease-restore' $?
}

restore_offload() {
  local live
  [[ -d "/sys/class/net/${VETH_A}" ]] || return
  [[ -f "${OFFLOAD_BASELINE_A}" ]] || return
  require_root_regular "${OFFLOAD_BASELINE_A}" 600 || fail 'restore-offload-baseline' 79
  if offload_live_matches_desired; then
    run_operation R2 offload-tso-restore || fail 'offload-tso-restore' $?
  fi
  live="$(run_operation R2.verify offload-show-a)" || fail 'offload-restored-read' $?
  [[ "${live}" == "$(/usr/bin/cat -- "${OFFLOAD_BASELINE_A}")" ]] || fail 'offload-restore-drift' 79
}

restore_network() {
  local existing
  if require_names_absent; then return; fi
  existing="$(/usr/sbin/ip -4 -j neigh show to "${REMOTE_IPV4}" dev "${VETH_A}")" || fail 'restore-neighbor-probe'
  if [[ "${existing}" != '[]' ]]; then
    neighbor_matches || fail 'restore-neighbor-foreign' 79
    run_operation R3 neighbor-delete || fail 'neighbor-delete' $?
  fi
  [[ "$(/usr/sbin/ip -4 -j neigh show to "${REMOTE_IPV4}" dev "${VETH_A}")" == '[]' ]] || fail 'neighbor-remains' 79
  existing="$(/usr/sbin/ip -4 -j route show table main exact "${REMOTE_IPV4}/${PREFIX_BITS}")" || fail 'restore-route-probe'
  if [[ "${existing}" != '[]' ]]; then
    route_matches || fail 'restore-route-foreign' 79
    run_operation R4 route-delete || fail 'route-delete' $?
  fi
  [[ "$(/usr/sbin/ip -4 -j route show table main exact "${REMOTE_IPV4}/${PREFIX_BITS}")" == '[]' ]] || fail 'route-remains' 79
  existing="$(/usr/sbin/ip -4 -j address show dev "${VETH_A}")" || fail 'restore-address-probe'
  if [[ "${existing}" == *'"family":"inet"'* ]]; then
    address_matches || fail 'restore-address-foreign' 79
    run_operation R5 address-delete || fail 'address-delete' $?
  fi
  [[ "$(/usr/sbin/ip -4 -j address show dev "${VETH_A}")" != *'"family":"inet"'* ]] || fail 'address-remains' 79
  if [[ -f "${VETH_PHASE}" ]]; then
    verify_veth_pair || fail 'pre-delete-veth-identity' 79
  else
    unreceipted_veth_pair_matches || fail 'pre-delete-owned-cut-identity' 79
  fi
  run_operation R6 veth-delete || fail 'veth-delete' $?
  require_names_absent || fail 'veth-remains' 79
}

first_missing_receipt() {
  local spec label path
  for spec in \
    "veth|${VETH_PHASE}" "address|${ADDRESS_PHASE}" "route|${ROUTE_PHASE}" \
    "neighbor|${NEIGHBOR_PHASE}" "offload|${OFFLOAD_PHASE}" "module|${MODULE_PHASE}"; do
    IFS='|' read -r label path <<<"${spec}"
    if [[ ! -e "${path}" && ! -L "${path}" ]]; then
      printf '%s\n' "${label}"
      return
    fi
    require_root_regular "${path}" 600 || return 79
  done
  printf 'none\n'
}

validate_receipt_prefix() {
  local spec path missing=0
  for spec in "${VETH_PHASE}" "${ADDRESS_PHASE}" "${ROUTE_PHASE}" \
    "${NEIGHBOR_PHASE}" "${OFFLOAD_PHASE}" "${MODULE_PHASE}"; do
    path="${spec}"
    if [[ -e "${path}" || -L "${path}" ]]; then
      ((missing == 0)) || return 79
      require_root_regular "${path}" 600 || return 79
    else
      missing=1
    fi
  done
  if [[ -e "${TESTED_PHASE}" || -L "${TESTED_PHASE}" ]]; then
    ((missing == 0)) || return 79
    phase_matches "${TESTED_PHASE}" "$(render_tested)" || return 79
  fi
}

validate_runtime_temp_for_restore() {
  if [[ -e "${RUNTIME_TEMP}" || -L "${RUNTIME_TEMP}" ]]; then
    require_root_directory "${RUNTIME_TEMP}" || fail 'restore-runtime-temp-identity' 79
    return
  fi
  [[ ! -f "${VETH_INTENT_PHASE}" ]] || fail 'restore-runtime-temp-missing-after-veth-intent' 79
}

validate_artifact_state_for_restore() {
  local path identity
  ARTIFACT_STATE=''
  if [[ -e "${ARTIFACT_PHASE}" || -L "${ARTIFACT_PHASE}" ]]; then
    [[ -e "${ARTIFACT_INTENT_PHASE}" || -L "${ARTIFACT_INTENT_PHASE}" ]] ||
      fail 'restore-artifact-receipt-without-intent' 79
    validate_artifact_receipt || fail 'restore-artifact-receipt' 79
    ARTIFACT_STATE='receipt'
    return
  fi
  [[ ! -L "${ARTIFACT_PHASE}" ]] || fail 'restore-artifact-receipt-symlink' 79
  if [[ -e "${ARTIFACT_INTENT_PHASE}" || -L "${ARTIFACT_INTENT_PHASE}" ]]; then
    load_build_input_identity || fail 'restore-artifact-build-input' $?
    phase_matches "${ARTIFACT_INTENT_PHASE}" "$(render_artifact_intent)" ||
      fail 'restore-artifact-intent' 79
    if [[ -e "${ARTIFACT_ROOT}" || -L "${ARTIFACT_ROOT}" ]]; then
      require_root_directory "${ARTIFACT_ROOT}" || fail 'restore-partial-artifact-root' 79
    fi
    for path in "${BASELINE_OBJECT}" "${EXPERIMENTAL_OBJECT}" "${MODULE_OBJECT}"; do
      if [[ -e "${path}" || -L "${path}" ]]; then
        [[ -f "${path}" && ! -L "${path}" ]] || fail "restore-partial-artifact-shape:${path}" 79
        identity="$(artifact_identity "${path}")" || fail "restore-partial-artifact-stat:${path}"
        [[ "${identity}" =~ ^[0-9]+:[0-9]+:0:0:(600|644):1:regular\ file$ ]] ||
          fail "restore-partial-artifact-identity:${path}" 79
      fi
    done
    ARTIFACT_STATE='intent'
    return
  fi
  [[ ! -L "${ARTIFACT_INTENT_PHASE}" ]] || fail 'restore-artifact-intent-symlink' 79
  [[ ! -e "${ARTIFACT_ROOT}" && ! -L "${ARTIFACT_ROOT}" ]] ||
    fail 'restore-artifact-root-without-intent' 79
  ARTIFACT_STATE='absent'
}

validate_dependency_caches_for_restore() {
  local path
  validate_artifact_state_for_restore
  if [[ ! -e "${DEPENDENCY_INTENT_PHASE}" && ! -L "${DEPENDENCY_INTENT_PHASE}" ]]; then
    [[ "${ARTIFACT_STATE}" == absent ]] || fail 'restore-artifact-without-dependency-intent' 79
    for path in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
      [[ ! -e "${path}" && ! -L "${path}" ]] || fail "restore-dependency-cache-without-intent:${path}" 79
    done
    [[ ! -e "${PREFLIGHT_BINARY}" && ! -L "${PREFLIGHT_BINARY}" ]] || fail 'restore-preflight-binary-without-intent' 79
    return
  fi
  phase_matches "${DEPENDENCY_INTENT_PHASE}" "$(render_dependency_intent)" || fail 'restore-dependency-intent' 79
  for path in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
    if [[ -e "${path}" || -L "${path}" ]]; then
      require_root_directory "${path}" || fail "restore-dependency-cache-identity:${path}" 79
    fi
  done
  if [[ -e "${DEPENDENCY_PHASE}" || -L "${DEPENDENCY_PHASE}" ]]; then
    [[ "${ARTIFACT_STATE}" == receipt ]] || fail 'restore-dependency-receipt-without-artifacts' 79
    validate_dependency_preflight || fail 'restore-dependency-preflight' 79
  elif [[ "${ARTIFACT_STATE}" != receipt ]]; then
    [[ ! -e "${PREFLIGHT_BINARY}" && ! -L "${PREFLIGHT_BINARY}" ]] ||
      fail 'restore-preflight-binary-before-artifact-receipt' 79
  elif [[ -e "${PREFLIGHT_BINARY}" || -L "${PREFLIGHT_BINARY}" ]]; then
    require_root_test_binary "${PREFLIGHT_BINARY}" || fail 'restore-partial-preflight-binary' 79
  fi
}

validate_no_live_before_artifact_receipt() {
  local path existing
  for path in "${RUNTIME_TEMP}" "${PREFLIGHT_BINARY}" "${VETH_INTENT_PHASE}" \
    "${VETH_PHASE}" "${ADDRESS_PHASE}" "${ROUTE_PHASE}" "${NEIGHBOR_PHASE}" \
    "${OFFLOAD_BASELINE_A}" "${OFFLOAD_PHASE}" "${MODULE_INTENT_PHASE}" \
    "${MODULE_PHASE}" "${MODULE_UNLOADED_PHASE}" "${TESTED_PHASE}"; do
    [[ ! -e "${path}" && ! -L "${path}" ]] ||
      fail "restore-live-state-before-artifact-receipt:${path}" 79
  done
  require_names_absent || fail 'restore-veth-before-artifact-receipt' 79
  existing="$(/usr/sbin/ip -4 -j address show to "${LOCAL_IPV4}/${PREFIX_BITS}")" ||
    fail 'restore-address-before-artifact-receipt-probe'
  [[ "${existing}" == '[]' ]] || fail 'restore-address-before-artifact-receipt' 79
  existing="$(/usr/sbin/ip -4 -j route show table all exact "${REMOTE_IPV4}/${PREFIX_BITS}")" ||
    fail 'restore-route-before-artifact-receipt-probe'
  [[ "${existing}" == '[]' ]] || fail 'restore-route-before-artifact-receipt' 79
  [[ ! -d "/sys/module/${MODULE_NAME}" && ! -e "/sys/kernel/btf/${MODULE_NAME}" &&
    ! -L "/sys/kernel/btf/${MODULE_NAME}" ]] || fail 'restore-module-before-artifact-receipt' 79
  assert_bpf_links_baseline
}

complete_no_artifact_restore() {
  local restored already=0
  validate_no_live_before_artifact_receipt
  if [[ "${ARTIFACT_STATE}" == intent ]]; then
    fail 'restore-artifact-intent-without-receipt-no-live-mutation' 78
  fi
  [[ "${ARTIFACT_STATE}" == absent ]] || fail 'restore-artifact-state-unexpected' 79
  [[ ! -f "${RESTORED_PHASE}" ]] || already=1
  ensure_cleanup_intent
  restored="$(render_fixed_phase restored 'result=restored,filesystem=retained')"
  if ((already)); then
    phase_matches "${RESTORED_PHASE}" "${restored}" || fail 'restored-phase-drift' 79
    printf 'B82_ROUTED_VETH_ALREADY_RESTORED run_id=%s resource_id=%s evidence=%s\n' \
      "${RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
    return
  fi
  write_phase "${RESTORED_PHASE}" "${restored}" || fail 'restored-phase-write' $?
  printf 'B82_ROUTED_VETH_RESTORE_COMPLETE run_id=%s resource_id=%s restored=1 filesystem_retained=1 artifact_state=absent evidence=%s\n' \
    "${RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
}

validate_module_for_restore() {
  local first="$1" state
  state="$(c8_checksum_module_validate_restore_state)" || fail 'restore-module-state' $?
  case "${state}" in
    00-clean) ;;
    00-intent-no-live | 10-unreceipted-live)
      [[ "${first}" == module ]] || fail 'restore-module-unreceipted-order' 79
      ;;
    11-owned-live)
      [[ "${first}" == none ]] || fail 'restore-module-owned-order' 79
      ;;
    01-owned-live-absent)
      [[ "${first}" == none && -f "${CLEANUP_PHASE}" ]] ||
        fail 'restore-module-owned-absent-before-cleanup' 79
      ;;
    00-restored)
      [[ -f "${CLEANUP_PHASE}" && ("${first}" == module || "${first}" == none) ]] ||
        fail 'restore-module-restored-order' 79
      ;;
    *) fail "restore-module-state-unknown:${state}" 79 ;;
  esac
}

validate_partial_setup_for_restore() {
  local first names_present=1 baseline_sha existing live
  validate_dependency_caches_for_restore
  validate_runtime_temp_for_restore
  validate_receipt_prefix || fail 'restore-receipt-prefix' 79
  first="$(first_missing_receipt)" || fail 'restore-first-missing' $?
  validate_module_for_restore "${first}"

  if [[ ! -e "${VETH_INTENT_PHASE}" && ! -L "${VETH_INTENT_PHASE}" ]]; then
    [[ "${first}" == veth ]] || fail 'restore-receipt-without-veth-intent' 79
    require_names_absent || fail 'restore-foreign-veth-without-intent' 79
    existing="$(/usr/sbin/ip -4 -j address show to "${LOCAL_IPV4}/${PREFIX_BITS}")" || fail 'restore-address-without-intent-probe'
    [[ "${existing}" == '[]' ]] || fail 'restore-address-without-intent-drift' 79
    existing="$(/usr/sbin/ip -4 -j route show table all exact "${REMOTE_IPV4}/${PREFIX_BITS}")" || fail 'restore-route-without-intent-probe'
    [[ "${existing}" == '[]' ]] || fail 'restore-route-without-intent-drift' 79
    return
  fi
  phase_matches "${VETH_INTENT_PHASE}" "$(render_veth_intent)" || fail 'restore-veth-intent' 79
  validate_dependency_preflight || fail 'restore-dependency-preflight' 79

  if require_names_absent; then names_present=0; fi
  if [[ -f "${VETH_PHASE}" ]]; then
    read_veth_receipt || fail 'restore-veth-receipt' 79
    phase_matches "${VETH_PHASE}" "$(render_veth)" || fail 'restore-veth-phase' 79
    if ((names_present)); then
      verify_veth_pair || fail 'restore-veth-live' 79
    else
      [[ -f "${CLEANUP_PHASE}" ]] || fail 'restore-veth-receipt-live-missing' 79
    fi
  elif ((names_present)); then
    [[ "${first}" == veth ]] || fail 'restore-unreceipted-veth-out-of-order' 79
    unreceipted_veth_pair_matches || fail 'restore-owned-veth-cut' 79
    VETH_A_IFINDEX="$(/usr/bin/cat "/sys/class/net/${VETH_A}/ifindex")" || fail 'restore-veth-a-ifindex'
    VETH_B_IFINDEX="$(/usr/bin/cat "/sys/class/net/${VETH_B}/ifindex")" || fail 'restore-veth-b-ifindex'
    VETH_A_SYSFS="$(sysfs_identity "${VETH_A}")" || fail 'restore-veth-a-sysfs'
    VETH_B_SYSFS="$(sysfs_identity "${VETH_B}")" || fail 'restore-veth-b-sysfs'
  fi

  if [[ -f "${ADDRESS_PHASE}" ]]; then
    phase_matches "${ADDRESS_PHASE}" \
      "$(render_fixed_phase address "address=${LOCAL_IPV4}/${PREFIX_BITS},ifindex=${VETH_A_IFINDEX}")" || fail 'restore-address-phase' 79
  fi
  if ((names_present)); then
    existing="$(/usr/sbin/ip -4 -j address show dev "${VETH_A}")" || fail 'restore-address-probe'
    if [[ "${existing}" == *'"family":"inet"'* ]]; then
      address_matches || fail 'restore-address-foreign' 79
      [[ -f "${ADDRESS_PHASE}" || "${first}" == address ]] || fail 'restore-address-out-of-order' 79
    elif [[ -f "${ADDRESS_PHASE}" && ! -f "${CLEANUP_PHASE}" ]]; then
      fail 'restore-address-live-missing' 79
    fi
  elif [[ -f "${ADDRESS_PHASE}" && ! -f "${CLEANUP_PHASE}" ]]; then
    fail 'restore-address-veth-missing' 79
  fi

  if [[ -f "${ROUTE_PHASE}" ]]; then
    phase_matches "${ROUTE_PHASE}" \
      "$(render_fixed_phase route "route=${REMOTE_IPV4}/${PREFIX_BITS},ifindex=${VETH_A_IFINDEX},src=${LOCAL_IPV4},mtu=${ROUTE_MTU},proto=static,scope=link")" || fail 'restore-route-phase' 79
  fi
  existing="$(/usr/sbin/ip -4 -j route show table main exact "${REMOTE_IPV4}/${PREFIX_BITS}")" || fail 'restore-route-probe'
  if [[ "${existing}" != '[]' ]]; then
    route_matches || fail 'restore-route-foreign' 79
    [[ -f "${ROUTE_PHASE}" || "${first}" == route ]] || fail 'restore-route-out-of-order' 79
  elif [[ -f "${ROUTE_PHASE}" && ! -f "${CLEANUP_PHASE}" ]]; then
    fail 'restore-route-live-missing' 79
  fi

  if [[ -f "${NEIGHBOR_PHASE}" ]]; then
    phase_matches "${NEIGHBOR_PHASE}" \
      "$(render_fixed_phase neighbor "neighbor=${REMOTE_IPV4},ifindex=${VETH_A_IFINDEX},lladdr=${VETH_B_MAC},state=PERMANENT")" || fail 'restore-neighbor-phase' 79
  fi
  if ((names_present)); then
    existing="$(/usr/sbin/ip -4 -j neigh show to "${REMOTE_IPV4}" dev "${VETH_A}")" || fail 'restore-neighbor-probe'
    if [[ "${existing}" != '[]' ]]; then
      neighbor_matches || fail 'restore-neighbor-foreign' 79
      [[ -f "${NEIGHBOR_PHASE}" || "${first}" == neighbor ]] || fail 'restore-neighbor-out-of-order' 79
    elif [[ -f "${NEIGHBOR_PHASE}" && ! -f "${CLEANUP_PHASE}" ]]; then
      fail 'restore-neighbor-live-missing' 79
    fi
  elif [[ -f "${NEIGHBOR_PHASE}" && ! -f "${CLEANUP_PHASE}" ]]; then
    fail 'restore-neighbor-veth-missing' 79
  fi

  if [[ -f "${OFFLOAD_PHASE}" ]]; then
    require_root_regular "${OFFLOAD_BASELINE_A}" 600 || fail 'restore-offload-baseline' 79
    baseline_sha="$(sha256_file "${OFFLOAD_BASELINE_A}")" || fail 'restore-offload-sha'
    phase_matches "${OFFLOAD_PHASE}" \
      "$(render_fixed_phase offload "ifindex=${VETH_A_IFINDEX},baseline_sha256=${baseline_sha},tso=off,tx-checksumming=on,tx-udp-segmentation=on")" || fail 'restore-offload-phase' 79
  fi
  if [[ -f "${OFFLOAD_BASELINE_A}" ]]; then
    require_root_regular "${OFFLOAD_BASELINE_A}" 600 || fail 'restore-offload-baseline' 79
    feature_file_is_exact "${OFFLOAD_BASELINE_A}" 'tcp-segmentation-offload' on || fail 'restore-offload-baseline-tso' 79
    feature_file_is_exact "${OFFLOAD_BASELINE_A}" 'tx-checksumming' on || fail 'restore-offload-baseline-checksum' 79
    feature_file_is_exact "${OFFLOAD_BASELINE_A}" 'tx-udp-segmentation' on || fail 'restore-offload-baseline-udp-segment' 79
    if ((names_present)); then
      live="$(run_operation V.offload offload-show-a)" || fail 'restore-offload-probe' $?
      if [[ "${live}" == "$(/usr/bin/cat -- "${OFFLOAD_BASELINE_A}")" ]]; then :
      elif feature_text_is_exact "${live}" 'tcp-segmentation-offload' off &&
        feature_text_is_exact "${live}" 'tx-checksumming' on &&
        feature_text_is_exact "${live}" 'tx-udp-segmentation' on; then
        [[ -f "${OFFLOAD_PHASE}" || "${first}" == offload ]] || fail 'restore-offload-out-of-order' 79
      else fail 'restore-offload-foreign' 79; fi
      if [[ -f "${OFFLOAD_PHASE}" && ! -f "${CLEANUP_PHASE}" ]]; then
        offload_live_matches_desired || fail 'restore-offload-live-missing' 79
      fi
    fi
  elif [[ -f "${OFFLOAD_PHASE}" ]]; then
    fail 'restore-offload-phase-without-baseline' 79
  fi

}

run_state_machine() {
  classify_artifact_retry_state
  bootstrap_evidence
  c8_checksum_module_acquire L0.run
  ensure_owner
  ensure_baseline
  [[ ! -f "${CLEANUP_PHASE}" && ! -f "${RESTORED_PHASE}" ]] || fail 'run-after-cleanup-intent' 79
  ensure_operation_intent
  ensure_dependency_intent
  ensure_dependency_preflight
  configure_checksum_module_lease
  ensure_runtime_temp
  ensure_veth_phase
  ensure_address_phase
  ensure_route_phase
  ensure_neighbor_phase
  ensure_offload_phase
  ensure_module_phase
  run_tests
  printf 'B82_ROUTED_VETH_RUN_COMPLETE run_id=%s resource_id=%s tested=1 retained=1 restore_required=1 evidence=%s\n' \
    "${RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
}

restore_state_machine() {
  local restored module_state
  bootstrap_evidence
  c8_checksum_module_acquire L0.restore
  ensure_owner
  [[ -f "${BASELINE_PHASE}" && -f "${OPERATION_PHASE}" ]] || fail 'restore-state-incomplete' 79
  ensure_baseline
  ensure_operation_intent
  validate_dependency_caches_for_restore
  if [[ "${ARTIFACT_STATE}" != receipt ]]; then
    complete_no_artifact_restore
    return
  fi
  configure_checksum_module_lease
  if [[ -f "${RESTORED_PHASE}" ]]; then
    validate_runtime_temp_for_restore
    restored="$(render_fixed_phase restored 'result=restored,filesystem=retained')"
    phase_matches "${RESTORED_PHASE}" "${restored}" || fail 'restored-phase-drift' 79
    require_names_absent || fail 'restored-veth-drift' 79
    module_state="$(c8_checksum_module_validate_restore_state)" || fail 'restored-module-state' $?
    [[ "${module_state}" == 00-clean || "${module_state}" == 00-restored ]] ||
      fail 'restored-module-drift' 79
    assert_bpf_links_baseline
    printf 'B82_ROUTED_VETH_ALREADY_RESTORED run_id=%s resource_id=%s evidence=%s\n' "${RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
    return
  fi
  validate_partial_setup_for_restore
  ensure_cleanup_intent
  assert_bpf_links_baseline
  restore_module
  restore_offload
  restore_network
  assert_bpf_links_baseline
  restored="$(render_fixed_phase restored 'result=restored,filesystem=retained')"
  write_phase "${RESTORED_PHASE}" "${restored}" || fail 'restored-phase-write' $?
  printf 'B82_ROUTED_VETH_RESTORE_COMPLETE run_id=%s resource_id=%s restored=1 filesystem_retained=1 evidence=%s\n' \
    "${RUN_ID}" "${RESOURCE_ID}" "${EVIDENCE_ROOT}"
}

main() {
  parse_arguments "$@" || fail 'arguments' $?
  if [[ "${MODE}" == plan ]]; then
    render_plan
    return
  fi
  verify_source_identity
  load_checksum_module_helper
  case "${MODE}" in
    run) run_state_machine ;;
    restore) restore_state_machine ;;
  esac
}

main "$@"
