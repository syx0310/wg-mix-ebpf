#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

readonly RUN_ID='7e42a19c'
readonly RESOURCE_ID='5b8d30f1'
readonly STATE_SCHEMA='owner,baseline,operation-intent,dependency-preflight,veth-intent,veth,address,route,neighbor,offload,module,tested,cleanup-intent,restored'
readonly STAGE_ROOT="/run/wg-mix-ebpf-source-stages/${RUN_ID}"
readonly EXPECTED_SOURCE="${STAGE_ROOT}/source"
readonly GO_CACHE="${STAGE_ROOT}/go-cache"
readonly GO_MOD_CACHE="${STAGE_ROOT}/go-mod-cache"
readonly GO_PATH="${STAGE_ROOT}/go-path"
readonly GO_TMP="${STAGE_ROOT}/go-tmp"
readonly EVIDENCE_ROOT="${STAGE_ROOT}/routed-evidence-${RESOURCE_ID}"
readonly AUDIT_LOG="${EVIDENCE_ROOT}/audit.log"
readonly OWNER_PHASE="${EVIDENCE_ROOT}/phase-owner.v1"
readonly BASELINE_PHASE="${EVIDENCE_ROOT}/phase-baseline.v1"
readonly OPERATION_PHASE="${EVIDENCE_ROOT}/phase-operation-intent.v1"
readonly DEPENDENCY_PHASE="${EVIDENCE_ROOT}/phase-dependency-preflight.v1"
readonly VETH_INTENT_PHASE="${EVIDENCE_ROOT}/phase-veth-intent.v1"
readonly VETH_PHASE="${EVIDENCE_ROOT}/phase-veth.v1"
readonly ADDRESS_PHASE="${EVIDENCE_ROOT}/phase-address.v1"
readonly ROUTE_PHASE="${EVIDENCE_ROOT}/phase-route.v1"
readonly NEIGHBOR_PHASE="${EVIDENCE_ROOT}/phase-neighbor.v1"
readonly OFFLOAD_PHASE="${EVIDENCE_ROOT}/phase-offload.v1"
readonly MODULE_PHASE="${EVIDENCE_ROOT}/phase-module.v1"
readonly TESTED_PHASE="${EVIDENCE_ROOT}/phase-tested.v1"
readonly CLEANUP_PHASE="${EVIDENCE_ROOT}/phase-cleanup-intent.v1"
readonly RESTORED_PHASE="${EVIDENCE_ROOT}/phase-restored.v1"
readonly BPF_LINK_BASELINE="${EVIDENCE_ROOT}/baseline-bpf-links.json"
readonly OFFLOAD_BASELINE_A="${EVIDENCE_ROOT}/baseline-offload-a.txt"
readonly PREFLIGHT_BINARY="${EVIDENCE_ROOT}/dataplane-preflight.test"

readonly VETH_A="wg${RUN_ID:0:5}a"
readonly VETH_B="wg${RUN_ID:0:5}b"
readonly VETH_A_ALIAS="wg-mix-ebpf:${RUN_ID}:a"
readonly VETH_B_ALIAS="wg-mix-ebpf:${RUN_ID}:b"
readonly VETH_A_MAC='02:7e:42:a1:9c:0a'
readonly VETH_B_MAC='02:7e:42:a1:9c:0b'
readonly LOCAL_IPV4='198.18.82.1'
readonly REMOTE_IPV4='198.18.82.2'
readonly PREFIX_BITS='32'
readonly ROUTE_MTU='1500'
readonly MODULE_NAME='wg_mix_faketcp_checksum'
readonly EXPERIMENTAL_OBJECT="${EXPECTED_SOURCE}/build/wg_mix_faketcp_experimental.o"
readonly BASELINE_OBJECT="${EXPECTED_SOURCE}/build/wg_mix_tc.o"
readonly MODULE_OBJECT="${EXPECTED_SOURCE}/build/faketcp_checksum_kmod/${MODULE_NAME}.ko"
readonly SELF_RELATIVE='scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh'
readonly SEAM_RELATIVE='scripts/realhost-b82-routed-veth-v1/controller-seam.sh'
readonly ROUTED_CONTRACT_RELATIVE='internal/dataplane/faketcp_routed_realhost_contract_test.go'
readonly ROUTED_TEST_RELATIVE='internal/dataplane/faketcp_routed_realhost_linux_test.go'
readonly NEGATIVE_TEST_RELATIVE='internal/dataplane/faketcp_realhost_linux_test.go'
readonly GSO_KFUNC_RELATIVE='kernel/faketcp_checksum/wg_mix_faketcp_checksum.c'
readonly NEGATIVE_TEST='TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration'
readonly -a POSITIVE_TESTS=(
  TestFakeTCPRealHostRoutedIPHdrInclNone
  TestFakeTCPRealHostRoutedUDPSocketPartial
  TestFakeTCPRealHostRoutedUDPSegmentGSO
)
readonly EXPECTED_HOSTNAME='ubuntu-2604-test'
readonly EXPECTED_MACHINE_ID='9db3fb717cc74974b2a6b243d67f67b9'

MODE=''
SOURCE=''
COMMIT=''
EXPERIMENTAL_SHA256=''
BASELINE_SHA256=''
MODULE_SHA256=''
INITIAL_NETNS=''
BOOT_ID=''
VETH_A_IFINDEX=''
VETH_B_IFINDEX=''
VETH_A_SYSFS=''
VETH_B_SYSFS=''
EXPECTED_MODULE_SRCVERSION=''
OP_TARGET=''
declare -a OP_ARGV=()
declare -a BOOTSTRAP_AUDIT_LINES=()

readonly -a GO_ENV=(
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
  CGO_ENABLED=0 GOENV=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
  'GOVCS=*:off'
  GOCACHE="${GO_CACHE}" GOMODCACHE="${GO_MOD_CACHE}" GOPATH="${GO_PATH}"
  GOTMPDIR="${GO_TMP}" TMPDIR="${GO_TMP}" GOWORK=off GO111MODULE=on
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
    '  --commit 40-lowercase-hex' \
    '  --experimental-sha256 64-lowercase-hex' \
    '  --baseline-sha256 64-lowercase-hex' \
    '  --module-sha256 64-lowercase-hex' >&2
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
  local seen_source=0 seen_commit=0 seen_experimental=0 seen_baseline=0 seen_module=0
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
      --experimental-sha256)
        ((seen_experimental == 0)) || return 65
        seen_experimental=1; EXPERIMENTAL_SHA256="$2"
        ;;
      --baseline-sha256)
        ((seen_baseline == 0)) || return 65
        seen_baseline=1; BASELINE_SHA256="$2"
        ;;
      --module-sha256)
        ((seen_module == 0)) || return 65
        seen_module=1; MODULE_SHA256="$2"
        ;;
      *) usage; return 64 ;;
    esac
    shift 2
  done
  ((seen_source == 1 && seen_commit == 1 && seen_experimental == 1 &&
    seen_baseline == 1 && seen_module == 1)) || return 65
  [[ "${SOURCE}" == "${EXPECTED_SOURCE}" ]] || return 65
  valid_commit "${COMMIT}" || return 65
  valid_sha256 "${EXPERIMENTAL_SHA256}" || return 65
  valid_sha256 "${BASELINE_SHA256}" || return 65
  valid_sha256 "${MODULE_SHA256}" || return 65
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

# Every external operation which can mutate state or execute a test is built
# here. Callers never concatenate a shell command, use eval, or add free-form
# remote argv.
build_argv() {
  local operation="$1" name
  OP_TARGET="${operation}"
  OP_ARGV=()
  case "${operation}" in
    evidence-mkdir) OP_TARGET="${EVIDENCE_ROOT}"; OP_ARGV=(/usr/bin/mkdir --mode=0700 -- "${EVIDENCE_ROOT}") ;;
    bpf-links) OP_TARGET='global-bpf-links'; OP_ARGV=(/usr/sbin/bpftool -j link show) ;;
    preflight-mod-verify) OP_TARGET="${GO_MOD_CACHE}"; OP_ARGV=("${GO_ENV[@]}" /usr/bin/timeout --signal=TERM --kill-after=10s 5m /usr/bin/go -C "${SOURCE}" mod verify) ;;
    preflight-build) OP_TARGET="${PREFLIGHT_BINARY}"; OP_ARGV=("${GO_ENV[@]}" /usr/bin/timeout --signal=TERM --kill-after=10s 10m /usr/bin/go -C "${SOURCE}" test -c -o "${PREFLIGHT_BINARY}" ./internal/dataplane) ;;
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
    module-load) OP_TARGET="${MODULE_NAME}"; OP_ARGV=(/usr/sbin/insmod "${MODULE_OBJECT}") ;;
    module-unload) OP_TARGET="${MODULE_NAME}"; OP_ARGV=(/usr/sbin/rmmod "${MODULE_NAME}") ;;
    list:*)
      name="${operation#list:}"; valid_test_name "${name}" || return 64
      OP_TARGET="${name}"
      OP_ARGV=(/usr/bin/timeout --signal=TERM --kill-after=10s 1m "${PREFLIGHT_BINARY}" -test.list "^${name}$")
      ;;
    test:*)
      name="${operation#test:}"; valid_test_name "${name}" || return 64
      OP_TARGET="${name}"
      OP_ARGV=(/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TMPDIR="${GO_TMP}" WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION=1 WG_MIX_FAKETCP_REALHOST_OBJECT="${EXPERIMENTAL_OBJECT}" WG_MIX_FAKETCP_REALHOST_BASELINE_OBJECT="${BASELINE_OBJECT}" WG_MIX_FAKETCP_REALHOST_IFINDEX="${VETH_A_IFINDEX}" WG_MIX_FAKETCP_REALHOST_PEER_IFINDEX="${VETH_B_IFINDEX}" WG_MIX_FAKETCP_REALHOST_XDP_MODE=generic WG_MIX_FAKETCP_REALHOST_RUN_ID="${RUN_ID}" WG_MIX_FAKETCP_ROUTED_LOCAL_IPV4="${LOCAL_IPV4}" WG_MIX_FAKETCP_ROUTED_REMOTE_IPV4="${REMOTE_IPV4}" WG_MIX_FAKETCP_ROUTED_PREFIX_BITS="${PREFIX_BITS}" WG_MIX_FAKETCP_ROUTED_ROUTE_MTU="${ROUTE_MTU}" /usr/bin/timeout --signal=TERM --kill-after=10s 3m "${PREFLIGHT_BINARY}" -test.run "^${name}$" -test.count=1 -test.timeout=2m -test.v)
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
  plan_operation A.bpf bpf-links
  plan_operation P0 preflight-mod-verify
  plan_operation P1 preflight-build
  for name in "${NEGATIVE_TEST}" "${POSITIVE_TESTS[@]}"; do
    plan_operation "P.${name}" "list:${name}"
  done
  for spec in \
    'N0|veth-add' 'N1|veth-alias-a' 'N2|veth-alias-b' \
    'N3|veth-up-a' 'N4|veth-up-b' 'N5|address-add' \
    'N6|route-add' 'N7|neighbor-add' 'N8|offload-show-a' \
    'N9|offload-tso-off' 'M0|module-load'; do
    IFS='|' read -r label operation <<<"${spec}"
    plan_operation "${label}" "${operation}"
  done
  for name in "${NEGATIVE_TEST}" "${POSITIVE_TESTS[@]}"; do
    plan_operation "T.${name}" "test:${name}"
  done
  for spec in \
    'R0|bpf-links' 'R1|module-unload' 'R2|offload-tso-restore' \
    'R3|neighbor-delete' 'R4|route-delete' 'R5|address-delete' \
    'R6|veth-delete' 'R7|bpf-links'; do
    IFS='|' read -r label operation <<<"${spec}"
    plan_operation "${label}" "${operation}"
  done
  printf 'B82_ROUTED_VETH_WRITE_SET filesystem=%s,%s,%s,%s,%s,%s network=veth:%s,%s,address:%s/%s,route:%s/%s,neighbor:%s,offload:%s:tso module=%s bpf=transient-unpinned-test-owned evidence_retained=1\n' \
    "${EVIDENCE_ROOT}" "${PREFLIGHT_BINARY}" "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}" \
    "${VETH_A}" "${VETH_B}" "${LOCAL_IPV4}" "${PREFIX_BITS}" "${REMOTE_IPV4}" \
    "${PREFIX_BITS}" "${REMOTE_IPV4}" "${VETH_A}" "${MODULE_NAME}"
  printf 'B82_ROUTED_VETH_RESTORE_ORDER cleanup-intent,bpf-baseline,module,offload,neighbor,route,address,veth,bpf-baseline,restored retryable=1 exact_reverse=1\n'
  printf 'B82_ROUTED_VETH_COVERAGE af_packet=none,partial,gso:route-unknown-negative routed=iphdrincl-none,udp-partial,udp-segment-gso:positive capability_bits_changed=0\n'
  printf 'B82_ROUTED_VETH_PLAN_COMPLETE commands_are_review_templates=1 preflight_before_host_mutation=1 network_downloads=0 no_commands_executed=1 credential_read=0 remote_connections=0 network_operations=0\n'
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

run_operation() {
  local label="$1" operation="$2" rendered rc
  local -a status
  build_argv "${operation}" || fail "operation-builder:${operation}" $?
  rendered="$(quote_argv "${OP_ARGV[@]}")" || fail "render:${label}"
  audit_line start "${label}" "${OP_TARGET}" not-run "${rendered}" || fail "audit-start:${label}"
  "${OP_ARGV[@]}" 2>&1 | /usr/bin/tee -a "${AUDIT_LOG}"
  status=("${PIPESTATUS[@]}")
  ((${#status[@]} == 2)) || fail "pipeline:${label}"
  rc="${status[0]}"
  audit_line finish "${label}" "${OP_TARGET}" "${rc}" "${rendered}" || fail "audit-finish:${label}"
  ((status[1] == 0)) || fail "audit-output:${label}" "${status[1]}"
  return "${rc}"
}

capture_operation() {
  local label="$1" operation="$2" destination="$3" rendered output rc
  [[ ! -e "${destination}" && ! -L "${destination}" ]] || return 73
  build_argv "${operation}" || fail "capture-builder:${operation}" $?
  rendered="$(quote_argv "${OP_ARGV[@]}")" || fail "capture-render:${label}"
  audit_line start "${label}" "${OP_TARGET}" not-run "${rendered}" || fail "capture-audit-start:${label}"
  output="$("${OP_ARGV[@]}" 2>&1)"; rc=$?
  printf '%s\n' "${output}" | /usr/bin/tee -a "${AUDIT_LOG}"
  ((${PIPESTATUS[0]} == 0 && ${PIPESTATUS[1]} == 0)) || fail "capture-output:${label}"
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
    "netns=${INITIAL_NETNS}" "source=${SOURCE}" "commit=${COMMIT}" \
    "experimental_sha256=${EXPERIMENTAL_SHA256}" \
    "baseline_sha256=${BASELINE_SHA256}" "module_sha256=${MODULE_SHA256}"
}

render_baseline() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-baseline-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" \
    "netns=${INITIAL_NETNS}" 'veth=absent' 'address=absent' 'route=absent' \
    'neighbor=absent' 'module=absent' \
    "bpf_links_sha256=$(sha256_file "${BPF_LINK_BASELINE}")"
}

render_operation_intent() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-operation-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" \
    "source=${SOURCE}" "commit=${COMMIT}" \
    "dependency_cache=${GO_MOD_CACHE},proxy=off,mode=readonly" \
    "preflight_binary=${PREFLIGHT_BINARY}" \
    "veth=${VETH_A},${VETH_B}" "address=${LOCAL_IPV4}/${PREFIX_BITS}" \
    "route=${REMOTE_IPV4}/${PREFIX_BITS},src=${LOCAL_IPV4},mtu=${ROUTE_MTU}" \
    "neighbor=${REMOTE_IPV4},lladdr=${VETH_B_MAC}" \
    "offload=${VETH_A},tso:on->off->on" "module=${MODULE_NAME}" \
    'reverse=module,offload,neighbor,route,address,veth'
}

render_dependency_preflight() {
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-dependency-v1' \
    "run_id=${RUN_ID}" "resource_id=${RESOURCE_ID}" "commit=${COMMIT}" \
    "binary=${PREFLIGHT_BINARY}" "binary_sha256=$(sha256_file "${PREFLIGHT_BINARY}")" \
    "go_cache=${GO_CACHE}" "go_mod_cache=${GO_MOD_CACHE}" \
    'module_cache_verified=1' 'goproxy=off' 'go_mod=readonly' \
    "tests=${NEGATIVE_TEST},${POSITIVE_TESTS[*]}"
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

verify_source_and_artifacts() {
  local actual head mapped self_blob actual_blob status line identity
  [[ "$EUID" == 0 ]] || fail 'root-required' 77
  [[ "$(/usr/bin/hostname)" == "${EXPECTED_HOSTNAME}" ]] || fail 'hostname' 77
  [[ "$(/usr/bin/cat /etc/machine-id)" == "${EXPECTED_MACHINE_ID}" ]] || fail 'machine-id' 77
  [[ "$(/usr/bin/uname -r)" == 7.0.* ]] || fail 'kernel-release' 77
  INITIAL_NETNS="$(/usr/bin/readlink /proc/self/ns/net)" || fail 'self-netns'
  [[ "${INITIAL_NETNS}" == "$(/usr/bin/readlink /proc/1/ns/net)" && "${INITIAL_NETNS}" == net:\[*\] ]] || fail 'initial-netns' 77
  BOOT_ID="$(/usr/bin/cat /proc/sys/kernel/random/boot_id)" || fail 'boot-id'
  [[ "${BOOT_ID}" =~ ^[0-9a-f-]{36}$ ]] || fail 'boot-id-format' 77
  require_root_directory "${STAGE_ROOT}" || fail 'stage-root-identity' 79
  for path in "${GO_CACHE}" "${GO_MOD_CACHE}" "${GO_PATH}" "${GO_TMP}"; do
    require_root_directory "${path}" || fail "stage-go-directory-identity:${path}" 79
  done
  [[ -d "${SOURCE}/.git" && ! -L "${SOURCE}" ]] || fail 'source-identity' 79
  head="$("${GIT_COMMAND[@]}" -C "${SOURCE}" rev-parse --verify HEAD^{commit})" || fail 'source-head'
  [[ "${head}" == "${COMMIT}" ]] || fail 'source-commit' 79
  "${GIT_COMMAND[@]}" -C "${SOURCE}" diff --quiet "${COMMIT}" -- || fail 'tracked-worktree-drift' 79
  "${GIT_COMMAND[@]}" -C "${SOURCE}" diff --cached --quiet "${COMMIT}" -- || fail 'index-drift' 79
  status="$("${GIT_COMMAND[@]}" -C "${SOURCE}" status --porcelain=v1 --untracked-files=all)" || fail 'source-status'
  while IFS= read -r line; do
    [[ -z "${line}" || "${line}" == '?? build/'* ]] || fail 'untracked-source-input' 79
  done <<<"${status}"
  for spec in \
    "${EXPERIMENTAL_OBJECT}|${EXPERIMENTAL_SHA256}" \
    "${BASELINE_OBJECT}|${BASELINE_SHA256}" \
    "${MODULE_OBJECT}|${MODULE_SHA256}"; do
    IFS='|' read -r path expected <<<"${spec}"
    [[ -f "${path}" && ! -L "${path}" ]] || fail "artifact-shape:${path}" 79
    identity="$(/usr/bin/stat -Lc '%u:%g:%a:%h:%F' -- "${path}")" || fail "artifact-stat:${path}"
    [[ "${identity}" == '0:0:600:1:regular file' || "${identity}" == '0:0:644:1:regular file' ]] || fail "artifact-owner:${path}" 79
    actual="$(sha256_file "${path}")" || fail "artifact-sha-read:${path}"
    [[ "${actual}" == "${expected}" ]] || fail "artifact-sha:${path}" 79
  done
  for relative in "${SELF_RELATIVE}" "${SEAM_RELATIVE}" "${ROUTED_CONTRACT_RELATIVE}" "${ROUTED_TEST_RELATIVE}" \
    "${NEGATIVE_TEST_RELATIVE}" "${GSO_KFUNC_RELATIVE}"; do
    mapped="$("${GIT_COMMAND[@]}" -C "${SOURCE}" rev-parse "${COMMIT}:${relative}")" || fail "mapped-blob:${relative}"
    actual_blob="$("${GIT_COMMAND[@]}" -C "${SOURCE}" hash-object -- "${SOURCE}/${relative}")" || fail "actual-blob:${relative}"
    [[ "${mapped}" == "${actual_blob}" ]] || fail "blob-drift:${relative}" 79
  done
  self_blob="$(/usr/bin/readlink -e -- "$0")" || fail 'self-canonical'
  [[ "${self_blob}" == "${SOURCE}/${SELF_RELATIVE}" ]] || fail 'self-path' 79
  EXPECTED_MODULE_SRCVERSION="$(/usr/sbin/modinfo -F srcversion -- "${MODULE_OBJECT}")" || fail 'module-srcversion'
  [[ "${EXPECTED_MODULE_SRCVERSION}" =~ ^[0-9A-Fa-f]{8,64}$ ]] || fail 'module-srcversion-format' 79
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

ensure_dependency_preflight() {
  local name expected output
  if [[ -f "${DEPENDENCY_PHASE}" ]]; then
    require_root_test_binary "${PREFLIGHT_BINARY}" || fail 'preflight-binary-identity' 79
    expected="$(render_dependency_preflight)" || fail 'preflight-render'
    phase_matches "${DEPENDENCY_PHASE}" "${expected}" || fail 'preflight-phase-drift' 79
    return
  fi
  run_operation P0 preflight-mod-verify || fail 'dependency-module-verification' $?
  if [[ ! -e "${PREFLIGHT_BINARY}" && ! -L "${PREFLIGHT_BINARY}" ]]; then
    run_operation P1 preflight-build || fail 'dependency-build-preflight' $?
  fi
  require_root_test_binary "${PREFLIGHT_BINARY}" || fail 'preflight-binary-identity' 79
  for name in "${NEGATIVE_TEST}" "${POSITIVE_TESTS[@]}"; do
    output="$(run_operation "P.${name}" "list:${name}")" || fail "dependency-test-list:${name}" $?
    [[ "$(printf '%s\n' "${output}" | /usr/bin/grep -Fxc -- "${name}")" == 1 ]] || fail "dependency-test-definition:${name}" 79
  done
  expected="$(render_dependency_preflight)" || fail 'preflight-render'
  write_phase "${DEPENDENCY_PHASE}" "${expected}" || fail 'preflight-phase-write' $?
}

validate_dependency_preflight() {
  local expected
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
  if ((${PIPESTATUS[0]} != 0 || ${PIPESTATUS[1]} != 0)); then run_operation N3 veth-up-a || fail 'veth-up-a' $?; fi
  /usr/sbin/ip -j link show dev "${VETH_B}" | /usr/bin/jq -e '.[0].flags | index("UP") != null' >/dev/stdout
  if ((${PIPESTATUS[0]} != 0 || ${PIPESTATUS[1]} != 0)); then run_operation N4 veth-up-b || fail 'veth-up-b' $?; fi
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

module_matches() {
  [[ -d "/sys/module/${MODULE_NAME}" &&
    "$(/usr/bin/cat "/sys/module/${MODULE_NAME}/srcversion")" == "${EXPECTED_MODULE_SRCVERSION}" ]]
}

ensure_module_phase() {
  local expected
  expected="$(render_fixed_phase module "module=${MODULE_NAME},sha256=${MODULE_SHA256},srcversion=${EXPECTED_MODULE_SRCVERSION}")" || fail 'module-render'
  if [[ -f "${MODULE_PHASE}" ]]; then
    phase_matches "${MODULE_PHASE}" "${expected}" || fail 'module-phase-drift' 79
    module_matches || fail 'module-identity' 79
    return
  fi
  if [[ -d "/sys/module/${MODULE_NAME}" ]]; then module_matches || fail 'module-unreceipted-drift' 79
  else run_operation M0 module-load || fail 'module-load' $?; module_matches || fail 'module-postcondition' 79; fi
  write_phase "${MODULE_PHASE}" "${expected}" || fail 'module-phase-write' $?
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
  local owner baseline operation dependency veth_intent veth address route
  local neighbor offload_baseline offload module tested
  owner="$(sha256_file "${OWNER_PHASE}")" || return $?
  baseline="$(sha256_file "${BASELINE_PHASE}")" || return $?
  operation="$(sha256_file "${OPERATION_PHASE}")" || return $?
  dependency="$(phase_binding "${DEPENDENCY_PHASE}")" || return $?
  veth_intent="$(phase_binding "${VETH_INTENT_PHASE}")" || return $?
  veth="$(phase_binding "${VETH_PHASE}")" || return $?
  address="$(phase_binding "${ADDRESS_PHASE}")" || return $?
  route="$(phase_binding "${ROUTE_PHASE}")" || return $?
  neighbor="$(phase_binding "${NEIGHBOR_PHASE}")" || return $?
  offload_baseline="$(phase_binding "${OFFLOAD_BASELINE_A}")" || return $?
  offload="$(phase_binding "${OFFLOAD_PHASE}")" || return $?
  module="$(phase_binding "${MODULE_PHASE}")" || return $?
  tested="$(phase_binding "${TESTED_PHASE}")" || return $?
  printf '%s\n' \
    'format=wg-mix-ebpf-b82-routed-cleanup-v1' "run_id=${RUN_ID}" \
    "resource_id=${RESOURCE_ID}" "boot_id=${BOOT_ID}" "netns=${INITIAL_NETNS}" \
    "owner_sha256=${owner}" "baseline_sha256=${baseline}" \
    "operation_sha256=${operation}" "dependency=${dependency}" \
    "veth_intent=${veth_intent}" "veth=${veth}" "address=${address}" \
    "route=${route}" "neighbor=${neighbor}" \
    "offload_baseline=${offload_baseline}" "offload=${offload}" \
    "module=${module}" "tested=${tested}" \
    'reverse=module,offload,neighbor,route,address,veth'
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
  local fields
  if [[ -d "/sys/module/${MODULE_NAME}" ]]; then
    module_matches || fail 'restore-module-identity' 79
    fields="$(/usr/bin/awk -v name="${MODULE_NAME}" '$1 == name {print $1 ":" $3}' /proc/modules)" || fail 'module-refcount-read'
    [[ "${fields}" == "${MODULE_NAME}:0" ]] || fail 'module-refcount' 79
    run_operation R1 module-unload || fail 'module-unload' $?
  fi
  [[ ! -d "/sys/module/${MODULE_NAME}" ]] || fail 'module-remains' 79
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

validate_partial_setup_for_restore() {
  local first names_present=1 baseline_sha existing live
  validate_receipt_prefix || fail 'restore-receipt-prefix' 79
  first="$(first_missing_receipt)" || fail 'restore-first-missing' $?

  if [[ ! -e "${VETH_INTENT_PHASE}" && ! -L "${VETH_INTENT_PHASE}" ]]; then
    [[ "${first}" == veth ]] || fail 'restore-receipt-without-veth-intent' 79
    require_names_absent || fail 'restore-foreign-veth-without-intent' 79
    [[ ! -d "/sys/module/${MODULE_NAME}" ]] || fail 'restore-module-without-veth-intent' 79
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

  if [[ -f "${MODULE_PHASE}" ]]; then
    phase_matches "${MODULE_PHASE}" \
      "$(render_fixed_phase module "module=${MODULE_NAME},sha256=${MODULE_SHA256},srcversion=${EXPECTED_MODULE_SRCVERSION}")" || fail 'restore-module-phase' 79
  fi
  if [[ -d "/sys/module/${MODULE_NAME}" ]]; then
    module_matches || fail 'restore-module-foreign' 79
    [[ -f "${MODULE_PHASE}" || "${first}" == module ]] || fail 'restore-module-out-of-order' 79
  elif [[ -f "${MODULE_PHASE}" && ! -f "${CLEANUP_PHASE}" ]]; then
    fail 'restore-module-live-missing' 79
  fi
}

run_state_machine() {
  bootstrap_evidence
  ensure_owner
  ensure_baseline
  [[ ! -f "${CLEANUP_PHASE}" && ! -f "${RESTORED_PHASE}" ]] || fail 'run-after-cleanup-intent' 79
  ensure_operation_intent
  ensure_dependency_preflight
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
  local restored
  bootstrap_evidence
  ensure_owner
  [[ -f "${BASELINE_PHASE}" && -f "${OPERATION_PHASE}" ]] || fail 'restore-state-incomplete' 79
  ensure_baseline
  ensure_operation_intent
  if [[ -f "${RESTORED_PHASE}" ]]; then
    restored="$(render_fixed_phase restored 'result=restored,filesystem=retained')"
    phase_matches "${RESTORED_PHASE}" "${restored}" || fail 'restored-phase-drift' 79
    require_names_absent || fail 'restored-veth-drift' 79
    [[ ! -d "/sys/module/${MODULE_NAME}" ]] || fail 'restored-module-drift' 79
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
  verify_source_and_artifacts
  case "${MODE}" in
    run) run_state_machine ;;
    restore) restore_state_machine ;;
  esac
}

main "$@"
