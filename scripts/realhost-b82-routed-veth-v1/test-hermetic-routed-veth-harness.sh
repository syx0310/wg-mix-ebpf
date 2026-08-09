#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

REVIEW_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)" || exit 70
readonly REVIEW_ROOT
REPOSITORY="$(CDPATH='' cd -- "${REVIEW_ROOT}/../.." && pwd -P)" || exit 70
readonly REPOSITORY
readonly RUNNER="${REVIEW_ROOT}/root-routed-veth-n-r.sh"
readonly SEAM="${REVIEW_ROOT}/controller-seam.sh"
readonly STATIC_TEST="${REVIEW_ROOT}/test_routed_veth_harness_static.py"
readonly MODULE_LEASE_HELPER="${REVIEW_ROOT}/../realhost-b82-c8e41d73/checksum-module-lease.sh"
readonly MODULE_LEASE_HERMETIC="${REVIEW_ROOT}/../realhost-b82-c8e41d73/test-hermetic-checksum-module-lease.sh"
readonly SOURCE='/run/wg-mix-ebpf-source-stages/c8e41d73/source'
readonly STAGE_ROOT='/run/wg-mix-ebpf-source-stages/c8e41d73'
COMMIT='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly BASE_COMMIT='3ea1cf0272197d580e90d51c8997352e79c47ba9'
readonly LOCKED_STANDALONE='scripts/realhost-b82-c8e41d73/root-veth-n-r.sh'
readonly STANDALONE_LEASE_SCOPE='1c4102b96d28657b60ee58314c7088069c59eea9'
readonly STANDALONE_LEASE_ADAPTER='e5757dc8063aec13c3fb8793cb4bcb2ed14dcc1e'
readonly STANDALONE_LEASE_RUNNER_BLOB='35d62e78f8bb9d410b22f86d734740fab1c36855'
readonly STANDALONE_PREMUTATION_FIX_PARENT='2d3b95752aaf0d71cb17a0a3ad94d81d55208ec8'
readonly STANDALONE_PREMUTATION_FIX='7a286559580e15ec0d89ed69f3130fe6894b5803'
readonly STANDALONE_PREMUTATION_RUNNER_BLOB='99aea86c89e2069a3ff8acdd673b0222dc517e60'

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit "${2:-1}"
}

expect_failure() {
  local label="$1" output
  shift
  if output="$("$@" 2>&1)"; then
    fail "${label} unexpectedly succeeded"
  fi
  printf 'EXPECTED_FAILURE label=%s output=%q\n' "${label}" "${output}"
}

require_ordered_literals() {
  local remaining="$1" marker
  shift
  for marker in "$@"; do
    [[ "${remaining}" == *"${marker}"* ]] || fail "ordered plan marker missing: ${marker}"
    remaining="${remaining#*"${marker}"}"
  done
}

for path in "${RUNNER}" "${SEAM}" "${STATIC_TEST}" \
  "${MODULE_LEASE_HELPER}" "${MODULE_LEASE_HERMETIC}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "fixture is not a regular file: ${path}"
done

/bin/bash -n "${RUNNER}" "${SEAM}" "${MODULE_LEASE_HELPER}" \
  "${MODULE_LEASE_HERMETIC}" "$0" || fail 'Bash syntax gate'
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I "${STATIC_TEST}" "${RUNNER}" "${SEAM}" ||
  fail 'static safety and lifecycle model'
/bin/bash "${MODULE_LEASE_HERMETIC}" || fail 'shared checksum-module lease contract'
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${RUNNER}" "${SEAM}" \
    "${MODULE_LEASE_HELPER}" "${MODULE_LEASE_HERMETIC}" "$0" || fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable locally; .82 execution remains shellcheck-gated\n'
fi

ADAPTER_PARENT="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P "${STANDALONE_LEASE_ADAPTER}")" ||
  fail 'cannot read standalone lease adapter parent'
readonly ADAPTER_PARENT
[[ "${ADAPTER_PARENT}" == "${STANDALONE_LEASE_SCOPE}" ]] ||
  fail 'standalone lease adapter does not descend directly from its exact scope commit'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor \
  "${STANDALONE_LEASE_ADAPTER}" HEAD || fail 'standalone lease adapter is not in bound history'
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${BASE_COMMIT}" "${STANDALONE_LEASE_ADAPTER}^" -- "${LOCKED_STANDALONE}" ||
  fail 'pre-adapter routed history changed the reviewer-locked standalone runner'
ADAPTER_PATHS="$(/usr/bin/git -C "${REPOSITORY}" diff --name-only \
  "${STANDALONE_LEASE_ADAPTER}^" "${STANDALONE_LEASE_ADAPTER}")" ||
  fail 'cannot read standalone lease adapter write set'
readonly ADAPTER_PATHS
[[ "${ADAPTER_PATHS}" == $'scripts/realhost-b82-c8e41d73/root-veth-n-r.sh\nscripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh\nscripts/realhost-b82-c8e41d73/test_veth_runner_static.py' ]] ||
  fail 'standalone lease adapter changed an unexpected path'
[[ "$(/usr/bin/git -C "${REPOSITORY}" rev-parse \
  "${STANDALONE_LEASE_ADAPTER}:${LOCKED_STANDALONE}")" == "${STANDALONE_LEASE_RUNNER_BLOB}" ]] ||
  fail 'standalone lease adapter runner blob drifted'
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${STANDALONE_LEASE_ADAPTER}" "${STANDALONE_PREMUTATION_FIX}^" -- "${LOCKED_STANDALONE}" ||
  fail 'standalone lease runner changed before its pre-mutation fix'
FIX_PARENT="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P "${STANDALONE_PREMUTATION_FIX}")" ||
  fail 'cannot read standalone pre-mutation fix parent'
readonly FIX_PARENT
[[ "${FIX_PARENT}" == "${STANDALONE_PREMUTATION_FIX_PARENT}" ]] ||
  fail 'standalone pre-mutation fix does not have its exact parent'
FIX_PATHS="$(/usr/bin/git -C "${REPOSITORY}" diff --name-only \
  "${STANDALONE_PREMUTATION_FIX}^" "${STANDALONE_PREMUTATION_FIX}")" ||
  fail 'cannot read standalone pre-mutation fix write set'
readonly FIX_PATHS
[[ "${FIX_PATHS}" == $'scripts/realhost-b82-c8e41d73/root-veth-n-r.sh\nscripts/realhost-b82-c8e41d73/test_veth_runner_static.py' ]] ||
  fail 'standalone pre-mutation fix changed an unexpected path'
[[ "$(/usr/bin/git -C "${REPOSITORY}" rev-parse \
  "${STANDALONE_PREMUTATION_FIX}:${LOCKED_STANDALONE}")" == "${STANDALONE_PREMUTATION_RUNNER_BLOB}" ]] ||
  fail 'standalone pre-mutation fix runner blob drifted'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor \
  "${STANDALONE_PREMUTATION_FIX}" HEAD ||
  fail 'bound history does not contain the reviewed pre-mutation fix'

STAGED_CONTEXT='absent'
if [[ -e "${STAGE_ROOT}" || -L "${STAGE_ROOT}" ]]; then
  [[ "$EUID" == 0 &&
    "$0" == "${SOURCE}/scripts/realhost-b82-routed-veth-v1/test-hermetic-routed-veth-harness.sh" &&
    "$(/usr/bin/readlink -e -- "${STAGE_ROOT}")" == "${STAGE_ROOT}" &&
    "$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${STAGE_ROOT}")" == '0:0:700:directory' &&
    "$(/usr/bin/readlink -e -- "${SOURCE}")" == "${SOURCE}" &&
    "$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${SOURCE}")" == '0:0:700:directory' ]] ||
    fail 'pre-existing stage is not the exact root-owned staged test context'
  COMMIT="$(/usr/bin/git -C "${SOURCE}" rev-parse --verify 'HEAD^{commit}')" ||
    fail 'cannot bind exact staged context commit'
  STAGED_CONTEXT='exact'
else
  [[ ! -e "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] ||
    fail 'local absent-stage fixture is ambiguous'
fi
readonly COMMIT STAGED_CONTEXT

readonly -a RUNNER_ARGS=(
  --source "${SOURCE}"
  --commit "${COMMIT}"
)
readonly -a SEAM_ARGS=(
  --commit "${COMMIT}"
)

PLAN_OUTPUT="$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /bin/bash "${RUNNER}" plan "${RUNNER_ARGS[@]}")" ||
  fail 'root runner plan'
readonly PLAN_OUTPUT
if [[ "${STAGED_CONTEXT}" == exact ]]; then
  SEAM_OUTPUT="$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    /bin/bash "${SEAM}" plan "${SEAM_ARGS[@]}")" || fail 'controller seam exact-stage plan'
else
  SEAM_OUTPUT="$(/bin/cat -- "${SEAM}")" || fail 'controller seam absent-stage source fixture'
fi
readonly SEAM_OUTPUT

for literal in \
  'B82_ROUTED_VETH_PLAN_ONLY run_id=c8e41d73 resource_id=5b8d30f1' \
  'state_schema=owner,baseline,operation-intent,dependency-intent,artifact-intent,artifacts,dependency-preflight,veth-intent,veth,address,route,neighbor,offload,module-intent,module,tested,cleanup-intent,restored' \
  'L0 operation=shared-module-lock target=/run/wg-mix-ebpf-source-stages/c8e41d73/checksum-module-lease.v1.lock helper=/run/wg-mix-ebpf-source-stages/c8e41d73/source/scripts/realhost-b82-c8e41d73/checksum-module-lease.sh argv=/usr/bin/flock --exclusive --nonblock MODULE_LEASE_FD' \
  'netns=initial veth=wg5b8d3a,wg5b8d3b sender=198.18.82.1/32 peer=wg5b8d3b/unnumbered route=198.18.82.2/32 mtu=1500 neighbor=02:5b:8d:30:f1:0b no_external_peer=1' \
  'N5 operation=address-add target=wg5b8d3a:198.18.82.1/32 argv=/usr/sbin/ip -4 address add 198.18.82.1/32 dev wg5b8d3a scope global' \
  'N6 operation=route-add target=198.18.82.2/32 argv=/usr/sbin/ip -4 route add 198.18.82.2/32 dev wg5b8d3a src 198.18.82.1 mtu 1500 proto static scope link' \
  'N7 operation=neighbor-add target=wg5b8d3a:198.18.82.2 argv=/usr/sbin/ip -4 neigh add 198.18.82.2 lladdr 02:5b:8d:30:f1:0b nud permanent dev wg5b8d3a' \
  'N1 operation=veth-alias-a target=wg5b8d3a argv=/usr/sbin/ip link set dev wg5b8d3a alias wg-mix-ebpf:c8e41d73:5b8d30f1:a' \
  'N2 operation=veth-alias-b target=wg5b8d3b argv=/usr/sbin/ip link set dev wg5b8d3b alias wg-mix-ebpf:c8e41d73:5b8d30f1:b' \
  'N9 operation=offload-tso-off target=wg5b8d3a:tso=off argv=/usr/sbin/ethtool -K wg5b8d3a tso off' \
  'M0 operation=shared-module-load target=wg_mix_faketcp_checksum helper=c8_checksum_module_load argv=/usr/sbin/insmod /run/wg-mix-ebpf-source-stages/c8e41d73/source/build/faketcp_checksum_kmod/wg_mix_faketcp_checksum.ko lease_id=c8e41d73-5b8d30f1' \
  'R1 operation=shared-module-restore target=wg_mix_faketcp_checksum helper=c8_checksum_module_restore argv=/usr/sbin/rmmod wg_mix_faketcp_checksum' \
  'B1 operation=runtime-temp-mkdir target=/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost-5b8d30f1 argv=/usr/bin/mkdir --mode=0700 -- /run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost-5b8d30f1' \
  'R2 operation=offload-tso-restore target=wg5b8d3a:tso=on argv=/usr/sbin/ethtool -K wg5b8d3a tso on' \
  'R3 operation=neighbor-delete target=wg5b8d3a:198.18.82.2 argv=/usr/sbin/ip -4 neigh del 198.18.82.2 lladdr 02:5b:8d:30:f1:0b nud permanent dev wg5b8d3a' \
  'R4 operation=route-delete target=198.18.82.2/32 argv=/usr/sbin/ip -4 route del 198.18.82.2/32 dev wg5b8d3a src 198.18.82.1 mtu 1500 proto static scope link' \
  'R5 operation=address-delete target=wg5b8d3a:198.18.82.1/32 argv=/usr/sbin/ip -4 address del 198.18.82.1/32 dev wg5b8d3a scope global' \
  'R6 operation=veth-delete target=wg5b8d3a argv=/usr/sbin/ip link delete dev wg5b8d3a' \
  'B82_ROUTED_VETH_RESTORE_ORDER cleanup-intent,bpf-baseline,module,offload,neighbor,route,address,veth,bpf-baseline,restored retryable=1 exact_reverse=1' \
  'af_packet=none,partial,gso:route-unknown-negative routed=iphdrincl-none,udp-partial,udp-segment-gso:positive capability_bits_changed=0' \
  'B82_ROUTED_VETH_PLAN_COMPLETE commands_are_review_templates=1 preflight_before_host_mutation=1 network_downloads=bounded-go-module-proxy-only no_commands_executed=1 credential_read=0 remote_connections=0 network_operations=0'; do
  [[ "${PLAN_OUTPUT}" == *"${literal}"* ]] || fail "runner plan is missing ${literal}"
done

for spec in \
  'C0 operation=go-cache-mkdir target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-cache' \
  'C1 operation=go-mod-cache-mkdir target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-mod-cache' \
  'C2 operation=go-path-mkdir target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-path' \
  'C3 operation=go-tmp-mkdir target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-tmp'; do
  [[ "${PLAN_OUTPUT}" == *"${spec}"* ]] || fail "runner plan is missing clean-cache producer ${spec}"
done
[[ "${PLAN_OUTPUT}" == *'P0 operation=preflight-mod-download target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-mod-cache argv='* ]] ||
  fail 'runner plan is missing the bounded clean-cache dependency producer'
[[ "${PLAN_OUTPUT}" == *'P1 operation=preflight-mod-verify target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-mod-cache argv='* ]] ||
  fail 'runner plan is missing the offline produced-module verification'
[[ "${PLAN_OUTPUT}" == *'P2 operation=preflight-build target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/dataplane-preflight.test argv='* ]] ||
  fail 'runner plan is missing the pre-mutation compiled test binary'
for artifact_step in \
  'P.artifact-intent operation=artifact-intent target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/phase-artifact-intent.v1 argv=internal:noclobber-phase-0600' \
  'P.artifact-build operation=artifact-build target=/run/wg-mix-ebpf-source-stages/c8e41d73/source/build argv=' \
  'P.artifact-mode operation=artifact-mode target=/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/wg_mix_faketcp_experimental.o:/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/wg_mix_tc.o:/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/faketcp_checksum_kmod/wg_mix_faketcp_checksum.ko argv=' \
  'P.artifact-receipt operation=artifact-receipt target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/phase-artifacts.v1 argv=internal:noclobber-phase-0600'; do
  [[ "${PLAN_OUTPUT}" == *"${artifact_step}"* ]] ||
    fail "runner plan is missing artifact authority ${artifact_step}"
done
require_ordered_literals "${PLAN_OUTPUT}" \
  'P0 operation=preflight-mod-download ' \
  'P1 operation=preflight-mod-verify ' \
  'P.artifact-intent operation=artifact-intent ' \
  'P.artifact-build operation=artifact-build ' \
  'P.artifact-mode operation=artifact-mode ' \
  'P.artifact-receipt operation=artifact-receipt ' \
  'P2 operation=preflight-build '
artifact_build_line="$(printf '%s\n' "${PLAN_OUTPUT}" | /usr/bin/grep -F \
  'P.artifact-build operation=artifact-build ')" || fail 'cannot isolate artifact build argv'
[[ "${artifact_build_line}" == *'GOPROXY=off GOSUMDB=off'* ]] ||
  fail 'artifact producer is not offline after the bounded dependency download'
[[ "${PLAN_OUTPUT}" == *'GOMODCACHE=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-mod-cache'* ]] ||
  fail 'clean-stage producer does not use the routed evidence-owned module cache'
[[ "${PLAN_OUTPUT}" == *'GOTMPDIR=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-tmp TMPDIR=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-tmp'* ]] ||
  fail 'Go preflight does not use the routed evidence-owned temp root'
download_line="$(printf '%s\n' "${PLAN_OUTPUT}" | /usr/bin/grep -F 'P0 operation=preflight-mod-download ')" ||
  fail 'cannot isolate the dependency producer argv'
[[ "${download_line}" == *'GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org'* ]] ||
  fail 'dependency producer is not bound to the reviewed Go module proxy'
for offline_label in \
  'P1 operation=preflight-mod-verify ' \
  'P2 operation=preflight-build '; do
  offline_line="$(printf '%s\n' "${PLAN_OUTPUT}" | /usr/bin/grep -F "${offline_label}")" ||
    fail "cannot isolate offline consumer ${offline_label}"
  [[ "${offline_line}" == *'GOPROXY=off GOSUMDB=off'* ]] ||
    fail "post-download consumer is not offline: ${offline_label}"
done
preflight_offset="${PLAN_OUTPUT%%P.contract operation=preflight-contract*}"
runtime_temp_offset="${PLAN_OUTPUT%%B1 operation=runtime-temp-mkdir*}"
mutation_offset="${PLAN_OUTPUT%%N0 operation=veth-add*}"
(( ${#preflight_offset} < ${#runtime_temp_offset} && ${#runtime_temp_offset} < ${#mutation_offset} )) ||
  fail 'contract preflight and runtime temp are not ordered before the first host mutation'

[[ "${PLAN_OUTPUT}" == *'operation=list:TestFakeTCPRealHostRoutedHarnessSelectedBinaryContract target=TestFakeTCPRealHostRoutedHarnessSelectedBinaryContract argv='* ]] ||
  fail 'runner plan is missing the selected-binary contract definition gate'
[[ "${PLAN_OUTPUT}" == *'P.contract operation=preflight-contract target=TestFakeTCPRealHostRoutedHarnessSelectedBinaryContract argv='* ]] ||
  fail 'runner plan is missing the selected-binary contract execution gate'

for test_name in \
  TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration \
  TestFakeTCPRealHostRoutedIPHdrInclNone \
  TestFakeTCPRealHostRoutedUDPSocketPartial \
  TestFakeTCPRealHostRoutedUDPSegmentGSO; do
  [[ "${PLAN_OUTPUT}" == *"operation=list:${test_name} target=${test_name} argv="* ]] ||
    fail "runner plan is missing list operation for ${test_name}"
  [[ "${PLAN_OUTPUT}" == *"dataplane-preflight.test -test.list \\^${test_name}\\\$"* ]] ||
    fail "clean-stage fixture does not list ${test_name} from the prebuilt binary"
  [[ "${PLAN_OUTPUT}" == *"operation=test:${test_name} target=${test_name} argv="* ]] ||
    fail "runner plan is missing test operation for ${test_name}"
  test_line="$(printf '%s\n' "${PLAN_OUTPUT}" | /usr/bin/grep -F "operation=test:${test_name} ")" ||
    fail "runner plan cannot isolate test operation for ${test_name}"
  [[ "${test_line}" == *'TMPDIR=/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost-5b8d30f1'* ]] ||
    fail "selected binary contract TMPDIR drifted for ${test_name}"
  [[ "${test_line}" == *'WG_MIX_FAKETCP_REALHOST_RUN_ID=c8e41d73'* &&
    "${test_line}" == *'WG_MIX_FAKETCP_REALHOST_RESOURCE_ID=5b8d30f1'* ]] ||
    fail "selected binary stage/resource identity drifted for ${test_name}"
  [[ "${test_line}" != *'TMPDIR=/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp '* ]] ||
    fail "selected binary still receives the generic Go preflight TMPDIR for ${test_name}"
done

WRITE_SET_LINE="$(printf '%s\n' "${PLAN_OUTPUT}" | /usr/bin/grep -F \
  'B82_ROUTED_VETH_WRITE_SET filesystem=')" || fail 'cannot isolate routed write set'
readonly WRITE_SET_LINE
readonly EXPECTED_FILESYSTEM_WRITE_SET='/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1,/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/dataplane-preflight.test,/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-cache,/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-mod-cache,/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-path,/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-tmp,/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost-5b8d30f1,/run/wg-mix-ebpf-source-stages/c8e41d73/source/build'
[[ "${WRITE_SET_LINE}" == "B82_ROUTED_VETH_WRITE_SET filesystem=${EXPECTED_FILESYSTEM_WRITE_SET} shared_lock="* ]] ||
  fail 'write set does not contain the exact eight retained filesystem authorities'
[[ "${PLAN_OUTPUT}" == *'/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/go-mod-cache'* ]] ||
  fail 'write set does not declare the routed dependency cache producer'
[[ "${PLAN_OUTPUT}" == *'shared_lock=/run/wg-mix-ebpf-source-stages/c8e41d73/checksum-module-lease.v1.lock:advisory-only'* &&
  "${PLAN_OUTPUT}" == *'module=wg_mix_faketcp_checksum,lease_id:c8e41d73-5b8d30f1'* ]] ||
  fail 'write set does not declare the shared module lock and exact lease token'

for central_owned in \
  'veth=wgc8e41a,wgc8e41b' \
  'wg-mix-ebpf:c8e41d73:a' \
  'wg-mix-ebpf:c8e41d73:b' \
  '/run/wg-mix-ebpf-source-stages/c8e41d73/realhost-v6-6bd913ac' \
  '/run/wg-mix-ebpf-source-stages/c8e41d73/go-cache-realhost' \
  '/run/wg-mix-ebpf-source-stages/c8e41d73/go-mod-cache-realhost' \
  '/run/wg-mix-ebpf-source-stages/c8e41d73/go-path-realhost' \
  '/sys/fs/bpf/wg-mix-ebpf-c8e41d73-tcx'; do
  [[ "${PLAN_OUTPUT}" != *"${central_owned}"* ]] ||
    fail "routed write set collides with controller matrix resource ${central_owned}"
done

for forbidden in \
  '/usr/bin/ssh' '/usr/bin/scp' '/usr/bin/sudo' 'credientials/' \
  '192.168.10.28' '47.116.202.155' 'ip netns' 'rm -rf' 'find -delete'; do
  [[ "${PLAN_OUTPUT}" != *"${forbidden}"* ]] || fail "runner plan contains forbidden ${forbidden}"
  [[ "${SEAM_OUTPUT}" != *"${forbidden}"* ]] || fail "seam plan contains forbidden ${forbidden}"
done

if [[ "${STAGED_CONTEXT}" == exact ]]; then
  [[ "${SEAM_OUTPUT}" == *"B82_ROUTED_VETH_PLAN_ONLY run_id=c8e41d73 resource_id=5b8d30f1 commit=${COMMIT}"* &&
    "${SEAM_OUTPUT}" == *'B82_ROUTED_VETH_PLAN_COMPLETE commands_are_review_templates=1'* ]] ||
    fail 'controller seam did not execute the exact staged runner plan'
else
  # These patterns intentionally match literal variable references in generated shell.
  # shellcheck disable=SC2016
  [[ "${SEAM_OUTPUT}" == *'/bin/bash -p "${ROOT_RUNNER}" "${MODE}"'* &&
    "${SEAM_OUTPUT}" == *'--source "${SOURCE}"'* &&
    "${SEAM_OUTPUT}" == *'--commit "${COMMIT}"'* &&
    "${SEAM_OUTPUT}" == *'exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "${RUNNER_ARGV[@]}"'* ]] ||
    fail 'controller seam fixed exec authority'
fi

expect_failure invalid-mode /bin/bash "${RUNNER}" execute "${RUNNER_ARGS[@]}"
expect_failure wrong-source /bin/bash "${RUNNER}" plan \
  --source /run/wg-mix-ebpf-source-stages/aaaaaaaa/source \
  --commit "${COMMIT}"
expect_failure short-commit /bin/bash "${RUNNER}" plan \
  --source "${SOURCE}" --commit aaaaaaaa
expect_failure duplicate-commit /bin/bash "${RUNNER}" plan "${RUNNER_ARGS[@]}" --commit "${COMMIT}"
expect_failure extra-argv /bin/bash "${SEAM}" plan "${SEAM_ARGS[@]}" --remote-argv arbitrary

if [[ "${STAGED_CONTEXT}" == absent ]]; then
  [[ ! -e "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] ||
    fail 'plan or failure fixture mutated the absent stage root'
fi
printf 'hermetic routed-veth runner, executable empty-cache producer, controller seam=%s, exact argv and lifecycle model: PASS\n' \
  "${STAGED_CONTEXT}"
