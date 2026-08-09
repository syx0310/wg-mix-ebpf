#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

REVIEW_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)" || exit 70
readonly REVIEW_ROOT
REPOSITORY="$(CDPATH= cd -- "${REVIEW_ROOT}/../.." && pwd -P)" || exit 70
readonly REPOSITORY
readonly RUNNER="${REVIEW_ROOT}/root-routed-veth-n-r.sh"
readonly SEAM="${REVIEW_ROOT}/controller-seam.sh"
readonly STATIC_TEST="${REVIEW_ROOT}/test_routed_veth_harness_static.py"
readonly SOURCE='/run/wg-mix-ebpf-source-stages/c8e41d73/source'
readonly STAGE_ROOT='/run/wg-mix-ebpf-source-stages/c8e41d73'
readonly COMMIT='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly EXPERIMENTAL_SHA='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly BASELINE_SHA='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
readonly MODULE_SHA='dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
readonly BASE_COMMIT='3ea1cf0272197d580e90d51c8997352e79c47ba9'
readonly LOCKED_STANDALONE='scripts/realhost-b82-c8e41d73/root-veth-n-r.sh'

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

for path in "${RUNNER}" "${SEAM}" "${STATIC_TEST}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "fixture is not a regular file: ${path}"
done

/bin/bash -n "${RUNNER}" "${SEAM}" "$0" || fail 'Bash syntax gate'
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I "${STATIC_TEST}" "${RUNNER}" "${SEAM}" ||
  fail 'static safety and lifecycle model'
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${RUNNER}" "${SEAM}" "$0" || fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable locally; .82 execution remains shellcheck-gated\n'
fi

/usr/bin/git -C "${REPOSITORY}" diff --exit-code "${BASE_COMMIT}" -- "${LOCKED_STANDALONE}" ||
  fail 'new routed harness changed the reviewer-locked standalone runner'

readonly -a RUNNER_ARGS=(
  --source "${SOURCE}"
  --commit "${COMMIT}"
  --experimental-sha256 "${EXPERIMENTAL_SHA}"
  --baseline-sha256 "${BASELINE_SHA}"
  --module-sha256 "${MODULE_SHA}"
)
readonly -a SEAM_ARGS=(
  --commit "${COMMIT}"
  --experimental-sha256 "${EXPERIMENTAL_SHA}"
  --baseline-sha256 "${BASELINE_SHA}"
  --module-sha256 "${MODULE_SHA}"
)

[[ ! -e "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] ||
  fail 'hermetic plan refuses a pre-existing production stage path'
PLAN_OUTPUT="$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /bin/bash "${RUNNER}" plan "${RUNNER_ARGS[@]}")" ||
  fail 'root runner plan'
readonly PLAN_OUTPUT
SEAM_OUTPUT="$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /bin/bash "${SEAM}" plan "${SEAM_ARGS[@]}")" ||
  fail 'controller seam plan'
readonly SEAM_OUTPUT

for literal in \
  'B82_ROUTED_VETH_PLAN_ONLY run_id=c8e41d73 resource_id=5b8d30f1' \
  'state_schema=owner,baseline,operation-intent,dependency-preflight,veth-intent,veth,address,route,neighbor,offload,module,tested,cleanup-intent,restored' \
  'netns=initial veth=wg5b8d3a,wg5b8d3b sender=198.18.82.1/32 peer=wg5b8d3b/unnumbered route=198.18.82.2/32 mtu=1500 neighbor=02:5b:8d:30:f1:0b no_external_peer=1' \
  'N5 operation=address-add target=wg5b8d3a:198.18.82.1/32 argv=/usr/sbin/ip -4 address add 198.18.82.1/32 dev wg5b8d3a scope global' \
  'N6 operation=route-add target=198.18.82.2/32 argv=/usr/sbin/ip -4 route add 198.18.82.2/32 dev wg5b8d3a src 198.18.82.1 mtu 1500 proto static scope link' \
  'N7 operation=neighbor-add target=wg5b8d3a:198.18.82.2 argv=/usr/sbin/ip -4 neigh add 198.18.82.2 lladdr 02:5b:8d:30:f1:0b nud permanent dev wg5b8d3a' \
  'N1 operation=veth-alias-a target=wg5b8d3a argv=/usr/sbin/ip link set dev wg5b8d3a alias wg-mix-ebpf:c8e41d73:5b8d30f1:a' \
  'N2 operation=veth-alias-b target=wg5b8d3b argv=/usr/sbin/ip link set dev wg5b8d3b alias wg-mix-ebpf:c8e41d73:5b8d30f1:b' \
  'N9 operation=offload-tso-off target=wg5b8d3a:tso=off argv=/usr/sbin/ethtool -K wg5b8d3a tso off' \
  'B1 operation=runtime-temp-mkdir target=/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost-5b8d30f1 argv=/usr/bin/mkdir --mode=0700 -- /run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost-5b8d30f1' \
  'R2 operation=offload-tso-restore target=wg5b8d3a:tso=on argv=/usr/sbin/ethtool -K wg5b8d3a tso on' \
  'R3 operation=neighbor-delete target=wg5b8d3a:198.18.82.2 argv=/usr/sbin/ip -4 neigh del 198.18.82.2 lladdr 02:5b:8d:30:f1:0b nud permanent dev wg5b8d3a' \
  'R4 operation=route-delete target=198.18.82.2/32 argv=/usr/sbin/ip -4 route del 198.18.82.2/32 dev wg5b8d3a src 198.18.82.1 mtu 1500 proto static scope link' \
  'R5 operation=address-delete target=wg5b8d3a:198.18.82.1/32 argv=/usr/sbin/ip -4 address del 198.18.82.1/32 dev wg5b8d3a scope global' \
  'R6 operation=veth-delete target=wg5b8d3a argv=/usr/sbin/ip link delete dev wg5b8d3a' \
  'B82_ROUTED_VETH_RESTORE_ORDER cleanup-intent,bpf-baseline,module,offload,neighbor,route,address,veth,bpf-baseline,restored retryable=1 exact_reverse=1' \
  'af_packet=none,partial,gso:route-unknown-negative routed=iphdrincl-none,udp-partial,udp-segment-gso:positive capability_bits_changed=0' \
  'B82_ROUTED_VETH_PLAN_COMPLETE commands_are_review_templates=1 preflight_before_host_mutation=1 network_downloads=0 no_commands_executed=1 credential_read=0 remote_connections=0 network_operations=0'; do
  [[ "${PLAN_OUTPUT}" == *"${literal}"* ]] || fail "runner plan is missing ${literal}"
done

[[ "${PLAN_OUTPUT}" == *'P0 operation=preflight-mod-verify target=/run/wg-mix-ebpf-source-stages/c8e41d73/go-mod-cache argv='* ]] ||
  fail 'runner plan is missing the offline staged-module verification'
[[ "${PLAN_OUTPUT}" == *'P1 operation=preflight-build target=/run/wg-mix-ebpf-source-stages/c8e41d73/routed-evidence-5b8d30f1/dataplane-preflight.test argv='* ]] ||
  fail 'runner plan is missing the pre-mutation compiled test binary'
[[ "${PLAN_OUTPUT}" == *'GOMODCACHE=/run/wg-mix-ebpf-source-stages/c8e41d73/go-mod-cache'* ]] ||
  fail 'clean-stage fixture does not reuse the bound staged module cache'
[[ "${PLAN_OUTPUT}" == *'GOTMPDIR=/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp TMPDIR=/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp'* ]] ||
  fail 'Go preflight does not use the generic staged temp root'
[[ "${PLAN_OUTPUT}" != *'go-mod-cache-routed'* && "${PLAN_OUTPUT}" != *'go-cache-routed'* ]] ||
  fail 'clean-stage fixture still depends on an empty routed-only cache'
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

[[ "${PLAN_OUTPUT}" == *'B82_ROUTED_VETH_WRITE_SET filesystem='*'/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost-5b8d30f1 network='* ]] ||
  fail 'write set does not declare the retained real-host TMPDIR'

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

[[ "${SEAM_OUTPUT}" == *'B82_ROUTED_CONTROLLER_SEAM_PLAN run_id=c8e41d73 target=192.168.10.82 credential_read=0 remote_connections=0 argv='* ]] ||
  fail 'controller seam plan header'
[[ "${SEAM_OUTPUT}" == *'/bin/bash -p /run/wg-mix-ebpf-source-stages/c8e41d73/source/scripts/realhost-b82-routed-veth-v1/root-routed-veth-n-r.sh plan'* ]] ||
  fail 'controller seam exact root-runner argv'
[[ "${SEAM_OUTPUT}" == *'B82_ROUTED_CONTROLLER_SEAM_PLAN_COMPLETE transport_integration=pending no_commands_executed=1'* ]] ||
  fail 'controller seam completion'

expect_failure invalid-mode /bin/bash "${RUNNER}" execute "${RUNNER_ARGS[@]}"
expect_failure wrong-source /bin/bash "${RUNNER}" plan \
  --source /run/wg-mix-ebpf-source-stages/aaaaaaaa/source \
  --commit "${COMMIT}" --experimental-sha256 "${EXPERIMENTAL_SHA}" \
  --baseline-sha256 "${BASELINE_SHA}" --module-sha256 "${MODULE_SHA}"
expect_failure short-commit /bin/bash "${RUNNER}" plan \
  --source "${SOURCE}" --commit aaaaaaaa --experimental-sha256 "${EXPERIMENTAL_SHA}" \
  --baseline-sha256 "${BASELINE_SHA}" --module-sha256 "${MODULE_SHA}"
expect_failure duplicate-commit /bin/bash "${RUNNER}" plan "${RUNNER_ARGS[@]}" --commit "${COMMIT}"
expect_failure extra-argv /bin/bash "${SEAM}" plan "${SEAM_ARGS[@]}" --remote-argv arbitrary

[[ ! -e "${STAGE_ROOT}" && ! -L "${STAGE_ROOT}" ]] || fail 'plan or failure fixture mutated the stage root'
printf 'hermetic routed-veth runner, controller seam, exact argv and lifecycle model: PASS\n'
