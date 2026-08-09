#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

REVIEW_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)" || exit 70
readonly REVIEW_ROOT
REPOSITORY="$(CDPATH= cd -- "${REVIEW_ROOT}/../.." && pwd -P)" || exit 70
readonly REPOSITORY
readonly RUNNER="${REVIEW_ROOT}/root-veth-n-r.sh"
readonly STATIC_TEST="${REVIEW_ROOT}/test_veth_runner_static.py"
readonly MATRIX="${REVIEW_ROOT}/root-matrix-n-r.sh"
readonly CONTROLLER_SOURCE='/run/wg-mix-ebpf-source-stages/c8e41d73/source'
readonly BUNDLE='/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle'
readonly VETH_STAGE='/run/wg-mix-ebpf-source-stages/a19f7c2e'
readonly COMMIT='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly BUNDLE_SHA256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly STANDALONE_BASE_COMMIT='90b1205decfa7267bac0d7839067ef868ca49942'
readonly INTEGRATION_MERGE_COMMIT='2abfd1a67dcb6ba951b9e382da312264d161855b'
readonly INTEGRATION_PARENT_COMMIT='7a13c8709b72185ceda8eaa595fdf425b8c5557c'
readonly OFFLOAD_BASE_COMMIT='4ab01b7cb7f8f0551133df9c342a619b3b9a0c57'

readonly -a CONTROLLER_FILES=(
  scripts/realhost-b82-c8e41d73/bind-final-package.sh
  scripts/realhost-b82-c8e41d73/controller.sh
  scripts/realhost-b82-c8e41d73/locked-transport.exp
  scripts/realhost-b82-c8e41d73/prepare-stage-root.sh
  scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh
)
readonly -a GSO_TESTS=(
  TestFakeTCPRealHostVirtioNetHeaderEncoding
  TestFakeTCPRealHostGSOOutputMatcher
  TestFakeTCPRealHostGSOProbeIsolationContract
)

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

for path in "${RUNNER}" "${STATIC_TEST}" "${MATRIX}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "fixture input is not a regular file: ${path}"
done

/bin/bash -n "${RUNNER}" "$0" || fail 'Bash syntax gate'
/usr/bin/python3 -I "${STATIC_TEST}" "${RUNNER}" "${MATRIX}" || fail 'static runner contract'

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${RUNNER}" "$0" || fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable locally; remote execution remains review-gated\n'
fi

BOUND_COMMIT="$(/usr/bin/git -C "${REPOSITORY}" rev-parse --verify HEAD^{commit})" ||
  fail 'cannot bind the hermetic fixture to HEAD'
readonly BOUND_COMMIT
[[ "${BOUND_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || fail 'bound commit is malformed'

MERGE_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P "${INTEGRATION_MERGE_COMMIT}")" ||
  fail 'cannot read integration merge parents'
readonly MERGE_PARENTS
[[ "${MERGE_PARENTS}" == "${STANDALONE_BASE_COMMIT} ${INTEGRATION_PARENT_COMMIT}" ]] ||
  fail 'integration merge does not preserve the reviewed two-parent topology'

/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor \
  "${INTEGRATION_MERGE_COMMIT}" "${BOUND_COMMIT}" ||
  fail 'bound commit does not descend from the explicit integration merge'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor \
  "${OFFLOAD_BASE_COMMIT}" "${BOUND_COMMIT}" ||
  fail 'bound commit does not contain reviewed GSO isolation history'

# Cover both the standalone commit's parent edge and every committed tree since it.
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${STANDALONE_BASE_COMMIT}^" "${STANDALONE_BASE_COMMIT}" -- "${CONTROLLER_FILES[@]}" ||
  fail 'standalone base changed an existing controller or matrix file'
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${STANDALONE_BASE_COMMIT}" "${BOUND_COMMIT}" -- "${CONTROLLER_FILES[@]}" ||
  fail 'committed standalone history changed an existing controller or matrix file'
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${BOUND_COMMIT}" -- "${CONTROLLER_FILES[@]}" ||
  fail 'working tree changed an existing controller or matrix file'

GSO_SOURCE="$(/usr/bin/git -C "${REPOSITORY}" show \
  "${BOUND_COMMIT}:internal/dataplane/faketcp_realhost_linux_test.go")" ||
  fail 'cannot read GSO tests from the bound commit tree'
readonly GSO_SOURCE
for test_name in "${GSO_TESTS[@]}"; do
  definition_count="$(printf '%s\n' "${GSO_SOURCE}" | /usr/bin/grep -Ec \
    "^func ${test_name}\\(t \\*testing\\.T\\) \\{$")"
  [[ "${definition_count}" == 1 ]] ||
    fail "bound commit must define exactly one real ${test_name} test function"
done

[[ ! -e "${VETH_STAGE}" && ! -L "${VETH_STAGE}" ]] ||
  fail 'local fixture refuses a pre-existing production veth stage path'

readonly -a PLAN_ARGS=(
  --controller-source "${CONTROLLER_SOURCE}"
  --commit "${COMMIT}"
  --bundle "${BUNDLE}"
  --bundle-sha256 "${BUNDLE_SHA256}"
  --wg-state absent
)

PLAN_OUTPUT="$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
  /bin/bash "${RUNNER}" plan "${PLAN_ARGS[@]}")" || fail 'standalone plan'
readonly PLAN_OUTPUT

for literal in \
  'B82_VETH_V6_PLAN_ONLY controller_run_id=c8e41d73 run_id=a19f7c2e resource_id=d34b8e65' \
  'state_schema=owner,baseline,mutation-plan,veth,tcx,module,cleanup-intent,restored|filesystem-retained' \
  'wg_state=absent wg_active_scoped=not-covered pass=0' \
  'raw_ens33=not-covered raw_ens33_pass=0 peer_47=read-only peer_access=0' \
  'B0 operation=stage-mkdir target=/run/wg-mix-ebpf-source-stages/a19f7c2e argv=/usr/bin/mkdir --mode=0700 -- /run/wg-mix-ebpf-source-stages/a19f7c2e' \
  'S0.copy operation=bundle-copy target=/run/wg-mix-ebpf-source-stages/a19f7c2e/source-4f2a9b61-d34b8e65.bundle argv=/usr/bin/timeout --signal=TERM --kill-after=10s 2m /usr/bin/cp --no-clobber --no-preserve=mode\,ownership\,timestamps' \
  'S1 operation=source-clone target=/run/wg-mix-ebpf-source-stages/a19f7c2e/source argv=/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C' \
  'N.add operation=veth-add target=wga19f7a:wga19f7b argv=/usr/sbin/ip link add wga19f7a address 02:a1:9f:7c:2e:0a type veth peer name wga19f7b address 02:a1:9f:7c:2e:0b' \
  'T.run operation=tcx-run target=exact-tcx-run argv=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C' \
  'WG_MIX_EBPF_TEST_ACTION=run' \
  'R.tcx operation=tcx-restore target=exact-tcx-restore argv=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C' \
  'WG_MIX_EBPF_TEST_ACTION=restore' \
  'M.load operation=module-load target=wg_mix_faketcp_checksum argv=/usr/sbin/insmod' \
  'R.module operation=module-unload target=wg_mix_faketcp_checksum argv=/usr/sbin/rmmod wg_mix_faketcp_checksum' \
  'R.veth-a operation=veth-delete target=wga19f7a argv=/usr/sbin/ip link delete dev wga19f7a' \
  'R.veth-b operation=veth-delete-b target=wga19f7b argv=/usr/sbin/ip link delete dev wga19f7b' \
  'B82_VETH_V6_WRITE_SET stage=/run/wg-mix-ebpf-source-stages/a19f7c2e' \
  'B82_VETH_V6_PLAN_COMPLETE argv_builder=shared commands_are_review_templates=1 no_commands_executed=1 credential_read=0 network_operations=0 capability_bits_changed=0'; do
  [[ "${PLAN_OUTPUT}" == *"${literal}"* ]] || fail "plan is missing ${literal}"
done

# Both independently conditional cleanup builders must remain visible exactly once.
for exact_line in \
  'R.veth-a operation=veth-delete target=wga19f7a argv=/usr/sbin/ip link delete dev wga19f7a ' \
  'R.veth-b operation=veth-delete-b target=wga19f7b argv=/usr/sbin/ip link delete dev wga19f7b '; do
  line_count="$(printf '%s\n' "${PLAN_OUTPUT}" | /usr/bin/grep -Fxc -- "${exact_line}")"
  [[ "${line_count}" == 1 ]] || fail "plan must contain exactly one ${exact_line}"
done
[[ "${PLAN_OUTPUT}" != *$'\nR.veth operation='* ]] ||
  fail 'plan retains the obsolete single-delete operation'

for test_name in "${GSO_TESTS[@]}"; do
  [[ "${PLAN_OUTPUT}" == *"operation=list:${test_name} target=${test_name} argv="* ]] ||
    fail "plan is missing list operation for ${test_name}"
  [[ "${PLAN_OUTPUT}" == *"operation=offload:${test_name} target=${test_name} argv="* ]] ||
    fail "plan is missing execution operation for ${test_name}"
done

for literal in \
  'TestFakeTCPBPFPacketProbe' \
  'TestExperimentalFakeTCPRealHostLifecycleIntegration' \
  'TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration' \
  'TestBaselineExperimentalRealHostMutualExclusionIntegration'; do
  [[ "${PLAN_OUTPUT}" == *"${literal}"* ]] || fail "plan is missing ${literal}"
done

for forbidden in \
  '/usr/bin/ssh' '/usr/bin/scp' '/usr/bin/sudo' 'credientials/' \
  'ethtool -K' 'ip link set dev ens33' 'WG_MIX_EBPF_RUN_SCOPED_REALNIC_INTEGRATION=1' \
  'REVIEWED_GO_ENV'; do
  [[ "${PLAN_OUTPUT}" != *"${forbidden}"* ]] || fail "plan contains forbidden ${forbidden}"
done

[[ ! -e "${VETH_STAGE}" && ! -L "${VETH_STAGE}" ]] || fail 'plan created the veth stage'

expect_failure invalid-mode /bin/bash "${RUNNER}" matrix "${PLAN_ARGS[@]}"
expect_failure bound-wireguard /bin/bash "${RUNNER}" plan \
  --controller-source "${CONTROLLER_SOURCE}" --commit "${COMMIT}" \
  --bundle "${BUNDLE}" --bundle-sha256 "${BUNDLE_SHA256}" --wg-state bound
expect_failure wrong-controller-source /bin/bash "${RUNNER}" plan \
  --controller-source /run/wg-mix-ebpf-source-stages/a19f7c2e/source --commit "${COMMIT}" \
  --bundle "${BUNDLE}" --bundle-sha256 "${BUNDLE_SHA256}" --wg-state absent
expect_failure malformed-commit /bin/bash "${RUNNER}" plan \
  --controller-source "${CONTROLLER_SOURCE}" --commit HEAD \
  --bundle "${BUNDLE}" --bundle-sha256 "${BUNDLE_SHA256}" --wg-state absent
expect_failure extra-argument /bin/bash "${RUNNER}" plan "${PLAN_ARGS[@]}" --remote-argv arbitrary

# Every supported option is single-assignment; the second --commit is explicit.
expect_failure duplicate-controller-source /bin/bash "${RUNNER}" plan \
  "${PLAN_ARGS[@]}" --controller-source "${CONTROLLER_SOURCE}"
expect_failure duplicate-commit-second-commit /bin/bash "${RUNNER}" plan \
  "${PLAN_ARGS[@]}" --commit "${COMMIT}"
expect_failure duplicate-bundle /bin/bash "${RUNNER}" plan \
  "${PLAN_ARGS[@]}" --bundle "${BUNDLE}"
expect_failure duplicate-bundle-sha256 /bin/bash "${RUNNER}" plan \
  "${PLAN_ARGS[@]}" --bundle-sha256 "${BUNDLE_SHA256}"
expect_failure duplicate-wg-state /bin/bash "${RUNNER}" plan \
  "${PLAN_ARGS[@]}" --wg-state absent

[[ ! -e "${VETH_STAGE}" && ! -L "${VETH_STAGE}" ]] ||
  fail 'failure fixtures or duplicate-option fixtures created the veth stage'
printf 'hermetic standalone veth plan, shared argv, strict single-assignment argv, commit-tree GSO definitions and no-controller history: PASS\n'
