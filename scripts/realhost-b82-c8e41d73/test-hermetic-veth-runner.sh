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
readonly MODULE_LEASE_HELPER="${REVIEW_ROOT}/checksum-module-lease.sh"
readonly CONTROLLER_SOURCE='/run/wg-mix-ebpf-source-stages/c8e41d73/source'
readonly BUNDLE='/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle'
readonly VETH_STAGE='/run/wg-mix-ebpf-source-stages/a19f7c2e'
readonly COMMIT='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly BUNDLE_SHA256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly STANDALONE_BASE_COMMIT='90b1205decfa7267bac0d7839067ef868ca49942'
readonly INTEGRATION_MERGE_COMMIT='2abfd1a67dcb6ba951b9e382da312264d161855b'
readonly INTEGRATION_PARENT_COMMIT='7a13c8709b72185ceda8eaa595fdf425b8c5557c'
readonly OFFLOAD_BASE_COMMIT='4ab01b7cb7f8f0551133df9c342a619b3b9a0c57'
readonly CONTROLLER_LEASE_TIP='eb46d2d6142e6d91b34f031c8a198b35ce927879'
readonly CANONICAL_FINAL='8f6418c4877eb29d163080402381da2ba9bb3b2b'
readonly CANONICAL_MERGE='232aad72afa9327985d869eb80aad7e359201a36'
readonly STANDALONE_SCOPE_COMMIT='1c4102b96d28657b60ee58314c7088069c59eea9'
readonly SINGLE_L3_PARENT='cecf74ceded6b13a770d7b02283abe45de2faedb'
readonly SINGLE_L3_FINAL='ad31ae79af828b756c884ae342f8e4f51a6bacf7'
readonly SINGLE_L3_MERGE='15e2122a74738ed1904465e1f1e8e75f4892c4b2'
readonly MANAGED_INGRESS_BASE='d28585bfaaefe44c0e71d2cbbced494da96dd7fa'
readonly MANAGED_INGRESS_ACCOUNTING='eb1b90ec4d73267e2eaebc313e82cfd81351fe23'
readonly MANAGED_INGRESS_PRODUCTION='829e6f2e5664207cecb52ccb0b55e4ed9f9533ff'
readonly MANAGED_INGRESS_ACCEPTANCE_ROOT='ea8af467ba9d4a7ee526391cc8f030dde27f61fb'
readonly MANAGED_INGRESS_ACCEPTANCE='26587191a8ba1e75e372889cd7c851ad926319fc'

readonly -a CONTROLLER_FILES=(
  scripts/realhost-b82-c8e41d73/bind-final-package.sh
  scripts/realhost-b82-c8e41d73/controller.sh
  scripts/realhost-b82-c8e41d73/locked-transport.exp
  scripts/realhost-b82-c8e41d73/prepare-stage-root.sh
  scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh
)
readonly -a ORIGINAL_MERGE_RESOLUTION_BLOBS=(
  'scripts/realhost-b82-c8e41d73/prepare-stage-root.sh c955b4508fb55728cf948a0cc2fb1b0109df6078'
  'scripts/realhost-b82-c8e41d73/test-hermetic-controller.sh 93b4c576c42ef269c2ae718fac7c68f1f2b12f9c'
  'scripts/realhost-b82-c8e41d73/test_controller_static.py 9273502f2b8ab54bf810b36ce7a935734d244ec0'
)
readonly -a GSO_TESTS=(
  TestFakeTCPRealHostVirtioNetHeaderEncoding
  TestFakeTCPRealHostGSOOutputMatcher
  TestFakeTCPRealHostGSOProbeIsolationContract
)
readonly -a WORKTREE_BOUND_FILES=(
  scripts/realhost-b82-c8e41d73/root-veth-n-r.sh
  scripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh
  scripts/realhost-b82-c8e41d73/test_veth_runner_static.py
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

for path in "${RUNNER}" "${STATIC_TEST}" "${MATRIX}" "${MODULE_LEASE_HELPER}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "fixture input is not a regular file: ${path}"
done

/bin/bash -n "${RUNNER}" "${MODULE_LEASE_HELPER}" "$0" || fail 'Bash syntax gate'
/usr/bin/python3 -I "${STATIC_TEST}" "${RUNNER}" "${MATRIX}" "${MODULE_LEASE_HELPER}" ||
  fail 'static runner contract'

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${RUNNER}" "${MODULE_LEASE_HELPER}" "$0" ||
    fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable locally; remote execution remains review-gated\n'
fi

BOUND_COMMIT="$(/usr/bin/git -C "${REPOSITORY}" rev-parse --verify HEAD^{commit})" ||
  fail 'cannot bind the hermetic fixture to HEAD'
readonly BOUND_COMMIT
[[ "${BOUND_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || fail 'bound commit is malformed'
/usr/bin/git -C "${REPOSITORY}" diff --exit-code "${BOUND_COMMIT}" -- \
  "${WORKTREE_BOUND_FILES[@]}" || fail 'runner/static/hermetic working tree drifted from HEAD'

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

CANONICAL_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P "${CANONICAL_MERGE}")" ||
  fail 'cannot read canonical merge parents'
readonly CANONICAL_PARENTS
[[ "${CANONICAL_PARENTS}" == "${CONTROLLER_LEASE_TIP} ${CANONICAL_FINAL}" ]] ||
  fail 'canonical merge does not preserve the approved controller/lease parents'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor "${CANONICAL_MERGE}" "${BOUND_COMMIT}" ||
  fail 'bound commit does not descend from the explicit canonical merge'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor "${STANDALONE_SCOPE_COMMIT}" "${BOUND_COMMIT}" ||
  fail 'bound commit does not contain the exact standalone lease scope'

SINGLE_L3_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P "${SINGLE_L3_MERGE}")" ||
  fail 'cannot read single-L3 merge parents'
readonly SINGLE_L3_PARENTS
[[ "${SINGLE_L3_PARENTS}" == "${SINGLE_L3_PARENT} ${SINGLE_L3_FINAL}" ]] ||
  fail 'single-L3 merge does not preserve the exact reviewed parents'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor "${SINGLE_L3_MERGE}" "${BOUND_COMMIT}" ||
  fail 'bound commit does not descend from the explicit single-L3 merge'
SINGLE_L3_PATHS="$(/usr/bin/git -C "${REPOSITORY}" diff --name-only \
  "${SINGLE_L3_MERGE}^1" "${SINGLE_L3_MERGE}")" || fail 'cannot read single-L3 merge write set'
readonly SINGLE_L3_PATHS
[[ "${SINGLE_L3_PATHS}" == $'bpf/wg_mix_faketcp.h\nbpf/wg_mix_tc.c\ninternal/dataplane/faketcp_admission_contract_test.go\ninternal/dataplane/faketcp_gso_contract_test.go\ninternal/dataplane/faketcp_l3_parser_test.go\ninternal/dataplane/faketcp_mtu_contract_test.go\ninternal/dataplane/faketcp_order_test.go\ninternal/dataplane/faketcp_policy_test.go\ninternal/dataplane/faketcp_single_parse_contract_test.go\ninternal/faketcp/l3_single_parse_model_test.go' ]] ||
  fail 'single-L3 merge changed a non-topic path'
MANAGED_INGRESS_ACCOUNTING_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P \
  "${MANAGED_INGRESS_ACCOUNTING}")" || fail 'cannot read managed-ingress accounting parent'
readonly MANAGED_INGRESS_ACCOUNTING_PARENTS
[[ "${MANAGED_INGRESS_ACCOUNTING_PARENTS}" == "${MANAGED_INGRESS_BASE}" ]] ||
  fail 'managed-ingress accounting commit is not based on the exact canonical commit'
MANAGED_INGRESS_PRODUCTION_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P \
  "${MANAGED_INGRESS_PRODUCTION}")" || fail 'cannot read managed-ingress production parent'
readonly MANAGED_INGRESS_PRODUCTION_PARENTS
[[ "${MANAGED_INGRESS_PRODUCTION_PARENTS}" == "${MANAGED_INGRESS_ACCOUNTING}" ]] ||
  fail 'managed-ingress typeword fix is not directly append-only after accounting'
MANAGED_INGRESS_ACCEPTANCE_ROOT_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P \
  "${MANAGED_INGRESS_ACCEPTANCE_ROOT}")" || fail 'cannot read managed-ingress acceptance-root parent'
readonly MANAGED_INGRESS_ACCEPTANCE_ROOT_PARENTS
[[ "${MANAGED_INGRESS_ACCEPTANCE_ROOT_PARENTS}" == "${MANAGED_INGRESS_PRODUCTION}" ]] ||
  fail 'managed-ingress acceptance root is not directly append-only after production'
MANAGED_INGRESS_ACCEPTANCE_PARENTS="$(/usr/bin/git -C "${REPOSITORY}" show -s --format=%P \
  "${MANAGED_INGRESS_ACCEPTANCE}")" || fail 'cannot read managed-ingress acceptance parent'
readonly MANAGED_INGRESS_ACCEPTANCE_PARENTS
[[ "${MANAGED_INGRESS_ACCEPTANCE_PARENTS}" == "${MANAGED_INGRESS_ACCEPTANCE_ROOT}" ]] ||
  fail 'managed-ingress fixture hardening is not directly append-only after acceptance root'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor \
  "${SINGLE_L3_MERGE}" "${MANAGED_INGRESS_BASE}" ||
  fail 'managed-ingress base lost the reviewed single-L3 merge'
/usr/bin/git -C "${REPOSITORY}" merge-base --is-ancestor \
  "${MANAGED_INGRESS_ACCEPTANCE}" "${BOUND_COMMIT}" ||
  fail 'bound commit does not contain managed-ingress acceptance'
MANAGED_INGRESS_PRODUCTION_PATHS="$(/usr/bin/git -C "${REPOSITORY}" diff --name-only \
  "${MANAGED_INGRESS_BASE}" "${MANAGED_INGRESS_PRODUCTION}")" ||
  fail 'cannot read managed-ingress production write set'
readonly MANAGED_INGRESS_PRODUCTION_PATHS
[[ "${MANAGED_INGRESS_PRODUCTION_PATHS}" == 'bpf/wg_mix_faketcp.h' ]] ||
  fail 'managed-ingress production commit changed a non-topic path'
MANAGED_INGRESS_TEST_PATHS="$(/usr/bin/git -C "${REPOSITORY}" diff --name-only \
  "${MANAGED_INGRESS_PRODUCTION}" "${MANAGED_INGRESS_ACCEPTANCE}")" ||
  fail 'cannot read managed-ingress acceptance write set'
readonly MANAGED_INGRESS_TEST_PATHS
[[ "${MANAGED_INGRESS_TEST_PATHS}" == $'internal/dataplane/faketcp_managed_ingress_contract_test.go\ninternal/dataplane/faketcp_managed_ingress_realhost_linux_test.go\nscripts/realhost-b82-c8e41d73/root-veth-n-r.sh\nscripts/realhost-b82-c8e41d73/test-hermetic-veth-runner.sh\nscripts/realhost-b82-c8e41d73/test_veth_runner_static.py' ]] ||
  fail 'managed-ingress acceptance changed a non-topic path'

# The original standalone commit itself remained isolated from the controller.
/usr/bin/git -C "${REPOSITORY}" diff --exit-code \
  "${STANDALONE_BASE_COMMIT}^" "${STANDALONE_BASE_COMMIT}" -- "${CONTROLLER_FILES[@]}" ||
  fail 'standalone base changed an existing controller or matrix file'
for resolution in "${ORIGINAL_MERGE_RESOLUTION_BLOBS[@]}"; do
  read -r resolution_file expected_blob <<<"${resolution}"
  actual_blob="$(/usr/bin/git -C "${REPOSITORY}" rev-parse \
    "${CANONICAL_MERGE}:${resolution_file}")" || fail 'cannot read canonical resolution blob'
  [[ "${actual_blob}" == "${expected_blob}" ]] ||
    fail "historical canonical resolution blob changed: ${resolution_file}"
done

MERGED_STAGER="$(/usr/bin/git -C "${REPOSITORY}" show "${CANONICAL_MERGE}:scripts/realhost-b82-c8e41d73/prepare-stage-root.sh")" ||
  fail 'cannot read merged stager contract'
MERGED_HERMETIC="$(/usr/bin/git -C "${REPOSITORY}" show "${CANONICAL_MERGE}:scripts/realhost-b82-c8e41d73/test-hermetic-controller.sh")" ||
  fail 'cannot read merged hermetic controller contract'
MERGED_STATIC="$(/usr/bin/git -C "${REPOSITORY}" show "${CANONICAL_MERGE}:scripts/realhost-b82-c8e41d73/test_controller_static.py")" ||
  fail 'cannot read merged static controller contract'
readonly MERGED_STAGER MERGED_HERMETIC MERGED_STATIC
[[ "${MERGED_STAGER}" == *'MODULE_LEASE_HELPER_RELATIVE'* &&
  "${MERGED_STAGER}" == *'PROVISION_PATH'* ]] ||
  fail 'canonical stager resolution dropped lease helper or provisioner'
[[ "${MERGED_HERMETIC}" == *'MODULE_LEASE_HELPER'* &&
  "${MERGED_HERMETIC}" == *'PROVISION_POLICY_TEST'* ]] ||
  fail 'canonical hermetic resolution dropped lease helper or provision policy'
[[ "${MERGED_STATIC}" == *'module-lease-lock-drift'* &&
  "${MERGED_STATIC}" == *'provision_ubuntu_test_host_sh_path'* ]] ||
  fail 'canonical static resolution dropped lease or provision contract'

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

MANAGED_INGRESS_SOURCE="$(/usr/bin/git -C "${REPOSITORY}" show \
  "${BOUND_COMMIT}:internal/dataplane/faketcp_managed_ingress_realhost_linux_test.go")" ||
  fail 'cannot read managed-ingress acceptance from the bound commit tree'
readonly MANAGED_INGRESS_SOURCE
managed_ingress_definition_count="$(printf '%s\n' "${MANAGED_INGRESS_SOURCE}" | /usr/bin/grep -Ec \
  '^func TestFakeTCPRealHostManagedIngressAcceptance\(t \*testing\.T\) \{$')"
[[ "${managed_ingress_definition_count}" == 1 ]] ||
  fail 'bound commit must define exactly one managed-ingress real-host test'
for literal in \
  'faketcp.ClassifyManagedIngressFrame' \
  'faketcp.ParseL3' \
  'fakeTCPManagedIngressFakeStatCount    = 19' \
  'fakeTCPManagedIngressCoreStatCount    = 36' \
  'fakeTCPRoutedExactStatDeltas' \
  'fakeTCPManagedIngressInvalidWireWord' \
  'canonicalPayload[12:16]' \
  'name: "managed canonical decode"' \
  'name: "unmanaged native UDP pass"' \
  'name: "managed IPv4 options drop"' \
  'name: "unmanaged TCP options pass"' \
  'name: "managed IPv6 extension drop"' \
  'name: "unmanaged IPv6 extension pass"' \
  'name: "managed IPv4 first fragment drop"' \
  'name: "unmanaged IPv4 noninitial fragment pass"' \
  'name: "managed IPv6 first fragment drop"' \
  'name: "managed IPv6 noninitial fragment drop"' \
  'name: "unmanaged IPv6 noninitial fragment pass"' \
  'name: "managed truncation drop"' \
  'name: "unmanaged truncation pass"' \
  'name: "ICMP safe bypass"' \
  'name: "ICMPv6 safe bypass"' \
  'FAKETCP_MANAGED_INGRESS_COMPLETE'; do
  [[ "${MANAGED_INGRESS_SOURCE}" == *"${literal}"* ]] ||
    fail "managed-ingress acceptance source is missing ${literal}"
done
managed_ingress_cell_count="$(printf '%s\n' "${MANAGED_INGRESS_SOURCE}" | /usr/bin/grep -Ec \
  '^[[:space:]]+name: "')"
[[ "${managed_ingress_cell_count}" == 22 ]] ||
  fail 'managed-ingress acceptance must retain exactly 22 matrix cells'
[[ "${MANAGED_INGRESS_SOURCE}" != *'t.Parallel('* ]] ||
  fail 'managed-ingress live matrix must remain serial'

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
  'state_schema=owner,baseline,mutation-plan,veth,tcx,module-lease,cleanup-intent,restored|filesystem-retained' \
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
  'L0 operation=shared-module-lock target=/run/wg-mix-ebpf-source-stages/c8e41d73/checksum-module-lease.v1.lock helper=/run/wg-mix-ebpf-source-stages/c8e41d73/source/scripts/realhost-b82-c8e41d73/checksum-module-lease.sh argv=/usr/bin/flock --exclusive --nonblock MODULE_LEASE_FD' \
  'M.load operation=shared-module-load target=wg_mix_faketcp_checksum helper=c8_checksum_module_load argv=/usr/sbin/insmod /run/wg-mix-ebpf-source-stages/a19f7c2e/source/build/faketcp_checksum_kmod/wg_mix_faketcp_checksum.ko lease_id=c8e41d73-d34b8e65' \
  'R.module operation=shared-module-restore target=wg_mix_faketcp_checksum helper=c8_checksum_module_restore argv=/usr/sbin/rmmod wg_mix_faketcp_checksum' \
  'R.veth-a operation=veth-delete target=wga19f7a argv=/usr/sbin/ip link delete dev wga19f7a' \
  'R.veth-b operation=veth-delete-b target=wga19f7b argv=/usr/sbin/ip link delete dev wga19f7b' \
  'B82_VETH_V6_WRITE_SET stage=/run/wg-mix-ebpf-source-stages/a19f7c2e' \
  'shared_lock=/run/wg-mix-ebpf-source-stages/c8e41d73/checksum-module-lease.v1.lock:advisory-only' \
  'lease_id=c8e41d73-d34b8e65 module_receipts=/run/wg-mix-ebpf-source-stages/a19f7c2e/veth-evidence-d34b8e65/checksum-module-intent.v1' \
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

for operation in list realhost; do
  managed_operation_count="$(printf '%s\n' "${PLAN_OUTPUT}" | /usr/bin/grep -Foc -- \
    "operation=${operation}:TestFakeTCPRealHostManagedIngressAcceptance target=TestFakeTCPRealHostManagedIngressAcceptance argv=")"
  [[ "${managed_operation_count}" == 1 ]] ||
    fail "plan must contain exactly one managed-ingress ${operation} operation"
done
[[ "${PLAN_OUTPUT}" != *'operation=offload:TestFakeTCPRealHostManagedIngressAcceptance '* ]] ||
  fail 'managed-ingress acceptance moved into the offload phase'

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
printf 'hermetic standalone veth plan, shared module lease, canonical merge resolution, strict argv and commit-tree GSO definitions: PASS\n'
