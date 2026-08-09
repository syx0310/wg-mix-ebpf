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

/usr/bin/git -C "${REPOSITORY}" diff --exit-code HEAD -- \
  scripts/realhost-b82-c8e41d73/bind-final-package.sh \
  scripts/realhost-b82-c8e41d73/controller.sh \
  scripts/realhost-b82-c8e41d73/locked-transport.exp \
  scripts/realhost-b82-c8e41d73/prepare-stage-root.sh \
  scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh ||
  fail 'standalone phase changed an existing controller or matrix file'

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

for literal in \
  'B82_VETH_V6_PLAN_ONLY controller_run_id=c8e41d73 run_id=a19f7c2e resource_id=d34b8e65' \
  'wg_state=absent wg_active_scoped=not-covered pass=0' \
  'raw_ens33=not-covered raw_ens33_pass=0 peer_47=read-only peer_access=0' \
  'S0.copy argv=/usr/bin/timeout --signal=TERM --kill-after=10s 2m /usr/bin/cp --no-clobber --no-preserve=mode\,ownership\,timestamps' \
  '/run/wg-mix-ebpf-source-stages/a19f7c2e/source-4f2a9b61-d34b8e65.bundle' \
  'S1 argv=/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C' \
  '/run/wg-mix-ebpf-source-stages/a19f7c2e/source' \
  '/run/wg-mix-ebpf-source-stages/a19f7c2e/veth-evidence-d34b8e65' \
  '/sys/fs/bpf/wg-mix-ebpf-a19f7c2e-tcx' \
  'N.add argv=/usr/sbin/ip link add wga19f7a type veth peer name wga19f7b' \
  'WG_MIX_EBPF_TEST_ACTION=run' \
  'WG_MIX_EBPF_TEST_ACTION=restore' \
  'TestFakeTCPBPFPacketProbe' \
  'TestFakeTCPRealHostVirtioNetHeaderEncoding' \
  'TestFakeTCPRealHostGSOOutputMatcher' \
  'TestFakeTCPRealHostGSOProbeIsolationContract' \
  'TestExperimentalFakeTCPRealHostLifecycleIntegration' \
  'TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration' \
  'TestBaselineExperimentalRealHostMutualExclusionIntegration' \
  'M.unload argv=/usr/sbin/rmmod wg_mix_faketcp_checksum' \
  'N.delete argv=/usr/sbin/ip link delete dev wga19f7a' \
  'B82_VETH_V6_WRITE_SET stage=/run/wg-mix-ebpf-source-stages/a19f7c2e' \
  'B82_VETH_V6_PLAN_COMPLETE commands_are_review_templates=1 no_commands_executed=1 credential_read=0 network_operations=0 capability_bits_changed=0'; do
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

[[ ! -e "${VETH_STAGE}" && ! -L "${VETH_STAGE}" ]] || fail 'failure fixtures created the veth stage'
printf 'hermetic standalone veth plan, strict argv, self-identity model and no-controller-diff: PASS\n'
