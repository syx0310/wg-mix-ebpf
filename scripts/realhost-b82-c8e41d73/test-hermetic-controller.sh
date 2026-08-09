#!/usr/bin/env bash
set -u
set -o pipefail
umask 077

REVIEW_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)" || exit 70
readonly REVIEW_ROOT
REPOSITORY="$(CDPATH= cd -- "${REVIEW_ROOT}/../.." && pwd -P)" || exit 70
readonly REPOSITORY
readonly BINDER="${REVIEW_ROOT}/bind-final-package.sh"
readonly CONTROLLER="${REVIEW_ROOT}/controller.sh"
readonly TRANSPORT="${REVIEW_ROOT}/locked-transport.exp"
readonly STAGER="${REVIEW_ROOT}/prepare-stage-root.sh"
readonly MATRIX="${REVIEW_ROOT}/root-matrix-n-r.sh"
readonly STATIC_TEST="${REVIEW_ROOT}/test_controller_static.py"
readonly CREDENTIAL_PATH='/Users/siyixuan/codes-2/wg-mix-ebpf/credientials/192.168.10.82'

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit "${2:-1}"
}

sha256_file() {
  local line
  if [[ -x /usr/bin/shasum ]]; then
    line="$(/usr/bin/shasum -a 256 -- "$1")" || return $?
  else
    line="$(/usr/bin/sha256sum -- "$1")" || return $?
  fi
  printf '%s\n' "${line%% *}"
}

expect_failure() {
  local label="$1" output
  shift
  if output="$("$@" 2>&1)"; then
    fail "${label} unexpectedly succeeded"
  fi
  printf 'EXPECTED_FAILURE label=%s output=%q\n' "${label}" "${output}"
}

for path in "${BINDER}" "${CONTROLLER}" "${TRANSPORT}" "${STAGER}" "${MATRIX}" "${STATIC_TEST}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "review input is not a regular file: ${path}"
done

/bin/bash -n "${BINDER}" "${CONTROLLER}" "${STAGER}" "$0" || fail 'Bash syntax gate'
/usr/bin/python3 -I "${STATIC_TEST}" \
  "${BINDER}" "${CONTROLLER}" "${TRANSPORT}" "${STAGER}" "${MATRIX}" ||
  fail 'static controller contract'
EXPECT_ARGUMENT_OUTPUT="$(/usr/bin/expect "${TRANSPORT}" 2>&1)"
EXPECT_ARGUMENT_RC=$?
[[ "${EXPECT_ARGUMENT_RC}" -eq 64 && "${EXPECT_ARGUMENT_OUTPUT}" == *'reason=arguments rc=64'* ]] ||
  fail 'Expect syntax/argument gate'

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${BINDER}" "${CONTROLLER}" "${STAGER}" "$0" ||
    fail 'ShellCheck gate'
else
  printf 'SKIP: shellcheck unavailable locally; .82 preflight binds /usr/bin/shellcheck\n'
fi

/usr/bin/git -C "${REPOSITORY}" diff --exit-code -- \
  scripts/realhost-b82-c8e41d73/root-matrix-n-r.sh || fail 'existing root matrix was modified'

TEST_ROOT="$(/usr/bin/mktemp -d /private/tmp/wg-mix-b82-v6-controller-hermetic.XXXXXX)" ||
  fail 'temporary root creation'
FIXTURE_REPOSITORY="${TEST_ROOT}/repository"
FIXTURE_REVIEW="${FIXTURE_REPOSITORY}/scripts/realhost-b82-c8e41d73"
/bin/mkdir -m 0700 -- "${FIXTURE_REPOSITORY}" || fail 'fixture repository creation'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" init || fail 'fixture Git init'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" config user.name 'Hermetic Controller Test' || fail 'fixture Git name'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" config user.email 'hermetic-controller@example.invalid' || fail 'fixture Git email'
/bin/mkdir -p -- "${FIXTURE_REVIEW}" || fail 'fixture review directory creation'
for name in \
  bind-final-package.sh controller.sh locked-transport.exp prepare-stage-root.sh \
  root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh test_matrix_static.py; do
  /bin/cp -- "${REVIEW_ROOT}/${name}" "${FIXTURE_REVIEW}/${name}" || fail "fixture copy ${name}"
done
printf 'fixture=%s\n' "${TEST_ROOT##*/}" >"${FIXTURE_REPOSITORY}/fixture-token.v1" || fail 'fixture token'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- scripts fixture-token.v1 || fail 'fixture Git add'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" commit -m 'Hermetic binding fixture' || fail 'fixture Git commit'
FIXTURE_COMMIT="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" rev-parse HEAD)" || fail 'fixture commit'
FIXTURE_BRANCH="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" symbolic-ref --short HEAD)" || fail 'fixture branch'
FIXTURE_REF="refs/heads/${FIXTURE_BRANCH}"
BOUND_OUTPUT="/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-${FIXTURE_COMMIT:0:12}"

BIND_ARGS=(
  --repository "${FIXTURE_REPOSITORY}"
  --source-ref "${FIXTURE_REF}"
  --commit "${FIXTURE_COMMIT}"
  --wg-state bound
  --wg-interface wg0
  --wg-local-address 10.200.0.1
  --wg-peer-address 10.200.0.2
  --output-dir "${BOUND_OUTPUT}"
)

BIND_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" plan "${BIND_ARGS[@]}")" ||
  fail 'binding plan'
[[ "${BIND_PLAN}" == *'no_files_created=1 credential_read=0 network_operations=0'* ]] ||
  fail 'binding plan side-effect fence'
[[ ! -e "${BOUND_OUTPUT}" && ! -L "${BOUND_OUTPUT}" ]] || fail 'binding plan created output'
BIND_RESULT="$(/bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" bind "${BIND_ARGS[@]}")" ||
  fail 'package binding'
[[ "${BIND_RESULT}" == *'B82_V6_BIND_COMPLETE'* ]] || fail 'binding completion marker'
BOUND_MANIFEST="${BOUND_OUTPUT}/package-manifest.v1"
BOUND_MANIFEST_SHA="$(sha256_file "${BOUND_MANIFEST}")" || fail 'manifest digest'

CONTROLLER_ARGS=(
  --manifest "${BOUND_MANIFEST}"
  --manifest-sha256 "${BOUND_MANIFEST_SHA}"
  --credential-path "${CREDENTIAL_PATH}"
  --restore-cell none
)
CONTROLLER_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/controller.sh" plan "${CONTROLLER_ARGS[@]}")" ||
  fail 'controller plan'
for literal in \
  'operation=identity-hostname transport=ssh credential_read=0 network_operations=0' \
  'operation=identity-wg-interfaces transport=ssh credential_read=0 network_operations=0' \
  'operation=tool-bpftool transport=ssh credential_read=0 network_operations=0' \
  'operation=kernel-btf transport=ssh credential_read=0 network_operations=0' \
  'operation=scp-source-4f2a9b61.bundle transport=scp credential_read=0 network_operations=0' \
  "${FIXTURE_REPOSITORY}/scripts/realhost-b82-c8e41d73/locked-transport.exp" \
  "${BOUND_OUTPUT}/source-4f2a9b61.bundle" \
  'siyixuan@192.168.10.82:/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle' \
  'operation=stage-run transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/sudo -- /usr/bin/env -i' \
  'operation=matrix-run transport=ssh credential_read=0 network_operations=0' \
  '--wg-interface wg0 --wg-local-address 10.200.0.1 --wg-peer-address 10.200.0.2' \
  'B82_V6_CONTROLLER_PLAN_COMPLETE credential_read=0 network_operations=0 mutations=0'; do
  [[ "${CONTROLLER_PLAN}" == *"${literal}"* ]] || fail "controller plan missing ${literal}"
done
[[ "${CONTROLLER_PLAN}" != *'B82_V6_MATRIX_BLOCKED'* ]] || fail 'bound plan was blocked'

STAGE_PLAN="$(/bin/bash "${BOUND_OUTPUT}/prepare-stage-root.sh" plan \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}")" ||
  fail 'root stage plan'
for literal in \
  'B82_V6_STAGE_PLAN run_id=c8e41d73' \
  'git -c core.hooksPath=/dev/null clone --no-local --no-checkout' \
  "checkout --detach ${FIXTURE_COMMIT}" \
  'B82_V6_STAGE_PLAN_COMPLETE no_commands_executed=1 no_cleanup=1'; do
  [[ "${STAGE_PLAN}" == *"${literal}"* ]] || fail "stage plan missing ${literal}"
done

expect_failure wrong-manifest-sha /bin/bash "${FIXTURE_REVIEW}/controller.sh" plan \
  --manifest "${BOUND_MANIFEST}" \
  --manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --credential-path "${CREDENTIAL_PATH}" --restore-cell none
expect_failure existing-output /bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" bind "${BIND_ARGS[@]}"
expect_failure ref-commit-mismatch /bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" plan \
  --repository "${FIXTURE_REPOSITORY}" --source-ref "${FIXTURE_REF}" \
  --commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --wg-state bound \
  --wg-interface wg0 --wg-local-address 10.200.0.1 --wg-peer-address 10.200.0.2 \
  --output-dir /private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-aaaaaaaaaaaa
expect_failure inconsistent-absent-binding /bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" plan \
  --repository "${FIXTURE_REPOSITORY}" --source-ref "${FIXTURE_REF}" --commit "${FIXTURE_COMMIT}" \
  --wg-state absent --wg-interface wg0 --wg-local-address absent --wg-peer-address absent \
  --output-dir "${BOUND_OUTPUT}"
expect_failure invalid-transport-operation /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path "${CREDENTIAL_PATH}" --action plan --operation arbitrary-command
expect_failure credential-path-before-spawn /usr/bin/expect "${FIXTURE_REVIEW}/locked-transport.exp" \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}" \
  --credential-path /private/tmp/not-a-credential --action execute --operation identity-hostname

printf 'fixture-absent=%s\n' "${TEST_ROOT##*/}" >>"${FIXTURE_REPOSITORY}/fixture-token.v1" ||
  fail 'absent fixture token'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- fixture-token.v1 || fail 'absent fixture add'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" commit -m 'Hermetic absent WireGuard fixture' || fail 'absent fixture commit'
ABSENT_COMMIT="$(/usr/bin/git -C "${FIXTURE_REPOSITORY}" rev-parse HEAD)" || fail 'absent commit'
ABSENT_OUTPUT="/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-${ABSENT_COMMIT:0:12}"
ABSENT_ARGS=(
  --repository "${FIXTURE_REPOSITORY}" --source-ref "${FIXTURE_REF}" --commit "${ABSENT_COMMIT}"
  --wg-state absent --wg-interface absent --wg-local-address absent --wg-peer-address absent
  --output-dir "${ABSENT_OUTPUT}"
)
/bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" bind "${ABSENT_ARGS[@]}" || fail 'absent package binding'
ABSENT_MANIFEST="${ABSENT_OUTPUT}/package-manifest.v1"
ABSENT_MANIFEST_SHA="$(sha256_file "${ABSENT_MANIFEST}")" || fail 'absent manifest digest'
ABSENT_CONTROLLER_ARGS=(
  --manifest "${ABSENT_MANIFEST}" --manifest-sha256 "${ABSENT_MANIFEST_SHA}"
  --credential-path "${CREDENTIAL_PATH}" --restore-cell none
)
ABSENT_PLAN="$(/bin/bash "${FIXTURE_REVIEW}/controller.sh" plan "${ABSENT_CONTROLLER_ARGS[@]}")" ||
  fail 'absent controller plan'
[[ "${ABSENT_PLAN}" == *'B82_V6_MATRIX_BLOCKED reason=wireguard-topology-absent wg_active_scoped=not-covered pass=0'* ]] ||
  fail 'absent WireGuard matrix block missing'
[[ "${ABSENT_PLAN}" != *'operation=matrix-run'* ]] || fail 'absent plan rendered matrix execution'
expect_failure absent-matrix-run /bin/bash "${FIXTURE_REVIEW}/controller.sh" run "${ABSENT_CONTROLLER_ARGS[@]}"

printf 'hermetic v6 binder, SSH/SCP/Expect plan, failure paths and WireGuard absence: PASS\n'
printf 'RETAINED_HERMETIC_ROOT path=%s reason=auditable-no-cleanup-test-policy\n' "${TEST_ROOT}"
