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
readonly PROVISION_POLICY_TEST="${REVIEW_ROOT}/test_provision_policy.tcl"
readonly PROVISIONER="${REPOSITORY}/scripts/provision-ubuntu-test-host.sh"
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

manifest_value() {
  local key="$1" manifest="$2"
  /usr/bin/awk -F '\t' -v expected="${key}" \
    '$1 == expected { if (++seen > 1 || NF != 2) exit 65; value=$2 } END { if (seen != 1) exit 65; print value }' \
    "${manifest}"
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

for path in "${BINDER}" "${CONTROLLER}" "${TRANSPORT}" "${STAGER}" "${MATRIX}" \
  "${STATIC_TEST}" "${PROVISION_POLICY_TEST}" "${PROVISIONER}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || fail "review input is not a regular file: ${path}"
done

/bin/bash -n "${BINDER}" "${CONTROLLER}" "${STAGER}" "${PROVISIONER}" "$0" || fail 'Bash syntax gate'
/usr/bin/python3 -I "${STATIC_TEST}" \
  "${BINDER}" "${CONTROLLER}" "${TRANSPORT}" "${STAGER}" "${MATRIX}" "${PROVISIONER}" ||
  fail 'static controller contract'
/usr/bin/expect "${PROVISION_POLICY_TEST}" "${TRANSPORT}" || fail 'provision output policy'
EXPECT_ARGUMENT_OUTPUT="$(/usr/bin/expect "${TRANSPORT}" 2>&1)"
EXPECT_ARGUMENT_RC=$?
[[ "${EXPECT_ARGUMENT_RC}" -eq 64 && "${EXPECT_ARGUMENT_OUTPUT}" == *'reason=arguments rc=64'* ]] ||
  fail 'Expect syntax/argument gate'

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --norc --shell=bash -- "${BINDER}" "${CONTROLLER}" "${STAGER}" "${PROVISIONER}" "$0" ||
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
printf 'history-root=%s\n' "${TEST_ROOT##*/}" >"${FIXTURE_REPOSITORY}/history-root.v1" ||
  fail 'fixture history root'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" add -- history-root.v1 || fail 'fixture history root add'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" commit -m 'Hermetic history root' || fail 'fixture history root commit'
/bin/mkdir -p -- "${FIXTURE_REVIEW}" || fail 'fixture review directory creation'
for name in \
  bind-final-package.sh controller.sh locked-transport.exp prepare-stage-root.sh \
  root-matrix-n-r.sh check-realhost-iperf.py test-hermetic-matrix.sh test_matrix_static.py \
  test_provision_policy.tcl; do
  /bin/cp -- "${REVIEW_ROOT}/${name}" "${FIXTURE_REVIEW}/${name}" || fail "fixture copy ${name}"
done
/bin/cp -- "${PROVISIONER}" "${FIXTURE_REPOSITORY}/scripts/provision-ubuntu-test-host.sh" ||
  fail 'fixture copy provisioner'
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
[[ "${BIND_PLAN}" == *'repository_shallow=false history_verification=isolated-unbundle-rev-list-fsck-v1'* ]] ||
  fail 'binding plan full-history fence'
[[ ! -e "${BOUND_OUTPUT}" && ! -L "${BOUND_OUTPUT}" ]] || fail 'binding plan created output'
BIND_RESULT="$(/bin/bash "${FIXTURE_REVIEW}/bind-final-package.sh" bind "${BIND_ARGS[@]}")" ||
  fail 'package binding'
[[ "${BIND_RESULT}" == *'B82_V6_BIND_COMPLETE'* ]] || fail 'binding completion marker'
BOUND_MANIFEST="${BOUND_OUTPUT}/package-manifest.v1"
BOUND_MANIFEST_SHA="$(sha256_file "${BOUND_MANIFEST}")" || fail 'manifest digest'
[[ -d "${BOUND_OUTPUT}/history-verification.git" && ! -L "${BOUND_OUTPUT}/history-verification.git" &&
  -f "${BOUND_OUTPUT}/history-objects.v1" && -f "${BOUND_OUTPUT}/history-roots.v1" ]] ||
  fail 'isolated history evidence shape'
[[ "$(manifest_value history_verification "${BOUND_MANIFEST}")" == 'isolated-unbundle-rev-list-fsck-v1' ]] ||
  fail 'history method manifest binding'
[[ "$(manifest_value history_commit_count "${BOUND_MANIFEST}")" == '2' ]] ||
  fail 'full fixture history count'
[[ "$(sha256_file "${BOUND_OUTPUT}/history-objects.v1")" == \
  "$(manifest_value history_objects_sha256 "${BOUND_MANIFEST}")" ]] || fail 'history objects digest'
[[ "$(sha256_file "${BOUND_OUTPUT}/history-roots.v1")" == \
  "$(manifest_value history_roots_sha256 "${BOUND_MANIFEST}")" ]] || fail 'history roots digest'
[[ "$(manifest_value provision_ubuntu_test_host_sh_path "${BOUND_MANIFEST}")" == \
  'scripts/provision-ubuntu-test-host.sh' ]] || fail 'provisioner manifest path binding'
[[ "$(sha256_file "${BOUND_OUTPUT}/provision-ubuntu-test-host.sh")" == \
  "$(manifest_value provision_ubuntu_test_host_sh_sha256 "${BOUND_MANIFEST}")" ]] ||
  fail 'provisioner package digest binding'
/usr/bin/git -C "${BOUND_OUTPUT}/history-verification.git" fsck --full --strict --no-dangling \
  "${FIXTURE_COMMIT}" || fail 'isolated history fsck'
/usr/bin/grep -E '^\?' -- "${BOUND_OUTPUT}/history-objects.v1"
HISTORY_MISSING_RC=$?
case "${HISTORY_MISSING_RC}" in
  1) ;;
  0) fail 'history evidence contains a missing object' ;;
  *) fail 'history evidence scan failed' ;;
esac

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
  '/usr/sbin/bpftool -V' \
  'operation=kernel-btf transport=ssh credential_read=0 network_operations=0' \
  'operation=scp-source-4f2a9b61.bundle transport=scp credential_read=0 network_operations=0' \
  "${FIXTURE_REPOSITORY}/scripts/realhost-b82-c8e41d73/locked-transport.exp" \
  "${BOUND_OUTPUT}/source-4f2a9b61.bundle" \
  'siyixuan@192.168.10.82:/home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle' \
  'operation=stage-run transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/sudo -- /usr/bin/env -i' \
  'operation=bootstrap-absent transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/test ! -e /run/wg-mix-ebpf-source-bootstrap-c8e41d73' \
  'operation=bootstrap-not-symlink transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/test ! -L /run/wg-mix-ebpf-source-bootstrap-c8e41d73' \
  'operation=bootstrap-create transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/mkdir --mode=0700 -- /run/wg-mix-ebpf-source-bootstrap-c8e41d73' \
  'operation=bootstrap-root-readlink transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-root-stat transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-install-stager transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/install --owner=root --group=root --mode=0700 --no-target-directory -- /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/prepare-stage-root.sh /run/wg-mix-ebpf-source-bootstrap-c8e41d73/prepare-stage-root.sh' \
  'operation=bootstrap-stager-readlink transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-stager-sha transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-stager-stat transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-install-provisioner transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/install --owner=root --group=root --mode=0700 --no-target-directory -- /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/provision-ubuntu-test-host.sh /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh' \
  'operation=bootstrap-provisioner-readlink transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-provisioner-stat transport=ssh credential_read=0 network_operations=0' \
  'operation=bootstrap-provisioner-sha transport=ssh credential_read=0 network_operations=0' \
  'operation=provision-check transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/sudo -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh --check --expected-address 192.168.10.82 --expected-interface ens33 --expected-hostname ubuntu-2604-test --expected-kernel 7.0.0-28-generic --expected-machine-id 9db3fb717cc74974b2a6b243d67f67b9' \
  'operation=provision-apply transport=ssh credential_read=0 network_operations=0' \
  '/usr/bin/sudo -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/provision-ubuntu-test-host.sh --apply --expected-address 192.168.10.82 --expected-interface ens33 --expected-hostname ubuntu-2604-test --expected-kernel 7.0.0-28-generic --expected-machine-id 9db3fb717cc74974b2a6b243d67f67b9' \
  'B82_V6_CONTROLLER_STATE current=PACKAGE_BOUND automatic_apply=0' \
  'B82_V6_CONTROLLER_STATE from=PACKAGE_BOUND to=BOOTSTRAP_ONLY automatic_apply=0' \
  'B82_V6_CONTROLLER_BRANCH missing_set=none next_state=POSTFLIGHT' \
  'B82_V6_CONTROLLER_BRANCH missing_set=initial|iperf3 next_state=AWAIT_APPLY' \
  'B82_V6_CONTROLLER_STATE from=AWAIT_APPLY to=PROVISION_APPLY explicit_mode=provision-apply automatic_apply=0' \
  'operation=stage-snapshot transport=ssh credential_read=0 network_operations=0' \
  '/bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/prepare-stage-root.sh snapshot --manifest /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1' \
  '/bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/prepare-stage-root.sh plan --manifest /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  '/bin/bash -p /run/wg-mix-ebpf-source-bootstrap-c8e41d73/prepare-stage-root.sh run --manifest /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  'operation=matrix-run transport=ssh credential_read=0 network_operations=0' \
  '--wg-interface wg0 --wg-local-address 10.200.0.1 --wg-peer-address 10.200.0.2' \
  'B82_V6_CONTROLLER_PLAN_COMPLETE credential_read=0 network_operations=0 mutations=0'; do
  [[ "${CONTROLLER_PLAN}" == *"${literal}"* ]] || fail "controller plan missing ${literal}"
done
[[ "${CONTROLLER_PLAN}" != *'B82_V6_MATRIX_BLOCKED'* ]] || fail 'bound plan was blocked'
[[ "${CONTROLLER_PLAN}" != *'/bin/bash -p /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/prepare-stage-root.sh'* ]] ||
  fail 'controller plan executes user-writable package stager'
[[ "${CONTROLLER_PLAN}" != *'/bin/bash -p /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/provision-ubuntu-test-host.sh'* ]] ||
  fail 'controller plan executes user-writable package provisioner'
[[ "${CONTROLLER_PLAN}" != *'/usr/sbin/bpftool version'* ]] || fail 'legacy bpftool probe survived'
[[ "${CONTROLLER_PLAN}" != *'prepare-stage-root.sh plan --manifest /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1'* ]] ||
  fail 'controller stage plan reopens the user-owned manifest'
[[ "${CONTROLLER_PLAN}" != *'prepare-stage-root.sh run --manifest /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1'* ]] ||
  fail 'controller stage run reopens the user-owned manifest'
require_ordered_literals "${CONTROLLER_PLAN}" \
  'operation=bootstrap-absent ' \
  'operation=bootstrap-not-symlink ' \
  'operation=bootstrap-create ' \
  'operation=bootstrap-root-readlink ' \
  'operation=bootstrap-root-stat ' \
  'operation=bootstrap-install-provisioner ' \
  'operation=bootstrap-install-stager ' \
  'operation=bootstrap-provisioner-readlink ' \
  'operation=bootstrap-provisioner-stat ' \
  'operation=bootstrap-provisioner-sha ' \
  'operation=provision-check ' \
  'operation=bootstrap-provisioner-readlink ' \
  'operation=bootstrap-provisioner-stat ' \
  'operation=bootstrap-provisioner-sha ' \
  'operation=provision-apply ' \
  'operation=identity-driver ' \
  'operation=bootstrap-stager-readlink ' \
  'operation=bootstrap-stager-stat ' \
  'operation=bootstrap-stager-sha ' \
  'operation=stage-snapshot ' \
  'operation=stage-plan ' \
  'operation=stage-run '

BOOTSTRAP_FIXTURE="${TEST_ROOT}/bootstrap-first-run-c8e41d73"
[[ ! -e "${BOOTSTRAP_FIXTURE}" && ! -L "${BOOTSTRAP_FIXTURE}" ]] || fail 'bootstrap fixture was not fresh'
/bin/test ! -e "${BOOTSTRAP_FIXTURE}" || fail 'bootstrap first-run absence gate'
/bin/test ! -L "${BOOTSTRAP_FIXTURE}" || fail 'bootstrap first-run symlink gate'
/bin/mkdir -m 0700 -- "${BOOTSTRAP_FIXTURE}" || fail 'bootstrap first-run creation'
if /bin/test ! -e "${BOOTSTRAP_FIXTURE}"; then
  fail 'pre-existing bootstrap passed the absence gate'
fi
BOOTSTRAP_SYMLINK_FIXTURE="${TEST_ROOT}/bootstrap-dangling-symlink-c8e41d73"
/bin/ln -s "${TEST_ROOT}/missing-bootstrap-target" "${BOOTSTRAP_SYMLINK_FIXTURE}" ||
  fail 'bootstrap dangling symlink fixture'
/bin/test ! -e "${BOOTSTRAP_SYMLINK_FIXTURE}" || fail 'dangling symlink fixture unexpectedly exists'
if /bin/test ! -L "${BOOTSTRAP_SYMLINK_FIXTURE}"; then
  fail 'dangling bootstrap symlink passed the symlink gate'
fi
printf 'HERMETIC_BOOTSTRAP first_run_reachable=1 preexisting_rejected=1 retained=%s\n' "${BOOTSTRAP_FIXTURE}"

IMMUTABLE_FIXTURE="${TEST_ROOT}/immutable-intake-c8e41d73"
/bin/mkdir -m 0700 -- "${IMMUTABLE_FIXTURE}" || fail 'immutable intake fixture creation'
MANIFEST_GOOD="${IMMUTABLE_FIXTURE}/manifest-good.v1"
MANIFEST_EVIL="${IMMUTABLE_FIXTURE}/manifest-evil.v1"
MANIFEST_SOURCE="${IMMUTABLE_FIXTURE}/manifest-source.v1"
MANIFEST_SNAPSHOT="${IMMUTABLE_FIXTURE}/manifest-snapshot.v1"
printf 'decision\ttrusted\n' >"${MANIFEST_GOOD}" || fail 'trusted manifest fixture'
printf 'decision\tuntrusted\n' >"${MANIFEST_EVIL}" || fail 'untrusted manifest fixture'
/bin/cp -- "${MANIFEST_GOOD}" "${MANIFEST_SOURCE}" || fail 'old manifest source setup'
OLD_MANIFEST_SHA="$(sha256_file "${MANIFEST_SOURCE}")" || fail 'old manifest hash gate'
/bin/cp -- "${MANIFEST_EVIL}" "${MANIFEST_SOURCE}" || fail 'old manifest evil swap'
OLD_MANIFEST_VALUE="$(/usr/bin/awk -F '\t' '$1 == "decision" { print $2 }' "${MANIFEST_SOURCE}")" ||
  fail 'old manifest reopen'
[[ "${OLD_MANIFEST_SHA}" == "$(sha256_file "${MANIFEST_GOOD}")" &&
  "${OLD_MANIFEST_VALUE}" == 'untrusted' ]] || fail 'old manifest TOCTOU was not reproduced'
/bin/cp -- "${MANIFEST_GOOD}" "${MANIFEST_SOURCE}" || fail 'manifest source good restore'
(umask 077
  set -o noclobber
  /bin/cat -- "${MANIFEST_SOURCE}" >"${MANIFEST_SNAPSHOT}") || fail 'manifest intake copy'
/bin/cp -- "${MANIFEST_EVIL}" "${MANIFEST_SOURCE}" || fail 'manifest post-copy evil swap'
/bin/cp -- "${MANIFEST_GOOD}" "${MANIFEST_SOURCE}" || fail 'manifest post-copy good restore'
[[ "$(sha256_file "${MANIFEST_SNAPSHOT}")" == "$(sha256_file "${MANIFEST_GOOD}")" &&
  "$(/usr/bin/awk -F '\t' '$1 == "decision" { print $2 }' "${MANIFEST_SNAPSHOT}")" == 'trusted' ]] ||
  fail 'immutable manifest copy changed after source replacement'
if (set -o noclobber
  /bin/cat -- "${MANIFEST_EVIL}" >"${MANIFEST_SNAPSHOT}") \
  2>"${IMMUTABLE_FIXTURE}/manifest-noclobber.err"; then
  fail 'immutable manifest destination was clobbered'
fi

BUNDLE_SOURCE="${IMMUTABLE_FIXTURE}/bundle-source.bundle"
BUNDLE_SNAPSHOT="${IMMUTABLE_FIXTURE}/bundle-snapshot.bundle"
/bin/cp -- "${BOUND_OUTPUT}/source-4f2a9b61.bundle" "${BUNDLE_SOURCE}" || fail 'old bundle source setup'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" bundle verify "${BUNDLE_SOURCE}" || fail 'old bundle verify gate'
printf 'replacement-after-verify\n' >"${BUNDLE_SOURCE}" || fail 'old bundle replacement'
if /usr/bin/git -C "${FIXTURE_REPOSITORY}" bundle verify "${BUNDLE_SOURCE}" \
  >"${IMMUTABLE_FIXTURE}/old-bundle-reopen.log" 2>&1; then
  fail 'old bundle reopen unexpectedly consumed the verified bytes'
fi
/bin/cp -- "${BOUND_OUTPUT}/source-4f2a9b61.bundle" "${BUNDLE_SOURCE}" || fail 'bundle source restore'
(umask 077
  set -o noclobber
  /bin/cat -- "${BUNDLE_SOURCE}" >"${BUNDLE_SNAPSHOT}") || fail 'bundle intake copy'
printf 'replacement-after-copy\n' >"${BUNDLE_SOURCE}" || fail 'bundle post-copy replacement'
[[ "$(sha256_file "${BUNDLE_SNAPSHOT}")" == \
  "$(manifest_value bundle_sha256 "${BOUND_MANIFEST}")" ]] || fail 'immutable bundle digest'
/usr/bin/git -C "${FIXTURE_REPOSITORY}" bundle verify "${BUNDLE_SNAPSHOT}" ||
  fail 'immutable bundle verify'
IMMUTABLE_CLONE="${IMMUTABLE_FIXTURE}/source"
/usr/bin/git clone --no-local --no-checkout --single-branch --branch "${FIXTURE_BRANCH}" -- \
  "${BUNDLE_SNAPSHOT}" "${IMMUTABLE_CLONE}" || fail 'immutable bundle clone'
/usr/bin/git -C "${IMMUTABLE_CLONE}" checkout --detach "${FIXTURE_COMMIT}" ||
  fail 'immutable bundle checkout'
[[ "$(/usr/bin/git -C "${IMMUTABLE_CLONE}" rev-parse HEAD)" == "${FIXTURE_COMMIT}" ]] ||
  fail 'immutable clone commit mismatch'
printf 'HERMETIC_IMMUTABLE_INTAKE old_manifest_reopen=failed old_bundle_reopen=failed root_copy_only=pass retained=%s\n' \
  "${IMMUTABLE_FIXTURE}"

STAGE_PLAN="$(/bin/bash "${BOUND_OUTPUT}/prepare-stage-root.sh" snapshot-plan \
  --manifest /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1 \
  --manifest-sha256 "${BOUND_MANIFEST_SHA}")" || fail 'root snapshot plan'
for literal in \
  'B82_V6_SNAPSHOT_PLAN run_id=c8e41d73' \
  'shell-builtin noclobber-copy /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/package-manifest.v1 /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  'shell-builtin noclobber-copy /home/siyixuan/wg-mix-ebpf-test/unpriv-4f2a9b61/source-4f2a9b61.bundle /run/wg-mix-ebpf-source-bootstrap-c8e41d73/source-4f2a9b61.bundle' \
  'shell-builtin parse-verified-root-manifest /run/wg-mix-ebpf-source-bootstrap-c8e41d73/package-manifest.v1' \
  'B82_V6_SNAPSHOT_PLAN_COMPLETE no_commands_executed=1 no_cleanup=1 failure_resources_retained=1'; do
  [[ "${STAGE_PLAN}" == *"${literal}"* ]] || fail "snapshot plan missing ${literal}"
done
require_ordered_literals "${STAGE_PLAN}" 'C4 argv=' 'C7 argv=' 'C8 argv=' 'C11 argv=' 'C14 argv='

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
expect_failure package-stager-root-run /bin/bash "${BOUND_OUTPUT}/prepare-stage-root.sh" run \
  --manifest "${BOUND_MANIFEST}" --manifest-sha256 "${BOUND_MANIFEST_SHA}"

SHALLOW_REPOSITORY="${TEST_ROOT}/shallow-repository"
/usr/bin/git clone --depth 1 --branch "${FIXTURE_BRANCH}" \
  "file://${FIXTURE_REPOSITORY}" "${SHALLOW_REPOSITORY}" || fail 'shallow fixture clone'
[[ "$(/usr/bin/git -C "${SHALLOW_REPOSITORY}" rev-parse --is-shallow-repository)" == 'true' ]] ||
  fail 'shallow fixture is not shallow'
/usr/bin/git -C "${SHALLOW_REPOSITORY}" config user.name 'Hermetic Shallow Test' || fail 'shallow Git name'
/usr/bin/git -C "${SHALLOW_REPOSITORY}" config user.email 'hermetic-shallow@example.invalid' || fail 'shallow Git email'
printf 'shallow-child=%s\n' "${TEST_ROOT##*/}" >"${SHALLOW_REPOSITORY}/shallow-child.v1" ||
  fail 'shallow child fixture'
/usr/bin/git -C "${SHALLOW_REPOSITORY}" add -- shallow-child.v1 || fail 'shallow child add'
/usr/bin/git -C "${SHALLOW_REPOSITORY}" commit -m 'Hermetic shallow child' || fail 'shallow child commit'
SHALLOW_COMMIT="$(/usr/bin/git -C "${SHALLOW_REPOSITORY}" rev-parse HEAD)" || fail 'shallow fixture commit'
SHALLOW_OUTPUT="/private/tmp/wg-mix-b82-v6-c8e41d73-4f2a9b61-${SHALLOW_COMMIT:0:12}"
SHALLOW_ARGS=(
  --repository "${SHALLOW_REPOSITORY}" --source-ref "${FIXTURE_REF}" --commit "${SHALLOW_COMMIT}"
  --wg-state bound --wg-interface wg0 --wg-local-address 10.200.0.1 --wg-peer-address 10.200.0.2
  --output-dir "${SHALLOW_OUTPUT}"
)
expect_failure shallow-plan /bin/bash \
  "${SHALLOW_REPOSITORY}/scripts/realhost-b82-c8e41d73/bind-final-package.sh" plan "${SHALLOW_ARGS[@]}"
expect_failure shallow-bind /bin/bash \
  "${SHALLOW_REPOSITORY}/scripts/realhost-b82-c8e41d73/bind-final-package.sh" bind "${SHALLOW_ARGS[@]}"
[[ ! -e "${SHALLOW_OUTPUT}" && ! -L "${SHALLOW_OUTPUT}" ]] || fail 'shallow bind created output'

printf '?ffffffffffffffffffffffffffffffffffffffff\n' >>"${BOUND_OUTPUT}/history-objects.v1" ||
  fail 'history evidence tamper fixture'
expect_failure tampered-history-evidence /bin/bash "${FIXTURE_REVIEW}/controller.sh" plan "${CONTROLLER_ARGS[@]}"

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

printf '%s\n' \
  'hermetic v6 full-history binder, explicit toolchain state machine, root-owned bootstrap,' \
  'SSH/SCP/Expect fixed check/apply plans, provision output policy,' \
  'immutable-intake/shallow/failure paths and WireGuard absence: PASS'
printf 'RETAINED_HERMETIC_ROOT path=%s reason=auditable-no-cleanup-test-policy\n' "${TEST_ROOT}"
