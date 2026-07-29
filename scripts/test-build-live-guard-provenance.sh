#!/bin/bash
set -euo pipefail

readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly LC_ALL="C"
readonly BUILD_GATE="${1:-}"
readonly CHMOD_BIN="/usr/bin/chmod"
readonly CP_BIN="/usr/bin/cp"
readonly ENV_BIN="/usr/bin/env"
readonly GIT_BIN="/usr/bin/git"
readonly GO_BIN="/usr/bin/go"
readonly MKDIR_BIN="/usr/bin/mkdir"
readonly MKTEMP_BIN="/usr/bin/mktemp"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly STAT_BIN="/usr/bin/stat"
readonly TAR_BIN="/usr/bin/tar"
readonly TIMEOUT_BIN="/usr/bin/timeout"
readonly TOUCH_BIN="/usr/bin/touch"
readonly TRUNCATE_BIN="/usr/bin/truncate"
readonly ARCHIVE_LIMIT_BYTES=268435456
export PATH LC_ALL
umask 077

[[ "${EUID}" -ne 0 ]] || {
  echo "error: provenance regression must run as an unprivileged user" >&2
  exit 1
}
[[ "${BUILD_GATE}" =~ ^/[[:alnum:]_./+@-]+$ && -x "${BUILD_GATE}" ]] || {
  echo "usage: test-build-live-guard-provenance.sh /absolute/build-live-guard-test.sh" >&2
  exit 2
}
[[ -x "${CHMOD_BIN}" && -x "${CP_BIN}" && -x "${ENV_BIN}" && -x "${GIT_BIN}" &&
  -x "${GO_BIN}" && -x "${MKDIR_BIN}" && -x "${MKTEMP_BIN}" &&
  -x "${SHA256_BIN}" && -x "${STAT_BIN}" && -x "${TAR_BIN}" &&
  -x "${TIMEOUT_BIN}" && -x "${TOUCH_BIN}" && -x "${TRUNCATE_BIN}" ]] || {
  echo "error: fixed provenance regression tools are unavailable" >&2
  exit 1
}

fixture_root="$("${MKTEMP_BIN}" -d \
  "/tmp/wg-mix-ebpf-guard-provenance.XXXXXXXXXXXX")"
readonly fixture_root
readonly fixture_repo="${fixture_root}/repo"
readonly fixture_home="${fixture_root}/fixture-home"
readonly poisoned_home="${fixture_root}/poisoned-home"
readonly first_output_parent="${fixture_root}/index-pollution-output"
readonly second_output_parent="${fixture_root}/git-env-pollution-output"
readonly no_tag_parent="${fixture_root}/no-tag-output"
readonly relative_replace_output_parent="${fixture_root}/relative-replace-output"
readonly absolute_replace_output_parent="${fixture_root}/absolute-replace-output"
readonly oversized_output_parent="${fixture_root}/oversized-archive-output"
readonly absolute_outside_module="${fixture_root}/absolute-outside-module"
readonly relative_outside_module="${relative_replace_output_parent}/outside-module"
readonly tar_options_control_output="${fixture_root}/tar-options-control-output"
readonly tar_options_control_action="${fixture_root}/tar-options-control-action.sh"
readonly tar_options_control_marker="${fixture_root}/tar-options-control-action.ran"
readonly tar_options_action="${fixture_root}/tar-options-action.sh"
readonly tar_options_marker="${fixture_root}/tar-options-action.ran"

record_retained_fixture() {
  local exit_code="$1"
  printf 'provenance_fixture_retained path=%s exit=%s\n' \
    "${fixture_root}" "${exit_code}"
  return "${exit_code}"
}
trap 'record_retained_fixture "$?"' EXIT

for directory in \
  "${fixture_repo}/internal/guard/nested/deeper" \
  "${fixture_repo}/scripts" \
  "${fixture_home}" \
  "${poisoned_home}" \
  "${first_output_parent}" \
  "${second_output_parent}" \
  "${no_tag_parent}" \
  "${relative_outside_module}" \
  "${absolute_replace_output_parent}" \
  "${oversized_output_parent}" \
  "${absolute_outside_module}" \
  "${tar_options_control_output}"; do
  "${MKDIR_BIN}" --mode=0700 --parents -- "${directory}"
done

cat >"${fixture_repo}/go.mod" <<'EOF'
module github.com/syx0310/wg-mix-ebpf

go 1.24
EOF
cat >"${fixture_repo}/.gitignore" <<'EOF'
*_bpfel.go
EOF
cat >"${fixture_repo}/internal/guard/guard.go" <<'EOF'
package guard

const archiveGuardSource = "candidate"
EOF
cat >"${fixture_repo}/internal/guard/stable.go" <<'EOF'
package guard

const archiveStableSource = "candidate"
EOF
cat >"${fixture_repo}/internal/guard/unit_test.go" <<'EOF'
package guard

import "testing"

func TestUnitOnly(t *testing.T) {
	if archiveGuardSource != "candidate" || archiveStableSource != "candidate" {
		t.Fatal("mutable worktree source entered the build")
	}
}
EOF
cat >"${fixture_repo}/internal/guard/live_linux_test.go" <<'EOF'
//go:build linux && realhosttest

package guard

import "testing"

var liveGuardBuiltCommit = "unset"

func TestLiveGuardOwnership(t *testing.T) {
	if liveGuardBuiltCommit == "unset" {
		t.Fatal("candidate commit was not embedded")
	}
}
EOF
cat >"${fixture_repo}/internal/guard/nested/deeper/payload.txt" <<'EOF'
nested snapshot payload
EOF
cat >"${fixture_repo}/internal/guard/nested/deeper/runner.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
"${CHMOD_BIN}" 0700 -- \
  "${fixture_repo}/internal/guard/nested/deeper/runner.sh"
"${CP_BIN}" -- "${BUILD_GATE}" \
  "${fixture_repo}/scripts/build-live-guard-test.sh"
readonly fixture_gate="${fixture_repo}/scripts/build-live-guard-test.sh"
[[ -x "${fixture_gate}" ]] || {
  echo "error: candidate builder fixture is not executable" >&2
  exit 1
}

fixture_git() {
  "${ENV_BIN}" -i \
    "PATH=${PATH}" \
    "LC_ALL=${LC_ALL}" \
    "HOME=${fixture_home}" \
    "XDG_CONFIG_HOME=${fixture_home}" \
    "GIT_ATTR_NOSYSTEM=1" \
    "GIT_CONFIG_GLOBAL=/dev/null" \
    "GIT_CONFIG_NOSYSTEM=1" \
    "GIT_CONFIG_SYSTEM=/dev/null" \
    "GIT_NO_REPLACE_OBJECTS=1" \
    "${GIT_BIN}" --no-pager --no-replace-objects \
    -c core.attributesFile=/dev/null \
    -c core.hooksPath=/dev/null \
    -C "${fixture_repo}" "$@"
}

"${ENV_BIN}" -i \
  "PATH=${PATH}" \
  "LC_ALL=${LC_ALL}" \
  "HOME=${fixture_home}" \
  "XDG_CONFIG_HOME=${fixture_home}" \
  "GIT_ATTR_NOSYSTEM=1" \
  "GIT_CONFIG_GLOBAL=/dev/null" \
  "GIT_CONFIG_NOSYSTEM=1" \
  "GIT_CONFIG_SYSTEM=/dev/null" \
  "GIT_NO_REPLACE_OBJECTS=1" \
  "${GIT_BIN}" --no-pager --no-replace-objects \
  -c core.attributesFile=/dev/null \
  -c core.hooksPath=/dev/null \
  init --initial-branch=main "${fixture_repo}"
fixture_git add -- .gitignore go.mod internal/guard scripts/build-live-guard-test.sh
fixture_git update-index --chmod=+x -- \
  internal/guard/nested/deeper/runner.sh
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit -m "fixture candidate"
candidate_commit="$(fixture_git rev-parse HEAD)"
readonly candidate_commit
[[ "${candidate_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: fixture did not create a SHA-1 candidate commit" >&2
  exit 1
}
nested_exec_entry="$(fixture_git ls-files -s -- \
  internal/guard/nested/deeper/runner.sh)"
[[ "${nested_exec_entry}" == \
  100755\ *$'\t'internal/guard/nested/deeper/runner.sh ]] || {
  echo "error: nested executable fixture is not stored with Git mode 100755" >&2
  exit 1
}
readonly expected_archive="${fixture_root}/expected-candidate.tar"
[[ ! -e "${expected_archive}" && ! -L "${expected_archive}" ]] || {
  echo "error: expected candidate archive fixture already exists" >&2
  exit 1
}
fixture_git archive --format=tar "${candidate_commit}" >"${expected_archive}"
expected_archive_sha="$("${SHA256_BIN}" -- "${expected_archive}")"
expected_archive_sha="${expected_archive_sha%% *}"
readonly expected_archive_sha

# Each worktree-only source below is deliberately invalid Go. A build from the
# worktree, normal index, ignored files, or alternate index must therefore fail.
cat >"${fixture_repo}/internal/guard/injected_bpfel.go" <<'EOF'
this ignored Go source must never compile
EOF
fixture_git check-ignore --quiet -- internal/guard/injected_bpfel.go

fixture_git update-index --assume-unchanged -- internal/guard/guard.go
cat >"${fixture_repo}/internal/guard/guard.go" <<'EOF'
this assume-unchanged source must never compile
EOF
assume_entry="$(fixture_git ls-files -v -- internal/guard/guard.go)"
[[ "${assume_entry}" == h\ internal/guard/guard.go ]] || {
  printf 'error: assume-unchanged fixture is not active: %q\n' \
    "${assume_entry}" >&2
  exit 1
}

fixture_git update-index --skip-worktree -- internal/guard/stable.go
cat >"${fixture_repo}/internal/guard/stable.go" <<'EOF'
this skip-worktree source must never compile
EOF
skip_entry="$(fixture_git ls-files -v -- internal/guard/stable.go)"
[[ "${skip_entry}" == S\ internal/guard/stable.go ]] || {
  printf 'error: skip-worktree fixture is not active: %q\n' \
    "${skip_entry}" >&2
  exit 1
}

readonly alternate_index="${fixture_root}/alternate-index"
[[ ! -e "${alternate_index}" && ! -L "${alternate_index}" ]] || {
  echo "error: alternate index fixture already exists" >&2
  exit 1
}
alternate_fixture_git() {
  "${ENV_BIN}" -i \
    "PATH=${PATH}" \
    "LC_ALL=${LC_ALL}" \
    "HOME=${fixture_home}" \
    "XDG_CONFIG_HOME=${fixture_home}" \
    "GIT_ATTR_NOSYSTEM=1" \
    "GIT_CONFIG_GLOBAL=/dev/null" \
    "GIT_CONFIG_NOSYSTEM=1" \
    "GIT_CONFIG_SYSTEM=/dev/null" \
    "GIT_INDEX_FILE=${alternate_index}" \
    "GIT_NO_REPLACE_OBJECTS=1" \
    "${GIT_BIN}" --no-pager --no-replace-objects \
    -c core.attributesFile=/dev/null \
    -c core.hooksPath=/dev/null \
    -C "${fixture_repo}" "$@"
}
alternate_fixture_git read-tree HEAD
alternate_fixture_git add --force -- internal/guard/injected_bpfel.go
alternate_entry="$(alternate_fixture_git ls-files -- \
  internal/guard/injected_bpfel.go)"
[[ "${alternate_entry}" == "internal/guard/injected_bpfel.go" ]] || {
  echo "error: alternate index pollution fixture is missing" >&2
  exit 1
}

cat >"${poisoned_home}/global.gitconfig" <<EOF
[core]
	attributesFile = ${poisoned_home}/malicious.attributes
EOF
cat >"${poisoned_home}/malicious.attributes" <<'EOF'
* export-ignore
EOF
cat >"${tar_options_control_action}" <<EOF
#!/bin/sh
${TOUCH_BIN} -- "${tar_options_control_marker}"
EOF
cat >"${tar_options_action}" <<EOF
#!/bin/sh
${TOUCH_BIN} -- "${tar_options_marker}"
EOF
"${CHMOD_BIN}" 0700 -- "${tar_options_control_action}"
"${CHMOD_BIN}" 0700 -- "${tar_options_action}"
readonly tar_options_control="--checkpoint=1 --checkpoint-action=exec=${tar_options_control_action} --strip-components=1"
readonly malicious_tar_options="--checkpoint=1 --checkpoint-action=exec=${tar_options_action} --strip-components=1"
[[ ! -e "${tar_options_control_marker}" &&
  ! -L "${tar_options_control_marker}" &&
  ! -e "${tar_options_marker}" &&
  ! -L "${tar_options_marker}" ]] || {
  echo "error: TAR_OPTIONS marker already exists" >&2
  exit 1
}

# This intentionally supplies TAR_OPTIONS inside an otherwise empty
# environment. It proves the exact GNU tar options used by the pollution case
# both execute an action and alter extraction when they are not filtered.
printf 'provenance_case_start case=tar-options-effective-control\n'
"${TIMEOUT_BIN}" \
  --signal=TERM \
  --kill-after=2s \
  30s \
  "${ENV_BIN}" \
  -i \
  "PATH=${PATH}" \
  "LC_ALL=${LC_ALL}" \
  "HOME=${fixture_home}" \
  "TMPDIR=${fixture_root}" \
  "TAR_OPTIONS=${tar_options_control}" \
  "${TAR_BIN}" \
  --extract \
  "--file=${expected_archive}" \
  "--directory=${tar_options_control_output}" \
  --no-same-owner \
  --no-same-permissions
[[ -f "${tar_options_control_marker}" &&
  ! -L "${tar_options_control_marker}" &&
  -f "${tar_options_control_output}/guard/guard.go" &&
  -f "${tar_options_control_output}/guard/nested/deeper/payload.txt" &&
  ! -e "${tar_options_control_output}/internal/guard/guard.go" &&
  ! -L "${tar_options_control_output}/internal/guard/guard.go" ]] || {
  echo "error: TAR_OPTIONS effective control did not execute and alter extraction" >&2
  exit 1
}

run_gate_with_poisoned_environment() {
  "${ENV_BIN}" \
    "TAR_OPTIONS=${malicious_tar_options}" \
    "GOENV=${fixture_root}/does-not-exist-goenv" \
    "GOFLAGS=-modfile=${fixture_root}/does-not-exist.mod" \
    "GOWORK=${fixture_root}/does-not-exist.work" \
    "GOCACHE=off" \
    "GOMODCACHE=${fixture_root}/poisoned-modcache" \
    "GOTOOLCHAIN=does-not-exist" \
    "PYTHONHASHSEED=not-an-integer" \
    "PYTHONHOME=${fixture_root}/does-not-exist-python-home" \
    "PYTHONPATH=${fixture_root}/does-not-exist-python-path" \
    "PYTHONWARNINGS=error" \
    "GIT_ALTERNATE_OBJECT_DIRECTORIES=${fixture_root}/does-not-exist-objects" \
    "GIT_CONFIG_COUNT=1" \
    "GIT_CONFIG_KEY_0=core.attributesFile" \
    "GIT_CONFIG_VALUE_0=${poisoned_home}/malicious.attributes" \
    "GIT_DIR=${fixture_root}/does-not-exist-git-dir" \
    "GIT_INDEX_FILE=${alternate_index}" \
    "GIT_NO_REPLACE_OBJECTS=0" \
    "GIT_OBJECT_DIRECTORY=${fixture_root}/does-not-exist-object-dir" \
    "GIT_WORK_TREE=${fixture_root}/does-not-exist-work-tree" \
    "${fixture_gate}" "$@"
}

assert_snapshot_entry() {
  local path="$1"
  local expected_mode="$2"
  local expected_kind="$3"
  local expected_links="${4:-}"
  local actual_uid
  local actual_mode
  local actual_links
  local actual_kind

  [[ ! -L "${path}" ]] || {
    printf 'error: sealed snapshot entry is a symlink: %s\n' "${path}" >&2
    return 1
  }
  read -r actual_uid actual_mode actual_links actual_kind < <(
    "${STAT_BIN}" -c '%u %a %h %F' -- "${path}"
  )
  [[ "${actual_uid}" == "${EUID}" &&
    "${actual_mode}" == "${expected_mode}" &&
    "${actual_kind}" == "${expected_kind}" ]] || {
    printf 'error: sealed snapshot entry metadata mismatch: path=%s uid=%s mode=%s links=%s type=%s\n' \
      "${path}" "${actual_uid}" "${actual_mode}" "${actual_links}" \
      "${actual_kind}" >&2
    return 1
  }
  if [[ -n "${expected_links}" &&
    "${actual_links}" != "${expected_links}" ]]; then
    printf 'error: sealed snapshot entry link count mismatch: path=%s links=%s\n' \
      "${path}" "${actual_links}" >&2
    return 1
  fi
}

assert_sealed_snapshot() {
  local snapshot="$1"

  assert_snapshot_entry "${snapshot}" "500" "directory"
  assert_snapshot_entry "${snapshot}/internal" "500" "directory"
  assert_snapshot_entry "${snapshot}/internal/guard" "500" "directory"
  assert_snapshot_entry \
    "${snapshot}/internal/guard/nested" "500" "directory"
  assert_snapshot_entry \
    "${snapshot}/internal/guard/nested/deeper" "500" "directory"
  assert_snapshot_entry \
    "${snapshot}/internal/guard/nested/deeper/payload.txt" \
    "400" "regular file" "1"
  assert_snapshot_entry \
    "${snapshot}/internal/guard/nested/deeper/runner.sh" \
    "500" "regular file" "1"
  assert_snapshot_entry \
    "${snapshot}/scripts/build-live-guard-test.sh" \
    "500" "regular file" "1"
}

printf 'provenance_case_start case=ignored-assume-skip-index commit=%s\n' \
  "${candidate_commit}"
(
  builtin cd "${fixture_repo}"
  HOME="${poisoned_home}" \
    XDG_CONFIG_HOME="${poisoned_home}" \
    GIT_CONFIG_GLOBAL="${poisoned_home}/global.gitconfig" \
    GIT_INDEX_FILE="${alternate_index}" \
    "${fixture_gate}" \
    --candidate-commit "${candidate_commit}" \
    --output "${first_output_parent}/guard-live.test"
)
[[ -x "${first_output_parent}/guard-live.test" &&
  ! -e "${first_output_parent}/source-snapshot/internal/guard/injected_bpfel.go" ]] || {
  echo "error: index-pollution provenance build result is unsafe" >&2
  exit 1
}
assert_sealed_snapshot "${first_output_parent}/source-snapshot"

printf 'provenance_case_start case=all-tool-environment-pollution commit=%s\n' \
  "${candidate_commit}"
(
  builtin cd "${fixture_repo}"
  run_gate_with_poisoned_environment \
    --candidate-commit "${candidate_commit}" \
    --output "${second_output_parent}/guard-live.test"
)
[[ -x "${second_output_parent}/guard-live.test" ]] || {
  echo "error: tool-environment-pollution provenance build failed" >&2
  exit 1
}
[[ ! -e "${tar_options_marker}" && ! -L "${tar_options_marker}" ]] || {
  echo "error: malicious TAR_OPTIONS executed during snapshot extraction" >&2
  exit 1
}
assert_sealed_snapshot "${second_output_parent}/source-snapshot"

first_archive_sha="$("${SHA256_BIN}" -- \
  "${first_output_parent}/candidate.tar")"
first_archive_sha="${first_archive_sha%% *}"
second_archive_sha="$("${SHA256_BIN}" -- \
  "${second_output_parent}/candidate.tar")"
second_archive_sha="${second_archive_sha%% *}"
[[ "${first_archive_sha}" == "${second_archive_sha}" ]] || {
  echo "error: candidate archive changed under Git environment pollution" >&2
  exit 1
}
[[ "${first_archive_sha}" == "${expected_archive_sha}" ]] || {
  echo "error: isolated candidate archive does not match the exact commit archive" >&2
  exit 1
}
first_binary_sha="$("${SHA256_BIN}" -- \
  "${first_output_parent}/guard-live.test")"
first_binary_sha="${first_binary_sha%% *}"
second_binary_sha="$("${SHA256_BIN}" -- \
  "${second_output_parent}/guard-live.test")"
second_binary_sha="${second_binary_sha%% *}"
[[ "${first_binary_sha}" == "${second_binary_sha}" ]] || {
  echo "error: tagged artifact changed under Git environment pollution" >&2
  exit 1
}

for directory in \
  "${no_tag_parent}/home" \
  "${no_tag_parent}/tmp" \
  "${no_tag_parent}/cache" \
  "${no_tag_parent}/modcache"; do
  "${MKDIR_BIN}" --mode=0700 -- "${directory}"
done
readonly no_tag_binary="${no_tag_parent}/guard-no-tag.test"
"${ENV_BIN}" -i \
  "--chdir=${first_output_parent}/source-snapshot" \
  "PATH=${PATH}" \
  "LC_ALL=${LC_ALL}" \
  "HOME=${no_tag_parent}/home" \
  "TMPDIR=${no_tag_parent}/tmp" \
  "GOTMPDIR=${no_tag_parent}/tmp" \
  "GOCACHE=${no_tag_parent}/cache" \
  "GOMODCACHE=${no_tag_parent}/modcache" \
  "CGO_ENABLED=0" \
  "GOENV=off" \
  "GOFLAGS=-mod=readonly -buildvcs=false" \
  "GOTOOLCHAIN=local" \
  "GOWORK=off" \
  "${GO_BIN}" test -trimpath -c -o "${no_tag_binary}" ./internal/guard
"${fixture_gate}" --self-test-reject-test-binary "${no_tag_binary}"

expect_gate_failure() {
  local label="$1"
  local candidate="$2"
  local output_parent="$3"
  local expected_message="$4"
  local expected_suffix="${5:-}"
  local gate_output
  local gate_exit

  printf 'provenance_case_start case=%s commit=%s\n' \
    "${label}" "${candidate}"
  set +e
  gate_output="$(
    (
      builtin cd "${fixture_repo}"
      run_gate_with_poisoned_environment \
        --candidate-commit "${candidate}" \
        --output "${output_parent}/guard-live.test"
    ) 2>&1
  )"
  gate_exit=$?
  set -e
  printf '%s\n' "${gate_output}"
  [[ "${gate_exit}" -ne 0 ]] || {
    printf 'error: expected provenance rejection succeeded: case=%s\n' \
      "${label}" >&2
    return 1
  }
  [[ "${gate_output}" == *"${expected_message}"* ]] || {
    printf 'error: provenance rejection reason mismatch: case=%s exit=%s\n' \
      "${label}" "${gate_exit}" >&2
    return 1
  }
  if [[ -n "${expected_suffix}" &&
    "${gate_output}" != *"${expected_suffix}" ]]; then
    printf 'error: provenance secondary rejection evidence missing: case=%s exit=%s\n' \
      "${label}" "${gate_exit}" >&2
    return 1
  fi
  [[ ! -e "${output_parent}/guard-live.test" &&
    ! -L "${output_parent}/guard-live.test" ]] || {
    printf 'error: rejected provenance case created a test binary: case=%s\n' \
      "${label}" >&2
    return 1
  }
  [[ ! -e "${tar_options_marker}" && ! -L "${tar_options_marker}" ]] || {
    printf 'error: rejected provenance case executed TAR_OPTIONS: case=%s\n' \
      "${label}" >&2
    return 1
  }
  printf 'provenance_case_rejected case=%s exit=%s\n' \
    "${label}" "${gate_exit}"
}

cat >"${relative_outside_module}/go.mod" <<'EOF'
module example.com/outside

go 1.24
EOF
cat >"${relative_outside_module}/outside.go" <<'EOF'
package outside

const Mutable = true
EOF
cat >"${absolute_outside_module}/go.mod" <<'EOF'
module example.com/outside

go 1.24
EOF
cat >"${absolute_outside_module}/outside.go" <<'EOF'
package outside

const Mutable = true
EOF
[[ -w "${relative_outside_module}/go.mod" &&
  -w "${absolute_outside_module}/go.mod" ]] || {
  echo "error: outside-module fixtures are not mutable" >&2
  exit 1
}

cat >"${fixture_repo}/go.mod" <<'EOF'
module github.com/syx0310/wg-mix-ebpf

go 1.24

replace example.com/outside => ../outside-module
EOF
fixture_git add -- go.mod
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit -m "fixture relative local replacement"
relative_replace_commit="$(fixture_git rev-parse HEAD)"
readonly relative_replace_commit
[[ "${relative_replace_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: relative-replace fixture commit is invalid" >&2
  exit 1
}
expect_gate_failure \
  "relative-local-replace" \
  "${relative_replace_commit}" \
  "${relative_replace_output_parent}" \
  "error: candidate go.mod contains a forbidden local replacement at Replace[0]"

cat >"${fixture_repo}/go.mod" <<EOF
module github.com/syx0310/wg-mix-ebpf

go 1.24

replace example.com/outside => ${absolute_outside_module}
EOF
fixture_git add -- go.mod
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit -m "fixture absolute local replacement"
absolute_replace_commit="$(fixture_git rev-parse HEAD)"
readonly absolute_replace_commit
[[ "${absolute_replace_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: absolute-replace fixture commit is invalid" >&2
  exit 1
}
expect_gate_failure \
  "absolute-local-replace" \
  "${absolute_replace_commit}" \
  "${absolute_replace_output_parent}" \
  "error: candidate go.mod contains a forbidden local replacement at Replace[0]"

readonly oversized_source="${fixture_repo}/zz-oversized.bin"
"${TRUNCATE_BIN}" --size="$((ARCHIVE_LIMIT_BYTES + 1))" -- \
  "${oversized_source}"
read -r oversized_source_size oversized_source_kind < <(
  "${STAT_BIN}" -c '%s %F' -- "${oversized_source}"
)
[[ "${oversized_source_size}" -eq "$((ARCHIVE_LIMIT_BYTES + 1))" &&
  "${oversized_source_kind}" == "regular file" ]] || {
  echo "error: oversized sparse archive fixture is invalid" >&2
  exit 1
}
fixture_git add -- zz-oversized.bin
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit -m "fixture oversized candidate archive"
oversized_commit="$(fixture_git rev-parse HEAD)"
readonly oversized_commit
[[ "${oversized_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: oversized fixture commit is invalid" >&2
  exit 1
}
expect_gate_failure \
  "oversized-candidate-archive" \
  "${oversized_commit}" \
  "${oversized_output_parent}" \
  "error: candidate archive exceeds 268435456 byte hard limit" \
  "limiter=1"
readonly partial_archive="${oversized_output_parent}/candidate.tar"
[[ -f "${partial_archive}" && ! -L "${partial_archive}" ]] || {
  echo "error: oversized archive failure did not retain a partial archive" >&2
  exit 1
}
read -r partial_archive_size partial_archive_links partial_archive_kind < <(
  "${STAT_BIN}" -c '%s %h %F' -- "${partial_archive}"
)
[[ "${partial_archive_size}" -gt 0 &&
  "${partial_archive_size}" -le "${ARCHIVE_LIMIT_BYTES}" &&
  "${partial_archive_links}" == "1" &&
  "${partial_archive_kind}" == "regular file" ]] || {
  echo "error: oversized archive limiter wrote beyond its hard bound" >&2
  exit 1
}
[[ ! -e "${oversized_output_parent}/source-snapshot/go.mod" &&
  ! -L "${oversized_output_parent}/source-snapshot/go.mod" ]] || {
  echo "error: oversized archive failure reached snapshot extraction" >&2
  exit 1
}

printf 'live guard build provenance regression passed commit=%s archive_sha256=%s\n' \
  "${candidate_commit}" "${first_archive_sha}"
