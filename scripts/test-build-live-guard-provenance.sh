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
  -x "${SHA256_BIN}" ]] || {
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

record_retained_fixture() {
  local exit_code="$1"
  printf 'provenance_fixture_retained path=%s exit=%s\n' \
    "${fixture_root}" "${exit_code}"
  return "${exit_code}"
}
trap 'record_retained_fixture "$?"' EXIT

for directory in \
  "${fixture_repo}/internal/guard" \
  "${fixture_repo}/scripts" \
  "${fixture_home}" \
  "${poisoned_home}" \
  "${first_output_parent}" \
  "${second_output_parent}" \
  "${no_tag_parent}"; do
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

printf 'provenance_case_start case=all-git-environment commit=%s\n' \
  "${candidate_commit}"
(
  builtin cd "${fixture_repo}"
  GIT_ALTERNATE_OBJECT_DIRECTORIES="${fixture_root}/does-not-exist-objects" \
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=core.attributesFile \
    GIT_CONFIG_VALUE_0="${poisoned_home}/malicious.attributes" \
    GIT_DIR="${fixture_root}/does-not-exist-git-dir" \
    GIT_INDEX_FILE="${alternate_index}" \
    GIT_NO_REPLACE_OBJECTS=0 \
    GIT_OBJECT_DIRECTORY="${fixture_root}/does-not-exist-object-dir" \
    GIT_WORK_TREE="${fixture_root}/does-not-exist-work-tree" \
    "${fixture_gate}" \
    --candidate-commit "${candidate_commit}" \
    --output "${second_output_parent}/guard-live.test"
)
[[ -x "${second_output_parent}/guard-live.test" ]] || {
  echo "error: Git-environment-pollution provenance build failed" >&2
  exit 1
}

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

printf 'live guard build provenance regression passed commit=%s archive_sha256=%s\n' \
  "${candidate_commit}" "${first_archive_sha}"
