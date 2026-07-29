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
readonly LN_BIN="/usr/bin/ln"
readonly MKDIR_BIN="/usr/bin/mkdir"
readonly MKTEMP_BIN="/usr/bin/mktemp"
readonly PYTHON3_BIN="/usr/bin/python3"
readonly SHA256_BIN="/usr/bin/sha256sum"
readonly STAT_BIN="/usr/bin/stat"
readonly TAR_BIN="/usr/bin/tar"
readonly TIMEOUT_BIN="/usr/bin/timeout"
readonly TOUCH_BIN="/usr/bin/touch"
readonly TRUNCATE_BIN="/usr/bin/truncate"
readonly ARCHIVE_LIMIT_BYTES=268435456
readonly TREE_INVENTORY_LIMIT_BYTES=33554432
readonly BLOB_ORACLE_LIMIT_BYTES=268435456
readonly OVERSIZED_CHUNK_BYTES=1048576
readonly OVERSIZED_CHUNK_COUNT=257
export PATH LC_ALL
umask 077

readonly TMPDIR_GATE_PYTHON='import os
import re
import stat
import sys

SAFE_PATH = re.compile(r"/[A-Za-z0-9_./+@-]+")


class GateError(RuntimeError):
    pass


def reject(message):
    raise GateError(message)


def require_path_text(path):
    if (
        not path
        or not os.path.isabs(path)
        or path == "/"
        or path.startswith("//")
        or os.path.normpath(path) != path
        or SAFE_PATH.fullmatch(path) is None
    ):
        reject("path is not an absolute normalized safe path")


def require_ancestor_metadata(kind, owner, permissions, expected_owner):
    if kind != stat.S_IFDIR:
        reject("path chain contains a non-directory or symlink")
    if owner not in (0, expected_owner):
        reject("path chain contains an untrusted owner")
    if permissions & 0o022 and not permissions & stat.S_ISVTX:
        reject("path chain contains an unsafe writable directory")


def require_private_metadata(kind, owner, permissions, expected_owner):
    if kind != stat.S_IFDIR:
        reject("controlled temporary parent is not a real directory")
    if owner != expected_owner:
        reject("controlled temporary parent has the wrong owner")
    if permissions != 0o700:
        reject("controlled temporary parent mode is not 0700")


def require_default_metadata(kind, owner, permissions, expected_owner):
    if kind != stat.S_IFDIR:
        reject("default temporary parent is not a real directory")
    private_parent = owner == expected_owner and permissions == 0o700
    system_parent = owner == 0 and permissions == 0o1777
    if not private_parent and not system_parent:
        reject("default temporary parent metadata is unsafe")


def metadata_fields(metadata):
    return (
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def require_safe_chain(path, expected_owner):
    current = "/"
    components = [current]
    for component in path.split("/")[1:]:
        current = os.path.join(current, component)
        components.append(current)
    for component in components:
        metadata = os.lstat(component)
        require_ancestor_metadata(
            *metadata_fields(metadata),
            expected_owner,
        )


def require_access(path):
    if not os.access(path, os.W_OK | os.X_OK, effective_ids=True):
        reject("temporary parent is not writable and searchable")


def resolve_controlled(
    path,
    expected_owner,
    realpath=os.path.realpath,
    safe_chain=require_safe_chain,
    lstat=os.lstat,
    access=require_access,
):
    require_path_text(path)
    if realpath(path) != path:
        reject("controlled temporary parent is not canonical")
    safe_chain(path, expected_owner)
    metadata = lstat(path)
    require_private_metadata(*metadata_fields(metadata), expected_owner)
    access(path)
    return path, metadata


def resolve_default(path, expected_owner):
    require_path_text(path)
    source = os.lstat(path)
    source_kind = stat.S_IFMT(source.st_mode)
    if source_kind == stat.S_IFLNK:
        if source.st_uid != 0:
            reject("default temporary symlink is not root-owned")
    elif source_kind != stat.S_IFDIR:
        reject("default temporary path is neither a directory nor symlink")
    canonical = os.path.realpath(path)
    require_path_text(canonical)
    require_safe_chain(canonical, expected_owner)
    metadata = os.lstat(canonical)
    require_default_metadata(*metadata_fields(metadata), expected_owner)
    require_access(canonical)
    return canonical, metadata


def expect_rejected(function, *arguments):
    try:
        function(*arguments)
    except GateError:
        return
    reject("TMPDIR gate self-test accepted an unsafe case")


def synthetic_metadata(kind, owner, permissions):
    return os.stat_result(
        (kind | permissions, 1, 1, 1, owner, 0, 0, 0, 0, 0)
    )


def self_test():
    owner = 1234
    controlled_path = "/home/test/wg-runs/run-1/tmp"
    require_path_text(controlled_path)
    for path in (
        "",
        "tmp",
        "/",
        "//tmp",
        "/tmp/",
        "/tmp/../unsafe",
        "/tmp/./unsafe",
        "/tmp unsafe",
        "/tmp\nunsafe",
    ):
        expect_rejected(require_path_text, path)

    require_ancestor_metadata(stat.S_IFDIR, 0, 0o755, owner)
    require_ancestor_metadata(stat.S_IFDIR, owner, 0o700, owner)
    require_ancestor_metadata(stat.S_IFDIR, 0, 0o1777, owner)
    require_private_metadata(stat.S_IFDIR, owner, 0o700, owner)
    require_default_metadata(stat.S_IFDIR, 0, 0o1777, owner)
    require_default_metadata(stat.S_IFDIR, owner, 0o700, owner)
    unsafe_metadata_checks = (
        (require_ancestor_metadata, (stat.S_IFLNK, 0, 0o777, owner)),
        (require_ancestor_metadata, (stat.S_IFDIR, owner + 1, 0o755, owner)),
        (require_ancestor_metadata, (stat.S_IFDIR, 0, 0o777, owner)),
        (require_private_metadata, (stat.S_IFREG, owner, 0o700, owner)),
        (require_private_metadata, (stat.S_IFDIR, 0, 0o700, owner)),
        (require_private_metadata, (stat.S_IFDIR, owner, 0o750, owner)),
        (require_default_metadata, (stat.S_IFDIR, 0, 0o777, owner)),
        (require_default_metadata, (stat.S_IFDIR, owner + 1, 0o700, owner)),
    )
    for function, arguments in unsafe_metadata_checks:
        expect_rejected(function, *arguments)

    private = synthetic_metadata(stat.S_IFDIR, owner, 0o700)
    unsafe_entries = (
        synthetic_metadata(stat.S_IFDIR, owner + 1, 0o700),
        synthetic_metadata(stat.S_IFDIR, owner, 0o750),
        synthetic_metadata(stat.S_IFLNK, owner, 0o777),
    )
    calls = []

    def check_chain(path, expected_owner):
        calls.append(("chain", path, expected_owner))

    def check_access(path):
        calls.append(("access", path))

    identity = lambda path: path
    private_entry = lambda path: private
    resolved, metadata = resolve_controlled(
        controlled_path,
        owner,
        identity,
        check_chain,
        private_entry,
        check_access,
    )
    if (
        (resolved, metadata) != (controlled_path, private)
        or calls
        != [
            ("chain", controlled_path, owner),
            ("access", controlled_path),
        ]
    ):
        reject("controlled TMPDIR success path did not enforce every gate")

    controlled_prefix = (resolve_controlled, controlled_path, owner)
    expect_rejected(
        *controlled_prefix,
        lambda path: "/different",
        check_chain,
        private_entry,
        check_access,
    )
    expect_rejected(
        *controlled_prefix,
        identity,
        lambda path, expected_owner: reject("synthetic unsafe ancestor"),
        private_entry,
        check_access,
    )
    for entry in unsafe_entries:
        expect_rejected(
            *controlled_prefix,
            identity,
            check_chain,
            lambda path, value=entry: value,
            check_access,
        )
    expect_rejected(
        *controlled_prefix,
        identity,
        check_chain,
        private_entry,
        lambda path: reject("synthetic access failure"),
    )
    resolve_default("/tmp", os.geteuid())


def main():
    arguments = sys.argv[1:]
    if arguments == ["--self-test"]:
        self_test()
        return
    if len(arguments) != 2 or arguments[0] not in ("controlled", "default"):
        reject("internal TMPDIR gate invocation is invalid")
    policy, path = arguments
    if policy == "controlled":
        resolved, metadata = resolve_controlled(path, os.geteuid())
    else:
        resolved, metadata = resolve_default(path, os.geteuid())
    print(f"{resolved} {metadata.st_dev} {metadata.st_ino}")


try:
    main()
except (GateError, OSError) as error:
    print(f"error: unsafe provenance temporary parent: {error}", file=sys.stderr)
    raise SystemExit(1)
'

run_tmpdir_gate() {
  "${PYTHON3_BIN}" -I -B -c "${TMPDIR_GATE_PYTHON}" "$@"
}

set_fixture_parent_selection() {
  if [[ "${TMPDIR+x}" == "x" ]]; then
    fixture_parent_policy="controlled"
    fixture_parent_candidate="${TMPDIR}"
  else
    fixture_parent_policy="default"
    fixture_parent_candidate="/tmp"
  fi
}

identity_record_is_valid() {
  local record="$1"

  [[ -n "${record}" &&
    "${record}" != *$'\n'* &&
    "${record}" =~ ^(/[[:alnum:]_./+@-]+)\ ([0-9]+)\ ([0-9]+)$ ]]
}

fixture_identity_record_matches() {
  local record="$1"
  local expected_path="$2"
  local expected_parent="$3"

  identity_record_is_valid "${record}" &&
    [[ "${record%% *}" == "${expected_path}" &&
      "${expected_path%/*}" == "${expected_parent}" ]]
}

identity_records_match() {
  local before="$1"
  local after="$2"

  identity_record_is_valid "${before}" &&
    identity_record_is_valid "${after}" &&
    [[ "${after}" == "${before}" ]]
}

export_fixture_tmpdir() {
  [[ "$#" -eq 1 && "$1" == /* ]] || return 1
  TMPDIR="$1"
  export TMPDIR
}

run_isolated_environment() {
  local isolated_tmpdir="$1"
  local option_count="$2"
  local environment_option=""

  shift 2
  [[ "${isolated_tmpdir}" == /* &&
    "${option_count}" =~ ^[01]$ ]] || return 1
  if [[ "${option_count}" == "1" ]]; then
    [[ "$#" -gt 0 ]] || return 1
    environment_option="$1"
    shift
  fi
  [[ "$#" -gt 0 ]] || return 1
  if [[ "${option_count}" == "1" ]]; then
    "${ENV_BIN}" -i \
      "${environment_option}" \
      "PATH=${PATH}" \
      "LC_ALL=${LC_ALL}" \
      "TMPDIR=${isolated_tmpdir}" \
      "$@"
  else
    "${ENV_BIN}" -i \
      "PATH=${PATH}" \
      "LC_ALL=${LC_ALL}" \
      "TMPDIR=${isolated_tmpdir}" \
      "$@"
  fi
}

tmpdir_gate_shell_self_test() {
  local environment_probe
  local option_environment_probe
  local expected_environment
  local exported_tmpdir_probe
  local fixture_parent_candidate
  local fixture_parent_policy
  local unsafe_tmpdir

  unset TMPDIR
  set_fixture_parent_selection
  [[ "${fixture_parent_policy}" == "default" &&
    "${fixture_parent_candidate}" == "/tmp" ]] || return 1
  TMPDIR=""
  set_fixture_parent_selection
  [[ "${fixture_parent_policy}" == "controlled" &&
    -z "${fixture_parent_candidate}" ]] || return 1
  if run_tmpdir_gate \
    "${fixture_parent_policy}" "${fixture_parent_candidate}" \
    >/dev/null 2>&1; then
    return 1
  fi
  TMPDIR="/controlled/tmp"
  set_fixture_parent_selection
  [[ "${fixture_parent_policy}" == "controlled" &&
    "${fixture_parent_candidate}" == "${TMPDIR}" ]] || return 1
  for unsafe_tmpdir in \
    $'/controlled/tmp\n' \
    $'/controlled/tmp\r\n' \
    $'/controlled/tmp\n\n'; do
    TMPDIR="${unsafe_tmpdir}"
    set_fixture_parent_selection
    [[ "${fixture_parent_policy}" == "controlled" &&
      "${fixture_parent_candidate}" == "${unsafe_tmpdir}" ]] || return 1
    if run_tmpdir_gate \
      "${fixture_parent_policy}" "${fixture_parent_candidate}" \
      >/dev/null 2>&1; then
      return 1
    fi
  done

  identity_record_is_valid "/controlled/tmp 11 22" || return 1
  if identity_record_is_valid $'/controlled/tmp 11 22\n/injected 33 44' ||
    identity_record_is_valid "/controlled/tmp 11 22 extra" ||
    identity_record_is_valid "/controlled/tmp device 22"; then
    return 1
  fi
  fixture_identity_record_matches \
    "/controlled/tmp/fixture 33 44" \
    "/controlled/tmp/fixture" \
    "/controlled/tmp" || return 1
  if fixture_identity_record_matches \
    "/outside/fixture 33 44" \
    "/controlled/tmp/fixture" \
    "/controlled/tmp"; then
    return 1
  fi
  if fixture_identity_record_matches \
    "/controlled/tmp/fixture 33 44" \
    "/controlled/tmp/fixture" \
    "/outside"; then
    return 1
  fi
  identity_records_match \
    "/controlled/tmp 11 22" \
    "/controlled/tmp 11 22" || return 1
  if identity_records_match \
    "/controlled/tmp 11 22" \
    "/controlled/tmp 11 23"; then
    return 1
  fi

  exported_tmpdir_probe="$(
    TMPDIR="/poisoned/tmp"
    export_fixture_tmpdir "/controlled/tmp"
    "${PYTHON3_BIN}" -I -B -c \
      'import os; print(os.environ.get("TMPDIR", ""))'
  )"
  [[ "${exported_tmpdir_probe}" == "/controlled/tmp" ]] || return 1
  environment_probe="$(
    HOME="/poisoned/home" \
      TMPDIR="/poisoned/tmp" \
      run_isolated_environment \
      "/controlled/tmp" 0 "${ENV_BIN}"
  )"
  expected_environment="$(
    printf 'PATH=%s\nLC_ALL=%s\nTMPDIR=/controlled/tmp\n' \
      "${PATH}" "${LC_ALL}"
  )"
  [[ "${environment_probe}" == "${expected_environment}" ]] || return 1
  option_environment_probe="$(
    run_isolated_environment \
      "/controlled/tmp" 1 "-i" "${ENV_BIN}"
  )"
  [[ "${option_environment_probe}" == "${expected_environment}" ]] || return 1
}

if [[ "${BUILD_GATE}" == "--self-test-tmpdir-gate" ]]; then
  [[ "$#" -eq 1 &&
    -x "${ENV_BIN}" &&
    -x "${PYTHON3_BIN}" ]] || {
    echo "error: TMPDIR gate self-test prerequisites are unavailable" >&2
    exit 1
  }
  run_tmpdir_gate --self-test
  tmpdir_gate_shell_self_test || {
    echo "error: provenance TMPDIR shell gate self-test failed" >&2
    exit 1
  }
  echo "provenance TMPDIR gate self-test passed"
  exit 0
fi

[[ "${EUID}" -ne 0 ]] || {
  echo "error: provenance regression must run as an unprivileged user" >&2
  exit 1
}
[[ "${BUILD_GATE}" =~ ^/[[:alnum:]_./+@-]+$ && -x "${BUILD_GATE}" ]] || {
  echo "usage: test-build-live-guard-provenance.sh /absolute/build-live-guard-test.sh" >&2
  exit 2
}
[[ -x "${CHMOD_BIN}" && -x "${CP_BIN}" && -x "${ENV_BIN}" && -x "${GIT_BIN}" &&
  -x "${GO_BIN}" && -x "${LN_BIN}" && -x "${MKDIR_BIN}" && -x "${MKTEMP_BIN}" &&
  -x "${PYTHON3_BIN}" && -x "${SHA256_BIN}" && -x "${STAT_BIN}" && -x "${TAR_BIN}" &&
  -x "${TIMEOUT_BIN}" && -x "${TOUCH_BIN}" && -x "${TRUNCATE_BIN}" ]] || {
  echo "error: fixed provenance regression tools are unavailable" >&2
  exit 1
}

set_fixture_parent_selection
fixture_parent_record="$(
  run_tmpdir_gate \
    "${fixture_parent_policy}" \
    "${fixture_parent_candidate}"
)"
identity_record_is_valid "${fixture_parent_record}" || {
  echo "error: TMPDIR gate returned malformed parent identity" >&2
  exit 1
}
fixture_parent="${fixture_parent_record%% *}"
readonly fixture_parent_policy
readonly fixture_parent
readonly fixture_parent_record

fixture_root="$("${MKTEMP_BIN}" -d \
  "${fixture_parent}/wg-mix-ebpf-guard-provenance.XXXXXXXXXXXX")"
[[ "${fixture_root%/*}" == "${fixture_parent}" ]] || {
  printf 'error: mktemp returned a fixture outside the validated parent: path=%s parent=%s\n' \
    "${fixture_root}" "${fixture_parent}" >&2
  exit 1
}
fixture_root_record="$(run_tmpdir_gate controlled "${fixture_root}")"
fixture_identity_record_matches \
  "${fixture_root_record}" \
  "${fixture_root}" \
  "${fixture_parent}" || {
  printf 'error: created provenance fixture identity is unsafe: path=%s\n' \
    "${fixture_root}" >&2
  exit 1
}
fixture_parent_after_record="$(
  run_tmpdir_gate "${fixture_parent_policy}" "${fixture_parent}"
)"
identity_records_match \
  "${fixture_parent_record}" \
  "${fixture_parent_after_record}" || {
  printf 'error: validated temporary parent changed during fixture creation: parent=%s fixture=%s\n' \
    "${fixture_parent}" "${fixture_root}" >&2
  exit 1
}
readonly fixture_root
export_fixture_tmpdir "${fixture_root}"
readonly TMPDIR
readonly fixture_repo="${fixture_root}/repo"
readonly fixture_home="${fixture_root}/fixture-home"
readonly poisoned_home="${fixture_root}/poisoned-home"
readonly first_output_parent="${fixture_root}/index-pollution-output"
readonly second_output_parent="${fixture_root}/git-env-pollution-output"
readonly no_tag_parent="${fixture_root}/no-tag-output"
readonly export_ignore_output_parent="${fixture_root}/export-ignore-output"
readonly export_subst_output_parent="${fixture_root}/export-subst-output"
readonly relative_replace_output_parent="${fixture_root}/relative-replace-output"
readonly absolute_replace_output_parent="${fixture_root}/absolute-replace-output"
readonly gitlink_output_parent="${fixture_root}/gitlink-output"
readonly malformed_tree_output_parent="${fixture_root}/malformed-tree-output"
readonly byte_paths_output_parent="${fixture_root}/byte-paths-output"
readonly oversized_output_parent="${fixture_root}/oversized-archive-output"
readonly symlink_output_parent="${fixture_root}/symlink-output"
readonly embedded_probe_root="${fixture_root}/embedded-probes"
readonly tree_probe_parent="${embedded_probe_root}/tree-inventory"
readonly blob_limit_probe_parent="${embedded_probe_root}/blob-limiter"
readonly blob_batch_probe_parent="${embedded_probe_root}/blob-batch"
readonly stat_regular_probe_parent="${embedded_probe_root}/stat-regular"
readonly seal_probe_parent="${embedded_probe_root}/snapshot-seal"
readonly seal_probe_snapshot="${seal_probe_parent}/source-snapshot"
readonly seal_mode_probe_parent="${embedded_probe_root}/snapshot-seal-mode"
readonly seal_mode_probe_snapshot="${seal_mode_probe_parent}/source-snapshot"
readonly seal_content_probe_parent="${embedded_probe_root}/snapshot-seal-content"
readonly seal_content_probe_snapshot="${seal_content_probe_parent}/source-snapshot"
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
  "${export_ignore_output_parent}" \
  "${export_subst_output_parent}" \
  "${relative_outside_module}" \
  "${absolute_replace_output_parent}" \
  "${gitlink_output_parent}" \
  "${malformed_tree_output_parent}" \
  "${byte_paths_output_parent}" \
  "${oversized_output_parent}" \
  "${symlink_output_parent}" \
  "${tree_probe_parent}" \
  "${blob_limit_probe_parent}" \
  "${blob_batch_probe_parent}" \
  "${stat_regular_probe_parent}" \
  "${seal_probe_snapshot}" \
  "${seal_mode_probe_snapshot}" \
  "${seal_content_probe_snapshot}" \
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
build_gate_sha="$("${SHA256_BIN}" -- "${BUILD_GATE}")"
build_gate_sha="${build_gate_sha%% *}"
fixture_gate_sha="$("${SHA256_BIN}" -- "${fixture_gate}")"
fixture_gate_sha="${fixture_gate_sha%% *}"
readonly build_gate_sha fixture_gate_sha
[[ "${fixture_gate_sha}" == "${build_gate_sha}" ]] || {
  echo "error: copied candidate builder differs from the reviewed build gate" >&2
  exit 1
}

fixture_git() {
  run_isolated_environment "${fixture_root}" 0 \
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

fixture_index_git() {
  local index_path="$1"
  shift

  run_isolated_environment "${fixture_root}" 0 \
    "HOME=${fixture_home}" \
    "XDG_CONFIG_HOME=${fixture_home}" \
    "GIT_ATTR_NOSYSTEM=1" \
    "GIT_CONFIG_GLOBAL=/dev/null" \
    "GIT_CONFIG_NOSYSTEM=1" \
    "GIT_CONFIG_SYSTEM=/dev/null" \
    "GIT_INDEX_FILE=${index_path}" \
    "GIT_NO_REPLACE_OBJECTS=1" \
    "${GIT_BIN}" --no-pager --no-replace-objects \
    -c core.attributesFile=/dev/null \
    -c core.hooksPath=/dev/null \
    -C "${fixture_repo}" "$@"
}

run_isolated_environment "${fixture_root}" 0 \
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
  run_isolated_environment "${fixture_root}" 0 \
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
cat >"${fixture_repo}/.git/info/attributes" <<'EOF'
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

# Compare the type bits from stat %f; descriptive file-type text varies by
# coreutils version (an empty regular file may be "regular empty file").
stat_mode_matches_kind() {
  local raw_mode="$1"
  local expected_kind="$2"
  local expected_type

  [[ "${raw_mode}" =~ ^[[:xdigit:]]+$ ]] || return 1
  case "${expected_kind}" in
    "regular file")
      expected_type=$((0100000))
      ;;
    "directory")
      expected_type=$((0040000))
      ;;
    *)
      return 1
      ;;
  esac
  (( (16#${raw_mode} & 0170000) == expected_type ))
}

assert_snapshot_entry() {
  local path="$1"
  local expected_mode="$2"
  local expected_kind="$3"
  local expected_links="${4:-}"
  local actual_uid
  local actual_mode
  local actual_links
  local actual_raw_mode

  [[ ! -L "${path}" ]] || {
    printf 'error: sealed snapshot entry is a symlink: %s\n' "${path}" >&2
    return 1
  }
  read -r actual_uid actual_mode actual_links actual_raw_mode < <(
    "${STAT_BIN}" -c '%u %a %h %f' -- "${path}"
  )
  if ! [[ "${actual_uid}" == "${EUID}" &&
    "${actual_mode}" == "${expected_mode}" ]] ||
    ! stat_mode_matches_kind "${actual_raw_mode}" "${expected_kind}"; then
    printf 'error: sealed snapshot entry metadata mismatch: path=%s uid=%s mode=%s links=%s raw_mode=%s expected_type=%s\n' \
      "${path}" "${actual_uid}" "${actual_mode}" "${actual_links}" \
      "${actual_raw_mode}" "${expected_kind}" >&2
    return 1
  fi
  if [[ -n "${expected_links}" &&
    "${actual_links}" != "${expected_links}" ]]; then
    printf 'error: sealed snapshot entry link count mismatch: path=%s links=%s\n' \
      "${path}" "${actual_links}" >&2
    return 1
  fi
}

assert_evidence_file() {
  local path="$1"
  local expected_mode="$2"
  local byte_limit="$3"
  local actual_uid
  local actual_mode
  local actual_links
  local actual_size
  local actual_raw_mode

  [[ -f "${path}" && ! -L "${path}" ]] || {
    printf 'error: provenance evidence is missing or not regular: %s\n' \
      "${path}" >&2
    return 1
  }
  read -r actual_uid actual_mode actual_links actual_size actual_raw_mode < <(
    "${STAT_BIN}" -c '%u %a %h %s %f' -- "${path}"
  )
  if ! [[ "${actual_uid}" == "${EUID}" &&
    "${actual_mode}" == "${expected_mode}" &&
    "${actual_links}" == "1" &&
    "${actual_size}" -gt 0 &&
    "${actual_size}" -le "${byte_limit}" ]] ||
    ! stat_mode_matches_kind "${actual_raw_mode}" "regular file"; then
    printf 'error: provenance evidence metadata is unsafe: path=%s uid=%s mode=%s links=%s size=%s raw_mode=%s\n' \
      "${path}" "${actual_uid}" "${actual_mode}" "${actual_links}" \
      "${actual_size}" "${actual_raw_mode}" >&2
    return 1
  fi
}

assert_isolated_attributes_absent() {
  local output_parent="$1"
  local attributes_path="${output_parent}/candidate.git/info/attributes"

  [[ ! -e "${attributes_path}" && ! -L "${attributes_path}" ]] || {
    printf 'error: isolated Git info/attributes exists: %s\n' \
      "${attributes_path}" >&2
    return 1
  }
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
assert_evidence_file \
  "${first_output_parent}/candidate-tree.raw" \
  "400" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_evidence_file \
  "${first_output_parent}/candidate-blobs.raw" \
  "400" "${BLOB_ORACLE_LIMIT_BYTES}"
assert_evidence_file \
  "${first_output_parent}/candidate.tar" \
  "400" "${ARCHIVE_LIMIT_BYTES}"
assert_isolated_attributes_absent "${first_output_parent}"

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
assert_evidence_file \
  "${second_output_parent}/candidate-tree.raw" \
  "400" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_evidence_file \
  "${second_output_parent}/candidate-blobs.raw" \
  "400" "${BLOB_ORACLE_LIMIT_BYTES}"
assert_evidence_file \
  "${second_output_parent}/candidate.tar" \
  "400" "${ARCHIVE_LIMIT_BYTES}"
assert_isolated_attributes_absent "${second_output_parent}"

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
run_isolated_environment "${no_tag_parent}/tmp" 1 \
  "--chdir=${first_output_parent}/source-snapshot" \
  "HOME=${no_tag_parent}/home" \
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

LAST_GATE_OUTPUT=""
expect_gate_failure() {
  local label="$1"
  local candidate="$2"
  local output_parent="$3"
  local expected_message="$4"
  local expected_suffix="${5:-}"
  local expected_exit="${6:-1}"
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
  LAST_GATE_OUTPUT="${gate_output}"
  [[ "${gate_exit}" == "${expected_exit}" ]] || {
    printf 'error: provenance rejection exit mismatch: case=%s actual=%s expected=%s\n' \
      "${label}" "${gate_exit}" "${expected_exit}" >&2
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

assert_stage_sequence() {
  local label="$1"
  local output="$2"
  local marker

  shift 2
  for marker in "$@"; do
    [[ "${output}" == *"${marker}"* ]] || {
      printf 'error: provenance stage is missing or out of order: case=%s marker=%s\n' \
        "${label}" "${marker}" >&2
      return 1
    }
    output="${output#*"${marker}"}"
  done
}

assert_stages_absent() {
  local label="$1"
  local output="$2"
  local marker

  shift 2
  for marker in "$@"; do
    [[ "${output}" != *"${marker}"* ]] || {
      printf 'error: rejected provenance case reached a forbidden stage: case=%s marker=%s\n' \
        "${label}" "${marker}" >&2
      return 1
    }
  done
}

assert_runtime_error_after_argv() {
  local label="$1"
  local output="$2"
  local bare_message="$3"
  local runtime_line="RuntimeError: ${bare_message}"
  local last_line="${output##*$'\n'}"
  local line
  local argv_lines=0
  local runtime_lines=0

  while IFS= read -r line; do
    if [[ "${line}" == candidate_blob_oracle_validate\ argv=* ]]; then
      ((argv_lines += 1))
      [[ "${line}" == *"${bare_message}"* &&
        "${line}" != "${runtime_line}" ]] || {
        printf 'error: runtime-error source control is invalid: case=%s\n' \
          "${label}" >&2
        return 1
      }
    fi
    if [[ "${line}" == "${runtime_line}" ]]; then
      ((runtime_lines += 1))
    fi
  done <<<"${output}"

  [[ "${argv_lines}" == "1" &&
    "${runtime_lines}" == "1" &&
    "${last_line}" == "${runtime_line}" ]] || {
    printf 'error: provenance runtime error is not uniquely anchored after argv: case=%s argv_lines=%s runtime_lines=%s last=%q\n' \
      "${label}" "${argv_lines}" "${runtime_lines}" "${last_line}" >&2
    return 1
  }
}

assert_go_phase_not_reached() {
  local label="$1"
  local output_parent="$2"

  [[ ! -e "${output_parent}/build-tmp/go-mod-edit.json" &&
    ! -L "${output_parent}/build-tmp/go-mod-edit.json" ]] || {
    printf 'error: rejected provenance case reached Go metadata: case=%s\n' \
      "${label}" >&2
    return 1
  }
}

assert_blob_archive_go_not_reached() {
  local label="$1"
  local output_parent="$2"

  [[ ! -e "${output_parent}/candidate-blobs.raw" &&
    ! -L "${output_parent}/candidate-blobs.raw" ]] || {
    printf 'error: rejected raw tree case reached blob acquisition: case=%s\n' \
      "${label}" >&2
    return 1
  }
  assert_archive_phase_not_reached "${label}" "${output_parent}"
}

assert_archive_phase_not_reached() {
  local label="$1"
  local output_parent="$2"

  [[ ! -e "${output_parent}/candidate.tar" &&
    ! -L "${output_parent}/candidate.tar" &&
    ! -e "${output_parent}/source-snapshot/go.mod" &&
    ! -L "${output_parent}/source-snapshot/go.mod" ]] || {
    printf 'error: rejected raw tree case reached archive extraction: case=%s\n' \
      "${label}" >&2
    return 1
  }
  assert_go_phase_not_reached "${label}" "${output_parent}"
}

assert_partial_evidence_file() {
  local path="$1"
  local expected_mode="$2"
  local minimum_size="$3"
  local maximum_size="$4"
  local expected_links="$5"
  local actual_uid
  local actual_mode
  local actual_links
  local actual_size
  local actual_raw_mode

  [[ -f "${path}" && ! -L "${path}" ]] || {
    printf 'error: partial provenance evidence is missing or not regular: %s\n' \
      "${path}" >&2
    return 1
  }
  read -r actual_uid actual_mode actual_links actual_size actual_raw_mode < <(
    "${STAT_BIN}" -c '%u %a %h %s %f' -- "${path}"
  )
  if ! [[ "${actual_uid}" == "${EUID}" &&
    "${actual_mode}" == "${expected_mode}" &&
    "${actual_links}" == "${expected_links}" &&
    "${actual_size}" -ge "${minimum_size}" &&
    "${actual_size}" -le "${maximum_size}" ]] ||
    ! stat_mode_matches_kind "${actual_raw_mode}" "regular file"; then
    printf 'error: partial provenance evidence metadata mismatch: path=%s uid=%s mode=%s links=%s size=%s raw_mode=%s\n' \
      "${path}" "${actual_uid}" "${actual_mode}" "${actual_links}" \
      "${actual_size}" "${actual_raw_mode}" >&2
    return 1
  fi
}

readonly stat_empty_regular_probe="${stat_regular_probe_parent}/empty.raw"
readonly stat_nonempty_regular_probe="${stat_regular_probe_parent}/nonempty.raw"
"${TOUCH_BIN}" -- "${stat_empty_regular_probe}"
printf 'x' >"${stat_nonempty_regular_probe}"
"${CHMOD_BIN}" 0600 -- \
  "${stat_empty_regular_probe}" \
  "${stat_nonempty_regular_probe}"
assert_partial_evidence_file "${stat_empty_regular_probe}" "600" 0 0 1
assert_partial_evidence_file "${stat_nonempty_regular_probe}" "600" 1 1 1
printf 'provenance_probe_passed probe=stat-regular-empty-and-nonempty\n'

readonly EMBEDDED_LITERAL_EXTRACT_PYTHON='import hashlib
import os
import stat
import sys

source_path = sys.argv[1]
literal_name = sys.argv[2].encode("ascii")
expected_hash = sys.argv[3]
destination = sys.argv[4]
expected_uid = os.geteuid()
source_limit = 1024 * 1024
open_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def exact(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_mode,
        metadata.st_size,
    )


source_fd = os.open(source_path, open_flags)
try:
    before = os.fstat(source_fd)
    if (
        stat.S_IFMT(before.st_mode) != stat.S_IFREG
        or before.st_uid != expected_uid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_size <= 0
        or before.st_size > source_limit
    ):
        raise RuntimeError("embedded literal source metadata is unsafe")
    chunks = []
    total = 0
    while True:
        chunk = os.read(source_fd, min(1024 * 1024, source_limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > source_limit:
            raise RuntimeError("embedded literal source exceeds its byte limit")
        chunks.append(chunk)
    after = os.fstat(source_fd)
    if exact(before) != exact(after) or total != before.st_size:
        raise RuntimeError("embedded literal source changed while reading")
finally:
    os.close(source_fd)

source = b"".join(chunks)
quote = bytes((39,))
prefix = b"readonly " + literal_name + b"=" + quote
if source.count(prefix) != 1:
    raise RuntimeError("embedded literal declaration is not unique")
start = source.index(prefix) + len(prefix)
closing = b"\n" + quote + b"\n"
end = source.find(closing, start)
if end < 0:
    raise RuntimeError("embedded literal closing boundary is missing")
literal = source[start:end + 1]
actual_hash = hashlib.sha256(literal).hexdigest()
if actual_hash != expected_hash:
    raise RuntimeError(
        f"embedded literal hash mismatch: name={literal_name!r} "
        f"actual={actual_hash} expected={expected_hash}"
    )

destination_fd = os.open(
    destination,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
    0o600,
)
try:
    view = memoryview(literal)
    while view:
        written = os.write(destination_fd, view)
        if written <= 0:
            raise RuntimeError("short write while extracting embedded literal")
        view = view[written:]
    os.fsync(destination_fd)
    os.fchmod(destination_fd, 0o400)
    written_metadata = os.fstat(destination_fd)
    if (
        stat.S_IFMT(written_metadata.st_mode) != stat.S_IFREG
        or written_metadata.st_uid != expected_uid
        or written_metadata.st_nlink != 1
        or stat.S_IMODE(written_metadata.st_mode) != 0o400
        or written_metadata.st_size != len(literal)
    ):
        raise RuntimeError("extracted embedded literal metadata is unsafe")
finally:
    os.close(destination_fd)

print(
    f"embedded_literal_bound name={literal_name.decode()} "
    f"bytes={len(literal)} sha256={actual_hash}"
)
'
readonly -a EMBEDDED_LITERAL_NAMES=(
  TREE_INVENTORY_PYTHON
  BLOB_ORACLE_LIMIT_PYTHON
  BLOB_ORACLE_VALIDATE_PYTHON
  SNAPSHOT_SEAL_PYTHON
)
readonly -a EMBEDDED_LITERAL_HASHES=(
  dc8369ad92c863268a8b41901fa87ace2a217ae4baa5944b12b9d6f290f136df
  5b5480fe4803890803b0af8fa1b63604ef70c7ecb90eb48bb46259f8d9c2df61
  ff69db95d29997b6e53ac65c77a56ca2d2dd75d2f35c2900959f1950d01af91f
  39b0c96cc4f8141265b27e0e6d8bff7ad76ac5a039da9f8878a2c322ff12a99f
)
for literal_index in "${!EMBEDDED_LITERAL_NAMES[@]}"; do
  literal_name="${EMBEDDED_LITERAL_NAMES[${literal_index}]}"
  literal_hash="${EMBEDDED_LITERAL_HASHES[${literal_index}]}"
  literal_path="${embedded_probe_root}/${literal_name}.py"
  run_isolated_environment "${embedded_probe_root}" 0 \
    "HOME=${fixture_home}" \
    "${PYTHON3_BIN}" \
    -I \
    -B \
    -c "${EMBEDDED_LITERAL_EXTRACT_PYTHON}" \
    "${fixture_gate}" \
    "${literal_name}" \
    "${literal_hash}" \
    "${literal_path}"
  assert_evidence_file "${literal_path}" "400" 65536
done
readonly tree_inventory_probe_python="${embedded_probe_root}/TREE_INVENTORY_PYTHON.py"
readonly blob_limiter_probe_python="${embedded_probe_root}/BLOB_ORACLE_LIMIT_PYTHON.py"
readonly blob_validator_probe_python="${embedded_probe_root}/BLOB_ORACLE_VALIDATE_PYTHON.py"
readonly snapshot_seal_probe_python="${embedded_probe_root}/SNAPSHOT_SEAL_PYTHON.py"

run_embedded_python_failure() {
  local label="$1"
  local script_path="$2"
  local input_path="$3"
  local expected_message="$4"
  local probe_output
  local probe_exit

  shift 4
  printf 'provenance_probe_start probe=%s\n' "${label}"
  set +e
  probe_output="$(
    run_isolated_environment "${embedded_probe_root}" 0 \
      "HOME=${fixture_home}" \
      "${PYTHON3_BIN}" \
      -I \
      -B \
      "${script_path}" \
      "$@" <"${input_path}" 2>&1
  )"
  probe_exit=$?
  set -e
  printf '%s\n' "${probe_output}"
  [[ "${probe_exit}" == "1" &&
    "${probe_output}" == *"${expected_message}"* ]] || {
    printf 'error: embedded Python probe rejection mismatch: probe=%s exit=%s\n' \
      "${label}" "${probe_exit}" >&2
    return 1
  }
  printf 'provenance_probe_rejected probe=%s exit=%s\n' \
    "${label}" "${probe_exit}"
}

run_embedded_python_success() {
  local label="$1"
  local script_path="$2"
  local input_path="$3"
  local expected_message="$4"
  local probe_output
  local probe_exit

  shift 4
  printf 'provenance_probe_start probe=%s\n' "${label}"
  set +e
  probe_output="$(
    run_isolated_environment "${embedded_probe_root}" 0 \
      "HOME=${fixture_home}" \
      "${PYTHON3_BIN}" \
      -I \
      -B \
      "${script_path}" \
      "$@" <"${input_path}" 2>&1
  )"
  probe_exit=$?
  set -e
  printf '%s\n' "${probe_output}"
  [[ "${probe_exit}" == "0" &&
    "${probe_output}" == *"${expected_message}"* ]] || {
    printf 'error: embedded Python probe success mismatch: probe=%s exit=%s\n' \
      "${label}" "${probe_exit}" >&2
    return 1
  }
  printf 'provenance_probe_passed probe=%s\n' "${label}"
}

readonly tree_byte_limit_input="${tree_probe_parent}/byte-limit.input"
readonly tree_entry_limit_input="${tree_probe_parent}/entry-limit.input"
readonly blob_limit_input="${blob_limit_probe_parent}/byte-limit.input"
"${PYTHON3_BIN}" -I -B - \
  "${tree_byte_limit_input}" \
  "${tree_entry_limit_input}" \
  "${blob_limit_input}" <<'PY'
import os
import sys


def write_private(path, payload):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("short fixture write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


zero_oid = b"0" * 40
record_a = b"100644 blob " + zero_oid + b"\ta\0"
record_b = b"100644 blob " + zero_oid + b"\tb\0"
write_private(sys.argv[1], b"x" * 17)
write_private(sys.argv[2], record_a + record_b)
write_private(sys.argv[3], b"x" * 9)
PY

readonly tree_byte_limit_output="${tree_probe_parent}/byte-limit.raw"
run_embedded_python_failure \
  "tree-inventory-byte-limit" \
  "${tree_inventory_probe_python}" \
  "${tree_byte_limit_input}" \
  "raw Git tree inventory exceeds 16 byte hard limit" \
  "${tree_byte_limit_output}" 16 8
assert_partial_evidence_file \
  "${tree_byte_limit_output}" "600" 0 0 1

readonly tree_entry_limit_output="${tree_probe_parent}/entry-limit.raw"
run_embedded_python_failure \
  "tree-inventory-entry-limit" \
  "${tree_inventory_probe_python}" \
  "${tree_entry_limit_input}" \
  "raw Git tree inventory exceeds 1 entries" \
  "${tree_entry_limit_output}" 4096 1
tree_entry_input_size="$("${STAT_BIN}" -c '%s' -- \
  "${tree_entry_limit_input}")"
readonly tree_entry_input_size
assert_partial_evidence_file \
  "${tree_entry_limit_output}" \
  "600" "${tree_entry_input_size}" "${tree_entry_input_size}" 1

readonly blob_limit_output="${blob_limit_probe_parent}/byte-limit.raw"
run_embedded_python_failure \
  "blob-oracle-byte-limit" \
  "${blob_limiter_probe_python}" \
  "${blob_limit_input}" \
  "candidate blob oracle exceeds 8 byte hard limit" \
  "${blob_limit_output}" 8
assert_partial_evidence_file "${blob_limit_output}" "600" 0 0 1

blob_probe_oid="$(printf 'x' | fixture_git hash-object --stdin)"
readonly blob_probe_oid
[[ "${blob_probe_oid}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: blob batch probe object id is invalid" >&2
  exit 1
}
readonly blob_batch_inventory="${blob_batch_probe_parent}/tree.raw"
readonly blob_batch_valid="${blob_batch_probe_parent}/valid.raw"
readonly blob_batch_truncated="${blob_batch_probe_parent}/truncated.raw"
readonly blob_batch_bad_header="${blob_batch_probe_parent}/bad-header.raw"
readonly blob_batch_bad_type="${blob_batch_probe_parent}/bad-type.raw"
readonly blob_batch_bad_size="${blob_batch_probe_parent}/bad-size.raw"
readonly blob_batch_bad_framing="${blob_batch_probe_parent}/bad-framing.raw"
readonly blob_batch_bad_content="${blob_batch_probe_parent}/bad-content.raw"
"${PYTHON3_BIN}" -I -B - \
  "${blob_probe_oid}" \
  "${blob_batch_inventory}" \
  "${blob_batch_valid}" \
  "${blob_batch_truncated}" \
  "${blob_batch_bad_header}" \
  "${blob_batch_bad_type}" \
  "${blob_batch_bad_size}" \
  "${blob_batch_bad_framing}" \
  "${blob_batch_bad_content}" <<'PY'
import os
import sys


def write_read_only(path, payload):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("short fixture write")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    finally:
        os.close(descriptor)


object_id = sys.argv[1].encode("ascii")
inventory = b"100644 blob " + object_id + b"\tprobe.bin\0"
valid = object_id + b" blob 1\nx\n"
write_read_only(sys.argv[2], inventory)
write_read_only(sys.argv[3], valid)
write_read_only(sys.argv[4], object_id + b" blob 1")
write_read_only(sys.argv[5], object_id + b" blob 1 extra\nx\n")
write_read_only(sys.argv[6], object_id + b" tree 1\nx\n")
write_read_only(sys.argv[7], object_id + b" blob 01\nx\n")
write_read_only(sys.argv[8], object_id + b" blob 2\nx\n")
write_read_only(sys.argv[9], object_id + b" blob 1\ny\n")
PY
assert_evidence_file "${blob_batch_inventory}" "400" 4096
for blob_batch_evidence in \
  "${blob_batch_valid}" \
  "${blob_batch_truncated}" \
  "${blob_batch_bad_header}" \
  "${blob_batch_bad_type}" \
  "${blob_batch_bad_size}" \
  "${blob_batch_bad_framing}" \
  "${blob_batch_bad_content}"; do
  assert_evidence_file "${blob_batch_evidence}" "400" 4096
done
run_embedded_python_success \
  "blob-batch-valid-control" \
  "${blob_validator_probe_python}" \
  /dev/null \
  "candidate_blob_oracle_validated unique=1" \
  "${blob_batch_inventory}" "${blob_batch_valid}" 4096 8 4096
run_embedded_python_failure \
  "blob-batch-truncated-header" \
  "${blob_validator_probe_python}" \
  /dev/null \
  "candidate blob oracle batch header is missing" \
  "${blob_batch_inventory}" "${blob_batch_truncated}" 4096 8 4096
run_embedded_python_failure \
  "blob-batch-malformed-header" \
  "${blob_validator_probe_python}" \
  /dev/null \
  "candidate blob oracle batch header is malformed" \
  "${blob_batch_inventory}" "${blob_batch_bad_header}" 4096 8 4096
run_embedded_python_failure \
  "blob-batch-wrong-type" \
  "${blob_validator_probe_python}" \
  /dev/null \
  "candidate blob oracle batch identity is invalid" \
  "${blob_batch_inventory}" "${blob_batch_bad_type}" 4096 8 4096
run_embedded_python_failure \
  "blob-batch-noncanonical-size" \
  "${blob_validator_probe_python}" \
  /dev/null \
  "candidate blob oracle batch size is invalid" \
  "${blob_batch_inventory}" "${blob_batch_bad_size}" 4096 8 4096
run_embedded_python_failure \
  "blob-batch-body-framing" \
  "${blob_validator_probe_python}" \
  /dev/null \
  "candidate blob oracle batch framing is invalid" \
  "${blob_batch_inventory}" "${blob_batch_bad_framing}" 4096 8 4096
run_embedded_python_failure \
  "blob-batch-content-hash" \
  "${blob_validator_probe_python}" \
  /dev/null \
  "candidate blob oracle content hash is invalid" \
  "${blob_batch_inventory}" "${blob_batch_bad_content}" 4096 8 4096
assert_evidence_file "${blob_batch_inventory}" "400" 4096
for blob_batch_evidence in \
  "${blob_batch_valid}" \
  "${blob_batch_truncated}" \
  "${blob_batch_bad_header}" \
  "${blob_batch_bad_type}" \
  "${blob_batch_bad_size}" \
  "${blob_batch_bad_framing}" \
  "${blob_batch_bad_content}"; do
  assert_evidence_file "${blob_batch_evidence}" "400" 4096
done

readonly seal_probe_inventory="${seal_probe_parent}/tree.raw"
readonly seal_probe_blob_oracle="${seal_probe_parent}/blobs.raw"
readonly seal_probe_file="${seal_probe_snapshot}/probe.bin"
readonly seal_probe_outside_link="${seal_probe_parent}/outside-hardlink"
"${PYTHON3_BIN}" -I -B - \
  "${blob_probe_oid}" \
  "${seal_probe_inventory}" \
  "${seal_probe_blob_oracle}" \
  "${seal_probe_file}" <<'PY'
import os
import sys


def write_exact(path, payload, mode):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("short fixture write")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


object_id = sys.argv[1].encode("ascii")
write_exact(
    sys.argv[2],
    b"100644 blob " + object_id + b"\tprobe.bin\0",
    0o400,
)
write_exact(sys.argv[3], object_id + b" blob 1\nx\n", 0o400)
write_exact(sys.argv[4], b"x", 0o600)
PY
"${LN_BIN}" -- "${seal_probe_file}" "${seal_probe_outside_link}"
assert_snapshot_entry "${seal_probe_snapshot}" "700" "directory"
assert_snapshot_entry "${seal_probe_file}" "600" "regular file" "2"
assert_snapshot_entry "${seal_probe_outside_link}" "600" "regular file" "2"
assert_evidence_file "${seal_probe_inventory}" "400" 4096
assert_evidence_file "${seal_probe_blob_oracle}" "400" 4096
run_embedded_python_failure \
  "snapshot-seal-hardlink" \
  "${snapshot_seal_probe_python}" \
  /dev/null \
  "regular file has multiple links" \
  "${seal_probe_snapshot}" \
  "${seal_probe_inventory}" \
  "${seal_probe_blob_oracle}" \
  4096 8 4096
assert_snapshot_entry "${seal_probe_snapshot}" "700" "directory"
assert_snapshot_entry "${seal_probe_file}" "600" "regular file" "2"
assert_snapshot_entry "${seal_probe_outside_link}" "600" "regular file" "2"
assert_evidence_file "${seal_probe_inventory}" "400" 4096
assert_evidence_file "${seal_probe_blob_oracle}" "400" 4096

readonly SEAL_PROBE_FIXTURE_PYTHON='import os
import sys


def write_exact(path, payload, mode):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("short fixture write")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


object_id = sys.argv[1].encode("ascii")
oracle_mode = sys.argv[2].encode("ascii")
snapshot_body = bytes.fromhex(sys.argv[3])
write_exact(
    sys.argv[4],
    oracle_mode + b" blob " + object_id + b"\tprobe.bin\0",
    0o400,
)
write_exact(sys.argv[5], object_id + b" blob 1\nx\n", 0o400)
write_exact(sys.argv[6], snapshot_body, 0o600)
'

readonly seal_mode_probe_inventory="${seal_mode_probe_parent}/tree.raw"
readonly seal_mode_probe_blob_oracle="${seal_mode_probe_parent}/blobs.raw"
readonly seal_mode_probe_file="${seal_mode_probe_snapshot}/probe.bin"
"${PYTHON3_BIN}" \
  -I \
  -B \
  -c "${SEAL_PROBE_FIXTURE_PYTHON}" \
  "${blob_probe_oid}" \
  100755 \
  78 \
  "${seal_mode_probe_inventory}" \
  "${seal_mode_probe_blob_oracle}" \
  "${seal_mode_probe_file}"
assert_snapshot_entry "${seal_mode_probe_snapshot}" "700" "directory"
assert_snapshot_entry "${seal_mode_probe_file}" "600" "regular file" "1"
assert_evidence_file "${seal_mode_probe_inventory}" "400" 4096
assert_evidence_file "${seal_mode_probe_blob_oracle}" "400" 4096
run_embedded_python_failure \
  "snapshot-seal-executable-mode-mismatch" \
  "${snapshot_seal_probe_python}" \
  /dev/null \
  "candidate snapshot executable mode differs from Git tree" \
  "${seal_mode_probe_snapshot}" \
  "${seal_mode_probe_inventory}" \
  "${seal_mode_probe_blob_oracle}" \
  4096 8 4096
assert_snapshot_entry "${seal_mode_probe_snapshot}" "700" "directory"
assert_snapshot_entry "${seal_mode_probe_file}" "600" "regular file" "1"
assert_evidence_file "${seal_mode_probe_inventory}" "400" 4096
assert_evidence_file "${seal_mode_probe_blob_oracle}" "400" 4096

readonly seal_content_probe_inventory="${seal_content_probe_parent}/tree.raw"
readonly seal_content_probe_blob_oracle="${seal_content_probe_parent}/blobs.raw"
readonly seal_content_probe_file="${seal_content_probe_snapshot}/probe.bin"
"${PYTHON3_BIN}" \
  -I \
  -B \
  -c "${SEAL_PROBE_FIXTURE_PYTHON}" \
  "${blob_probe_oid}" \
  100644 \
  79 \
  "${seal_content_probe_inventory}" \
  "${seal_content_probe_blob_oracle}" \
  "${seal_content_probe_file}"
seal_content_before_sha="$("${SHA256_BIN}" -- \
  "${seal_content_probe_file}")"
seal_content_before_sha="${seal_content_before_sha%% *}"
readonly seal_content_before_sha
assert_snapshot_entry "${seal_content_probe_snapshot}" "700" "directory"
assert_snapshot_entry "${seal_content_probe_file}" "600" "regular file" "1"
assert_evidence_file "${seal_content_probe_inventory}" "400" 4096
assert_evidence_file "${seal_content_probe_blob_oracle}" "400" 4096
run_embedded_python_failure \
  "snapshot-seal-content-mismatch" \
  "${snapshot_seal_probe_python}" \
  /dev/null \
  "candidate snapshot blob content differs from raw Git blob" \
  "${seal_content_probe_snapshot}" \
  "${seal_content_probe_inventory}" \
  "${seal_content_probe_blob_oracle}" \
  4096 8 4096
seal_content_after_sha="$("${SHA256_BIN}" -- \
  "${seal_content_probe_file}")"
seal_content_after_sha="${seal_content_after_sha%% *}"
readonly seal_content_after_sha
[[ "${seal_content_after_sha}" == "${seal_content_before_sha}" ]] || {
  echo "error: content-mismatch snapshot evidence changed after rejection" >&2
  exit 1
}
assert_snapshot_entry "${seal_content_probe_snapshot}" "700" "directory"
assert_snapshot_entry "${seal_content_probe_file}" "600" "regular file" "1"
assert_evidence_file "${seal_content_probe_inventory}" "400" 4096
assert_evidence_file "${seal_content_probe_blob_oracle}" "400" 4096

readonly gitlink_index="${fixture_root}/gitlink.index"
fixture_index_git "${gitlink_index}" read-tree "${candidate_commit}"
fixture_index_git "${gitlink_index}" update-index \
  --add \
  --cacheinfo 160000 "${candidate_commit}" vendor/submodule
gitlink_tree="$(fixture_index_git "${gitlink_index}" write-tree)"
readonly gitlink_tree
[[ "${gitlink_tree}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: gitlink fixture tree is invalid" >&2
  exit 1
}
gitlink_commit="$(
  fixture_git \
    -c user.name=guard-provenance-fixture \
    -c user.email=guard-provenance-fixture.invalid \
    commit-tree "${gitlink_tree}" \
    -p "${candidate_commit}" \
    -m "fixture committed gitlink"
)"
readonly gitlink_commit
[[ "${gitlink_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: gitlink fixture commit is invalid" >&2
  exit 1
}
gitlink_listing="${fixture_root}/gitlink-tree.raw"
fixture_git ls-tree -r -t -z "${gitlink_commit}" >"${gitlink_listing}"
"${PYTHON3_BIN}" -I -B - \
  "${gitlink_listing}" "${candidate_commit}" <<'PY'
import sys

payload = open(sys.argv[1], "rb").read()
expected = (
    b"160000 commit "
    + sys.argv[2].encode("ascii")
    + b"\tvendor/submodule\0"
)
if not payload.endswith(b"\0"):
    raise RuntimeError("gitlink fixture raw tree is not NUL-terminated")
records = payload[:-1].split(b"\0")
if expected[:-1] not in records:
    raise RuntimeError("gitlink fixture raw tree entry is missing")
PY
fixture_git update-ref refs/heads/main \
  "${gitlink_commit}" "${candidate_commit}"
expect_gate_failure \
  "committed-gitlink" \
  "${gitlink_commit}" \
  "${gitlink_output_parent}" \
  "forbidden Git tree entry mode=160000 type=commit"
assert_stage_sequence \
  "committed-gitlink" \
  "${LAST_GATE_OUTPUT}" \
  "candidate_tree_inventory_start" \
  "candidate_tree_inventory_validate" \
  "forbidden Git tree entry mode=160000 type=commit"
assert_stages_absent \
  "committed-gitlink" \
  "${LAST_GATE_OUTPUT}" \
  "candidate_blob_query_start" \
  "candidate_archive_start" \
  "candidate_extract_start" \
  "build_start"
assert_blob_archive_go_not_reached \
  "committed-gitlink" "${gitlink_output_parent}"
assert_evidence_file \
  "${gitlink_output_parent}/candidate-tree.raw" \
  "600" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_isolated_attributes_absent "${gitlink_output_parent}"
fixture_git update-ref refs/heads/main \
  "${candidate_commit}" "${gitlink_commit}"

candidate_tree="$(fixture_git rev-parse "${candidate_commit}^{tree}")"
readonly candidate_tree
[[ "${candidate_tree}" =~ ^[0-9a-f]{40}$ &&
  "$(fixture_git cat-file -t "${candidate_tree}")" == "tree" ]] || {
  echo "error: malformed-tree fixture source tree is invalid" >&2
  exit 1
}
readonly malformed_tree_source="${fixture_root}/malformed-tree.object"
"${PYTHON3_BIN}" -I -B - \
  "${malformed_tree_source}" "${candidate_tree}" <<'PY'
import os
import sys

payload = b"100644 mismatch\0" + bytes.fromhex(sys.argv[2])
descriptor = os.open(
    sys.argv[1],
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
    0o600,
)
try:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeError("short malformed-tree fixture write")
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
malformed_tree="$(
  fixture_git hash-object \
    -t tree \
    --literally \
    -w \
    --stdin <"${malformed_tree_source}"
)"
readonly malformed_tree
[[ "${malformed_tree}" =~ ^[0-9a-f]{40}$ &&
  "$(fixture_git cat-file -t "${malformed_tree}")" == "tree" ]] || {
  echo "error: malformed raw tree object was not stored exactly" >&2
  exit 1
}
readonly malformed_tree_roundtrip="${fixture_root}/malformed-tree.roundtrip"
fixture_git cat-file tree "${malformed_tree}" >"${malformed_tree_roundtrip}"
malformed_source_sha="$("${SHA256_BIN}" -- "${malformed_tree_source}")"
malformed_source_sha="${malformed_source_sha%% *}"
malformed_roundtrip_sha="$("${SHA256_BIN}" -- \
  "${malformed_tree_roundtrip}")"
malformed_roundtrip_sha="${malformed_roundtrip_sha%% *}"
readonly malformed_source_sha malformed_roundtrip_sha
[[ "${malformed_source_sha}" == "${malformed_roundtrip_sha}" ]] || {
  echo "error: malformed raw tree object changed after object storage" >&2
  exit 1
}
readonly malformed_tree_listing="${fixture_root}/malformed-tree-listing.raw"
fixture_git ls-tree -r -t -z \
  "${malformed_tree}" >"${malformed_tree_listing}"
"${PYTHON3_BIN}" -I -B - \
  "${malformed_tree_listing}" "${candidate_tree}" <<'PY'
import sys

payload = open(sys.argv[1], "rb").read()
expected = (
    b"100644 blob "
    + sys.argv[2].encode("ascii")
    + b"\tmismatch\0"
)
if payload != expected:
    raise RuntimeError("malformed mode/type fixture is not exact")
PY
malformed_tree_commit="$(
  fixture_git \
    -c user.name=guard-provenance-fixture \
    -c user.email=guard-provenance-fixture.invalid \
    commit-tree "${malformed_tree}" \
    -p "${candidate_commit}" \
    -m "fixture regular mode references tree object"
)"
readonly malformed_tree_commit
[[ "${malformed_tree_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: malformed-tree fixture commit is invalid" >&2
  exit 1
}
fixture_git update-ref refs/heads/main \
  "${malformed_tree_commit}" "${candidate_commit}"
expect_gate_failure \
  "regular-mode-references-tree-object" \
  "${malformed_tree_commit}" \
  "${malformed_tree_output_parent}" \
  "RuntimeError: candidate blob oracle batch identity is invalid"
assert_runtime_error_after_argv \
  "regular-mode-references-tree-object" \
  "${LAST_GATE_OUTPUT}" \
  "candidate blob oracle batch identity is invalid"
assert_stage_sequence \
  "regular-mode-references-tree-object" \
  "${LAST_GATE_OUTPUT}" \
  "candidate_tree_inventory_start" \
  "candidate_tree_inventory entries=1 trees=0 blobs=1" \
  "candidate_blob_query_start" \
  "candidate_blob_oracle_written" \
  "candidate_blob_oracle_validate" \
  "RuntimeError: candidate blob oracle batch identity is invalid"
assert_stages_absent \
  "regular-mode-references-tree-object" \
  "${LAST_GATE_OUTPUT}" \
  "candidate_archive_start" \
  "candidate_extract_start" \
  "candidate_snapshot_seal_start" \
  "build_start"
assert_archive_phase_not_reached \
  "regular-mode-references-tree-object" \
  "${malformed_tree_output_parent}"
assert_evidence_file \
  "${malformed_tree_output_parent}/candidate-tree.raw" \
  "400" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_evidence_file \
  "${malformed_tree_output_parent}/candidate-blobs.raw" \
  "400" "${BLOB_ORACLE_LIMIT_BYTES}"
assert_isolated_attributes_absent "${malformed_tree_output_parent}"
fixture_git update-ref refs/heads/main \
  "${candidate_commit}" "${malformed_tree_commit}"

readonly byte_paths_index="${fixture_root}/byte-paths.index"
readonly byte_paths_index_listing="${fixture_root}/byte-paths-index.raw"
readonly byte_paths_tree_listing="${fixture_root}/byte-paths-tree.raw"
fixture_index_git "${byte_paths_index}" read-tree "${candidate_commit}"
byte_paths_blob_oid="$(
  printf 'weird-path-payload\n' |
    fixture_git hash-object -w --stdin
)"
readonly byte_paths_blob_oid
[[ "${byte_paths_blob_oid}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: byte-path fixture blob object id is invalid" >&2
  exit 1
}
"${PYTHON3_BIN}" -I -B - "${byte_paths_blob_oid}" <<'PY' |
import sys

object_id = sys.argv[1].encode("ascii")
for path in (
    b"weird/tab\tname.txt",
    b"weird/line\nname.txt",
    b"weird/nonutf8-\xff.bin",
):
    sys.stdout.buffer.write(b"100644 blob " + object_id + b"\t" + path + b"\0")
sys.stdout.buffer.flush()
PY
  fixture_index_git "${byte_paths_index}" \
    update-index -z --index-info
fixture_index_git "${byte_paths_index}" \
  ls-files --stage -z >"${byte_paths_index_listing}"
byte_paths_tree="$(fixture_index_git "${byte_paths_index}" write-tree)"
readonly byte_paths_tree
[[ "${byte_paths_tree}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: byte-path fixture tree is invalid" >&2
  exit 1
}
fixture_git ls-tree -r -z \
  "${byte_paths_tree}" >"${byte_paths_tree_listing}"
"${PYTHON3_BIN}" -I -B - \
  "${byte_paths_index_listing}" \
  "${byte_paths_tree_listing}" \
  "${byte_paths_blob_oid}" <<'PY'
import sys

expected_paths = {
    b"weird/tab\tname.txt",
    b"weird/line\nname.txt",
    b"weird/nonutf8-\xff.bin",
}
object_id = sys.argv[3].encode("ascii")

index_payload = open(sys.argv[1], "rb").read()
if not index_payload.endswith(b"\0"):
    raise RuntimeError("byte-path index listing is not NUL-terminated")
index_records = index_payload[:-1].split(b"\0")
seen_index = set()
for record in index_records:
    header, path = record.split(b"\t", 1)
    if path in expected_paths:
        if header != b"100644 " + object_id + b" 0":
            raise RuntimeError("byte-path index entry metadata differs")
        seen_index.add(path)
if seen_index != expected_paths:
    raise RuntimeError("byte-path index entry set differs")

tree_payload = open(sys.argv[2], "rb").read()
if not tree_payload.endswith(b"\0"):
    raise RuntimeError("byte-path tree listing is not NUL-terminated")
tree_records = tree_payload[:-1].split(b"\0")
seen_tree = set()
for record in tree_records:
    header, path = record.split(b"\t", 1)
    if path in expected_paths:
        if header != b"100644 blob " + object_id:
            raise RuntimeError("byte-path raw tree entry metadata differs")
        seen_tree.add(path)
if seen_tree != expected_paths:
    raise RuntimeError("byte-path raw tree entry set differs")
print("byte_path_index_tree_verified entries=3")
PY
byte_paths_commit="$(
  fixture_git \
    -c user.name=guard-provenance-fixture \
    -c user.email=guard-provenance-fixture.invalid \
    commit-tree "${byte_paths_tree}" \
    -p "${candidate_commit}" \
    -m "fixture byte-exact Git paths"
)"
readonly byte_paths_commit
[[ "${byte_paths_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: byte-path fixture commit is invalid" >&2
  exit 1
}
fixture_git update-ref refs/heads/main \
  "${byte_paths_commit}" "${candidate_commit}"
printf 'provenance_case_start case=byte-exact-git-paths commit=%s\n' \
  "${byte_paths_commit}"
set +e
byte_paths_gate_output="$(
  (
    builtin cd "${fixture_repo}"
    run_gate_with_poisoned_environment \
      --candidate-commit "${byte_paths_commit}" \
      --output "${byte_paths_output_parent}/guard-live.test"
  ) 2>&1
)"
byte_paths_gate_exit=$?
set -e
printf '%s\n' "${byte_paths_gate_output}"
[[ "${byte_paths_gate_exit}" == "0" ]] || {
  printf 'error: byte-exact Git path build failed: exit=%s\n' \
    "${byte_paths_gate_exit}" >&2
  exit 1
}
assert_stage_sequence \
  "byte-exact-git-paths" \
  "${byte_paths_gate_output}" \
  "candidate_tree_inventory_start" \
  "candidate_tree_inventory entries=" \
  "candidate_blob_oracle_validated unique=" \
  "candidate_archive_start" \
  "candidate_extract_start" \
  "candidate_snapshot_seal_start" \
  "candidate_snapshot_sealed entries=" \
  "build_start" \
  "build_finish"
[[ -x "${byte_paths_output_parent}/guard-live.test" &&
  ! -e "${tar_options_marker}" &&
  ! -L "${tar_options_marker}" ]] || {
  echo "error: byte-exact Git path build artifact is unsafe" >&2
  exit 1
}
assert_sealed_snapshot "${byte_paths_output_parent}/source-snapshot"
assert_evidence_file \
  "${byte_paths_output_parent}/candidate-tree.raw" \
  "400" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_evidence_file \
  "${byte_paths_output_parent}/candidate-blobs.raw" \
  "400" "${BLOB_ORACLE_LIMIT_BYTES}"
assert_evidence_file \
  "${byte_paths_output_parent}/candidate.tar" \
  "400" "${ARCHIVE_LIMIT_BYTES}"
assert_isolated_attributes_absent "${byte_paths_output_parent}"
"${PYTHON3_BIN}" -I -B - \
  "${byte_paths_output_parent}/source-snapshot" <<'PY'
import os
import stat
import sys

root = os.fsencode(sys.argv[1])
directory = root + b"/weird"
expected_names = {
    b"tab\tname.txt",
    b"line\nname.txt",
    b"nonutf8-\xff.bin",
}
directory_metadata = os.stat(directory, follow_symlinks=False)
if (
    stat.S_IFMT(directory_metadata.st_mode) != stat.S_IFDIR
    or directory_metadata.st_uid != os.geteuid()
    or stat.S_IMODE(directory_metadata.st_mode) != 0o500
):
    raise RuntimeError("byte-path snapshot directory metadata is unsafe")
actual_names = set(os.listdir(directory))
if actual_names != expected_names:
    raise RuntimeError(
        f"byte-path snapshot names differ: actual={actual_names!r}"
    )
for name in expected_names:
    path = directory + b"/" + name
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            stat.S_IFMT(metadata.st_mode) != stat.S_IFREG
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_size != len(b"weird-path-payload\n")
        ):
            raise RuntimeError(
                f"byte-path snapshot file metadata is unsafe: {name!r}"
            )
        payload = os.read(descriptor, metadata.st_size + 1)
        if payload != b"weird-path-payload\n":
            raise RuntimeError(
                f"byte-path snapshot content differs: {name!r}"
            )
    finally:
        os.close(descriptor)
print("byte_path_snapshot_verified entries=3")
PY
fixture_git update-ref refs/heads/main \
  "${candidate_commit}" "${byte_paths_commit}"

cat >"${fixture_repo}/.gitattributes" <<'EOF'
internal/guard/unit_test.go export-ignore
EOF
fixture_git add -- .gitattributes
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit -m "fixture committed export-ignore"
export_ignore_commit="$(fixture_git rev-parse HEAD)"
readonly export_ignore_commit
[[ "${export_ignore_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: export-ignore fixture commit is invalid" >&2
  exit 1
}
expect_gate_failure \
  "committed-export-ignore" \
  "${export_ignore_commit}" \
  "${export_ignore_output_parent}" \
  "candidate snapshot path set differs from raw Git tree inventory"
assert_go_phase_not_reached \
  "committed-export-ignore" "${export_ignore_output_parent}"
assert_evidence_file \
  "${export_ignore_output_parent}/candidate-tree.raw" \
  "400" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_evidence_file \
  "${export_ignore_output_parent}/candidate-blobs.raw" \
  "400" "${BLOB_ORACLE_LIMIT_BYTES}"
assert_evidence_file \
  "${export_ignore_output_parent}/candidate.tar" \
  "400" "${ARCHIVE_LIMIT_BYTES}"
assert_isolated_attributes_absent "${export_ignore_output_parent}"

cat >"${fixture_repo}/.gitattributes" <<'EOF'
internal/guard/archive-subst.txt export-subst
EOF
cat >"${fixture_repo}/internal/guard/archive-subst.txt" <<'EOF'
candidate=$Format:%H$
EOF
fixture_git add -- .gitattributes internal/guard/archive-subst.txt
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit -m "fixture committed export-subst"
export_subst_commit="$(fixture_git rev-parse HEAD)"
readonly export_subst_commit
[[ "${export_subst_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: export-subst fixture commit is invalid" >&2
  exit 1
}
expect_gate_failure \
  "committed-export-subst" \
  "${export_subst_commit}" \
  "${export_subst_output_parent}" \
  "candidate snapshot blob size differs from raw Git blob"
assert_go_phase_not_reached \
  "committed-export-subst" "${export_subst_output_parent}"
assert_evidence_file \
  "${export_subst_output_parent}/candidate-tree.raw" \
  "400" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_evidence_file \
  "${export_subst_output_parent}/candidate-blobs.raw" \
  "400" "${BLOB_ORACLE_LIMIT_BYTES}"
assert_evidence_file \
  "${export_subst_output_parent}/candidate.tar" \
  "400" "${ARCHIVE_LIMIT_BYTES}"
assert_isolated_attributes_absent "${export_subst_output_parent}"

cat >"${fixture_repo}/.gitattributes" <<'EOF'
# committed attributes intentionally inert after negative fixtures
EOF
fixture_git add -- .gitattributes
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit -m "fixture inert committed attributes"
inert_attributes_commit="$(fixture_git rev-parse HEAD)"
readonly inert_attributes_commit
[[ "${inert_attributes_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: inert-attributes fixture commit is invalid" >&2
  exit 1
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
"${TRUNCATE_BIN}" --size="${OVERSIZED_CHUNK_BYTES}" -- \
  "${oversized_source}"
read -r oversized_source_size oversized_source_raw_mode < <(
  "${STAT_BIN}" -c '%s %f' -- "${oversized_source}"
)
if ! [[ "${oversized_source_size}" -eq "${OVERSIZED_CHUNK_BYTES}" ]] ||
  ! stat_mode_matches_kind "${oversized_source_raw_mode}" "regular file"; then
  echo "error: repeated-blob archive fixture is invalid" >&2
  exit 1
fi
oversized_blob_oid="$(fixture_git hash-object -w -- "${oversized_source}")"
readonly oversized_blob_oid
[[ "${oversized_blob_oid}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: repeated-blob archive object id is invalid" >&2
  exit 1
}
for ((chunk_index = 0; chunk_index < OVERSIZED_CHUNK_COUNT; chunk_index++)); do
  printf -v chunk_path 'oversized/chunk-%03d.bin' "${chunk_index}"
  fixture_git update-index \
    --add \
    --cacheinfo 100644 "${oversized_blob_oid}" "${chunk_path}"
done
first_chunk_entry="$(fixture_git ls-files -s -- oversized/chunk-000.bin)"
last_chunk_entry="$(fixture_git ls-files -s -- oversized/chunk-256.bin)"
[[ "${first_chunk_entry}" == \
  100644\ "${oversized_blob_oid}"\ 0$'\t'oversized/chunk-000.bin &&
  "${last_chunk_entry}" == \
  100644\ "${oversized_blob_oid}"\ 0$'\t'oversized/chunk-256.bin ]] || {
  echo "error: repeated-blob archive index entries are invalid" >&2
  exit 1
}
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit --quiet -m "fixture oversized repeated-blob archive"
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
read -r partial_archive_size partial_archive_links partial_archive_raw_mode < <(
  "${STAT_BIN}" -c '%s %h %f' -- "${partial_archive}"
)
if ! [[ "${partial_archive_size}" -gt 0 &&
  "${partial_archive_size}" -le "${ARCHIVE_LIMIT_BYTES}" &&
  "${partial_archive_links}" == "1" ]] ||
  ! stat_mode_matches_kind "${partial_archive_raw_mode}" "regular file"; then
  echo "error: oversized archive limiter wrote beyond its hard bound" >&2
  exit 1
fi
assert_evidence_file \
  "${oversized_output_parent}/candidate-tree.raw" \
  "400" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_evidence_file \
  "${oversized_output_parent}/candidate-blobs.raw" \
  "400" "${BLOB_ORACLE_LIMIT_BYTES}"
assert_evidence_file \
  "${partial_archive}" \
  "600" "${ARCHIVE_LIMIT_BYTES}"
assert_isolated_attributes_absent "${oversized_output_parent}"
[[ ! -e "${oversized_output_parent}/source-snapshot/go.mod" &&
  ! -L "${oversized_output_parent}/source-snapshot/go.mod" ]] || {
  echo "error: oversized archive failure reached snapshot extraction" >&2
  exit 1
}

readonly committed_symlink="${fixture_repo}/internal/guard/committed-link"
"${LN_BIN}" -s -- "nested/deeper/payload.txt" "${committed_symlink}"
fixture_git add -- internal/guard/committed-link
fixture_git \
  -c user.name=guard-provenance-fixture \
  -c user.email=guard-provenance-fixture.invalid \
  commit -m "fixture committed symlink"
symlink_commit="$(fixture_git rev-parse HEAD)"
readonly symlink_commit
[[ "${symlink_commit}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: symlink fixture commit is invalid" >&2
  exit 1
}
symlink_index_entry="$(fixture_git ls-files -s -- \
  internal/guard/committed-link)"
[[ "${symlink_index_entry}" == \
  120000\ *$'\t'internal/guard/committed-link ]] || {
  echo "error: committed symlink fixture is not stored with Git mode 120000" >&2
  exit 1
}
expect_gate_failure \
  "committed-symlink" \
  "${symlink_commit}" \
  "${symlink_output_parent}" \
  "forbidden Git tree entry mode=120000 type=blob"
assert_archive_phase_not_reached \
  "committed-symlink" "${symlink_output_parent}"
readonly rejected_tree_inventory="${symlink_output_parent}/candidate-tree.raw"
assert_evidence_file \
  "${rejected_tree_inventory}" \
  "600" "${TREE_INVENTORY_LIMIT_BYTES}"
assert_isolated_attributes_absent "${symlink_output_parent}"

printf 'live guard build provenance regression passed commit=%s archive_sha256=%s\n' \
  "${candidate_commit}" "${first_archive_sha}"
