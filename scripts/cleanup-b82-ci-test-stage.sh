#!/bin/bash

set -euo pipefail

readonly PATH='/usr/bin:/bin'
readonly LC_ALL='C'
readonly STAGE_PREFIX='/var/tmp/wg-mix-ci-test'

export PATH LC_ALL
umask 077

usage() {
  printf '%s\n' \
    'usage: cleanup-b82-ci-test-stage.sh --run-id <12hex> --commit <40hex> --bundle-sha256 <64hex>' >&2
  exit 64
}

run_id=''
commit=''
bundle_sha256=''
while (($#)); do
  (($# >= 2)) || usage
  case "$1" in
    --run-id) run_id="$2" ;;
    --commit) commit="$2" ;;
    --bundle-sha256) bundle_sha256="$2" ;;
    *) usage ;;
  esac
  shift 2
done

[[ "${run_id}" =~ ^[0-9a-f]{12}$ ]] || usage
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "${bundle_sha256}" =~ ^[0-9a-f]{64}$ ]] || usage
[[ "${EUID}" -ne 0 && "$(/usr/bin/id -un)" == 'siyixuan' ]] || {
  printf 'error: cleanup must run as the unprivileged test user\n' >&2
  exit 77
}

readonly stage="${STAGE_PREFIX}-${run_id}"
readonly source="${stage}/source"
readonly bundle="${stage}/candidate.bundle"
readonly owner_marker="${stage}/.owner-${commit}-${bundle_sha256}"

[[ -d "${stage}" && ! -L "${stage}" &&
  "$(/usr/bin/readlink -e -- "${stage}")" == "${stage}" &&
  "$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${stage}")" == \
    'siyixuan:siyixuan:700:directory' ]] || {
  printf 'error: CI test stage is not a canonical owned directory: %s\n' "${stage}" >&2
  exit 66
}

expected_entries="$(/usr/bin/printf '%s\n' \
  ".owner-${commit}-${bundle_sha256}" \
  'candidate.bundle' 'go-cache' 'go-mod-cache' 'go-path' 'go-tmp' 'source' |
  /usr/bin/sort)"
if [[ -e "${stage}/.config" || -L "${stage}/.config" ]]; then
  [[ -d "${stage}/.config" && ! -L "${stage}/.config" &&
    "$(/usr/bin/stat -Lc '%U:%G:%F' -- "${stage}/.config")" == \
      'siyixuan:siyixuan:directory' &&
    -z "$(/usr/bin/find "${stage}/.config" -xdev \
      \( -type l -o \( ! -type d ! -type f \) -o \
      ! -user siyixuan -o ! -group siyixuan \) -print -quit)" ]] || {
    printf 'error: CI test stage Go config tree is invalid\n' >&2
    exit 66
  }
  expected_entries="$(/usr/bin/printf '%s\n%s\n' '.config' "${expected_entries}" |
    /usr/bin/sort)"
fi
readonly expected_entries
readonly actual_entries="$(/usr/bin/find "${stage}" -mindepth 1 -maxdepth 1 -printf '%f\n' |
  /usr/bin/sort)"
[[ "${actual_entries}" == "${expected_entries}" ]] || {
  printf 'error: CI test stage entries drifted: %s\n' "${stage}" >&2
  exit 66
}

[[ -f "${owner_marker}" && ! -L "${owner_marker}" &&
  "$(/usr/bin/stat -Lc '%U:%G:%a:%h:%s:%F' -- "${owner_marker}")" == \
    'siyixuan:siyixuan:600:1:0:regular file' ]] || {
  printf 'error: CI test stage ownership marker is invalid\n' >&2
  exit 66
}
[[ -f "${bundle}" && ! -L "${bundle}" &&
  "$(/usr/bin/stat -Lc '%U:%G:%a:%h:%F' -- "${bundle}")" == \
    'siyixuan:siyixuan:400:1:regular file' &&
  "$(/usr/bin/sha256sum -- "${bundle}")" == "${bundle_sha256}  ${bundle}" ]] || {
  printf 'error: CI test stage bundle identity is invalid\n' >&2
  exit 66
}

for directory in go-cache go-mod-cache go-path go-tmp source; do
  path="${stage}/${directory}"
  [[ -d "${path}" && ! -L "${path}" &&
    "$(/usr/bin/stat -Lc '%U:%G:%a:%F' -- "${path}")" == \
      'siyixuan:siyixuan:700:directory' ]] || {
    printf 'error: CI test stage child directory is invalid: %s\n' "${path}" >&2
    exit 66
  }
done
[[ "$(/usr/bin/git -C "${source}" rev-parse 'HEAD^{commit}')" == "${commit}" ]] || {
  printf 'error: CI test source commit drifted\n' >&2
  exit 66
}

readonly var_tmp_device="$(/usr/bin/stat -c '%d' -- /var/tmp)"
[[ "$(/usr/bin/stat -c '%d' -- "${stage}")" == "${var_tmp_device}" ]] || {
  printf 'error: CI test stage is outside the /var/tmp filesystem\n' >&2
  exit 66
}
if /usr/bin/find "${stage}" -xdev -mindepth 1 -type d \
    -exec /usr/bin/stat -c '%d' -- '{}' + |
    /usr/bin/grep -Fvxq "${var_tmp_device}"; then
  printf 'error: CI test stage crosses a filesystem boundary\n' >&2
  exit 66
fi
[[ -z "$(/usr/bin/find "${stage}" -xdev \
  \( ! -user siyixuan -o ! -group siyixuan \) -print -quit)" ]] || {
  printf 'error: CI test stage contains a foreign-owned entry\n' >&2
  exit 66
}

printf 'B82_CI_STAGE_CLEANUP_PREFLIGHT run_id=%s commit=%s stage=%s\n' \
  "${run_id}" "${commit}" "${stage}"
/usr/bin/find "${stage}" -xdev -type d \
  -exec /usr/bin/chmod u+rwx -- '{}' +
/usr/bin/find "${stage}" -xdev -depth -delete
[[ ! -e "${stage}" && ! -L "${stage}" ]] || {
  printf 'error: CI test stage cleanup did not converge: %s\n' "${stage}" >&2
  exit 67
}
printf 'B82_CI_STAGE_CLEANUP_COMPLETE run_id=%s stage_absent=1\n' "${run_id}"
