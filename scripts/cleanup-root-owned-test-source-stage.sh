#!/bin/bash

set -euo pipefail

readonly PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly LC_ALL='C'
readonly STAGE_PREFIX='/run/wg-mix-ebpf-source-stages'
readonly BOOTSTRAP_PREFIX='/run/wg-mix-ebpf-source-bootstrap'

export PATH LC_ALL
umask 077

[[ "${EUID}" -eq 0 ]] || {
  printf 'error: cleanup must run as root\n' >&2
  exit 77
}

usage() {
  printf '%s\n' \
    'usage: cleanup-root-owned-test-source-stage.sh --run-id <8hex> --commit <40hex> --bundle-sha256 <64hex> --runner-sha256 <64hex> [--legacy-inspect-sha256 <64hex>]' >&2
  exit 64
}

run_id=''
commit=''
bundle_sha256=''
runner_sha256=''
legacy_inspect_sha256=''
while (($#)); do
  (($# >= 2)) || usage
  case "$1" in
    --run-id) run_id="$2" ;;
    --commit) commit="$2" ;;
    --bundle-sha256) bundle_sha256="$2" ;;
    --runner-sha256) runner_sha256="$2" ;;
    --legacy-inspect-sha256) legacy_inspect_sha256="$2" ;;
    *) usage ;;
  esac
  shift 2
done

[[ "${run_id}" =~ ^[0-9a-f]{8}$ ]] || usage
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "${bundle_sha256}" =~ ^[0-9a-f]{64}$ ]] || usage
[[ "${runner_sha256}" =~ ^[0-9a-f]{64}$ ]] || usage
[[ -z "${legacy_inspect_sha256}" ||
  "${legacy_inspect_sha256}" =~ ^[0-9a-f]{64}$ ]] || usage

readonly stage="${STAGE_PREFIX}/${run_id}"
readonly bootstrap="${BOOTSTRAP_PREFIX}/${run_id}"
readonly source="${stage}/source"
readonly bundle="${stage}/candidate.bundle"
readonly runner="${bootstrap}/run-root-owned-test-source-stage.sh"
readonly legacy_inspect="${bootstrap}/inspect-linux-test-host.sh"

for target in "${stage}" "${bootstrap}"; do
  [[ -d "${target}" && ! -L "${target}" ]] || {
    printf 'error: cleanup target is not an existing directory: %s\n' "${target}" >&2
    exit 66
  }
  [[ "$(/usr/bin/readlink -e -- "${target}")" == "${target}" ]] || {
    printf 'error: cleanup target is not canonical: %s\n' "${target}" >&2
    exit 66
  }
  [[ "$(/usr/bin/stat -c '%U:%G:%a:%F' -- "${target}")" == 'root:root:700:directory' ]] || {
    printf 'error: cleanup target metadata is unsafe: %s\n' "${target}" >&2
    exit 66
  }
done

readonly expected_stage_entries=$'candidate.bundle\ngit-template\ngo-cache\ngo-mod-cache\ngo-path\ngo-tmp\nsource\nstaging.log'
readonly standard_bootstrap_entries=$'root-stage-runner.audit\nrun-root-owned-test-source-stage.sh\nstage-root-owned-test-source.bootstrap\nstage-root-owned-test-source.py\nstage-root-owned-test-source.sh'
readonly legacy_bootstrap_entries=$'inspect-linux-test-host.sh\nroot-stage-runner.audit\nrun-root-owned-test-source-stage.sh\nstage-root-owned-test-source.bootstrap\nstage-root-owned-test-source.py\nstage-root-owned-test-source.sh'
if [[ -n "${legacy_inspect_sha256}" ]]; then
  readonly expected_bootstrap_entries="${legacy_bootstrap_entries}"
else
  readonly expected_bootstrap_entries="${standard_bootstrap_entries}"
fi
actual_stage_entries="$(/usr/bin/find "${stage}" -mindepth 1 -maxdepth 1 -printf '%f\n' | /usr/bin/sort)"
actual_bootstrap_entries="$(/usr/bin/find "${bootstrap}" -mindepth 1 -maxdepth 1 -printf '%f\n' | /usr/bin/sort)"
[[ "${actual_stage_entries}" == "${expected_stage_entries}" ]] || {
  printf 'error: stage top-level entries drifted: %s\n' "${stage}" >&2
  exit 66
}
[[ "${actual_bootstrap_entries}" == "${expected_bootstrap_entries}" ]] || {
  printf 'error: bootstrap top-level entries drifted: %s\n' "${bootstrap}" >&2
  exit 66
}

[[ "$(/usr/bin/git -C "${source}" rev-parse HEAD)" == "${commit}" ]] || {
  printf 'error: staged source commit mismatch: %s\n' "${source}" >&2
  exit 66
}
[[ "$(/usr/bin/sha256sum -- "${bundle}")" == "${bundle_sha256}  ${bundle}" ]] || {
  printf 'error: staged bundle digest mismatch: %s\n' "${bundle}" >&2
  exit 66
}
[[ "$(/usr/bin/sha256sum -- "${runner}")" == "${runner_sha256}  ${runner}" ]] || {
  printf 'error: bootstrap runner digest mismatch: %s\n' "${runner}" >&2
  exit 66
}
if [[ -n "${legacy_inspect_sha256}" ]]; then
  [[ "$(/usr/bin/stat -c '%U:%G:%a:%h:%F' -- "${legacy_inspect}")" == \
      'root:root:500:1:regular file' &&
    "$(/usr/bin/sha256sum -- "${legacy_inspect}")" == \
      "${legacy_inspect_sha256}  ${legacy_inspect}" ]] || {
    printf 'error: legacy inspect helper identity mismatch: %s\n' \
      "${legacy_inspect}" >&2
    exit 66
  }
fi

readonly run_device="$(/usr/bin/stat -c '%d' -- /run)"
for target in "${stage}" "${bootstrap}"; do
  [[ "$(/usr/bin/stat -c '%d' -- "${target}")" == "${run_device}" ]] || {
    printf 'error: cleanup target is outside the /run filesystem: %s\n' "${target}" >&2
    exit 66
  }
  if /usr/bin/find "${target}" -xdev -mindepth 1 -type d -exec /usr/bin/stat -c '%d' -- '{}' + |
      /usr/bin/grep -Fvxq "${run_device}"; then
    printf 'error: cleanup target crosses a filesystem boundary: %s\n' "${target}" >&2
    exit 66
  fi
done

printf 'SOURCE_STAGE_CLEANUP_PREFLIGHT run_id=%s commit=%s stage=%s bootstrap=%s legacy_inspect=%s\n' \
  "${run_id}" "${commit}" "${stage}" "${bootstrap}" \
  "$([[ -n "${legacy_inspect_sha256}" ]] && printf 1 || printf 0)"

/usr/bin/find "${stage}" -xdev -depth -delete
[[ ! -e "${stage}" && ! -L "${stage}" ]] || {
  printf 'error: stage cleanup did not converge: %s\n' "${stage}" >&2
  exit 67
}
/usr/bin/find "${bootstrap}" -xdev -depth -delete
[[ ! -e "${bootstrap}" && ! -L "${bootstrap}" ]] || {
  printf 'error: bootstrap cleanup did not converge: %s\n' "${bootstrap}" >&2
  exit 67
}

printf 'SOURCE_STAGE_CLEANUP_COMPLETE run_id=%s stage_absent=1 bootstrap_absent=1\n' "${run_id}"
