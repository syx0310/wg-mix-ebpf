#!/bin/bash

set -euo pipefail

readonly PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly LC_ALL='C'
readonly STAGE_PREFIX='/var/tmp/wg-mix-ebpf-source-stages'
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

readonly standard_bootstrap_entries=$'root-stage-runner.audit\nrun-root-owned-test-source-stage.sh\nstage-root-owned-test-source.bootstrap\nstage-root-owned-test-source.py\nstage-root-owned-test-source.sh'
readonly legacy_bootstrap_entries=$'inspect-linux-test-host.sh\nroot-stage-runner.audit\nrun-root-owned-test-source-stage.sh\nstage-root-owned-test-source.bootstrap\nstage-root-owned-test-source.py\nstage-root-owned-test-source.sh'
if [[ -n "${legacy_inspect_sha256}" ]]; then
  readonly expected_bootstrap_entries="${legacy_bootstrap_entries}"
else
  readonly expected_bootstrap_entries="${standard_bootstrap_entries}"
fi

validate_stage_entry_set() {
  local entry=''
  local candidate_bundle_seen=0
  local source_seen=0
  local staging_log_seen=0

  for entry in "$@"; do
    case "${entry}" in
      candidate.bundle) candidate_bundle_seen=1 ;;
      source) source_seen=1 ;;
      staging.log) staging_log_seen=1 ;;
      git-template | go-cache | go-mod-cache | go-path | go-tmp) ;;
      *)
        printf 'error: foreign stage top-level entry: %s\n' "${entry}" >&2
        return 66
        ;;
    esac
  done

  ((candidate_bundle_seen == 1)) || {
    printf 'error: required stage top-level entry is missing: candidate.bundle\n' >&2
    return 66
  }
  ((source_seen == 1)) || {
    printf 'error: required stage top-level entry is missing: source\n' >&2
    return 66
  }
  ((staging_log_seen == 1)) || {
    printf 'error: required stage top-level entry is missing: staging.log\n' >&2
    return 66
  }
}

actual_stage_entries=()
while IFS= read -r -d '' entry; do
  actual_stage_entries+=("${entry}")
done < <(/usr/bin/find "${stage}" -mindepth 1 -maxdepth 1 -printf '%f\0' | /usr/bin/sort -z)
readonly -a actual_stage_entries
actual_bootstrap_entries="$(/usr/bin/find "${bootstrap}" -mindepth 1 -maxdepth 1 -printf '%f\n' | /usr/bin/sort)"
validate_stage_entry_set "${actual_stage_entries[@]}" || exit $?
[[ "${actual_bootstrap_entries}" == "${expected_bootstrap_entries}" ]] || {
  printf 'error: bootstrap top-level entries drifted: %s\n' "${bootstrap}" >&2
  exit 66
}

[[ ! -L "${bundle}" && -f "${bundle}" &&
  "$(/usr/bin/stat -c '%U:%G:%a:%h:%F' -- "${bundle}")" == \
    'root:root:400:1:regular file' ]] || {
  printf 'error: staged bundle metadata is unsafe: %s\n' "${bundle}" >&2
  exit 66
}
[[ ! -L "${source}" && -d "${source}" &&
  "$(/usr/bin/readlink -e -- "${source}")" == "${source}" &&
  "$(/usr/bin/stat -c '%U:%G:%a:%F' -- "${source}")" == \
    'root:root:700:directory' ]] || {
  printf 'error: staged source metadata is unsafe: %s\n' "${source}" >&2
  exit 66
}
readonly staging_log="${stage}/staging.log"
[[ ! -L "${staging_log}" && -f "${staging_log}" &&
  "$(/usr/bin/stat -c '%U:%G:%a:%h:%F' -- "${staging_log}")" == \
    'root:root:600:1:regular file' ]] || {
  printf 'error: staging log metadata is unsafe: %s\n' "${staging_log}" >&2
  exit 66
}
for optional_directory in git-template go-cache go-mod-cache go-path go-tmp; do
  optional_path="${stage}/${optional_directory}"
  if [[ -e "${optional_path}" || -L "${optional_path}" ]]; then
    [[ ! -L "${optional_path}" && -d "${optional_path}" &&
      "$(/usr/bin/readlink -e -- "${optional_path}")" == "${optional_path}" &&
      "$(/usr/bin/stat -c '%U:%G:%a:%F' -- "${optional_path}")" == \
        'root:root:700:directory' ]] || {
      printf 'error: optional stage directory metadata is unsafe: %s\n' \
        "${optional_path}" >&2
      exit 66
    }
  fi
done

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
[[ ! -L "${runner}" && -f "${runner}" &&
  "$(/usr/bin/stat -c '%U:%G:%a:%h:%F' -- "${runner}")" == \
    'root:root:500:1:regular file' ]] || {
  printf 'error: bootstrap runner metadata is unsafe: %s\n' "${runner}" >&2
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

readonly stage_device="$(/usr/bin/stat -c '%d' -- /var/tmp)"
readonly bootstrap_device="$(/usr/bin/stat -c '%d' -- /run)"
for target_and_device in "${stage}:${stage_device}" "${bootstrap}:${bootstrap_device}"; do
  target="${target_and_device%:*}"
  expected_device="${target_and_device##*:}"
  [[ "$(/usr/bin/stat -c '%d' -- "${target}")" == "${expected_device}" ]] || {
    printf 'error: cleanup target is outside its fixed filesystem: %s\n' "${target}" >&2
    exit 66
  }
  if /usr/bin/find "${target}" -xdev -mindepth 1 -exec /usr/bin/stat -c '%d' -- '{}' + |
      /usr/bin/grep -Fvxq "${expected_device}"; then
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
