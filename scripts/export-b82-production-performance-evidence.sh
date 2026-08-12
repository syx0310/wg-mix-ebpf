#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' \
    'error: B82 performance evidence exporter requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly STAGED_NAME="scripts/export-b82-production-performance-evidence.sh"
readonly RUN_PARENT="/run/wg-mix-ebpf-performance-tests"
PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB XOR_PASSWORD

if [[ "${EUID}" -ne 0 || "${EGID}" -ne 0 ]]; then
  echo "error: run the B82 performance evidence exporter as root" >&2
  exit 1
fi
if (($# != 4)) || [[ "$1" != "--run-id" || "$3" != "--output" ]]; then
  echo "usage: ${STAGED_NAME} --run-id <8hex> --output /absolute/path.tar" >&2
  exit 2
fi
run_id="$2"
output="$4"
if [[ ! "${run_id}" =~ ^[0-9a-f]{8}$ || "${output}" != /* ||
  "${output}" == "/" || "${output}" == "${RUN_PARENT}"/* ]]; then
  echo "error: invalid performance evidence export arguments" >&2
  exit 2
fi

script_reference="${BASH_SOURCE[0]}"
if [[ "${script_reference}" == /* ]]; then
  script_path="${script_reference}"
elif [[ "${script_reference}" == "${STAGED_NAME}" ]]; then
  script_path="$(builtin pwd -P)/${STAGED_NAME}"
else
  echo "error: evidence exporter path is not the fixed staged entry" >&2
  exit 1
fi
source_root="${script_path%/"${STAGED_NAME}"}"
if [[ ! "${source_root}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]]; then
  echo "error: evidence exporter must use a root-owned source stage" >&2
  exit 1
fi
if [[ ! -f "${script_path}" || -L "${script_path}" || ! -x "${script_path}" ||
  "$(stat -c '%u:%g:%a:%h' -- "${script_path}")" != "0:0:700:1" ]]; then
  echo "error: staged evidence exporter is unsafe" >&2
  exit 1
fi

run_root="${RUN_PARENT}/${run_id}"
owner="${run_root}/owner"
manifest="${run_root}/manifest"
complete="${run_root}/complete"
if [[ ! -d "${run_root}" || -L "${run_root}" ||
  "$(stat -c '%u:%g:%a:%h' -- "${run_root}")" != "0:0:700:1" ||
  ! -f "${owner}" || -L "${owner}" ||
  "$(<"${owner}")" != "wg-mix-ebpf-performance:${run_id}" ||
  ! -f "${manifest}" || -L "${manifest}" ||
  ! -f "${complete}" || -L "${complete}" ]]; then
  echo "error: completed run ownership contract is invalid: ${run_root}" >&2
  exit 1
fi
if [[ "$(stat -c '%u:%g:%a:%h' -- "${owner}")" != "0:0:600:1" ||
  "$(stat -c '%u:%g:%a:%h' -- "${manifest}")" != "0:0:600:1" ||
  "$(stat -c '%u:%g:%a:%h' -- "${complete}")" != "0:0:600:1" ]]; then
  echo "error: completed run proof metadata is unsafe" >&2
  exit 1
fi
manifest_sha256="$(sha256sum -- "${manifest}" | awk '{print $1}')"
if ! grep -Fxq -- 'format=wg-mix-ebpf-b82-production-performance-complete-v1' "${complete}" ||
  ! grep -Fxq -- "run_id=${run_id}" "${complete}" ||
  ! grep -Fxq -- "manifest_sha256=${manifest_sha256}" "${complete}" ||
  ! grep -Fxq -- 'active_resources=absent' "${complete}" ||
  ! grep -Fxq -- 'sensitive_files=absent' "${complete}"; then
  echo "error: completed run proof does not bind the retained manifest" >&2
  exit 1
fi
if [[ -e "${output}" || -L "${output}" ]]; then
  echo "error: evidence output already exists: ${output}" >&2
  exit 1
fi
output_parent="${output%/*}"
[[ -n "${output_parent}" ]] || output_parent="/"
if [[ ! -d "${output_parent}" || -L "${output_parent}" ]]; then
  echo "error: evidence output parent is missing or unsafe: ${output_parent}" >&2
  exit 1
fi

printf 'EVIDENCE_EXPORT_START run_id=%s source=%s output=%s timestamp=%s argv=' \
  "${run_id}" "${run_root}" "${output}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%q ' tar --create --format=posix --numeric-owner --owner=0 --group=0 \
  --file "${output}" --directory "${RUN_PARENT}" "${run_id}"
printf '\n'
tar --create --format=posix --numeric-owner --owner=0 --group=0 \
  --file "${output}" --directory "${RUN_PARENT}" "${run_id}"
output_sha256="$(sha256sum -- "${output}" | awk '{print $1}')"
if [[ ! "${output_sha256}" =~ ^[0-9a-f]{64}$ ||
  "$(stat -c '%u:%g:%a:%h' -- "${output}")" != "0:0:600:1" ]]; then
  echo "error: evidence export artifact is unsafe" >&2
  exit 1
fi
printf 'EVIDENCE_EXPORT_COMPLETE run_id=%s output=%s sha256=%s timestamp=%s\n' \
  "${run_id}" "${output}" "${output_sha256}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
