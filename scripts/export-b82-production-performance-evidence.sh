#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' \
    'error: B82 performance evidence exporter requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly STAGED_NAME="scripts/export-b82-production-performance-evidence.sh"
readonly RUN_PARENT="/var/tmp/wg-mix-ebpf-performance-tests"
PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB XOR_PASSWORD

if [[ "${EUID}" -ne 0 || "$(/usr/bin/id -g)" -ne 0 ]]; then
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
script_metadata="$(stat -c '%u:%g:%a:%h' -- "${script_path}")"
if [[ ! -f "${script_path}" || -L "${script_path}" || ! -x "${script_path}" ||
  ! "${script_metadata}" =~ ^0:0:([0-7]{3,4}):1$ ]] ||
  (((8#${BASH_REMATCH[1]:-0} & 8#22) != 0)); then
  echo "error: staged evidence exporter is unsafe" >&2
  exit 1
fi
unset script_metadata

run_root="${RUN_PARENT}/${run_id}"
owner="${run_root}/owner"
manifest="${run_root}/manifest"
complete="${run_root}/complete"
if ! run_root_metadata="$(stat -c '%u:%g:%a:%h' -- "${run_root}")"; then
  echo "error: completed run metadata cannot be read: ${run_root}" >&2
  exit 1
fi
if [[ ! -d "${run_root}" || -L "${run_root}" ||
  ! "${run_root_metadata}" =~ ^0:0:700:[1-9][0-9]*$ ||
  ! -f "${owner}" || -L "${owner}" ||
  "$(<"${owner}")" != "wg-mix-ebpf-performance:${run_id}" ||
  ! -f "${manifest}" || -L "${manifest}" ||
  ! -f "${complete}" || -L "${complete}" ]]; then
  echo "error: completed run ownership contract is invalid: ${run_root}" >&2
  exit 1
fi
unset run_root_metadata
if [[ "$(stat -c '%u:%g:%a:%h' -- "${owner}")" != "0:0:600:1" ||
  "$(stat -c '%u:%g:%a:%h' -- "${manifest}")" != "0:0:600:1" ||
  "$(stat -c '%u:%g:%a:%h' -- "${complete}")" != "0:0:600:1" ]]; then
  echo "error: completed run proof metadata is unsafe" >&2
  exit 1
fi
manifest_sha256="$(sha256sum -- "${manifest}" | awk '{print $1}')"
manifest_kind="$(awk -F= '$1 == "kind" { count++; value=substr($0,length($1)+2) } END { if (count > 1) exit 79; print value }' "${manifest}")"
[[ -n "${manifest_kind}" ]] || manifest_kind=cell
if [[ ! "${manifest_kind}" =~ ^(cell|matrix)$ ]]; then
  echo "error: performance evidence manifest kind is invalid" >&2
  exit 1
fi
complete_format='wg-mix-ebpf-b82-production-performance-complete-v1'
[[ "${manifest_kind}" == matrix ]] && \
  complete_format='wg-mix-ebpf-b82-production-performance-complete-v2'
proof_value() {
  awk -F= -v wanted="$1" \
    '$1 == wanted {count++; value=substr($0,length($1)+2)}
     END {if(count != 1 || value == "") exit 79; print value}' "${complete}"
}
expected_complete_lines=5
[[ "${manifest_kind}" == matrix ]] && expected_complete_lines=10
if [[ "$(awk 'END{print NR}' "${complete}")" != "${expected_complete_lines}" ||
  "$(proof_value format)" != "${complete_format}" ||
  "$(proof_value run_id)" != "${run_id}" ||
  "$(proof_value manifest_sha256)" != "${manifest_sha256}" ||
  "$(proof_value active_resources)" != absent ||
  "$(proof_value sensitive_files)" != absent ]]; then
  echo "error: completed run proof does not bind the retained manifest" >&2
  exit 1
fi
if [[ "${manifest_kind}" == matrix ]]; then
  if [[ "$(proof_value cells)" != 63 || "$(proof_value samples)" != 567 ]]; then
    echo 'error: matrix completion does not bind the exact 63/567 result count' >&2
    exit 1
  fi
  for result_spec in \
    "artifacts_sha256:${run_root}/artifacts.v1" \
    "results_sha256:${run_root}/results.v1.json" \
    "report_sha256:${run_root}/report.zh-CN.md"; do
    field="${result_spec%%:*}"
    result_path="${result_spec#*:}"
    if [[ ! -f "${result_path}" || -L "${result_path}" ||
      "$(stat -c '%u:%g:%a:%h' -- "${result_path}")" != "0:0:600:1" ]] ||
      "$(proof_value "${field}")" != \
        "$(sha256sum -- "${result_path}" | awk '{print $1}')" ]]; then
      echo "error: matrix completion does not bind ${field}" >&2
      exit 1
    fi
  done
fi
unset expected_complete_lines complete_format manifest_kind manifest_sha256
if [[ -e "${output}" || -L "${output}" ]]; then
  echo "error: evidence output already exists: ${output}" >&2
  exit 1
fi
output_parent="${output%/*}"
[[ -n "${output_parent}" ]] || output_parent="/"
canonical_output_parent="$(readlink -e -- "${output_parent}")" || {
  echo "error: evidence output parent cannot be resolved: ${output_parent}" >&2
  exit 1
}
canonical_output="${canonical_output_parent%/}/${output##*/}"
if [[ ! -d "${output_parent}" || -L "${output_parent}" ||
  "${canonical_output_parent}" != "${output_parent}" ||
  "${canonical_output}" != "${output}" ||
  "${output}" == "${RUN_PARENT}"/* ]]; then
  echo "error: evidence output parent is missing or unsafe: ${output_parent}" >&2
  exit 1
fi
unset canonical_output canonical_output_parent

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
