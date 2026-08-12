#!/usr/bin/bash -p
if [[ "$-" != *p* ]]; then
  builtin printf '%s\n' 'error: B82 performance tmux wrapper requires Bash privileged mode' >&2
  exit 1
fi
set -Eeuo pipefail

readonly SAFE_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly STAGED_NAME='scripts/run-b82-complete-performance-tmux.sh'
readonly MATRIX_NAME='scripts/run-b82-complete-performance-matrix.sh'
PATH="${SAFE_PATH}"
LC_ALL=C
export PATH LC_ALL
IFS=$' \t\n'
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD \
  PERL5LIB PYTHONHOME PYTHONPATH RUBYLIB XOR_PASSWORD

if [[ "${EUID}" -ne 0 || "$(/usr/bin/id -g)" -ne 0 ]]; then
  echo 'error: run the B82 performance tmux wrapper as root' >&2
  exit 1
fi

matrix_id="${WG_MIX_EBPF_PERFORMANCE_MATRIX_ID-}"
unset WG_MIX_EBPF_PERFORMANCE_MATRIX_ID
if [[ ! "${matrix_id}" =~ ^[0-9a-f]{8}$ || "$#" -ne 0 ]]; then
  echo 'error: tmux wrapper requires one sealed 8-hex matrix ID environment value' >&2
  exit 2
fi

script_reference="${BASH_SOURCE[0]}"
if [[ "${script_reference}" == /* ]]; then
  script_path="${script_reference}"
elif [[ "${script_reference}" == "${STAGED_NAME}" ]]; then
  script_path="$(builtin pwd -P)/${STAGED_NAME}"
else
  echo 'error: performance tmux wrapper path is not the fixed staged entry' >&2
  exit 1
fi
source_root="${script_path%/"${STAGED_NAME}"}"
if [[ ! "${source_root}" =~ ^/run/wg-mix-ebpf-source-stages/[0-9a-f]{8}/source$ ]]; then
  echo 'error: performance tmux wrapper must use a root-owned source stage' >&2
  exit 1
fi
matrix="${source_root}/${MATRIX_NAME}"
for executable in "${script_path}" "${matrix}"; do
  metadata="$(stat -c '%u:%g:%a:%h' -- "${executable}")"
  if [[ ! -f "${executable}" || -L "${executable}" || ! -x "${executable}" ||
    ! "${metadata}" =~ ^0:0:([0-7]{3,4}):1$ ]] ||
    (((8#${BASH_REMATCH[1]:-0} & 8#22) != 0)); then
    echo "error: staged performance executable is unsafe: ${executable}" >&2
    exit 1
  fi
done

exec /usr/bin/timeout --foreground --signal=TERM --kill-after=180s 9000s \
  /usr/bin/bash -p "${matrix}" run --matrix-id "${matrix_id}"
