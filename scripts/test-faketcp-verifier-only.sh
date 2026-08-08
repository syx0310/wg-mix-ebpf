#!/bin/bash
set -euo pipefail

readonly PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly LC_ALL="C"
readonly PYTHON_BIN="/usr/bin/python3"
readonly DIRNAME_BIN="/usr/bin/dirname"
export PATH LC_ALL

readonly RUNNER="${1:-}"
[[ -n "${RUNNER}" && "${RUNNER}" == /* && -f "${RUNNER}" && ! -L "${RUNNER}" ]] || {
  echo "usage: $0 /absolute/path/to/run-faketcp-verifier-only.py" >&2
  exit 2
}
shift
[[ "$#" -eq 0 ]] || {
  echo "error: verifier self-test accepts exactly one runner path" >&2
  exit 2
}
[[ -x "${PYTHON_BIN}" ]] || {
  echo "error: fixed Python interpreter is unavailable" >&2
  exit 1
}

SCRIPT_DIR="$(cd "$("${DIRNAME_BIN}" -- "$0")" && pwd -P)"
readonly SCRIPT_DIR
readonly TESTER="${SCRIPT_DIR}/test_faketcp_verifier_only.py"
[[ -f "${TESTER}" && ! -L "${TESTER}" ]] || {
  echo "error: FakeTCP verifier self-test module is unavailable" >&2
  exit 1
}

"${PYTHON_BIN}" -I "${TESTER}" "${RUNNER}"
