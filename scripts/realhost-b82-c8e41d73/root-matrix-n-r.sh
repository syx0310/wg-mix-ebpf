#!/usr/bin/env bash
set -u
set -o pipefail

readonly RUN_ID='c8e41d73'

usage() {
  printf '%s\n' "usage: $0 {plan|run|restore}" >&2
}

retired() {
  printf '%s\n' \
    'REALHOST_V6_STOP run_id=c8e41d73 reason=legacy-matrix-retired-use-frozen-original-package-before-final-staging rc=78' >&2
  return 78
}

main() {
  (($# >= 1)) || { usage; return 64; }
  local mode="$1"
  shift
  case "${mode}" in
    plan)
      (($# == 0)) || { usage; return 64; }
      printf '%s\n' \
        'REALHOST_V6_FORWARD_AUTHORITY state=retired replacement=realnic-acceptance-v1' \
        'REALHOST_V6_LEGACY_CONTROLLER_AUTHORITY state=retired controller_entries=0 restore_entries=0' \
        'REALHOST_V6_HISTORICAL_RECOVERY package=frozen-original-package timing=before-final-staging' \
        'REALHOST_V6_PLAN_COMPLETE commands_executed=0 filesystem_writes=0 network_writes=0'
      ;;
    run | restore)
      retired
      ;;
    *)
      usage
      return 64
      ;;
  esac
}

main "$@"
