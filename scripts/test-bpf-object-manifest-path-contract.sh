#!/bin/sh

set -eu

fail() {
	printf 'error: BPF object manifest path contract: %s\n' "$1" >&2
	exit 1
}

actual_cwd=$(pwd -P)
expected_cwd=${WG_MIX_MANIFEST_CONTRACT_EXPECT_CWD-}
expected_baseline=${WG_MIX_MANIFEST_CONTRACT_EXPECT_BASELINE-}
expected_experimental=${WG_MIX_MANIFEST_CONTRACT_EXPECT_EXPERIMENTAL-}

test -n "$expected_cwd" || fail "missing expected working directory"
test -n "$expected_baseline" || fail "missing expected baseline path"
test -n "$expected_experimental" || fail "missing expected experimental path"

test "$actual_cwd" = "$expected_cwd" ||
	fail "working directory mismatch: got '$actual_cwd', want '$expected_cwd'"
test "${WG_MIX_BASELINE_MANIFEST_OBJECT-}" = "$expected_baseline" ||
	fail "baseline path mismatch: got '${WG_MIX_BASELINE_MANIFEST_OBJECT-}', want '$expected_baseline'"
test "${WG_MIX_FAKETCP_MANIFEST_OBJECT-}" = "$expected_experimental" ||
	fail "experimental path mismatch: got '${WG_MIX_FAKETCP_MANIFEST_OBJECT-}', want '$expected_experimental'"

case ${WG_MIX_BASELINE_MANIFEST_OBJECT-} in
	/*) ;;
	*) fail "baseline path is not absolute" ;;
esac
case ${WG_MIX_FAKETCP_MANIFEST_OBJECT-} in
	/*) ;;
	*) fail "experimental path is not absolute" ;;
esac

test "${CGO_ENABLED-}" = 0 || fail "CGO_ENABLED is not zero"
test "$#" -eq 5 || fail "argv count is $#, want 5"
test "$1" = test || fail "argv[1] is '$1', want 'test'"
test "$2" = ./internal/dataplane ||
	fail "argv[2] is '$2', want './internal/dataplane'"
test "$3" = -run || fail "argv[3] is '$3', want '-run'"
test "$4" = '^TestBuiltBPFObjectManifests$' ||
	fail "argv[4] is '$4', want '^TestBuiltBPFObjectManifests$'"
test "$5" = -count=1 || fail "argv[5] is '$5', want '-count=1'"

printf 'ok: BPF object manifest paths and argv are stable\n'
