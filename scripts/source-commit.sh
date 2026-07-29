#!/bin/sh

set -eu

unknown=unknown

print_unknown() {
	printf '%s\n' "${unknown}"
}

# Run Git with a deliberately minimal environment so repository-selection,
# alternate-object, config-injection, and replacement variables cannot
# redirect identity discovery away from the current worktree.
git_path=${PATH:-/usr/bin:/bin}
clean_git() {
	env -i \
		PATH="${git_path}" \
		LC_ALL=C \
		GIT_OPTIONAL_LOCKS=0 \
		git "$@"
}

if ! commit=$(clean_git rev-parse --verify 'HEAD^{commit}' 2>/dev/null); then
	print_unknown
	exit 0
fi
case "${commit}" in
	'' | *[!0-9a-f]*)
		print_unknown
		exit 0
		;;
esac
if [ "${#commit}" -ne 40 ]; then
	print_unknown
	exit 0
fi

if ! status=$(clean_git -c core.fsmonitor=false status --porcelain=v1 --untracked-files=normal --ignore-submodules=none 2>/dev/null); then
	print_unknown
	exit 0
fi
if [ -n "${status}" ]; then
	print_unknown
	exit 0
fi

printf '%s\n' "${commit}"
