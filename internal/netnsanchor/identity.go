package netnsanchor

import "strings"

const unknownSourceCommit = "unknown"

// sourceCommit is injected only by the audited Makefile build target.
var sourceCommit = unknownSourceCommit

func normalizedSourceCommit() string {
	if len(sourceCommit) != 40 || strings.IndexFunc(sourceCommit, func(character rune) bool {
		return (character < '0' || character > '9') &&
			(character < 'a' || character > 'f')
	}) >= 0 {
		return unknownSourceCommit
	}
	return sourceCommit
}
