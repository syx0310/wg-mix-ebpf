package diagnostic

import (
	"fmt"
	"regexp"

	"github.com/cilium/ebpf"
)

var guardOwnershipMarkerPattern = regexp.MustCompile(`wg-mix-ebpf-guard-v2:[0-9A-Fa-f]{64}`)

// Redact removes durable ownership proof material from text which may be
// persisted in a world-readable status file or emitted by a diagnostic
// command. Table names and handles remain visible because they are useful for
// recovery and are not sufficient to authorize a mutation.
func Redact(text string) string {
	return guardOwnershipMarkerPattern.ReplaceAllString(text, "wg-mix-ebpf-guard-v2:<redacted>")
}

// ErrorText preserves the outer operation context and expands an embedded
// verifier error to its complete log. Verifier logs contain BPF instructions
// and kernel diagnostics, not configuration secrets, and are required to
// diagnose a rejected object without repeatedly changing and rerunning it.
func ErrorText(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	verifiers := verifierErrors(err)
	if len(verifiers) == 0 {
		return Redact(text)
	}
	for index, verifier := range verifiers {
		text += fmt.Sprintf(
			"\nBPF_VERIFIER_LOG_BEGIN index=%d total=%d\n%+v\nBPF_VERIFIER_LOG_END index=%d total=%d",
			index+1,
			len(verifiers),
			verifier,
			index+1,
			len(verifiers),
		)
	}
	return Redact(text)
}

func verifierErrors(err error) []*ebpf.VerifierError {
	seen := make(map[*ebpf.VerifierError]struct{})
	var found []*ebpf.VerifierError
	var walk func(error)
	walk = func(current error) {
		if current == nil {
			return
		}
		if verifier, ok := current.(*ebpf.VerifierError); ok {
			if _, duplicate := seen[verifier]; !duplicate {
				seen[verifier] = struct{}{}
				found = append(found, verifier)
			}
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range wrapped.Unwrap() {
				walk(child)
			}
		case interface{ Unwrap() error }:
			walk(wrapped.Unwrap())
		}
	}
	walk(err)
	return found
}
