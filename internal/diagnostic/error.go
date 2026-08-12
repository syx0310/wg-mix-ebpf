package diagnostic

import (
	"fmt"

	"github.com/cilium/ebpf"
)

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
		return text
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
	return text
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
