package netnsanchor

import "testing"

func TestNormalizedSourceCommitFailsClosed(t *testing.T) {
	original := sourceCommit
	t.Cleanup(func() {
		sourceCommit = original
	})
	valid := "0123456789abcdef0123456789abcdef01234567"
	sourceCommit = valid
	if got := normalizedSourceCommit(); got != valid {
		t.Fatalf("valid source commit = %q, want %q", got, valid)
	}
	for _, invalid := range []string{
		"",
		unknownSourceCommit,
		valid[:39],
		"0123456789ABCDEF0123456789ABCDEF01234567",
		valid[:39] + "\n",
	} {
		sourceCommit = invalid
		if got := normalizedSourceCommit(); got != unknownSourceCommit {
			t.Fatalf(
				"invalid source commit %q normalized to %q",
				invalid,
				got,
			)
		}
	}
}
