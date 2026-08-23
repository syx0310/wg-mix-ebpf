package diagnostic

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestErrorTextExpandsCompleteWrappedVerifierLog(t *testing.T) {
	verifier := &ebpf.VerifierError{
		Cause: errors.New("permission denied"),
		Log:   []string{"first verifier line", "middle verifier line", "last verifier line"},
	}
	text := ErrorText(errors.Join(errors.New("load production object"), verifier))
	for _, required := range []string{
		"load production object",
		"BPF_VERIFIER_LOG_BEGIN",
		"first verifier line",
		"middle verifier line",
		"last verifier line",
		"BPF_VERIFIER_LOG_END",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("ErrorText() omitted %q:\n%s", required, text)
		}
	}
}

func TestErrorTextExpandsEveryJoinedVerifierLog(t *testing.T) {
	first := &ebpf.VerifierError{Cause: errors.New("first failure"), Log: []string{"first full log"}}
	second := &ebpf.VerifierError{Cause: errors.New("second failure"), Log: []string{"second full log"}}
	text := ErrorText(errors.Join(
		fmt.Errorf("program a: %w", first),
		fmt.Errorf("program b: %w", second),
	))
	for _, required := range []string{
		"BPF_VERIFIER_LOG_BEGIN index=1 total=2",
		"first full log",
		"BPF_VERIFIER_LOG_BEGIN index=2 total=2",
		"second full log",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("ErrorText() omitted %q:\n%s", required, text)
		}
	}
}

func TestErrorTextLeavesOrdinaryErrorConcise(t *testing.T) {
	if got := ErrorText(errors.New("ordinary")); got != "ordinary" {
		t.Fatalf("ErrorText() = %q, want ordinary", got)
	}
}

func TestRedactRemovesGuardOwnershipMarker(t *testing.T) {
	marker := "wg-mix-ebpf-guard-v2:" + strings.Repeat("a", 64)
	got := ErrorText(fmt.Errorf("nft rejected comment %s", marker))
	if strings.Contains(got, marker) || !strings.Contains(got, "wg-mix-ebpf-guard-v2:<redacted>") {
		t.Fatalf("ownership marker was not redacted: %q", got)
	}
}
