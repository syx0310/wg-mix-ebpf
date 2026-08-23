package faketcp

import (
	"errors"
	"slices"
	"testing"
)

type fakeGenerationPreCommit struct {
	trace *[]string
	err   error
}

func (hook *fakeGenerationPreCommit) PrepareUnreachableGeneration() error {
	*hook.trace = append(*hook.trace, "seed-runtime-identity")
	return hook.err
}

func TestCommitGenerationReachabilityOrdersIdentityBeforeEveryReachabilityMutation(t *testing.T) {
	trace := []string{"create-maps"}
	err := CommitGenerationReachability(
		&fakeGenerationPreCommit{trace: &trace},
		func() error {
			trace = append(trace,
				"populate-prog-array",
				"publish-policy-reachability",
				"attach-xdp-tc",
			)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"create-maps",
		"seed-runtime-identity",
		"populate-prog-array",
		"publish-policy-reachability",
		"attach-xdp-tc",
	}
	if !slices.Equal(trace, want) {
		t.Fatalf("generation commit trace=%v want=%v", trace, want)
	}
}

func TestCommitGenerationReachabilityNeverPublishesAfterPreparationFailure(t *testing.T) {
	trace := []string{"create-maps"}
	seedErr := errors.New("injected identity seed failure")
	err := CommitGenerationReachability(
		&fakeGenerationPreCommit{trace: &trace, err: seedErr},
		func() error {
			trace = append(trace, "reachable")
			return nil
		},
	)
	if !errors.Is(err, seedErr) {
		t.Fatalf("commit error=%v want=%v", err, seedErr)
	}
	want := []string{"create-maps", "seed-runtime-identity"}
	if !slices.Equal(trace, want) {
		t.Fatalf("failed generation commit trace=%v want=%v", trace, want)
	}
}

func TestCommitGenerationReachabilityRejectsNilBoundaries(t *testing.T) {
	trace := []string{}
	if err := CommitGenerationReachability(nil, func() error { return nil }); err == nil {
		t.Fatal("nil pre-commit hook was accepted")
	}
	if err := CommitGenerationReachability(
		&fakeGenerationPreCommit{trace: &trace}, nil,
	); err == nil {
		t.Fatal("nil reachability callback was accepted")
	}
	if len(trace) != 0 {
		t.Fatalf("invalid commit boundary invoked preparation: %v", trace)
	}
}
