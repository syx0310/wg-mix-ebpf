package faketcp

import "errors"

// GenerationPreCommit prepares generation-local state while that generation
// is still unreachable from packet processing. Implementations must be safe to
// call only once, or make repeated calls return the result of the first call.
type GenerationPreCommit interface {
	PrepareUnreachableGeneration() error
}

// CommitGenerationReachability establishes the ordering boundary between
// generation-local preparation and every operation which can make that
// generation visible to packet processing.
//
// makeReachable must contain all reachability mutations for the generation,
// including program-array population, policy publication, and XDP/TC attach.
// It is never called when preparation fails. The generation owner remains
// responsible for rolling back any partial reachability caused by an error in
// makeReachable.
func CommitGenerationReachability(
	preCommit GenerationPreCommit,
	makeReachable func() error,
) error {
	if interfaceValueIsNil(preCommit) {
		return errors.New("faketcp generation pre-commit hook is nil")
	}
	if makeReachable == nil {
		return errors.New("faketcp generation reachability callback is nil")
	}
	if err := preCommit.PrepareUnreachableGeneration(); err != nil {
		return err
	}
	return makeReachable()
}
