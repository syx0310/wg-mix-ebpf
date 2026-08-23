package guard

// Observation describes what an executor can prove about the kernel startup
// guard after an operation. Unchanged is an operation outcome: no nft mutation
// was attempted, so callers must retain any observation established by an
// earlier operation in the same transaction.
type Observation string

const (
	ObservationUnchanged Observation = "unchanged"
	ObservationActive    Observation = "active"
	ObservationAbsent    Observation = "absent"
	ObservationUnknown   Observation = "unknown"
)

// Outcome separates the safety-relevant kernel observation from command
// diagnostics. Mutated is set once an nft mutation command has been issued;
// when the command fails it means the kernel may have been mutated, not that a
// mutation was conclusively observed. Warning preserves a command failure only
// when the requested postcondition was nevertheless proved exactly.
type Outcome struct {
	Observation Observation
	Mutated     bool
	Warning     error
}

func unchangedOutcome() Outcome {
	return Outcome{Observation: ObservationUnchanged}
}

func unknownOutcome() Outcome {
	return Outcome{Observation: ObservationUnknown}
}
