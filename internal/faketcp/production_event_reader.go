package faketcp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

var ErrEventCaptureOutOfOrder = errors.New("faketcp capture event is out of order")

// eventLossCounter is borrowed for the lifetime of productionEventReader.
// Its owner must outlive the reader and fence Close before releasing it.
type eventLossCounter interface {
	Count() (uint64, error)
}

type captureSequenceState struct {
	sequence    uint64
	fingerprint [sha256.Size]byte
}

// productionEventReader adds the two invariants a raw ring reader cannot
// prove by itself: the kernel event-error counter must not advance, and each
// CPU's capture sequence must be gap-free and monotonic for one exact runtime
// identity. Exact duplicate records are admitted so Controller and the
// once-only reinjector can apply their normal idempotence rules. A gap or an
// older record is terminal; there is no alternate reader or replay path.
type productionEventReader struct {
	reader    EventReader
	identity  RuntimeIdentity
	sequences []captureSequenceState
	losses    eventLossCounter
	lastLoss  uint64
}

func newProductionEventReader(
	reader EventReader,
	identity RuntimeIdentity,
	possibleCPUs int,
	losses eventLossCounter,
	initialLoss uint64,
) (*productionEventReader, error) {
	if eventReaderIsNil(reader) {
		return nil, errors.New("faketcp production event reader is nil")
	}
	if err := validateRuntimeIdentity(identity); err != nil {
		return nil, fmt.Errorf("faketcp production event reader runtime identity: %w", err)
	}
	if possibleCPUs <= 0 {
		return nil, errors.New("faketcp production event reader possible CPU count must be positive")
	}
	if interfaceValueIsNil(losses) {
		return nil, errors.New("faketcp production event loss counter is nil")
	}
	return &productionEventReader{
		reader: reader, identity: identity,
		sequences: make([]captureSequenceState, possibleCPUs),
		losses:    losses,
		lastLoss:  initialLoss,
	}, nil
}

func (reader *productionEventReader) Read() (EventRecord, error) {
	if reader == nil || eventReaderIsNil(reader.reader) || interfaceValueIsNil(reader.losses) {
		return EventRecord{}, errors.New("faketcp production event reader is closed")
	}
	record, readErr := reader.reader.Read()
	currentLoss, lossErr := reader.losses.Count()
	if lossErr != nil {
		return EventRecord{}, fmt.Errorf("read faketcp kernel event-loss counter: %w", lossErr)
	}
	if currentLoss < reader.lastLoss {
		return EventRecord{}, fmt.Errorf(
			"faketcp kernel event-loss counter decreased from %d to %d",
			reader.lastLoss,
			currentLoss,
		)
	}
	kernelLoss := currentLoss - reader.lastLoss
	reader.lastLoss = currentLoss
	if kernelLoss > math.MaxUint64-record.LostSamples {
		return EventRecord{}, errors.New("faketcp event-loss count overflowed")
	}
	if lost := kernelLoss + record.LostSamples; lost != 0 {
		return EventRecord{LostSamples: lost}, nil
	}
	if readErr != nil {
		return EventRecord{}, readErr
	}

	decoded, err := DecodeEventSample(record.RawSample)
	if err != nil {
		return EventRecord{}, fmt.Errorf("validate ordered faketcp event: %w", err)
	}
	if identity := runtimeIdentityFromEvent(decoded.Event); identity != reader.identity {
		return EventRecord{}, fmt.Errorf(
			"faketcp event runtime identity does not match reader: event=%x reader=%x",
			identity.Incarnation,
			reader.identity.Incarnation,
		)
	}
	if decoded.Event.Type != abi.FakeTCPEventNeedHandshake {
		return record, nil
	}
	cpu := decoded.Event.CaptureCPU
	if uint64(cpu) >= uint64(len(reader.sequences)) {
		return EventRecord{}, fmt.Errorf(
			"faketcp capture CPU %d is outside possible CPU count %d",
			decoded.Event.CaptureCPU,
			len(reader.sequences),
		)
	}
	state := &reader.sequences[int(cpu)]
	sequence := decoded.Event.CaptureSequence
	fingerprint := sha256.Sum256(record.RawSample)
	switch {
	case sequence == state.sequence && sequence != 0:
		if fingerprint != state.fingerprint {
			return EventRecord{}, ErrCaptureIdentityConflict
		}
		return record, nil
	case sequence <= state.sequence:
		return EventRecord{}, fmt.Errorf(
			"%w on CPU %d: sequence %d follows %d",
			ErrEventCaptureOutOfOrder,
			cpu,
			sequence,
			state.sequence,
		)
	case sequence != state.sequence+1:
		return EventRecord{LostSamples: sequence - state.sequence - 1}, nil
	default:
		state.sequence = sequence
		state.fingerprint = fingerprint
		return record, nil
	}
}

func (reader *productionEventReader) SetDeadline(deadline time.Time) {
	if reader != nil && !eventReaderIsNil(reader.reader) {
		reader.reader.SetDeadline(deadline)
	}
}

func (reader *productionEventReader) Close() error {
	if reader == nil || eventReaderIsNil(reader.reader) {
		return nil
	}
	return reader.reader.Close()
}
