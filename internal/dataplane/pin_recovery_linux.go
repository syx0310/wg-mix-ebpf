//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

// pinOwnerRecoveryResult is shared by the v4 exact-TCX recovery state machine.
// Classic filter recovery deliberately has no production entry point.
type pinOwnerRecoveryResult struct {
	record           *pinOwnerRecord
	directoryRemoved bool
}

func ownerRuntimeNow(runtime pinPathRuntime) (time.Time, error) {
	if runtime.now == nil {
		return time.Time{}, errors.New("pin owner clock is unavailable")
	}
	now := runtime.now().UTC()
	if now.IsZero() {
		return time.Time{}, errors.New("pin owner clock returned zero time")
	}
	return now, nil
}

func observeOwnerMount(record *pinOwnerRecord, mountID uint64) {
	if record == nil || mountID == 0 {
		return
	}
	if !slices.Contains(record.BPFFSMountIDs, mountID) {
		record.BPFFSMountIDs = append(record.BPFFSMountIDs, mountID)
	}
	normalizePinOwnerRecord(record)
}

func validateOwnerPins(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	pins []pinnedMapPin,
	requireComplete bool,
) error {
	if requireComplete {
		if err := validateOwnerMapsAgainstPins(record, pins); err != nil {
			return err
		}
	} else {
		recordMaps := make(map[string]uint32, len(record.Maps))
		for _, ownerMap := range record.Maps {
			recordMaps[ownerMap.Name] = ownerMap.ID
		}
		for _, pin := range pins {
			wantID, exists := recordMaps[pin.descriptor.name]
			if !exists || pin.observation == nil || pin.observation.id != wantID {
				return fmt.Errorf(
					"partial canonical pin %s is outside the owner record",
					pin.descriptor.name,
				)
			}
		}
	}
	ownerPin, err := ownerMapPin(pins)
	if err != nil {
		if requireComplete {
			return err
		}
		return nil
	}
	return validateOwnerSentinel(
		ownerPin.observation.owner,
		ownerPin.observation.ownerSeen,
		record,
		handle.resource,
	)
}

func ownerControlValue(pins []pinnedMapPin) (abi.ControlValue, error) {
	for _, pin := range pins {
		if pin.descriptor.name != "control_map" {
			continue
		}
		if pin.observation == nil || !pin.observation.controlSeen {
			return abi.ControlValue{}, errors.New("owner control_map value is unavailable")
		}
		return pin.observation.control, nil
	}
	return abi.ControlValue{}, errors.New("owner canonical set is missing control_map")
}

func validateOwnerControlGeneration(
	pins []pinnedMapPin,
	generation uint64,
) error {
	value, err := ownerControlValue(pins)
	if err != nil {
		if generation == 0 {
			for _, pin := range pins {
				if pin.descriptor.name == "control_map" {
					return err
				}
			}
			return nil
		}
		return err
	}
	if generation == 0 {
		if value != (abi.ControlValue{}) {
			return fmt.Errorf(
				"fresh owner control value = %+v, want zero",
				value,
			)
		}
		return nil
	}
	if value.ActiveGeneration != generation ||
		value.ABIVersion != abi.Version {
		return fmt.Errorf(
			"owner control value generation/ABI = %d/%d, want %d/%d",
			value.ActiveGeneration, value.ABIVersion,
			generation, abi.Version,
		)
	}
	return nil
}
