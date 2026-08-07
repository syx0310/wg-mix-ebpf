//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"path/filepath"
)

// loadedOwnerPrograms holds the exact program FDs referenced by a v4 TCX
// owner transaction. Classic TC slot inspection and rollback are intentionally
// absent: a v4 record never authorizes name/priority/handle based mutation.
type loadedOwnerPrograms struct {
	observations []*pinnedProgramObservation
	byID         map[uint32]*pinnedProgramObservation
}

func (programs *loadedOwnerPrograms) Close() error {
	if programs == nil {
		return nil
	}
	var errs []error
	for _, observation := range programs.observations {
		if err := observation.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	programs.observations = nil
	programs.byID = nil
	return errors.Join(errs...)
}

func loadOwnerPrograms(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) (*loadedOwnerPrograms, error) {
	if handle == nil || record == nil {
		return nil, errors.New("load owner programs requires a handle and record")
	}
	if handle.runtime.loadPinnedProgram == nil {
		return nil, errors.New("pinned-program loader is unavailable")
	}
	loaded := &loadedOwnerPrograms{
		byID: make(map[uint32]*pinnedProgramObservation),
	}
	closeOnError := func(err error) (*loadedOwnerPrograms, error) {
		return nil, errors.Join(err, loaded.Close())
	}
	for _, stage := range record.ProgramStages {
		if err := validateOwnerProgramStage(handle, record, stage); err != nil {
			return closeOnError(err)
		}
		observation, err := handle.runtime.loadPinnedProgram(
			filepath.Join(handle.procPath(), stage.FileName),
		)
		if err != nil {
			return closeOnError(fmt.Errorf(
				"load owner program stage %s: %w",
				stage.FileName, err,
			))
		}
		loaded.observations = append(loaded.observations, observation)
		if observation == nil ||
			observation.fd < 0 ||
			observation.id != stage.ProgramID {
			return closeOnError(fmt.Errorf(
				"owner program stage %s returned invalid FD/ID",
				stage.FileName,
			))
		}
		if previous, exists := loaded.byID[stage.ProgramID]; exists {
			// Active and desired stage pins may intentionally reference the
			// same exact program. Keep one lookup while closing every FD.
			if previous.id != observation.id {
				return closeOnError(fmt.Errorf(
					"owner program ID %d changed between stage pins",
					stage.ProgramID,
				))
			}
			continue
		}
		loaded.byID[stage.ProgramID] = observation
	}
	return loaded, nil
}
