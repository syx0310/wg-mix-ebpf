//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type loadedOwnerMapStages struct {
	pins   []pinnedMapPin
	byName map[string]*pinnedMapObservation
}

func (stages *loadedOwnerMapStages) Close() error {
	if stages == nil {
		return nil
	}
	err := closePinnedMapPins(stages.pins)
	stages.pins = nil
	stages.byName = nil
	return err
}

func ownerMapDescriptor(name string) (pinnedMapDescriptor, error) {
	for _, descriptor := range pinnedMapDescriptors() {
		if descriptor.name == name {
			return descriptor, nil
		}
	}
	return pinnedMapDescriptor{}, fmt.Errorf("unknown canonical owner map %q", name)
}

func ownerMapsFromCollection(
	collection *ebpf.Collection,
) ([]pinOwnerMapIdentity, error) {
	if collection == nil {
		return nil, errors.New("BPF collection is nil")
	}
	maps := make([]pinOwnerMapIdentity, 0, len(pinnedMapDescriptors()))
	for _, descriptor := range pinnedMapDescriptors() {
		bpfMap := collection.Maps[descriptor.name]
		if bpfMap == nil {
			return nil, fmt.Errorf("BPF collection missing map %q", descriptor.name)
		}
		info, err := bpfMap.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect collection map %s: %w", descriptor.name, err)
		}
		mapID, ok := info.ID()
		if !ok || mapID == 0 {
			return nil, fmt.Errorf("collection map %s has no stable ID", descriptor.name)
		}
		maps = append(maps, pinOwnerMapIdentity{
			Name: descriptor.name,
			ID:   uint32(mapID),
		})
	}
	slices.SortFunc(maps, func(left, right pinOwnerMapIdentity) int {
		switch {
		case left.Name < right.Name:
			return -1
		case left.Name > right.Name:
			return 1
		default:
			return 0
		}
	})
	return maps, nil
}

func pinFreshCollectionMaps(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	collection *ebpf.Collection,
) error {
	if handle == nil || record == nil || collection == nil {
		return errors.New("pin fresh collection requires handle, owner, and collection")
	}
	ids := make(map[string]uint32, len(record.Maps))
	for _, ownerMap := range record.Maps {
		ids[ownerMap.Name] = ownerMap.ID
	}
	for _, descriptor := range pinnedMapDescriptors() {
		var stat unix.Stat_t
		err := unix.Fstatat(
			handle.targetFD,
			descriptor.name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if err == nil {
			return fmt.Errorf(
				"fresh canonical map %s unexpectedly already exists",
				descriptor.name,
			)
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		bpfMap := collection.Maps[descriptor.name]
		if bpfMap == nil || ids[descriptor.name] == 0 {
			return fmt.Errorf(
				"fresh owner record does not cover collection map %s",
				descriptor.name,
			)
		}
		if err := bpfMap.Pin(
			filepath.Join(handle.procPath(), descriptor.name),
		); err != nil {
			return fmt.Errorf("pin fresh collection map %s: %w", descriptor.name, err)
		}
		pin, err := validatePinnedMapAt(
			handle,
			descriptor,
			descriptor.name,
			ids[descriptor.name],
		)
		if err != nil {
			return err
		}
		if descriptor.name == "owner_map" {
			if err := validateOwnerSentinel(
				pin.observation.owner,
				pin.observation.ownerSeen,
				record,
				handle.resource,
			); err != nil {
				_ = pin.observation.Close()
				return err
			}
		}
		if err := pin.observation.Close(); err != nil {
			return err
		}
	}
	return nil
}

func validatePinnedMapAt(
	handle *pinPathHandle,
	descriptor pinnedMapDescriptor,
	fileName string,
	expectedID uint32,
) (*pinnedMapPin, error) {
	if handle == nil ||
		filepath.Base(fileName) != fileName ||
		expectedID == 0 {
		return nil, fmt.Errorf("unsafe pinned-map validation target %q", fileName)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(
		handle.targetFD,
		fileName,
		&stat,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o7777 != 0o600 ||
		stat.Uid != handle.runtime.expectedUID ||
		stat.Nlink != 1 {
		return nil, fmt.Errorf(
			"unsafe map pin %s/%s: mode=%#o uid=%d links=%d",
			handle.pinPath, fileName, stat.Mode, stat.Uid, stat.Nlink,
		)
	}
	mountID, err := handle.runtime.mountIDAt(
		handle.targetFD,
		fileName,
		unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW,
	)
	if err != nil {
		return nil, err
	}
	if mountID != handle.mountID {
		return nil, fmt.Errorf("map pin %s is on another mount", fileName)
	}
	observation, err := handle.runtime.loadPinnedMap(
		filepath.Join(handle.procPath(), fileName),
		descriptor.name,
	)
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (*pinnedMapPin, error) {
		return nil, errors.Join(err, observation.Close())
	}
	if err := validatePinnedMapObservation(
		descriptor,
		observation,
		false,
	); err != nil {
		return closeOnError(err)
	}
	if observation.id != expectedID {
		return closeOnError(fmt.Errorf(
			"map pin %s has ID %d, owner journal requires %d",
			fileName, observation.id, expectedID,
		))
	}
	var after unix.Stat_t
	if err := unix.Fstatat(
		handle.targetFD,
		fileName,
		&after,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return closeOnError(err)
	}
	if !samePinPathInode(
		pinPathInodeFromStat(&stat),
		pinPathInodeFromStat(&after),
	) {
		return closeOnError(fmt.Errorf("map pin %s changed while validating", fileName))
	}
	return &pinnedMapPin{
		descriptor:  descriptor,
		inode:       pinPathInodeFromStat(&stat),
		observation: observation,
	}, nil
}

func stageOwnerMaps(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	canonical []pinnedMapPin,
) error {
	if handle == nil || record == nil {
		return errors.New("stage owner maps requires a handle and record")
	}
	canonicalByName := make(map[string]pinnedMapPin, len(canonical))
	for _, pin := range canonical {
		canonicalByName[pin.descriptor.name] = pin
	}
	for _, stage := range record.MapStages {
		descriptor, err := ownerMapDescriptor(stage.Name)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		err = unix.Fstatat(
			handle.targetFD,
			stage.FileName,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if err == nil {
			pin, err := validatePinnedMapAt(
				handle,
				descriptor,
				stage.FileName,
				stage.MapID,
			)
			if err != nil {
				return err
			}
			if descriptor.name == "owner_map" {
				if err := validateOwnerSentinel(
					pin.observation.owner,
					pin.observation.ownerSeen,
					record,
					handleResource(handle),
				); err != nil {
					_ = pin.observation.Close()
					return err
				}
			}
			if err := pin.observation.Close(); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
		source, ok := canonicalByName[stage.Name]
		if !ok ||
			source.observation == nil ||
			source.observation.pin == nil ||
			source.observation.id != stage.MapID {
			if record.ActiveGeneration == 0 {
				continue
			}
			return fmt.Errorf(
				"canonical owner map %s is unavailable for staging",
				stage.Name,
			)
		}
		if err := source.observation.pin(
			filepath.Join(handle.procPath(), stage.FileName),
		); err != nil {
			return fmt.Errorf("stage owner map %s: %w", stage.Name, err)
		}
		pin, err := validatePinnedMapAt(
			handle,
			descriptor,
			stage.FileName,
			stage.MapID,
		)
		if err != nil {
			return err
		}
		if descriptor.name == "owner_map" {
			if err := validateOwnerSentinel(
				pin.observation.owner,
				pin.observation.ownerSeen,
				record,
				handleResource(handle),
			); err != nil {
				_ = pin.observation.Close()
				return err
			}
		}
		if err := pin.observation.Close(); err != nil {
			return err
		}
	}
	return nil
}

func loadOwnerMapStages(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) (*loadedOwnerMapStages, error) {
	loaded := &loadedOwnerMapStages{
		byName: make(map[string]*pinnedMapObservation, len(record.MapStages)),
	}
	closeOnError := func(err error) (*loadedOwnerMapStages, error) {
		return nil, errors.Join(err, loaded.Close())
	}
	for _, stage := range record.MapStages {
		descriptor, err := ownerMapDescriptor(stage.Name)
		if err != nil {
			return closeOnError(err)
		}
		pin, err := validatePinnedMapAt(
			handle,
			descriptor,
			stage.FileName,
			stage.MapID,
		)
		if err != nil {
			if record.ActiveGeneration == 0 && errors.Is(err, unix.ENOENT) {
				var canonicalStat unix.Stat_t
				canonicalErr := unix.Fstatat(
					handle.targetFD,
					stage.Name,
					&canonicalStat,
					unix.AT_SYMLINK_NOFOLLOW,
				)
				if errors.Is(canonicalErr, unix.ENOENT) {
					continue
				}
				if canonicalErr != nil {
					return closeOnError(canonicalErr)
				}
			}
			return closeOnError(fmt.Errorf(
				"load owner map stage %s: %w",
				stage.FileName, err,
			))
		}
		if descriptor.name == "owner_map" {
			if err := validateOwnerSentinel(
				pin.observation.owner,
				pin.observation.ownerSeen,
				record,
				handleResource(handle),
			); err != nil {
				_ = pin.observation.Close()
				return closeOnError(err)
			}
		}
		loaded.pins = append(loaded.pins, *pin)
		loaded.byName[stage.Name] = pin.observation
	}
	return loaded, nil
}

func handleResource(handle *pinPathHandle) pinResourceIdentity {
	if handle == nil {
		return pinResourceIdentity{}
	}
	return handle.resource
}

func canonicalMapIdentity(
	record *pinOwnerRecord,
	name string,
) (uint32, error) {
	for _, ownerMap := range record.Maps {
		if ownerMap.Name == name {
			return ownerMap.ID, nil
		}
	}
	return 0, fmt.Errorf("owner record does not list canonical map %s", name)
}

func removeCanonicalOwnerMaps(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	stages *loadedOwnerMapStages,
) error {
	if handle == nil || record == nil || stages == nil {
		return errors.New("canonical map removal requires owner stages")
	}
	// Preflight every canonical/staged ID before the first namespace mutation.
	for _, stage := range record.MapStages {
		descriptor, err := ownerMapDescriptor(stage.Name)
		if err != nil {
			return err
		}
		retiredName := stage.FileName + ".canonical-retired"
		var canonicalStat unix.Stat_t
		canonicalErr := unix.Fstatat(
			handle.targetFD,
			stage.Name,
			&canonicalStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		var retiredStat unix.Stat_t
		retiredErr := unix.Fstatat(
			handle.targetFD,
			retiredName,
			&retiredStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if canonicalErr == nil && retiredErr == nil {
			return fmt.Errorf(
				"both canonical and retired owner map %s exist",
				stage.Name,
			)
		}
		if canonicalErr != nil && !errors.Is(canonicalErr, unix.ENOENT) {
			return canonicalErr
		}
		if retiredErr != nil && !errors.Is(retiredErr, unix.ENOENT) {
			return retiredErr
		}
		stageObservation := stages.byName[stage.Name]
		if stageObservation == nil ||
			stageObservation.id != stage.MapID {
			if record.ActiveGeneration == 0 &&
				errors.Is(canonicalErr, unix.ENOENT) &&
				errors.Is(retiredErr, unix.ENOENT) {
				continue
			}
			return fmt.Errorf("owner map stage %s is unavailable", stage.Name)
		}
		switch {
		case canonicalErr == nil:
			pin, err := validatePinnedMapAt(
				handle,
				descriptor,
				stage.Name,
				stage.MapID,
			)
			if err != nil {
				return err
			}
			if err := pin.observation.Close(); err != nil {
				return err
			}
		case retiredErr == nil:
			pin, err := validatePinnedMapAt(
				handle,
				descriptor,
				retiredName,
				stage.MapID,
			)
			if err != nil {
				return err
			}
			if err := pin.observation.Close(); err != nil {
				return err
			}
		}
	}

	for _, stage := range record.MapStages {
		descriptor, err := ownerMapDescriptor(stage.Name)
		if err != nil {
			return err
		}
		retiredName := stage.FileName + ".canonical-retired"
		var retiredStat unix.Stat_t
		retiredErr := unix.Fstatat(
			handle.targetFD,
			retiredName,
			&retiredStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if retiredErr == nil {
			if err := unlinkValidatedOwnerMap(
				handle,
				descriptor,
				retiredName,
				stage.MapID,
			); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(retiredErr, unix.ENOENT) {
			return retiredErr
		}
		var canonicalStat unix.Stat_t
		canonicalErr := unix.Fstatat(
			handle.targetFD,
			stage.Name,
			&canonicalStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if errors.Is(canonicalErr, unix.ENOENT) {
			continue
		}
		if canonicalErr != nil {
			return canonicalErr
		}
		pin, err := validatePinnedMapAt(
			handle,
			descriptor,
			stage.Name,
			stage.MapID,
		)
		if err != nil {
			return err
		}
		identity := pin.inode
		if err := pin.observation.Close(); err != nil {
			return err
		}
		if handle.runtime.beforePinQuarantine != nil {
			if err := handle.runtime.beforePinQuarantine(stage.Name); err != nil {
				return fmt.Errorf("canonical map quarantine hook %s: %w", stage.Name, err)
			}
		}
		pin, err = validatePinnedMapAt(
			handle,
			descriptor,
			stage.Name,
			stage.MapID,
		)
		if err != nil {
			return fmt.Errorf("canonical map %s changed at quarantine hook: %w", stage.Name, err)
		}
		if !samePinPathInode(identity, pin.inode) {
			_ = pin.observation.Close()
			return fmt.Errorf("canonical map %s changed at quarantine hook", stage.Name)
		}
		if err := pin.observation.Close(); err != nil {
			return err
		}
		if err := unix.Renameat2(
			handle.targetFD,
			stage.Name,
			handle.targetFD,
			retiredName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("quarantine canonical owner map %s: %w", stage.Name, err)
		}
		if err := unlinkValidatedOwnerMap(
			handle,
			descriptor,
			retiredName,
			stage.MapID,
		); err != nil {
			return err
		}
	}
	return nil
}

func unlinkValidatedOwnerMap(
	handle *pinPathHandle,
	descriptor pinnedMapDescriptor,
	fileName string,
	mapID uint32,
) error {
	pin, err := validatePinnedMapAt(handle, descriptor, fileName, mapID)
	if err != nil {
		return err
	}
	identity := pin.inode
	if err := pin.observation.Close(); err != nil {
		return err
	}
	if handle.runtime.beforePinUnlink != nil {
		if err := handle.runtime.beforePinUnlink(fileName); err != nil {
			return fmt.Errorf("map pin unlink hook %s: %w", fileName, err)
		}
	}
	pin, err = validatePinnedMapAt(handle, descriptor, fileName, mapID)
	if err != nil {
		return fmt.Errorf("map pin %s changed at unlink hook: %w", fileName, err)
	}
	if !samePinPathInode(identity, pin.inode) {
		_ = pin.observation.Close()
		return fmt.Errorf("map pin %s changed at unlink hook", fileName)
	}
	if err := pin.observation.Close(); err != nil {
		return err
	}
	if err := unix.Unlinkat(handle.targetFD, fileName, 0); err != nil {
		return fmt.Errorf("unlink owner map pin %s: %w", fileName, err)
	}
	return nil
}

func restoreCanonicalOwnerMaps(
	handle *pinPathHandle,
	record *pinOwnerRecord,
	stages *loadedOwnerMapStages,
) error {
	var errs []error
	for _, stage := range record.MapStages {
		descriptor, err := ownerMapDescriptor(stage.Name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		observation := stages.byName[stage.Name]
		if observation == nil ||
			observation.id != stage.MapID ||
			observation.pin == nil {
			errs = append(errs, fmt.Errorf(
				"owner map stage %s cannot restore canonical pin",
				stage.Name,
			))
			continue
		}
		var stat unix.Stat_t
		err = unix.Fstatat(
			handle.targetFD,
			stage.Name,
			&stat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if errors.Is(err, unix.ENOENT) {
			if err := observation.pin(
				filepath.Join(handle.procPath(), stage.Name),
			); err != nil {
				errs = append(errs, fmt.Errorf(
					"restore canonical owner map %s: %w",
					stage.Name, err,
				))
				continue
			}
		} else if err != nil {
			errs = append(errs, err)
			continue
		}
		pin, err := validatePinnedMapAt(
			handle,
			descriptor,
			stage.Name,
			stage.MapID,
		)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := pin.observation.Close(); err != nil {
			errs = append(errs, err)
			continue
		}

		retiredName := stage.FileName + ".canonical-retired"
		var retiredStat unix.Stat_t
		err = unix.Fstatat(
			handle.targetFD,
			retiredName,
			&retiredStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if err == nil {
			if err := unlinkValidatedOwnerMap(
				handle,
				descriptor,
				retiredName,
				stage.MapID,
			); err != nil {
				errs = append(errs, err)
			}
		} else if !errors.Is(err, unix.ENOENT) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeOwnerMapStages(
	handle *pinPathHandle,
	record *pinOwnerRecord,
) error {
	stages := slices.Clone(record.MapStages)
	// owner_map is the bidirectional ownership sentinel and is removed last.
	for index, stage := range stages {
		if stage.Name != "owner_map" {
			continue
		}
		stages = append(stages[:index], stages[index+1:]...)
		stages = append(stages, stage)
		break
	}
	for _, stage := range stages {
		descriptor, err := ownerMapDescriptor(stage.Name)
		if err != nil {
			return err
		}
		retiredName := stage.FileName + ".retired"
		var stageStat unix.Stat_t
		stageErr := unix.Fstatat(
			handle.targetFD,
			stage.FileName,
			&stageStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		var retiredStat unix.Stat_t
		retiredErr := unix.Fstatat(
			handle.targetFD,
			retiredName,
			&retiredStat,
			unix.AT_SYMLINK_NOFOLLOW,
		)
		if stageErr == nil && retiredErr == nil {
			return fmt.Errorf(
				"both active and retired map stage %s exist",
				stage.FileName,
			)
		}
		if stageErr != nil && !errors.Is(stageErr, unix.ENOENT) {
			return stageErr
		}
		if retiredErr != nil && !errors.Is(retiredErr, unix.ENOENT) {
			return retiredErr
		}
		if retiredErr == nil {
			if err := unlinkValidatedOwnerMap(
				handle,
				descriptor,
				retiredName,
				stage.MapID,
			); err != nil {
				return err
			}
			continue
		}
		if errors.Is(stageErr, unix.ENOENT) {
			continue
		}
		pin, err := validatePinnedMapAt(
			handle,
			descriptor,
			stage.FileName,
			stage.MapID,
		)
		if err != nil {
			return err
		}
		identity := pin.inode
		if err := pin.observation.Close(); err != nil {
			return err
		}
		if handle.runtime.beforePinQuarantine != nil {
			if err := handle.runtime.beforePinQuarantine(stage.FileName); err != nil {
				return fmt.Errorf("map stage quarantine hook %s: %w", stage.FileName, err)
			}
		}
		pin, err = validatePinnedMapAt(
			handle,
			descriptor,
			stage.FileName,
			stage.MapID,
		)
		if err != nil {
			return fmt.Errorf("map stage %s changed at quarantine hook: %w", stage.FileName, err)
		}
		if !samePinPathInode(identity, pin.inode) {
			_ = pin.observation.Close()
			return fmt.Errorf("map stage %s changed at quarantine hook", stage.FileName)
		}
		if err := pin.observation.Close(); err != nil {
			return err
		}
		if err := unix.Renameat2(
			handle.targetFD,
			stage.FileName,
			handle.targetFD,
			retiredName,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("quarantine owner map stage %s: %w", stage.FileName, err)
		}
		if err := unlinkValidatedOwnerMap(
			handle,
			descriptor,
			retiredName,
			stage.MapID,
		); err != nil {
			return err
		}
	}
	return nil
}
