package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// mapBatchEntry keeps the value which corresponds to a key available while a
// delete is in flight. Batch delete may complete a prefix before returning an
// error, so the original values are needed to restore that prefix.
type mapBatchEntry[K comparable, V any] struct {
	key   K
	value V
}

// mapBatchOperations is deliberately expressed as functions instead of an
// interface. The cilium/ebpf batch API accepts untyped slices, while keeping
// the helper typed makes partial-completion and rollback behavior directly
// unit-testable without a kernel map.
type mapBatchOperations[K comparable, V any] struct {
	batchUpdate func([]K, []V) (int, error)
	update      func(K, V) error
	batchDelete func([]K) (int, error)
	delete      func(K) error
}

// defaultMapBatchChunkSize bounds both the userspace argument allocation and
// the number of elements submitted in one BPF batch syscall. The largest
// canonical static map currently contains 512 entries, so 256 retains most of
// the syscall reduction without returning to an effectively unbounded batch.
const defaultMapBatchChunkSize = 256

func mapBatchEntries[K comparable, V any](entries map[K]V) []mapBatchEntry[K, V] {
	out := make([]mapBatchEntry[K, V], 0, len(entries))
	for key, value := range entries {
		out = append(out, mapBatchEntry[K, V]{key: key, value: value})
	}
	return out
}

// updateMapBatch updates entries which the generation pre-clean established as
// absent. A typed ebpf.ErrNotSupported from the first, zero-completion chunk is
// the only condition which selects the one-by-one compatibility path. Other
// batch errors are returned after all completed chunks have been rolled back.
func updateMapBatch[K comparable, V any](
	name string,
	ops mapBatchOperations[K, V],
	entries []mapBatchEntry[K, V],
) error {
	return updateMapBatchChunked(name, ops, entries, defaultMapBatchChunkSize)
}

func updateMapBatchChunked[K comparable, V any](
	name string,
	ops mapBatchOperations[K, V],
	entries []mapBatchEntry[K, V],
	chunkSize int,
) error {
	if chunkSize <= 0 {
		return fmt.Errorf("batch update map %s requires a positive chunk size, got %d", name, chunkSize)
	}
	if len(entries) == 0 {
		return nil
	}

	keys := make([]K, min(chunkSize, len(entries)))
	values := make([]V, len(keys))
	for start, chunkIndex := 0, 0; start < len(entries); start, chunkIndex = start+chunkSize, chunkIndex+1 {
		end := min(start+chunkSize, len(entries))
		chunk := entries[start:end]
		chunkKeys := keys[:len(chunk)]
		chunkValues := values[:len(chunk)]
		for i, entry := range chunk {
			chunkKeys[i] = entry.key
			chunkValues[i] = entry.value
		}

		completed, batchErr := ops.batchUpdate(chunkKeys, chunkValues)
		if batchErr == nil && completed == len(chunk) {
			continue
		}

		operationErr := mapBatchChunkError(
			"update", name, chunkIndex, start, end,
			mapBatchCompletionError("update", name, completed, len(chunk), batchErr),
		)
		if !validMapBatchCompletion(completed, len(chunk)) {
			// The completion count cannot identify a safe current-chunk
			// prefix. Conservatively undo the entire attempted chunk plus
			// every prior successful chunk, but never touch future chunks.
			return errors.Join(operationErr, rollbackMapUpdates(name, ops, entries[:end]))
		}
		if start == 0 && completed == 0 && batchErr != nil && errors.Is(batchErr, ebpf.ErrNotSupported) {
			return updateMapEntriesIndividually(name, ops, entries)
		}

		// A later unsupported result is an operation failure, not a signal
		// to mix batch and individual semantics. The contiguous prefix
		// includes all prior chunks and the completed part of this chunk.
		return errors.Join(
			operationErr,
			rollbackMapUpdates(name, ops, entries[:start+completed]),
		)
	}
	return nil
}

func updateMapEntriesIndividually[K comparable, V any](
	name string,
	ops mapBatchOperations[K, V],
	entries []mapBatchEntry[K, V],
) error {
	for i, entry := range entries {
		if err := ops.update(entry.key, entry.value); err != nil {
			updateErr := fmt.Errorf(
				"update map %s entry %d after batch API was unsupported: %w",
				name,
				i,
				err,
			)
			// Include the failed entry because a failed syscall need not prove
			// that the kernel left it untouched. Future entries were never
			// attempted and must not be mutated by rollback.
			rollbackErr := rollbackMapUpdates(name, ops, entries[:i+1])
			return errors.Join(updateErr, rollbackErr)
		}
	}
	return nil
}

func rollbackMapUpdates[K comparable, V any](
	name string,
	ops mapBatchOperations[K, V],
	entries []mapBatchEntry[K, V],
) error {
	var errs []error
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if err := ops.delete(entry.key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("rollback map %s update entry %d: %w", name, i, err))
		}
	}
	return errors.Join(errs...)
}

// deleteMapBatch removes a fully observed set of entries. On a batch failure,
// values from every completed chunk and the current completed prefix are
// restored before the error is returned. The individual compatibility path is
// selected only before the first batch mutation and tolerates already-missing
// keys.
func deleteMapBatch[K comparable, V any](
	name string,
	ops mapBatchOperations[K, V],
	entries []mapBatchEntry[K, V],
) error {
	return deleteMapBatchChunked(name, ops, entries, defaultMapBatchChunkSize)
}

func deleteMapBatchChunked[K comparable, V any](
	name string,
	ops mapBatchOperations[K, V],
	entries []mapBatchEntry[K, V],
	chunkSize int,
) error {
	if chunkSize <= 0 {
		return fmt.Errorf("batch delete map %s requires a positive chunk size, got %d", name, chunkSize)
	}
	if len(entries) == 0 {
		return nil
	}

	keys := make([]K, min(chunkSize, len(entries)))
	for start, chunkIndex := 0, 0; start < len(entries); start, chunkIndex = start+chunkSize, chunkIndex+1 {
		end := min(start+chunkSize, len(entries))
		chunk := entries[start:end]
		chunkKeys := keys[:len(chunk)]
		for i, entry := range chunk {
			chunkKeys[i] = entry.key
		}

		completed, batchErr := ops.batchDelete(chunkKeys)
		if batchErr == nil && completed == len(chunk) {
			continue
		}

		operationErr := mapBatchChunkError(
			"delete", name, chunkIndex, start, end,
			mapBatchCompletionError("delete", name, completed, len(chunk), batchErr),
		)
		if !validMapBatchCompletion(completed, len(chunk)) {
			return errors.Join(operationErr, rollbackMapDeletes(name, ops, entries[:end]))
		}
		if start == 0 && completed == 0 && batchErr != nil && errors.Is(batchErr, ebpf.ErrNotSupported) {
			return deleteMapEntriesIndividually(name, ops, entries)
		}

		return errors.Join(
			operationErr,
			rollbackMapDeletes(name, ops, entries[:start+completed]),
		)
	}
	return nil
}

func validMapBatchCompletion(completed, total int) bool {
	return completed >= 0 && completed <= total
}

func deleteMapEntriesIndividually[K comparable, V any](
	name string,
	ops mapBatchOperations[K, V],
	entries []mapBatchEntry[K, V],
) error {
	for i, entry := range entries {
		if err := ops.delete(entry.key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			deleteErr := fmt.Errorf(
				"delete map %s entry %d after batch API was unsupported: %w",
				name,
				i,
				err,
			)
			rollbackErr := rollbackMapDeletes(name, ops, entries[:i+1])
			return errors.Join(deleteErr, rollbackErr)
		}
	}
	return nil
}

func rollbackMapDeletes[K comparable, V any](
	name string,
	ops mapBatchOperations[K, V],
	entries []mapBatchEntry[K, V],
) error {
	var errs []error
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if err := ops.update(entry.key, entry.value); err != nil {
			errs = append(errs, fmt.Errorf("rollback map %s delete entry %d: %w", name, i, err))
		}
	}
	return errors.Join(errs...)
}

func mapBatchChunkError(
	operation string,
	name string,
	chunkIndex int,
	start int,
	end int,
	err error,
) error {
	return fmt.Errorf(
		"batch %s map %s chunk %d entries [%d:%d]: %w",
		operation,
		name,
		chunkIndex,
		start,
		end,
		err,
	)
}

func mapBatchCompletionError(operation, name string, completed, total int, err error) error {
	if completed < 0 || completed > total {
		if err == nil {
			return fmt.Errorf(
				"batch %s map %s reported invalid completion count %d for %d entries",
				operation,
				name,
				completed,
				total,
			)
		}
		return fmt.Errorf(
			"batch %s map %s reported invalid completion count %d for %d entries: %w",
			operation,
			name,
			completed,
			total,
			err,
		)
	}
	if err == nil {
		return fmt.Errorf(
			"batch %s map %s completed %d of %d entries without an error",
			operation,
			name,
			completed,
			total,
		)
	}
	return fmt.Errorf(
		"batch %s map %s completed %d of %d entries: %w",
		operation,
		name,
		completed,
		total,
		err,
	)
}
