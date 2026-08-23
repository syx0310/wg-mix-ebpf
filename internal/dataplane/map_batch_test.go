package dataplane

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

type mapBatchFixture struct {
	entries map[int]int

	batchUpdateCount *int
	batchUpdateErr   error
	batchDeleteCount *int
	batchDeleteErr   error
	updateErrAt      int
	deleteErrAt      int
	updateErr        error
	deleteErr        error

	batchUpdates int
	updates      int
	batchDeletes int
	deletes      int
}

func newMapBatchFixture(entries map[int]int) *mapBatchFixture {
	cloned := maps.Clone(entries)
	if cloned == nil {
		cloned = make(map[int]int)
	}
	return &mapBatchFixture{entries: cloned}
}

func (fixture *mapBatchFixture) operations() mapBatchOperations[int, int] {
	return mapBatchOperations[int, int]{
		batchUpdate: func(keys []int, values []int) (int, error) {
			fixture.batchUpdates++
			completed := len(keys)
			if fixture.batchUpdateCount != nil {
				completed = *fixture.batchUpdateCount
			}
			for i := 0; i < completed && i < len(keys); i++ {
				fixture.entries[keys[i]] = values[i]
			}
			return completed, fixture.batchUpdateErr
		},
		update: func(key int, value int) error {
			fixture.updates++
			if fixture.updateErrAt > 0 && fixture.updates == fixture.updateErrAt {
				return fixture.updateErr
			}
			fixture.entries[key] = value
			return nil
		},
		batchDelete: func(keys []int) (int, error) {
			fixture.batchDeletes++
			completed := len(keys)
			if fixture.batchDeleteCount != nil {
				completed = *fixture.batchDeleteCount
			}
			for i := 0; i < completed && i < len(keys); i++ {
				delete(fixture.entries, keys[i])
			}
			return completed, fixture.batchDeleteErr
		},
		delete: func(key int) error {
			fixture.deletes++
			if fixture.deleteErrAt > 0 && fixture.deletes == fixture.deleteErrAt {
				return fixture.deleteErr
			}
			if _, ok := fixture.entries[key]; !ok {
				return ebpf.ErrKeyNotExist
			}
			delete(fixture.entries, key)
			return nil
		},
	}
}

func mapBatchTestEntries() []mapBatchEntry[int, int] {
	return []mapBatchEntry[int, int]{
		{key: 1, value: 11},
		{key: 2, value: 22},
		{key: 3, value: 33},
	}
}

func intPointer(value int) *int {
	return &value
}

func TestMapBatchUpdateUsesOneBatchOperation(t *testing.T) {
	fixture := newMapBatchFixture(nil)
	entries := mapBatchTestEntries()

	if err := updateMapBatch("test_map", fixture.operations(), entries); err != nil {
		t.Fatal(err)
	}
	if fixture.batchUpdates != 1 || fixture.updates != 0 || fixture.deletes != 0 {
		t.Fatalf(
			"mutation calls: batch updates=%d updates=%d deletes=%d",
			fixture.batchUpdates,
			fixture.updates,
			fixture.deletes,
		)
	}
	want := map[int]int{1: 11, 2: 22, 3: 33}
	if !maps.Equal(fixture.entries, want) {
		t.Fatalf("updated entries = %v, want %v", fixture.entries, want)
	}
}

func TestMapBatchUpdateFallbackRequiresTypedUnsupported(t *testing.T) {
	entries := mapBatchTestEntries()

	t.Run("typed unsupported", func(t *testing.T) {
		fixture := newMapBatchFixture(nil)
		fixture.batchUpdateCount = intPointer(0)
		fixture.batchUpdateErr = fmt.Errorf("batch probe: %w", ebpf.ErrNotSupported)

		if err := updateMapBatch("test_map", fixture.operations(), entries); err != nil {
			t.Fatal(err)
		}
		if fixture.batchUpdates != 1 || fixture.updates != len(entries) {
			t.Fatalf("batch/fallback calls = %d/%d", fixture.batchUpdates, fixture.updates)
		}
	})

	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "untyped text", err: errors.New("not supported")},
		{name: "raw EINVAL", err: syscall.EINVAL},
		{name: "raw EOPNOTSUPP", err: syscall.EOPNOTSUPP},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMapBatchFixture(nil)
			fixture.batchUpdateCount = intPointer(0)
			fixture.batchUpdateErr = test.err

			err := updateMapBatch("test_map", fixture.operations(), entries)
			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want wrapped %v", err, test.err)
			}
			if fixture.updates != 0 {
				t.Fatalf("non-typed unsupported error used fallback %d times", fixture.updates)
			}
		})
	}
}

func TestMapBatchUpdatePartialFailureRollsBack(t *testing.T) {
	injected := errors.New("injected batch update failure")
	fixture := newMapBatchFixture(nil)
	fixture.batchUpdateCount = intPointer(2)
	fixture.batchUpdateErr = injected

	err := updateMapBatch("test_map", fixture.operations(), mapBatchTestEntries())
	if !errors.Is(err, injected) {
		t.Fatalf("error = %v, want wrapped %v", err, injected)
	}
	if len(fixture.entries) != 0 {
		t.Fatalf("partial batch update survived rollback: %v", fixture.entries)
	}
	if fixture.deletes != 2 {
		t.Fatalf("rollback deletes = %d, want 2", fixture.deletes)
	}
}

func TestMapBatchUpdateFallbackFailureRollsBackAttemptedPrefix(t *testing.T) {
	injected := errors.New("injected individual update failure")
	fixture := newMapBatchFixture(nil)
	fixture.batchUpdateCount = intPointer(0)
	fixture.batchUpdateErr = fmt.Errorf("batch probe: %w", ebpf.ErrNotSupported)
	fixture.updateErrAt = 2
	fixture.updateErr = injected

	err := updateMapBatch("test_map", fixture.operations(), mapBatchTestEntries())
	if !errors.Is(err, injected) {
		t.Fatalf("error = %v, want wrapped %v", err, injected)
	}
	if len(fixture.entries) != 0 {
		t.Fatalf("failed fallback survived rollback: %v", fixture.entries)
	}
	if fixture.deletes != 2 {
		t.Fatalf("fallback rollback deletes = %d, want attempted prefix 2", fixture.deletes)
	}
}

func TestMapBatchDeleteUsesOneBatchOperation(t *testing.T) {
	fixture := newMapBatchFixture(map[int]int{1: 11, 2: 22, 3: 33})

	if err := deleteMapBatch("test_map", fixture.operations(), mapBatchTestEntries()); err != nil {
		t.Fatal(err)
	}
	if fixture.batchDeletes != 1 || fixture.deletes != 0 || fixture.updates != 0 {
		t.Fatalf(
			"mutation calls: batch deletes=%d deletes=%d updates=%d",
			fixture.batchDeletes,
			fixture.deletes,
			fixture.updates,
		)
	}
	if len(fixture.entries) != 0 {
		t.Fatalf("batch delete left entries: %v", fixture.entries)
	}
}

func TestMapBatchDeleteTypedUnsupportedFallsBackBeforeMutation(t *testing.T) {
	fixture := newMapBatchFixture(map[int]int{1: 11, 2: 22, 3: 33})
	fixture.batchDeleteCount = intPointer(0)
	fixture.batchDeleteErr = fmt.Errorf("batch probe: %w", ebpf.ErrNotSupported)

	if err := deleteMapBatch("test_map", fixture.operations(), mapBatchTestEntries()); err != nil {
		t.Fatal(err)
	}
	if fixture.batchDeletes != 1 || fixture.deletes != 3 {
		t.Fatalf("batch/fallback calls = %d/%d", fixture.batchDeletes, fixture.deletes)
	}
	if len(fixture.entries) != 0 {
		t.Fatalf("fallback delete left entries: %v", fixture.entries)
	}
}

func TestMapBatchDeleteFallbackFailureRestoresAttemptedPrefix(t *testing.T) {
	injected := errors.New("injected individual delete failure")
	want := map[int]int{1: 11, 2: 22, 3: 33}
	fixture := newMapBatchFixture(want)
	fixture.batchDeleteCount = intPointer(0)
	fixture.batchDeleteErr = fmt.Errorf("batch probe: %w", ebpf.ErrNotSupported)
	fixture.deleteErrAt = 2
	fixture.deleteErr = injected

	err := deleteMapBatch("test_map", fixture.operations(), mapBatchTestEntries())
	if !errors.Is(err, injected) {
		t.Fatalf("error = %v, want wrapped %v", err, injected)
	}
	if !maps.Equal(fixture.entries, want) {
		t.Fatalf("failed fallback entries = %v, want restored %v", fixture.entries, want)
	}
	if fixture.updates != 2 {
		t.Fatalf("fallback rollback updates = %d, want attempted prefix 2", fixture.updates)
	}
}

func TestMapBatchDeleteFallbackRequiresTypedUnsupported(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "untyped text", err: errors.New("not supported")},
		{name: "raw EINVAL", err: syscall.EINVAL},
		{name: "raw EOPNOTSUPP", err: syscall.EOPNOTSUPP},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := map[int]int{1: 11, 2: 22, 3: 33}
			fixture := newMapBatchFixture(want)
			fixture.batchDeleteCount = intPointer(0)
			fixture.batchDeleteErr = test.err

			err := deleteMapBatch("test_map", fixture.operations(), mapBatchTestEntries())
			if !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want wrapped %v", err, test.err)
			}
			if fixture.deletes != 0 {
				t.Fatalf("non-typed unsupported error used fallback %d times", fixture.deletes)
			}
			if !maps.Equal(fixture.entries, want) {
				t.Fatalf("failed batch delete changed entries: %v", fixture.entries)
			}
		})
	}
}

func TestMapBatchDeletePartialFailureRestoresCompletedPrefix(t *testing.T) {
	injected := errors.New("injected batch delete failure")
	want := map[int]int{1: 11, 2: 22, 3: 33}
	fixture := newMapBatchFixture(want)
	fixture.batchDeleteCount = intPointer(2)
	fixture.batchDeleteErr = injected

	err := deleteMapBatch("test_map", fixture.operations(), mapBatchTestEntries())
	if !errors.Is(err, injected) {
		t.Fatalf("error = %v, want wrapped %v", err, injected)
	}
	if !maps.Equal(fixture.entries, want) {
		t.Fatalf("entries after rollback = %v, want %v", fixture.entries, want)
	}
	if fixture.updates != 2 {
		t.Fatalf("rollback updates = %d, want 2", fixture.updates)
	}
}

func TestMapBatchPartialSuccessWithoutErrorFailsAndRollsBack(t *testing.T) {
	entries := mapBatchTestEntries()

	t.Run("update", func(t *testing.T) {
		fixture := newMapBatchFixture(nil)
		fixture.batchUpdateCount = intPointer(2)
		err := updateMapBatch("test_map", fixture.operations(), entries)
		if err == nil || len(fixture.entries) != 0 {
			t.Fatalf("partial nil-error update: entries=%v error=%v", fixture.entries, err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		want := map[int]int{1: 11, 2: 22, 3: 33}
		fixture := newMapBatchFixture(want)
		fixture.batchDeleteCount = intPointer(2)
		err := deleteMapBatch("test_map", fixture.operations(), entries)
		if err == nil || !maps.Equal(fixture.entries, want) {
			t.Fatalf("partial nil-error delete: entries=%v error=%v", fixture.entries, err)
		}
	})
}

func TestMapBatchInvalidCompletionCountRollsBackWholeAttempt(t *testing.T) {
	entries := mapBatchTestEntries()

	t.Run("update", func(t *testing.T) {
		fixture := newMapBatchFixture(nil)
		fixture.batchUpdateCount = intPointer(len(entries) + 1)
		err := updateMapBatch("test_map", fixture.operations(), entries)
		if err == nil || len(fixture.entries) != 0 {
			t.Fatalf("invalid-count update: entries=%v error=%v", fixture.entries, err)
		}
		if fixture.deletes != len(entries) {
			t.Fatalf("conservative rollback deletes = %d, want %d", fixture.deletes, len(entries))
		}
	})

	t.Run("delete", func(t *testing.T) {
		want := map[int]int{1: 11, 2: 22, 3: 33}
		fixture := newMapBatchFixture(want)
		fixture.batchDeleteCount = intPointer(len(entries) + 1)
		err := deleteMapBatch("test_map", fixture.operations(), entries)
		if err == nil || !maps.Equal(fixture.entries, want) {
			t.Fatalf("invalid-count delete: entries=%v error=%v", fixture.entries, err)
		}
		if fixture.updates != len(entries) {
			t.Fatalf("conservative rollback updates = %d, want %d", fixture.updates, len(entries))
		}
	})
}

func TestMapBatchPreservesMutationAndRollbackErrors(t *testing.T) {
	mutationErr := errors.New("injected batch failure")
	rollbackErr := errors.New("injected rollback failure")
	fixture := newMapBatchFixture(nil)
	fixture.batchUpdateCount = intPointer(1)
	fixture.batchUpdateErr = mutationErr
	fixture.deleteErrAt = 1
	fixture.deleteErr = rollbackErr

	err := updateMapBatch("test_map", fixture.operations(), mapBatchTestEntries())
	if !errors.Is(err, mutationErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("joined error = %v, want mutation %v and rollback %v", err, mutationErr, rollbackErr)
	}
}

func TestMapBatchEmptySetAvoidsSyscalls(t *testing.T) {
	fixture := newMapBatchFixture(nil)
	ops := fixture.operations()
	if err := updateMapBatch("test_map", ops, nil); err != nil {
		t.Fatal(err)
	}
	if err := deleteMapBatch("test_map", ops, nil); err != nil {
		t.Fatal(err)
	}
	if fixture.batchUpdates+fixture.updates+fixture.batchDeletes+fixture.deletes != 0 {
		t.Fatalf("empty batch issued mutations: %+v", fixture)
	}
}

func sequentialMapBatchEntries(count int) []mapBatchEntry[int, int] {
	entries := make([]mapBatchEntry[int, int], count)
	for i := range entries {
		entries[i] = mapBatchEntry[int, int]{key: i, value: i + 1000}
	}
	return entries
}

func mapBatchEntryMap(entries []mapBatchEntry[int, int]) map[int]int {
	out := make(map[int]int, len(entries))
	for _, entry := range entries {
		out[entry.key] = entry.value
	}
	return out
}

func TestMapBatchDefaultChunkIsBounded(t *testing.T) {
	entries := sequentialMapBatchEntries(600)
	var updateSizes, deleteSizes []int
	ops := mapBatchOperations[int, int]{
		batchUpdate: func(keys []int, values []int) (int, error) {
			updateSizes = append(updateSizes, len(keys))
			if len(keys) != len(values) {
				t.Fatalf("keys=%d values=%d", len(keys), len(values))
			}
			return len(keys), nil
		},
		batchDelete: func(keys []int) (int, error) {
			deleteSizes = append(deleteSizes, len(keys))
			return len(keys), nil
		},
	}
	if err := updateMapBatch("canonical", ops, entries); err != nil {
		t.Fatal(err)
	}
	if err := deleteMapBatch("canonical", ops, entries); err != nil {
		t.Fatal(err)
	}
	want := []int{256, 256, 88}
	if !slices.Equal(updateSizes, want) || !slices.Equal(deleteSizes, want) {
		t.Fatalf("chunk sizes update=%v delete=%v, want %v", updateSizes, deleteSizes, want)
	}
}

func TestMapBatchRejectsInvalidChunkSizeBeforeMutation(t *testing.T) {
	entries := sequentialMapBatchEntries(1)
	for _, chunkSize := range []int{0, -1} {
		t.Run(fmt.Sprintf("size-%d", chunkSize), func(t *testing.T) {
			calls := 0
			ops := mapBatchOperations[int, int]{
				batchUpdate: func([]int, []int) (int, error) { calls++; return 0, nil },
				batchDelete: func([]int) (int, error) { calls++; return 0, nil },
			}
			if err := updateMapBatchChunked("canonical", ops, entries, chunkSize); err == nil {
				t.Fatal("invalid update chunk size succeeded")
			}
			if err := deleteMapBatchChunked("canonical", ops, entries, chunkSize); err == nil {
				t.Fatal("invalid delete chunk size succeeded")
			}
			if calls != 0 {
				t.Fatalf("invalid chunk size issued %d mutations", calls)
			}
		})
	}
}

func TestMapBatchUpdateSecondChunkPartialFailureRollsBackAllCompletedInReverse(t *testing.T) {
	entries := sequentialMapBatchEntries(600)
	state := make(map[int]int)
	injected := errors.New("injected second chunk update failure")
	batchCalls := 0
	var rollbackKeys []int
	ops := mapBatchOperations[int, int]{
		batchUpdate: func(keys []int, values []int) (int, error) {
			batchCalls++
			completed := len(keys)
			var err error
			if batchCalls == 2 {
				completed = 3
				err = injected
			}
			for i := 0; i < completed; i++ {
				state[keys[i]] = values[i]
			}
			return completed, err
		},
		delete: func(key int) error {
			rollbackKeys = append(rollbackKeys, key)
			delete(state, key)
			return nil
		},
	}
	err := updateMapBatch("canonical", ops, entries)
	if !errors.Is(err, injected) {
		t.Fatalf("error=%v, want %v", err, injected)
	}
	if len(state) != 0 {
		t.Fatalf("partial update survived rollback: %d entries", len(state))
	}
	if len(rollbackKeys) != 259 || rollbackKeys[0] != 258 || rollbackKeys[len(rollbackKeys)-1] != 0 {
		t.Fatalf("rollback order len=%d first/last=%d/%d", len(rollbackKeys), rollbackKeys[0], rollbackKeys[len(rollbackKeys)-1])
	}
}

func TestMapBatchDeleteLastChunkPartialFailureRestoresAllCompletedInReverse(t *testing.T) {
	entries := sequentialMapBatchEntries(600)
	want := mapBatchEntryMap(entries)
	state := maps.Clone(want)
	injected := errors.New("injected last chunk delete failure")
	batchCalls := 0
	var rollbackKeys []int
	ops := mapBatchOperations[int, int]{
		batchDelete: func(keys []int) (int, error) {
			batchCalls++
			completed := len(keys)
			var err error
			if batchCalls == 3 {
				completed = 7
				err = injected
			}
			for i := 0; i < completed; i++ {
				delete(state, keys[i])
			}
			return completed, err
		},
		update: func(key int, value int) error {
			rollbackKeys = append(rollbackKeys, key)
			state[key] = value
			return nil
		},
	}
	err := deleteMapBatch("canonical", ops, entries)
	if !errors.Is(err, injected) {
		t.Fatalf("error=%v, want %v", err, injected)
	}
	if !maps.Equal(state, want) {
		t.Fatalf("delete rollback restored %d/%d entries", len(state), len(want))
	}
	if len(rollbackKeys) != 519 || rollbackKeys[0] != 518 || rollbackKeys[len(rollbackKeys)-1] != 0 {
		t.Fatalf("rollback order len=%d first/last=%d/%d", len(rollbackKeys), rollbackKeys[0], rollbackKeys[len(rollbackKeys)-1])
	}
}

func TestMapBatchLaterTypedUnsupportedDoesNotMixFallback(t *testing.T) {
	entries := sequentialMapBatchEntries(300)
	t.Run("update", func(t *testing.T) {
		state := make(map[int]int)
		batchCalls, individualCalls := 0, 0
		ops := mapBatchOperations[int, int]{
			batchUpdate: func(keys []int, values []int) (int, error) {
				batchCalls++
				if batchCalls == 2 {
					return 0, fmt.Errorf("later update: %w", ebpf.ErrNotSupported)
				}
				for i := range keys {
					state[keys[i]] = values[i]
				}
				return len(keys), nil
			},
			update: func(key int, value int) error {
				individualCalls++
				state[key] = value
				return nil
			},
			delete: func(key int) error { delete(state, key); return nil },
		}
		err := updateMapBatch("canonical", ops, entries)
		if !errors.Is(err, ebpf.ErrNotSupported) || individualCalls != 0 || len(state) != 0 {
			t.Fatalf("error=%v individual=%d state=%d", err, individualCalls, len(state))
		}
	})

	t.Run("delete", func(t *testing.T) {
		want := mapBatchEntryMap(entries)
		state := maps.Clone(want)
		batchCalls, individualCalls := 0, 0
		ops := mapBatchOperations[int, int]{
			batchDelete: func(keys []int) (int, error) {
				batchCalls++
				if batchCalls == 2 {
					return 0, fmt.Errorf("later delete: %w", ebpf.ErrNotSupported)
				}
				for _, key := range keys {
					delete(state, key)
				}
				return len(keys), nil
			},
			delete: func(key int) error { individualCalls++; delete(state, key); return nil },
			update: func(key int, value int) error { state[key] = value; return nil },
		}
		err := deleteMapBatch("canonical", ops, entries)
		if !errors.Is(err, ebpf.ErrNotSupported) || individualCalls != 0 || !maps.Equal(state, want) {
			t.Fatalf("error=%v individual=%d restored=%v", err, individualCalls, maps.Equal(state, want))
		}
	})
}

func TestMapBatchPartialTypedUnsupportedDoesNotFallback(t *testing.T) {
	entries := mapBatchTestEntries()
	t.Run("update", func(t *testing.T) {
		fixture := newMapBatchFixture(nil)
		fixture.batchUpdateCount = intPointer(1)
		fixture.batchUpdateErr = fmt.Errorf("partial update: %w", ebpf.ErrNotSupported)
		err := updateMapBatch("canonical", fixture.operations(), entries)
		if !errors.Is(err, ebpf.ErrNotSupported) || fixture.updates != 0 || len(fixture.entries) != 0 {
			t.Fatalf("error=%v fallback=%d state=%v", err, fixture.updates, fixture.entries)
		}
	})

	t.Run("delete", func(t *testing.T) {
		want := mapBatchEntryMap(entries)
		fixture := newMapBatchFixture(want)
		fixture.batchDeleteCount = intPointer(1)
		fixture.batchDeleteErr = fmt.Errorf("partial delete: %w", ebpf.ErrNotSupported)
		err := deleteMapBatch("canonical", fixture.operations(), entries)
		if !errors.Is(err, ebpf.ErrNotSupported) || fixture.deletes != 0 || !maps.Equal(fixture.entries, want) {
			t.Fatalf("error=%v fallback=%d state=%v", err, fixture.deletes, fixture.entries)
		}
	})
}

func TestMapBatchLaterInvalidCompletionRollsBackOnlyAttemptedChunks(t *testing.T) {
	entries := sequentialMapBatchEntries(600)
	t.Run("update", func(t *testing.T) {
		state := make(map[int]int)
		batchCalls := 0
		var rollbackKeys []int
		ops := mapBatchOperations[int, int]{
			batchUpdate: func(keys []int, values []int) (int, error) {
				batchCalls++
				for i := range keys {
					state[keys[i]] = values[i]
				}
				if batchCalls == 2 {
					return len(keys) + 1, errors.New("invalid update count")
				}
				return len(keys), nil
			},
			delete: func(key int) error {
				rollbackKeys = append(rollbackKeys, key)
				delete(state, key)
				return nil
			},
		}
		if err := updateMapBatch("canonical", ops, entries); err == nil {
			t.Fatal("invalid completion count succeeded")
		}
		if len(state) != 0 || len(rollbackKeys) != 512 || rollbackKeys[0] != 511 || rollbackKeys[511] != 0 {
			t.Fatalf("state=%d rollback len=%d first/last=%d/%d", len(state), len(rollbackKeys), rollbackKeys[0], rollbackKeys[511])
		}
	})

	t.Run("delete", func(t *testing.T) {
		want := mapBatchEntryMap(entries)
		state := maps.Clone(want)
		batchCalls := 0
		var rollbackKeys []int
		ops := mapBatchOperations[int, int]{
			batchDelete: func(keys []int) (int, error) {
				batchCalls++
				for _, key := range keys {
					delete(state, key)
				}
				if batchCalls == 2 {
					return -1, errors.New("invalid delete count")
				}
				return len(keys), nil
			},
			update: func(key int, value int) error {
				rollbackKeys = append(rollbackKeys, key)
				state[key] = value
				return nil
			},
		}
		if err := deleteMapBatch("canonical", ops, entries); err == nil {
			t.Fatal("invalid completion count succeeded")
		}
		if !maps.Equal(state, want) || len(rollbackKeys) != 512 || rollbackKeys[0] != 511 || rollbackKeys[511] != 0 {
			t.Fatalf("restored=%v rollback len=%d first/last=%d/%d", maps.Equal(state, want), len(rollbackKeys), rollbackKeys[0], rollbackKeys[511])
		}
	})
}

func TestMapBatchCrossChunkPreservesOperationAndRollbackErrors(t *testing.T) {
	entries := sequentialMapBatchEntries(300)
	operationErr := errors.New("injected second chunk failure")
	rollbackErr := errors.New("injected prior chunk rollback failure")
	batchCalls := 0
	ops := mapBatchOperations[int, int]{
		batchUpdate: func(keys []int, _ []int) (int, error) {
			batchCalls++
			if batchCalls == 2 {
				return 1, operationErr
			}
			return len(keys), nil
		},
		delete: func(key int) error {
			if key == 100 {
				return rollbackErr
			}
			return nil
		},
	}
	err := updateMapBatch("canonical", ops, entries)
	if !errors.Is(err, operationErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("joined error=%v", err)
	}
}

// This is a valid high-cardinality mixed UDP/ICMP generation: 128 underlays,
// one UDP WireGuard and one ICMP WireGuard. It reaches the 256 managed-rule
// limit while keeping all seven canonical static maps non-empty.
var canonicalStaticMapBenchmarkSizes = []int{
	64,  // profile_map
	64,  // cipher_map
	128, // underlay_config_map
	256, // managed_fwmark_map
	384, // egress_rule_map: 128 * (2 UDP + 1 ICMP rule)
	512, // ingress_listener_map: 128 * 2 WireGuards * 2 families
	128, // icmp_listener_map
}

func canonicalStaticMapBenchmarkEntries() [][]mapBatchEntry[int, int] {
	sets := make([][]mapBatchEntry[int, int], len(canonicalStaticMapBenchmarkSizes))
	key := 0
	for i, size := range canonicalStaticMapBenchmarkSizes {
		sets[i] = make([]mapBatchEntry[int, int], size)
		for j := range sets[i] {
			sets[i][j] = mapBatchEntry[int, int]{key: key, value: key + 1}
			key++
		}
	}
	return sets
}

func TestCanonicalStaticMapReloadBatchSyscallBudget(t *testing.T) {
	sets := canonicalStaticMapBenchmarkEntries()
	for _, test := range []struct {
		name      string
		chunkSize int
		wantCalls int
	}{
		{name: "candidate-128", chunkSize: 128, wantCalls: 26},
		{name: "default-256", chunkSize: defaultMapBatchChunkSize, wantCalls: 18},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutationCalls := 0
			ops := mapBatchOperations[int, int]{
				batchUpdate: func(keys []int, _ []int) (int, error) {
					mutationCalls++
					return len(keys), nil
				},
				batchDelete: func(keys []int) (int, error) {
					mutationCalls++
					return len(keys), nil
				},
			}
			for _, entries := range sets {
				if err := updateMapBatchChunked("canonical", ops, entries, test.chunkSize); err != nil {
					t.Fatal(err)
				}
				if err := deleteMapBatchChunked("canonical", ops, entries, test.chunkSize); err != nil {
					t.Fatal(err)
				}
			}
			if mutationCalls != test.wantCalls {
				t.Fatalf("batch reload mutation calls = %d, want %d", mutationCalls, test.wantCalls)
			}
		})
	}

	individualCalls := 0
	for _, entries := range sets {
		individualCalls += 2 * len(entries)
	}
	if individualCalls != 3072 {
		t.Fatalf("individual reload mutation calls = %d, want 3072", individualCalls)
	}
}

func BenchmarkCanonicalStaticMapReloadBatchSyscallModel(b *testing.B) {
	sets := canonicalStaticMapBenchmarkEntries()
	entriesPerReload := 0
	for _, entries := range sets {
		entriesPerReload += len(entries)
	}

	for _, chunkSize := range []int{128, 256} {
		b.Run(fmt.Sprintf("chunk-%d", chunkSize), func(b *testing.B) {
			mutationCalls := 0
			ops := mapBatchOperations[int, int]{
				batchUpdate: func(keys []int, _ []int) (int, error) {
					mutationCalls++
					return len(keys), nil
				},
				batchDelete: func(keys []int) (int, error) {
					mutationCalls++
					return len(keys), nil
				},
			}
			b.ResetTimer()
			for range b.N {
				for _, entries := range sets {
					if err := updateMapBatchChunked("canonical", ops, entries, chunkSize); err != nil {
						b.Fatal(err)
					}
					if err := deleteMapBatchChunked("canonical", ops, entries, chunkSize); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(mutationCalls)/float64(b.N), "batch-syscalls/op")
			b.ReportMetric(float64(2*entriesPerReload), "individual-syscalls/op")
			b.ReportMetric(float64(entriesPerReload), "entries/op")
		})
	}
}
