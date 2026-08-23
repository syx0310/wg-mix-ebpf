//go:build linux

package dataplane

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func ebpfMapBatchOperations[K comparable, V any](m *ebpf.Map) mapBatchOperations[K, V] {
	return mapBatchOperations[K, V]{
		batchUpdate: func(keys []K, values []V) (int, error) {
			return m.BatchUpdate(keys, values, nil)
		},
		update: func(key K, value V) error {
			return m.Update(key, value, ebpf.UpdateAny)
		},
		batchDelete: func(keys []K) (int, error) {
			return m.BatchDelete(keys, nil)
		},
		delete: func(key K) error {
			return m.Delete(key)
		},
	}
}

func updateMap[K comparable, V any](coll *ebpf.Collection, name string, entries map[K]V) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	return updateMapBatch(name, ebpfMapBatchOperations[K, V](m), mapBatchEntries(entries))
}

func deleteEntriesByGeneration[K comparable, V interface{ MapGeneration() uint64 }](
	coll *ebpf.Collection,
	name string,
	generation uint64,
) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	var (
		key     K
		value   V
		entries []mapBatchEntry[K, V]
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if value.MapGeneration() != generation {
			continue
		}
		entries = append(entries, mapBatchEntry[K, V]{key: key, value: value})
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate map %s for generation %d: %w", name, generation, err)
	}
	if err := deleteMapBatch(name, ebpfMapBatchOperations[K, V](m), entries); err != nil {
		return fmt.Errorf("delete generation %d entries from %s: %w", generation, name, err)
	}
	return nil
}

func deleteStaleEntries[K comparable, V any](
	coll *ebpf.Collection,
	name string,
	desired map[K]V,
) error {
	m := coll.Maps[name]
	if m == nil {
		return fmt.Errorf("BPF object missing map %q", name)
	}
	var (
		key     K
		value   V
		entries []mapBatchEntry[K, V]
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if _, ok := desired[key]; ok {
			continue
		}
		entries = append(entries, mapBatchEntry[K, V]{key: key, value: value})
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate map %s for stale entries: %w", name, err)
	}
	if err := deleteMapBatch(name, ebpfMapBatchOperations[K, V](m), entries); err != nil {
		return fmt.Errorf("delete stale entries from %s: %w", name, err)
	}
	return nil
}
