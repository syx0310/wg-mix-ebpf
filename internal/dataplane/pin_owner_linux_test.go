//go:build linux

package dataplane

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
)

func testPinOwnerRecord(
	t *testing.T,
	root string,
) (pinPathRuntime, *pinPathParent, *pinOwnerRecord) {
	t.Helper()
	pinPath := filepath.Join(root, "bpffs", "wg-mix-ebpf-owner-test")
	base := filepath.Base(pinPath)
	const (
		parentDevice = 42
		parentInode  = 99
		mountID      = 101
	)
	key, err := pinidentity.Key(parentDevice, parentInode, base)
	if err != nil {
		t.Fatal(err)
	}
	resource := pinResourceIdentity{
		key:          key,
		parentDevice: parentDevice,
		parentInode:  parentInode,
		base:         base,
		pinPath:      pinPath,
	}
	parent := &pinPathParent{
		pinPath:  pinPath,
		base:     base,
		mountID:  mountID,
		resource: resource,
	}
	maps := make([]pinOwnerMapIdentity, 0, len(pinnedMapDescriptors()))
	for index, descriptor := range pinnedMapDescriptors() {
		maps = append(maps, pinOwnerMapIdentity{
			Name: descriptor.name,
			ID:   uint32(index + 1),
		})
	}
	var token [32]byte
	for index := range token {
		token[index] = byte(index + 1)
	}
	record, err := newActivePinOwnerRecord(
		parent,
		token,
		"12345678-1234-1234-1234-123456789abc",
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		7,
		maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime := pinPathRuntime{
		ownerRoot:            filepath.Join(root, "pin-owners"),
		expectedUID:          uint32(os.Getuid()),
		allowUnsafeAncestors: true,
	}
	parent.runtime = runtime
	return runtime, parent, record
}

func TestPinOwnerJSONFieldOrderAndCanonicalUTC(t *testing.T) {
	_, parent, record := testPinOwnerRecord(t, t.TempDir())
	data, err := marshalPinOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{
		`"version":`,
		`"sequence":`,
		`"resource_key":`,
		`"parent_device":`,
		`"parent_inode":`,
		`"pin_basename":`,
		`"pin_path":`,
		`"bpffs_root_path":`,
		`"bpffs_mount_ids":`,
		`"boot_id":`,
		`"token":`,
		`"created_at":`,
		`"updated_at":`,
		`"phase":`,
		`"step":`,
		`"active_generation":`,
		`"next_generation":`,
		`"maps":`,
		`"active_filters":`,
		`"desired_filters":`,
		`"program_stages":`,
		`"map_stages":`,
		`"retired_from_resource_key":`,
	}
	position := -1
	for _, key := range keys {
		next := bytes.Index(data, []byte(key))
		if next <= position {
			t.Fatalf("owner JSON field %s is out of order: %s", key, data)
		}
		position = next
	}
	nonUTC := clonePinOwnerRecord(record)
	nonUTC.UpdatedAt = "2026-07-29T09:02:03.000000004+08:00"
	if err := validatePinOwnerRecord(
		nonUTC,
		parent.resource,
		parent.mountID,
	); err == nil || !strings.Contains(err.Error(), "canonical RFC3339Nano UTC") {
		t.Fatalf("non-UTC owner timestamp error = %v", err)
	}
}

func TestPinOwnerDescriptorRecoveryPublishesOnlyNextSequence(t *testing.T) {
	runtime, parent, record := testPinOwnerRecord(t, t.TempDir())
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	next := clonePinOwnerRecord(record)
	next.Sequence++
	next.UpdatedAt = time.Date(
		2026, 7, 29, 1, 2, 4, 0, time.UTC,
	).Format(time.RFC3339Nano)
	data, err := marshalPinOwnerRecord(next)
	if err != nil {
		t.Fatal(err)
	}
	nextFile, identity, err := createAnchoredRegularFileExclusive(
		store.root,
		store.nextName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAndSyncAnchoredFile(
		store.root,
		store.nextName,
		nextFile,
		identity,
		data,
		store.expectedUID,
	); err != nil {
		t.Fatal(err)
	}
	if err := nextFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	recoveredStore, err := openPinOwnerStore(runtime, parent.resource, false)
	if err != nil {
		t.Fatal(err)
	}
	defer recoveredStore.Close()
	recovered, err := recoveredStore.Load(parent.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Sequence != next.Sequence ||
		recovered.UpdatedAt != next.UpdatedAt {
		t.Fatalf("recovered owner = %#v, want sequence %d", recovered, next.Sequence)
	}
}

func TestPinOwnerExchangeRejectsTargetSwap(t *testing.T) {
	runtime, parent, record := testPinOwnerRecord(t, t.TempDir())
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	next := clonePinOwnerRecord(record)
	next.Sequence++
	next.UpdatedAt = time.Date(
		2026, 7, 29, 1, 2, 4, 0, time.UTC,
	).Format(time.RFC3339Nano)
	store.beforeOwnerExchange = func() {
		target := filepath.Join(runtime.ownerRoot, store.fileName)
		if err := os.Rename(target, target+".swapped"); err != nil {
			t.Errorf("swap owner target: %v", err)
			return
		}
		if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
			t.Errorf("replace owner target: %v", err)
		}
	}
	err = store.Persist(next, record, parent.mountID)
	if err == nil || !strings.Contains(err.Error(), "changed at exchange hook") {
		t.Fatalf("owner target swap error = %v", err)
	}
}
