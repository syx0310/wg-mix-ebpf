//go:build linux

package dataplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
)

type fakeTCPChecksumStageMap struct {
	key         uint32
	value       fakeTCPKprobeRuntimeValue
	updated     bool
	updateFlags ebpf.MapUpdateFlags
	lookupErr   error
}

func (m *fakeTCPChecksumStageMap) Lookup(key, valueOut any) error {
	if m.lookupErr != nil {
		return m.lookupErr
	}
	gotKey, ok := key.(uint32)
	if !ok || !m.updated || gotKey != m.key {
		return ebpf.ErrKeyNotExist
	}
	out, ok := valueOut.(*fakeTCPKprobeRuntimeValue)
	if !ok {
		return errors.New("unexpected checksum stage lookup type")
	}
	*out = m.value
	return nil
}

func (m *fakeTCPChecksumStageMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	gotKey, keyOK := key.(uint32)
	gotValue, valueOK := value.(fakeTCPKprobeRuntimeValue)
	if !keyOK || !valueOK {
		return errors.New("unexpected checksum stage update type")
	}
	m.key = gotKey
	m.value = gotValue
	m.updated = true
	m.updateFlags = flags
	return nil
}

func (*fakeTCPChecksumStageMap) Delete(any) error { return nil }
func (*fakeTCPChecksumStageMap) Close() error     { return nil }

func TestFakeTCPKprobeRuntimeValueMatchesFrozenBridgeABI(t *testing.T) {
	var value fakeTCPKprobeRuntimeValue
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "sizeof", got: unsafe.Sizeof(value), want: 16},
		{name: "cookie", got: unsafe.Offsetof(value.Cookie), want: 0},
		{name: "abi", got: unsafe.Offsetof(value.ABIVersion), want: 8},
		{name: "reserved", got: unsafe.Offsetof(value.Reserved), want: 12},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s offset/size=%d, want %d", check.name, check.got, check.want)
		}
	}
}

func TestFakeTCPChecksumStageFactorySeedsAndRetainsExactKprobeMap(t *testing.T) {
	const cookie = uint64(0x1122334455667788)
	selection := fakeTCPKprobeSelectionForStageTest(cookie)
	runtimeMap := &fakeTCPChecksumStageMap{}
	collection := &experimentalCollectionOwner{
		maps: map[string]experimentalMapResource{
			fakeTCPKprobeRuntimeMapName: runtimeMap,
		},
	}
	factory, err := FakeTCPChecksumStageFactory(selection)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := factory(t.Context(), collection)
	if err != nil {
		t.Fatal(err)
	}
	want := fakeTCPKprobeRuntimeValue{Cookie: cookie, ABIVersion: fakeTCPKprobeBridgeABIVersion}
	if !runtimeMap.updated || runtimeMap.key != 0 || runtimeMap.updateFlags != ebpf.UpdateAny ||
		!reflect.DeepEqual(runtimeMap.value, want) {
		t.Fatalf("seed key/value/flags = %d/%#v/%v", runtimeMap.key, runtimeMap.value, runtimeMap.updateFlags)
	}
	if err := owner.Healthy(t.Context()); err != nil {
		t.Fatal(err)
	}
	runtimeMap.value.Reserved = 1
	err = owner.Healthy(t.Context())
	if err == nil || !strings.Contains(err.Error(), "differs from retained") {
		t.Fatalf("corrupt runtime map health error = %v", err)
	}
	if strings.Contains(err.Error(), "112233") || strings.Contains(err.Error(), "1234605616436508552") {
		t.Fatalf("health error leaked cookie: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if selection.RuntimeStatus().LeaseHeld != true {
		t.Fatal("checksum stage Close released outer-owned module lease")
	}
}

func TestFakeTCPChecksumStageFactoryKfuncHasNoMapMutation(t *testing.T) {
	healthCalls := 0
	selection := newFakeTCPChecksumSelection(
		config.FakeTCPChecksumBackendKfunc,
		config.FakeTCPChecksumBackendKfunc,
		FakeTCPObjectVariantModernKfunc,
		DefaultFakeTCPKfuncModule,
		nil,
	)
	selection.health = func(context.Context, uint64) error {
		healthCalls++
		return nil
	}
	factory, err := FakeTCPChecksumStageFactory(selection)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := factory(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Healthy(t.Context()); err != nil {
		t.Fatal(err)
	}
	if healthCalls != 2 {
		t.Fatalf("kfunc health calls=%d, want constructor+retained health", healthCalls)
	}
}

func TestFakeTCPChecksumStageFactoryRejectsMissingLegacyRuntimeMapBeforeAttach(t *testing.T) {
	const cookie = uint64(0x1122334455667788)
	selection := fakeTCPKprobeSelectionForStageTest(cookie)
	factory, err := FakeTCPChecksumStageFactory(selection)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := factory(t.Context(), &experimentalCollectionOwner{
		maps: map[string]experimentalMapResource{},
	})
	wantError := `seed FakeTCP kprobe checksum stage: experimental FakeTCP collection is missing map "` +
		fakeTCPKprobeRuntimeMapName + `"`
	if !experimentalChecksumStageOwnerIsNil(owner) || err == nil || err.Error() != wantError {
		t.Fatalf("owner=%#v error=%v", owner, err)
	}
	if !selection.RuntimeStatus().LeaseHeld {
		t.Fatal("failed pre-attach seed released outer-owned module lease")
	}
}

func TestFakeTCPChecksumStageHealthRejectsClosedOrChangedLeaseWithoutCookieLeak(t *testing.T) {
	const cookie = uint64(0x1122334455667788)
	selection := fakeTCPKprobeSelectionForStageTest(cookie)
	runtimeMap := &fakeTCPChecksumStageMap{}
	collection := &experimentalCollectionOwner{
		maps: map[string]experimentalMapResource{fakeTCPKprobeRuntimeMapName: runtimeMap},
	}
	stage, err := seedFakeTCPKprobeChecksumStage(t.Context(), collection, selection)
	if err != nil {
		t.Fatal(err)
	}
	selection.health = func(context.Context, uint64) error {
		return errors.New("injected held-FD health failure")
	}
	err = stage.Healthy(t.Context())
	if err == nil || !strings.Contains(err.Error(), "held-FD health failure") {
		t.Fatalf("lease health error=%v", err)
	}
	if strings.Contains(err.Error(), "112233") || strings.Contains(err.Error(), "1234605616436508552") {
		t.Fatalf("lease health error leaked cookie: %v", err)
	}
}

func fakeTCPKprobeSelectionForStageTest(cookie uint64) *FakeTCPChecksumSelection {
	selection := newFakeTCPChecksumSelection(
		config.FakeTCPChecksumBackendKprobe,
		config.FakeTCPChecksumBackendKprobe,
		FakeTCPObjectVariantLegacy515,
		DefaultFakeTCPKprobeModule,
		&fakeTCPChecksumTestLease{},
	)
	selection.cookie = cookie
	selection.health = func(context.Context, uint64) error { return nil }
	return selection
}
