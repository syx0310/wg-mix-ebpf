//go:build linux

package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testTCHandoffBinding(
	t *testing.T,
	fixture *durableTCOwnerJournalFixture,
) *durableTCOwnerJournalBinding {
	t.Helper()
	coverage, err := tcOwnerJournalCoverageDigest(fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := tcHandoffWitnessSourceFromMutating(fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	return &durableTCOwnerJournalBinding{
		intent:       clonePinOwnerRecord(fixture.intent),
		resourceKey:  fixture.intent.ResourceKey,
		sequence:     fixture.intent.Sequence,
		coverage:     coverage,
		sourceDigest: digest,
	}
}

func completeTestTCHandoffSource(
	t *testing.T,
	fixture *durableTCOwnerJournalFixture,
	persistWitness bool,
) (*pinOwnerRecord, *durableTCOwnerJournalBinding) {
	t.Helper()
	binding := testTCHandoffBinding(t, fixture)
	if persistWitness {
		digest, err := fixture.store.persistPendingTCHandoffWitness(fixture.intent)
		if err != nil {
			t.Fatal(err)
		}
		if digest != binding.sourceDigest {
			t.Fatal("pending witness returned a different source digest")
		}
	}
	now := time.Date(2026, 8, 8, 2, 1, 0, 0, time.UTC)
	fixture.store.now = func() time.Time { return now }
	cleanup := advancePinOwnerRecord(
		fixture.intent,
		now,
		pinOwnerPhaseApplying,
		pinOwnerStepCleanup,
	)
	if err := fixture.store.Persist(
		cleanup,
		fixture.intent,
		fixture.handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	completed, err := fixture.store.completePendingTCHandoffWitness(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	if completed != persistWitness {
		t.Fatalf("completed witness=%t want=%t", completed, persistWitness)
	}
	active := completeApplyingPinOwnerRecord(cleanup, now.Add(time.Second))
	if err := fixture.store.Persist(
		active,
		cleanup,
		fixture.handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	return active, binding
}

func advanceTestOwnerOneMoreGeneration(
	t *testing.T,
	fixture *durableTCOwnerJournalFixture,
	active *pinOwnerRecord,
) *pinOwnerRecord {
	t.Helper()
	parent := &pinPathParent{
		pinPath:  fixture.handle.pinPath,
		base:     fixture.handle.base,
		mountID:  fixture.handle.mountID,
		resource: fixture.handle.resource,
	}
	token, err := tokenFromOwnerRecord(active)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 2, 2, 0, 0, time.UTC)
	applying, err := newApplyingPinOwnerRecord(
		parent,
		token,
		active.BootID,
		now,
		active.ActiveGeneration,
		active.ActiveGeneration+1,
		active.Maps,
		active.ActiveFilters,
		active.ActiveFilters,
		active,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(
		applying,
		active,
		fixture.handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	mutating := advancePinOwnerRecord(
		applying,
		now.Add(time.Second),
		pinOwnerPhaseApplying,
		pinOwnerStepMutating,
	)
	if err := fixture.store.Persist(
		mutating,
		applying,
		fixture.handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	cleanup := advancePinOwnerRecord(
		mutating,
		now.Add(2*time.Second),
		pinOwnerPhaseApplying,
		pinOwnerStepCleanup,
	)
	if err := fixture.store.Persist(
		cleanup,
		mutating,
		fixture.handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	nextActive := completeApplyingPinOwnerRecord(cleanup, now.Add(3*time.Second))
	if err := fixture.store.Persist(
		nextActive,
		cleanup,
		fixture.handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	return nextActive
}

func TestCompletedTCHandoffWitnessProvesDeepDescendant(t *testing.T) {
	fixture := newDurableTCOwnerJournalFixture(t)
	active, binding := completeTestTCHandoffSource(t, fixture, true)
	deep := advanceTestOwnerOneMoreGeneration(t, fixture, active)
	if deep.ActiveGeneration != fixture.intent.NextGeneration+1 {
		t.Fatalf("deep generation=%d", deep.ActiveGeneration)
	}
	progress, err := classifyDurableTCOwnerJournalProgress(
		binding,
		fixture.handle,
		fixture.store,
	)
	if progress != durableTCOwnerJournalProgressAdvanced || err != nil {
		t.Fatalf("deep descendant progress=%d error=%v", progress, err)
	}
}

func TestTCHandoffWitnessMissingCorruptAndForeignFailClosed(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		active, binding := completeTestTCHandoffSource(t, fixture, false)
		_ = advanceTestOwnerOneMoreGeneration(t, fixture, active)
		progress, err := classifyDurableTCOwnerJournalProgress(
			binding,
			nil,
			fixture.store,
		)
		if progress != durableTCOwnerJournalProgressUnproven ||
			err == nil || !strings.Contains(err.Error(), "witness") {
			t.Fatalf("missing witness progress=%d error=%v", progress, err)
		}
	})

	t.Run("corrupt", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		active, binding := completeTestTCHandoffSource(t, fixture, false)
		_ = advanceTestOwnerOneMoreGeneration(t, fixture, active)
		canonical, _, _, err := tcHandoffWitnessNames(
			fixture.intent.ResourceKey,
			binding.sourceDigest,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(fixture.handle.runtime.ownerRoot, canonical),
			[]byte("not-json\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		progress, classifyErr := classifyDurableTCOwnerJournalProgress(
			binding,
			fixture.handle,
			fixture.store,
		)
		if progress != durableTCOwnerJournalProgressUnproven || classifyErr == nil {
			t.Fatalf("corrupt witness progress=%d error=%v", progress, classifyErr)
		}
	})

	t.Run("foreign source at expected name", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		active, binding := completeTestTCHandoffSource(t, fixture, false)
		_ = advanceTestOwnerOneMoreGeneration(t, fixture, active)
		source, _, err := tcHandoffWitnessSourceFromMutating(fixture.intent)
		if err != nil {
			t.Fatal(err)
		}
		foreign := pendingTCHandoffWitness(source, binding.sourceDigest)
		foreign.Source.Token = strings.Repeat("ab", 32)
		data, err := marshalTCHandoffWitness(foreign)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _, _, err := tcHandoffWitnessNames(
			fixture.intent.ResourceKey,
			binding.sourceDigest,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(fixture.handle.runtime.ownerRoot, canonical),
			data,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		progress, classifyErr := classifyDurableTCOwnerJournalProgress(
			binding,
			fixture.handle,
			fixture.store,
		)
		if progress != durableTCOwnerJournalProgressUnproven || classifyErr == nil {
			t.Fatalf("foreign witness progress=%d error=%v", progress, classifyErr)
		}
	})
}

func TestTCHandoffWitnessDescriptorCrashRecovery(t *testing.T) {
	fixture := newDurableTCOwnerJournalFixture(t)
	source, digest, err := tcHandoffWitnessSourceFromMutating(fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	canonical, draft, next, err := tcHandoffWitnessNames(source.ResourceKey, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(fixture.handle.runtime.ownerRoot, draft),
		[]byte("partial unpublished witness"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.handle.runtime.ownerRoot, draft)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unpublished witness draft still exists: %v", err)
	}
	stage := func(witness *tcHandoffWitness) {
		t.Helper()
		data, err := marshalTCHandoffWitness(witness)
		if err != nil {
			t.Fatal(err)
		}
		file, _, err := stageSyncedDescriptor(
			fixture.store.root,
			draft,
			next,
			data,
			fixture.store.expectedUID,
			fixture.store.descriptorOps,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}

	pending := pendingTCHandoffWitness(source, digest)
	stage(pending)
	if err := fixture.store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		t.Fatal(err)
	}
	file, _, loaded, err := fixture.store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if err != nil || loaded.State != tcHandoffWitnessPending {
		t.Fatalf("recovered pending witness=%#v error=%v", loaded, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	cleanup := advancePinOwnerRecord(
		fixture.intent,
		time.Date(2026, 8, 8, 2, 3, 0, 0, time.UTC),
		pinOwnerPhaseApplying,
		pinOwnerStepCleanup,
	)
	completed, err := completedTCHandoffWitness(
		pending,
		cleanup,
		time.Date(2026, 8, 8, 2, 3, 1, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	stage(completed)
	if err := fixture.store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		t.Fatal(err)
	}
	file, _, loaded, err = fixture.store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if err != nil || loaded.State != tcHandoffWitnessComplete {
		t.Fatalf("recovered completed witness=%#v error=%v", loaded, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash immediately after the exchange: the completed canonical
	// record coexists with the old pending record at .next.
	stage(pending)
	if err := fixture.store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.handle.runtime.ownerRoot, next)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovered witness next descriptor still exists: %v", err)
	}
}

func TestTCHandoffWitnessABACurrentOwnerDoesNotProveCompletion(t *testing.T) {
	fixture := newDurableTCOwnerJournalFixture(t)
	active, binding := completeTestTCHandoffSource(t, fixture, false)
	now := time.Date(2026, 8, 8, 2, 4, 0, 0, time.UTC)
	detaching, err := newDetachingPinOwnerRecord(active, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(
		detaching,
		active,
		fixture.handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{
		pinOwnerStepMutatingTC,
		pinOwnerStepUnlinkingMaps,
		pinOwnerStepCleanupStages,
	} {
		next := advancePinOwnerRecord(detaching, now, pinOwnerPhaseDetaching, step)
		if err := fixture.store.Persist(
			next,
			detaching,
			fixture.handle.mountID,
		); err != nil {
			t.Fatal(err)
		}
		detaching = next
	}
	if err := fixture.store.Remove(detaching); err != nil {
		t.Fatal(err)
	}
	var token [32]byte
	for index := range token {
		token[index] = byte(255 - index)
	}
	parent := &pinPathParent{
		pinPath:  fixture.handle.pinPath,
		base:     fixture.handle.base,
		mountID:  fixture.handle.mountID,
		resource: fixture.handle.resource,
	}
	aba, err := newActivePinOwnerRecord(
		parent,
		token,
		"abcdefab-cdef-abcd-efab-cdefabcdefab",
		now.Add(time.Second),
		fixture.intent.NextGeneration+1,
		active.Maps,
		active.ActiveFilters,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Persist(aba, nil, fixture.handle.mountID); err != nil {
		t.Fatal(err)
	}
	progress, classifyErr := classifyDurableTCOwnerJournalProgress(
		binding,
		fixture.handle,
		fixture.store,
	)
	if progress != durableTCOwnerJournalProgressUnproven || classifyErr == nil {
		t.Fatalf("ABA owner progress=%d error=%v", progress, classifyErr)
	}
}

func TestCompletedTCHandoffWitnessRejectsForeignResourceAndRebootLineage(
	t *testing.T,
) {
	fixture := newDurableTCOwnerJournalFixture(t)
	active, binding := completeTestTCHandoffSource(t, fixture, true)
	_ = advanceTestOwnerOneMoreGeneration(t, fixture, active)

	t.Run("foreign resource", func(t *testing.T) {
		foreignStore := *fixture.store
		foreignStore.resource.key = strings.Repeat("f", 64)
		foreignStore.resource.parentInode++
		progress, err := classifyDurableTCOwnerJournalProgress(
			binding,
			fixture.handle,
			&foreignStore,
		)
		if progress != durableTCOwnerJournalProgressUnproven || err == nil {
			t.Fatalf("foreign resource progress=%d error=%v", progress, err)
		}
	})

	t.Run("foreign reboot lineage", func(t *testing.T) {
		foreignBinding := *binding
		foreignBinding.intent = clonePinOwnerRecord(binding.intent)
		foreignBinding.intent.BootID = "abcdefab-cdef-abcd-efab-cdefabcdefab"
		progress, err := classifyDurableTCOwnerJournalProgress(
			&foreignBinding,
			fixture.handle,
			fixture.store,
		)
		if progress != durableTCOwnerJournalProgressUnproven || err == nil {
			t.Fatalf("foreign reboot progress=%d error=%v", progress, err)
		}
	})
}
