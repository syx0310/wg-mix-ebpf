//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testTCHandoffHolderID = "0101010101010101010101010101010101010101010101010101010101010101"

const testTCHandoffSecondHolderID = "0202020202020202020202020202020202020202020202020202020202020202"

func loadTestTCHandoffWitness(
	t *testing.T,
	store *pinOwnerStore,
	source tcHandoffWitnessSource,
	digest [32]byte,
) *tcHandoffWitness {
	t.Helper()
	canonical, _, _, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	file, _, witness, err := store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return witness
}

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
		holderID:     testTCHandoffHolderID,
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
		digest, err := fixture.store.persistPendingTCHandoffWitness(
			fixture.intent,
			binding.holderID,
		)
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

func TestTCHandoffCompletionClockRollbackLeavesPendingCanonicalUntouched(
	t *testing.T,
) {
	fixture := newDurableTCOwnerJournalFixture(t)
	binding := testTCHandoffBinding(t, fixture)
	source, digest, err := tcHandoffWitnessSourceFromMutating(fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.persistPendingTCHandoffWitness(
		fixture.intent,
		binding.holderID,
	); err != nil {
		t.Fatal(err)
	}
	canonical, draft, next, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPath := filepath.Join(fixture.handle.runtime.ownerRoot, canonical)
	before, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	draftPath := filepath.Join(fixture.handle.runtime.ownerRoot, draft)
	draftBefore := []byte("partial pre-completion draft")
	if err := os.WriteFile(draftPath, draftBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, fixture.intent.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAt := createdAt.Add(time.Hour)
	cleanup := advancePinOwnerRecord(
		fixture.intent,
		cleanupAt,
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
	createCalls := 0
	writeCalls := 0
	syncFileCalls := 0
	renameCalls := 0
	syncDirCalls := 0
	unlinkCalls := 0
	liveCreate := fixture.store.descriptorOps.create
	liveWrite := fixture.store.descriptorOps.write
	liveSyncFile := fixture.store.descriptorOps.syncFile
	liveRename := fixture.store.descriptorOps.rename
	liveSyncDir := fixture.store.descriptorOps.syncDir
	liveUnlink := fixture.store.descriptorOps.unlink
	fixture.store.descriptorOps.create = func(
		root *anchoredDirectoryPath,
		name string,
		mode uint32,
		expectedUID uint32,
	) (*os.File, pinPathInodeIdentity, error) {
		createCalls++
		return liveCreate(root, name, mode, expectedUID)
	}
	fixture.store.descriptorOps.write = func(file *os.File, data []byte) (int, error) {
		writeCalls++
		return liveWrite(file, data)
	}
	fixture.store.descriptorOps.syncFile = func(file *os.File) error {
		syncFileCalls++
		return liveSyncFile(file)
	}
	fixture.store.descriptorOps.rename = func(
		root *anchoredDirectoryPath,
		oldName string,
		newName string,
		flags uint,
	) error {
		renameCalls++
		return liveRename(root, oldName, newName, flags)
	}
	fixture.store.descriptorOps.syncDir = func(root *anchoredDirectoryPath) error {
		syncDirCalls++
		return liveSyncDir(root)
	}
	fixture.store.descriptorOps.unlink = func(
		root *anchoredDirectoryPath,
		name string,
		fd int,
		identity pinPathInodeIdentity,
		expectedUID uint32,
	) error {
		unlinkCalls++
		return liveUnlink(root, name, fd, identity, expectedUID)
	}
	fixture.store.now = func() time.Time { return createdAt.Add(-time.Second) }
	completed, completeErr := fixture.store.completePendingTCHandoffWitness(cleanup)
	if completed || completeErr == nil || !strings.Contains(completeErr.Error(), "clock") {
		t.Fatalf("rollback completion=%t error=%v", completed, completeErr)
	}
	after, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("clock rollback changed the pending canonical witness")
	}
	if createCalls != 0 || writeCalls != 0 || syncFileCalls != 0 ||
		renameCalls != 0 || syncDirCalls != 0 || unlinkCalls != 0 {
		t.Fatalf(
			"clock rollback performed descriptor writes create=%d write=%d sync-file=%d rename=%d sync-dir=%d unlink=%d",
			createCalls,
			writeCalls,
			syncFileCalls,
			renameCalls,
			syncDirCalls,
			unlinkCalls,
		)
	}
	draftAfter, err := os.ReadFile(draftPath)
	if err != nil || string(draftAfter) != string(draftBefore) {
		t.Fatalf("clock rollback changed unpublished draft bytes=%q error=%v", draftAfter, err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.handle.runtime.ownerRoot, next)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clock rollback published %s: %v", next, err)
	}
	if witness := loadTestTCHandoffWitness(t, fixture.store, source, digest); witness.State != tcHandoffWitnessPending || witness.Revision != 1 {
		t.Fatalf("rollback witness=%#v", witness)
	}

	fixture.store.now = func() time.Time { return cleanupAt.Add(time.Second) }
	completed, err = fixture.store.completePendingTCHandoffWitness(cleanup)
	if err != nil || !completed {
		t.Fatalf("restored-clock completion=%t error=%v", completed, err)
	}
	if witness := loadTestTCHandoffWitness(t, fixture.store, source, digest); witness.State != tcHandoffWitnessComplete || witness.Revision != 2 {
		t.Fatalf("restored-clock witness=%#v", witness)
	}
}

func TestTCHandoffWitnessHoldersReleaseOnlyTheirExactReference(t *testing.T) {
	fixture := newDurableTCOwnerJournalFixture(t)
	source, digest, err := tcHandoffWitnessSourceFromMutating(fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	for _, holderID := range []string{
		testTCHandoffHolderID,
		testTCHandoffSecondHolderID,
	} {
		if _, err := fixture.store.persistPendingTCHandoffWitness(
			fixture.intent,
			holderID,
		); err != nil {
			t.Fatal(err)
		}
	}
	witness := loadTestTCHandoffWitness(t, fixture.store, source, digest)
	if witness.Revision != 2 || len(witness.Holders) != 2 {
		t.Fatalf("registered holders witness=%#v", witness)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, fixture.intent.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	completionAt := createdAt.Add(time.Hour)
	cleanup := advancePinOwnerRecord(
		fixture.intent,
		completionAt,
		pinOwnerPhaseApplying,
		pinOwnerStepCleanup,
	)
	fixture.store.now = func() time.Time { return completionAt.Add(time.Second) }
	if completed, err := fixture.store.completePendingTCHandoffWitness(cleanup); err != nil || !completed {
		t.Fatalf("complete two-holder witness=%t error=%v", completed, err)
	}
	if err := fixture.store.releaseTCHandoffWitnessHolder(
		fixture.intent,
		digest,
		testTCHandoffHolderID,
	); err != nil {
		t.Fatal(err)
	}
	witness = loadTestTCHandoffWitness(t, fixture.store, source, digest)
	if witness.Revision != 4 || len(witness.Holders) != 1 ||
		witness.Holders[0].ID != testTCHandoffSecondHolderID {
		t.Fatalf("one-holder witness=%#v", witness)
	}
	if completed, err := fixture.store.loadCompletedTCHandoffWitness(
		fixture.intent,
		digest,
		testTCHandoffHolderID,
	); completed || err == nil || !strings.Contains(err.Error(), "exact stage holder") {
		t.Fatalf("released holder proof=%t error=%v", completed, err)
	}
	if completed, err := fixture.store.loadCompletedTCHandoffWitness(
		fixture.intent,
		digest,
		testTCHandoffSecondHolderID,
	); !completed || err != nil {
		t.Fatalf("remaining holder proof=%t error=%v", completed, err)
	}
	if err := fixture.store.releaseTCHandoffWitnessHolder(
		fixture.intent,
		digest,
		testTCHandoffHolderID,
	); err != nil {
		t.Fatalf("idempotent holder release: %v", err)
	}

	canonical, _, _, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantUnlink := errors.New("injected exact witness unlink failure")
	liveUnlink := fixture.store.descriptorOps.unlink
	fixture.store.descriptorOps.unlink = func(
		root *anchoredDirectoryPath,
		name string,
		fd int,
		identity pinPathInodeIdentity,
		expectedUID uint32,
	) error {
		if name == canonical {
			return wantUnlink
		}
		return liveUnlink(root, name, fd, identity, expectedUID)
	}
	if err := fixture.store.releaseTCHandoffWitnessHolder(
		fixture.intent,
		digest,
		testTCHandoffSecondHolderID,
	); !errors.Is(err, wantUnlink) {
		t.Fatalf("injected last-holder unlink error=%v", err)
	}
	witness = loadTestTCHandoffWitness(t, fixture.store, source, digest)
	if len(witness.Holders) != 1 || witness.Holders[0].ID != testTCHandoffSecondHolderID {
		t.Fatalf("failed unlink changed witness=%#v", witness)
	}
	fixture.store.descriptorOps.unlink = liveUnlink
	if err := fixture.store.releaseTCHandoffWitnessHolder(
		fixture.intent,
		digest,
		testTCHandoffSecondHolderID,
	); err != nil {
		t.Fatalf("retry last-holder release: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.handle.runtime.ownerRoot, canonical)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("last-holder witness remains: %v", err)
	}
}

func writeTestTCHandoffWitness(
	t *testing.T,
	root string,
	name string,
	witness *tcHandoffWitness,
) {
	t.Helper()
	data, err := marshalTCHandoffWitness(witness)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPriorBootTCHandoffWitnessCleanupIsExactAndBounded(t *testing.T) {
	const oldBootID = "abcdefab-cdef-abcd-efab-cdefabcdefab"

	t.Run("valid old boot only", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		currentSource, currentDigest, err := tcHandoffWitnessSourceFromMutating(
			fixture.intent,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.persistPendingTCHandoffWitness(
			fixture.intent,
			testTCHandoffHolderID,
		); err != nil {
			t.Fatal(err)
		}
		currentCanonical, _, _, err := tcHandoffWitnessNames(
			currentSource.ResourceKey,
			currentSource.BootID,
			currentDigest,
		)
		if err != nil {
			t.Fatal(err)
		}

		oldRecord := clonePinOwnerRecord(fixture.intent)
		oldRecord.BootID = oldBootID
		oldSource, oldDigest, err := tcHandoffWitnessSourceFromMutating(oldRecord)
		if err != nil {
			t.Fatal(err)
		}
		oldCanonical, oldDraft, oldNext, err := tcHandoffWitnessNames(
			oldSource.ResourceKey,
			oldSource.BootID,
			oldDigest,
		)
		if err != nil {
			t.Fatal(err)
		}
		oldWitness := pendingTCHandoffWitness(
			oldSource,
			oldDigest,
			testTCHandoffSecondHolderID,
		)
		writeTestTCHandoffWitness(
			t,
			fixture.handle.runtime.ownerRoot,
			oldCanonical,
			oldWitness,
		)
		writeTestTCHandoffWitness(
			t,
			fixture.handle.runtime.ownerRoot,
			oldNext,
			oldWitness,
		)
		if err := os.WriteFile(
			filepath.Join(fixture.handle.runtime.ownerRoot, oldDraft),
			[]byte("partial old-boot draft"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		unrelated := filepath.Join(fixture.handle.runtime.ownerRoot, "unrelated.keep")
		if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := fixture.store.cleanupPriorBootTCHandoffWitnesses(
			fixture.intent.BootID,
		); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{oldCanonical, oldDraft, oldNext} {
			if _, err := os.Lstat(filepath.Join(fixture.handle.runtime.ownerRoot, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("old-boot descriptor %s remains: %v", name, err)
			}
		}
		for _, path := range []string{
			filepath.Join(fixture.handle.runtime.ownerRoot, currentCanonical),
			unrelated,
		} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("cleanup removed retained path %s: %v", path, err)
			}
		}
	})

	t.Run("foreign content blocks every unlink", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		oldRecord := clonePinOwnerRecord(fixture.intent)
		oldRecord.BootID = oldBootID
		oldSource, oldDigest, err := tcHandoffWitnessSourceFromMutating(oldRecord)
		if err != nil {
			t.Fatal(err)
		}
		oldCanonical, _, oldNext, err := tcHandoffWitnessNames(
			oldSource.ResourceKey,
			oldSource.BootID,
			oldDigest,
		)
		if err != nil {
			t.Fatal(err)
		}
		writeTestTCHandoffWitness(
			t,
			fixture.handle.runtime.ownerRoot,
			oldCanonical,
			pendingTCHandoffWitness(
				oldSource,
				oldDigest,
				testTCHandoffHolderID,
			),
		)
		if err := os.WriteFile(
			filepath.Join(fixture.handle.runtime.ownerRoot, oldNext),
			[]byte("foreign\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.cleanupPriorBootTCHandoffWitnesses(
			fixture.intent.BootID,
		); err == nil {
			t.Fatal("foreign old-boot descriptor allowed cleanup")
		}
		for _, name := range []string{oldCanonical, oldNext} {
			if _, err := os.Lstat(filepath.Join(fixture.handle.runtime.ownerRoot, name)); err != nil {
				t.Fatalf("fail-closed cleanup removed %s: %v", name, err)
			}
		}
	})

	t.Run("scan limit blocks every unlink", func(t *testing.T) {
		fixture := newDurableTCOwnerJournalFixture(t)
		oldRecord := clonePinOwnerRecord(fixture.intent)
		oldRecord.BootID = oldBootID
		oldSource, oldDigest, err := tcHandoffWitnessSourceFromMutating(oldRecord)
		if err != nil {
			t.Fatal(err)
		}
		oldCanonical, _, _, err := tcHandoffWitnessNames(
			oldSource.ResourceKey,
			oldSource.BootID,
			oldDigest,
		)
		if err != nil {
			t.Fatal(err)
		}
		writeTestTCHandoffWitness(
			t,
			fixture.handle.runtime.ownerRoot,
			oldCanonical,
			pendingTCHandoffWitness(
				oldSource,
				oldDigest,
				testTCHandoffHolderID,
			),
		)
		for index := 0; index < tcHandoffWitnessMaxScan; index++ {
			name := filepath.Join(
				fixture.handle.runtime.ownerRoot,
				fmt.Sprintf("scan-bound-%04d", index),
			)
			if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := fixture.store.cleanupPriorBootTCHandoffWitnesses(
			fixture.intent.BootID,
		); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("unbounded cleanup error=%v", err)
		}
		if _, err := os.Lstat(
			filepath.Join(fixture.handle.runtime.ownerRoot, oldCanonical),
		); err != nil {
			t.Fatalf("bounded cleanup removed old witness: %v", err)
		}
	})
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
			fixture.intent.BootID,
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
		foreign := pendingTCHandoffWitness(
			source,
			binding.sourceDigest,
			binding.holderID,
		)
		foreign.Source.Token = strings.Repeat("ab", 32)
		data, err := marshalTCHandoffWitness(foreign)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _, _, err := tcHandoffWitnessNames(
			fixture.intent.ResourceKey,
			fixture.intent.BootID,
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
	canonical, draft, next, err := tcHandoffWitnessNames(
		source.ResourceKey,
		source.BootID,
		digest,
	)
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

	pending := pendingTCHandoffWitness(source, digest, testTCHandoffHolderID)
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
	withSecondHolder, changed, err := addTCHandoffWitnessHolder(
		pending,
		testTCHandoffSecondHolderID,
	)
	if err != nil || !changed {
		t.Fatalf("add crash-recovery holder changed=%t error=%v", changed, err)
	}
	stage(withSecondHolder)
	if err := fixture.store.recoverTCHandoffWitnessDescriptor(source, digest); err != nil {
		t.Fatal(err)
	}
	file, _, loaded, err = fixture.store.loadTCHandoffWitnessFile(
		canonical,
		source,
		digest,
	)
	if err != nil || loaded.Revision != 2 || len(loaded.Holders) != 2 {
		t.Fatalf("recovered holder update witness=%#v error=%v", loaded, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	pending = withSecondHolder

	cleanup := advancePinOwnerRecord(
		fixture.intent,
		time.Date(2026, 8, 8, 2, 3, 0, 0, time.UTC),
		pinOwnerPhaseApplying,
		pinOwnerStepCleanup,
	)
	completed, err := completedTCHandoffWitness(
		pending,
		cleanup,
		source,
		digest,
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
