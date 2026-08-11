//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/syx0310/wg-mix-ebpf/internal/pinidentity"
	"golang.org/x/sys/unix"
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
		`"active_links":`,
		`"desired_links":`,
		`"program_stages":`,
		`"map_stages":`,
		`"retired_from_resource_key":`,
		`"retired_from_boot_id":`,
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

func TestOpenPinOwnerStoreCreatesMissingManagedParent(t *testing.T) {
	root := t.TempDir()
	runtime, parent, _ := testPinOwnerRecord(t, root)
	runtime.ownerRoot = filepath.Join(root, "state", "pin-owners")
	parent.runtime = runtime

	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for path, wantMode := range map[string]os.FileMode{
		filepath.Dir(runtime.ownerRoot): 0o755,
		runtime.ownerRoot:               0o700,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != wantMode {
			t.Fatalf("managed owner directory %s mode = %v, want directory %v", path, info.Mode(), wantMode)
		}
	}
}

func TestPinOwnerV3ClassicSchemaIsDecodedAndValidated(t *testing.T) {
	_, parent, current := testPinOwnerRecord(t, t.TempDir())
	legacy := clonePinOwnerRecord(current)
	legacy.Version = pinOwnerLegacyClassicVersion
	legacy.ActiveLinks = nil
	legacy.DesiredLinks = nil
	legacy.ActiveFilters = []tcFilterBinding{
		{
			IfIndex:   11,
			Direction: "ingress",
			Parent:    0xfffffff2,
			Handle:    0x10001,
			Priority:  49152,
			ProgramID: 77,
		},
	}
	normalizePinOwnerRecord(legacy)
	data, err := marshalPinOwnerRecord(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy-v3-owner.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoded, err := readPinOwnerRecord(file)
	if err != nil {
		t.Fatalf("v3 schema must remain decodable for an explicit compatibility error: %v", err)
	}
	if err := validatePinOwnerRecord(decoded, parent.resource, parent.mountID); err != nil {
		t.Fatalf("classic v3 validation error = %v", err)
	}
	withLink := clonePinOwnerRecord(decoded)
	withLink.ActiveLinks = []exactTCXBinding{testExactTCXBinding(11, exactTCXIngress, 77)}
	withLink.ActiveLinks[0].LinkID = 99
	if err := validatePinOwnerRecord(withLink, parent.resource, parent.mountID); err == nil ||
		!strings.Contains(err.Error(), "must not contain TCX links") {
		t.Fatalf("classic v3 accepted a TCX link: %v", err)
	}
	withClassicFilter := clonePinOwnerRecord(current)
	withClassicFilter.ActiveFilters = slices.Clone(decoded.ActiveFilters)
	if err := validatePinOwnerRecord(withClassicFilter, parent.resource, parent.mountID); err == nil ||
		!strings.Contains(err.Error(), "must not contain classic TC filters") {
		t.Fatalf("TCX v4 accepted a classic filter: %v", err)
	}
}

func TestHistoricalPinOwnerV3WireAndIndexDigestRemainStable(t *testing.T) {
	const historical = "{\"version\":3,\"sequence\":7,\"resource_key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"parent_device\":1,\"parent_inode\":2,\"pin_basename\":\"wg-mix-ebpf\",\"pin_path\":\"/sys/fs/bpf/wg-mix-ebpf\",\"bpffs_root_path\":\"/sys/fs/bpf\",\"bpffs_mount_ids\":[101],\"boot_id\":\"12345678-1234-1234-1234-123456789abc\",\"token\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"created_at\":\"2026-01-02T03:04:05Z\",\"updated_at\":\"2026-01-02T03:04:06Z\",\"phase\":\"active\",\"step\":\"ready\",\"active_generation\":1,\"next_generation\":0,\"maps\":[],\"active_filters\":[],\"desired_filters\":[],\"program_stages\":[],\"map_stages\":[],\"retired_from_resource_key\":\"\",\"retired_from_boot_id\":\"\"}\n"
	const historicalDigest = "fa07f5169d4d5001afe832330247a2792192ab5397e5901dbe1042ae6d551896"

	path := filepath.Join(t.TempDir(), "historical-v3.owner.json")
	if err := os.WriteFile(path, []byte(historical), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := readPinOwnerRecord(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read historical v3 owner: %v / close: %v", err, closeErr)
	}
	remarshaled, err := marshalPinOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remarshaled, []byte(historical)) {
		t.Fatalf("historical v3 owner wire drifted:\n got %s\nwant %s", remarshaled, historical)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(remarshaled))
	if sum != historicalDigest {
		t.Fatalf("historical v3 digest = %s, want %s", sum, historicalDigest)
	}
	entry := pinOwnerIndexEntry{
		ResourceKey:    record.ResourceKey,
		ParentDevice:   record.ParentDevice,
		ParentInode:    record.ParentInode,
		PinBaseName:    record.PinBaseName,
		BPFFSRootPath:  record.BPFFSRootPath,
		BPFFSMountIDs:  slices.Clone(record.BPFFSMountIDs),
		BootID:         record.BootID,
		RecordFileName: record.ResourceKey + ".owner.json",
		OwnerDigest:    historicalDigest,
		Status:         pinOwnerIndexActive,
	}
	index := &pinOwnerIndex{
		Version: pinOwnerIndexVersion,
		Active:  []pinOwnerIndexActivePointer{activePointerFromEntry(entry)},
		Entries: []pinOwnerIndexEntry{entry},
	}
	if _, err := activeIndexedOwnerForRecordInIndex(index, record); err != nil {
		t.Fatalf("historical v3 owner no longer matches its durable index: %v", err)
	}
}

func TestPinOwnerQuarantineNamesAreSchemaAware(t *testing.T) {
	classic := &pinOwnerRecord{Version: pinOwnerLegacyClassicVersion}
	classicNames := []string{
		ownerProgramRetiredName(classic, "program-stage"),
		ownerMapRetiredName(classic, "map-stage"),
		ownerCanonicalMapRetiredName(classic, "map-stage"),
	}
	if want := []string{
		"program-stage-retired",
		"map-stage-retired",
		"map-stage-canonical-retired",
	}; !slices.Equal(classicNames, want) {
		t.Fatalf("classic quarantine names = %v, want %v", classicNames, want)
	}
	for _, name := range classicNames {
		if strings.Contains(name, ".") {
			t.Fatalf("classic bpffs quarantine name contains a dot: %q", name)
		}
	}

	tcx := &pinOwnerRecord{Version: pinOwnerRecordVersion}
	tcxNames := []string{
		ownerProgramRetiredName(tcx, "program-stage"),
		ownerMapRetiredName(tcx, "map-stage"),
		ownerCanonicalMapRetiredName(tcx, "map-stage"),
	}
	if want := []string{
		"program-stage.retired",
		"map-stage.retired",
		"map-stage.canonical-retired",
	}; !slices.Equal(tcxNames, want) {
		t.Fatalf("TCX quarantine names = %v, want %v", tcxNames, want)
	}
}

func TestOwnerRecoveryEntrypointsRejectTheOtherBackend(t *testing.T) {
	_, _, tcx := testPinOwnerRecord(t, t.TempDir())
	classic := clonePinOwnerRecord(tcx)
	classic.Version = pinOwnerLegacyClassicVersion
	if _, err := recoverPinOwnerTransaction(
		&pinPathHandle{},
		&pinOwnerStore{},
		tcx,
		tcRuntime{},
	); err == nil || !strings.Contains(err.Error(), "requires schema 3") {
		t.Fatalf("classic recovery accepted TCX owner: %v", err)
	}
	if _, err := recoverExactPinOwnerTransaction(
		context.Background(),
		&pinPathHandle{},
		&pinOwnerStore{},
		classic,
		exactTCXRuntime{},
	); err == nil || !strings.Contains(err.Error(), "requires schema 4") {
		t.Fatalf("TCX recovery accepted classic owner: %v", err)
	}
}

func TestClassicPinOwnerApplyAndDetachTransitions(t *testing.T) {
	_, parent, base := testPinOwnerRecord(t, t.TempDir())
	token := mustPinOwnerToken(t, base)
	activeFilters := []tcFilterBinding{
		{
			IfIndex: 11, Direction: "ingress", Parent: canonicalTCFilterSlots()[0].parent,
			Handle: ingressHandle, Priority: filterPriority, ProgramID: 701,
		},
		{
			IfIndex: 11, Direction: "egress", Parent: canonicalTCFilterSlots()[1].parent,
			Handle: egressHandle, Priority: filterPriority, ProgramID: 702,
		},
	}
	active, err := newClassicActivePinOwnerRecord(
		parent,
		token,
		base.BootID,
		time.Date(2026, 8, 11, 1, 2, 3, 0, time.UTC),
		base.ActiveGeneration,
		base.Maps,
		activeFilters,
	)
	if err != nil {
		t.Fatal(err)
	}
	if active.Version != pinOwnerLegacyClassicVersion ||
		!slices.Equal(active.ActiveFilters, activeFilters) ||
		len(active.ActiveLinks) != 0 {
		t.Fatalf("classic active owner = %#v", active)
	}

	desiredFilters := slices.Clone(activeFilters)
	desiredFilters[0].ProgramID = 801
	desiredFilters[1].ProgramID = 802
	applying, err := newClassicApplyingPinOwnerRecord(
		parent,
		token,
		active.BootID,
		time.Date(2026, 8, 11, 1, 2, 4, 0, time.UTC),
		active.ActiveGeneration,
		active.ActiveGeneration+1,
		active.Maps,
		active.ActiveFilters,
		desiredFilters,
		active,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(applying.ProgramStages) != 4 {
		t.Fatalf("classic applying program stages = %d, want 4", len(applying.ProgramStages))
	}
	completed := completeApplyingPinOwnerRecord(
		applying,
		time.Date(2026, 8, 11, 1, 2, 5, 0, time.UTC),
	)
	if err := validatePinOwnerRecord(completed, parent.resource, parent.mountID); err != nil {
		t.Fatalf("validate completed classic owner: %v", err)
	}
	if !slices.Equal(completed.ActiveFilters, desiredFilters) ||
		len(completed.DesiredFilters) != 0 ||
		len(completed.ProgramStages) != 0 ||
		completed.ActiveGeneration != applying.NextGeneration {
		t.Fatalf("completed classic owner = %#v", completed)
	}

	detaching, err := newDetachingPinOwnerRecord(
		completed,
		time.Date(2026, 8, 11, 1, 2, 6, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(detaching.ProgramStages) != 2 ||
		len(detaching.MapStages) != len(pinnedMapDescriptors()) {
		t.Fatalf(
			"classic detach stages = programs:%d maps:%d",
			len(detaching.ProgramStages), len(detaching.MapStages),
		)
	}
	if err := validatePinOwnerRecord(detaching, parent.resource, parent.mountID); err != nil {
		t.Fatalf("validate classic detach: %v", err)
	}
}

func TestClassicPinOwnerAbortPreservesActiveFilters(t *testing.T) {
	_, parent, base := testPinOwnerRecord(t, t.TempDir())
	token := mustPinOwnerToken(t, base)
	activeFilters := []tcFilterBinding{{
		IfIndex: 19, Direction: "ingress", Parent: canonicalTCFilterSlots()[0].parent,
		Handle: ingressHandle, Priority: filterPriority, ProgramID: 901,
	}}
	active, err := newClassicActivePinOwnerRecord(
		parent, token, base.BootID, time.Now().UTC(), 7, base.Maps, activeFilters,
	)
	if err != nil {
		t.Fatal(err)
	}
	desired := slices.Clone(activeFilters)
	desired[0].ProgramID = 902
	applying, err := newClassicApplyingPinOwnerRecord(
		parent, token, active.BootID, time.Now().UTC(), 7, 8,
		active.Maps, active.ActiveFilters, desired, active,
	)
	if err != nil {
		t.Fatal(err)
	}
	aborted, err := abortApplyingPinOwnerRecord(applying, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(aborted.ActiveFilters, activeFilters) ||
		len(aborted.DesiredFilters) != 0 ||
		len(aborted.ProgramStages) != 0 ||
		aborted.ActiveGeneration != active.ActiveGeneration {
		t.Fatalf("aborted classic owner = %#v", aborted)
	}
}

func TestPinOwnerV4ExactLinkIdentityAndTransitionValidation(t *testing.T) {
	_, parent, base := testPinOwnerRecord(t, t.TempDir())
	active := testExactTCXBinding(31, exactTCXIngress, 801)
	active.LinkID = 901
	record, err := newActivePinOwnerRecord(
		parent,
		mustPinOwnerToken(t, base),
		base.BootID,
		time.Date(2026, 7, 29, 1, 2, 4, 0, time.UTC),
		base.ActiveGeneration,
		base.Maps,
		[]exactTCXBinding{active},
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.Version != pinOwnerRecordVersion || len(record.ActiveLinks) != 1 {
		t.Fatalf("v4 exact owner = %#v", record)
	}

	badAttach := clonePinOwnerRecord(record)
	badAttach.ActiveLinks[0].AttachType++
	if err := validatePinOwnerRecord(badAttach, parent.resource, parent.mountID); err == nil {
		t.Fatal("owner accepted a direction/attach-type mismatch")
	}

	desired := active
	desired.ProgramID++
	applying, err := newApplyingPinOwnerRecord(
		parent,
		mustPinOwnerToken(t, record),
		record.BootID,
		time.Date(2026, 7, 29, 1, 2, 5, 0, time.UTC),
		record.ActiveGeneration,
		record.ActiveGeneration+1,
		record.Maps,
		record.ActiveLinks,
		[]exactTCXBinding{desired},
		record,
	)
	if err != nil {
		t.Fatal(err)
	}
	changedID := clonePinOwnerRecord(applying)
	changedID.DesiredLinks[0].LinkID++
	if err := validatePinOwnerRecord(changedID, parent.resource, parent.mountID); err == nil ||
		!strings.Contains(err.Error(), "changes link ID") {
		t.Fatalf("same-slot link-ID change error = %v", err)
	}
	replacing := clonePinOwnerRecord(applying)
	replacing.DesiredLinks[0].LinkID = 0
	replacing.DesiredLinks[0].ReplacesLinkID = active.LinkID
	if err := validatePinOwnerRecord(replacing, parent.resource, parent.mountID); err != nil {
		t.Fatalf("explicit detached-link replacement intent: %v", err)
	}
	publishedReplacement := clonePinOwnerRecord(replacing)
	publishedReplacement.DesiredLinks[0].LinkID = active.LinkID + 100
	if err := validatePinOwnerRecord(publishedReplacement, parent.resource, parent.mountID); err != nil {
		t.Fatalf("published detached-link replacement identity: %v", err)
	}
	rollingBackReplacement := advancePinOwnerRecord(
		publishedReplacement,
		time.Date(2026, 7, 29, 1, 2, 5, 250, time.UTC),
		pinOwnerPhaseApplying,
		pinOwnerStepRollingBack,
	)
	rollingBackReplacement.ActiveLinks[0].LinkID = active.LinkID + 200
	rollingBackReplacement.ActiveLinks[0].ReplacesLinkID = active.LinkID
	if err := validatePinOwnerRecord(
		rollingBackReplacement, parent.resource, parent.mountID,
	); err != nil {
		t.Fatalf("rollback detached-link replacement lineage: %v", err)
	}
	wrongRollbackLineage := clonePinOwnerRecord(rollingBackReplacement)
	wrongRollbackLineage.DesiredLinks[0].ReplacesLinkID =
		wrongRollbackLineage.ActiveLinks[0].LinkID
	if err := validatePinOwnerRecord(
		wrongRollbackLineage, parent.resource, parent.mountID,
	); err == nil || !strings.Contains(err.Error(), "rollback active lineage") {
		t.Fatalf("rollback replacement accepted new-link lineage: %v", err)
	}
	sharedRollbackIdentity := clonePinOwnerRecord(rollingBackReplacement)
	sharedRollbackIdentity.DesiredLinks[0].LinkID =
		sharedRollbackIdentity.ActiveLinks[0].LinkID
	if err := validatePinOwnerRecord(
		sharedRollbackIdentity, parent.resource, parent.mountID,
	); err == nil || !strings.Contains(err.Error(), "reuses rollback active link ID") {
		t.Fatalf("failed target reused rollback identity: %v", err)
	}
	reusedRetiredRollbackID := clonePinOwnerRecord(rollingBackReplacement)
	reusedRetiredRollbackID.DesiredLinks[0].LinkID = active.LinkID
	if err := validatePinOwnerRecord(
		reusedRetiredRollbackID, parent.resource, parent.mountID,
	); err == nil || !strings.Contains(err.Error(), "rollback active lineage") {
		t.Fatalf("rollback detached replacement reused retired link ID: %v", err)
	}
	sameLinkRollback := advancePinOwnerRecord(
		applying,
		time.Date(2026, 7, 29, 1, 2, 5, 300, time.UTC),
		pinOwnerPhaseApplying,
		pinOwnerStepRollingBack,
	)
	if err := validatePinOwnerRecord(sameLinkRollback, parent.resource, parent.mountID); err != nil {
		t.Fatalf("same-link CAS rollback: %v", err)
	}
	detachedSameLinkRollback := clonePinOwnerRecord(sameLinkRollback)
	detachedSameLinkRollback.ActiveLinks[0].LinkID = active.LinkID + 300
	detachedSameLinkRollback.ActiveLinks[0].ReplacesLinkID = active.LinkID
	if err := validatePinOwnerRecord(
		detachedSameLinkRollback, parent.resource, parent.mountID,
	); err != nil {
		t.Fatalf("detached same-link CAS rollback lineage: %v", err)
	}
	badReplacement := clonePinOwnerRecord(replacing)
	badReplacement.DesiredLinks[0].ReplacesLinkID++
	if err := validatePinOwnerRecord(badReplacement, parent.resource, parent.mountID); err == nil ||
		!strings.Contains(err.Error(), "active is") {
		t.Fatalf("mismatched detached-link replacement error = %v", err)
	}
	completedReplacement := completeApplyingPinOwnerRecord(
		publishedReplacement,
		time.Date(2026, 7, 29, 1, 2, 5, 500, time.UTC),
	)
	if len(completedReplacement.ActiveLinks) != 1 ||
		completedReplacement.ActiveLinks[0].ReplacesLinkID != 0 ||
		completedReplacement.ActiveLinks[0].LinkID != active.LinkID+100 {
		t.Fatalf("completed replacement retained transient marker: %+v", completedReplacement.ActiveLinks)
	}
	cleanup := advancePinOwnerRecord(
		applying,
		time.Date(2026, 7, 29, 1, 2, 6, 0, time.UTC),
		pinOwnerPhaseApplying,
		pinOwnerStepCleanup,
	)
	cleanup.DesiredLinks[0].LinkID = 0
	if err := validatePinOwnerRecord(cleanup, parent.resource, parent.mountID); err == nil ||
		!strings.Contains(err.Error(), "changes link ID") {
		t.Fatalf("cleanup unpublished link-ID error = %v", err)
	}
}

func TestValidateRollingBackOwnerLinkMatrix(t *testing.T) {
	stable := testExactTCXBinding(71, exactTCXIngress, 901)
	stable.LinkID = 1001
	desiredCAS := stable
	desiredCAS.ProgramID = 902
	desiredReplacement := desiredCAS
	desiredReplacement.LinkID = 1002
	desiredReplacement.ReplacesLinkID = stable.LinkID
	rollbackReplacement := stable
	rollbackReplacement.LinkID = 1003
	rollbackReplacement.ReplacesLinkID = stable.LinkID
	pendingRollbackReplacement := rollbackReplacement
	pendingRollbackReplacement.LinkID = 0
	targetOnly := testExactTCXBinding(72, exactTCXEgress, 903)
	targetOnly.LinkID = 1004

	tests := []struct {
		name      string
		active    []exactTCXBinding
		desired   []exactTCXBinding
		wantError string
	}{
		{
			name:   "same-link-CAS",
			active: []exactTCXBinding{stable}, desired: []exactTCXBinding{desiredCAS},
		},
		{
			name:   "detached-forward-pending",
			active: []exactTCXBinding{stable},
			desired: []exactTCXBinding{{
				Backend: stable.Backend, IfIndex: stable.IfIndex,
				Direction: stable.Direction, AttachType: stable.AttachType,
				PinName: stable.PinName, ProgramID: desiredCAS.ProgramID,
				ReplacesLinkID: stable.LinkID,
			}},
		},
		{
			name:   "detached-forward-published",
			active: []exactTCXBinding{stable}, desired: []exactTCXBinding{desiredReplacement},
		},
		{
			name:   "rollback-replacement-pending",
			active: []exactTCXBinding{pendingRollbackReplacement},
			desired: []exactTCXBinding{{
				Backend: stable.Backend, IfIndex: stable.IfIndex,
				Direction: stable.Direction, AttachType: stable.AttachType,
				PinName: stable.PinName, ProgramID: desiredCAS.ProgramID,
				ReplacesLinkID: stable.LinkID,
			}},
		},
		{
			name:    "rollback-replacement-detached-forward",
			active:  []exactTCXBinding{rollbackReplacement},
			desired: []exactTCXBinding{desiredReplacement},
		},
		{
			name:   "rollback-replacement-same-link-CAS",
			active: []exactTCXBinding{rollbackReplacement}, desired: []exactTCXBinding{desiredCAS},
		},
		{
			name:    "target-only-slot",
			desired: []exactTCXBinding{targetOnly},
		},
		{
			name:   "stable-different-link-without-lineage",
			active: []exactTCXBinding{stable},
			desired: []exactTCXBinding{func() exactTCXBinding {
				binding := desiredCAS
				binding.LinkID = 1002
				return binding
			}()},
			wantError: "without replacement lineage",
		},
		{
			name:   "stable-zero-link-without-lineage",
			active: []exactTCXBinding{stable},
			desired: []exactTCXBinding{func() exactTCXBinding {
				binding := desiredCAS
				binding.LinkID = 0
				return binding
			}()},
			wantError: "without replacement lineage",
		},
		{
			name: "rollback-replacement-retiring",
			active: []exactTCXBinding{func() exactTCXBinding {
				binding := rollbackReplacement
				binding.Retiring = true
				return binding
			}()},
			desired:   []exactTCXBinding{desiredReplacement},
			wantError: "cannot be retiring",
		},
		{
			name:   "failed-target-reuses-rollback-link",
			active: []exactTCXBinding{rollbackReplacement},
			desired: []exactTCXBinding{func() exactTCXBinding {
				binding := desiredReplacement
				binding.LinkID = rollbackReplacement.LinkID
				return binding
			}()},
			wantError: "reuses rollback active link ID",
		},
		{
			name:   "failed-target-wrong-lineage",
			active: []exactTCXBinding{rollbackReplacement},
			desired: []exactTCXBinding{func() exactTCXBinding {
				binding := desiredReplacement
				binding.ReplacesLinkID = rollbackReplacement.LinkID
				return binding
			}()},
			wantError: "rollback active lineage",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateOwnerLinks(test.active, "rollback active", false)
			if err == nil {
				err = validateOwnerLinks(test.desired, "desired", false)
			}
			if err == nil {
				err = validateRollingBackOwnerLinks(test.active, test.desired)
			}
			if test.wantError == "" && err != nil {
				t.Fatalf("legal rolling-back lineage rejected: %v", err)
			}
			if test.wantError != "" &&
				(err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("rolling-back lineage error=%v, want %q", err, test.wantError)
			}
		})
	}
}

func mustPinOwnerToken(t *testing.T, record *pinOwnerRecord) [32]byte {
	t.Helper()
	token, err := tokenFromOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestPinOwnerPhaseStepMatrix(t *testing.T) {
	_, parent, active := testPinOwnerRecord(t, t.TempDir())
	var token [32]byte
	for index := range token {
		token[index] = byte(index + 1)
	}
	now := time.Date(2026, 7, 29, 1, 2, 4, 0, time.UTC)
	applying, err := newApplyingPinOwnerRecord(
		parent,
		token,
		active.BootID,
		now,
		active.ActiveGeneration,
		active.ActiveGeneration+1,
		active.Maps,
		active.ActiveLinks,
		active.ActiveLinks,
		active,
	)
	if err != nil {
		t.Fatal(err)
	}
	detaching, err := newDetachingPinOwnerRecord(active, now)
	if err != nil {
		t.Fatal(err)
	}
	validSteps := map[string][]string{
		pinOwnerPhaseActive: {
			pinOwnerStepReady,
		},
		pinOwnerPhaseApplying: {
			pinOwnerStepStaging,
			pinOwnerStepMutating,
			pinOwnerStepRollingBack,
			pinOwnerStepRollbackCleanup,
			pinOwnerStepCleanup,
		},
		pinOwnerPhaseDetaching: {
			pinOwnerStepStaging,
			pinOwnerStepMutatingTC,
			pinOwnerStepUnlinkingMaps,
			pinOwnerStepCleanupStages,
		},
	}
	bases := map[string]*pinOwnerRecord{
		pinOwnerPhaseActive:    active,
		pinOwnerPhaseApplying:  applying,
		pinOwnerPhaseDetaching: detaching,
	}
	allSteps := []string{
		pinOwnerStepReady,
		pinOwnerStepRetiring,
		pinOwnerStepStaging,
		pinOwnerStepMutating,
		pinOwnerStepRollingBack,
		pinOwnerStepRollbackCleanup,
		pinOwnerStepMutatingTC,
		pinOwnerStepUnlinkingMaps,
		pinOwnerStepCleanup,
		pinOwnerStepCleanupStages,
	}
	for phase, base := range bases {
		for _, step := range allSteps {
			t.Run(phase+"/"+step, func(t *testing.T) {
				record := clonePinOwnerRecord(base)
				record.Step = step
				err := validatePinOwnerRecord(
					record,
					parent.resource,
					parent.mountID,
				)
				wantValid := false
				for _, valid := range validSteps[phase] {
					wantValid = wantValid || valid == step
				}
				if wantValid && err != nil {
					t.Fatalf("valid phase/step rejected: %v", err)
				}
				if !wantValid && err == nil {
					t.Fatal("invalid phase/step was accepted")
				}
			})
		}
	}
}

func TestOwnerDirectoryCoversExactTCXLinkPinsAcrossPhases(t *testing.T) {
	type fixture struct {
		handle *pinPathHandle
		parent *pinPathParent
		active *pinOwnerRecord
	}
	setup := func(t *testing.T, activeLinks []exactTCXBinding, present ...string) fixture {
		t.Helper()
		bpffsRoot, validator := newTestBPFFS(t)
		pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-owner-links")
		mapStore := writeCanonicalMockPins(t, pinPath)
		runtime := newTestPinPathRuntime(t, validator, mapStore)
		validated, err := validatePinPath(pinPath, validator)
		if err != nil {
			t.Fatal(err)
		}
		parent, err := openPinPathParent(pinPath, validated, runtime)
		if err != nil {
			t.Fatal(err)
		}
		handle, _, err := openPinPathHandleFromParent(parent, validated, false)
		if err != nil {
			_ = parent.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = handle.Close()
			_ = parent.Close()
		})
		pins, err := inspectPinnedMapSet(handle, true)
		if err != nil {
			t.Fatal(err)
		}
		ownerMaps := ownerMapsFromPins(pins)
		if err := closePinnedMapPins(pins); err != nil {
			t.Fatal(err)
		}
		var token [32]byte
		for index := range token {
			token[index] = byte(index + 1)
		}
		active, err := newActivePinOwnerRecord(
			parent,
			token,
			"12345678-1234-1234-1234-123456789abc",
			time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC),
			7,
			ownerMaps,
			activeLinks,
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range present {
			if err := os.WriteFile(filepath.Join(pinPath, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return fixture{handle: handle, parent: parent, active: active}
	}
	link := func(ifindex int, direction exactTCXDirection, programID, linkID uint32) exactTCXBinding {
		binding := testExactTCXBinding(ifindex, direction, programID)
		binding.LinkID = linkID
		return binding
	}

	t.Run("active exact set", func(t *testing.T) {
		links := []exactTCXBinding{
			link(41, exactTCXIngress, 1001, 2001),
			link(41, exactTCXEgress, 1002, 2002),
		}
		fixture := setup(t, links, links[0].PinName, links[1].PinName)
		if err := validateOwnerDirectoryEntries(fixture.handle, fixture.active); err != nil {
			t.Fatal(err)
		}
		state, err := classifyCanonicalPinDirectory(fixture.handle)
		if err != nil || state != canonicalPinsOwnedTCX {
			t.Fatalf("canonical state = %v, error=%v", state, err)
		}
	})

	t.Run("active missing and unjournaled fail closed", func(t *testing.T) {
		owned := link(42, exactTCXIngress, 1003, 2003)
		foreign := link(42, exactTCXEgress, 1004, 2004)
		fixture := setup(t, []exactTCXBinding{owned}, foreign.PinName)
		if err := validateOwnerDirectoryEntries(fixture.handle, fixture.active); err == nil ||
			!strings.Contains(err.Error(), "not covered") {
			t.Fatalf("unjournaled exact pin error = %v", err)
		}
	})

	t.Run("applying mutation covers unpublished deterministic pin", func(t *testing.T) {
		activeLink := link(43, exactTCXIngress, 1005, 2005)
		newLink := testExactTCXBinding(44, exactTCXEgress, 1006)
		fixture := setup(t, []exactTCXBinding{activeLink}, activeLink.PinName, newLink.PinName)
		applying, err := newApplyingPinOwnerRecord(
			fixture.parent,
			mustPinOwnerToken(t, fixture.active),
			fixture.active.BootID,
			time.Date(2026, 8, 8, 1, 2, 4, 0, time.UTC),
			fixture.active.ActiveGeneration,
			fixture.active.ActiveGeneration+1,
			fixture.active.Maps,
			fixture.active.ActiveLinks,
			[]exactTCXBinding{activeLink, newLink},
			fixture.active,
		)
		if err != nil {
			t.Fatal(err)
		}
		mutating := advancePinOwnerRecord(
			applying,
			time.Date(2026, 8, 8, 1, 2, 5, 0, time.UTC),
			pinOwnerPhaseApplying,
			pinOwnerStepMutating,
		)
		if err := validateOwnerDirectoryEntries(fixture.handle, mutating); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("applying staging rejects a pre-mutation desired pin", func(t *testing.T) {
		newLink := testExactTCXBinding(49, exactTCXIngress, 1011)
		fixture := setup(t, nil, newLink.PinName)
		applying, err := newApplyingPinOwnerRecord(
			fixture.parent,
			mustPinOwnerToken(t, fixture.active),
			fixture.active.BootID,
			time.Date(2026, 8, 8, 1, 2, 4, 0, time.UTC),
			fixture.active.ActiveGeneration,
			fixture.active.ActiveGeneration+1,
			fixture.active.Maps,
			fixture.active.ActiveLinks,
			[]exactTCXBinding{newLink},
			fixture.active,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateOwnerDirectoryEntries(fixture.handle, applying); err == nil ||
			!strings.Contains(err.Error(), "unexpected exact TCX pin") {
			t.Fatalf("staging desired pin error = %v", err)
		}
	})

	t.Run("applying cleanup permits already removed stale active pin", func(t *testing.T) {
		retained := link(45, exactTCXIngress, 1007, 2007)
		stale := link(46, exactTCXEgress, 1008, 2008)
		fixture := setup(t, []exactTCXBinding{retained, stale}, retained.PinName)
		applying, err := newApplyingPinOwnerRecord(
			fixture.parent,
			mustPinOwnerToken(t, fixture.active),
			fixture.active.BootID,
			time.Date(2026, 8, 8, 1, 2, 4, 0, time.UTC),
			fixture.active.ActiveGeneration,
			fixture.active.ActiveGeneration+1,
			fixture.active.Maps,
			fixture.active.ActiveLinks,
			[]exactTCXBinding{retained},
			fixture.active,
		)
		if err != nil {
			t.Fatal(err)
		}
		cleanup := advancePinOwnerRecord(
			applying,
			time.Date(2026, 8, 8, 1, 2, 5, 0, time.UTC),
			pinOwnerPhaseApplying,
			pinOwnerStepCleanup,
		)
		if err := validateOwnerDirectoryEntries(fixture.handle, cleanup); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("detaching mutation permits exact progress but unlinking requires none", func(t *testing.T) {
		first := link(47, exactTCXIngress, 1009, 2009)
		second := link(47, exactTCXEgress, 1010, 2010)
		fixture := setup(t, []exactTCXBinding{first, second}, second.PinName)
		detaching, err := newDetachingPinOwnerRecord(
			fixture.active,
			time.Date(2026, 8, 8, 1, 2, 4, 0, time.UTC),
		)
		if err != nil {
			t.Fatal(err)
		}
		mutating := advancePinOwnerRecord(
			detaching,
			time.Date(2026, 8, 8, 1, 2, 5, 0, time.UTC),
			pinOwnerPhaseDetaching,
			pinOwnerStepMutatingTC,
		)
		if err := validateOwnerDirectoryEntries(fixture.handle, mutating); err != nil {
			t.Fatal(err)
		}
		unlinking := advancePinOwnerRecord(
			mutating,
			time.Date(2026, 8, 8, 1, 2, 6, 0, time.UTC),
			pinOwnerPhaseDetaching,
			pinOwnerStepUnlinkingMaps,
		)
		if err := validateOwnerDirectoryEntries(fixture.handle, unlinking); err == nil ||
			!strings.Contains(err.Error(), "still has exact TCX") {
			t.Fatalf("unlinking exact pin error = %v", err)
		}
	})
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
	index, exists, err := indexStoreFromOwner(recoveredStore).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	nextEntry, err := ownerIndexEntryFromRecord(
		next,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		len(index.Entries) != 1 ||
		len(index.Active) != 1 ||
		!samePinOwnerIndexEntries(index.Entries, []pinOwnerIndexEntry{nextEntry}) ||
		index.Active[0] != activePointerFromEntry(nextEntry) {
		t.Fatalf("recovered owner index = %#v", index)
	}
}

func TestPinOwnerDescriptorAndIndexRecoveryAtEveryDurablePhase(t *testing.T) {
	for _, phase := range []string{
		"staged",
		"exchanged",
		"index-synced",
	} {
		t.Run(phase, func(t *testing.T) {
			runtime, parent, record, store, _ :=
				openPersistedTestPinOwner(t)
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
				_ = nextFile.Close()
				t.Fatal(err)
			}
			if err := nextFile.Close(); err != nil {
				t.Fatal(err)
			}
			if phase == "exchanged" || phase == "index-synced" {
				if err := unix.Renameat2(
					store.root.FD(),
					store.nextName,
					store.root.FD(),
					store.fileName,
					unix.RENAME_EXCHANGE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "index-synced" {
				if err := store.syncIndexRecord(next, false); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			recoveredStore, err := openPinOwnerStore(
				runtime,
				parent.resource,
				true,
			)
			if err != nil {
				t.Fatalf("recover descriptor phase %s: %v", phase, err)
			}
			defer recoveredStore.Close()
			recovered, err := recoveredStore.Load(parent.mountID)
			if err != nil {
				t.Fatal(err)
			}
			if !sameExpectedOwnerRecord(recovered, next) {
				t.Fatalf("recovered owner = %#v, want %#v", recovered, next)
			}
			nextEntry, err := ownerIndexEntryFromRecord(
				next,
				pinOwnerIndexActive,
				"",
			)
			if err != nil {
				t.Fatal(err)
			}
			index, exists, err := indexStoreFromOwner(
				recoveredStore,
			).loadOptional()
			if err != nil {
				t.Fatal(err)
			}
			if !exists ||
				len(index.Entries) != 1 ||
				len(index.Active) != 1 ||
				!samePinOwnerIndexEntries(
					index.Entries,
					[]pinOwnerIndexEntry{nextEntry},
				) ||
				index.Active[0] != activePointerFromEntry(nextEntry) {
				t.Fatalf("recovered owner index = %#v", index)
			}
			if _, err := os.Lstat(filepath.Join(
				runtime.ownerRoot,
				recoveredStore.nextName,
			)); !os.IsNotExist(err) {
				t.Fatalf(
					"recovered descriptor phase %s left old evidence: %v",
					phase,
					err,
				)
			}
		})
	}
}

func TestInitialOwnerPublishRepairsMissingIndex(t *testing.T) {
	runtime, parent, record := testPinOwnerRecord(t, t.TempDir())
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshalPinOwnerRecord(record)
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
		_ = nextFile.Close()
		t.Fatal(err)
	}
	if err := unix.Renameat2(
		store.root.FD(),
		store.nextName,
		store.root.FD(),
		store.fileName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		_ = nextFile.Close()
		t.Fatal(err)
	}
	if err := unix.Fsync(store.root.FD()); err != nil {
		_ = nextFile.Close()
		t.Fatal(err)
	}
	if err := nextFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	index, exists, err := indexStoreFromOwner(recovered).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		len(index.Entries) != 1 ||
		!samePinOwnerIndexEntries(index.Entries, []pinOwnerIndexEntry{entry}) {
		t.Fatalf("repaired initial owner index = %#v", index)
	}
}

func TestPinOwnerDescriptorRecoveryRejectsImmutableBootSwap(t *testing.T) {
	runtime, parent, record, store, entry := openPersistedTestPinOwner(t)
	next := clonePinOwnerRecord(record)
	next.Sequence++
	next.BootID = "87654321-4321-4321-4321-cba987654321"
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
		_ = nextFile.Close()
		t.Fatal(err)
	}
	if err := nextFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := openPinOwnerStore(
		runtime,
		parent.resource,
		true,
	); err == nil ||
		!strings.Contains(err.Error(), "immutable fields mismatch") {
		t.Fatalf("immutable boot-swap recovery error = %v", err)
	}
	for _, name := range []string{
		entry.RecordFileName,
		parent.resource.key + ".owner.next",
	} {
		if _, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			name,
		)); err != nil {
			t.Fatalf("immutable mismatch evidence %s was lost: %v", name, err)
		}
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

func TestPinOwnerIndexRetiresOldBootAndRemainsBounded(t *testing.T) {
	root := t.TempDir()
	runtime, parent, record := testPinOwnerRecord(t, root)
	runtime.now = func() time.Time {
		return time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	}
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	indexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		record,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC)
	historical, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*indexed,
		record,
		false,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if historical.Status != pinOwnerIndexRekeySource {
		t.Fatalf("archived owner status = %q", historical.Status)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	newBase := parent.resource.base
	newKey, err := pinidentity.Key(142, 199, newBase)
	if err != nil {
		t.Fatal(err)
	}
	newResource := pinResourceIdentity{
		key:          newKey,
		parentDevice: 142,
		parentInode:  199,
		base:         newBase,
		pinPath:      parent.pinPath,
	}
	newParent := *parent
	newParent.resource = newResource
	var newToken [32]byte
	for index := range newToken {
		newToken[index] = byte(0xa0 + index)
	}
	newRecord, err := newActivePinOwnerRecord(
		&newParent,
		newToken,
		"87654321-4321-4321-4321-cba987654321",
		now,
		record.ActiveGeneration,
		record.Maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	newRecord.RetiredFromResourceKey = record.ResourceKey
	newRecord.RetiredFromBootID = record.BootID
	if err := validatePinOwnerRecord(
		newRecord,
		newResource,
		parent.mountID,
	); err != nil {
		t.Fatal(err)
	}
	newStore, err := openPinOwnerStore(runtime, newResource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := newStore.Persist(newRecord, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	if err := newStore.Close(); err != nil {
		t.Fatal(err)
	}
	indexRoot, _, err := openAnchoredDirectoryPath(
		runtime.ownerRoot,
		false,
		0o700,
		runtime.expectedUID,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer indexRoot.Close()
	indexStore := &pinOwnerIndexStore{
		root:        indexRoot,
		expectedUID: runtime.expectedUID,
		now:         runtime.now,
	}
	index, exists, err := indexStore.loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		len(index.Entries) != 2 ||
		len(index.Active) != 1 {
		t.Fatalf("retired owner index = %#v", index)
	}
	statuses := make(map[string]string)
	for _, entry := range index.Entries {
		statuses[pinOwnerIndexEntryKey(entry.ResourceKey, entry.BootID)] =
			entry.Status
	}
	if statuses[pinOwnerIndexEntryKey(record.ResourceKey, record.BootID)] !=
		pinOwnerIndexRetiredStatus ||
		statuses[pinOwnerIndexEntryKey(newRecord.ResourceKey, newRecord.BootID)] !=
			pinOwnerIndexActive {
		t.Fatalf("owner index statuses = %#v", statuses)
	}
	if _, err := os.Stat(filepath.Join(
		runtime.ownerRoot,
		historical.RecordFileName,
	)); err != nil {
		t.Fatalf("historical owner record is not preserved: %v", err)
	}

	tooMany := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.Format(time.RFC3339Nano),
		Entries:   make([]pinOwnerIndexEntry, pinOwnerIndexMaxEntries+1),
	}
	if err := validatePinOwnerIndex(tooMany); err == nil ||
		!strings.Contains(err.Error(), "maximum") {
		t.Fatalf("oversized owner index error = %v", err)
	}
}

func TestSameKeyRebootOwnerPublishRecoversNextAndCanonicalCrash(t *testing.T) {
	for _, phase := range []string{"next", "canonical"} {
		t.Run(phase, func(t *testing.T) {
			runtime, parent, oldRecord, store, indexed :=
				openPersistedTestPinOwner(t)
			historical, err := indexStoreFromOwner(
				store,
			).archivePriorBootOwner(
				*indexed,
				oldRecord,
				false,
				time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC),
			)
			if err != nil {
				t.Fatal(err)
			}
			var token [32]byte
			for index := range token {
				token[index] = byte(0x80 + index)
			}
			current, err := newActivePinOwnerRecord(
				parent,
				token,
				"87654321-4321-4321-4321-cba987654321",
				time.Date(2026, 7, 30, 1, 3, 3, 4, time.UTC),
				oldRecord.ActiveGeneration,
				oldRecord.Maps,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			current.RetiredFromResourceKey = oldRecord.ResourceKey
			current.RetiredFromBootID = oldRecord.BootID
			normalizePinOwnerRecord(current)
			if err := validatePinOwnerRecord(
				current,
				parent.resource,
				parent.mountID,
			); err != nil {
				t.Fatal(err)
			}
			data, err := marshalPinOwnerRecord(current)
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
				_ = nextFile.Close()
				t.Fatal(err)
			}
			if phase == "canonical" {
				if err := unix.Renameat2(
					store.root.FD(),
					store.nextName,
					store.root.FD(),
					store.fileName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					_ = nextFile.Close()
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					_ = nextFile.Close()
					t.Fatal(err)
				}
			}
			if err := nextFile.Close(); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			recovered, err := openPinOwnerStore(
				runtime,
				parent.resource,
				true,
			)
			if err != nil {
				t.Fatalf(
					"recover same-key owner %s crash: %v",
					phase,
					err,
				)
			}
			defer recovered.Close()
			loaded, err := recovered.Load(parent.mountID)
			if err != nil {
				t.Fatal(err)
			}
			if !sameExpectedOwnerRecord(loaded, current) {
				t.Fatalf(
					"same-key recovered owner = %#v, want %#v",
					loaded,
					current,
				)
			}
			index, exists, err := indexStoreFromOwner(
				recovered,
			).loadOptional()
			if err != nil {
				t.Fatal(err)
			}
			if !exists ||
				index.Sequence != 3 ||
				len(index.Entries) != 2 ||
				len(index.Active) != 1 ||
				index.Active[0].ResourceKey != current.ResourceKey ||
				index.Active[0].BootID != current.BootID ||
				index.Active[0].Status != pinOwnerIndexActive {
				t.Fatalf("same-key recovered index = %#v", index)
			}
			statusByBoot := make(map[string]string, len(index.Entries))
			for _, entry := range index.Entries {
				statusByBoot[entry.BootID] = entry.Status
			}
			if statusByBoot[oldRecord.BootID] !=
				pinOwnerIndexRetiredStatus ||
				statusByBoot[current.BootID] != pinOwnerIndexActive {
				t.Fatalf(
					"same-key recovered statuses = %#v",
					statusByBoot,
				)
			}
			if _, err := os.Lstat(filepath.Join(
				runtime.ownerRoot,
				historical.RecordFileName,
			)); err != nil {
				t.Fatalf("same-key old evidence was lost: %v", err)
			}
		})
	}
}

func TestPinOwnerIndexJSONFieldOrderAndActivePathUniqueness(t *testing.T) {
	_, _, record := testPinOwnerRecord(t, t.TempDir())
	now := time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	entry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	index := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.Format(time.RFC3339Nano),
		Active: []pinOwnerIndexActivePointer{
			activePointerFromEntry(entry),
		},
		Entries: []pinOwnerIndexEntry{entry},
	}
	data, err := marshalPinOwnerIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONFieldOrder(t, data, []string{
		`"version":`,
		`"sequence":`,
		`"updated_at":`,
		`"active":`,
		`"rotation":`,
		`"entries":`,
	})
	activeStart := bytes.Index(data, []byte(`"active":[{`))
	if activeStart < 0 {
		t.Fatalf("owner index has no active pointer object: %s", data)
	}
	assertJSONFieldOrder(t, data[activeStart:], []string{
		`"bpffs_root_path":`,
		`"pin_basename":`,
		`"resource_key":`,
		`"boot_id":`,
		`"record_filename":`,
		`"status":`,
	})
	entryStart := bytes.Index(data, []byte(`"entries":[{`))
	if entryStart < 0 {
		t.Fatalf("owner index has no entry object: %s", data)
	}
	assertJSONFieldOrder(t, data[entryStart:], []string{
		`"resource_key":`,
		`"parent_device":`,
		`"parent_inode":`,
		`"pin_basename":`,
		`"bpffs_root_path":`,
		`"bpffs_mount_ids":`,
		`"boot_id":`,
		`"record_filename":`,
		`"owner_digest":`,
		`"status":`,
		`"retired_at":`,
	})
	retired, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexRetiredStatus,
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}
	rotationIndex := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  2,
		UpdatedAt: now.Add(time.Second).Format(time.RFC3339Nano),
		Rotation: &pinOwnerIndexRotation{
			ResourceKey:        retired.ResourceKey,
			BootID:             retired.BootID,
			RecordFileName:     retired.RecordFileName,
			QuarantineFileName: retired.RecordFileName + pinOwnerRotationSuffix,
			OwnerDigest:        retired.OwnerDigest,
		},
		Entries: []pinOwnerIndexEntry{retired},
	}
	rotationData, err := marshalPinOwnerIndex(rotationIndex)
	if err != nil {
		t.Fatal(err)
	}
	rotationStart := bytes.Index(rotationData, []byte(`"rotation":{`))
	if rotationStart < 0 {
		t.Fatalf("owner index has no rotation object: %s", rotationData)
	}
	assertJSONFieldOrder(t, rotationData[rotationStart:], []string{
		`"resource_key":`,
		`"boot_id":`,
		`"record_filename":`,
		`"quarantine_filename":`,
		`"owner_digest":`,
	})

	duplicate := entry
	duplicate.ResourceKey, err = pinidentity.Key(
		entry.ParentDevice+1,
		entry.ParentInode+1,
		entry.PinBaseName,
	)
	if err != nil {
		t.Fatal(err)
	}
	duplicate.ParentDevice++
	duplicate.ParentInode++
	duplicate.RecordFileName = duplicate.ResourceKey + ".owner.json"
	index.Entries = append(index.Entries, duplicate)
	index.Active = append(
		index.Active,
		activePointerFromEntry(duplicate),
	)
	normalizePinOwnerIndex(index)
	if err := validatePinOwnerIndex(index); err == nil ||
		!strings.Contains(err.Error(), "repeats active pointer") {
		t.Fatalf("duplicate active pin path error = %v", err)
	}
}

func TestPinOwnerIndexRejectsDuplicateActiveResourceAcrossPathAliases(
	t *testing.T,
) {
	_, _, record := testPinOwnerRecord(t, t.TempDir())
	now := time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	first, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.BootID = "22345678-1234-1234-1234-123456789abc"
	second.BPFFSRootPath = filepath.Join(
		filepath.Dir(first.BPFFSRootPath),
		"bpffs-alias",
	)
	index := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.Format(time.RFC3339Nano),
		Active: []pinOwnerIndexActivePointer{
			activePointerFromEntry(first),
			activePointerFromEntry(second),
		},
		Entries: []pinOwnerIndexEntry{first, second},
	}
	normalizePinOwnerIndex(index)
	if err := validatePinOwnerIndex(index); err == nil ||
		!strings.Contains(err.Error(), "active pointer for resource") {
		t.Fatalf("duplicate active resource error = %v", err)
	}
}

func TestPinOwnerIndexRejectsDisagreeingPathAndResourcePointers(
	t *testing.T,
) {
	_, parent, record := testPinOwnerRecord(t, t.TempDir())
	now := time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	resourceEntry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	aliasRoot := filepath.Join(
		filepath.Dir(resourceEntry.BPFFSRootPath),
		"bpffs-alias",
	)
	pathEntry := resourceEntry
	pathEntry.ParentDevice++
	pathEntry.ParentInode++
	pathEntry.ResourceKey, err = pinidentity.Key(
		pathEntry.ParentDevice,
		pathEntry.ParentInode,
		pathEntry.PinBaseName,
	)
	if err != nil {
		t.Fatal(err)
	}
	pathEntry.BPFFSRootPath = aliasRoot
	pathEntry.BootID = "22345678-1234-1234-1234-123456789abc"
	pathEntry.RecordFileName = pathEntry.ResourceKey + ".owner.json"
	index := &pinOwnerIndex{
		Version:   pinOwnerIndexVersion,
		Sequence:  1,
		UpdatedAt: now.Format(time.RFC3339Nano),
		Active: []pinOwnerIndexActivePointer{
			activePointerFromEntry(resourceEntry),
			activePointerFromEntry(pathEntry),
		},
		Entries: []pinOwnerIndexEntry{resourceEntry, pathEntry},
	}
	normalizePinOwnerIndex(index)
	if err := validatePinOwnerIndex(index); err != nil {
		t.Fatalf("valid ambiguous fixture: %v", err)
	}
	resource := parent.resource
	resource.pinPath = filepath.Join(aliasRoot, resource.base)
	if _, err := pinOwnerIndexPointerForResourceOrPath(
		index,
		resource,
		aliasRoot,
	); err == nil ||
		!strings.Contains(err.Error(), "pointers disagree") {
		t.Fatalf("disagreeing path/resource pointer error = %v", err)
	}
}

func TestPinOwnerIndexStaleExpectedDoesNotStageNext(t *testing.T) {
	runtime, _, _, store, _ := openPersistedTestPinOwner(t)
	indexStore := indexStoreFromOwner(store)
	expected, exists, err := indexStore.loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("persisted owner index is unavailable")
	}
	advanced := clonePinOwnerIndex(expected)
	advanced.Sequence++
	advanced.UpdatedAt = time.Date(
		2026,
		7,
		29,
		2,
		2,
		3,
		4,
		time.UTC,
	).Format(time.RFC3339Nano)
	if err := indexStore.persist(advanced, expected); err != nil {
		t.Fatal(err)
	}
	staleNext := clonePinOwnerIndex(expected)
	staleNext.Sequence++
	staleNext.UpdatedAt = time.Date(
		2026,
		7,
		29,
		3,
		2,
		3,
		4,
		time.UTC,
	).Format(time.RFC3339Nano)
	if err := indexStore.persist(
		staleNext,
		expected,
	); err == nil ||
		!strings.Contains(err.Error(), "before staging next") {
		t.Fatalf("stale index persist error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		pinOwnerIndexNextName,
	)); !os.IsNotExist(err) {
		t.Fatalf("stale index writer left next descriptor: %v", err)
	}
	current, exists, err := indexStore.loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || !samePinOwnerIndex(current, advanced) {
		t.Fatalf(
			"stale index writer changed current:\ncurrent=%#v\nwant=%#v",
			current,
			advanced,
		)
	}
}

func TestConcurrentPinOwnerIndexUpdatesForDifferentResources(
	t *testing.T,
) {
	root := t.TempDir()
	runtime, firstParent, firstRecord := testPinOwnerRecord(t, root)
	secondPinPath := filepath.Join(
		firstRecord.BPFFSRootPath,
		"wg-mix-ebpf-owner-concurrent",
	)
	secondBase := filepath.Base(secondPinPath)
	secondKey, err := pinidentity.Key(
		firstParent.resource.parentDevice,
		firstParent.resource.parentInode,
		secondBase,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondResource := pinResourceIdentity{
		key:          secondKey,
		parentDevice: firstParent.resource.parentDevice,
		parentInode:  firstParent.resource.parentInode,
		base:         secondBase,
		pinPath:      secondPinPath,
	}
	secondParent := &pinPathParent{
		pinPath:  secondPinPath,
		base:     secondBase,
		mountID:  firstParent.mountID,
		resource: secondResource,
		runtime:  runtime,
	}
	var secondToken [32]byte
	for index := range secondToken {
		secondToken[index] = byte(0x60 + index)
	}
	secondRecord, err := newActivePinOwnerRecord(
		secondParent,
		secondToken,
		"22345678-1234-1234-1234-123456789abc",
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		firstRecord.ActiveGeneration,
		firstRecord.Maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstStore, err := openPinOwnerStore(
		runtime,
		firstParent.resource,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	secondStore, err := openPinOwnerStore(
		runtime,
		secondParent.resource,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- firstStore.Persist(
			firstRecord,
			nil,
			firstParent.mountID,
		)
	}()
	go func() {
		<-start
		results <- secondStore.Persist(
			secondRecord,
			nil,
			secondParent.mountID,
		)
	}()
	close(start)
	for result := 0; result < 2; result++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent owner/index persist: %v", err)
		}
	}

	index, exists, err := indexStoreFromOwner(firstStore).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		index.Sequence != 2 ||
		len(index.Entries) != 2 ||
		len(index.Active) != 2 {
		t.Fatalf("concurrent owner index = %#v", index)
	}
	for _, name := range []string{
		pinOwnerIndexNextName,
		pinOwnerIndexRetired,
	} {
		if _, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			name,
		)); !os.IsNotExist(err) {
			t.Fatalf(
				"concurrent owner index left transient %s: %v",
				name,
				err,
			)
		}
	}
	for _, record := range []*pinOwnerRecord{
		firstRecord,
		secondRecord,
	} {
		if _, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			record.ResourceKey+".owner.json",
		)); err != nil {
			t.Fatalf(
				"concurrent owner record %s is unavailable: %v",
				record.ResourceKey,
				err,
			)
		}
	}
}

func assertJSONFieldOrder(
	t *testing.T,
	data []byte,
	keys []string,
) {
	t.Helper()
	position := -1
	for _, key := range keys {
		next := bytes.Index(data, []byte(key))
		if next <= position {
			t.Fatalf("JSON field %s is out of order: %s", key, data)
		}
		position = next
	}
}

func openPersistedTestPinOwner(
	t *testing.T,
) (
	pinPathRuntime,
	*pinPathParent,
	*pinOwnerRecord,
	*pinOwnerStore,
	*pinOwnerIndexEntry,
) {
	t.Helper()
	runtime, parent, record := testPinOwnerRecord(t, t.TempDir())
	runtime.now = func() time.Time {
		return time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
	}
	parent.runtime = runtime
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close test pin owner store: %v", err)
		}
	})
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	entry, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		record,
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, parent, record, store, entry
}

func TestPinOwnerArchiveRecoveryAtEveryDurablePhase(t *testing.T) {
	for _, phase := range []string{
		"canonical",
		"archive",
		"history",
		"indexed",
	} {
		t.Run(phase, func(t *testing.T) {
			runtime, parent, record, store, entry :=
				openPersistedTestPinOwner(t)
			now := time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC)
			historical := *entry
			historical.Status = pinOwnerIndexRekeySource
			historical.RetiredAt = now.Format(time.RFC3339Nano)
			historical.RecordFileName = pinOwnerHistoryFileName(historical)
			archiveName := pinOwnerArchiveFileName(entry.ResourceKey)

			switch phase {
			case "canonical":
			case "archive":
				if err := unix.Renameat2(
					store.root.FD(),
					entry.RecordFileName,
					store.root.FD(),
					archiveName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					t.Fatal(err)
				}
			case "history":
				if err := unix.Renameat2(
					store.root.FD(),
					entry.RecordFileName,
					store.root.FD(),
					archiveName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Renameat2(
					store.root.FD(),
					archiveName,
					store.root.FD(),
					historical.RecordFileName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					t.Fatal(err)
				}
			case "indexed":
				archived, err := indexStoreFromOwner(store).archivePriorBootOwner(
					*entry,
					record,
					false,
					now,
				)
				if err != nil {
					t.Fatal(err)
				}
				historical = *archived
			default:
				t.Fatalf("unknown archive phase %q", phase)
			}

			if err := indexStoreFromOwner(store).recoverOwnerArchive(
				parent.resource,
			); err != nil {
				t.Fatalf("recover owner archive phase %s: %v", phase, err)
			}
			index, exists, err := indexStoreFromOwner(store).loadOptional()
			if err != nil {
				t.Fatal(err)
			}
			if !exists || len(index.Active) != 1 {
				t.Fatalf("archive recovery index = %#v", index)
			}
			if phase == "indexed" {
				if index.Active[0] != activePointerFromEntry(historical) ||
					index.Active[0].Status != pinOwnerIndexRekeySource {
					t.Fatalf(
						"durable archive pointer = %#v, want %#v",
						index.Active[0],
						activePointerFromEntry(historical),
					)
				}
				if _, err := os.Lstat(filepath.Join(
					runtime.ownerRoot,
					historical.RecordFileName,
				)); err != nil {
					t.Fatalf("durable historical owner is unavailable: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(
					runtime.ownerRoot,
					entry.RecordFileName,
				)); !os.IsNotExist(err) {
					t.Fatalf("canonical owner returned after durable archive: %v", err)
				}
				return
			}
			if index.Active[0] != activePointerFromEntry(*entry) {
				t.Fatalf(
					"rolled-back archive pointer = %#v, want %#v",
					index.Active[0],
					activePointerFromEntry(*entry),
				)
			}
			loaded, err := store.Load(parent.mountID)
			if err != nil {
				t.Fatalf("load rolled-back canonical owner: %v", err)
			}
			if !sameExpectedOwnerRecord(loaded, record) {
				t.Fatalf("rolled-back owner = %#v, want %#v", loaded, record)
			}
			for _, transient := range []string{
				archiveName,
				historical.RecordFileName,
			} {
				if _, err := os.Lstat(filepath.Join(
					runtime.ownerRoot,
					transient,
				)); !os.IsNotExist(err) {
					t.Fatalf(
						"archive transient %s remains after rollback: %v",
						transient,
						err,
					)
				}
			}
		})
	}
}

func TestPinOwnerArchiveRejectsExactTargetCollisions(t *testing.T) {
	for _, target := range []string{"archive", "history"} {
		t.Run(target, func(t *testing.T) {
			runtime, parent, record, store, entry :=
				openPersistedTestPinOwner(t)
			historical := *entry
			historical.Status = pinOwnerIndexRekeySource
			historical.RetiredAt = time.Date(
				2026, 7, 30, 1, 2, 3, 4, time.UTC,
			).Format(time.RFC3339Nano)
			historical.RecordFileName = pinOwnerHistoryFileName(historical)
			collisionName := pinOwnerArchiveFileName(entry.ResourceKey)
			if target == "history" {
				collisionName = historical.RecordFileName
			}
			if err := os.WriteFile(
				filepath.Join(runtime.ownerRoot, collisionName),
				[]byte("collision\n"),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			_, err := indexStoreFromOwner(store).archivePriorBootOwner(
				*entry,
				record,
				false,
				time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC),
			)
			if err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("%s collision error = %v", target, err)
			}
			loaded, err := store.Load(parent.mountID)
			if err != nil {
				t.Fatalf("canonical owner lost after %s collision: %v", target, err)
			}
			if !sameExpectedOwnerRecord(loaded, record) {
				t.Fatalf("canonical owner changed after %s collision", target)
			}
			index, exists, err := indexStoreFromOwner(store).loadOptional()
			if err != nil {
				t.Fatal(err)
			}
			if !exists ||
				len(index.Active) != 1 ||
				index.Active[0] != activePointerFromEntry(*entry) {
				t.Fatalf("index changed after %s collision: %#v", target, index)
			}
		})
	}
}

func TestPinOwnerArchiveRejectsCanonicalSwapAtHook(t *testing.T) {
	runtime, parent, record, store, entry := openPersistedTestPinOwner(t)
	swappedName := entry.RecordFileName + ".swapped"
	var hookErr error
	store.beforeOwnerExchange = func() {
		if hookErr != nil {
			return
		}
		hookErr = unix.Renameat2(
			store.root.FD(),
			entry.RecordFileName,
			store.root.FD(),
			swappedName,
			unix.RENAME_NOREPLACE,
		)
		if hookErr == nil {
			hookErr = os.WriteFile(
				filepath.Join(runtime.ownerRoot, entry.RecordFileName),
				[]byte("{}\n"),
				0o600,
			)
		}
	}
	_, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*entry,
		record,
		false,
		time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC),
	)
	if hookErr != nil {
		t.Fatalf("archive swap hook: %v", hookErr)
	}
	if err == nil ||
		!strings.Contains(err.Error(), "changed at archive hook") {
		t.Fatalf("archive canonical-swap error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		swappedName,
	)); err != nil {
		t.Fatalf("original swapped owner evidence is unavailable: %v", err)
	}
	index, exists, indexErr := indexStoreFromOwner(store).loadOptional()
	if indexErr != nil {
		t.Fatal(indexErr)
	}
	if !exists ||
		len(index.Active) != 1 ||
		index.Active[0] != activePointerFromEntry(*entry) {
		t.Fatalf("index changed after canonical swap: %#v", index)
	}
	if _, loadErr := store.Load(parent.mountID); loadErr == nil {
		t.Fatal("replacement canonical owner unexpectedly validated")
	}
}

func advanceTestPinOwnerHistory(
	t *testing.T,
	parent *pinPathParent,
	store *pinOwnerStore,
	current *pinOwnerRecord,
	count int,
) (*pinOwnerRecord, []pinOwnerIndexEntry) {
	t.Helper()
	history := make([]pinOwnerIndexEntry, 0, count)
	baseTime := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	for generation := 1; generation <= count; generation++ {
		indexed, err := activeIndexedOwnerForRecord(
			indexStoreFromOwner(store),
			current,
		)
		if err != nil {
			t.Fatal(err)
		}
		transitionTime := baseTime.Add(time.Duration(generation) * time.Hour)
		archived, err := indexStoreFromOwner(store).archivePriorBootOwner(
			*indexed,
			current,
			false,
			transitionTime,
		)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, *archived)

		var token [32]byte
		for tokenIndex := range token {
			token[tokenIndex] = byte(0x20 + generation + tokenIndex)
		}
		next, err := newActivePinOwnerRecord(
			parent,
			token,
			fmt.Sprintf(
				"%08x-1234-1234-1234-%012x",
				0x20000000+generation,
				generation,
			),
			transitionTime.Add(time.Minute),
			current.ActiveGeneration,
			current.Maps,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		next.RetiredFromResourceKey = current.ResourceKey
		next.RetiredFromBootID = current.BootID
		normalizePinOwnerRecord(next)
		if err := validatePinOwnerRecord(
			next,
			parent.resource,
			parent.mountID,
		); err != nil {
			t.Fatal(err)
		}
		if err := store.Persist(next, nil, parent.mountID); err != nil {
			t.Fatal(err)
		}
		current = next
	}
	return current, history
}

func testPinOwnerHistoryAtCapacity(
	t *testing.T,
) (
	pinPathRuntime,
	*pinPathParent,
	*pinOwnerRecord,
	*pinOwnerStore,
	*pinOwnerIndex,
	pinOwnerIndexEntry,
) {
	t.Helper()
	runtime, parent, record, store, _ := openPersistedTestPinOwner(t)
	current, _ := advanceTestPinOwnerHistory(
		t,
		parent,
		store,
		record,
		pinOwnerIndexMaxHistory,
	)
	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		len(index.Entries) != pinOwnerIndexMaxHistory+1 ||
		len(index.Active) != 1 {
		t.Fatalf("history-at-capacity index = %#v", index)
	}
	var retired []pinOwnerIndexEntry
	for _, entry := range index.Entries {
		if entry.Status == pinOwnerIndexRetiredStatus {
			retired = append(retired, entry)
		}
	}
	sort.Slice(retired, func(i, j int) bool {
		if retired[i].RetiredAt != retired[j].RetiredAt {
			return retired[i].RetiredAt < retired[j].RetiredAt
		}
		return pinOwnerIndexEntryLess(retired[i], retired[j])
	})
	if len(retired) != pinOwnerIndexMaxHistory {
		t.Fatalf("retired history count = %d", len(retired))
	}
	return runtime, parent, current, store, index, retired[0]
}

func persistTestPinOwnerRotationJournal(
	t *testing.T,
	store *pinOwnerStore,
	index *pinOwnerIndex,
	victim pinOwnerIndexEntry,
) *pinOwnerIndex {
	t.Helper()
	next := clonePinOwnerIndex(index)
	next.Sequence++
	next.UpdatedAt = time.Date(
		2026, 8, 1, 1, 2, 3, 4, time.UTC,
	).Format(time.RFC3339Nano)
	next.Rotation = &pinOwnerIndexRotation{
		ResourceKey:        victim.ResourceKey,
		BootID:             victim.BootID,
		RecordFileName:     victim.RecordFileName,
		QuarantineFileName: victim.RecordFileName + pinOwnerRotationSuffix,
		OwnerDigest:        victim.OwnerDigest,
	}
	normalizePinOwnerIndex(next)
	if err := indexStoreFromOwner(store).persist(next, index); err != nil {
		t.Fatal(err)
	}
	return next
}

func TestPinOwnerHistoryBoundRotatesOnlyOldestExactRecord(t *testing.T) {
	runtime, parent, current, store, _, oldest :=
		testPinOwnerHistoryAtCapacity(t)
	currentIndexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		current,
	)
	if err != nil {
		t.Fatal(err)
	}
	archiveTime := time.Date(2026, 8, 1, 2, 0, 0, 0, time.UTC)
	latestHistory, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*currentIndexed,
		current,
		false,
		archiveTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	var nextToken [32]byte
	for index := range nextToken {
		nextToken[index] = byte(0xa0 + index)
	}
	next, err := newActivePinOwnerRecord(
		parent,
		nextToken,
		"87654321-4321-4321-4321-cba987654321",
		archiveTime.Add(time.Minute),
		current.ActiveGeneration,
		current.Maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	next.RetiredFromResourceKey = current.ResourceKey
	next.RetiredFromBootID = current.BootID
	normalizePinOwnerRecord(next)
	if err := store.Persist(next, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists ||
		index.Rotation != nil ||
		len(index.Entries) != pinOwnerIndexMaxHistory+1 ||
		len(index.Active) != 1 ||
		index.Active[0].BootID != next.BootID ||
		index.Active[0].Status != pinOwnerIndexActive {
		t.Fatalf("rotated history index = %#v", index)
	}
	historyCount := 0
	for _, entry := range index.Entries {
		if entry.Status != pinOwnerIndexActive {
			historyCount++
		}
		if entry.ResourceKey == oldest.ResourceKey &&
			entry.BootID == oldest.BootID {
			t.Fatalf("oldest rotated entry remains indexed: %#v", entry)
		}
	}
	if historyCount != pinOwnerIndexMaxHistory {
		t.Fatalf("history count after bounded rotation = %d", historyCount)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		oldest.RecordFileName,
	)); !os.IsNotExist(err) {
		t.Fatalf("oldest history remains after rotation: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		oldest.RecordFileName+pinOwnerRotationSuffix,
	)); !os.IsNotExist(err) {
		t.Fatalf("oldest history quarantine remains after rotation: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		latestHistory.RecordFileName,
	)); err != nil {
		t.Fatalf("latest exact history was not preserved: %v", err)
	}
}

func TestPinOwnerHistoryBoundCannotBeBypassedWithPathAliases(t *testing.T) {
	runtime, parent, current, store, _ := openPersistedTestPinOwner(t)
	aliasRoot := filepath.Join(
		filepath.Dir(current.BPFFSRootPath),
		"bpffs-alias",
	)
	aliasResource := parent.resource
	aliasResource.pinPath = filepath.Join(
		aliasRoot,
		aliasResource.base,
	)
	aliasParent := &pinPathParent{
		pinPath:  aliasResource.pinPath,
		base:     aliasResource.base,
		mountID:  parent.mountID + 1,
		resource: aliasResource,
		runtime:  runtime,
	}
	var archived []pinOwnerIndexEntry
	baseTime := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	for generation := 1; generation <= pinOwnerIndexMaxHistory+2; generation++ {
		indexed, err := activeIndexedOwnerForRecord(
			indexStoreFromOwner(store),
			current,
		)
		if err != nil {
			t.Fatal(err)
		}
		transitionTime := baseTime.Add(
			time.Duration(generation) * time.Hour,
		)
		history, err := indexStoreFromOwner(store).archivePriorBootOwner(
			*indexed,
			current,
			false,
			transitionTime,
		)
		if err != nil {
			t.Fatal(err)
		}
		archived = append(archived, *history)

		nextParent := parent
		if generation%2 != 0 {
			nextParent = aliasParent
		}
		var token [32]byte
		for tokenIndex := range token {
			token[tokenIndex] = byte(
				0x30 + generation + tokenIndex,
			)
		}
		next, err := newActivePinOwnerRecord(
			nextParent,
			token,
			fmt.Sprintf(
				"%08x-1234-1234-1234-%012x",
				0x30000000+generation,
				generation,
			),
			transitionTime.Add(time.Minute),
			current.ActiveGeneration,
			current.Maps,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		next.RetiredFromResourceKey = current.ResourceKey
		next.RetiredFromBootID = current.BootID
		normalizePinOwnerRecord(next)
		if err := store.Persist(
			next,
			nil,
			nextParent.mountID,
		); err != nil {
			t.Fatal(err)
		}
		current = next
	}

	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || len(index.Active) != 1 {
		t.Fatalf("path-alias history index = %#v", index)
	}
	resourceHistory := 0
	historyByPath := make(map[string]int)
	for _, entry := range index.Entries {
		if entry.Status == pinOwnerIndexActive {
			continue
		}
		if entry.ResourceKey == parent.resource.key {
			resourceHistory++
		}
		historyByPath[pinOwnerIndexPathKey(
			entry.BPFFSRootPath,
			entry.PinBaseName,
		)]++
	}
	if resourceHistory != pinOwnerIndexMaxHistory {
		t.Fatalf(
			"path-alias resource history count = %d, want %d",
			resourceHistory,
			pinOwnerIndexMaxHistory,
		)
	}
	for path, count := range historyByPath {
		if count > pinOwnerIndexMaxHistory {
			t.Fatalf(
				"path-alias history for %q = %d, maximum %d",
				path,
				count,
				pinOwnerIndexMaxHistory,
			)
		}
	}
	rotated := len(archived) - pinOwnerIndexMaxHistory
	for historyIndex, history := range archived {
		_, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			history.RecordFileName,
		))
		if historyIndex < rotated {
			if !os.IsNotExist(err) {
				t.Fatalf(
					"rotated path-alias history %s remains: %v",
					history.RecordFileName,
					err,
				)
			}
			continue
		}
		if err != nil {
			t.Fatalf(
				"retained path-alias history %s is unavailable: %v",
				history.RecordFileName,
				err,
			)
		}
	}
}

func TestPinOwnerArchiveCollisionAtHistoryBoundDoesNotRotate(t *testing.T) {
	runtime, _, current, store, before, oldest :=
		testPinOwnerHistoryAtCapacity(t)
	currentIndexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		current,
	)
	if err != nil {
		t.Fatal(err)
	}
	historical := *currentIndexed
	historical.Status = pinOwnerIndexRekeySource
	historical.RetiredAt = time.Date(
		2026, 8, 1, 2, 0, 0, 0, time.UTC,
	).Format(time.RFC3339Nano)
	historical.RecordFileName = pinOwnerHistoryFileName(historical)
	if err := os.WriteFile(
		filepath.Join(runtime.ownerRoot, historical.RecordFileName),
		[]byte("collision\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, err = indexStoreFromOwner(store).archivePriorBootOwner(
		*currentIndexed,
		current,
		false,
		time.Date(2026, 8, 1, 2, 0, 0, 0, time.UTC),
	)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("history-bound archive collision error = %v", err)
	}
	after, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || !samePinOwnerIndex(after, before) {
		t.Fatalf(
			"history index rotated before collision refusal:\nbefore=%#v\nafter=%#v",
			before,
			after,
		)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		oldest.RecordFileName,
	)); err != nil {
		t.Fatalf("oldest evidence was removed before collision refusal: %v", err)
	}
}

func TestPinOwnerHistoryRotationRecoversEveryDurablePhase(t *testing.T) {
	for _, phase := range []string{
		"journaled",
		"quarantined",
		"unlinked",
	} {
		t.Run(phase, func(t *testing.T) {
			runtime, _, _, store, index, victim :=
				testPinOwnerHistoryAtCapacity(t)
			journal := persistTestPinOwnerRotationJournal(
				t,
				store,
				index,
				victim,
			)
			quarantineName := journal.Rotation.QuarantineFileName
			if phase == "quarantined" || phase == "unlinked" {
				if err := unix.Renameat2(
					store.root.FD(),
					victim.RecordFileName,
					store.root.FD(),
					quarantineName,
					unix.RENAME_NOREPLACE,
				); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fsync(store.root.FD()); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "unlinked" {
				history, err := validatePinOwnerHistoryAt(
					indexStoreFromOwner(store),
					victim,
					quarantineName,
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := unlinkAnchoredRegularFile(
					store.root,
					quarantineName,
					int(history.file.Fd()),
					history.identity,
					store.expectedUID,
				); err != nil {
					_ = history.Close()
					t.Fatal(err)
				}
				if err := history.Close(); err != nil {
					t.Fatal(err)
				}
			}
			recovered, exists, err := indexStoreFromOwner(store).loadOptional()
			if err != nil {
				t.Fatalf("recover rotation phase %s: %v", phase, err)
			}
			if !exists ||
				recovered.Rotation != nil ||
				len(recovered.Entries) != len(index.Entries)-1 {
				t.Fatalf("recovered rotation index = %#v", recovered)
			}
			for _, entry := range recovered.Entries {
				if entry.ResourceKey == victim.ResourceKey &&
					entry.BootID == victim.BootID {
					t.Fatalf("rotation victim remains indexed: %#v", entry)
				}
			}
			for _, name := range []string{
				victim.RecordFileName,
				quarantineName,
			} {
				if _, err := os.Lstat(filepath.Join(
					runtime.ownerRoot,
					name,
				)); !os.IsNotExist(err) {
					t.Fatalf(
						"rotation phase %s left %s: %v",
						phase,
						name,
						err,
					)
				}
			}
		})
	}
}

func TestPinOwnerHistoryRotationFailsClosedOnArchiveCollision(t *testing.T) {
	runtime, _, _, store, index, victim :=
		testPinOwnerHistoryAtCapacity(t)
	journal := persistTestPinOwnerRotationJournal(
		t,
		store,
		index,
		victim,
	)
	original, err := os.ReadFile(filepath.Join(
		runtime.ownerRoot,
		victim.RecordFileName,
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(
			runtime.ownerRoot,
			journal.Rotation.QuarantineFileName,
		),
		original,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := indexStoreFromOwner(store).loadOptional(); err == nil ||
		!strings.Contains(err.Error(), "both original and quarantine") {
		t.Fatalf("rotation collision error = %v", err)
	}
	for _, name := range []string{
		victim.RecordFileName,
		journal.Rotation.QuarantineFileName,
	} {
		if _, err := os.Lstat(filepath.Join(
			runtime.ownerRoot,
			name,
		)); err != nil {
			t.Fatalf("rotation collision evidence %s was lost: %v", name, err)
		}
	}
	file, _, err := openExistingAnchoredRegularFile(
		store.root,
		pinOwnerIndexFileName,
		0o600,
		store.expectedUID,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stillJournaled, err := readPinOwnerIndex(file)
	if err != nil {
		t.Fatal(err)
	}
	if stillJournaled.Rotation == nil ||
		*stillJournaled.Rotation != *journal.Rotation {
		t.Fatalf("rotation journal changed after collision: %#v", stillJournaled)
	}
}

func TestPinOwnerIndexRemovesFileWhenLastEntryIsRemoved(t *testing.T) {
	root := t.TempDir()
	runtime, parent, record := testPinOwnerRecord(t, root)
	store, err := openPinOwnerStore(runtime, parent.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Persist(record, nil, parent.mountID); err != nil {
		t.Fatal(err)
	}
	indexStore := indexStoreFromOwner(store)
	entry, err := ownerIndexEntryFromRecord(
		record,
		pinOwnerIndexActive,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := indexStore.updateEntry(
		entry,
		true,
		time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		pinOwnerIndexFileName,
	)); !os.IsNotExist(err) {
		t.Fatalf("empty owner index file still exists: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRekeyRebootedOwnerPreservesOldRecordAndRetiresIndex(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-rekey-test")
	mapStore := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, mapStore)
	runtime.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32))
	runtime.now = func() time.Time {
		return time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC)
	}
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	oldResource := handle.resource
	oldResource.parentDevice += 1000
	oldResource.parentInode += 1000
	oldResource.key, err = pinidentity.Key(
		oldResource.parentDevice,
		oldResource.parentInode,
		oldResource.base,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldParent := &pinPathParent{
		pinPath:  pinPath,
		base:     oldResource.base,
		mountID:  handle.mountID,
		resource: oldResource,
		runtime:  runtime,
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		t.Fatal(err)
	}
	oldMaps := ownerMapsFromPins(pins)
	if err := closePinnedMapPins(pins); err != nil {
		t.Fatal(err)
	}
	var oldToken [32]byte
	for index := range oldToken {
		oldToken[index] = byte(index + 1)
	}
	oldSentinel, err := pinOwnerSentinelFor(oldResource, oldToken)
	if err != nil {
		t.Fatal(err)
	}
	ownerObservation := mapStore.observations["owner_map"]
	ownerObservation.owner = oldSentinel
	ownerObservation.ownerSeen = true
	mapStore.observations["owner_map"] = ownerObservation
	oldRecord, err := newActivePinOwnerRecord(
		oldParent,
		oldToken,
		"12345678-1234-1234-1234-123456789abc",
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		1,
		oldMaps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldStore, err := openPinOwnerStore(runtime, oldResource, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldStore.Persist(oldRecord, nil, handle.mountID); err != nil {
		t.Fatal(err)
	}
	indexedOld, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(oldStore),
		oldRecord,
	)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := indexStoreFromOwner(oldStore).archivePriorBootOwner(
		*indexedOld,
		oldRecord,
		true,
		runtime.now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := oldStore.Close(); err != nil {
		t.Fatal(err)
	}

	currentStore, err := openPinOwnerStore(runtime, handle.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer currentStore.Close()
	entry, err := indexedOwnerEntryForRekey(currentStore, handle)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil ||
		!samePinOwnerIndexEntries(
			[]pinOwnerIndexEntry{*entry},
			[]pinOwnerIndexEntry{*historical},
		) {
		t.Fatalf("indexed rekey source = %#v", entry)
	}
	currentBoot := "87654321-4321-4321-4321-cba987654321"
	rekeyed, err := rekeyRebootedPinOwner(
		handle,
		parent,
		currentStore,
		entry,
		currentBoot,
		runtime.now(),
		exactTCXRuntime{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if rekeyed.ResourceKey != handle.resource.key ||
		rekeyed.RetiredFromResourceKey != oldResource.key ||
		rekeyed.RetiredFromBootID != oldRecord.BootID ||
		rekeyed.BootID != currentBoot ||
		len(rekeyed.ActiveLinks) != 0 {
		t.Fatalf("rekeyed owner = %#v", rekeyed)
	}
	if _, err := os.Stat(filepath.Join(
		runtime.ownerRoot,
		historical.RecordFileName,
	)); err != nil {
		t.Fatalf("old owner record was not preserved: %v", err)
	}
	index, exists, err := indexStoreFromOwner(currentStore).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || len(index.Entries) != 2 {
		t.Fatalf("rekey owner index = %#v", index)
	}
	if index.Sequence != 3 {
		t.Fatalf(
			"rekey owner index sequence = %d, want archive plus publish to reach 3",
			index.Sequence,
		)
	}
	statuses := make(map[string]string)
	var activeEntry *pinOwnerIndexEntry
	for _, indexed := range index.Entries {
		statuses[pinOwnerIndexEntryKey(
			indexed.ResourceKey,
			indexed.BootID,
		)] = indexed.Status
		if indexed.Status == pinOwnerIndexActive {
			copy := indexed
			activeEntry = &copy
		}
	}
	if statuses[pinOwnerIndexEntryKey(
		oldResource.key,
		oldRecord.BootID,
	)] != pinOwnerIndexRetiredStatus ||
		statuses[pinOwnerIndexEntryKey(
			handle.resource.key,
			currentBoot,
		)] != pinOwnerIndexActive ||
		len(index.Active) != 1 ||
		activeEntry == nil ||
		index.Active[0] != activePointerFromEntry(*activeEntry) {
		t.Fatalf("rekey owner index statuses = %#v", statuses)
	}
}

func TestRekeyRebootedOwnerWithSameResourceKeyAndOlderHistory(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-same-key-rekey")
	mapStore := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, mapStore)
	runtime.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32))
	runtime.now = func() time.Time {
		return time.Date(2026, 7, 31, 1, 2, 3, 4, time.UTC)
	}
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		t.Fatal(err)
	}
	ownerMaps := ownerMapsFromPins(pins)
	if err := closePinnedMapPins(pins); err != nil {
		t.Fatal(err)
	}
	var firstToken [32]byte
	for index := range firstToken {
		firstToken[index] = byte(index + 1)
	}
	firstBoot := "12345678-1234-1234-1234-123456789abc"
	firstRecord, err := newActivePinOwnerRecord(
		parent,
		firstToken,
		firstBoot,
		time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
		1,
		ownerMaps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstSentinel, err := pinOwnerSentinelFor(
		handle.resource,
		firstToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	ownerObservation := mapStore.observations["owner_map"]
	ownerObservation.owner = firstSentinel
	ownerObservation.ownerSeen = true
	mapStore.observations["owner_map"] = ownerObservation

	store, err := openPinOwnerStore(runtime, handle.resource, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Persist(firstRecord, nil, handle.mountID); err != nil {
		t.Fatal(err)
	}
	firstIndexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		firstRecord,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstHistory, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*firstIndexed,
		firstRecord,
		true,
		time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}

	var secondToken [32]byte
	for index := range secondToken {
		secondToken[index] = byte(0x40 + index)
	}
	secondBoot := "22345678-1234-1234-1234-123456789abc"
	secondRecord, err := newActivePinOwnerRecord(
		parent,
		secondToken,
		secondBoot,
		time.Date(2026, 7, 30, 2, 2, 3, 4, time.UTC),
		firstRecord.ActiveGeneration,
		ownerMaps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRecord.RetiredFromResourceKey = firstRecord.ResourceKey
	secondRecord.RetiredFromBootID = firstRecord.BootID
	normalizePinOwnerRecord(secondRecord)
	if err := validatePinOwnerRecord(
		secondRecord,
		handle.resource,
		handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	secondSentinel, err := pinOwnerSentinelFor(
		handle.resource,
		secondToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	ownerObservation = mapStore.observations["owner_map"]
	ownerObservation.owner = secondSentinel
	mapStore.observations["owner_map"] = ownerObservation
	if err := store.Persist(
		secondRecord,
		nil,
		handle.mountID,
	); err != nil {
		t.Fatal(err)
	}
	secondIndexed, err := activeIndexedOwnerForRecord(
		indexStoreFromOwner(store),
		secondRecord,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondHistory, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*secondIndexed,
		secondRecord,
		true,
		runtime.now(),
	)
	if err != nil {
		t.Fatal(err)
	}

	rekeySource, err := indexedOwnerEntryForRekey(store, handle)
	if err != nil {
		t.Fatal(err)
	}
	if rekeySource == nil ||
		!samePinOwnerIndexEntries(
			[]pinOwnerIndexEntry{*rekeySource},
			[]pinOwnerIndexEntry{*secondHistory},
		) {
		t.Fatalf("same-key rekey source = %#v", rekeySource)
	}
	currentBoot := "87654321-4321-4321-4321-cba987654321"
	rekeyed, err := rekeyRebootedPinOwner(
		handle,
		parent,
		store,
		rekeySource,
		currentBoot,
		runtime.now(),
		exactTCXRuntime{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if rekeyed.ResourceKey != firstRecord.ResourceKey ||
		rekeyed.RetiredFromResourceKey != secondRecord.ResourceKey ||
		rekeyed.RetiredFromBootID != secondBoot ||
		rekeyed.BootID != currentBoot {
		t.Fatalf("same-key rekeyed owner = %#v", rekeyed)
	}
	for _, history := range []*pinOwnerIndexEntry{
		firstHistory,
		secondHistory,
	} {
		if _, err := os.Stat(filepath.Join(
			runtime.ownerRoot,
			history.RecordFileName,
		)); err != nil {
			t.Fatalf(
				"same-key history %s is not preserved: %v",
				history.RecordFileName,
				err,
			)
		}
	}
	index, exists, err := indexStoreFromOwner(store).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || len(index.Entries) != 3 || len(index.Active) != 1 {
		t.Fatalf("same-key rekey index = %#v", index)
	}
	statusByBoot := make(map[string]string, len(index.Entries))
	for _, entry := range index.Entries {
		if entry.ResourceKey != handle.resource.key {
			t.Fatalf("same-key history changed resource key: %#v", entry)
		}
		statusByBoot[entry.BootID] = entry.Status
	}
	if statusByBoot[firstBoot] != pinOwnerIndexRetiredStatus ||
		statusByBoot[secondBoot] != pinOwnerIndexRetiredStatus ||
		statusByBoot[currentBoot] != pinOwnerIndexActive ||
		index.Active[0].ResourceKey != handle.resource.key ||
		index.Active[0].BootID != currentBoot {
		t.Fatalf("same-key statuses = %#v active=%#v", statusByBoot, index.Active)
	}
}

func TestSameResourcePathAliasRetryRetiresExactRekeySource(t *testing.T) {
	runtime, parent, oldRecord, store, indexed :=
		openPersistedTestPinOwner(t)
	archiveTime := time.Date(2026, 7, 30, 1, 2, 3, 4, time.UTC)
	historical, err := indexStoreFromOwner(store).archivePriorBootOwner(
		*indexed,
		oldRecord,
		false,
		archiveTime,
	)
	if err != nil {
		t.Fatal(err)
	}

	aliasRoot := filepath.Join(
		filepath.Dir(oldRecord.BPFFSRootPath),
		"bpffs-alias",
	)
	aliasPinPath := filepath.Join(aliasRoot, parent.resource.base)
	aliasResource := parent.resource
	aliasResource.pinPath = aliasPinPath
	aliasParent := &pinPathParent{
		pinPath:  aliasPinPath,
		base:     aliasResource.base,
		mountID:  parent.mountID + 1,
		resource: aliasResource,
		runtime:  runtime,
	}
	aliasStore, err := openPinOwnerStore(
		runtime,
		aliasResource,
		true,
	)
	if err != nil {
		t.Fatalf("open owner store through path alias: %v", err)
	}
	defer aliasStore.Close()
	retrySource, err := indexedOwnerEntryForRekey(
		aliasStore,
		&pinPathHandle{
			pinPath:  aliasPinPath,
			resource: aliasResource,
		},
	)
	if err != nil {
		t.Fatalf("find rekey source through path alias: %v", err)
	}
	if retrySource == nil ||
		!samePinOwnerIndexEntries(
			[]pinOwnerIndexEntry{*retrySource},
			[]pinOwnerIndexEntry{*historical},
		) {
		t.Fatalf("path-alias rekey source = %#v", retrySource)
	}

	var token [32]byte
	for index := range token {
		token[index] = byte(0x90 + index)
	}
	current, err := newActivePinOwnerRecord(
		aliasParent,
		token,
		"87654321-4321-4321-4321-cba987654321",
		archiveTime.Add(time.Minute),
		oldRecord.ActiveGeneration,
		oldRecord.Maps,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	current.RetiredFromResourceKey = historical.ResourceKey
	current.RetiredFromBootID = historical.BootID
	normalizePinOwnerRecord(current)
	if err := aliasStore.Persist(
		current,
		nil,
		aliasParent.mountID,
	); err != nil {
		t.Fatalf("publish reboot owner through path alias: %v", err)
	}

	index, exists, err := indexStoreFromOwner(aliasStore).loadOptional()
	if err != nil {
		t.Fatal(err)
	}
	if !exists || len(index.Active) != 1 ||
		len(index.Entries) != 2 {
		t.Fatalf("path-alias retry index = %#v", index)
	}
	if index.Active[0].BPFFSRootPath != aliasRoot ||
		index.Active[0].ResourceKey != current.ResourceKey ||
		index.Active[0].BootID != current.BootID ||
		index.Active[0].Status != pinOwnerIndexActive {
		t.Fatalf("path-alias active pointer = %#v", index.Active[0])
	}
	statusByBoot := make(map[string]string, len(index.Entries))
	for _, entry := range index.Entries {
		statusByBoot[entry.BootID] = entry.Status
	}
	if statusByBoot[oldRecord.BootID] !=
		pinOwnerIndexRetiredStatus ||
		statusByBoot[current.BootID] != pinOwnerIndexActive {
		t.Fatalf("path-alias retry statuses = %#v", statusByBoot)
	}
	if _, err := os.Lstat(filepath.Join(
		runtime.ownerRoot,
		historical.RecordFileName,
	)); err != nil {
		t.Fatalf("path-alias retry lost old evidence: %v", err)
	}
	loaded, err := aliasStore.Load(aliasParent.mountID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameExpectedOwnerRecord(loaded, current) {
		t.Fatalf("path-alias current owner = %#v, want %#v", loaded, current)
	}
}

func TestPinOwnershipMutationAPIsRequireMatchingLifecycleLease(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "daemon.lease")
	maintenancePath := filepath.Join(root, "maintenance.gate")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		leasePath,
		maintenancePath,
	)
	if _, err := RecoverPinOwnership(
		ctx,
		"relative",
		nil,
	); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
		t.Fatalf("recover without lifecycle lease error = %v", err)
	}
	if err := DetachPinOwnership(
		ctx,
		"relative",
		nil,
	); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
		t.Fatalf("detach without lifecycle lease error = %v", err)
	}
	lease, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := RecoverPinOwnership(
		ctx,
		"relative",
		lease,
	); errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) ||
		err == nil ||
		!strings.Contains(err.Error(), "path must be absolute") {
		t.Fatalf("recover with lifecycle lease error = %v", err)
	}
	if err := DetachPinOwnership(
		ctx,
		"relative",
		lease,
	); errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) ||
		err == nil ||
		!strings.Contains(err.Error(), "path must be absolute") {
		t.Fatalf("detach with lifecycle lease error = %v", err)
	}
	mismatchedRoot := t.TempDir()
	mismatchedCtx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		filepath.Join(mismatchedRoot, "other-daemon.lease"),
		filepath.Join(mismatchedRoot, "maintenance.gate"),
	)
	if _, err := RecoverPinOwnership(
		mismatchedCtx,
		"relative",
		lease,
	); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
		t.Fatalf("recover with mismatched lifecycle key error = %v", err)
	}
	if err := DetachPinOwnership(
		mismatchedCtx,
		"relative",
		lease,
	); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
		t.Fatalf("detach with mismatched lifecycle key error = %v", err)
	}
}

func TestPinOwnershipMutationRejectsClosedAndReplacedLifecycleLease(t *testing.T) {
	t.Run("closed", func(t *testing.T) {
		root := t.TempDir()
		leasePath := filepath.Join(root, "daemon.lease")
		ctx := lockfile.WithLifecyclePathsForTest(
			t.Context(),
			leasePath,
			filepath.Join(root, "maintenance.gate"),
		)
		lease, err := lockfile.AcquireLifecycle(
			ctx,
			lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := RecoverPinOwnership(
			ctx,
			"relative",
			lease,
		); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
			t.Fatalf("recover with closed lifecycle lease error = %v", err)
		}
	})
	t.Run("replaced-path-entry", func(t *testing.T) {
		root := t.TempDir()
		leasePath := filepath.Join(root, "daemon.lease")
		ctx := lockfile.WithLifecyclePathsForTest(
			t.Context(),
			leasePath,
			filepath.Join(root, "maintenance.gate"),
		)
		lease, err := lockfile.AcquireLifecycle(
			ctx,
			lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
		)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		if err := os.Rename(leasePath, leasePath+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			leasePath,
			[]byte("{}\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := DetachPinOwnership(
			ctx,
			"relative",
			lease,
		); !errors.Is(err, ErrPinOwnershipLifecycleLeaseRequired) {
			t.Fatalf("detach with replaced lifecycle entry error = %v", err)
		}
	})
}

func TestPinOwnershipRetainedLeaseSurvivesCallerClose(t *testing.T) {
	root := t.TempDir()
	leasePath := filepath.Join(root, "daemon.lease")
	ctx := lockfile.WithLifecyclePathsForTest(
		t.Context(),
		leasePath,
		filepath.Join(root, "maintenance.gate"),
	)
	lease, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := retainPinOwnershipLifecycleLease(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if reacquired, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "contender"},
	); !errors.Is(err, lockfile.ErrLifecycleLeaseHeld) {
		if reacquired != nil {
			_ = reacquired.Close()
		}
		t.Fatalf("lifecycle lease was released before retained close: %v", err)
	}
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := lockfile.AcquireLifecycle(
		ctx,
		lockfile.LifecycleOwner{PID: os.Getpid(), Action: "after-close"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func snapshotFlatTestDirectory(
	t *testing.T,
	path string,
) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected subdirectory %s/%s", path, entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name()] = fmt.Sprintf(
			"%#o:%d:%s",
			info.Mode().Perm(),
			len(data),
			data,
		)
	}
	return snapshot
}

func TestInspectPinOwnershipDoesNotMutateOwnerIndexOrPins(t *testing.T) {
	bpffsRoot, validator := newTestBPFFS(t)
	pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-inspect-read-only")
	mapStore := writeCanonicalMockPins(t, pinPath)
	runtime := newTestPinPathRuntime(t, validator, mapStore)
	validated, err := validatePinPath(pinPath, validator)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openPinPathParent(pinPath, validated, runtime)
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := openPinPathHandleFromParent(parent, validated, false)
	if err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	pins, err := inspectPinnedMapSet(handle, true)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	ownerMaps := ownerMapsFromPins(pins)
	if err := closePinnedMapPins(pins); err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
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
		1,
		ownerMaps,
		nil,
	)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	sentinel, err := pinOwnerSentinelFor(handle.resource, token)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	ownerObservation := mapStore.observations["owner_map"]
	ownerObservation.owner = sentinel
	ownerObservation.ownerSeen = true
	mapStore.observations["owner_map"] = ownerObservation
	store, err := openPinOwnerStore(runtime, handle.resource, true)
	if err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := store.Persist(record, nil, handle.mountID); err != nil {
		_ = store.Close()
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		_ = handle.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}

	ownerBefore := snapshotFlatTestDirectory(t, runtime.ownerRoot)
	pinsBefore := snapshotFlatTestDirectory(t, pinPath)
	runtime.beforeOwnerExchange = func() {
		t.Error("read-only inspection attempted an owner/index exchange")
	}
	runtime.beforePinQuarantine = func(name string) error {
		return fmt.Errorf("read-only inspection attempted to quarantine %s", name)
	}
	runtime.beforePinUnlink = func(name string) error {
		return fmt.Errorf("read-only inspection attempted to unlink %s", name)
	}
	// This owner has no exact TCX links, so inspection must not touch the
	// deliberately empty runtime.
	status, err := inspectPinOwnershipWithRuntime(
		t.Context(),
		pinPath,
		false,
		runtime,
		exactTCXRuntime{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !status.DirectoryExists ||
		!status.OwnerExists ||
		status.RecoveryRequired ||
		status.ResourceKey != record.ResourceKey ||
		status.Sequence != record.Sequence {
		t.Fatalf("read-only ownership status = %#v", status)
	}
	ownerAfter := snapshotFlatTestDirectory(t, runtime.ownerRoot)
	pinsAfter := snapshotFlatTestDirectory(t, pinPath)
	if !maps.Equal(ownerAfter, ownerBefore) {
		t.Fatalf(
			"owner/index files changed during inspection:\nbefore=%#v\nafter=%#v",
			ownerBefore,
			ownerAfter,
		)
	}
	if !maps.Equal(pinsAfter, pinsBefore) {
		t.Fatalf(
			"pin files changed during inspection:\nbefore=%#v\nafter=%#v",
			pinsBefore,
			pinsAfter,
		)
	}
	lockEntries, err := os.ReadDir(runtime.lockRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(lockEntries) != 1 {
		t.Fatalf("resource lease entries after inspection = %v", lockEntries)
	}
}

func TestMissingPinDirectoryPreservesAndReportsOwnershipEvidence(
	t *testing.T,
) {
	for _, archived := range []bool{false, true} {
		name := "active"
		if archived {
			name = "rekey-source"
		}
		t.Run(name, func(t *testing.T) {
			bpffsRoot, validator := newTestBPFFS(t)
			pinPath := filepath.Join(
				bpffsRoot,
				"wg-mix-ebpf-missing-owner",
			)
			runtime := newTestPinPathRuntime(
				t,
				validator,
				newFakePinnedMapStore(),
			)
			validated, err := validatePinPath(pinPath, validator)
			if err != nil {
				t.Fatal(err)
			}
			parent, err := openPinPathParent(
				pinPath,
				validated,
				runtime,
			)
			if err != nil {
				t.Fatal(err)
			}
			_, _, template := testPinOwnerRecord(t, t.TempDir())
			var token [32]byte
			for index := range token {
				token[index] = byte(index + 1)
			}
			record, err := newActivePinOwnerRecord(
				parent,
				token,
				"12345678-1234-1234-1234-123456789abc",
				time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
				1,
				template.Maps,
				nil,
			)
			if err != nil {
				_ = parent.Close()
				t.Fatal(err)
			}
			store, err := openPinOwnerStore(
				runtime,
				parent.resource,
				true,
			)
			if err != nil {
				_ = parent.Close()
				t.Fatal(err)
			}
			if err := store.Persist(
				record,
				nil,
				parent.mountID,
			); err != nil {
				_ = store.Close()
				_ = parent.Close()
				t.Fatal(err)
			}
			expectedRecordPath := filepath.Join(
				runtime.ownerRoot,
				record.ResourceKey+".owner.json",
			)
			if archived {
				indexed, err := activeIndexedOwnerForRecord(
					indexStoreFromOwner(store),
					record,
				)
				if err != nil {
					_ = store.Close()
					_ = parent.Close()
					t.Fatal(err)
				}
				history, err := indexStoreFromOwner(
					store,
				).archivePriorBootOwner(
					*indexed,
					record,
					false,
					time.Date(
						2026,
						7,
						30,
						1,
						2,
						3,
						4,
						time.UTC,
					),
				)
				if err != nil {
					_ = store.Close()
					_ = parent.Close()
					t.Fatal(err)
				}
				expectedRecordPath = filepath.Join(
					runtime.ownerRoot,
					history.RecordFileName,
				)
			}
			if err := store.Close(); err != nil {
				_ = parent.Close()
				t.Fatal(err)
			}
			if err := parent.Close(); err != nil {
				t.Fatal(err)
			}

			before := snapshotFlatTestDirectory(
				t,
				runtime.ownerRoot,
			)
			runtime.beforeOwnerExchange = func() {
				t.Error(
					"missing-directory inspection attempted an owner/index exchange",
				)
			}
			runtime.beforePinQuarantine = func(name string) error {
				return fmt.Errorf(
					"missing-directory inspection attempted to quarantine %s",
					name,
				)
			}
			runtime.beforePinUnlink = func(name string) error {
				return fmt.Errorf(
					"missing-directory inspection attempted to unlink %s",
					name,
				)
			}
			status, err := inspectPinOwnershipWithRuntime(
				t.Context(),
				pinPath,
				false,
				runtime,
				exactTCXRuntime{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if status.DirectoryExists ||
				!status.OwnerExists ||
				!status.RecoveryRequired ||
				status.ResourceKey != record.ResourceKey ||
				status.RecordPath != expectedRecordPath {
				t.Fatalf(
					"missing-directory ownership status = %#v",
					status,
				)
			}
			afterInspect := snapshotFlatTestDirectory(
				t,
				runtime.ownerRoot,
			)
			if !maps.Equal(afterInspect, before) {
				t.Fatalf(
					"missing-directory inspection changed evidence:\nbefore=%#v\nafter=%#v",
					before,
					afterInspect,
				)
			}

			loader := LinuxLoader{
				PinPath: pinPath,
				runtime: &runtime,
			}
			err = loader.Detach(t.Context(), nil)
			if err == nil ||
				!strings.Contains(err.Error(), "directory is missing") {
				t.Fatalf(
					"missing-directory detach error = %v",
					err,
				)
			}
			afterDetach := snapshotFlatTestDirectory(
				t,
				runtime.ownerRoot,
			)
			if !maps.Equal(afterDetach, before) {
				t.Fatalf(
					"missing-directory detach changed evidence:\nbefore=%#v\nafter=%#v",
					before,
					afterDetach,
				)
			}
		})
	}
}

func TestReadOnlyOwnershipInspectionReportsJournalsWithoutRecovery(t *testing.T) {
	t.Run("owner-next", func(t *testing.T) {
		runtime, _, record, store, _ := openPersistedTestPinOwner(t)
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
			_ = nextFile.Close()
			t.Fatal(err)
		}
		if err := nextFile.Close(); err != nil {
			t.Fatal(err)
		}
		before := snapshotFlatTestDirectory(t, runtime.ownerRoot)
		pending, err := inspectPinOwnerDescriptorsReadOnly(store)
		if err != nil {
			t.Fatal(err)
		}
		if !pending {
			t.Fatal("read-only owner inspection missed pending next record")
		}
		_, exists, indexPending, err := indexStoreFromOwner(
			store,
		).inspectOptionalReadOnly()
		if err != nil {
			t.Fatal(err)
		}
		if !exists || indexPending {
			t.Fatalf(
				"steady index read-only state exists=%t pending=%t",
				exists,
				indexPending,
			)
		}
		after := snapshotFlatTestDirectory(t, runtime.ownerRoot)
		if !maps.Equal(after, before) {
			t.Fatalf(
				"read-only descriptor inspection changed files:\nbefore=%#v\nafter=%#v",
				before,
				after,
			)
		}
	})
	t.Run("history-rotation", func(t *testing.T) {
		runtime, _, _, store, index, victim :=
			testPinOwnerHistoryAtCapacity(t)
		persistTestPinOwnerRotationJournal(
			t,
			store,
			index,
			victim,
		)
		before := snapshotFlatTestDirectory(t, runtime.ownerRoot)
		inspected, exists, pending, err := indexStoreFromOwner(
			store,
		).inspectOptionalReadOnly()
		if err != nil {
			t.Fatal(err)
		}
		if !exists || !pending || inspected.Rotation == nil {
			t.Fatalf(
				"read-only rotation state exists=%t pending=%t index=%#v",
				exists,
				pending,
				inspected,
			)
		}
		after := snapshotFlatTestDirectory(t, runtime.ownerRoot)
		if !maps.Equal(after, before) {
			t.Fatalf(
				"read-only rotation inspection changed files:\nbefore=%#v\nafter=%#v",
				before,
				after,
			)
		}
	})
}

func TestOwnerMapUnlinkFailureAtEveryPositionRestoresCanonicalSet(t *testing.T) {
	for failAt := 1; failAt <= len(pinnedMapDescriptors()); failAt++ {
		t.Run(fmt.Sprintf("unlink-%02d", failAt), func(t *testing.T) {
			bpffsRoot, validator := newTestBPFFS(t)
			pinPath := filepath.Join(bpffsRoot, "wg-mix-ebpf-unlink-test")
			mapStore := writeCanonicalMockPins(t, pinPath)
			runtime := newTestPinPathRuntime(t, validator, mapStore)
			validated, err := validatePinPath(pinPath, validator)
			if err != nil {
				t.Fatal(err)
			}
			parent, err := openPinPathParent(pinPath, validated, runtime)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			handle, _, err := openPinPathHandleFromParent(
				parent,
				validated,
				false,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
			pins, err := inspectPinnedMapSet(handle, true)
			if err != nil {
				t.Fatal(err)
			}
			defer closePinnedMapPins(pins)
			var token [32]byte
			for index := range token {
				token[index] = byte(index + 1)
			}
			active, err := newActivePinOwnerRecord(
				parent,
				token,
				"12345678-1234-1234-1234-123456789abc",
				time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
				1,
				ownerMapsFromPins(pins),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			sentinel, err := pinOwnerSentinelFor(handle.resource, token)
			if err != nil {
				t.Fatal(err)
			}
			ownerObservation := mapStore.observations["owner_map"]
			ownerObservation.owner = sentinel
			ownerObservation.ownerSeen = true
			mapStore.observations["owner_map"] = ownerObservation
			detaching, err := newDetachingPinOwnerRecord(
				active,
				time.Date(2026, 7, 29, 1, 2, 4, 0, time.UTC),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := stageOwnerMaps(handle, detaching, pins); err != nil {
				t.Fatal(err)
			}
			stages, err := loadOwnerMapStages(handle, detaching)
			if err != nil {
				t.Fatal(err)
			}
			defer stages.Close()
			unlinks := 0
			handle.runtime.beforePinUnlink = func(string) error {
				unlinks++
				if unlinks == failAt {
					return errors.New("injected map unlink failure")
				}
				return nil
			}
			err = removeCanonicalOwnerMaps(handle, detaching, stages)
			if err == nil || !strings.Contains(err.Error(), "injected map unlink failure") {
				t.Fatalf("canonical unlink error = %v", err)
			}
			if err := restoreCanonicalOwnerMaps(
				handle,
				detaching,
				stages,
			); err != nil {
				t.Fatalf("restore canonical owner maps: %v", err)
			}
			for _, stage := range detaching.MapStages {
				descriptor, err := ownerMapDescriptor(stage.Name)
				if err != nil {
					t.Fatal(err)
				}
				pin, err := validatePinnedMapAt(
					handle,
					descriptor,
					stage.Name,
					stage.MapID,
				)
				if err != nil {
					t.Fatalf("canonical map %s was not restored: %v", stage.Name, err)
				}
				if err := pin.observation.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(
					pinPath,
					stage.FileName+".canonical-retired",
				)); !os.IsNotExist(err) {
					t.Fatalf("canonical quarantine %s remains: %v", stage.Name, err)
				}
			}
			if err := removeOwnerMapStages(handle, detaching); err != nil {
				t.Fatal(err)
			}
		})
	}
}
